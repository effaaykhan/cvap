// Command cvap-credscan is the credentialed validation instrument (ADR-075/076).
//
// It is an operator-run measurement tool, NOT a fleet engine: one short-lived
// process that holds a credential (ADR-027/076: the runtime holds it, never an
// engine), reads a Linux host's package inventory and exact release over SSH, and
// measures the unauthenticated pipeline's findings against that credentialed ground
// truth. It authenticates only to a host in lab/scope.txt (non-negotiable #10) and
// establishes evidence without impact — it reads inventory, runs no exploit, writes
// nothing to the target (non-negotiable #9).
//
// It prints three numbers on the real host (ADR-076): version extraction (banner vs
// installed), release attribution (band vote vs /etc/os-release), and the §6.2 FP/FN
// of the unauthenticated findings. It changes nothing in the database and tunes
// nothing against the sample — a banner-inference error is a backlog finding, not a
// fix.
//
// Usage:
//
//	APP_DATABASE_URL=... cvap-credscan \
//	  --host 10.10.4.9 --user ubuntu --key ~/.ssh/id_ed25519 \
//	  --known-hosts ~/.ssh/known_hosts \
//	  --tenant <uuid> --asset <uuid> [--scope lab/scope.txt] [--port 22]
//
// The credential is a private key file (--key) or a password (env
// CVAP_CREDSCAN_PASSWORD). Prefer --key: an env-var password persists in the process
// environment for the whole run, beyond the reach of the credential's zeroise (the
// key file's bytes are read into a zeroisable Credential; the env string is not).
// Host-key verification is mandatory: --known-hosts must contain the host's key,
// because presenting a credential to an unverified host is the credential handed to
// whoever answered.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/effaaykhan/cvap/internal/credscan"
	"github.com/effaaykhan/cvap/internal/scanpoint"
	"github.com/effaaykhan/cvap/internal/scope"
	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/target"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cvap-credscan:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		host       = flag.String("host", "", "target host address (must be in scope)")
		port       = flag.Int("port", 22, "SSH port")
		user       = flag.String("user", "", "SSH user")
		keyPath    = flag.String("key", "", "path to an SSH private key (or set CVAP_CREDSCAN_PASSWORD)")
		knownHosts = flag.String("known-hosts", "", "path to a known_hosts file (required)")
		scopePath  = flag.String("scope", "lab/scope.txt", "scan scope file")
		tenantStr  = flag.String("tenant", "", "tenant uuid")
		assetStr   = flag.String("asset", "", "asset uuid (already scanned unauthenticated)")
		timeout    = flag.Duration("timeout", 30*time.Second, "SSH connect/read timeout")
		useAgent   = flag.Bool("agent", false, "authenticate via a runtime CredAgent signing proxy (ADR-086) instead of holding the key directly")
		invOnly    = flag.Bool("inventory-only", false, "read and print the host's release and inventory; no database, no measurement")
		truthOnly  = flag.Bool("truth-only", false, "read the host and print the credentialed advisory finding set (exact-version matching), with no unauthenticated Diff — used where no unauth scan exists (e.g. the rpm/B26 host)")
		grep       = flag.String("grep", "", "with --inventory-only, list installed packages whose source or binary contains this substring")
	)
	flag.Parse()

	// Inventory-only touches no database; truth-only reads the keyspace (needs a
	// tenant for the transaction) but no unauth asset; the full measurement needs both.
	required := *host == "" || *user == "" || *knownHosts == ""
	switch {
	case *invOnly:
		// host/user/known-hosts only
	case *truthOnly:
		required = required || *tenantStr == ""
	default:
		required = required || *tenantStr == "" || *assetStr == ""
	}
	if required {
		return errors.New("credscan: missing required flags for this mode (--host/--user/--known-hosts always; --tenant unless --inventory-only; --asset for the full measurement)")
	}

	// --- Scope gate (non-negotiable #10): the same matcher Core uses. ---
	canon, err := target.Canonicalise(*host)
	if err != nil {
		return fmt.Errorf("host %q: %w", *host, err)
	}
	// This instrument requires an ADDRESS target, not a hostname. A hostname is
	// matched by scope.Permits by exact string, but the address DNS resolves it to
	// is never re-checked against the scope — so a hostname allow rule could resolve
	// to an out-of-scope or excluded address and still be handed the credential
	// (scope.go's own stated limitation, made live by this tool's dial). Refusing a
	// hostname closes that outright, and costs nothing: lab/scope.txt is addresses
	// and CIDRs by convention.
	if canon.Kind != target.KindAddress {
		return fmt.Errorf("host %q must be an address, not a hostname: this instrument does not resolve names (a resolved address is never re-checked against scope)", *host)
	}
	allowed, exclusions, err := loadScope(*scopePath)
	if err != nil {
		return err
	}
	if ok, why := scope.Permits(canon, allowed, exclusions); !ok {
		return fmt.Errorf("refusing to authenticate: %s is not in scope (%s): %s", canon.Value, *scopePath, why)
	}

	var tenant store.TenantID
	var assetID uuid.UUID
	if !*invOnly { // inventory-only touches no DB; truth-only and full both need a tenant
		tenantUUID, err := uuid.Parse(*tenantStr)
		if err != nil {
			return fmt.Errorf("--tenant is not a uuid: %w", err)
		}
		tenant, err = store.NewTenantID(tenantUUID)
		if err != nil {
			return err
		}
		if !*truthOnly {
			assetID, err = uuid.Parse(*assetStr)
			if err != nil {
				return fmt.Errorf("--asset is not a uuid: %w", err)
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout+30*time.Second)
	defer cancel()

	// --- Credential: runtime-held (ADR-027/076), memory-only, zeroised (ADR-038). ---
	cred, err := loadCredential(canon.Value, *keyPath, *timeout)
	if err != nil {
		return err
	}
	defer cred.Zeroise() // backstop; zeroised explicitly below once the read is done

	// Auth. --agent routes through the runtime signing proxy (ADR-086): the key
	// stays in the CredAgent and this read authenticates over the agent socket with
	// signatures only — the same split the production engine uses, exercised here
	// against a real host. Without --agent, the key is presented directly (the S39
	// instrument path).
	var auth ssh.AuthMethod
	var credAgent *scanpoint.CredAgent
	if *useAgent {
		credAgent, err = scanpoint.NewCredAgent(cred)
		if err != nil {
			cred.Zeroise()
			return err
		}
		defer credAgent.Zeroise()
		sockFile, ferr := credAgent.EngineFile()
		if ferr != nil {
			cred.Zeroise()
			return ferr
		}
		sockConn, cerr := net.FileConn(sockFile)
		_ = sockFile.Close()
		if cerr != nil {
			cred.Zeroise()
			return cerr
		}
		defer sockConn.Close()
		agentClient := agent.NewClient(sockConn)
		auth = ssh.PublicKeysCallback(agentClient.Signers)
	} else {
		auth, err = authMethod(cred)
		if err != nil {
			cred.Zeroise()
			return err
		}
	}

	hostKeyCallback, err := knownhosts.New(*knownHosts)
	if err != nil {
		cred.Zeroise()
		return fmt.Errorf("known_hosts %q: %w", *knownHosts, err)
	}

	// --- The one host-dependent step: authenticate and read. ---
	read, err := credscan.ReadHost(ctx, credscan.SSHConfig{
		Addr:            net.JoinHostPort(canon.Value, fmt.Sprint(*port)),
		User:            *user,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         *timeout,
	})
	// The credential's job is done the moment the authenticated read returns: the
	// session is closed and the inventory is in hand (ADR-057 derive-before-zeroise).
	cred.Zeroise()
	if err != nil {
		return err
	}

	// --- Inventory-only: print the host facts, no database, no measurement. ---
	if *invOnly {
		printInventory(read, *grep)
		return nil
	}

	// --- Truth-only: the credentialed finding set from exact versions, no unauth
	// Diff — for a host with no unauthenticated scan (the rpm/B26 host). ---
	if *truthOnly {
		return truthReport(ctx, tenant, read)
	}

	// --- The measurement: all store reads in one read-only tenant transaction. ---
	report, err := measure(ctx, tenant, assetID, read)
	if err != nil {
		return err
	}
	fmt.Print(report.Render())
	return nil
}

// measure gathers the stored side (the asset's band-resolved release, its identified
// services, its unauthenticated advisory findings, and the advisory keyspace) and
// computes the three measurements. It only READS — the instrument changes nothing.
func measure(ctx context.Context, tenant store.TenantID, assetID uuid.UUID, read credscan.HostRead) (credscan.Report, error) {
	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return credscan.Report{}, errors.New("APP_DATABASE_URL is not set (the same value cvap-core uses)")
	}
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return credscan.Report{}, fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	// Installed inventory indexed by source package; first wins for a multi-arch
	// duplicate — the version is the same across arches for this comparison.
	installed := map[string]string{}
	for _, p := range read.Packages {
		if _, ok := installed[p.Source]; !ok {
			installed[p.Source] = p.Version
		}
	}

	report := credscan.Report{
		Host:     read.Release.Get("PRETTY_NAME"),
		Release:  read.Release,
		Packages: len(read.Packages),
	}
	if report.Host == "" {
		report.Host = assetID.String()
	}

	err = db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		adv := store.Advisories{}

		// Credentialed ground truth (measurement 3's truth side): exact inventory,
		// exact release, same matching rules as the unauthenticated path.
		fixes := func(release, pkg string) ([]credscan.AdvisoryFix, error) {
			rows, err := adv.FixesFor(ctx, c, release, pkg)
			if err != nil {
				return nil, err
			}
			out := make([]credscan.AdvisoryFix, len(rows))
			for i, r := range rows {
				out[i] = credscan.AdvisoryFix{AdvisoryRef: r.AdvisoryRef, FixedVersion: r.FixedVersion, Comparator: r.Comparator}
			}
			return out, nil
		}
		vulns := func(ref string) ([]string, error) {
			rows, err := adv.AdvisoryVulnDefs(ctx, c, ref)
			if err != nil {
				return nil, err
			}
			cves := make([]string, len(rows))
			for i, r := range rows {
				cves[i] = r.CVE
			}
			return cves, nil
		}
		truth, err := credscan.CredentialedTruth(read.Packages, read.Release.Codename, fixes, vulns)
		if err != nil {
			return err
		}
		report.TruthSkipped = truth.Skipped

		// Measurement 3: FP/FN of the unauthenticated findings vs the truth.
		unauthRows, err := (store.Findings{}).AdvisoryKeysForAsset(ctx, c, assetID)
		if err != nil {
			return err
		}
		unauth := make([]credscan.FindingKey, len(unauthRows))
		for i, r := range unauthRows {
			unauth[i] = credscan.FindingKey{Package: r.Package, CVE: r.CVE}
		}
		report.Accuracy = credscan.Diff(unauth, truth.Keys)

		// Network-exposed subset (S39 "report both"): restrict the credentialed truth
		// to installed packages that back an observed open service, so the comparison
		// is like-for-like with what an unauthenticated scan could have seen. The
		// observed products come from the asset's identified services; their candidate
		// source packages come from the product->package map; the subset is the
		// installed packages whose source is in that set. Computed for the report only
		// — the instrument's truth logic is unchanged (Diff and CredentialedTruth are
		// the same functions).

		// Measurements 1 and 2 come off the asset detail.
		detail, err := (store.Assets{}).GetDetail(ctx, c, assetID)
		if err != nil {
			return err
		}
		if detail.DistroRelease != nil {
			report.BandResolved = *detail.DistroRelease
		}
		report.ReleaseVerdict = credscan.CompareRelease(report.BandResolved, read.Release.Codename)

		var svcs []credscan.ServiceVersion
		exposedSrc := map[string]bool{} // installed source pkgs backing an observed service
		seenProduct := map[string]bool{}
		for _, s := range detail.Services {
			if s.Product == "" {
				continue // no product to map; not a version-extraction subject
			}
			candidates, err := adv.PackagesForProduct(ctx, c, s.Product)
			if err != nil {
				return err
			}
			if !seenProduct[s.Product] {
				seenProduct[s.Product] = true
				report.ExposedProducts = append(report.ExposedProducts, s.Product)
			}
			for _, cand := range candidates {
				if _, installedHere := installed[cand]; installedHere {
					exposedSrc[cand] = true
				}
			}
			name := s.Service
			if name == "" {
				name = fmt.Sprintf("%s/%d", s.Protocol, s.Port)
			}
			svcs = append(svcs, credscan.BuildServiceVersion(name, s.Product, s.Version, candidates, installed))
		}
		report.Versions = credscan.ClassifyVersion(svcs)

		// Exposed-subset truth: the same CredentialedTruth over only the installed
		// packages that back an observed service.
		var exposedPkgs []credscan.Package
		for _, p := range read.Packages {
			if exposedSrc[p.Source] {
				exposedPkgs = append(exposedPkgs, p)
			}
		}
		report.ExposedPackages = len(exposedPkgs)
		exposedTruth, err := credscan.CredentialedTruth(exposedPkgs, read.Release.Codename, fixes, vulns)
		if err != nil {
			return err
		}
		report.Exposed = credscan.Diff(unauth, exposedTruth.Keys)
		return nil
	})
	if err != nil {
		return credscan.Report{}, err
	}
	return report, nil
}

// printInventory reports the host facts a credentialed read yields, with no database
// access — the authoritative /etc/os-release and dpkg answer, independent of the
// advisory pipeline. With grep set, it lists installed packages whose source or
// binary name contains the substring.
func printInventory(read credscan.HostRead, grep string) {
	fmt.Printf("host read: %s\n", read.Release.Get("PRETTY_NAME"))
	fmt.Printf("  /etc/os-release: ID=%s VERSION_ID=%s VERSION_CODENAME=%s\n",
		read.Release.ID, read.Release.VersionID, read.Release.Codename)
	fmt.Printf("  packages installed: %d\n", len(read.Packages))
	if grep == "" {
		return
	}
	fmt.Printf("  packages matching %q:\n", grep)
	for _, p := range read.Packages {
		if strings.Contains(p.Source, grep) || strings.Contains(p.Binary, grep) {
			fmt.Printf("    source=%-20s binary=%-24s version=%s\n", p.Source, p.Binary, p.Version)
		}
	}
}

// releaseKey is the advisory keyspace's key for a host's release: the codename for
// dpkg distros (jammy/resolute), and ID+major for rpm distros, which carry no
// codename (almalinux 10.2 -> "almalinux-10", matching the thin ALSA import).
func releaseKey(rel credscan.OSRelease) string {
	if rel.Codename != "" {
		return rel.Codename
	}
	major := rel.VersionID
	if i := strings.IndexByte(major, '.'); i >= 0 {
		major = major[:i]
	}
	return rel.ID + "-" + major
}

// truthReport computes and prints the credentialed advisory finding set — exact
// installed versions matched against the keyspace with the release's own comparator
// (dpkg or rpm, ADR-062). No unauthenticated Diff: this is for a host with no unauth
// scan (the rpm/B26 host), where the point is that the credentialed matcher runs
// correctly against real advisories, not a comparison to inference.
func truthReport(ctx context.Context, tenant store.TenantID, read credscan.HostRead) error {
	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return errors.New("APP_DATABASE_URL is not set")
	}
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer db.Close()

	relKey := releaseKey(read.Release)
	var truth credscan.TruthResult
	err = db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		adv := store.Advisories{}
		fixes := func(release, pkg string) ([]credscan.AdvisoryFix, error) {
			rows, e := adv.FixesFor(ctx, c, release, pkg)
			if e != nil {
				return nil, e
			}
			out := make([]credscan.AdvisoryFix, len(rows))
			for i, r := range rows {
				out[i] = credscan.AdvisoryFix{AdvisoryRef: r.AdvisoryRef, FixedVersion: r.FixedVersion, Comparator: r.Comparator}
			}
			return out, nil
		}
		vulns := func(ref string) ([]string, error) {
			rows, e := adv.AdvisoryVulnDefs(ctx, c, ref)
			if e != nil {
				return nil, e
			}
			cves := make([]string, len(rows))
			for i, r := range rows {
				cves[i] = r.CVE
			}
			return cves, nil
		}
		var e error
		truth, e = credscan.CredentialedTruth(read.Packages, relKey, fixes, vulns)
		return e
	})
	if err != nil {
		return err
	}

	fmt.Printf("Credentialed truth — %s (release key %q), %d packages read\n",
		read.Release.Get("PRETTY_NAME"), relKey, len(read.Packages))
	fmt.Printf("  credentialed advisory findings (exact installed version matched via %s comparator): %d\n",
		map[bool]string{true: "rpm", false: "dpkg"}[read.Release.IsRPMFamily()], len(truth.Keys))
	byPkg := map[string]int{}
	for _, k := range truth.Keys {
		byPkg[k.Package]++
	}
	pkgs := make([]string, 0, len(byPkg))
	for p := range byPkg {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		fmt.Printf("    %-16s %d\n", p, byPkg[p])
	}
	for _, k := range truth.Keys {
		fmt.Printf("      %s  %s\n", k.Package, k.CVE)
	}
	if len(truth.Skipped) > 0 {
		fmt.Printf("  could not judge %d candidate fix(es)\n", len(truth.Skipped))
	}
	return nil
}

// loadCredential reads the credential material into a runtime-held Credential
// (ADR-038: func-backed, zeroisable), scoped to the one host. A private key file if
// --key is given, else the password from CVAP_CREDSCAN_PASSWORD. The material is
// owned by the Credential from here on; nothing else retains it.
func loadCredential(host, keyPath string, ttl time.Duration) (*scanpoint.Credential, error) {
	scopeHost := []string{host}
	expires := time.Now().Add(ttl + time.Minute)
	if keyPath != "" {
		// #nosec G304 -- -key is an operator flag on a one-off instrument run by
		// the person who owns the key; no request input reaches this path.
		material, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("reading key %q: %w", keyPath, err)
		}
		return scanpoint.NewCredential("credscan-instrument", "credscan", "ssh-key", scopeHost, expires, material), nil
	}
	pw := os.Getenv("CVAP_CREDSCAN_PASSWORD")
	if pw == "" {
		return nil, errors.New("no credential: pass --key or set CVAP_CREDSCAN_PASSWORD")
	}
	return scanpoint.NewCredential("credscan-instrument", "credscan", "ssh-password", scopeHost, expires, []byte(pw)), nil
}

// authMethod builds an ssh.AuthMethod from the runtime-held credential. It reveals
// the material only to construct the method and does not retain the revealed slice.
// The ssh library copies key/password bytes into its own buffers (the ADR-038 caveat
// that a zeroise is one layer), which is why the credential lives only for the job.
func authMethod(cred *scanpoint.Credential) (ssh.AuthMethod, error) {
	switch cred.Kind {
	case "ssh-key":
		signer, err := ssh.ParsePrivateKey(cred.Reveal())
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	case "ssh-password":
		return ssh.Password(string(cred.Reveal())), nil
	default:
		return nil, fmt.Errorf("unknown credential kind %q", cred.Kind)
	}
}

// loadScope reads a scope file into allow and exclusion rule lists. One rule per
// line; a leading '!' is an exclusion; '#' begins a comment; blanks are ignored.
// This is the operator-written policy text scope.Permits parses on the rule side.
func loadScope(path string) (allowed, exclusions []string, err error) {
	// #nosec G304 -- -scope is an operator flag naming lab/scope.txt; the file
	// is read to NARROW what the instrument may reach, not to widen it.
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("scope file: %w", err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "!") {
			exclusions = append(exclusions, strings.TrimSpace(line[1:]))
			continue
		}
		allowed = append(allowed, line)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("scope file: %w", err)
	}
	return allowed, exclusions, nil
}
