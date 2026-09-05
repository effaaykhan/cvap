// Command cvap-cli is the CVAP operator command line.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := logging.New(os.Stderr, logging.Options{Level: slog.LevelInfo})

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "dev-ca":
		if err := devCA(log, os.Args[2:]); err != nil {
			log.Error("dev-ca failed", slog.Any("error", err))
			os.Exit(1)
		}
	case "bootstrap":
		if err := bootstrap(log, os.Args[2:]); err != nil {
			log.Error("bootstrap failed", slog.Any("error", err))
			os.Exit(1)
		}
	case "enroll-token":
		if err := enrollToken(log, os.Args[2:]); err != nil {
			log.Error("enroll-token failed", slog.Any("error", err))
			os.Exit(1)
		}
	default:
		log.Error("unknown command", slog.String("command", os.Args[1]))
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `cvap-cli %s

  dev-ca <dir>       Generate a DEVELOPMENT certificate authority into <dir>.

  bootstrap          Create the first tenant, an admin user (with a generated
                     first-login password), an operator role and a default zone.
                     Run once, on the Core host. Needs APP_DATABASE_URL.
                     --admin-email is required.

  enroll-token       Issue a single-use enrollment token for a zone, printed
                     once. Needs APP_DATABASE_URL, --tenant and --zone (both
                     from bootstrap's output).

`, version)
}

// devCA writes a self-signed CA for local use.
//
// Development only, and the warning is not boilerplate. This key mints
// identities into a scan point fleet, and Core holds a complete map of a
// customer's exploitable weaknesses plus credentials to their estate — so a CA
// key on a developer's disk is not a rough edge, it is the whole compromise
// (architecture-v2 §18.3). A real deployment supplies its own anchor, which is
// what ADR-018 means by the trust anchor being configuration rather than an
// assumption baked into the binary.
//
// Twenty-four hours, deliberately short. A development CA that outlives the
// afternoon is one that ends up in a deployment.
func devCA(log *slog.Logger, args []string) error {
	dir := "./secrets"
	if len(args) > 0 && args[0] != "" {
		dir = args[0]
	}
	dir = filepath.Clean(dir)
	// The argument is a path an operator typed, and writing there is the whole
	// point of the command — but it is still argv, so it is cleaned and refused
	// if it climbs. gosec's taint analysis is right that os.Args reaches
	// MkdirAll; this is the check that makes the reach harmless rather than an
	// argument about why it is fine.
	for _, part := range strings.Split(dir, string(filepath.Separator)) {
		if part == ".." {
			return fmt.Errorf("cvap-cli: refusing a path that climbs out of itself: %q", dir)
		}
	}
	// #nosec G703 -- cleaned and rejected above; the command exists to create a
	// directory at the operator's chosen path.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "cvap development CA", 24*time.Hour)
	if err != nil {
		return err
	}
	log.Warn("generated a DEVELOPMENT certificate authority; never use this key anywhere real",
		slog.String("cert", certPath),
		slog.String("key", keyPath),
		slog.Duration("valid_for", 24*time.Hour))
	return nil
}
