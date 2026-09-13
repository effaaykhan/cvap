package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
)

// The resolution queue's operator surface (ADR-097, B39).
//
// ADR-007 says conflicting or insufficient evidence goes to the queue and an
// operator adjudicates; ADR-094/096 route every address handover and every
// unclassifiable contradiction there. Until now nothing could close an item
// but the system's own rotation, lapse and expiry. These are the operator's
// verbs. None of them verifies anything — on banner data nothing can (B44) —
// they record a human decision with the human's identity beside it, which is
// the only kind of verification an observed SSH host key gets today.

// QueueItem is one parked (observation, key) pair, as the copied evidence
// describes it. Source is the service the key came from ("22/tcp"), stored
// canonical at enqueue (migration 0046) — one spelling for every reader.
type QueueItem struct {
	ResolutionID  uuid.UUID
	ObservationID *uuid.UUID
	KeyType       domain.IdentityKeyType
	KeyValue      string
	Source        string
	EnqueuedAt    time.Time
	Candidates    []uuid.UUID     // set by pendingAt (the verbs)
	Payload       json.RawMessage // fetched per recorded key by the verbs; never by the listing
	Evidence      string          // "service · product version", bounded, from the copied payload
}

// ParkedKey is one distinct (type, service, value) parked at an address, with
// how many items carry it — the unit an operator decides on and the unit a
// verb records, aggregated in SQL over EVERY item at the address so nothing
// a verb writes was unseen. The review measured the verbs recording a key
// from the sixty-first item while the screen showed fifty.
type ParkedKey struct {
	KeyType   domain.IdentityKeyType
	Source    string
	Value     string
	Items     int
	FirstSeen time.Time
	LastSeen  time.Time
}

// HeldKey is what a candidate asset holds live on a service — the key a
// "same host" decision retires. Shown so the operator sees what the verb
// destroys before, not after.
type HeldKey struct {
	AssetID uuid.UUID
	KeyType domain.IdentityKeyType
	Source  string
	Value   string
}

// QueueGroup is everything pending at one address naming one candidate set —
// the unit an operator decides on. Candidates is the set the verdicts named
// (usually one asset; empty when nothing held the address).
type QueueGroup struct {
	Address    string
	Candidates []uuid.UUID
	Reason     string // the latest verdict's reason
	FirstSeen  time.Time
	LastSeen   time.Time
	Items      []QueueItem // the newest MaxItemsPerGroup, for detail
	ItemsTotal int         // every pending item at the address
	// Keys, Held and Ambiguous are computed over ALL pending items at the
	// address, not the rendered page: they are what the decision turns on.
	Keys           []ParkedKey // the first MaxKeysPerGroup; KeysTotal is the full count
	KeysTotal      int
	Held           []HeldKey
	Ambiguous      []AmbiguousService // the first MaxKeysPerGroup; AmbiguousTotal is the full count
	AmbiguousTotal int
}

// AmbiguousService is one service at an address with several parked values
// of one key type; the operator must name which value is the host.
type AmbiguousService struct {
	KeyType     domain.IdentityKeyType
	Source      string
	Values      []string // the first MaxKeysPerGroup; ValuesTotal is the full count
	ValuesTotal int
}

// ListPending returns the pending queue grouped by address, newest address
// first, at most `limit` addresses. The whole tenant's pending set is read
// (bounded by the same growth the Health counters report) and grouped here,
// because the operator acts on an address, not on an item.
//
// Bounded in SQL, not in memory: the newest `limit` addresses, and at most
// MaxItemsPerGroup items each (ItemsTotal carries the true count). The review
// measured the unbounded version loading 24,000 payloads for one page — the
// operator's own screen becoming the load an attacker's parks impose.
//
// `only`, when set, narrows the listing to one address — the way back to a
// contest an attacker's newer parks have pushed off the first page (the
// ordering key is one the attacker refreshes every scan). The full pending
// address count travels beside the page (PendingAddresses).
func (ResolutionQueue) ListPending(ctx context.Context, c *Conn, limit int, only string) ([]QueueGroup, error) {
	if limit <= 0 {
		limit = 200
	}
	var onlyArg any
	if only != "" {
		onlyArg = only
	}
	const q = `
		WITH addrs AS (
		    SELECT address, max(enqueued_at) AS last_seen
		      FROM asset_resolution_queue
		     WHERE tenant_id = $1 AND state = 'pending' AND address IS NOT NULL
		       AND ($4::inet IS NULL OR address = host($4::inet)::inet)
		     GROUP BY address
		     ORDER BY last_seen DESC, address
		     LIMIT $2),
		ranked AS (
		    SELECT q.resolution_id, q.observation_id, q.key_type::text AS key_type, q.key_value,
		           q.candidate_asset_ids, q.conflict_reason, q.enqueued_at, host(q.address) AS address,
		           coalesce(q.source, '') AS source,
		           left(coalesce(q.observed_payload ->> 'service', ''), 32) AS svc,
		           left(coalesce(q.observed_payload ->> 'product', ''), 64) AS product,
		           left(coalesce(q.observed_payload ->> 'version', ''), 32) AS version,
		           row_number() OVER (PARTITION BY q.address ORDER BY q.enqueued_at DESC, q.resolution_id) AS rn,
		           count(*) OVER (PARTITION BY q.address) AS total
		      FROM asset_resolution_queue q
		      JOIN addrs a ON a.address = q.address
		     WHERE q.tenant_id = $1 AND q.state = 'pending')
		SELECT resolution_id, observation_id, key_type, key_value,
		       candidate_asset_ids, conflict_reason, enqueued_at, address, source, svc, product, version, total
		  FROM ranked
		 WHERE rn <= $3
		 ORDER BY address, enqueued_at DESC, resolution_id`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), limit, MaxItemsPerGroup, onlyArg)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	byAddr := map[string]*QueueGroup{}
	var order []string
	for rows.Next() {
		var (
			it                    QueueItem
			obs                   *uuid.UUID
			kt                    string
			cands                 []uuid.UUID
			reason                string
			addr                  string
			svc, product, version string
			total                 int
		)
		if err := rows.Scan(&it.ResolutionID, &obs, &kt, &it.KeyValue, &cands, &reason, &it.EnqueuedAt, &addr, &it.Source, &svc, &product, &version, &total); err != nil {
			return nil, mapError(err)
		}
		it.ObservationID = obs
		it.KeyType = domain.IdentityKeyType(kt)
		it.Evidence = evidenceLine(svc, product, version)
		_ = cands // the candidate set is aggregated over every item below
		g, ok := byAddr[addr]
		if !ok {
			g = &QueueGroup{Address: addr, Reason: reason, FirstSeen: it.EnqueuedAt, LastSeen: it.EnqueuedAt, ItemsTotal: total}
			byAddr[addr] = g
			order = append(order, addr)
		}
		if it.EnqueuedAt.Before(g.FirstSeen) {
			g.FirstSeen = it.EnqueuedAt
		}
		if it.EnqueuedAt.After(g.LastSeen) {
			g.LastSeen, g.Reason = it.EnqueuedAt, reason
		}
		g.Items = append(g.Items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	// The decision-bearing facts, over EVERY pending item at the listed
	// addresses, in SQL: the distinct parked keys (what a verb records), the
	// candidates (what "same host" may name), what each candidate holds on
	// the contested services (what "same host" retires), and the ambiguous
	// services. The review measured each of these computed over the rendered
	// fifty: a verb recording an unseen key as confirmed, a real holder with
	// no "same host" button, a choice not offered for a value in the tail.
	const keysQ = `
		WITH k AS (
		    SELECT host(address) AS address, key_type::text AS key_type, coalesce(source, '') AS source, key_value,
		           count(*) AS items, min(enqueued_at) AS first_seen, max(enqueued_at) AS last_seen,
		           row_number() OVER (PARTITION BY address ORDER BY key_type, source, key_value) AS rn,
		           count(*) OVER (PARTITION BY address) AS total
		      FROM asset_resolution_queue
		     WHERE tenant_id = $1 AND state = 'pending' AND address = ANY ($2::inet[])
		       AND key_type <> 'ip_window'
		     GROUP BY address, key_type, source, key_value)
		SELECT address, key_type, source, key_value, items, first_seen, last_seen, total
		  FROM k WHERE rn <= $3
		 ORDER BY 1, 2, 3, 4`
	krows, err := c.Query(ctx, keysQ, c.Tenant().UUID(), order, MaxKeysPerGroup)
	if err != nil {
		return nil, mapError(err)
	}
	defer krows.Close()
	for krows.Next() {
		var addr, kt string
		var k ParkedKey
		var total int
		if err := krows.Scan(&addr, &kt, &k.Source, &k.Value, &k.Items, &k.FirstSeen, &k.LastSeen, &total); err != nil {
			return nil, mapError(err)
		}
		k.KeyType = domain.IdentityKeyType(kt)
		if g, ok := byAddr[addr]; ok {
			g.Keys = append(g.Keys, k)
			g.KeysTotal = total
			if k.FirstSeen.Before(g.FirstSeen) {
				g.FirstSeen = k.FirstSeen
			}
		}
	}
	if err := krows.Err(); err != nil {
		return nil, mapError(err)
	}
	const candQ = `
		SELECT host(address), c
		  FROM asset_resolution_queue, unnest(candidate_asset_ids) AS c
		 WHERE tenant_id = $1 AND state = 'pending' AND address = ANY ($2::inet[])
		 GROUP BY 1, 2
		 ORDER BY 1, 2`
	crows, err := c.Query(ctx, candQ, c.Tenant().UUID(), order)
	if err != nil {
		return nil, mapError(err)
	}
	defer crows.Close()
	for crows.Next() {
		var addr string
		var id uuid.UUID
		if err := crows.Scan(&addr, &id); err != nil {
			return nil, mapError(err)
		}
		if g, ok := byAddr[addr]; ok {
			g.Candidates = appendUnique(g.Candidates, id)
		}
	}
	if err := crows.Err(); err != nil {
		return nil, mapError(err)
	}
	const heldQ = `
		SELECT address, asset_id, key_type, source, key_value FROM (
		SELECT host(q.address) AS address, k.asset_id, k.key_type::text AS key_type,
		       CASE WHEN k.merge_evidence_payload ? 'port'
		            THEN (k.merge_evidence_payload ->> 'port') || '/' ||
		                 lower(btrim(coalesce(nullif(k.merge_evidence_payload ->> 'protocol', ''), 'tcp')))
		            ELSE '' END AS source,
		       k.key_value,
		       row_number() OVER (PARTITION BY q.address ORDER BY k.asset_id, k.key_type, k.key_value) AS rn
		  FROM (SELECT DISTINCT address, c AS asset_id, key_type, source
		          FROM asset_resolution_queue, unnest(candidate_asset_ids) AS c
		         WHERE tenant_id = $1 AND state = 'pending' AND address = ANY ($2::inet[])
		           AND key_type <> 'ip_window') q
		  JOIN asset_identity_keys k
		    ON k.tenant_id = $1 AND k.asset_id = q.asset_id AND k.key_type = q.key_type AND k.valid_to IS NULL
		 WHERE (k.merge_evidence_payload ->> 'port') || '/' ||
		       lower(btrim(coalesce(nullif(k.merge_evidence_payload ->> 'protocol', ''), 'tcp'))) = q.source
		) h WHERE rn <= $3
		 ORDER BY 1, 2, 3, 4`
	// Budgeted PER ADDRESS, not per page: one page-wide LIMIT spent in
	// address-text order let a flood address consume the budget and a real
	// contest render with no "currently held" line (measured). The cut is in
	// SQL so the rows streamed match the rows kept; the Go guard is the same
	// bound stated twice.
	hrows, err := c.Query(ctx, heldQ, c.Tenant().UUID(), order, MaxKeysPerGroup)
	if err != nil {
		return nil, mapError(err)
	}
	defer hrows.Close()
	for hrows.Next() {
		var addr, kt string
		var h HeldKey
		if err := hrows.Scan(&addr, &h.AssetID, &kt, &h.Source, &h.Value); err != nil {
			return nil, mapError(err)
		}
		h.KeyType = domain.IdentityKeyType(kt)
		if g, ok := byAddr[addr]; ok && len(g.Held) < MaxKeysPerGroup {
			g.Held = append(g.Held, h)
		}
	}
	if err := hrows.Err(); err != nil {
		return nil, mapError(err)
	}
	const amb = `
		WITH a AS (
		    SELECT host(address) AS address, key_type::text AS key_type, source,
		           (array_agg(DISTINCT key_value ORDER BY key_value))[1:$3] AS vals, count(DISTINCT key_value) AS vtotal,
		           row_number() OVER (PARTITION BY address ORDER BY key_type, source) AS rn,
		           count(*) OVER (PARTITION BY address) AS total
		      FROM asset_resolution_queue
		     WHERE tenant_id = $1 AND state = 'pending' AND address = ANY ($2::inet[])
		       AND key_type <> 'ip_window' AND source IS NOT NULL
		     GROUP BY address, key_type, source
		    HAVING count(DISTINCT key_value) > 1)
		SELECT address, key_type, source, vals, vtotal, total FROM a WHERE rn <= $3
		 ORDER BY 1, 2, 3`
	// Only for groups a decision can cover: a group with more keys than a
	// page renders can only be discarded, so its choices are unusable by
	// construction — and shipping them was measured at 400 MB for one page.
	// With every listed group under the key cap, the values it carries are
	// bounded by that cap too.
	var decidable []string
	for _, a := range order {
		if g := byAddr[a]; g.KeysTotal <= MaxKeysPerGroup {
			decidable = append(decidable, a)
		}
	}
	if len(decidable) > 0 {
		if err := listAmbiguous(ctx, c, amb, decidable, byAddr); err != nil {
			return nil, err
		}
	}
	out := make([]QueueGroup, 0, len(order))
	for _, a := range order {
		out = append(out, *byAddr[a])
	}
	// Newest contest first: the one an operator has not seen yet.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].LastSeen.After(out[j-1].LastSeen); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

// listAmbiguous fills each decidable group's ambiguous services.
func listAmbiguous(ctx context.Context, c *Conn, amb string, decidable []string, byAddr map[string]*QueueGroup) error {
	arows, err := c.Query(ctx, amb, c.Tenant().UUID(), decidable, MaxKeysPerGroup)
	if err != nil {
		return mapError(err)
	}
	defer arows.Close()
	for arows.Next() {
		var addr, kt, src string
		var values []string
		var vtotal, total int
		if err := arows.Scan(&addr, &kt, &src, &values, &vtotal, &total); err != nil {
			return mapError(err)
		}
		if g, ok := byAddr[addr]; ok {
			g.Ambiguous = append(g.Ambiguous, AmbiguousService{KeyType: domain.IdentityKeyType(kt), Source: src, Values: values, ValuesTotal: vtotal})
			g.AmbiguousTotal = total
		}
	}
	return mapError(arows.Err())
}

// MaxItemsPerGroup bounds the items a queue listing carries per address.
const MaxItemsPerGroup = 50

// MaxKeysPerGroup bounds the distinct parked keys a listing carries per
// address, and the values an ambiguous service offers: "bounded by services"
// is a bound the attacker chooses (one host can answer SSH on any number of
// ports), and the review measured twenty thousand keys in one group turning
// the operator's screen into 33 MB. The totals travel beside the lists.
const MaxKeysPerGroup = 200

// ErrNothingToRecord is returned by "different host" when the decision would
// record no key on the new asset — every parked key is live on another asset
// (an echo of the occupant's own public fingerprint), or the group is
// address-only. A keyless asset holding the address can never merge and
// leaves the previous holder without trust (measured); the right verb there
// is "same host" on the holder, or discard.
var ErrNothingToRecord = fmt.Errorf("store: that decision would record no key on the new asset")

// ErrTooManyKeys is returned when an address carries more distinct parked
// keys than a listing renders (MaxKeysPerGroup): a decision must cover exactly
// what the operator saw, and every cap that let a verb act beyond the page
// was measured recording an unseen key as confirmed. The exit is `discard`.
var ErrTooManyKeys = fmt.Errorf("store: more parked keys at the address than a decision can cover")

// evidenceLine is the one bounded line of the copied payload an operator
// decides on. Target-controlled text, truncated in SQL, rendered as text.
func evidenceLine(svc, product, version string) string {
	out := svc
	if product != "" {
		out += " · " + product
	}
	if version != "" {
		out += " " + version
	}
	return out
}

func appendUnique(ids []uuid.UUID, id uuid.UUID) []uuid.UUID {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

// Resolution is what an operator's verb did.
type Resolution struct {
	AssetID           uuid.UUID // the asset the group's observations now belong to
	ItemsClosed       int64
	KeysRecorded      []string // "type@source value"
	KeysRetired       []string
	KeysHeldElsewhere []string // parked keys live on another asset, left there (B40)
	KeysDiscarded     []string // parked keys the operator's choice rejected
}

// KeyChoice names which parked key is the host on ONE service: the service
// is part of the choice, because one public fingerprint can be parked on two
// ports and a value alone was measured binding to the wrong one — the
// operator's correct answer refused, the attacker's accepted.
type KeyChoice struct {
	Type   domain.IdentityKeyType
	Source string
	Value  string
}

// normaliseChoice folds an operator-typed choice onto the stored grammar:
// key types and sources are lowercase and untrimmed in the store, and a
// choice spelled "22/TCP" can never name a different service than "22/tcp".
func normaliseChoice(ch KeyChoice) KeyChoice {
	ch.Type = domain.IdentityKeyType(strings.ToLower(strings.TrimSpace(string(ch.Type))))
	ch.Source = strings.ToLower(strings.TrimSpace(ch.Source))
	ch.Value = strings.TrimSpace(ch.Value)
	return ch
}

// ErrNothingPending is returned when the address has no pending item naming
// the asset an operator chose (or none at all): the queue moved under them.
var ErrNothingPending = fmt.Errorf("store: nothing pending at that address for that asset")

// ErrAmbiguousGroup is returned when the parked group carries two different
// values of one key type from one service — two hosts answered on one port
// (ADR-096) — and the operator named no key. Neither verb can say which is
// the host; the operator can, by naming the key value (`chosen`): the other
// keyed items of that service then close as `discarded`. Nothing is written
// on refusal.
var ErrAmbiguousGroup = fmt.Errorf("store: the parked group carries two keys from one service; name which is the host")

// ErrKeyNotParked is returned when the operator named a key that is not
// parked at the address.
var ErrKeyNotParked = fmt.Errorf("store: that key is not parked at the address")

// AmbiguousServiceError names the services a decision could not settle: each
// carries two parked values of one key type and no choice named one of them.
// `errors.Is(err, ErrAmbiguousGroup)` still holds, so a caller that only needs
// the class is unaffected; a caller answering a human needs the names, because
// the alternative is telling an API caller "some service, somewhere" and
// leaving the listing as the only way to find out which.
type AmbiguousServiceError struct {
	Services []string // "ssh_hostkey on 22/tcp", sorted
}

func (e *AmbiguousServiceError) Error() string {
	return ErrAmbiguousGroup.Error() + ": " + strings.Join(e.Services, ", ")
}

func (e *AmbiguousServiceError) Is(target error) bool { return target == ErrAmbiguousGroup }

// chooseKeys applies an operator's choices to a group, one per ambiguous
// (type, service): items of the chosen service carrying a different value
// are returned as `drop`; the rest as `keep`. A group still ambiguous after
// the choices — a service nobody named — is ErrAmbiguousGroup (the review
// measured a group with two ambiguous services having no exit when one
// choice was all the request could carry); a choice naming a key not parked
// on that service is ErrKeyNotParked. With no choice and no ambiguity
// everything is kept.
func chooseKeys(items []QueueItem, chosen []KeyChoice) (keep []QueueItem, drop []uuid.UUID, err error) {
	keep = items
	for _, ch := range chosen {
		ch = normaliseChoice(ch)
		if ch.Value == "" {
			continue
		}
		found := false
		for _, it := range keep {
			if it.KeyType == ch.Type && it.Source == ch.Source && it.KeyValue == ch.Value {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, ErrKeyNotParked
		}
		var next []QueueItem
		for _, it := range keep {
			if it.KeyType == ch.Type && it.Source == ch.Source && it.KeyValue != ch.Value {
				drop = append(drop, it.ResolutionID)
				continue
			}
			next = append(next, it)
		}
		keep = next
	}
	if unsettled := ambiguousServices(keep); len(unsettled) > 0 {
		return nil, nil, &AmbiguousServiceError{Services: unsettled}
	}
	return keep, drop, nil
}

// ambiguousServices names every (type, service) among items carrying two
// different values — domain.twoValuesOnOneService over queue items, except
// that it says WHICH, because a refusal an API caller cannot act on sends
// them back to the listing to work out what the store already knew. Sorted,
// so one shape refuses the same way twice.
func ambiguousServices(items []QueueItem) []string {
	seen := map[string]string{}
	amb := map[string]bool{}
	for _, it := range items {
		if it.KeyType == domain.KeyIPWindow || it.KeyType.Strength() < 2 {
			continue
		}
		id := string(it.KeyType) + " on " + it.Source
		if v, ok := seen[id]; ok && v != it.KeyValue {
			amb[id] = true
			continue
		}
		seen[id] = it.KeyValue
	}
	out := make([]string, 0, len(amb))
	for s := range amb {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ResolveSameHost is the operator's "same host" (ADR-097): every key parked at
// the address that names the asset is the asset's — the held key of the same
// service is retired and the parked one recorded with provenance `confirmed`,
// the items close as `merged` naming the operator, and the parked observations
// re-enter the sweep, where they now attach because the key they carry is the
// one the asset holds. A key already live on ANOTHER asset is not moved: that
// is a merge of two assets, which this verb does not perform (B40); its item
// closes as `discarded` so the observation stays out of the sweep rather than
// re-parking, and the response names it.
//
// seenThrough is the listing's `last_seen` the operator acted on: items parked
// after it are not theirs to decide — a key parked between the render and the
// click was measured recorded as confirmed from a screen that showed no keys —
// and stay pending, so the address is listed again. Zero means no bound.
func (ResolutionQueue) ResolveSameHost(ctx context.Context, c *Conn, address string, assetID uuid.UUID, chosen []KeyChoice, seenThrough time.Time, actor *uuid.UUID, at time.Time) (Resolution, error) {
	res := Resolution{AssetID: assetID}
	// The QUESTION is the whole address — every pending item there is what
	// the operator was shown — and the refusal is decided over it. The WRITE
	// is narrowed to the items naming this asset. The review measured the
	// guard evaluated over the narrowed set: two keys on one port whose
	// items named different candidate sets (CloseStale had released the
	// occupant's hold between the two parks) listed as ambiguous, and the
	// verb accepted "no choice" — recording the attacker's key as confirmed.
	all, err := pendingAt(ctx, c, address, seenThrough)
	if err != nil {
		return res, err
	}
	// A decision covers exactly the keys the listing renders. More than
	// that is refused: the exit is `discard`.
	if distinctKeys(all) > MaxKeysPerGroup {
		return res, ErrTooManyKeys
	}
	var mine []QueueItem
	for _, it := range all {
		if names(assetID, it.Candidates) {
			mine = append(mine, it)
		}
	}
	if len(mine) == 0 {
		return res, ErrNothingPending
	}
	keepAll, dropAll, err := chooseKeys(all, chosen)
	if err != nil {
		return res, err
	}
	kept := map[uuid.UUID]bool{}
	for _, it := range keepAll {
		kept[it.ResolutionID] = true
	}
	dropped := map[uuid.UUID]bool{}
	for _, id := range dropAll {
		dropped[id] = true
	}
	// Only the operator's explicit choice discards; absence from `kept`
	// never does (measured: a second capped window closed the host's own
	// keys as discarded under a choice nobody made). Items naming another
	// candidate stay pending — not this decision's to close.
	var items []QueueItem
	var discarded []uuid.UUID
	for _, it := range mine {
		switch {
		case kept[it.ResolutionID]:
			items = append(items, it)
		case dropped[it.ResolutionID]:
			discarded = append(discarded, it.ResolutionID)
			res.KeysDiscarded = append(res.KeysDiscarded, string(it.KeyType)+"@"+it.Source+" "+it.KeyValue)
		}
	}
	// The items this decision closes are the ones it READ: a row a
	// concurrent sweep parks between the read and the close is not the
	// operator's to close (measured: closed under their name, unexamined).
	closing := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		closing = append(closing, it.ResolutionID)
	}
	// One record per distinct key, not per item: the work is bounded by the
	// keys the operator saw, and the items close in one statement.
	keyed := items
	items = firstOfEachKey(items)
	for _, it := range items {
		if it.KeyType == domain.KeyIPWindow || it.KeyType.Strength() < 2 {
			continue
		}
		holder, err := (AssetIdentityKeys{}).LiveByValue(ctx, c, it.KeyType, it.KeyValue)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return res, err
		}
		if err == nil && holder == assetID {
			continue // already the asset's: a re-sighting parked with the group
		}
		if err == nil && holder != assetID {
			discarded = append(discarded, discardAll(keyed, it)...)
			res.KeysHeldElsewhere = append(res.KeysHeldElsewhere, string(it.KeyType)+"@"+it.Source+" "+it.KeyValue)
			continue
		}
		port, proto := SourcePortProto(it.Source)
		retired, err := (AssetIdentityKeys{}).Retire(ctx, c, assetID, it.KeyType, port, proto, at)
		if err != nil {
			return res, err
		}
		payload, err := payloadOf(ctx, c, it.ResolutionID)
		if err != nil {
			return res, err
		}
		k := domain.IdentityKey{Type: it.KeyType, Value: it.KeyValue, Source: it.Source, Payload: payload}
		if it.ObservationID != nil {
			k.ObservationID = *it.ObservationID
		}
		inserted, err := (AssetIdentityKeys{}).Record(ctx, c, assetID, k, at, KeyFromConfirmed, uuid.Nil, address, port)
		if err != nil {
			return res, err
		}
		if !inserted {
			return res, fmt.Errorf("store: key %s from %s was not recorded on asset %s", it.KeyType, it.Source, assetID)
		}
		// Outcome, not intent: under B42 the held key's first-seen port can
		// differ from the parked key's, and then nothing retires.
		if retired > 0 {
			res.KeysRetired = append(res.KeysRetired, string(it.KeyType)+"@"+it.Source)
		}
		res.KeysRecorded = append(res.KeysRecorded, string(it.KeyType)+"@"+it.Source+" "+it.KeyValue)
	}
	if len(discarded) > 0 {
		if _, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'discarded', resolved_by = $3, resolved_at = $4
		    WHERE tenant_id = $1 AND resolution_id = ANY ($2::uuid[]) AND state = 'pending'`,
			c.Tenant().UUID(), discarded, actor, at); err != nil {
			return res, mapError(err)
		}
	}
	tag, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'merged', resolved_asset_id = $3, resolved_by = $4, resolved_at = $5
	    WHERE tenant_id = $1 AND state = 'pending' AND resolution_id = ANY ($2::uuid[])`,
		c.Tenant().UUID(), closing, assetID, actor, at)
	if err != nil {
		return res, mapError(err)
	}
	res.ItemsClosed = tag.RowsAffected() + int64(len(discarded))
	return res, nil
}

// ResolveNewAsset is the operator's "different host" (ADR-097): the parked
// group is a host of its own. A new asset is created, the parked keys are
// recorded on it with provenance `confirmed`, it takes the address (the
// previous holder's interval closes under it, ADR-008), and the items close
// as `new_asset` naming the operator. Items carrying a key another asset
// holds live — the previous occupant's own sightings parked with the group —
// close as `discarded`: they were never the newcomer's, and released they
// would only re-park against the address the newcomer now holds.
func (ResolutionQueue) ResolveNewAsset(ctx context.Context, c *Conn, address string, chosen []KeyChoice, seenThrough time.Time, actor *uuid.UUID, at time.Time) (Resolution, error) {
	var res Resolution
	all, err := pendingAt(ctx, c, address, seenThrough)
	if err != nil {
		return res, err
	}
	if len(all) == 0 {
		return res, ErrNothingPending
	}
	if distinctKeys(all) > MaxKeysPerGroup {
		return res, ErrTooManyKeys
	}
	items, discarded, err := chooseKeys(all, chosen)
	if err != nil {
		return res, err
	}
	dropped := map[uuid.UUID]bool{}
	for _, id := range discarded {
		dropped[id] = true
	}
	for _, it := range all {
		if dropped[it.ResolutionID] {
			res.KeysDiscarded = append(res.KeysDiscarded, string(it.KeyType)+"@"+it.Source+" "+it.KeyValue)
		}
	}
	closing := make([]uuid.UUID, 0, len(items))
	for _, it := range items {
		closing = append(closing, it.ResolutionID)
	}
	keyed := items
	items = firstOfEachKey(items)
	a, err := (Assets{}).Create(ctx, c, Asset{})
	if err != nil {
		return res, err
	}
	res.AssetID = a.ID
	for _, it := range items {
		if it.KeyType == domain.KeyIPWindow || it.KeyType.Strength() < 2 {
			continue
		}
		holder, err := (AssetIdentityKeys{}).LiveByValue(ctx, c, it.KeyType, it.KeyValue)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return res, err
		}
		if err == nil && holder != a.ID {
			discarded = append(discarded, discardAll(keyed, it)...)
			res.KeysHeldElsewhere = append(res.KeysHeldElsewhere, string(it.KeyType)+"@"+it.Source+" "+it.KeyValue)
			continue
		}
		if err == nil {
			continue // recorded by an earlier item of this same group
		}
		port, _ := SourcePortProto(it.Source)
		payload, err := payloadOf(ctx, c, it.ResolutionID)
		if err != nil {
			return res, err
		}
		k := domain.IdentityKey{Type: it.KeyType, Value: it.KeyValue, Source: it.Source, Payload: payload}
		if it.ObservationID != nil {
			k.ObservationID = *it.ObservationID
		}
		inserted, err := (AssetIdentityKeys{}).Record(ctx, c, a.ID, k, at, KeyFromConfirmed, uuid.Nil, address, port)
		if err != nil {
			return res, err
		}
		if !inserted {
			return res, fmt.Errorf("store: key %s from %s was not recorded on the new asset", it.KeyType, it.Source)
		}
		res.KeysRecorded = append(res.KeysRecorded, string(it.KeyType)+"@"+it.Source+" "+it.KeyValue)
	}
	// Decided HERE, from what the loop actually recorded, and not from a count
	// taken earlier: Write is READ COMMITTED, so a key free when counted can be
	// another asset's by the time the loop reads it (a correlate sweep at
	// another address commits it in between — measured), and a pre-check was
	// measured letting the verb take the address with nothing recorded. The
	// address is taken only by an asset that recorded a key; the error rolls
	// the create back, and the create is the only write before this line.
	if len(res.KeysRecorded) == 0 {
		return res, ErrNothingToRecord
	}
	if err := (AssetAddresses{}).Open(ctx, c, a.ID, address, at); err != nil {
		return res, err
	}
	if len(discarded) > 0 {
		if _, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'discarded', resolved_by = $3, resolved_at = $4
		    WHERE tenant_id = $1 AND resolution_id = ANY ($2::uuid[]) AND state = 'pending'`,
			c.Tenant().UUID(), discarded, actor, at); err != nil {
			return res, mapError(err)
		}
	}
	tag, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'new_asset', resolved_asset_id = $3, resolved_by = $4, resolved_at = $5
	    WHERE tenant_id = $1 AND state = 'pending' AND resolution_id = ANY ($2::uuid[])`,
		c.Tenant().UUID(), closing, a.ID, actor, at)
	if err != nil {
		return res, mapError(err)
	}
	res.ItemsClosed = tag.RowsAffected() + int64(len(discarded))
	return res, nil
}

// pendingAt lists EVERY pending item at an address parked no later than
// `through` (zero: any time) — light columns only, no payload — so the
// decision is computed over the whole question and never over a window of
// it: two independently capped windows were measured disagreeing with each
// other and with the screen, each disagreement an unseen key confirmed.
func pendingAt(ctx context.Context, c *Conn, address string, through time.Time) ([]QueueItem, error) {
	const q = `
		SELECT resolution_id, observation_id, key_type::text, key_value, enqueued_at, coalesce(source, ''), candidate_asset_ids
		  FROM asset_resolution_queue
		 WHERE tenant_id = $1 AND state = 'pending' AND address = host($2::inet)::inet
		   AND ($3::timestamptz IS NULL OR enqueued_at <= $3::timestamptz)
		 ORDER BY enqueued_at, resolution_id`
	var thr any
	if !through.IsZero() {
		thr = through
	}
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), address, thr)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []QueueItem
	for rows.Next() {
		var it QueueItem
		var kt string
		if err := rows.Scan(&it.ResolutionID, &it.ObservationID, &kt, &it.KeyValue, &it.EnqueuedAt, &it.Source, &it.Candidates); err != nil {
			return nil, mapError(err)
		}
		it.KeyType = domain.IdentityKeyType(kt)
		out = append(out, it)
	}
	return out, mapError(rows.Err())
}

// payloadOf fetches one item's copied evidence, for the key a verb records.
func payloadOf(ctx context.Context, c *Conn, id uuid.UUID) (json.RawMessage, error) {
	var p []byte
	if err := c.QueryRow(ctx, `SELECT observed_payload FROM asset_resolution_queue WHERE tenant_id = $1 AND resolution_id = $2`,
		c.Tenant().UUID(), id).Scan(&p); err != nil {
		return nil, mapError(err)
	}
	return p, nil
}

func names(id uuid.UUID, cands []uuid.UUID) bool {
	for _, c := range cands {
		if c == id {
			return true
		}
	}
	return false
}

// distinctKeys counts the distinct keyed (type, source, value) among items.
func distinctKeys(items []QueueItem) int {
	seen := map[string]bool{}
	for _, it := range items {
		if it.KeyType == domain.KeyIPWindow {
			continue
		}
		seen[string(it.KeyType)+"|"+it.Source+"|"+it.KeyValue] = true
	}
	return len(seen)
}

// firstOfEachKey returns one item per distinct keyed (type, source, value),
// the oldest — the unit a verb records — and the ip_window items untouched.
func firstOfEachKey(items []QueueItem) []QueueItem {
	seen := map[string]bool{}
	var out []QueueItem
	for _, it := range items {
		if it.KeyType == domain.KeyIPWindow {
			continue
		}
		id := string(it.KeyType) + "|" + it.Source + "|" + it.KeyValue
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, it)
	}
	return out
}

// SourcePortProto splits a service ("22/tcp") into the (port, protocol) that
// names one live key; anything else — "unknown", "" — is (0, ""), which no
// key row carries.
func SourcePortProto(source string) (int, string) {
	var port int
	var proto string
	if _, err := fmt.Sscanf(source, "%d/%s", &port, &proto); err != nil || port <= 0 || port > 65535 {
		return 0, ""
	}
	return port, strings.ToLower(strings.TrimSpace(proto))
}

// discardAll returns the ids of every item carrying the key: a held-elsewhere
// key was measured discarded for its representative item and MERGED for its
// siblings, which put the siblings' observations back into the sweep to be
// parked again — the queue never drained.
func discardAll(all []QueueItem, k QueueItem) []uuid.UUID {
	var ids []uuid.UUID
	for _, it := range all {
		if it.KeyType == k.KeyType && it.Source == k.Source && it.KeyValue == k.KeyValue {
			ids = append(ids, it.ResolutionID)
		}
	}
	return ids
}

// ErrKeysChanged is returned when a key the operator named is not a live
// rotated or lapsed key on the asset: it was confirmed already, retired, or
// never there. Nothing is written.
var ErrKeysChanged = fmt.Errorf("store: a named key is not a live rotated or lapsed key on the asset")

// Discard is the operator's third word (ADR-097): the parked group at the
// address is noise — every pending item parked by seenThrough closes as
// `discarded` naming the operator, nothing is recorded, nothing is trusted,
// the observations stay out of the sweep. The exit for a group too large or
// too hostile to decide key by key. Returns how many closed.
func (ResolutionQueue) Discard(ctx context.Context, c *Conn, address string, seenThrough time.Time, actor *uuid.UUID, at time.Time) (int64, error) {
	var thr any
	if !seenThrough.IsZero() {
		thr = seenThrough
	}
	tag, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'discarded', resolved_by = $3, resolved_at = $4
	    WHERE tenant_id = $1 AND state = 'pending' AND address = host($2::inet)::inet
	      AND ($5::timestamptz IS NULL OR enqueued_at <= $5::timestamptz)`,
		c.Tenant().UUID(), address, actor, at, thr)
	if err != nil {
		return 0, mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrNothingPending
	}
	return tag.RowsAffected(), nil
}

// Confirm is the operator's word on a rotation or a lapse (ADR-097): the
// named keys ("type value") — each of which must be a live key the asset
// holds by a rotation or a lapse — are re-stamped `confirmed`, which the
// trust root and the establishment gate exclude from nothing. Named keys
// ONLY, a subset if the operator says so: the first draft confirmed
// everything rotated on the asset, and the review measured one genuine
// rotation on 22 blessing a planted key on 2222 and a lapsed certificate on
// 443; the second required the whole live set, which left the operator no way
// to refuse a member. A key that appears between the render and the click is
// simply not named, and stays where it was.
//
// What a confirmation hands back is exactly what ADR-096 took away: `rotation`
// and `lapsed` are excluded from the credentialed trust root AND from the
// establishment gate, after the review measured such a key reaching two
// sightings, corroborating its own certificate against the victim's, and
// merging at any address the attacker controlled. Confirming restores both —
// the dial and the power to corroborate. Naming the keys narrows WHO gets that
// back to the one key an operator pointed at; it does not change WHAT it is.
// (ADR-097 is accepted and frozen, so this is recorded here and in the ADR
// index rather than in its text.)
//
// Returns the keys confirmed, the
// rotated or lapsed keys still on the asset afterwards (the first
// MaxKeysPerGroup, sorted) and how many of those there are in all: a list cut
// without its total beside it is the shape that told an earlier console
// "confirmed 1 of 201" with four hundred still waiting.
func (AssetIdentityKeys) Confirm(ctx context.Context, c *Conn, assetID uuid.UUID, named []string) (confirmed, remaining []string, remainingTotal int, err error) {
	const live = `
		SELECT key_type::text || ' ' || key_value FROM asset_identity_keys
		 WHERE tenant_id = $1 AND asset_id = $2 AND valid_to IS NULL
		   AND provenance IN ('rotation', 'lapsed')
		 ORDER BY 1`
	rows, err := c.Query(ctx, live, c.Tenant().UUID(), assetID)
	if err != nil {
		return nil, nil, 0, mapError(err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return nil, nil, 0, mapError(err)
		}
		have[s] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, 0, mapError(err)
	}
	if len(have) == 0 {
		return nil, nil, 0, nil
	}
	seen := map[string]bool{}
	for _, n := range named {
		if !have[n] {
			return nil, nil, 0, ErrKeysChanged
		}
		if !seen[n] {
			seen[n] = true
			confirmed = append(confirmed, n)
		}
	}
	for h := range have {
		if !seen[h] {
			remaining = append(remaining, h)
		}
	}
	sort.Strings(remaining) // a map's order is not an answer
	remainingTotal = len(remaining)
	if len(remaining) > MaxKeysPerGroup {
		remaining = remaining[:MaxKeysPerGroup]
	}
	const q = `
		UPDATE asset_identity_keys
		   SET provenance = 'confirmed'
		 WHERE tenant_id = $1 AND asset_id = $2 AND valid_to IS NULL
		   AND provenance IN ('rotation', 'lapsed')
		   AND key_type::text || ' ' || key_value = ANY ($3::text[])`
	if _, err := c.Exec(ctx, q, c.Tenant().UUID(), assetID, confirmed); err != nil {
		return nil, nil, 0, mapError(err)
	}
	return confirmed, remaining, remainingTotal, nil
}

// KeySighting is one live identity key on an asset with its sightings at an
// address, and whether it is credentialed trust material there right now —
// the asset page's "what would the credentialed engine trust" (B39).
type KeySighting struct {
	Type       domain.IdentityKeyType
	Value      string
	Source     string
	Provenance KeyProvenance
	Address    string // "" when the key has never been sighted at an address
	Port       int
	ScansSeen  int
	LastSeenAt *time.Time
	// AddressHeld says the asset holds the sighting's address LIVE right now:
	// the trust root is read through asset_addresses, so a sighting at an
	// address the asset lost (an operator's "different host" closes it) is
	// history, not trust — the review measured the page saying "trusted" at
	// an address the wire returned nothing for.
	AddressHeld bool
}

// TrustMaterial says whether this sighting would be returned by
// SSHHostKeyFingerprintsAt for a dial on `port` right now — the same six
// conjuncts: SSH, the asset holds the address live, the sighting is on the
// dialled port, provenance not rotation/lapsed, two scans, inside the window.
func (k KeySighting) TrustMaterial(now time.Time, within time.Duration, port int) bool {
	return k.Type == domain.KeySSHHostKey && k.Address != "" && k.AddressHeld && k.Port == port &&
		k.Provenance != KeyFromRotation && k.Provenance != KeyFromLapsed &&
		k.ScansSeen >= 2 && k.LastSeenAt != nil && !k.LastSeenAt.Before(now.Add(-within))
}

// SightingsFor lists the asset's live keys with their sightings (one row per
// sighting address, or one row with no address for a key never sighted).
//
// At most 200 rows — one per (key, address seen at) — and the count of rows the
// same join holds travels beside them so the page can say what it does not
// show. The total is in the unit of the rows, not of keys: a total of live keys
// beside per-sighting rows was measured hiding 53 of 120 keys under a warning
// that never fired. Keys awaiting confirmation sort first, so they are the
// last to be truncated.
func (AssetIdentityKeys) SightingsFor(ctx context.Context, c *Conn, assetID uuid.UUID) ([]KeySighting, int, error) {
	var total int
	if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_identity_keys k
		  LEFT JOIN asset_identity_key_sightings s ON s.tenant_id = k.tenant_id AND s.identity_key_id = k.identity_key_id
		 WHERE k.tenant_id = $1 AND k.asset_id = $2 AND k.valid_to IS NULL`,
		c.Tenant().UUID(), assetID).Scan(&total); err != nil {
		return nil, 0, mapError(err)
	}
	const q = `
		SELECT k.key_type::text, k.key_value, k.provenance::text,
		       CASE WHEN k.merge_evidence_payload ? 'port'
		            THEN (k.merge_evidence_payload ->> 'port') || '/' ||
		                 coalesce(nullif(k.merge_evidence_payload ->> 'protocol', ''), 'tcp')
		            ELSE '' END,
		       coalesce(host(s.address), ''), coalesce(s.port, 0), coalesce(s.scans_seen, 0), s.last_seen_at,
		       EXISTS (SELECT 1 FROM asset_addresses a
		                WHERE a.tenant_id = k.tenant_id AND a.asset_id = k.asset_id
		                  AND a.ip_address = s.address AND a.valid_to IS NULL)
		  FROM asset_identity_keys k
		  LEFT JOIN asset_identity_key_sightings s
		    ON s.tenant_id = k.tenant_id AND s.identity_key_id = k.identity_key_id
		 WHERE k.tenant_id = $1 AND k.asset_id = $2 AND k.valid_to IS NULL
		 ORDER BY k.provenance IN ('rotation', 'lapsed') DESC, k.key_type, k.key_value, s.address
		 LIMIT 200`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), assetID)
	if err != nil {
		return nil, 0, mapError(err)
	}
	defer rows.Close()
	var out []KeySighting
	for rows.Next() {
		var k KeySighting
		var kt, prov string
		if err := rows.Scan(&kt, &k.Value, &prov, &k.Source, &k.Address, &k.Port, &k.ScansSeen, &k.LastSeenAt, &k.AddressHeld); err != nil {
			return nil, 0, mapError(err)
		}
		k.Type, k.Provenance = domain.IdentityKeyType(kt), KeyProvenance(prov)
		out = append(out, k)
	}
	return out, total, mapError(rows.Err())
}
