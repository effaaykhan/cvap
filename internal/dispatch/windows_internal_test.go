package dispatch

import (
	"strings"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// TestWindowsThatCannotBeEvaluatedFailTheJob is the same posture scope.go takes,
// on the other restriction.
//
// A window nobody can evaluate must not become "no window". It must not silently
// stop every scan either — it fails the job, which reaches an operator as an
// audit event naming the policy (refuseJob). Fail-open here is a scan running
// outside the maintenance window it was written for; fail-silent is a scan that
// never runs and nothing says why.
func TestWindowsThatCannotBeEvaluatedFailTheJob(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"not a list", `{"start":"22:00","end":"04:00"}`},
		{"not json at all", `22:00-04:00`},
		{"a field nobody defined, so the real ones decoded as empty", `[{"from":"22:00","to":"04:00"}]`},
		{"start is not HH:MM", `[{"start":"10pm","end":"04:00"}]`},
		{"end is not HH:MM", `[{"start":"22:00","end":"4:00"}]`},
		{"hour out of range", `[{"start":"24:00","end":"04:00"}]`},
		{"minute out of range", `[{"start":"22:60","end":"04:00"}]`},
		{"missing end", `[{"start":"22:00"}]`},
		// Zero-length or 24 hours, and the two readings differ by a day of
		// scanning. Refused rather than guessed.
		{"start equals end", `[{"start":"22:00","end":"22:00"}]`},
		{"a day nobody can name", `[{"start":"22:00","end":"04:00","days":["caturday"]}]`},
		// Parsed on every poll, per policy, per connected scan point, inside the
		// claim transaction. Unbounded, this is minutes of CPU per poll.
		{"more windows than one policy may carry",
			"[" + strings.TrimSuffix(strings.Repeat(`{"start":"22:00","end":"04:00"},`,
				MaxWindowsPerPolicy+1), ",") + "]"},
		// Falling back to UTC would move the window by an hour for half the
		// year, in the direction of scanning outside it.
		{"an unresolvable timezone", `[{"start":"22:00","end":"04:00","tz":"Middle/Earth"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseWindows([]byte(tc.raw)); err == nil {
				t.Error("parseWindows accepted a window it cannot evaluate; a restriction " +
					"that cannot be evaluated must fail the job, not disappear")
			}
			p := jp(store.Policy{SafetyMode: store.SafetySafe, TimeWindows: []byte(tc.raw)})
			if _, err := constraintsFor(p, nil, noWindow); err == nil {
				t.Error("constraintsFor built an assignment from an unevaluable window")
			}
		})
	}
}

// TestEmptyWindowsAreUnrestricted is the half of ADR-037 that runs the opposite
// way to allowed_targets.
//
// Every scan_policies row that exists defaults to '[]'. The deny-all reading
// would have stopped the fleet on the migration that enforced this column, which
// is why the two families of list read their empty case differently.
func TestEmptyWindowsAreUnrestricted(t *testing.T) {
	for _, raw := range []string{"", "[]", "  []  "} {
		windows, err := parseWindows([]byte(raw))
		if err != nil {
			t.Fatalf("parseWindows(%q): %v", raw, err)
		}
		end, open := windowEnd(windows, noWindow)
		if !open {
			t.Errorf("parseWindows(%q) produced a closed window; empty means unrestricted", raw)
		}
		if !end.IsZero() {
			t.Errorf("parseWindows(%q) produced an end of %v; unrestricted travels as 0", raw, end)
		}
	}

	got, err := constraintsFor(jp(store.Policy{SafetyMode: store.SafetySafe}), nil, noWindow)
	if err != nil {
		t.Fatalf("constraintsFor: %v", err)
	}
	if got.GetWindowEndsUnix() != 0 {
		t.Errorf("window_ends_unix = %d, want 0 for a policy with no windows",
			got.GetWindowEndsUnix())
	}
}

// TestWindowEnd covers the cases a maintenance window actually takes.
//
// The midnight crossing is the one that matters: a window that does not cross
// midnight is the unusual one, and evaluating only today's opening would close
// every real window at 00:00.
func TestWindowEnd(t *testing.T) {
	// A Wednesday.
	at := func(day int, hh, mm int) time.Time {
		return time.Date(2026, 9, day, hh, mm, 0, 0, time.UTC)
	}

	for _, tc := range []struct {
		name    string
		raw     string
		now     time.Time
		open    bool
		wantEnd time.Time
	}{
		{
			name: "inside a same-day window",
			raw:  `[{"start":"09:00","end":"17:00"}]`,
			now:  at(2, 12, 0), open: true, wantEnd: at(2, 17, 0),
		},
		{
			name: "before it opens",
			raw:  `[{"start":"09:00","end":"17:00"}]`,
			now:  at(2, 8, 59), open: false,
		},
		{
			name: "the closing instant is outside, not inside",
			raw:  `[{"start":"09:00","end":"17:00"}]`,
			now:  at(2, 17, 0), open: false,
		},
		{
			name: "the opening instant is inside",
			raw:  `[{"start":"09:00","end":"17:00"}]`,
			now:  at(2, 9, 0), open: true, wantEnd: at(2, 17, 0),
		},
		{
			// Opened yesterday. Checking only today's opening would close this
			// at midnight every night.
			name: "after midnight, inside a window that opened yesterday",
			raw:  `[{"start":"22:00","end":"04:00"}]`,
			now:  at(3, 1, 30), open: true, wantEnd: at(3, 4, 0),
		},
		{
			name: "before midnight, inside the same window",
			raw:  `[{"start":"22:00","end":"04:00"}]`,
			now:  at(2, 23, 0), open: true, wantEnd: at(3, 4, 0),
		},
		{
			name: "the gap between two nights",
			raw:  `[{"start":"22:00","end":"04:00"}]`,
			now:  at(2, 12, 0), open: false,
		},
		{
			// days names the day the window OPENS, so a Wednesday window runs
			// into Thursday morning.
			name: "a wednesday-night window is open on thursday morning",
			raw:  `[{"start":"22:00","end":"04:00","days":["wed"]}]`,
			now:  at(3, 2, 0), open: true, wantEnd: at(3, 4, 0),
		},
		{
			name: "and is not open on thursday night",
			raw:  `[{"start":"22:00","end":"04:00","days":["wed"]}]`,
			now:  at(3, 23, 0), open: false,
		},
		{
			// Union, not intersection. An operator who wrote both has
			// authorised scanning until the later end; stopping at the earlier
			// one would halt a job an hour into a window that is still open.
			name: "overlapping windows take the latest end",
			raw:  `[{"start":"22:00","end":"02:00"},{"start":"23:00","end":"04:00"}]`,
			now:  at(3, 1, 0), open: true, wantEnd: at(3, 4, 0),
		},
		{
			// Not merged, deliberately: the job ends at midnight and its
			// successor is claimed straight after.
			name: "abutting windows are not merged",
			raw:  `[{"start":"22:00","end":"00:00"},{"start":"00:00","end":"02:00"}]`,
			now:  at(2, 23, 0), open: true, wantEnd: at(3, 0, 0),
		},
		{
			// 21:00 UTC is 22:00 in London during BST. Falling back to UTC
			// would leave this closed for another hour.
			name: "a named zone is resolved, not assumed to be UTC",
			raw:  `[{"start":"22:00","end":"04:00","tz":"Europe/London"}]`,
			now:  at(2, 21, 30), open: true,
			wantEnd: time.Date(2026, 9, 3, 3, 0, 0, 0, time.UTC),
		},
		{
			// ================================================================
			// The fail-open a safety audit proved, and the reason wallClock
			// checks its own result.
			// ================================================================
			//
			// 2026-03-29: BST begins at 01:00 GMT, so 01:00-01:59 local does
			// not exist. time.Date normalises both 01:00 and 02:00 to the same
			// instant, the midnight-crossing branch reads closes == opens, and
			// a one-hour window opened for twenty-four — with window_ends_unix
			// on the wire agreeing, so the scan point would not have stopped
			// either. Once a year, silently, toward more packets.
			name: "a window inside the spring-forward gap does not open at all",
			raw:  `[{"start":"01:00","end":"02:00","tz":"Europe/London"}]`,
			now:  time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC), open: false,
		},
		{
			name: "and not at the moment the gap itself would have started",
			raw:  `[{"start":"01:00","end":"02:00","tz":"Europe/London"}]`,
			now:  time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC), open: false,
		},
		{
			// The day either side is unaffected: skipping the occurrence must
			// not disable the window.
			name: "the same window is open the day before",
			raw:  `[{"start":"01:00","end":"02:00","tz":"Europe/London"}]`,
			now:  time.Date(2026, 3, 28, 1, 30, 0, 0, time.UTC), open: true,
			wantEnd: time.Date(2026, 3, 28, 2, 0, 0, 0, time.UTC),
		},
		{
			// A window that merely SPANS the gap still opens — only a reading
			// inside it is unbuildable.
			name: "a window spanning the spring-forward gap is unaffected",
			raw:  `[{"start":"22:00","end":"04:00","tz":"Europe/London"}]`,
			now:  time.Date(2026, 3, 28, 23, 0, 0, 0, time.UTC), open: true,
			wantEnd: time.Date(2026, 3, 29, 3, 0, 0, 0, time.UTC),
		},
		{
			// The night the UK clocks go back: 02:00 BST becomes 01:00 GMT, so
			// the night is 25 hours long. "22:00 to 04:00" means those readings
			// on a clock in London, which is 04:00 GMT — seven hours after the
			// window opened. Adding six hours to the opening instant would end
			// it at 03:00 GMT and cut an hour off the maintenance window; the
			// spring transition errs the other way and would scan an hour past
			// the stated end.
			name: "a window spanning a DST transition ends at the wall-clock time",
			raw:  `[{"start":"22:00","end":"04:00","tz":"Europe/London"}]`,
			now:  time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC), open: true,
			wantEnd: time.Date(2026, 10, 25, 4, 0, 0, 0, time.UTC),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			windows, err := parseWindows([]byte(tc.raw))
			if err != nil {
				t.Fatalf("parseWindows: %v", err)
			}
			end, open := windowEnd(windows, tc.now)
			if open != tc.open {
				t.Fatalf("open = %v, want %v (end %v)", open, tc.open, end)
			}
			if !tc.open {
				return
			}
			if !end.Equal(tc.wantEnd) {
				t.Errorf("end = %v, want %v", end.UTC(), tc.wantEnd.UTC())
			}
		})
	}
}

// TestWindowEndReachesTheWire is the point of the whole file: ADR-024's window
// has to arrive at the component sending packets.
//
// time_windows, ScanConstraints.window_ends_unix and
// TerminationReason.WINDOW_EXPIRED all existed and nothing connected them. A
// ceiling that does not reach the scan point is decorative.
func TestWindowEndReachesTheWire(t *testing.T) {
	now := time.Date(2026, 9, 2, 23, 0, 0, 0, time.UTC)
	p := jp(store.Policy{
		SafetyMode:  store.SafetySafe,
		TimeWindows: []byte(`[{"start":"22:00","end":"04:00"}]`),
	})

	got, err := constraintsFor(p, nil, now)
	if err != nil {
		t.Fatalf("constraintsFor: %v", err)
	}
	want := time.Date(2026, 9, 3, 4, 0, 0, 0, time.UTC).Unix()
	if got.GetWindowEndsUnix() != want {
		t.Errorf("window_ends_unix = %d, want %d", got.GetWindowEndsUnix(), want)
	}

	// Outside the window, constraintsFor refuses rather than dispatching a job
	// whose end is already in the past. offerWork never reaches this — the same
	// evaluation keeps the job unclaimed — and it is asserted so that the two
	// halves cannot drift into disagreeing.
	if _, err := constraintsFor(p, nil, time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Error("constraintsFor built an assignment outside the policy's maintenance window")
	}
}
