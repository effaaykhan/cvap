package dispatch

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// scan_policies.time_windows, the half ADR-024 left to Core.
// ============================================================================
//
// A maintenance window is a recurring schedule, and a scan point has no use for
// one: it needs to know when to stop, not when it could have started. So the
// schedule is evaluated here and only the answer travels, as
// ScanConstraints.window_ends_unix — one instant, already in the past-free form
// the runtime compares its clock against. The recurring rule never leaves Core,
// which also means a scan point's clock drifting cannot widen a window.
//
// The column existed from migration 0003 and was read by nothing. window_ends_unix
// and TerminationReason.WINDOW_EXPIRED both existed too, so a policy could carry
// a window, the wire could carry its end and a scan point could report hitting
// it — and no code anywhere connected the three. An operator restricting a scan
// to a maintenance window had written a comment.
//
// EMPTY MEANS UNRESTRICTED. That is the opposite of allowed_targets and ADR-037
// records why: this list answers "is this scan restricted in time", and an unset
// restriction is no restriction.
//
// Unparseable is NOT unrestricted, and not silently closed either. Anything this
// file cannot evaluate fails the job with an audit event, the same way an
// unexpressible scope rule does (scope.go). A restriction that silently
// disappears is the worst of the three outcomes, and one that silently stops
// every scan without saying so is the second worst.

// Encoding, as documented on the column in migration 0024:
//
//	[{"start":"22:00","end":"04:00","days":["sat","sun"],"tz":"Europe/London"}]
//
// days and tz are optional, defaulting to every day and UTC. `end` at or before
// `start` crosses midnight, and `days` names the day the window OPENS — a
// Saturday 22:00-04:00 window runs into Sunday morning and a Sunday-only window
// does not cover it.
type window struct {
	Start string   `json:"start"`
	End   string   `json:"end"`
	Days  []string `json:"days"`
	TZ    string   `json:"tz"`
}

// parsedWindow is one window with everything resolved, so evaluation cannot fail.
type parsedWindow struct {
	startMin int // minutes past midnight, local to loc
	endMin   int
	days     map[time.Weekday]bool // nil means every day
	loc      *time.Location
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday,
	"sat": time.Saturday,
}

// parseWindows turns the raw jsonb into evaluable windows.
//
// A nil or empty document is no restriction and returns no windows and no error.
// Everything else must parse completely: DisallowUnknownFields is deliberate,
// because a window written as {"from":"22:00","to":"04:00"} would otherwise
// decode into two empty strings and become a rule nobody asked for.
// MaxWindowsPerPolicy bounds one policy's window list.
//
// This is parsed on every dispatch poll, for every connected scan point, inside
// the transaction that claims work — so its cost is multiplied by the fleet and
// held against a pooled connection. Unbounded, one policy with ten thousand
// windows measured at 122 ms per parse, which at the MaxWindowedPolicies ceiling
// is minutes of CPU per poll on a shared control plane.
//
// Ten is generous for a maintenance schedule: a weekly window per weekday is
// five, and anything past that is a policy that wants a cron expression rather
// than a list. Mirrored as a CHECK in migration 0024, so a policy over the cap
// cannot be written rather than merely failing to dispatch.
const MaxWindowsPerPolicy = 10

func parseWindows(raw []byte) ([]parsedWindow, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()

	var docs []window
	if err := dec.Decode(&docs); err != nil {
		return nil, fmt.Errorf("time_windows is not a list of windows: %w", err)
	}
	if len(docs) == 0 {
		return nil, nil
	}
	if len(docs) > MaxWindowsPerPolicy {
		return nil, fmt.Errorf("time_windows has %d entries; at most %d are allowed",
			len(docs), MaxWindowsPerPolicy)
	}

	out := make([]parsedWindow, 0, len(docs))
	for i, w := range docs {
		p, err := parseWindow(w)
		if err != nil {
			return nil, fmt.Errorf("time_windows[%d]: %w", i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseWindow(w window) (parsedWindow, error) {
	var p parsedWindow

	start, err := parseHHMM(w.Start)
	if err != nil {
		return p, fmt.Errorf("start: %w", err)
	}
	end, err := parseHHMM(w.End)
	if err != nil {
		return p, fmt.Errorf("end: %w", err)
	}
	if start == end {
		// Ambiguous between "zero length" and "the whole day", and the two
		// readings differ by 24 hours of scanning. Refused rather than guessed:
		// a window meaning "always" is written by omitting the list.
		return p, fmt.Errorf("start and end are both %s; a window of zero or 24 hours has to be written as one or the other", w.Start)
	}
	p.startMin, p.endMin = start, end

	// UTC by default. A named zone is resolved against the deployment's tzdata,
	// and an unknown one fails rather than falling back: silently treating
	// "Europe/London" as UTC moves a maintenance window by an hour for half the
	// year, in the direction of scanning outside it.
	p.loc = time.UTC
	if tz := strings.TrimSpace(w.TZ); tz != "" {
		loc, err := loadLocation(tz)
		if err != nil {
			return p, fmt.Errorf("tz %q cannot be resolved: %w", tz, err)
		}
		p.loc = loc
	}

	if len(w.Days) > 0 {
		p.days = make(map[time.Weekday]bool, len(w.Days))
		for _, d := range w.Days {
			wd, ok := weekdays[strings.ToLower(strings.TrimSpace(d))]
			if !ok {
				return p, fmt.Errorf("day %q is not one of sun mon tue wed thu fri sat", d)
			}
			p.days[wd] = true
		}
	}
	return p, nil
}

// locations memoises time.LoadLocation.
//
// The stdlib does not cache, and this runs once per window per policy per poll
// per connected scan point. A *time.Location is immutable and safe to share, and
// the set of zone names a deployment uses is tiny and bounded by what operators
// have typed. Failures are cached too, so a typo'd zone name does not re-read
// the filesystem on every poll for the life of the process.
var locations sync.Map // string -> locationResult

type locationResult struct {
	loc *time.Location
	err error
}

func loadLocation(name string) (*time.Location, error) {
	if v, ok := locations.Load(name); ok {
		r := v.(locationResult)
		return r.loc, r.err
	}
	loc, err := time.LoadLocation(name)
	locations.Store(name, locationResult{loc: loc, err: err})
	return loc, err
}

func parseHHMM(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	hh, err := strconv.Atoi(h)
	if err != nil || len(h) != 2 || hh < 0 || hh > 23 {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	mm, err := strconv.Atoi(m)
	if err != nil || len(m) != 2 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("%q is not HH:MM", s)
	}
	return hh*60 + mm, nil
}

// windowEnd reports whether now falls inside any window, and when the one it is
// in closes.
//
// No windows means unrestricted: open, with a zero end, which travels as
// window_ends_unix = 0 (ADR-037).
//
// When several windows contain now, the LATEST end wins. Overlapping windows are
// a union — an operator who wrote 22:00-02:00 and 23:00-04:00 has authorised
// scanning until 04:00, and taking the earliest would stop a job an hour into a
// window that is still open. Windows that merely ABUT (22:00-00:00 then
// 00:00-02:00) are not merged: the job ends at midnight and its successor is
// claimed immediately after, which costs one job boundary and keeps this
// function from having to reason about adjacency across timezone changes.
// wallClock builds a local time and reports whether that reading actually exists
// on that date in that zone.
//
// time.Date never fails: given a time inside a spring-forward gap it returns the
// normalised instant, whose wall clock is an hour later than what was asked for.
// Comparing the result back against the request is the only way to tell the
// difference, and the difference is load-bearing — see windowEnd.
func wallClock(year int, month time.Month, day, minutes int, loc *time.Location) (time.Time, bool) {
	t := time.Date(year, month, day, minutes/60, minutes%60, 0, 0, loc)
	return t, t.Hour()*60+t.Minute() == minutes
}

func windowEnd(windows []parsedWindow, now time.Time) (end time.Time, open bool) {
	if len(windows) == 0 {
		return time.Time{}, true
	}

	for _, w := range windows {
		local := now.In(w.loc)

		year, month, dayOfMonth := local.Date()

		// Two candidate openings: one today and one yesterday. A window that
		// crosses midnight was opened by yesterday's weekday, and checking only
		// today would close it at 00:00 every night — for the windows most
		// likely to exist, since a maintenance window that does not cross
		// midnight is the unusual one.
		for _, dayOffset := range []int{0, -1} {
			day := time.Date(year, month, dayOfMonth+dayOffset, 0, 0, 0, 0, w.loc)
			if w.days != nil && !w.days[day.Weekday()] {
				continue
			}

			// Built from wall-clock components rather than by adding a duration
			// to midnight, and the difference is a DST transition. "22:00 to
			// 04:00" means those readings on a clock in that zone; adding six
			// hours to 22:00 across an autumn fall-back lands at 05:00 local and
			// scans for an hour past the end the operator wrote. time.Date
			// normalises the day rollover and the month end for us.
			y, mo, d := day.Date()
			opens, okOpen := wallClock(y, mo, d, w.startMin, w.loc)
			closes, okClose := wallClock(y, mo, d, w.endMin, w.loc)

			// ====================================================================
			// A wall clock that does not exist today closes the window, not opens it.
			// ====================================================================
			//
			// At a spring-forward transition an hour of local time is skipped, and
			// time.Date normalises a reading inside it FORWARD. For a window written
			// entirely within that hour — 01:00 to 02:00 in Europe/London on the
			// changeover — both readings normalise to the same instant, the
			// midnight-crossing branch below sees closes == opens, rolls closes to
			// the next day, and a one-hour maintenance window is open for
			// twenty-four. Silently, once a year, in the direction of more packets
			// over a longer window than anyone authorised. Both enforcement sites
			// share this function, so they would have agreed on the wrong answer.
			//
			// Skipping the occurrence rather than failing the job: the window is
			// unrunnable on this one date and runnable on every other, which is not
			// a policy defect and must not terminate the scan. It waits for the next
			// occurrence, which is the same thing a closed window already means.
			//
			// parseWindow refuses start == end at parse time on the grounds that
			// zero hours and twenty-four differ by a day of scanning. This is that
			// same state, reached by the calendar rather than by the operator, and
			// it gets the same answer.
			if !okOpen || !okClose {
				continue
			}
			if !closes.After(opens) {
				closes, okClose = wallClock(y, mo, d+1, w.endMin, w.loc)
				if !okClose {
					continue
				}
			}
			if local.Before(opens) || !local.Before(closes) {
				continue
			}
			if closes.After(end) {
				end = closes
			}
			open = true
		}
	}
	return end, open
}
