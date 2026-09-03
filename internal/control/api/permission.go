package api

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Permission is one thing a role may do.
//
// A flat string rather than a resource/verb pair, because every check is an
// exact match and a structured form invites a wildcard — and a wildcard in a
// permission set is a permission set nobody can read back.
type Permission string

// The permissions this API defines. Registration refuses a route naming one
// that is not here, so a typo is a build-time failure rather than a route
// nobody can reach.
const (
	PermScanRead   Permission = "scan.read"
	PermScanCreate Permission = "scan.create"
	PermScanCancel Permission = "scan.cancel"

	// Separate from scan.create, deliberately. ADR-021 makes intrusive an
	// explicit opt-in, and a permission that came bundled with "may start a
	// scan" would make the opt-in a property of the plan rather than a decision
	// somebody is authorised to take.
	PermScanIntrusive Permission = "scan.safety_mode"

	PermPolicyRead  Permission = "policy.read"
	PermPolicyWrite Permission = "policy.write"

	PermZoneRead  Permission = "zone.read"
	PermZoneWrite Permission = "zone.write"

	PermScanPointRead   Permission = "scanpoint.read"
	PermScanPointEnroll Permission = "scanpoint.enroll"

	// The fleet stop. Held apart from every other permission because it is the
	// control ADR-024 requires to be reachable in seconds by whoever is holding
	// the pager, which is not necessarily whoever administers policy.
	PermKillIssue   Permission = "kill.issue"
	PermKillResolve Permission = "kill.resolve"

	PermAuthConfigRead  Permission = "auth.read"
	PermAuthConfigWrite Permission = "auth.write"
)

// allPermissions is the closed set. A route may only name a member.
var allPermissions = map[Permission]bool{
	PermScanRead: true, PermScanCreate: true, PermScanCancel: true,
	PermScanIntrusive: true,
	PermPolicyRead:    true, PermPolicyWrite: true,
	PermZoneRead: true, PermZoneWrite: true,
	PermScanPointRead: true, PermScanPointEnroll: true,
	PermKillIssue: true, PermKillResolve: true,
	PermAuthConfigRead: true, PermAuthConfigWrite: true,
}

// PermissionNames lists the closed set, sorted. For the OpenAPI document and
// for the role editor that will eventually need it.
func PermissionNames() []Permission {
	out := make([]Permission, 0, len(allPermissions))
	for p := range allPermissions {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PermissionSet is a role's permissions, as stored in roles.permissions.
//
// The stored shape is a JSON object of permission name to true:
//
//	{"scan.read": true, "scan.create": true}
//
// which is what the column's '{}' default already is — an empty object, and
// therefore no permissions at all.
//
// ADR-037 governs that reading. permissions is a PERMISSION list, so empty means
// DENY, not unrestricted. A role with no permissions can do nothing, which is
// what a newly created role should be able to do until somebody says otherwise.
// The constraint lists ADR-037 treats the other way — allowed_zones,
// time_windows — are elsewhere and are not this.
type PermissionSet map[Permission]bool

// ParsePermissions reads roles.permissions.
//
// A malformed value is an ERROR, not an empty set. Both deny, so the difference
// looks academic — but "this role's permissions are corrupt" and "this role
// grants nothing" need different responses, and silently treating the first as
// the second means a JSON defect presents as an operator's access quietly
// disappearing.
func ParsePermissions(raw []byte) (PermissionSet, error) {
	if len(raw) == 0 {
		return PermissionSet{}, nil
	}
	var m map[string]bool
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("api: role permissions are not a JSON object of name to bool: %w", err)
	}
	set := make(PermissionSet, len(m))
	for k, v := range m {
		if v {
			// Unknown names are kept rather than rejected. A permission this
			// build does not define grants nothing here — Has only ever asks
			// about a name from the closed set — and dropping it would mean a
			// rollback to an older Core silently deletes permissions from every
			// role it touches.
			set[Permission(k)] = true
		}
	}
	return set, nil
}

// Has reports whether the set grants a permission. There is no wildcard, no
// hierarchy and no implication: scan.cancel does not follow from scan.create,
// because stopping other people's scans is not the same authority as starting
// your own.
func (s PermissionSet) Has(p Permission) bool { return s[p] }
