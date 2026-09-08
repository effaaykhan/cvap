package domain

import "testing"

// mutate:subject internal/domain/attribution.go
// mutate:test    ./internal/domain/ -run TestAttributeOS
//
// mutate:case    the OS-attribution precedence is reversed, so a coarse SMB
//                "Windows" hint would overrule SSH's precise distro hint
// mutate:old     return len(osPrecedence) - i
// mutate:new     return i
//
// mutate:case    a losing hint is dropped instead of recorded, so the basis of a
//                wrong attribution is no longer reachable (ADR-061)
// mutate:old     case e.Family != winner.Family:
// mutate:new     case e.Family == winner.Family:
//
// The first restores the wrong-precedence bug the review trigger exists for; the
// SSH-beats-SMB case kills it. The second turns "ignored" into "agreed" for a
// disagreeing hint, so the overruled SMB source stops being recorded as
// overruled; the disagreement case's ignored-role assertion kills it.

func TestAttributeOS(t *testing.T) {
	t.Run("no evidence is no attribution, not a guess", func(t *testing.T) {
		a := AttributeOS(nil)
		if a.DistroFamily != "" || a.DistroRelease != nil {
			t.Fatalf("empty evidence must give no attribution, got %+v", a)
		}
	})

	t.Run("evidence with no family does not attribute", func(t *testing.T) {
		a := AttributeOS([]OSEvidence{{Service: "mysql", Port: 3306, Family: ""}})
		if a.DistroFamily != "" {
			t.Fatalf("a service with no OS hint is not OS evidence, got %+v", a)
		}
	})

	t.Run("family-only: banner never yields a release", func(t *testing.T) {
		a := AttributeOS([]OSEvidence{{Service: "ssh", Port: 22, Family: "ubuntu", Confidence: 0.95}})
		if a.DistroFamily != "ubuntu" {
			t.Errorf("family = %q, want ubuntu", a.DistroFamily)
		}
		if a.DistroRelease != nil {
			t.Errorf("release must be nil from a banner (family-only), got %q", *a.DistroRelease)
		}
		if a.Confidence != 0.95 {
			t.Errorf("confidence = %v, want the winning hint's 0.95", a.Confidence)
		}
	})

	t.Run("precedence: SSH beats SMB on disagreement, loser is recorded as ignored", func(t *testing.T) {
		a := AttributeOS([]OSEvidence{
			{Service: "smb", Port: 445, Family: "windows", Confidence: 0.7},
			{Service: "ssh", Port: 22, Family: "debian", Confidence: 0.95},
		})
		if a.DistroFamily != "debian" {
			t.Fatalf("SSH must win over SMB, got %q", a.DistroFamily)
		}
		var contributed, ignored *AttributionSource
		for i := range a.Provenance {
			switch a.Provenance[i].Role {
			case RoleContributed:
				contributed = &a.Provenance[i]
			case RoleIgnored:
				ignored = &a.Provenance[i]
			}
		}
		if contributed == nil || contributed.Service != "ssh" {
			t.Errorf("contributed source must be ssh, got %+v", contributed)
		}
		if ignored == nil || ignored.Service != "smb" || ignored.Family != "windows" {
			t.Errorf("the losing SMB/windows hint must be recorded as ignored, got %+v", ignored)
		}
	})

	t.Run("agreement: a second service naming the same family is recorded as agreed", func(t *testing.T) {
		a := AttributeOS([]OSEvidence{
			{Service: "ssh", Port: 22, Family: "ubuntu", Confidence: 0.95},
			{Service: "http", Port: 80, Family: "ubuntu", Confidence: 0.85},
		})
		roles := map[AttributionRole]int{}
		for _, s := range a.Provenance {
			roles[s.Role]++
		}
		if roles[RoleContributed] != 1 || roles[RoleAgreed] != 1 || roles[RoleIgnored] != 0 {
			t.Errorf("want 1 contributed + 1 agreed + 0 ignored, got %v", roles)
		}
	})
}
