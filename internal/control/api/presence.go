package api

import (
	"fmt"

	"github.com/effaaykhan/cvap/internal/store"
)

// Address presence on the API surface (ADR-108 decision 6, ADR-109).
//
// "512 assets" and "29 present, 254 suppressed behind one device, 229 unjudged"
// are different claims about the same network, and only the second is true. The
// first is what CVAP reported before this existed, and it is the reason every
// downstream number was wrong: asset counts, service inventory, OS attribution
// and advisory matching all start from the host list.
//
// Reporting only the smaller number would be no better. A count that quietly
// dropped 483 addresses would swap one wrong answer for a smaller wrong answer,
// so the suppression travels WITH the count and carries its reasoning.

// PresenceSummaryResponse is the estate's composition by verdict.
type PresenceSummaryResponse struct {
	Present   int `json:"present" doc:"Addresses where a service identified itself. The defensible inventory."`
	Responder int `json:"responder" doc:"Addresses whose answers carry the signature of one device answering for a range, or which are the network/broadcast address of a scanned prefix with nothing identified. SUPPRESSED from the estate, not deleted — the rows, services and history are intact and the per-address reason is on the row."`
	Unknown   int `json:"unknown" doc:"Answered, but nothing identified itself and no responder signature either. Not convicted, not confirmed — and deliberately NOT counted as present."`
	Total     int `json:"total" doc:"Every live address, judged or not. This is the number CVAP used to report as its asset count."`

	// Statement exists because each number above can be read as a verdict by
	// someone who does not know how it was reached, and the middle one is a
	// judgement about a live network that can be wrong.
	Statement string `json:"statement"`
}

func presenceSummaryResponse(s store.PresenceSummary) PresenceSummaryResponse {
	return PresenceSummaryResponse{
		Present: s.Present, Responder: s.Responder, Unknown: s.Unknown, Total: s.Total(),
		Statement: presenceStatement(s),
	}
}

// presenceStatement names the state in words.
//
// The case that needs it most is the ordinary one: a large `responder` count is
// the rule WORKING, not a fault, and an operator seeing four fifths of their
// estate disappear deserves to be told that in a sentence rather than left to
// infer it from a number that halved overnight.
func presenceStatement(s store.PresenceSummary) string {
	switch {
	case s.Total() == 0:
		return "No addresses have been observed yet."
	case s.Present == 0 && s.Responder == 0:
		return fmt.Sprintf("No presence verdict has been reached for any of %d addresses. Until correlation has run, every address is unjudged and this count is not an inventory.", s.Unknown)
	case s.Responder > s.Present:
		return fmt.Sprintf("%d of %d addresses answered without ever identifying themselves and were suppressed: the signature of one device answering for a range, not an estate. %d addresses have a service that identified itself; %d answered but proved nothing either way. Nothing was deleted — each suppressed address keeps its services, its history, and the reason it was suppressed.",
			s.Responder, s.Total(), s.Present, s.Unknown)
	default:
		return fmt.Sprintf("%d of %d addresses carry a service that identified itself. %d were suppressed as range responders and %d answered without proving anything either way — unmapped, not empty.",
			s.Present, s.Total(), s.Responder, s.Unknown)
	}
}
