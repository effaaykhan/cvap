package target

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
)

// CoreEndpoints is where Core can be reached, as addresses, so that a scan
// target naming Core can be refused (ADR-110).
//
// ============================================================================
// Core is the one destination the Scan Point's kernel packet ceiling exempts.
// ============================================================================
//
// The network-policy holder passes TCP to Core's endpoints ahead of the
// per-Scan-Point policer, because a shared bucket starved the control channel
// (R2-D measured a p95 of 1 s under a hostile flood). That exemption is a
// bypass of the ceiling for exactly those addresses, so the ceiling holds only
// if nothing is ever SCANNED there. Both ADR-024 enforcement sites refuse a
// target that is, or contains, one of these addresses: Core when it offers a
// job, and the runtime before it creates an engine.
//
// The addresses are resolved ONCE, when the set is built. A name that does not
// resolve is an error rather than an empty set: a refusal that silently matches
// nothing is the failure this exists to prevent.
type CoreEndpoints struct {
	addrs []netip.Addr
}

// ErrNoCoreEndpoint means no concrete Core address could be determined.
var ErrNoCoreEndpoint = errors.New("target: no Core endpoint address could be determined")

// Resolver turns a host name into addresses. net.DefaultResolver.LookupNetIP
// with network "ip" satisfies it.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// NewCoreEndpoints resolves host:port endpoints to the set of Core addresses.
//
// An endpoint whose host is empty or unspecified (":8444", "0.0.0.0:8444") is a
// listen address, not somewhere Core can be reached, and is skipped. Every other
// endpoint must yield at least one address, and the set must end up non-empty.
func NewCoreEndpoints(ctx context.Context, endpoints []string, resolve Resolver) (CoreEndpoints, error) {
	var out []netip.Addr
	for _, ep := range endpoints {
		if ep == "" {
			continue
		}
		host, _, err := net.SplitHostPort(ep)
		if err != nil {
			return CoreEndpoints{}, fmt.Errorf("target: Core endpoint %q: %w", ep, err)
		}
		if host == "" {
			continue
		}
		var addrs []netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			addrs = []netip.Addr{a}
		} else {
			if resolve == nil {
				return CoreEndpoints{}, fmt.Errorf("target: Core endpoint %q is a name and no resolver was given", ep)
			}
			addrs, err = resolve(ctx, host)
			if err != nil {
				return CoreEndpoints{}, fmt.Errorf("target: resolve Core endpoint %q: %w", ep, err)
			}
			if len(addrs) == 0 {
				return CoreEndpoints{}, fmt.Errorf("target: Core endpoint %q resolved to no address", ep)
			}
		}
		for _, a := range addrs {
			a = a.Unmap().WithZone("")
			if a.IsUnspecified() || slices.Contains(out, a) {
				continue
			}
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		return CoreEndpoints{}, ErrNoCoreEndpoint
	}
	return CoreEndpoints{addrs: out}, nil
}

// Addrs is the resolved set, for logging.
func (e CoreEndpoints) Addrs() []netip.Addr { return slices.Clone(e.addrs) }

// Contains reports whether scanning c would put packets on a Core address: c is
// one, or c is a prefix covering one. A hostname cannot be decided here and is
// reported as not contained; neither enforcement site lets a hostname reach the
// wire, and it is refused there for that reason, not this one.
func (e CoreEndpoints) Contains(c Canonical) bool {
	switch c.Kind {
	case KindAddress:
		a := c.Addr.Unmap().WithZone("")
		return slices.Contains(e.addrs, a)
	case KindPrefix:
		for _, a := range e.addrs {
			if c.Prefix.Contains(a) {
				return true
			}
		}
	}
	return false
}
