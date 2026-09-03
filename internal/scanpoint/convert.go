package scanpoint

import "math"

// u32 converts a length or a count to the uint32 the wire uses, bounded.
//
// Every one of these is a `len()` or an accumulated count, so in practice none
// can be negative or exceed 2^32. "In practice" is the problem: a silent wrap is
// how a count of 4,294,967,297 observations becomes 1 on the wire, and the
// counts here feed JobProgress and Heartbeat — numbers an operator reads to
// decide whether a scan point is healthy. gosec flags the class (G115) and it is
// right to; a bounded conversion is cheaper than an argument about why this one
// is safe.
//
// Saturating rather than wrapping, and clamping negatives to zero: for a count
// the honest failure is "very large", never "suddenly small".
func u32(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}
