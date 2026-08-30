// Package protocol holds conformance tests for the scan point wire contract in
// proto/, and nothing else.
//
// There is no code here. The contract's behaviour is entirely in the generated
// types under gen/, and generated code is not a place to put tests. What lives
// here are the assertions that the contract still has the properties ADR-022
// depends on -- properties that are invisible in a diff and that no compiler
// checks.
//
// The load-bearing one is compatibility with a future version. Scan points in
// customer networks run months-old builds; version skew is the normal state,
// not an edge case. `buf breaking` stops us removing or renumbering a field,
// but it cannot tell us whether an old build actually tolerates a new one.
// That needs a test that constructs the future and runs it through the present.
//
// Service implementations land in internal/scanpoint and internal/dispatch.
package protocol
