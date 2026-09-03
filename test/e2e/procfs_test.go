package e2e

import (
	"fmt"
	"strconv"
	"strings"
)

// Small helpers over /proc, kept out of the test bodies.
//
// Linux-only, which the whole repository already is (docker-compose, the
// migration tooling, syscall.Setpgid in the engine host). A test that located
// the engine by name would match the wrong process on a machine running two
// copies; the parent pid is exact.

func lastIndexByte(s string, b byte) int { return strings.LastIndexByte(s, b) }

func sscan(s string, state *string, ppid *int) (int, error) {
	return fmt.Sscan(strings.TrimSpace(s), state, ppid)
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
