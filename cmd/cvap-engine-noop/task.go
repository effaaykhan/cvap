package main

import "github.com/google/uuid"

// mustParseTask converts the wire task id, tolerating a malformed one.
//
// The runtime generates these from scan_tasks.task_id, so a parse failure is our
// own bug rather than hostile input — but an engine that exited on it would turn
// one bad task into a whole job reported as ENGINE_FAILURE, which is the reason
// an operator would then go looking in the wrong place. The nil UUID travels
// back, Core rejects the observation as malformed, and the failure is attributed
// where it happened.
func mustParseTask(s string) uuid.UUID {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil
	}
	return id
}
