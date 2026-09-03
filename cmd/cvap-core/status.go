package main

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// status_Unimplemented is what an Enroll call to the mTLS listener gets.
//
// Operator-facing rather than a bare code: a scan point that dialled the wrong
// port is in a network we cannot reach to diagnose, and ADR-022 wants the
// failure to say what to do about it.
func status_Unimplemented() error { //nolint:revive,staticcheck // named for what it returns
	return status.Error(codes.Unimplemented,
		"Enroll is served on the enrollment listener, not on the mTLS listener; "+
			"a scan point without a certificate cannot connect here")
}
