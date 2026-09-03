package api

import "testing"

// HashPasswordForTest exposes the password hasher to the integration test, which
// lives in api_test and therefore cannot reach an unexported function.
//
// A test-only export rather than making hashPassword public: nothing outside
// this package should be producing verifiers, because the parameters and the
// encoding are this package's to change.
func HashPasswordForTest(t *testing.T, password string) string {
	t.Helper()
	phc, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	return phc
}
