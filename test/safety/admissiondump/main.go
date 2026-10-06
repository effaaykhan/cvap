// Command admissiondump prints what the fingerprint engine admits for each
// operation of a job, so the safety gate can hold each captured connection to
// the engine's OWN number rather than a copy of the formula.
//
// It reads one engine job (the JSON the engine reads on stdin) and writes
// {"port": N, "probes": {"name": N}}: the admission for a port's first
// connection and for each probe, at the job's connect timeout clamped exactly as
// fingerprint.Run clamps it.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/fingerprint"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

func main() {
	var job enginewire.ToEngine
	if err := json.NewDecoder(os.Stdin).Decode(&job); err != nil {
		fmt.Fprintln(os.Stderr, "admissiondump:", err)
		os.Exit(1)
	}
	timeout := fingerprint.ClampConnectTimeout(time.Duration(job.ConnectTimeoutMS) * time.Millisecond)
	probes := map[string]uint32{}
	for _, p := range job.Probes {
		probes[p.Name] = fingerprint.ProbeAdmission(fingerprint.Probe{
			Name: p.Name, Kind: p.Kind, Payload: p.Payload, TLS: p.TLS,
		}, timeout)
	}
	out, err := json.Marshal(map[string]any{
		"port":       fingerprint.PortAdmission(timeout),
		"probes":     probes,
		"timeout_ms": timeout.Milliseconds(),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "admissiondump:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
