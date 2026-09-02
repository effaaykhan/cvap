// Command cvap-core runs the CVAP Control Plane.
package main

import (
	"log/slog"
	"os"

	// Embedded IANA timezone database.
	//
	// scan_policies.time_windows may name a zone — a maintenance window is
	// written in the operator's local time, not in UTC — and dispatch resolves
	// it with time.LoadLocation, which fails closed: a zone it cannot resolve
	// refuses the job rather than silently treating the window as UTC and
	// scanning an hour outside it for half the year.
	//
	// A scratch or distroless image carries no /usr/share/zoneinfo, so without
	// this every named window would fail on the deployment where it matters and
	// pass on every developer's laptop. Roughly 450 KB, in the binary rather
	// than in the base image, so it cannot go missing when the image changes.
	//
	// A FALLBACK, not an override: the system database still wins where there is
	// one, so a host with stale tzdata moves a maintenance window by an hour in
	// whichever direction the rule changed. Embedding removes the "no zones at
	// all" failure, not the "wrong zones" one.
	_ "time/tzdata"

	"github.com/effaaykhan/cvap/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := logging.New(os.Stdout, logging.Options{Level: slog.LevelInfo})
	log.Info("control plane starting", slog.String("version", version))
	log.Info("no services registered yet")
}
