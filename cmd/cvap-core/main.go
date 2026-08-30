// Command cvap-core runs the CVAP Control Plane.
package main

import (
	"log/slog"
	"os"

	"github.com/effaaykhan/cvap/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := logging.New(os.Stdout, logging.Options{Level: slog.LevelInfo})
	log.Info("control plane starting", slog.String("version", version))
	log.Info("no services registered yet")
}
