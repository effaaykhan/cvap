// Command cvap-scanpoint runs the CVAP Scan Point runtime.
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
	log.Info("scan point runtime starting", slog.String("version", version))
	log.Info("no engines registered yet")
}
