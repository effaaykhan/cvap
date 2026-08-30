// Command cvap-cli is the CVAP operator command line.
package main

import (
	"log/slog"
	"os"

	"github.com/effaaykhan/cvap/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := logging.New(os.Stderr, logging.Options{Level: slog.LevelInfo})
	log.Info("operator cli", slog.String("version", version))
	log.Info("no commands registered yet")
}
