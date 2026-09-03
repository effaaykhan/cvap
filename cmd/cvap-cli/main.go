// Command cvap-cli is the CVAP operator command line.
package main

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/logging"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	log := logging.New(os.Stderr, logging.Options{Level: slog.LevelInfo})

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "dev-ca":
		if err := devCA(log, os.Args[2:]); err != nil {
			log.Error("dev-ca failed", slog.Any("error", err))
			os.Exit(1)
		}
	default:
		log.Error("unknown command", slog.String("command", os.Args[1]))
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `cvap-cli %s

  dev-ca <dir>   Generate a DEVELOPMENT certificate authority into <dir>.

`, version)
}

// devCA writes a self-signed CA for local use.
//
// Development only, and the warning is not boilerplate. This key mints
// identities into a scan point fleet, and Core holds a complete map of a
// customer's exploitable weaknesses plus credentials to their estate — so a CA
// key on a developer's disk is not a rough edge, it is the whole compromise
// (architecture-v2 §18.3). A real deployment supplies its own anchor, which is
// what ADR-018 means by the trust anchor being configuration rather than an
// assumption baked into the binary.
//
// Twenty-four hours, deliberately short. A development CA that outlives the
// afternoon is one that ends up in a deployment.
func devCA(log *slog.Logger, args []string) error {
	dir := "./secrets"
	if len(args) > 0 && args[0] != "" {
		dir = args[0]
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "cvap development CA", 24*time.Hour)
	if err != nil {
		return err
	}
	log.Warn("generated a DEVELOPMENT certificate authority; never use this key anywhere real",
		slog.String("cert", certPath),
		slog.String("key", keyPath),
		slog.Duration("valid_for", 24*time.Hour))
	return nil
}
