package main

import (
	"os"

	"github.com/open-verix/provenix/internal/cli"
)

// Version information (set via ldflags during build)
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	// Set version info for CLI
	cli.SetVersion(version, commit, buildTime)
	
	if err := cli.Execute(); err != nil {
		os.Exit(cli.ExitCode(err))
	}
}
