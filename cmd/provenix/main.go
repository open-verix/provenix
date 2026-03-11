package main

import (
	"os"

	"github.com/open-verix/provenix/internal/cli"
)

// Version information (set via ldflags during build).
// Defaults are empty so SetVersion does not overwrite values
// already injected into internal/cli.* by goreleaser ldflags.
var (
	version   = ""
	commit    = ""
	buildTime = ""
)

func main() {
	// Set version info for CLI
	cli.SetVersion(version, commit, buildTime)
	
	if err := cli.Execute(); err != nil {
		os.Exit(cli.ExitCode(err))
	}
}
