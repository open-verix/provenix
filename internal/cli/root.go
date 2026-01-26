package cli

import (
	"fmt"
	"runtime"
	"github.com/spf13/cobra"
)

var (
	// Version is set at build time via ldflags
	Version = "dev"
	// GitCommit is set at build time via ldflags
	GitCommit = "unknown"
	// BuildDate is set at build time via ldflags
	BuildDate = "unknown"
)

// SetVersion sets the version information from main package
func SetVersion(version, commit, buildTime string) {
	if version != "" {
		Version = version
	}
	if commit != "" {
		GitCommit = commit
	}
	if buildTime != "" {
		BuildDate = buildTime
	}
}

var rootCmd = &cobra.Command{
	Use:   "provenix",
	Short: "Policy-Driven Software Supply Chain Orchestrator",
	Long: `Provenix generates atomic evidence for software artifacts.

It orchestrates SBOM generation, vulnerability scanning, and cryptographic
signing in a single atomic operation with cryptographic integrity guarantees.

Key Features:
  • Atomic Evidence: SBOM + Vulnerability Scan + Signature in one operation
  • Keyless Signing: OIDC-based signing via Sigstore (no private keys)
  • Transparency: Automatic publishing to Rekor transparency log
  • Policy-Driven: Configurable security policies via provenix.yaml

Exit Codes:
  0 - Complete success (attestation signed and published to Rekor)
  1 - Fatal error (cryptographic failure, artifact not found)
  2 - Partial success (attestation saved locally, Rekor unavailable)

Documentation: https://github.com/open-verix/provenix/docs
`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(attestCmd)
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(publishCmd)
	rootCmd.AddCommand(verifyCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("provenix version %s\n", Version)
		fmt.Printf("  commit: %s\n", GitCommit)
		fmt.Printf("  built:  %s\n", BuildDate)
		fmt.Printf("  go:     %s\n", runtime.Version())
	},
}
