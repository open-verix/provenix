package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [artifact|sbom-file]",
	Short: "Scan artifact or SBOM for vulnerabilities",
	Long: `Scan for vulnerabilities using Grype.

This command can either:
  1. Scan an artifact directly (generates SBOM internally)
  2. Scan an existing SBOM file

Vulnerability reports include severity ratings and remediation guidance.
`,
	Example: `  # Scan a Docker image
  provenix scan nginx:latest

  # Scan an existing SBOM
  provenix scan --sbom sbom.json

  # Output scan results to file
  provenix scan myapp --output scan-results.json`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("output", "o", "-", "Output file path (- for stdout)")
	scanCmd.Flags().String("sbom", "", "Path to existing SBOM file to scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	fmt.Printf("🔎 Scanning for vulnerabilities: %s\n", target)
	fmt.Println("⚠️  Not implemented yet - coming in Week 3-6")
	return nil
}
