package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom [artifact]",
	Short: "Generate SBOM for an artifact",
	Long: `Generate Software Bill of Materials (SBOM) for an artifact.

This command generates an SBOM using Syft and outputs it in the specified
format. Unlike 'attest', this command only generates the SBOM without
vulnerability scanning or signing.

Supported Formats:
  • cyclonedx-json (default)
  • spdx-json
  • syft-json
`,
	Example: `  # Generate SBOM for a Docker image
  provenix sbom nginx:latest

  # Generate SBOM with spdx-json format
  provenix sbom --format spdx-json myapp:v1.0

  # Output to specific file
  provenix sbom myapp --output sbom.json`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOM,
}

func init() {
	sbomCmd.Flags().StringP("output", "o", "-", "Output file path (- for stdout)")
	sbomCmd.Flags().String("format", "cyclonedx-json", "SBOM format")
}

func runSBOM(cmd *cobra.Command, args []string) error {
	artifact := args[0]
	fmt.Printf("📦 Generating SBOM for: %s\n", artifact)
	fmt.Println("⚠️  Not implemented yet - coming in Week 3-6")
	return nil
}
