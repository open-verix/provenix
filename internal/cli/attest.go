package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var attestCmd = &cobra.Command{
	Use:   "attest [artifact]",
	Short: "Generate SBOM, scan vulnerabilities, and create signed attestation",
	Long: `Generate atomic evidence for a software artifact.

This command orchestrates the complete attestation workflow:
  1. Generate SBOM using Syft
  2. Scan vulnerabilities using Grype
  3. Create in-toto statement
  4. Sign with Cosign (keyless via OIDC)
  5. Publish to Rekor transparency log

The entire operation is atomic - all data flows in-memory with no temporary
files, ensuring the SBOM and vulnerability report represent the exact state
of the artifact at signing time.

Exit Codes:
  0 - Complete success (signed and published)
  1 - Fatal error (cryptographic failure)
  2 - Partial success (saved locally, Rekor unavailable)

Supported Artifacts:
  • Container images (Docker, OCI)
  • OCI archives (.tar files)
  • Directories
  • Single binaries
`,
	Example: `  # Attest a Docker image
  provenix attest nginx:latest

  # Attest with local-only mode (no Rekor publishing)
  provenix attest --local ./myapp

  # Attest with custom output path
  provenix attest myapp:v1.0 --output attestation.json

  # Use custom configuration
  provenix attest myapp --config provenix.yaml

  # Use local private key (for development)
  provenix attest myapp --key path/to/key.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runAttest,
}

func init() {
	attestCmd.Flags().Bool("local", false, "Local-only mode (no Rekor publishing)")
	attestCmd.Flags().StringP("output", "o", "attestation.json", "Output file path")
	attestCmd.Flags().String("format", "cyclonedx-json", "SBOM format (cyclonedx-json, spdx-json, syft-json)")
	attestCmd.Flags().String("config", "", "Path to provenix.yaml configuration file")
	attestCmd.Flags().String("key", "", "Path to private key (for development)")
}

func runAttest(cmd *cobra.Command, args []string) error {
	artifact := args[0]
	fmt.Printf("🔍 Attesting artifact: %s\n", artifact)
	fmt.Println("⚠️  Not implemented yet - coming in Week 6-7")
	return nil
}
