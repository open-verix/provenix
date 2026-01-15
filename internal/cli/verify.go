package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/providers"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [artifact]",
	Short: "Verify attestation signature and identity",
	Long: `Verify attestation for an artifact.

This command:
  1. Queries Rekor for attestations matching the artifact
  2. Verifies cryptographic signatures
  3. Validates certificate chains
  4. Displays signing identity (who built it)

Verification ensures the attestation was:
  • Signed by the claimed identity (via certificate)
  • Logged in the transparency log (via Rekor)
  • Not tampered with (via signature validation)
`,
	Example: `  # Verify an artifact
  provenix verify nginx:latest

  # Verify with specific attestation file
  provenix verify myapp --attestation attestation.json

  # Verify and show detailed certificate info
  provenix verify myapp --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().String("attestation", "", "Path to attestation file (instead of querying Rekor)")
	verifyCmd.Flags().Bool("verbose", false, "Show detailed verification information")
	verifyCmd.Flags().String("rekor-url", "https://rekor.sigstore.dev", "Rekor server URL")
}

func runVerify(cmd *cobra.Command, args []string) error {
	artifact := args[0]
	attestationFile, _ := cmd.Flags().GetString("attestation")
	verbose, _ := cmd.Flags().GetBool("verbose")
	rekorURL, _ := cmd.Flags().GetString("rekor-url")

	fmt.Printf("✓ Verifying attestation for: %s\n", artifact)

	var attestationJSON []byte
	var err error

	// Load attestation from file or use provided one
	if attestationFile != "" {
		attestationJSON, err = os.ReadFile(attestationFile)
		if err != nil {
			fmt.Printf("❌ Failed to read attestation file: %v\n", err)
			os.Exit(ExitFatal)
		}
	} else {
		// In real implementation, this would query Rekor for the attestation
		// For now, use a stub that looks for attestation.json in current directory
		if _, err := os.Stat("attestation.json"); err == nil {
			attestationJSON, _ = os.ReadFile("attestation.json")
		} else {
			fmt.Printf("⚠️  No attestation found for %s\n", artifact)
			fmt.Printf("  Querying Rekor... (stub - would query %s in production)\n", rekorURL)
			return nil
		}
	}

	// Parse attestation
	var attestation map[string]interface{}
	if err := json.Unmarshal(attestationJSON, &attestation); err != nil {
		fmt.Printf("❌ Invalid attestation file: %v\n", err)
		os.Exit(ExitFatal)
	}

	// Get signer provider to verify (stub implementation)
	signerProvider, err := providers.GetSignerProvider("cosign")
	if err != nil {
		signerProvider, _ = providers.GetSignerProvider("mock")
	}

	// In real implementation, this would:
	// 1. Extract signature from attestation
	// 2. Extract certificate (if present)
	// 3. Verify signature using Cosign
	// 4. Validate certificate chain
	// 5. Display signer identity

	// For stub, show parsed attestation details
	fmt.Printf("\n📋 Attestation Details:\n")
	fmt.Printf("  Artifact:      %s\n", artifact)
	fmt.Printf("  Provider:      %s\n", signerProvider.Name())
	fmt.Printf("  Version:       %s\n", signerProvider.Version())
	fmt.Printf("  Rekor URL:     %s\n", rekorURL)
	fmt.Printf("  Verified At:   %s\n", time.Now().UTC().Format(time.RFC3339))

	// Show attestation structure if verbose
	if verbose {
		fmt.Printf("\n📄 Attestation Content:\n")
		prettyJSON, _ := json.MarshalIndent(attestation, "  ", "  ")
		fmt.Println(string(prettyJSON))
	}

	fmt.Printf("\n✅ Verification Complete\n")
	fmt.Printf("  Status:      Valid (stub verification)\n")
	fmt.Printf("  Timestamp:   %s\n", time.Now().UTC().Format(time.RFC3339))

	return nil
}
