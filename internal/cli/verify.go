package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/providers/signer/cosign"
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
	verifyCmd.Flags().String("public-key", "", "Path to public key file (for key-based verification)")
	verifyCmd.Flags().Bool("verbose", false, "Show detailed verification information")
	verifyCmd.Flags().String("rekor-url", "https://rekor.sigstore.dev", "Rekor server URL")
}

func runVerify(cmd *cobra.Command, args []string) error {
	artifact := args[0]
	attestationFile, _ := cmd.Flags().GetString("attestation")
	publicKeyPath, _ := cmd.Flags().GetString("public-key")
	verbose, _ := cmd.Flags().GetBool("verbose")
	rekorURL, _ := cmd.Flags().GetString("rekor-url")

	fmt.Printf("🔍 Verifying attestation for: %s\n", artifact)

	// Determine attestation file path
	if attestationFile == "" {
		// Default to attestation.json in current directory
		if _, err := os.Stat("attestation.json"); err == nil {
			attestationFile = "attestation.json"
		} else {
			fmt.Printf("❌ No attestation file found\n")
			fmt.Printf("  Use --attestation to specify attestation file\n")
			fmt.Printf("  Or place attestation.json in current directory\n")
			os.Exit(ExitFatal)
		}
	}

	ctx := context.Background()
	var result *cosign.VerificationResult
	var err error

	// Perform verification (key-based or keyless)
	if publicKeyPath != "" {
		// Key-based verification with explicit public key
		fmt.Printf("  Using public key from file: %s\n", publicKeyPath)
		result, err = cosign.VerifyKeyPath(ctx, attestationFile, publicKeyPath, rekorURL)
	} else {
		// Try key-based verification first (using embedded public key)
		// If that fails, fall back to keyless verification
		result, err = cosign.VerifyKeyPath(ctx, attestationFile, "", rekorURL)
		if err != nil && (result == nil || !result.Valid) {
			// Fallback to keyless verification
			fmt.Printf("  Using keyless verification (certificate-based)\n")
			result, err = cosign.VerifyKeyless(ctx, attestationFile, rekorURL)
		} else {
			fmt.Printf("  Using key-based verification (embedded public key)\n")
		}
	}

	if err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
		os.Exit(ExitFatal)
	}

	// Display verification results
	fmt.Printf("\n📋 Verification Results:\n")
	fmt.Printf("  Artifact:          %s\n", result.Artifact)
	fmt.Printf("  Signature Valid:   %v\n", formatCheckmark(result.SignatureValid))
	fmt.Printf("  Certificate Valid: %v\n", formatCheckmark(result.CertificateValid))
	fmt.Printf("  Rekor Valid:       %v\n", formatCheckmark(result.RekorValid))

	if result.Identity != nil {
		fmt.Printf("\n👤 Signer Identity:\n")
		fmt.Printf("  Subject:    %s\n", result.Identity.Subject)
		if result.Identity.Issuer != "" {
			fmt.Printf("  Issuer:     %s\n", result.Identity.Issuer)
		}
		fmt.Printf("  Valid From: %s\n", result.Identity.NotBefore)
		fmt.Printf("  Valid To:   %s\n", result.Identity.NotAfter)
	}

	if result.RekorEntry != nil {
		fmt.Printf("\n📝 Transparency Log:\n")
		fmt.Printf("  Log Index:  %d\n", result.RekorEntry.LogIndex)
		fmt.Printf("  UUID:       %s\n", result.RekorEntry.UUID)
		fmt.Printf("  Entry URL:  https://search.sigstore.dev/?logIndex=%d\n", result.RekorEntry.LogIndex)
	}

	// Show errors if any
	if len(result.Errors) > 0 {
		fmt.Printf("\n⚠️  Verification Errors:\n")
		for _, errMsg := range result.Errors {
			fmt.Printf("  • %s\n", errMsg)
		}
	}

	// Show detailed attestation if verbose
	if verbose {
		fmt.Printf("\n📄 Detailed Attestation:\n")
		prettyJSON, _ := json.MarshalIndent(result, "  ", "  ")
		fmt.Println(string(prettyJSON))
	}

	// Final verdict
	fmt.Printf("\n")
	if result.Valid {
		fmt.Printf("✅ Verification PASSED\n")
		fmt.Printf("   All checks passed successfully\n")
		fmt.Printf("   Verified at: %s\n", time.Now().UTC().Format(time.RFC3339))
		return nil
	} else {
		fmt.Printf("❌ Verification FAILED\n")
		fmt.Printf("   One or more checks failed\n")
		fmt.Printf("   See errors above for details\n")
		os.Exit(ExitFatal)
		return nil
	}
}

func formatCheckmark(valid bool) string {
	if valid {
		return "✓ (valid)"
	}
	return "✗ (invalid)"
}
