package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	
	"github.com/open-verix/provenix/internal/config"
	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	sbommock "github.com/open-verix/provenix/internal/providers/sbom/mock"
	"github.com/open-verix/provenix/internal/providers/scanner"
	scannermock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	"github.com/open-verix/provenix/internal/providers/signer"
	signermock "github.com/open-verix/provenix/internal/providers/signer/mock"
)

var attestCmd = &cobra.Command{
	Use:   "attest [artifact]",
	Short: "Generate SBOM, scan vulnerabilities, and create signed attestation",
	Long: `Generate atomic evidence for a software artifact.

This command orchestrates the complete attestation workflow:
  1. Generate SBOM using Syft
  2. Scan vulnerabilities using Grype
  3. Create in-toto statement
  4. Sign with Cosign (keyless via OIDC or local key)
  5. Publish to Rekor transparency log (unless --key is used)

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
	attestCmd.Flags().StringP("output", "o", "", "Output file path (default: .provenix/attestations/sha256-{digest}.json)")
	attestCmd.Flags().String("format", "cyclonedx-json", "SBOM format (cyclonedx-json, spdx-json, syft-json)")
	attestCmd.Flags().String("config", "", "Path to provenix.yaml configuration file")
	attestCmd.Flags().String("key", "", "Path to private key (for development)")
	attestCmd.Flags().Bool("skip-transparency", false, "Skip Rekor transparency log publishing (keyless signing only)")
	
	// Private Sigstore instance flags
	attestCmd.Flags().String("fulcio-url", "", "Fulcio URL (for private Sigstore instances)")
	attestCmd.Flags().String("rekor-url", "", "Rekor URL (for private Sigstore instances)")
	attestCmd.Flags().String("oidc-issuer", "", "OIDC issuer URL (for private Sigstore instances)")
	attestCmd.Flags().String("tuf-root", "", "Path to TUF root.json (for private Sigstore instances)")
	attestCmd.Flags().Bool("insecure-skip-verify", false, "Skip TLS verification (for testing private instances)")
}

func runAttest(cmd *cobra.Command, args []string) error {
	artifact := args[0]
	
	// Get flags
	outputPath, _ := cmd.Flags().GetString("output")
	sbomFormat, _ := cmd.Flags().GetString("format")
	configPath, _ := cmd.Flags().GetString("config")
	keyPath, _ := cmd.Flags().GetString("key")
	skipTransparency, _ := cmd.Flags().GetBool("skip-transparency")
	
	// Private Sigstore instance flags
	fulcioURL, _ := cmd.Flags().GetString("fulcio-url")
	rekorURL, _ := cmd.Flags().GetString("rekor-url")
	oidcIssuer, _ := cmd.Flags().GetString("oidc-issuer")
	tufRoot, _ := cmd.Flags().GetString("tuf-root")
	insecureSkipVerify, _ := cmd.Flags().GetBool("insecure-skip-verify")
	
	fmt.Printf("🔍 Attesting artifact: %s\n", artifact)
	
	// Load configuration
	var cfg *config.Config
	var err error
	
	if configPath != "" {
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		cfg = config.Default()
	}
	
	// Override config with CLI flags
	if fulcioURL != "" {
		cfg.Signing.OIDC.FulcioURL = fulcioURL
	}
	if rekorURL != "" {
		cfg.Rekor.URL = rekorURL
	}
	if oidcIssuer != "" {
		cfg.Signing.OIDC.Issuer = oidcIssuer
	}
	if tufRoot != "" {
		cfg.Rekor.TUFRoot = tufRoot
	}
	if insecureSkipVerify {
		cfg.Rekor.InsecureSkipVerify = insecureSkipVerify
	}
	
	// Override with CLI flags
	if sbomFormat != "" {
		cfg.SBOM.Format = sbomFormat
	}
	if keyPath != "" {
		cfg.Signing.Key.Path = keyPath
		cfg.Signing.Mode = "key"
	}
	
	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}
	
	// TODO: Replace with actual provider implementations in Week 5-7
	// For now, use mock providers to demonstrate the pipeline
	fmt.Println("⚠️  Using real Syft/Grype providers (Cosign stub)")
	
	// Get SBOM provider (Syft is registered in internal/providers/sbom/register.go)
	sbomProvider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		fmt.Println("⚠️  Syft provider not available, falling back to mock")
		sbomProvider = sbommock.NewProvider()
	}
	
	// Get scanner provider (Grype is registered in internal/providers/scanner/register.go)
	scannerProvider, err := providers.GetScannerProvider("grype")
	if err != nil {
		fmt.Println("⚠️  Grype provider not available, falling back to mock")
		scannerProvider = scannermock.NewProvider()
	}
	
	// Get signer provider (Cosign is registered in internal/providers/signer/register.go)
	signerProvider, err := providers.GetSignerProvider("cosign")
	if err != nil {
		fmt.Println("⚠️  Cosign provider not available, falling back to mock")
		signerProvider = signermock.NewProvider()
	}
	
	// Create evidence generator
	gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)
	
	// Prepare generation options
	opts := evidence.GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.Format(cfg.SBOM.Format),
		},
		ScanOptions: scanner.Options{
			FailOnSeverity: scanner.Severity(cfg.Scan.FailOn),
		},
		SignOptions: signer.Options{
			Mode:             signer.SigningMode(cfg.Signing.Mode),
			KeyPath:          cfg.Signing.Key.Path,
			FulcioURL:        cfg.Signing.OIDC.FulcioURL,
			RekorURL:         cfg.Rekor.URL,
			OIDCClientID:     "sigstore",
			SkipTransparency: skipTransparency || cfg.Rekor.URL == "",
		},
		GeneratorVersion: Version,
	}
	
	// Generate evidence
	fmt.Println("📦 Generating SBOM...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	
	ev, err := gen.Generate(ctx, artifact, opts)
	if err != nil {
		fmt.Printf("❌ Evidence generation failed: %v\n", err)
		return err
	}
	
	fmt.Printf("✅ SBOM generated (%s, %d packages)\n", 
		ev.SBOM.Format, 
		extractPackageCount(ev.SBOM))
	
	fmt.Printf("🔍 Vulnerability scan complete (%d vulnerabilities found)\n",
		len(ev.VulnerabilityReport.Vulnerabilities))
	
	fmt.Printf("🔏 Signature created (provider: %s)\n", 
		ev.Signature.SignerProvider)
	
	// Determine save path and save attestation
	savePath, err := saveEvidenceWithFallback(ev, outputPath)
	if err != nil {
		return fmt.Errorf("failed to save attestation: %w", err)
	}
	
	fmt.Printf("💾 Attestation saved to: %s\n", savePath)
	
	// Summary
	fmt.Println("\n📊 Summary:")
	fmt.Printf("  Artifact:        %s\n", ev.Artifact)
	fmt.Printf("  Digest:          %s\n", ev.ArtifactDigest)
	fmt.Printf("  SBOM Format:     %s\n", ev.SBOM.Format)
	fmt.Printf("  Vulnerabilities: %d\n", len(ev.VulnerabilityReport.Vulnerabilities))
	fmt.Printf("  Generation Time: %s\n", ev.Metadata.Duration)
	
	// Check if we should fail based on vulnerability severity
	if ev.VulnerabilityReport.ShouldFail(scanner.Severity(cfg.Scan.FailOn)) {
		fmt.Printf("\n⚠️  Found vulnerabilities above threshold: %s\n", cfg.Scan.FailOn)
		// Policy-controlled behavior; we do not change exit code here yet
	}

	// Exit code semantics:
	// 0: Complete success (signed and published to Rekor)
	// 2: Partial success (signed but Rekor unavailable)
	// 1: Fatal error (handled by error return)
	
	shouldSkipTransparency := cfg.Rekor.URL == "" || opts.SignOptions.SkipTransparency
	
	if shouldSkipTransparency {
		fmt.Println("\n🌐 Transparency: skipped (air-gapped mode)")
		fmt.Printf("\n✅ Attestation complete (exit code: %d)\n", ExitSuccess)
		return nil
	}

	// Check Rekor publishing status
	if ev.Signature != nil && ev.Signature.RekorEntry != "" {
		fmt.Printf("\n🌐 Published to Rekor: %s\n", ev.Signature.RekorEntry)
		if ev.Signature.RekorLogIndex > 0 {
			fmt.Printf("   Log Index: %d\n", ev.Signature.RekorLogIndex)
		}
		fmt.Printf("\n✅ Attestation complete (exit code: %d)\n", ExitSuccess)
		return nil
	}

	// Rekor publishing failed - partial success scenario
	fmt.Println("\n⚠️  Rekor Unavailable")
	fmt.Println("   Attestation signed and saved locally")
	fmt.Printf("   Location: %s\n", savePath)
	fmt.Println("\n💡 Re-publish later with:")
	fmt.Printf("   provenix publish %s\n", savePath)
	fmt.Printf("\n⚠️  Partial Success (exit code: %d)\n", ExitPartialSuccess)
	
	return &ExitError{Code: ExitPartialSuccess, Err: fmt.Errorf("rekor publishing unavailable")}
}

// saveEvidence saves evidence to a JSON file in AttestationBundle format.
func saveEvidence(ev *evidence.Evidence, path string) error {
	// Create attestation bundle for verification
	// CRITICAL: Store statement as base64 string to preserve exact bytes
	// json.RawMessage gets re-formatted when marshaled with indent
	bundle := map[string]interface{}{
		"statementBase64": base64.StdEncoding.EncodeToString(ev.Statement),
		"signature":       ev.Signature.Signature,
		"certificate":     ev.Signature.Certificate,
		"publicKey":       ev.Signature.PublicKey,
		"rekorUUID":       ev.Signature.RekorEntry,
	}
	if ev.Signature.RekorLogIndex > 0 {
		bundle["rekorLogIndex"] = int(ev.Signature.RekorLogIndex)
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attestation bundle: %w", err)
	}
	
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	return nil
}

// extractPackageCount tries to extract package count from SBOM content.
func extractPackageCount(s *sbom.SBOM) int {
	// This is a best-effort extraction from the SBOM content
	// The actual structure depends on the format
	var content map[string]interface{}
	if err := json.Unmarshal(s.Content, &content); err != nil {
		return 0
	}
	
	// Try CycloneDX format
	if components, ok := content["components"].([]interface{}); ok {
		return len(components)
	}
	
	// Try SPDX format
	if packages, ok := content["packages"].([]interface{}); ok {
		return len(packages)
	}
	
	return 0
}

// getDefaultAttestationPath generates the default attestation storage path.
// Format: .provenix/attestations/sha256-{first-12-chars}.json
func getDefaultAttestationPath(digest string) (string, error) {
	// Create .provenix/attestations directory if it doesn't exist
	attestDir := ".provenix/attestations"
	if err := os.MkdirAll(attestDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create attestation directory: %w", err)
	}

	// Extract first 12 characters of digest for filename
	digestShort := digest
	if len(digest) > 12 {
		// Remove "sha256:" prefix if present
		if idx := strings.Index(digest, ":"); idx != -1 {
			digestShort = digest[idx+1:]
		}
		if len(digestShort) > 12 {
			digestShort = digestShort[:12]
		}
	}

	filename := fmt.Sprintf("sha256-%s.json", digestShort)
	return filepath.Join(attestDir, filename), nil
}

// saveEvidenceWithFallback saves evidence to the specified path and returns
// whether Rekor publishing should be attempted.
// If outputPath is empty, generates default path in .provenix/attestations/
func saveEvidenceWithFallback(ev *evidence.Evidence, outputPath string) (string, error) {
	// Use provided path or generate default
	savePath := outputPath
	if savePath == "" {
		var err error
		savePath, err = getDefaultAttestationPath(ev.ArtifactDigest)
		if err != nil {
			return "", err
		}
	}

	// Save the attestation
	if err := saveEvidence(ev, savePath); err != nil {
		return "", fmt.Errorf("failed to save attestation: %w", err)
	}

	return savePath, nil
}
