package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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
	
	// Get flags
	localMode, _ := cmd.Flags().GetBool("local")
	outputPath, _ := cmd.Flags().GetString("output")
	sbomFormat, _ := cmd.Flags().GetString("format")
	configPath, _ := cmd.Flags().GetString("config")
	keyPath, _ := cmd.Flags().GetString("key")
	
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
	
	// Override with CLI flags
	if sbomFormat != "" {
		cfg.SBOM.Format = sbomFormat
	}
	if keyPath != "" {
		cfg.Signing.Key.Path = keyPath
		cfg.Signing.Mode = "key"
	}
	// Local mode: skip Rekor transparency log
	if localMode && cfg.Signing.Mode != "key" {
		// In keyless mode with --local, still use keyless but skip Rekor
		cfg.Rekor.URL = "" // Empty URL means skip transparency log
	} else if localMode && cfg.Signing.Mode == "key" {
		// In key mode with --local, also skip Rekor
		cfg.Rekor.URL = ""
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
			SkipTransparency: cfg.Rekor.URL == "",
			Local:            localMode,
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
	
	// Save attestation
	if err := saveEvidence(ev, outputPath); err != nil {
		return fmt.Errorf("failed to save attestation: %w", err)
	}
    
	fmt.Printf("💾 Attestation saved to: %s\n", outputPath)
	
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

	// Exit code semantics
	// 0: signed and published to Rekor
	// 2: partial success (saved locally, Rekor unavailable)
	// Local mode (skip transparency) is considered success
	skipTransparency := cfg.Rekor.URL == "" || opts.SignOptions.SkipTransparency
	if skipTransparency {
		fmt.Println("🌐 Transparency: skipped (local mode)")
		return nil
	}

	if ev.Signature != nil && ev.Signature.RekorEntry != "" {
		fmt.Printf("🌐 Published to Rekor: %s\n", ev.Signature.RekorEntry)
		return nil
	}

	fmt.Println("🌐 Rekor publishing failed or unavailable; local attestation retained")
	return &ExitError{Code: 2, Err: fmt.Errorf("rekor publishing unavailable")}
}

// saveEvidence saves evidence to a JSON file.
func saveEvidence(ev *evidence.Evidence, path string) error {
	data, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
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
