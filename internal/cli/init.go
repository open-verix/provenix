package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/policy"
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Provenix (create provenix.yaml, download vulnerability database)",
	Long: `Initialize Provenix for the current project.

This command should be run once in each project directory before using
attestation or scanning features. It performs the following steps:

  1. Create provenix.yaml with default tool config and policy settings
     (skipped if the file already exists — use --force to regenerate)
  2. Create the .provenix/ working directory
  3. Download the Grype vulnerability database (~200MB, first run only)
     stored in ~/.cache/grype/db/
  4. Optionally generate a development key pair (--generate-key)

The generated provenix.yaml contains both tool configuration (sbom, scan,
signing, rekor) and the policy: section in one unified file.`,
	Example: `  # Standard first-time setup
  provenix init

  # Regenerate provenix.yaml (overwrite existing)
  provenix init --force

  # Also generate development keys for local signing
  provenix init --generate-key

  # The following commands are then available:
  provenix attest alpine:latest
  provenix scan alpine:latest
  provenix report dependencies alpine:latest`,
	RunE: runInit,
}

var (
	initGenerateKey bool
	initKeyOutput   string
	initForce       bool
)

func init() {
	initCmd.Flags().BoolVar(&initGenerateKey, "generate-key", false, "Generate development key pair for local signing")
	initCmd.Flags().StringVar(&initKeyOutput, "key-output", ".provenix/cosign", "Output path prefix for generated keys")
	initCmd.Flags().BoolVar(&initForce, "force", false, "Overwrite provenix.yaml even if it already exists")
}

func runInit(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Step 0: Create .provenix/ directory
	if err := os.MkdirAll(".provenix", 0755); err != nil {
		return fmt.Errorf("failed to create .provenix directory: %w", err)
	}

	// Step 1: Generate provenix.yaml (skip if exists unless --force)
	const configFile = "provenix.yaml"
	_, statErr := os.Stat(configFile)
	switch {
	case statErr != nil: // file does not exist
		if err := policy.SaveUnifiedConfig(policy.DefaultConfig(), configFile); err != nil {
			return fmt.Errorf("failed to create %s: %w", configFile, err)
		}
		fmt.Fprintf(os.Stderr, "✅ Created %s (tool config + policy)\n", configFile)
	case initForce: // file exists but --force given
		if err := policy.SaveUnifiedConfig(policy.DefaultConfig(), configFile); err != nil {
			return fmt.Errorf("failed to overwrite %s: %w", configFile, err)
		}
		fmt.Fprintf(os.Stderr, "✅ Regenerated %s (overwritten)\n", configFile)
	default: // file exists, no --force
		fmt.Fprintf(os.Stderr, "ℹ️  %s already exists, skipping\n", configFile)
		fmt.Fprintf(os.Stderr, "   To regenerate: provenix init --force\n")
	}

	// Step 2: Generate keys if requested
	if initGenerateKey {
		if err := generateDevKeys(initKeyOutput); err != nil {
			return fmt.Errorf("failed to generate development keys: %w", err)
		}
	}

	// Step 3: Initialize vulnerability database
	s := newSpinner("Downloading Grype vulnerability database (~200MB, first run only)...")
	s.Start()

	// Get Grype provider
	scannerProvider, err := providers.GetScannerProvider("grype")
	if err != nil {
		s.Fail(fmt.Sprintf("❌ Scanner provider not available: %v", err))
		return fmt.Errorf("scanner provider not available: %w", err)
	}

	// Trigger database initialization by performing a dummy scan
	// Use empty SBOM to trigger database download without actual scanning
	dummyReport, err := scannerProvider.Scan(ctx, scanner.ScanInput{
		SBOM: &sbom.SBOM{
			Artifact: "init",
			Format:   sbom.FormatCycloneDXJSON,
			Content:  []byte(`{"bomFormat":"CycloneDX","specVersion":"1.2","components":[]}`),
		},
	}, scanner.Options{
		OfflineDB: false, // Force database download
	})
	if err != nil {
		s.Fail(fmt.Sprintf("❌ Failed to initialize vulnerability database: %v", err))
		return fmt.Errorf("failed to initialize vulnerability database: %w", err)
	}

	_ = dummyReport // Ignore the report

	s.Success("✅ Vulnerability database ready")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "You can now use:")
	if initGenerateKey {
		fmt.Fprintf(os.Stderr, "  provenix attest <artifact> --key %s.key\n", initKeyOutput)
	} else {
		fmt.Fprintln(os.Stderr, "  provenix attest <artifact>")
	}
	fmt.Fprintln(os.Stderr, "  provenix scan <artifact>")
	fmt.Fprintln(os.Stderr, "  provenix report dependencies <artifact>")

	return nil
}

// generateDevKeys generates a development ECDSA key pair for local signing.
// Keys are saved in Cosign-compatible format (encrypted private key).
func generateDevKeys(outputPrefix string) error {
	fmt.Fprintln(os.Stderr, "🔑 Generating development key pair...")

	// Create output directory if needed
	dir := filepath.Dir(outputPrefix)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Generate ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Marshal private key to PKCS#8 format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Use EC PRIVATE KEY format (Cosign compatible)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Marshal public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Write private key
	privateKeyPath := outputPrefix + ".key"
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write public key
	publicKeyPath := outputPrefix + ".pub"
	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Development keys generated:\n")
	fmt.Fprintf(os.Stderr, "   Private: %s (keep secret!)\n", privateKeyPath)
	fmt.Fprintf(os.Stderr, "   Public:  %s\n", publicKeyPath)
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "⚠️  WARNING: These keys are for DEVELOPMENT ONLY")
	fmt.Fprintln(os.Stderr, "   For production, use keyless signing (no --key flag)")
	fmt.Fprintln(os.Stderr, "")

	return nil
}
