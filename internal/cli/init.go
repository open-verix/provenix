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

	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Provenix (download vulnerability database and optionally generate keys)",
	Long: `Initialize Provenix by downloading the Grype vulnerability database.

This command should be run once before using attestation or scanning features.
The database will be stored in the default Grype cache location:
  ~/.cache/grype/db/

The database is updated regularly by Grype and contains vulnerability 
information from multiple sources (NVD, OSV, GitHub, etc.).

Optionally, you can generate a development key pair for local testing with --generate-key.`,
	Example: `  # Initialize vulnerability database
  provenix init

  # Generate development keys for local testing
  provenix init --generate-key

  # Specify custom key output location
  provenix init --generate-key --key-output ./dev-keys/cosign

  # The database will be used by these commands:
  provenix attest alpine:latest
  provenix scan alpine:latest
  provenix report dependencies alpine:latest`,
	RunE: runInit,
}

var (
	initGenerateKey bool
	initKeyOutput   string
)

func init() {
	initCmd.Flags().BoolVar(&initGenerateKey, "generate-key", false, "Generate development key pair for local signing")
	initCmd.Flags().StringVar(&initKeyOutput, "key-output", ".provenix/cosign", "Output path prefix for generated keys")
}

func runInit(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Step 1: Generate keys if requested
	if initGenerateKey {
		if err := generateDevKeys(initKeyOutput); err != nil {
			return fmt.Errorf("failed to generate development keys: %w", err)
		}
	}

	// Step 2: Initialize vulnerability database
	fmt.Fprintln(os.Stderr, "🔄 Initializing Provenix...")
	fmt.Fprintln(os.Stderr, "📥 Downloading Grype vulnerability database (this may take a few minutes)...")

	// Get Grype provider
	scannerProvider, err := providers.GetScannerProvider("grype")
	if err != nil {
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
		fmt.Fprintf(os.Stderr, "\n❌ Error: %v\n", err)
		return fmt.Errorf("failed to initialize vulnerability database: %w", err)
	}

	_ = dummyReport // Ignore the report

	fmt.Fprintln(os.Stderr, "✅ Initialization complete!")
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
