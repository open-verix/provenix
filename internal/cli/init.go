package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize Provenix (download vulnerability database)",
	Long: `Initialize Provenix by downloading the Grype vulnerability database.

This command should be run once before using attestation or scanning features.
The database will be stored in the default Grype cache location:
  ~/.cache/grype/db/

The database is updated regularly by Grype and contains vulnerability 
information from multiple sources (NVD, OSV, GitHub, etc.).`,
	Example: `  # Initialize vulnerability database
  provenix init

  # The database will be used by these commands:
  provenix attest alpine:latest
  provenix scan alpine:latest
  provenix report dependencies alpine:latest`,
	RunE: runInit,
}

func runInit(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

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
	fmt.Fprintln(os.Stderr, "  provenix attest <artifact>")
	fmt.Fprintln(os.Stderr, "  provenix scan <artifact>")
	fmt.Fprintln(os.Stderr, "  provenix report dependencies <artifact>")

	return nil
}
