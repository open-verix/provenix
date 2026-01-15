package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/providers"
	sbomprovider "github.com/open-verix/provenix/internal/providers/sbom"
)

var sbomCmd = &cobra.Command{
	Use:   "sbom [artifact]",
	Short: "Generate SBOM for an artifact",
	Long: `Generate Software Bill of Materials (SBOM) for an artifact.

This command generates an SBOM using Syft and outputs it in the specified
format. Unlike 'attest', this command only generates the SBOM without
vulnerability scanning or signing.

Supported Formats:
  • cyclonedx-json (default) - Security-focused, VEX support
  • spdx-json - ISO standard, compliance-focused
  • syft-json - Syft native format, most detailed
`,
	Example: `  # Generate SBOM for a Docker image
  provenix sbom nginx:latest

  # Generate SBOM with SPDX format
  provenix sbom --format spdx-json myapp:v1.0

  # Generate SBOM with Syft native format
  provenix sbom --format syft-json myapp:v1.0

  # Output to specific file
  provenix sbom myapp --output sbom.json`,
	Args: cobra.ExactArgs(1),
	RunE: runSBOM,
}

func init() {
	sbomCmd.Flags().StringP("output", "o", "-", "Output file path (- for stdout)")
	sbomCmd.Flags().String("format", "cyclonedx-json", "SBOM format (cyclonedx-json, spdx-json, syft-json)")
}

func runSBOM(cmd *cobra.Command, args []string) error {
	artifact := args[0]
	formatStr, _ := cmd.Flags().GetString("format")
	output, _ := cmd.Flags().GetString("output")

	fmt.Printf("📦 Generating SBOM for: %s\n", artifact)

	// Get SBOM provider (prefer real provider, fallback to mock)
	sbomProvider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		sbomProvider, _ = providers.GetSBOMProvider("mock")
	}

	// Generate SBOM
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Convert format string to Format type
	format := sbomprovider.Format(formatStr)
	opts := sbomprovider.Options{
		Format: format,
	}

	start := time.Now()
	sbom, err := sbomProvider.Generate(ctx, artifact, opts)
	if err != nil {
		fmt.Printf("❌ SBOM generation failed: %v\n", err)
		os.Exit(ExitFatal)
	}
	duration := time.Since(start)

	// Output result
	if output == "-" {
		fmt.Println(string(sbom.Content))
	} else {
		if err := os.WriteFile(output, sbom.Content, 0644); err != nil {
			fmt.Printf("❌ Failed to write SBOM: %v\n", err)
			os.Exit(ExitFatal)
		}
		fmt.Printf("✅ SBOM saved to: %s\n", output)
	}

	fmt.Printf("📊 Summary:\n")
	fmt.Printf("  Artifact:   %s\n", artifact)
	fmt.Printf("  Format:     %s\n", formatStr)
	fmt.Printf("  Duration:   %v\n", duration)

	return nil
}
