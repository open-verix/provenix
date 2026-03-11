package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/providers"
	sbomprovider "github.com/open-verix/provenix/internal/providers/sbom"
	scannerprovider "github.com/open-verix/provenix/internal/providers/scanner"
)

var scanCmd = &cobra.Command{
	Use:   "scan [artifact|sbom-file]",
	Short: "Scan artifact or SBOM for vulnerabilities",
	Long: `Scan for vulnerabilities using Grype.

This command can either:
  1. Scan an artifact directly (generates SBOM internally)
  2. Scan an existing SBOM file

Vulnerability reports include severity ratings and remediation guidance.
`,
	Example: `  # Scan a Docker image
  provenix scan nginx:latest

  # Scan an existing SBOM
  provenix scan --sbom sbom.json

  # Output scan results to file
  provenix scan myapp --output scan-results.json`,
	Args: cobra.ExactArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringP("output", "o", "-", "Output file path (- for stdout)")
	scanCmd.Flags().String("sbom", "", "Path to existing SBOM file to scan")
}

func runScan(cmd *cobra.Command, args []string) error {
	target := args[0]
	output, _ := cmd.Flags().GetString("output")
	sbomPath, _ := cmd.Flags().GetString("sbom")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	start := time.Now()
	var sbomObj *sbomprovider.SBOM
	var err error

	// Get SBOM: either from file or generate it
	if sbomPath != "" {
		data, err := os.ReadFile(sbomPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to read SBOM file: %v\n", err)
			os.Exit(ExitFatal)
		}
		sbomObj = &sbomprovider.SBOM{}
		if err := json.Unmarshal(data, sbomObj); err != nil {
			fmt.Fprintf(os.Stderr, "❌ Invalid SBOM file: %v\n", err)
			os.Exit(ExitFatal)
		}
	} else {
		// Generate SBOM from artifact
		sbomProvider, err := providers.GetSBOMProvider("syft")
		if err != nil {
			sbomProvider, _ = providers.GetSBOMProvider("mock")
		}
		s1 := newSpinner(fmt.Sprintf("Generating SBOM for %s...", target))
		s1.Start()
		sbomObj, err = sbomProvider.Generate(ctx, target, sbomprovider.Options{Format: sbomprovider.FormatCycloneDXJSON})
		if err != nil {
			s1.Fail(fmt.Sprintf("❌ SBOM generation failed: %v", err))
			os.Exit(ExitFatal)
		}
		s1.Success("✅ SBOM generated")
	}

	// Scan SBOM for vulnerabilities
	scanProvider, err := providers.GetScannerProvider("grype")
	if err != nil {
		scanProvider, _ = providers.GetScannerProvider("mock")
	}

	s2 := newSpinner("Scanning for vulnerabilities...")
	s2.Start()
	report, err := scanProvider.Scan(ctx, scannerprovider.ScanInput{Artifact: target, SBOM: sbomObj}, scannerprovider.DefaultOptions())
	if err != nil {
		s2.Fail(fmt.Sprintf("❌ Scan failed: %v", err))
		os.Exit(ExitFatal)
	}
	s2.Success(fmt.Sprintf("✅ Scan complete  %d vulnerabilities found", len(report.Vulnerabilities)))
	duration := time.Since(start)

	// Format output
	reportJSON, _ := json.MarshalIndent(report, "", "  ")

	if output == "-" {
		fmt.Println(string(reportJSON))
	} else {
		if err := os.WriteFile(output, reportJSON, 0644); err != nil {
			fmt.Printf("❌ Failed to write scan report: %v\n", err)
			os.Exit(ExitFatal)
		}
		fmt.Printf("✅ Scan report saved to: %s\n", output)
	}

	// Summary to stderr (JSON report goes to stdout)
	fmt.Fprintf(os.Stderr, "\n📊 Summary:\n")
	fmt.Fprintf(os.Stderr, "  Artifact:         %s\n", target)
	fmt.Fprintf(os.Stderr, "  Vulnerabilities:  %d\n", len(report.Vulnerabilities))
	fmt.Fprintf(os.Stderr, "  Duration:         %v\n", duration)

	return nil
}
