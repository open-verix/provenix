package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

var (
	reportIncludeIndirect bool
	reportOutputFormat    string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate various reports from evidence",
	Long: `Generate reports from attestation evidence.

Available report types:
  dependencies - Analyze dependency tree and vulnerabilities
  summary      - High-level summary of evidence

Reports can be generated from existing attestation files or by
generating new evidence on-the-fly.`,
}

var reportDepsCmd = &cobra.Command{
	Use:   "dependencies [artifact-or-attestation]",
	Short: "Generate dependency analysis report",
	Long: `Generate a comprehensive dependency analysis report.

This command analyzes the dependency tree, including:
  • Direct and indirect dependencies
  • License distribution
  • Vulnerability summary
  • Package counts and statistics

Input can be either:
  1. Path to existing attestation.json file
  2. Artifact name (will generate evidence first)

Example Output:
  # Dependency Report for alpine:latest
  
  ## Summary
  - Total Packages: 42
  - Direct Dependencies: 0 (base image)
  - Indirect Dependencies: 42
  - Vulnerabilities: 2 (0 critical, 0 high, 1 medium, 1 low)
  
  ## License Distribution
  - GPL-2.0: 15 packages
  - MIT: 12 packages
  - Apache-2.0: 8 packages
  - BSD-3-Clause: 5 packages
  - Other: 2 packages`,
	Example: `  # From existing attestation
  provenix report dependencies attestation.json

  # From artifact (generates evidence first)
  provenix report dependencies alpine:latest

  # Include detailed package list
  provenix report dependencies alpine:latest --include-indirect

  # Output as JSON
  provenix report dependencies attestation.json --format json`,
	Args: cobra.ExactArgs(1),
	RunE: runReportDependencies,
}

func init() {
	reportCmd.AddCommand(reportDepsCmd)
	
	reportDepsCmd.Flags().BoolVar(&reportIncludeIndirect, "include-indirect", false, "Include detailed indirect dependency list")
	reportDepsCmd.Flags().StringVar(&reportOutputFormat, "format", "markdown", "Output format: markdown, json")
}

func runReportDependencies(cmd *cobra.Command, args []string) error {
	input := args[0]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Check if input is an existing attestation file
	var ev *evidence.Evidence
	if _, err := os.Stat(input); err == nil && strings.HasSuffix(input, ".json") {
		// Load existing attestation
		data, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("failed to read attestation file: %w", err)
		}

		ev = &evidence.Evidence{}
		if err := json.Unmarshal(data, ev); err != nil {
			return fmt.Errorf("failed to parse attestation: %w", err)
		}

		fmt.Fprintf(os.Stderr, "Loaded attestation for: %s\n", ev.Artifact)
	} else {
		// Generate evidence for artifact (SBOM + Scan only, no signing needed)
		fmt.Fprintf(os.Stderr, "Generating evidence for: %s\n", input)

		sbomProvider, err := providers.GetSBOMProvider("syft")
		if err != nil {
			return fmt.Errorf("SBOM provider not available: %w", err)
		}

		scannerProvider, err := providers.GetScannerProvider("grype")
		if err != nil {
			return fmt.Errorf("scanner provider not available: %w", err)
		}

		// Generate SBOM
		fmt.Fprintf(os.Stderr, "📦 Generating SBOM...\n")
		sbomResult, err := sbomProvider.Generate(ctx, input, sbom.Options{
			Format: sbom.FormatCycloneDXJSON,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ Error: %v\n", err)
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}

		// Scan for vulnerabilities
		fmt.Fprintf(os.Stderr, "🔍 Scanning for vulnerabilities...\n")
		vulnReport, err := scannerProvider.Scan(ctx, scanner.ScanInput{
			SBOM: sbomResult,
		}, scanner.Options{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n❌ Error: %v\n", err)
			return fmt.Errorf("failed to scan vulnerabilities: %w", err)
		}

		// Create evidence structure (without signature)
		ev = &evidence.Evidence{
			Artifact:            input,
			ArtifactDigest:      sbomResult.Checksum,
			SBOM:                sbomResult,
			VulnerabilityReport: vulnReport,
			Metadata: &evidence.Metadata{
				GeneratedAt:      time.Now(),
				GeneratorVersion: Version,
				SBOMProvider: evidence.ProviderInfo{
					Name:    sbomResult.ProviderName,
					Version: sbomResult.ProviderVersion,
				},
				ScannerProvider: evidence.ProviderInfo{
					Name:    vulnReport.ProviderName,
					Version: vulnReport.ProviderVersion,
				},
			},
		}
	}

	// Generate report
	report := generateDependencyReport(ev)

	// Output report
	switch reportOutputFormat {
	case "json":
		return outputReportJSON(report)
	case "markdown", "md":
		return outputReportMarkdown(report, ev)
	default:
		return fmt.Errorf("unsupported format: %s", reportOutputFormat)
	}
}

type DependencyReport struct {
	Artifact             string
	TotalPackages        int
	DirectDependencies   int
	IndirectDependencies int
	Packages             []PackageInfo
	Vulnerabilities      VulnerabilitySummary
	Licenses             map[string]int
}

type PackageInfo struct {
	Name    string
	Version string
	License string
	Type    string
}

type VulnerabilitySummary struct {
	Total      int
	Critical   int
	High       int
	Medium     int
	Low        int
	Negligible int
}

func generateDependencyReport(ev *evidence.Evidence) *DependencyReport {
	report := &DependencyReport{
		Artifact: ev.Artifact,
		Licenses: make(map[string]int),
	}

	// Parse SBOM content
	var sbomData map[string]interface{}
	if err := json.Unmarshal(ev.SBOM.Content, &sbomData); err != nil {
		return report
	}

	// Extract packages from CycloneDX format
	if components, ok := sbomData["components"].([]interface{}); ok {
		report.TotalPackages = len(components)
		report.IndirectDependencies = len(components) // Most are indirect for containers

		for _, comp := range components {
			if c, ok := comp.(map[string]interface{}); ok {
				pkg := PackageInfo{}
				
				if name, ok := c["name"].(string); ok {
					pkg.Name = name
				}
				if version, ok := c["version"].(string); ok {
					pkg.Version = version
				}
				if purl, ok := c["purl"].(string); ok {
					pkg.Type = extractTypeFromPurl(purl)
				}
				
				// Extract license
				if licenses, ok := c["licenses"].([]interface{}); ok && len(licenses) > 0 {
					if lic, ok := licenses[0].(map[string]interface{}); ok {
						if license, ok := lic["license"].(map[string]interface{}); ok {
							if id, ok := license["id"].(string); ok {
								pkg.License = id
								report.Licenses[id]++
							} else if name, ok := license["name"].(string); ok {
								pkg.License = name
								report.Licenses[name]++
							}
						}
					}
				}
				
				if pkg.License == "" {
					pkg.License = "Unknown"
					report.Licenses["Unknown"]++
				}

				report.Packages = append(report.Packages, pkg)
			}
		}
	}

	// Analyze vulnerabilities
	if ev.VulnerabilityReport != nil {
		report.Vulnerabilities.Total = len(ev.VulnerabilityReport.Vulnerabilities)
		
		for _, vuln := range ev.VulnerabilityReport.Vulnerabilities {
			switch vuln.Severity {
			case "Critical":
				report.Vulnerabilities.Critical++
			case "High":
				report.Vulnerabilities.High++
			case "Medium":
				report.Vulnerabilities.Medium++
			case "Low":
				report.Vulnerabilities.Low++
			case "Negligible":
				report.Vulnerabilities.Negligible++
			}
		}
	}

	return report
}

func extractTypeFromPurl(purl string) string {
	// Extract type from Package URL (e.g., "pkg:apk/alpine/...")
	if strings.HasPrefix(purl, "pkg:") {
		parts := strings.SplitN(purl[4:], "/", 2)
		if len(parts) > 0 {
			return parts[0]
		}
	}
	return "unknown"
}

func outputReportJSON(report *DependencyReport) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func outputReportMarkdown(report *DependencyReport, ev *evidence.Evidence) error {
	var out strings.Builder

	// Header
	out.WriteString(fmt.Sprintf("# Dependency Report: %s\n\n", report.Artifact))
	out.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	out.WriteString(fmt.Sprintf("**Artifact Digest:** `%s`\n\n", ev.ArtifactDigest))

	// Summary
	out.WriteString("## Summary\n\n")
	out.WriteString(fmt.Sprintf("- **Total Packages:** %d\n", report.TotalPackages))
	out.WriteString(fmt.Sprintf("- **Direct Dependencies:** %d\n", report.DirectDependencies))
	out.WriteString(fmt.Sprintf("- **Indirect Dependencies:** %d\n", report.IndirectDependencies))
	out.WriteString(fmt.Sprintf("- **Vulnerabilities:** %d", report.Vulnerabilities.Total))
	
	if report.Vulnerabilities.Total > 0 {
		out.WriteString(fmt.Sprintf(" (%d critical, %d high, %d medium, %d low, %d negligible)\n",
			report.Vulnerabilities.Critical,
			report.Vulnerabilities.High,
			report.Vulnerabilities.Medium,
			report.Vulnerabilities.Low,
			report.Vulnerabilities.Negligible))
	} else {
		out.WriteString("\n")
	}
	out.WriteString("\n")

	// Vulnerability Status
	out.WriteString("## Vulnerability Status\n\n")
	if report.Vulnerabilities.Total == 0 {
		out.WriteString("✅ **No vulnerabilities detected**\n\n")
	} else {
		if report.Vulnerabilities.Critical > 0 {
			out.WriteString(fmt.Sprintf("🔴 **Critical:** %d vulnerabilities require immediate attention\n", report.Vulnerabilities.Critical))
		}
		if report.Vulnerabilities.High > 0 {
			out.WriteString(fmt.Sprintf("🟠 **High:** %d vulnerabilities\n", report.Vulnerabilities.High))
		}
		if report.Vulnerabilities.Medium > 0 {
			out.WriteString(fmt.Sprintf("🟡 **Medium:** %d vulnerabilities\n", report.Vulnerabilities.Medium))
		}
		if report.Vulnerabilities.Low > 0 {
			out.WriteString(fmt.Sprintf("🟢 **Low:** %d vulnerabilities\n", report.Vulnerabilities.Low))
		}
		if report.Vulnerabilities.Negligible > 0 {
			out.WriteString(fmt.Sprintf("⚪ **Negligible:** %d vulnerabilities\n", report.Vulnerabilities.Negligible))
		}
		out.WriteString("\n")
	}

	// License Distribution
	out.WriteString("## License Distribution\n\n")
	
	// Sort licenses by count (descending)
	type licenseCount struct {
		License string
		Count   int
	}
	var licenses []licenseCount
	for lic, count := range report.Licenses {
		licenses = append(licenses, licenseCount{lic, count})
	}
	sort.Slice(licenses, func(i, j int) bool {
		return licenses[i].Count > licenses[j].Count
	})

	for _, lc := range licenses {
		out.WriteString(fmt.Sprintf("- **%s:** %d packages\n", lc.License, lc.Count))
	}
	out.WriteString("\n")

	// Package Type Distribution
	out.WriteString("## Package Types\n\n")
	pkgTypes := make(map[string]int)
	for _, pkg := range report.Packages {
		pkgTypes[pkg.Type]++
	}
	
	var types []licenseCount
	for t, count := range pkgTypes {
		types = append(types, licenseCount{t, count})
	}
	sort.Slice(types, func(i, j int) bool {
		return types[i].Count > types[j].Count
	})

	for _, tc := range types {
		out.WriteString(fmt.Sprintf("- **%s:** %d packages\n", tc.License, tc.Count))
	}
	out.WriteString("\n")

	// Detailed package list (if requested)
	if reportIncludeIndirect && len(report.Packages) > 0 {
		out.WriteString("## Package List\n\n")
		out.WriteString("| Name | Version | License | Type |\n")
		out.WriteString("|------|---------|---------|------|\n")

		// Sort packages by name
		sortedPkgs := make([]PackageInfo, len(report.Packages))
		copy(sortedPkgs, report.Packages)
		sort.Slice(sortedPkgs, func(i, j int) bool {
			return sortedPkgs[i].Name < sortedPkgs[j].Name
		})

		for _, pkg := range sortedPkgs {
			out.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				pkg.Name, pkg.Version, pkg.License, pkg.Type))
		}
		out.WriteString("\n")
	}

	// Metadata
	out.WriteString("## Evidence Metadata\n\n")
	out.WriteString(fmt.Sprintf("- **SBOM Provider:** %s v%s\n", ev.Metadata.SBOMProvider.Name, ev.Metadata.SBOMProvider.Version))
	out.WriteString(fmt.Sprintf("- **Scanner Provider:** %s v%s\n", ev.Metadata.ScannerProvider.Name, ev.Metadata.ScannerProvider.Version))
	out.WriteString(fmt.Sprintf("- **Signer Provider:** %s v%s\n", ev.Metadata.SignerProvider.Name, ev.Metadata.SignerProvider.Version))
	out.WriteString(fmt.Sprintf("- **Generated At:** %s\n", ev.Metadata.GeneratedAt.Format(time.RFC3339)))
	out.WriteString(fmt.Sprintf("- **Generation Duration:** %v\n", ev.Metadata.Duration))

	fmt.Print(out.String())
	return nil
}
