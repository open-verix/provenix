package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

var (
	vexOutputFile string
	vexFormat     string
)

var vexCmd = &cobra.Command{
	Use:   "vex",
	Short: "Manage VEX (Vulnerability Exploitability eXchange) documents",
	Long: `Generate and manage VEX documents for vulnerability triage.

VEX documents allow you to communicate the exploitability status of vulnerabilities
in your software, including:
- Not affected (vulnerability doesn't apply)
- Affected (vulnerability confirmed)
- Fixed (vulnerability patched)
- Under investigation (status unknown)

This helps downstream consumers understand which vulnerabilities are actual risks.`,
	Example: `  # Generate VEX from attestation
  provenix vex generate attestation.json

  # Generate VEX from artifact
  provenix vex generate alpine:latest

  # Output in CycloneDX format
  provenix vex generate attestation.json --format cyclonedx`,
}

var vexGenerateCmd = &cobra.Command{
	Use:   "generate [artifact-or-attestation]",
	Short: "Generate VEX document from vulnerability scan",
	Long: `Generate a VEX document from an attestation or artifact.

The VEX document provides machine-readable vulnerability status information
that can be consumed by security scanners and policy engines.

Supported formats:
- openvex (default): OpenVEX format
- cyclonedx: CycloneDX VEX format
- csaf: CSAF VEX format`,
	Example: `  # From existing attestation
  provenix vex generate attestation.json

  # From Docker image
  provenix vex generate nginx:latest

  # Specify output format
  provenix vex generate alpine:latest --format cyclonedx -o vex.json`,
	Args: cobra.ExactArgs(1),
	RunE: runVEXGenerate,
}

func init() {
	vexCmd.AddCommand(vexGenerateCmd)

	vexGenerateCmd.Flags().StringVarP(&vexOutputFile, "output", "o", "vex.json", "Output VEX file")
	vexGenerateCmd.Flags().StringVar(&vexFormat, "format", "openvex", "VEX format: openvex, cyclonedx, csaf")
}

func runVEXGenerate(cmd *cobra.Command, args []string) error {
	input := args[0]
	_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Check if input is an existing attestation file
	var ev *evidence.Evidence
	if _, err := os.Stat(input); err == nil && (input == "attestation.json" || len(input) > 5 && input[len(input)-5:] == ".json") {
		// Load existing attestation
		data, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("failed to read attestation file: %w", err)
		}

		ev = &evidence.Evidence{}
		if err := json.Unmarshal(data, ev); err != nil {
			return fmt.Errorf("failed to parse attestation: %w", err)
		}

		fmt.Fprintf(os.Stderr, "📄 Loaded attestation for: %s\n", ev.Artifact)
	} else {
		return fmt.Errorf("VEX generation from live artifacts not yet implemented - use attestation.json")
	}

	// Check if there are any vulnerabilities
	if ev.VulnerabilityReport == nil {
		return fmt.Errorf("no vulnerability report found in attestation")
	}

	vulnCount := len(ev.VulnerabilityReport.Vulnerabilities)
	fmt.Fprintf(os.Stderr, "🔍 Found %d vulnerabilities to process\n", vulnCount)

	// Generate VEX document
	vexDoc, err := generateVEXDocument(ev, vexFormat)
	if err != nil {
		return fmt.Errorf("failed to generate VEX document: %w", err)
	}

	// Write VEX to file
	vexData, err := json.MarshalIndent(vexDoc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal VEX document: %w", err)
	}

	if err := os.WriteFile(vexOutputFile, vexData, 0644); err != nil {
		return fmt.Errorf("failed to write VEX file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✅ VEX document written to: %s\n", vexOutputFile)
	fmt.Fprintf(os.Stderr, "   Format: %s\n", vexFormat)
	fmt.Fprintf(os.Stderr, "   Vulnerabilities: %d\n", vulnCount)

	return nil
}

// VEXDocument represents an OpenVEX document
type VEXDocument struct {
	Context      string         `json:"@context"`
	ID           string         `json:"@id"`
	Author       string         `json:"author"`
	Timestamp    string         `json:"timestamp"`
	Version      string         `json:"version"`
	Tooling      string         `json:"tooling,omitempty"`
	Statements   []VEXStatement `json:"statements"`
}

// VEXStatement represents a single VEX statement about a vulnerability
type VEXStatement struct {
	VulnerabilityID   string   `json:"vulnerability"`
	Products          []string `json:"products"`
	Status            string   `json:"status"`
	StatusNotes       string   `json:"status_notes,omitempty"`
	Justification     string   `json:"justification,omitempty"`
	ImpactStatement   string   `json:"impact_statement,omitempty"`
	ActionStatement   string   `json:"action_statement,omitempty"`
	ActionStatementTS string   `json:"action_statement_timestamp,omitempty"`
}

func generateVEXDocument(ev *evidence.Evidence, format string) (interface{}, error) {
	switch format {
	case "openvex":
		return generateOpenVEX(ev)
	case "cyclonedx":
		return generateCycloneDXVEX(ev)
	case "csaf":
		return nil, fmt.Errorf("CSAF VEX format not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported VEX format: %s", format)
	}
}

func generateOpenVEX(ev *evidence.Evidence) (*VEXDocument, error) {
	doc := &VEXDocument{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        fmt.Sprintf("https://provenix.dev/vex/%s", ev.ArtifactDigest),
		Author:    "Provenix",
		Timestamp: time.Now().Format(time.RFC3339),
		Version:   "1",
		Tooling:   fmt.Sprintf("Provenix %s (Grype %s)", Version, ev.Metadata.ScannerProvider.Version),
		Statements: []VEXStatement{},
	}

	// Generate statements for each vulnerability
	for _, vuln := range ev.VulnerabilityReport.Vulnerabilities {
		status := determineVEXStatus(vuln)
		justification := determineJustification(vuln)

		statement := VEXStatement{
			VulnerabilityID: vuln.ID,
			Products: []string{
				ev.Artifact,
			},
			Status:        status,
			Justification: justification,
		}

		// Add status notes
		if vuln.FixedVersion != "" {
			statement.StatusNotes = fmt.Sprintf("Fixed in version %s", vuln.FixedVersion)
			statement.ActionStatement = fmt.Sprintf("Upgrade %s to version %s or later", vuln.Package, vuln.FixedVersion)
		} else {
			statement.StatusNotes = "No fix available"
			statement.ActionStatement = "Monitor for updates from upstream maintainer"
		}

		doc.Statements = append(doc.Statements, statement)
	}

	return doc, nil
}

func generateCycloneDXVEX(ev *evidence.Evidence) (interface{}, error) {
	// CycloneDX VEX implementation
	// For now, return error as not implemented
	return nil, fmt.Errorf("CycloneDX VEX format not yet implemented")
}

func determineVEXStatus(vuln scanner.Vulnerability) string {
	// Determine VEX status based on vulnerability data
	// Possible values: not_affected, affected, fixed, under_investigation

	if vuln.FixedVersion != "" {
		return "fixed"
	}

	// For now, mark all as affected
	// In a real implementation, this would involve:
	// - Analyzing if the vulnerable code path is actually used
	// - Checking if the vulnerability applies to this configuration
	// - Consulting a VEX database or manual triage results
	return "affected"
}

func determineJustification(vuln scanner.Vulnerability) string {
	// Determine justification for not_affected status
	// Possible values: component_not_present, vulnerable_code_not_present,
	// vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary,
	// inline_mitigations_already_exist

	// For affected vulnerabilities, justification is empty
	if vuln.FixedVersion != "" {
		return ""
	}

	// Default: no justification needed for affected status
	return ""
}
