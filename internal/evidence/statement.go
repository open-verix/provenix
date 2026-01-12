package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

// in-toto Statement v1 structures
// Reference: https://github.com/in-toto/attestation/tree/main/spec

// Statement represents an in-toto attestation statement.
type Statement struct {
	Type          string        `json:"_type"`
	Subject       []Subject     `json:"subject"`
	PredicateType string        `json:"predicateType"`
	Predicate     interface{}   `json:"predicate"`
}

// Subject identifies the artifact being attested.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// ProvenixPredicate is the custom predicate for Provenix atomic evidence.
type ProvenixPredicate struct {
	// SBOM contains the Software Bill of Materials
	SBOM *SBOMAttestation `json:"sbom"`

	// VulnerabilityReport contains the vulnerability scan results
	VulnerabilityReport *VulnerabilityAttestation `json:"vulnerabilityReport"`

	// Metadata contains generation metadata
	Metadata *AttestationMetadata `json:"metadata"`
}

// SBOMAttestation wraps SBOM data for attestation.
type SBOMAttestation struct {
	Format  string          `json:"format"`  // e.g., "cyclonedx-json", "spdx-json"
	Version string          `json:"version"` // Format version
	Content json.RawMessage `json:"content"` // Raw SBOM content
}

// VulnerabilityAttestation wraps vulnerability scan results.
type VulnerabilityAttestation struct {
	Scanner          string                        `json:"scanner"`          // e.g., "grype"
	ScannerVersion   string                        `json:"scannerVersion"`
	ScannedAt        time.Time                     `json:"scannedAt"`
	VulnerabilityDB  string                        `json:"vulnerabilityDB"`  // e.g., "grype-db:v5.14.0"
	TotalCount       int                           `json:"totalCount"`
	CriticalCount    int                           `json:"criticalCount"`
	HighCount        int                           `json:"highCount"`
	MediumCount      int                           `json:"mediumCount"`
	LowCount         int                           `json:"lowCount"`
	UnknownCount     int                           `json:"unknownCount"`
	Vulnerabilities  []VulnerabilitySummary        `json:"vulnerabilities"`
}

// VulnerabilitySummary contains a summary of a single vulnerability.
type VulnerabilitySummary struct {
	ID               string   `json:"id"`               // e.g., "CVE-2024-1234"
	Severity         string   `json:"severity"`         // CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
	PackageName      string   `json:"packageName"`
	PackageVersion   string   `json:"packageVersion"`
	FixedInVersions  []string `json:"fixedInVersions,omitempty"`
	Description      string   `json:"description,omitempty"`
}

// AttestationMetadata contains metadata about the attestation.
type AttestationMetadata struct {
	GeneratedAt      time.Time `json:"generatedAt"`
	GeneratorName    string    `json:"generatorName"`    // "provenix"
	GeneratorVersion string    `json:"generatorVersion"`
	SBOMProvider     string    `json:"sbomProvider"`     // e.g., "syft@v1.40.0"
	ScannerProvider  string    `json:"scannerProvider"`  // e.g., "grype@v0.104.4"
}

// CreateStatement creates an in-toto attestation statement from SBOM and vulnerability report.
func CreateStatement(
	artifact string,
	artifactDigest string,
	sbomData *sbom.SBOM,
	vulnReport *scanner.Report,
	generatorVersion string,
	sbomProviderName string,
	sbomProviderVersion string,
	scannerProviderName string,
	scannerProviderVersion string,
) ([]byte, error) {
	// Create subject
	subject := Subject{
		Name: artifact,
		Digest: map[string]string{
			"sha256": artifactDigest,
		},
	}

	// Convert SBOM to attestation format
	sbomAttestation := &SBOMAttestation{
		Format:  string(sbomData.Format),
		Version: "", // Version is embedded in the SBOM content
		Content: sbomData.Content,
	}

	// Convert vulnerability report to attestation format
	vulnAttestation := convertVulnReport(vulnReport, scannerProviderName, scannerProviderVersion)

	// Create metadata
	metadata := &AttestationMetadata{
		GeneratedAt:      time.Now().UTC(),
		GeneratorName:    "provenix",
		GeneratorVersion: generatorVersion,
		SBOMProvider:     fmt.Sprintf("%s@%s", sbomProviderName, sbomProviderVersion),
		ScannerProvider:  fmt.Sprintf("%s@%s", scannerProviderName, scannerProviderVersion),
	}

	// Create predicate
	predicate := &ProvenixPredicate{
		SBOM:                sbomAttestation,
		VulnerabilityReport: vulnAttestation,
		Metadata:            metadata,
	}

	// Create statement
	statement := &Statement{
		Type:          "https://in-toto.io/Statement/v1",
		Subject:       []Subject{subject},
		PredicateType: "https://provenix.dev/attestation/v1",
		Predicate:     predicate,
	}

	// Marshal to JSON
	statementJSON, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}

	return statementJSON, nil
}

// convertVulnReport converts a vulnerability report to attestation format.
func convertVulnReport(
	report *scanner.Report,
	scannerName string,
	scannerVersion string,
) *VulnerabilityAttestation {
	// Count vulnerabilities by severity
	counts := map[scanner.Severity]int{
		scanner.SeverityCritical: 0,
		scanner.SeverityHigh:     0,
		scanner.SeverityMedium:   0,
		scanner.SeverityLow:      0,
		scanner.SeverityUnknown:  0,
	}

	summaries := make([]VulnerabilitySummary, 0, len(report.Vulnerabilities))
	for _, vuln := range report.Vulnerabilities {
		counts[vuln.Severity]++
		
		// Convert Severity to string
		severityStr := string(vuln.Severity)
		
		// Convert FixedVersion to slice
		fixedVersions := []string{}
		if vuln.FixedVersion != "" {
			fixedVersions = append(fixedVersions, vuln.FixedVersion)
		}
		
		summaries = append(summaries, VulnerabilitySummary{
			ID:              vuln.ID,
			Severity:        severityStr,
			PackageName:     vuln.Package,
			PackageVersion:  vuln.Version,
			FixedInVersions: fixedVersions,
			Description:     vuln.Description,
		})
	}

	return &VulnerabilityAttestation{
		Scanner:         scannerName,
		ScannerVersion:  scannerVersion,
		ScannedAt:       report.ScannedAt,
		VulnerabilityDB: report.DBVersion,
		TotalCount:      len(report.Vulnerabilities),
		CriticalCount:   counts[scanner.SeverityCritical],
		HighCount:       counts[scanner.SeverityHigh],
		MediumCount:     counts[scanner.SeverityMedium],
		LowCount:        counts[scanner.SeverityLow],
		UnknownCount:    counts[scanner.SeverityUnknown],
		Vulnerabilities: summaries,
	}
}

// ComputeDigest computes SHA256 digest of the statement.
func ComputeDigest(statement []byte) string {
	hash := sha256.Sum256(statement)
	return hex.EncodeToString(hash[:])
}
