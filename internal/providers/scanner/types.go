package scanner

import (
	"encoding/json"
	"time"
	
	"github.com/open-verix/provenix/internal/providers/sbom"
)

// Severity represents the severity of a vulnerability.
type Severity string

const (
	SeverityUnknown    Severity = "Unknown"
	SeverityNegligible Severity = "Negligible"
	SeverityLow        Severity = "Low"
	SeverityMedium     Severity = "Medium"
	SeverityHigh       Severity = "High"
	SeverityCritical   Severity = "Critical"
)

// Vulnerability represents a single security vulnerability.
type Vulnerability struct {
	// ID is the vulnerability identifier (e.g., "CVE-2024-1234", "GHSA-xxxx-xxxx-xxxx")
	ID string `json:"id"`
	
	// Severity is the vulnerability severity
	Severity Severity `json:"severity"`
	
	// Package is the affected package name
	Package string `json:"package"`
	
	// Version is the affected package version
	Version string `json:"version"`
	
	// FixedVersion is the version that fixes the vulnerability (empty if no fix available)
	FixedVersion string `json:"fixed_version,omitempty"`
	
	// Description is a brief description of the vulnerability
	Description string `json:"description,omitempty"`
	
	// URLs contains references for more information
	URLs []string `json:"urls,omitempty"`
}

// Report represents a vulnerability scan report.
// This is an in-memory representation that must never be written to temporary files.
type Report struct {
	// Artifact is the scanned artifact identifier (must match the SBOM artifact)
	Artifact string `json:"artifact"`
	
	// Vulnerabilities is the list of discovered vulnerabilities
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	
	// Content is the raw scan report in the provider's native format
	// Used for detailed analysis and debugging
	Content json.RawMessage `json:"content"`
	
	// Checksum is the SHA256 hash of the Content
	Checksum string `json:"checksum"`
	
	// ScannedAt is the timestamp when the scan was performed
	ScannedAt time.Time `json:"scanned_at"`
	
	// ProviderName is the name of the scanner provider
	ProviderName string `json:"provider_name"`
	
	// ProviderVersion is the version of the scanner provider
	ProviderVersion string `json:"provider_version"`
	
	// DBVersion is the vulnerability database version used
	DBVersion string `json:"db_version,omitempty"`
}

// Options configures vulnerability scanning behavior.
type Options struct {
	// FailOnSeverity causes the scan to fail if vulnerabilities of this severity or higher are found
	// Empty string means never fail
	FailOnSeverity Severity
	
	// OnlyFixed only reports vulnerabilities that have a fix available
	OnlyFixed bool
	
	// IgnoreVulnerabilities is a list of vulnerability IDs to ignore
	IgnoreVulnerabilities []string
	
	// OfflineDB uses a local vulnerability database instead of fetching updates
	OfflineDB bool
}

// DefaultOptions returns the default vulnerability scanning options.
func DefaultOptions() Options {
	return Options{
		FailOnSeverity:        "", // Never fail
		OnlyFixed:             false,
		IgnoreVulnerabilities: []string{},
		OfflineDB:             false,
	}
}

// Stats returns statistics about the vulnerabilities in the report.
func (r *Report) Stats() map[Severity]int {
	stats := make(map[Severity]int)
	
	for _, vuln := range r.Vulnerabilities {
		stats[vuln.Severity]++
	}
	
	return stats
}

// ShouldFail checks if the report should cause a failure based on the severity threshold.
func (r *Report) ShouldFail(threshold Severity) bool {
	if threshold == "" {
		return false
	}
	
	severityOrder := map[Severity]int{
		SeverityUnknown:    0,
		SeverityNegligible: 1,
		SeverityLow:        2,
		SeverityMedium:     3,
		SeverityHigh:       4,
		SeverityCritical:   5,
	}
	
	thresholdLevel := severityOrder[threshold]
	
	for _, vuln := range r.Vulnerabilities {
		if severityOrder[vuln.Severity] >= thresholdLevel {
			return true
		}
	}
	
	return false
}

// ScanInput represents the input to the scanner.
// Scanners can accept either an SBOM or a direct artifact reference.
type ScanInput struct {
	// SBOM is the SBOM to scan (preferred for atomic evidence model)
	SBOM *sbom.SBOM
	
	// Artifact is a direct artifact reference (used when SBOM is not available)
	// Only used in standalone scan mode
	Artifact string
}
