package scanner

import (
	"context"
)

// Provider defines the interface for vulnerability scanning providers.
//
// Implementations must:
// - Accept SBOM input for atomic evidence generation
// - Scan entirely in-memory (no temporary files)
// - Return structured vulnerability data
// - Calculate SHA256 checksum of the raw report
//
// Example implementation: Grype provider in internal/providers/scanner/grype/
type Provider interface {
	// Scan performs vulnerability scanning on the provided input.
	//
	// For atomic evidence generation, input.SBOM must be provided.
	// This ensures the scan results correspond to the exact SBOM content.
	//
	// For standalone scanning, input.Artifact can be used.
	//
	// The ctx parameter is used for cancellation and timeouts.
	//
	// Returns:
	// - *Report: The scan report with vulnerabilities, checksum, and metadata
	// - error: Any error encountered during scanning
	Scan(ctx context.Context, input ScanInput, opts Options) (*Report, error)
	
	// Name returns the provider name (e.g., "grype", "trivy")
	Name() string
	
	// Version returns the provider version (e.g., "0.70.0")
	Version() string
	
	// DBVersion returns the vulnerability database version
	DBVersion(ctx context.Context) (string, error)
}
