package sbom

import (
	"context"
)

// Provider defines the interface for SBOM generation providers.
//
// Implementations must:
// - Generate SBOMs entirely in-memory (no temporary files)
// - Return valid JSON content
// - Calculate SHA256 checksum of the content
// - Support all three formats (CycloneDX, SPDX, Syft JSON)
//
// Example implementation: Syft provider in internal/providers/sbom/syft/
type Provider interface {
	// Generate creates an SBOM for the specified artifact.
	//
	// The artifact parameter can be:
	// - A container image reference (e.g., "nginx:latest", "gcr.io/myproject/myapp:v1.0")
	// - A local file path (when opts.Local is true)
	// - A directory path (when opts.Local is true)
	// - An OCI archive path (when opts.Local is true)
	//
	// The ctx parameter is used for cancellation and timeouts.
	// Implementations should respect context deadlines and return context.Canceled/context.DeadlineExceeded.
	//
	// Returns:
	// - *SBOM: The generated SBOM with content, checksum, and metadata
	// - error: Any error encountered during generation
	Generate(ctx context.Context, artifact string, opts Options) (*SBOM, error)
	
	// Name returns the provider name (e.g., "syft", "trivy")
	Name() string
	
	// Version returns the provider version (e.g., "0.100.0")
	Version() string
}
