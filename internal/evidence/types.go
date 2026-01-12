// Package evidence implements atomic evidence generation for software artifacts.
//
// The atomic evidence model ensures SBOM and vulnerability reports represent
// the exact state of the artifact at signing time, preventing TOCTOU vulnerabilities.
//
// Evidence E = (Artifact A, SBOM C, Vulnerability Report V, Signature σ)
// where σ signs the complete in-toto Statement containing A, C, and V.
package evidence

import (
	"time"

	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers/signer"
)

// Evidence represents atomic evidence for a software artifact.
//
// All components (SBOM, vulnerability report, signature) are generated
// atomically in-memory to ensure cryptographic integrity.
type Evidence struct {
	// Artifact is the identifier of the software artifact (e.g., "nginx:latest", "./myapp")
	Artifact string `json:"artifact"`

	// ArtifactDigest is the cryptographic hash of the artifact (e.g., "sha256:abc123...")
	ArtifactDigest string `json:"artifact_digest"`

	// SBOM is the Software Bill of Materials
	SBOM *sbom.SBOM `json:"sbom"`

	// VulnerabilityReport contains the vulnerability scan results
	VulnerabilityReport *scanner.Report `json:"vulnerability_report"`

	// Statement is the in-toto attestation statement
	Statement []byte `json:"statement"`

	// Signature is the cryptographic signature over the statement
	Signature *signer.Signature `json:"signature"`

	// Metadata contains generation metadata
	Metadata *Metadata `json:"metadata"`
}

// Metadata contains metadata about evidence generation.
type Metadata struct {
	// GeneratedAt is the timestamp when evidence was generated
	GeneratedAt time.Time `json:"generated_at"`

	// GeneratorVersion is the version of Provenix that generated the evidence
	GeneratorVersion string `json:"generator_version"`

	// SBOMProvider is the name and version of the SBOM provider used
	SBOMProvider ProviderInfo `json:"sbom_provider"`

	// ScannerProvider is the name and version of the scanner provider used
	ScannerProvider ProviderInfo `json:"scanner_provider"`

	// SignerProvider is the name and version of the signer provider used
	SignerProvider ProviderInfo `json:"signer_provider"`

	// Duration is the total time taken to generate evidence
	Duration time.Duration `json:"duration"`
}

// ProviderInfo contains information about a provider.
type ProviderInfo struct {
	// Name is the provider name (e.g., "syft", "grype", "cosign")
	Name string `json:"name"`

	// Version is the provider version
	Version string `json:"version"`
}

// GenerateOptions contains options for evidence generation.
type GenerateOptions struct {
	// SBOMOptions are passed to the SBOM provider
	SBOMOptions sbom.Options

	// ScanOptions are passed to the scanner provider
	ScanOptions scanner.Options

	// SignOptions are passed to the signer provider
	SignOptions signer.Options

	// ArtifactType indicates the type of artifact (auto-detected if empty)
	// Valid values: "docker", "oci-archive", "directory", "file"
	ArtifactType string

	// GeneratorVersion is the version of Provenix generating the evidence
	GeneratorVersion string
}

// Validate validates the evidence structure.
func (e *Evidence) Validate() error {
	if e.Artifact == "" {
		return ErrInvalidArtifact
	}
	if e.ArtifactDigest == "" {
		return ErrMissingDigest
	}
	if e.SBOM == nil {
		return ErrMissingSBOM
	}
	if e.VulnerabilityReport == nil {
		return ErrMissingVulnReport
	}
	if e.Statement == nil || len(e.Statement) == 0 {
		return ErrMissingStatement
	}
	if e.Signature == nil {
		return ErrMissingSignature
	}
	if e.Metadata == nil {
		return ErrMissingMetadata
	}
	return nil
}
