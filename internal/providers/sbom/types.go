package sbom

import (
	"encoding/json"
	"time"
)

// Format represents the SBOM output format.
type Format string

const (
	// FormatCycloneDXJSON represents CycloneDX JSON format (default, security-focused)
	FormatCycloneDXJSON Format = "cyclonedx-json"
	
	// FormatSPDXJSON represents SPDX JSON format (compliance-focused)
	FormatSPDXJSON Format = "spdx-json"
	
	// FormatSyftJSON represents Syft's native JSON format (detailed metadata)
	FormatSyftJSON Format = "syft-json"
)

// SBOM represents a Software Bill of Materials.
// This is an in-memory representation that must never be written to temporary files
// to prevent TOCTOU vulnerabilities.
type SBOM struct {
	// Format is the SBOM format used
	Format Format `json:"format"`
	
	// Artifact is the identifier of the scanned artifact (image, file, directory)
	Artifact string `json:"artifact"`
	
	// Content is the raw SBOM content in the specified format
	// Must be valid JSON for all supported formats
	Content json.RawMessage `json:"content"`
	
	// Checksum is the SHA256 hash of the Content
	// Used to verify SBOM integrity in the atomic evidence model
	Checksum string `json:"checksum"`
	
	// GeneratedAt is the timestamp when the SBOM was generated
	GeneratedAt time.Time `json:"generated_at"`
	
	// ProviderName is the name of the provider that generated this SBOM
	ProviderName string `json:"provider_name"`
	
	// ProviderVersion is the version of the provider
	ProviderVersion string `json:"provider_version"`
}

// Options configures SBOM generation behavior.
type Options struct {
	// Format specifies the output format (cyclonedx-json, spdx-json, syft-json)
	Format Format
	
	// Local indicates whether to scan a local file/directory instead of pulling an image
	Local bool
	
	// Platform specifies the target platform for multi-arch images (e.g., "linux/amd64")
	Platform string
	
	// Scope defines what to catalog (all-layers, squashed)
	Scope string
	
	// ExcludePaths is a list of paths to exclude from scanning
	ExcludePaths []string
	
	// IncludePaths is a list of paths to explicitly include
	IncludePaths []string
}

// DefaultOptions returns the default SBOM generation options.
func DefaultOptions() Options {
	return Options{
		Format:       FormatCycloneDXJSON,
		Local:        false,
		Platform:     "",
		Scope:        "squashed",
		ExcludePaths: []string{},
		IncludePaths: []string{},
	}
}

// Validate checks if the options are valid.
func (o Options) Validate() error {
	validFormats := map[Format]bool{
		FormatCycloneDXJSON: true,
		FormatSPDXJSON:      true,
		FormatSyftJSON:      true,
	}
	
	if !validFormats[o.Format] {
		return &InvalidFormatError{Format: string(o.Format)}
	}
	
	return nil
}

// InvalidFormatError is returned when an unsupported SBOM format is requested.
type InvalidFormatError struct {
	Format string
}

func (e *InvalidFormatError) Error() string {
	return "invalid SBOM format: " + e.Format + " (supported: cyclonedx-json, spdx-json, syft-json)"
}
