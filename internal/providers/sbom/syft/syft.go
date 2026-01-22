package syft

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/sbom"
	syftformat "github.com/anchore/syft/syft/format"

	sbomprovider "github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers"

	// Import SQLite driver for RPM database cataloging
	_ "modernc.org/sqlite"
)

// Provider implements sbom.Provider using Syft library.
// Full Syft API integration for SBOM generation with multiple format support.
type Provider struct {
	version string
}

// NewProvider creates a new Syft-based SBOM provider.
func NewProvider() *Provider {
	return &Provider{
		version: "1.40.0", // Syft version
	}
}

// Generate generates an SBOM for the specified artifact using Syft.
//
// The artifact parameter can be:
// - Container image reference (e.g., "nginx:latest")
// - Local file path (when opts.Local is true)
// - Directory path (when opts.Local is true)
// - OCI archive path (when opts.Local is true)
//
// Data flows entirely in-memory with no temporary files.
func (p *Provider) Generate(ctx context.Context, artifact string, opts sbomprovider.Options) (*sbomprovider.SBOM, error) {
	// Validate options
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	// Create GetSourceConfig with optimal settings
	getSourceCfg := p.createGetSourceConfig(artifact, opts)

	// Get source from artifact
	src, err := syft.GetSource(ctx, artifact, getSourceCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get source for %s: %w", artifact, err)
	}
	defer src.Close()

	// Create SBOM using Syft with optimized config
	createSBOMCfg := p.createCreateSBOMConfig(opts)
	sbomObj, err := syft.CreateSBOM(ctx, src, createSBOMCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	// Encode SBOM to requested format (spec-compliant)
	contentJSON, err := p.encodeSBOM(sbomObj, opts.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}

	// Calculate SHA256 checksum for integrity
	hash := sha256.Sum256(contentJSON)
	checksum := hex.EncodeToString(hash[:])

	return &sbomprovider.SBOM{
		Format:          opts.Format,
		Artifact:        artifact,
		Content:         json.RawMessage(contentJSON),
		Checksum:        checksum,
		GeneratedAt:     time.Now().UTC(),
		ProviderName:    p.Name(),
		ProviderVersion: p.Version(),
	}, nil
}

// createGetSourceConfig creates an optimized GetSourceConfig based on options.
// Handles Platform (multi-arch), SourceProviderConfig, and DefaultImagePullSource.
func (p *Provider) createGetSourceConfig(artifact string, opts sbomprovider.Options) *syft.GetSourceConfig {
	cfg := syft.DefaultGetSourceConfig()

	// Set platform for multi-architecture images
	if opts.Platform != "" {
		platform, err := image.NewPlatform(opts.Platform)
		if err == nil {
			cfg = cfg.WithPlatform(platform)
		}
	}

	// Determine source provider priority
	if !opts.Local {
		// Remote: prefer container registry
		cfg = cfg.WithDefaultImagePullSource("registry")
	}
	// Note: For local filesystem, don't set DefaultImagePullSource
	// Syft will auto-detect based on artifact path

	// Add digest algorithms for integrity verification
	cfg = cfg.WithDigestAlgorithms(crypto.SHA256)

	return cfg
}

// createCreateSBOMConfig creates an optimized CreateSBOMConfig.
func (p *Provider) createCreateSBOMConfig(opts sbomprovider.Options) *syft.CreateSBOMConfig {
	cfg := syft.DefaultCreateSBOMConfig()

	// Set tool information for audit trail
	cfg.ToolName = "provenix"
	cfg.ToolVersion = p.version

	// Enable license cataloging with default config
	cfg = cfg.WithLicenseConfig(cataloging.DefaultLicenseConfig())

	return cfg
}

// encodeSBOM encodes the SBOM to the requested format using Syft's FormatEncoder interface.
// Supports CycloneDX JSON, SPDX JSON, and Syft JSON formats with spec compliance.
func (p *Provider) encodeSBOM(sbomObj *sbom.SBOM, format sbomprovider.Format) ([]byte, error) {
	// Get appropriate encoder for the format
	enc, err := p.getFormatEncoder(format)
	if err != nil {
		return nil, fmt.Errorf("unsupported format %s: %w", format, err)
	}

	// Encode SBOM to writer
	var buf bytes.Buffer
	if err := enc.Encode(&buf, *sbomObj); err != nil {
		return nil, fmt.Errorf("failed to encode SBOM as %s: %w", format, err)
	}

	// Pretty-print JSON output
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, buf.Bytes(), "", "  "); err != nil {
		// Return non-pretty version if indent fails
		return buf.Bytes(), nil
	}

	return pretty.Bytes(), nil
}

// getFormatEncoder returns the appropriate FormatEncoder for the requested format.
func (p *Provider) getFormatEncoder(fmtType sbomprovider.Format) (sbom.FormatEncoder, error) {
	// Get all available encoders from Syft format package
	encoders := syftformat.Encoders()
	if len(encoders) == 0 {
		return nil, fmt.Errorf("no encoders available")
	}

	// Map our format to Syft format IDs
	var targetID sbom.FormatID
	switch fmtType {
	case sbomprovider.FormatCycloneDXJSON:
		targetID = "cyclonedx-json"
	case sbomprovider.FormatSPDXJSON:
		targetID = "spdx-json"
	case sbomprovider.FormatSyftJSON:
		targetID = "syft-json"
	default:
		return nil, fmt.Errorf("unknown format: %s", fmtType)
	}

	// Find matching encoder
	for _, enc := range encoders {
		if enc.ID() == targetID {
			return enc, nil
		}
	}

	return nil, fmt.Errorf("encoder not found for format %s", targetID)
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "syft"
}

// Version returns the provider version.
func (p *Provider) Version() string {
	return p.version
}

func init() {
	providers.RegisterSBOMProvider("syft", NewProvider())
}
