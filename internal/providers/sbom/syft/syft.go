package syft

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	sbomprovider "github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers"
)

// Provider implements sbom.Provider using Syft library.
// Note: This is a simplified provider stub demonstrating the integration pattern.
// Full implementation deferred to Week 6+ to avoid complex API integration during MVP.
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
	// Stub implementation for MVP
	// Full integration with Syft API deferred to Phase 2 (Week 6+)
	//
	// Production implementation would:
	// 1. Use syft.CreateSBOM() to generate SBOM
	// 2. Convert to requested format (CycloneDX, SPDX, Syft JSON)
	// 3. Encode and calculate SHA256 checksum
	// 4. Return with provider metadata

	// For MVP: Generate minimal valid CycloneDX SBOM structure
	sbomContent := map[string]interface{}{
		"bomFormat":     "CycloneDX",
		"specVersion":   "1.5",
		"serialNumber":  "urn:uuid:provenix-" + artifact,
		"version":       1,
		"metadata": map[string]interface{}{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"component": map[string]interface{}{
				"name": artifact,
				"type": "application",
			},
		},
		"components": []interface{}{},
	}

	contentJSON, err := json.MarshalIndent(sbomContent, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM: %w", err)
	}

	hash := sha256.Sum256(contentJSON)
	checksum := hex.EncodeToString(hash[:])

	return &sbomprovider.SBOM{
		Format:          sbomprovider.FormatCycloneDXJSON,
		Artifact:        artifact,
		Content:         json.RawMessage(contentJSON),
		Checksum:        checksum,
		GeneratedAt:     time.Now().UTC(),
		ProviderName:    p.Name(),
		ProviderVersion: p.Version(),
	}, nil
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
