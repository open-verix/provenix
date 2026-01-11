package mock

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
	
	"github.com/open-verix/provenix/internal/providers/sbom"
)

// Provider is a mock SBOM provider for testing.
type Provider struct {
	// GenerateFunc allows tests to customize the Generate behavior
	GenerateFunc func(ctx context.Context, artifact string, opts sbom.Options) (*sbom.SBOM, error)
	
	// NameValue is the provider name returned by Name()
	NameValue string
	
	// VersionValue is the provider version returned by Version()
	VersionValue string
}

// NewProvider creates a new mock SBOM provider with default behavior.
func NewProvider() *Provider {
	return &Provider{
		NameValue:    "mock",
		VersionValue: "1.0.0",
		GenerateFunc: defaultGenerate,
	}
}

// Generate generates a mock SBOM for testing.
func (p *Provider) Generate(ctx context.Context, artifact string, opts sbom.Options) (*sbom.SBOM, error) {
	if p.GenerateFunc != nil {
		return p.GenerateFunc(ctx, artifact, opts)
	}
	
	return defaultGenerate(ctx, artifact, opts)
}

// Name returns the provider name.
func (p *Provider) Name() string {
	if p.NameValue != "" {
		return p.NameValue
	}
	return "mock"
}

// Version returns the provider version.
func (p *Provider) Version() string {
	if p.VersionValue != "" {
		return p.VersionValue
	}
	return "1.0.0"
}

// defaultGenerate is the default mock SBOM generation function.
func defaultGenerate(ctx context.Context, artifact string, opts sbom.Options) (*sbom.SBOM, error) {
	// Check context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	// Validate options
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	
	// Create a minimal mock SBOM content based on format
	var content json.RawMessage
	var err error
	
	switch opts.Format {
	case sbom.FormatCycloneDXJSON:
		content, err = json.Marshal(map[string]interface{}{
			"bomFormat":   "CycloneDX",
			"specVersion": "1.4",
			"version":     1,
			"metadata": map[string]interface{}{
				"component": map[string]interface{}{
					"type": "application",
					"name": artifact,
				},
			},
			"components": []map[string]interface{}{
				{
					"type":    "library",
					"name":    "mock-package",
					"version": "1.0.0",
				},
			},
		})
	case sbom.FormatSPDXJSON:
		content, err = json.Marshal(map[string]interface{}{
			"spdxVersion":       "SPDX-2.3",
			"dataLicense":       "CC0-1.0",
			"SPDXID":            "SPDXRef-DOCUMENT",
			"name":              artifact,
			"documentNamespace": fmt.Sprintf("https://mock.dev/sbom/%s", artifact),
			"packages": []map[string]interface{}{
				{
					"SPDXID":  "SPDXRef-Package-mock-package",
					"name":    "mock-package",
					"version": "1.0.0",
				},
			},
		})
	case sbom.FormatSyftJSON:
		content, err = json.Marshal(map[string]interface{}{
			"schema": map[string]interface{}{
				"version": "5.0.0",
				"url":     "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-5.0.0.json",
			},
			"source": map[string]interface{}{
				"type":   "image",
				"target": artifact,
			},
			"artifacts": []map[string]interface{}{
				{
					"name":    "mock-package",
					"version": "1.0.0",
					"type":    "mock-pkg",
				},
			},
		})
	default:
		return nil, &sbom.InvalidFormatError{Format: string(opts.Format)}
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mock SBOM: %w", err)
	}
	
	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	
	return &sbom.SBOM{
		Format:          opts.Format,
		Artifact:        artifact,
		Content:         content,
		Checksum:        checksum,
		GeneratedAt:     time.Now(),
		ProviderName:    "mock",
		ProviderVersion: "1.0.0",
	}, nil
}
