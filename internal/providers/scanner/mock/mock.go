package mock

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
	
	"github.com/open-verix/provenix/internal/providers/scanner"
)

// Provider is a mock scanner provider for testing.
type Provider struct {
	// ScanFunc allows tests to customize the Scan behavior
	ScanFunc func(ctx context.Context, input scanner.ScanInput, opts scanner.Options) (*scanner.Report, error)
	
	// DBVersionFunc allows tests to customize the DBVersion behavior
	DBVersionFunc func(ctx context.Context) (string, error)
	
	// NameValue is the provider name returned by Name()
	NameValue string
	
	// VersionValue is the provider version returned by Version()
	VersionValue string
}

// NewProvider creates a new mock scanner provider with default behavior.
func NewProvider() *Provider {
	return &Provider{
		NameValue:     "mock",
		VersionValue:  "1.0.0",
		ScanFunc:      defaultScan,
		DBVersionFunc: defaultDBVersion,
	}
}

// Scan performs a mock vulnerability scan for testing.
func (p *Provider) Scan(ctx context.Context, input scanner.ScanInput, opts scanner.Options) (*scanner.Report, error) {
	if p.ScanFunc != nil {
		return p.ScanFunc(ctx, input, opts)
	}
	
	return defaultScan(ctx, input, opts)
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

// DBVersion returns the mock database version.
func (p *Provider) DBVersion(ctx context.Context) (string, error) {
	if p.DBVersionFunc != nil {
		return p.DBVersionFunc(ctx)
	}
	
	return defaultDBVersion(ctx)
}

// defaultScan is the default mock scan function.
func defaultScan(ctx context.Context, input scanner.ScanInput, opts scanner.Options) (*scanner.Report, error) {
	// Check context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	// Determine artifact name
	artifact := input.Artifact
	if input.SBOM != nil {
		artifact = input.SBOM.Artifact
	}
	
	// Create mock vulnerabilities
	vulnerabilities := []scanner.Vulnerability{
		{
			ID:           "CVE-2024-0001",
			Severity:     scanner.SeverityHigh,
			Package:      "mock-package",
			Version:      "1.0.0",
			FixedVersion: "1.0.1",
			Description:  "Mock high severity vulnerability",
			URLs:         []string{"https://mock.dev/CVE-2024-0001"},
		},
		{
			ID:           "CVE-2024-0002",
			Severity:     scanner.SeverityMedium,
			Package:      "mock-package",
			Version:      "1.0.0",
			FixedVersion: "1.0.1",
			Description:  "Mock medium severity vulnerability",
			URLs:         []string{"https://mock.dev/CVE-2024-0002"},
		},
	}
	
	// Filter vulnerabilities based on options
	filtered := make([]scanner.Vulnerability, 0)
	for _, vuln := range vulnerabilities {
		// Skip ignored vulnerabilities
		ignored := false
		for _, id := range opts.IgnoreVulnerabilities {
			if vuln.ID == id {
				ignored = true
				break
			}
		}
		if ignored {
			continue
		}
		
		// Skip unfixed vulnerabilities if OnlyFixed is true
		if opts.OnlyFixed && vuln.FixedVersion == "" {
			continue
		}
		
		filtered = append(filtered, vuln)
	}
	
	// Create mock report content
	content, err := json.Marshal(map[string]interface{}{
		"artifact":        artifact,
		"vulnerabilities": filtered,
		"metadata": map[string]interface{}{
			"scanner":  "mock",
			"db":       "mock-db:2024-01-11",
			"scannedAt": time.Now().Format(time.RFC3339),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal mock report: %w", err)
	}
	
	// Calculate checksum
	checksum := fmt.Sprintf("%x", sha256.Sum256(content))
	
	return &scanner.Report{
		Artifact:        artifact,
		Vulnerabilities: filtered,
		Content:         content,
		Checksum:        checksum,
		ScannedAt:       time.Now(),
		ProviderName:    "mock",
		ProviderVersion: "1.0.0",
		DBVersion:       "mock-db:2024-01-11",
	}, nil
}

// defaultDBVersion is the default mock database version function.
func defaultDBVersion(ctx context.Context) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	
	return "mock-db:2024-01-11", nil
}
