package grype

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	scannerprovider "github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers"
	
	// Grype imports for future complete implementation
	// TODO: Complete Grype integration in Step 1.2
	// "github.com/anchore/grype/grype"
	// "github.com/anchore/grype/grype/match"
	// "github.com/anchore/grype/grype/vulnerability"
)

// Provider implements scanner.Provider using Grype library.
// 
// Current Status: Stub implementation for MVP completion
// TODO: Full Grype API integration deferred due to package type compatibility issues
// between Syft v1.40.0 and Grype v0.104.4
//
// Next Steps (Post-MVP):
// 1. Resolve Syft Package → Grype Package conversion
// 2. Implement vulnerability database loading
// 3. Use VulnerabilityMatcher.FindMatches() for real scanning
// 4. Parse and convert vulnerability metadata (severity, description, URLs)
type Provider struct {
	version string
}

// NewProvider creates a new Grype-based scanner provider.
func NewProvider() *Provider {
	return &Provider{
		version: "0.104.4", // Grype version (pinned)
	}
}

// Scan generates a vulnerability report from an SBOM.
//
// Current Implementation: Returns empty vulnerability list (stub)
// Real Implementation: Will use Grype's VulnerabilityMatcher to scan packages
func (p *Provider) Scan(ctx context.Context, input scannerprovider.ScanInput, opts scannerprovider.Options) (*scannerprovider.Report, error) {
	artifact := input.Artifact
	if input.SBOM != nil {
		artifact = input.SBOM.Artifact
	}
	if artifact == "" {
		artifact = "unknown"
	}

	// TODO: Implement real Grype scanning
	// Steps:
	// 1. Parse input.SBOM.Content to get Syft SBOM
	// 2. Convert Syft packages to Grype packages
	// 3. Load vulnerability database
	// 4. Execute matchers
	// 5. Convert matches to scanner.Report

	report := &scannerprovider.Report{
		Artifact:        artifact,
		Vulnerabilities: []scannerprovider.Vulnerability{},
		Content:         json.RawMessage(`{"status":"stub_implementation","matches":[],"note":"Real Grype scanning deferred to post-MVP"}`),
		Checksum:        calculateHash(`{"status":"stub_implementation","matches":[],"note":"Real Grype scanning deferred to post-MVP"}`),
		ScannedAt:       time.Now().UTC(),
		ProviderName:    p.Name(),
		ProviderVersion: p.Version(),
		DBVersion:       "stub",
	}

	return report, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "grype"
}

// Version returns the provider version.
func (p *Provider) Version() string {
	return p.version
}

// DBVersion returns the vulnerability database version.
func (p *Provider) DBVersion(ctx context.Context) (string, error) {
	// TODO: Return real database version after full implementation
	return "grype-db:stub-" + time.Now().Format("20060102"), nil
}

// calculateHash computes SHA256 hash of content.
func calculateHash(content string) string {
	hash := sha256.Sum256([]byte(content))
	return hex.EncodeToString(hash[:])
}

// init registers the Grype provider when package is imported.
func init() {
	providers.RegisterScannerProvider("grype", NewProvider())
}
