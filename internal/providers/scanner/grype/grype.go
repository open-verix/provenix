package grype

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	scannerprovider "github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers"
)

// Provider implements scanner.Provider using Grype library.
// Note: Stub implementation for MVP. Full API integration deferred to Phase 2.
type Provider struct {
	version string
}

// NewProvider creates a new Grype-based scanner provider.
func NewProvider() *Provider {
	return &Provider{
		version: "0.104.4",
	}
}

// Scan generates a vulnerability report from an SBOM.
func (p *Provider) Scan(ctx context.Context, input scannerprovider.ScanInput, opts scannerprovider.Options) (*scannerprovider.Report, error) {
	artifact := input.Artifact
	if input.SBOM != nil {
		artifact = input.SBOM.Artifact
	}
	if artifact == "" {
		artifact = "unknown"
	}

	report := &scannerprovider.Report{
		Artifact:        artifact,
		Vulnerabilities: []scannerprovider.Vulnerability{},
		Content:         json.RawMessage(`{"vulnerabilities":[], "scan_status": "stub_for_mvp"}`),
		Checksum:        calculateHash(`{"vulnerabilities":[], "scan_status": "stub_for_mvp"}`),
		ScannedAt:       time.Now().UTC(),
		ProviderName:    p.Name(),
		ProviderVersion: p.Version(),
		DBVersion:       p.version,
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
	return "grype-db-stub-" + time.Now().Format("20060102"), nil
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
