package grype

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	v6dist "github.com/anchore/grype/grype/db/v6/distribution"
	v6inst "github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/syft/syft/sbom"

	scannerprovider "github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers"
)

// Provider implements scanner.Provider using Grype library.
// Uses in-memory SBOM scanning with Grype's vulnerability database.
type Provider struct {
	version      string
	vulnProvider vulnerability.Provider
}

// NewProvider creates a new Grype-based scanner provider.
func NewProvider() *Provider {
	return &Provider{
		version:      "0.104.4", // Grype version (pinned)
		vulnProvider: nil,        // Lazy initialization
	}
}

// Scan generates a vulnerability report from an SBOM.
// This is the core implementation that performs in-memory vulnerability scanning.
func (p *Provider) Scan(ctx context.Context, input scannerprovider.ScanInput, opts scannerprovider.Options) (*scannerprovider.Report, error) {
	// Validate input
	if input.SBOM == nil {
		return nil, fmt.Errorf("SBOM is required for atomic evidence scanning")
	}

	artifact := input.SBOM.Artifact
	if artifact == "" {
		artifact = "unknown"
	}

	// Parse SBOM content to get Syft SBOM
	var syftSBOM *sbom.SBOM
	if err := json.Unmarshal(input.SBOM.Content, &syftSBOM); err != nil {
		return nil, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	// Initialize vulnerability database if needed
	if p.vulnProvider == nil {
		if err := p.initializeVulnProvider(ctx, opts); err != nil {
			return nil, fmt.Errorf("failed to initialize vulnerability database: %w", err)
		}
	}

	// Convert Syft packages to Grype packages using pkg.FromPackages()
	syftPackages := syftSBOM.Artifacts.Packages.Sorted()
	grypePackages := grypePkg.FromPackages(syftPackages, grypePkg.SynthesisConfig{})

	// Perform vulnerability matching using Grype's built-in function
	matches := grype.FindVulnerabilitiesForPackage(p.vulnProvider, p.createMatchers(), grypePackages)

	// Convert matches to report
	report, err := p.buildReport(artifact, &matches, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to build report: %w", err)
	}

	return report, nil
}

// createMatchers creates the default set of Grype matchers.
func (p *Provider) createMatchers() []match.Matcher {
	return []match.Matcher{
		&stock.Matcher{},
		&golang.Matcher{},
		&java.Matcher{},
		&javascript.Matcher{},
		&python.Matcher{},
		&ruby.Matcher{},
		&dotnet.Matcher{},
	}
}

// initializeVulnProvider initializes the Grype vulnerability database provider.
func (p *Provider) initializeVulnProvider(ctx context.Context, opts scannerprovider.Options) error {
	// Configure vulnerability database distribution and installation
	distCfg := v6dist.Config{}
	installCfg := v6inst.Config{}

	// Load vulnerability database
	vulnProvider, _, err := grype.LoadVulnerabilityDB(distCfg, installCfg, !opts.OfflineDB)
	if err != nil {
		return fmt.Errorf("failed to load vulnerability database: %w", err)
	}

	p.vulnProvider = vulnProvider
	return nil
}

// buildReport converts Grype matches to scanner.Report format.
func (p *Provider) buildReport(
	artifact string,
	matches *match.Matches,
	opts scannerprovider.Options,
) (*scannerprovider.Report, error) {
	vulnerabilities := []scannerprovider.Vulnerability{}

	if matches == nil {
		matches = &match.Matches{}
	}

	// Deduplicate and convert matches
	seen := make(map[string]bool)

	for _, m := range matches.Sorted() {
		vulnID := m.Vulnerability.ID
		if seen[vulnID] {
			continue
		}
		seen[vulnID] = true

		// Filter by options
		if opts.OnlyFixed && (m.Vulnerability.Fix.State == "not-fixed" || m.Vulnerability.Fix.State == "unknown") {
			continue
		}

		if contains(opts.IgnoreVulnerabilities, vulnID) {
			continue
		}

		// Get severity from metadata
		severity := scannerprovider.SeverityUnknown
		if m.Vulnerability.Metadata != nil {
			severity = convertSeverity(m.Vulnerability.Metadata.Severity)
		}

		// Extract fix version
		fixVersion := ""
		if len(m.Vulnerability.Fix.Versions) > 0 {
			fixVersion = m.Vulnerability.Fix.Versions[0]
		}

		// Get description and URLs from metadata
		description := ""
		urls := []string{}
		if m.Vulnerability.Metadata != nil {
			description = m.Vulnerability.Metadata.Description
			urls = m.Vulnerability.Metadata.URLs
		}

		vuln := scannerprovider.Vulnerability{
			ID:           vulnID,
			Severity:     severity,
			Package:      m.Package.Name,
			Version:      m.Package.Version,
			FixedVersion: fixVersion,
			Description:  description,
			URLs:         urls,
		}

		vulnerabilities = append(vulnerabilities, vuln)
	}

	// Serialize matches to JSON for Content field
	content, err := json.Marshal(map[string]interface{}{
		"matches":      matches.Sorted(),
		"matchCount":   len(matches.Sorted()),
		"timestamp":    time.Now().UTC(),
		"artifactName": artifact,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scan results: %w", err)
	}

	// Get DB version
	dbVersion := "grype-db:latest"

	report := &scannerprovider.Report{
		Artifact:        artifact,
		Vulnerabilities: vulnerabilities,
		Content:         json.RawMessage(content),
		Checksum:        calculateHash(string(content)),
		ScannedAt:       time.Now().UTC(),
		ProviderName:    p.Name(),
		ProviderVersion: p.Version(),
		DBVersion:       dbVersion,
	}

	return report, nil
}

// convertSeverity converts Grype severity to scanner.Severity.
func convertSeverity(grypeSeverity string) scannerprovider.Severity {
	switch grypeSeverity {
	case "Critical":
		return scannerprovider.SeverityCritical
	case "High":
		return scannerprovider.SeverityHigh
	case "Medium":
		return scannerprovider.SeverityMedium
	case "Low":
		return scannerprovider.SeverityLow
	case "Negligible":
		return scannerprovider.SeverityNegligible
	default:
		return scannerprovider.SeverityUnknown
	}
}

// contains checks if a string is in a slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
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
	if p.vulnProvider == nil {
		if err := p.initializeVulnProvider(ctx, scannerprovider.DefaultOptions()); err != nil {
			return "", err
		}
	}

	return "grype-db:latest", nil
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
