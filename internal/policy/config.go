package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the policy configuration.
type Config struct {
	// Version is the config schema version
	Version string `yaml:"version"`

	// Vulnerabilities contains vulnerability-related policies
	Vulnerabilities *VulnerabilityPolicy `yaml:"vulnerabilities,omitempty"`

	// Licenses contains license-related policies
	Licenses *LicensePolicy `yaml:"licenses,omitempty"`

	// SBOM contains SBOM-related policies
	SBOM *SBOMPolicy `yaml:"sbom,omitempty"`

	// Signing contains signing-related policies
	Signing *SigningPolicy `yaml:"signing,omitempty"`

	// Custom contains custom policy rules (OPA/Rego)
	Custom *CustomPolicy `yaml:"custom,omitempty"`
}

// VulnerabilityPolicy defines vulnerability-related policies.
type VulnerabilityPolicy struct {
	// MaxCritical is the maximum number of critical vulnerabilities allowed
	MaxCritical *int `yaml:"max_critical,omitempty"`

	// MaxHigh is the maximum number of high vulnerabilities allowed
	MaxHigh *int `yaml:"max_high,omitempty"`

	// MaxMedium is the maximum number of medium vulnerabilities allowed
	MaxMedium *int `yaml:"max_medium,omitempty"`

	// MaxLow is the maximum number of low vulnerabilities allowed
	MaxLow *int `yaml:"max_low,omitempty"`

	// OnlyFixed requires all vulnerabilities to have fixes available
	OnlyFixed bool `yaml:"only_fixed,omitempty"`

	// IgnoreIDs is a list of vulnerability IDs to ignore
	IgnoreIDs []string `yaml:"ignore_ids,omitempty"`

	// FailOnAny fails if any vulnerabilities are found (regardless of severity)
	FailOnAny bool `yaml:"fail_on_any,omitempty"`
}

// LicensePolicy defines license-related policies.
type LicensePolicy struct {
	// AllowedLicenses is a list of allowed license identifiers (SPDX)
	AllowedLicenses []string `yaml:"allowed,omitempty"`

	// DeniedLicenses is a list of denied license identifiers (SPDX)
	DeniedLicenses []string `yaml:"denied,omitempty"`

	// RequireAllPackages requires all packages to have identified licenses
	RequireAllPackages bool `yaml:"require_all_packages,omitempty"`

	// WarnOnUnknown warns when packages have unknown licenses
	WarnOnUnknown bool `yaml:"warn_on_unknown,omitempty"`
}

// SBOMPolicy defines SBOM-related policies.
type SBOMPolicy struct {
	// RequiredFormat specifies the required SBOM format
	// Valid values: "cyclonedx-json", "spdx-json", "syft-json"
	RequiredFormat string `yaml:"required_format,omitempty"`

	// MinPackages is the minimum number of packages expected in SBOM
	MinPackages int `yaml:"min_packages,omitempty"`

	// RequireChecksum requires SBOM to have a checksum
	RequireChecksum bool `yaml:"require_checksum,omitempty"`
}

// SigningPolicy defines signing-related policies.
type SigningPolicy struct {
	// Required makes signing mandatory
	Required bool `yaml:"required,omitempty"`

	// RequireKeyless requires keyless signing (OIDC + Fulcio)
	RequireKeyless bool `yaml:"require_keyless,omitempty"`

	// RequireRekor requires Rekor transparency log entry
	RequireRekor bool `yaml:"require_rekor,omitempty"`

	// AllowedIssuers is a list of allowed OIDC issuers
	// e.g., ["https://token.actions.githubusercontent.com"]
	AllowedIssuers []string `yaml:"allowed_issuers,omitempty"`

	// AllowedSubjects is a list of allowed OIDC subjects (patterns)
	// e.g., ["repo:open-verix/*"]
	AllowedSubjects []string `yaml:"allowed_subjects,omitempty"`
}

// CustomPolicy defines custom policy rules.
type CustomPolicy struct {
	// CELEnabled enables CEL (Common Expression Language) integration
	CELEnabled bool `yaml:"cel_enabled,omitempty"`

	// CELExpressions is a list of CEL expressions to evaluate
	CELExpressions []CELExpression `yaml:"cel_expressions,omitempty"`

	// OPAEnabled enables Open Policy Agent integration (future)
	OPAEnabled bool `yaml:"opa_enabled,omitempty"`

	// PolicyFiles is a list of Rego policy files (future)
	PolicyFiles []string `yaml:"policy_files,omitempty"`

	// EntryPoint is the OPA policy entrypoint (future)
	// Default: "data.provenix.allow"
	EntryPoint string `yaml:"entry_point,omitempty"`
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	maxCritical := 0
	maxHigh := 0
	maxMedium := 10

	return &Config{
		Version: "v1",
		Vulnerabilities: &VulnerabilityPolicy{
			MaxCritical: &maxCritical,
			MaxHigh:     &maxHigh,
			MaxMedium:   &maxMedium,
			OnlyFixed:   false,
			IgnoreIDs:   []string{},
			FailOnAny:   false,
		},
		Licenses: &LicensePolicy{
			AllowedLicenses: []string{
				"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
				"ISC", "Unlicense", "CC0-1.0",
			},
			DeniedLicenses: []string{
				"GPL-3.0", "AGPL-3.0", // Copyleft licenses (often restricted in commercial use)
			},
			RequireAllPackages: false,
			WarnOnUnknown:      true,
		},
		SBOM: &SBOMPolicy{
			RequiredFormat:  "", // Any format is acceptable
			MinPackages:     0,
			RequireChecksum: true,
		},
		Signing: &SigningPolicy{
			Required:        false, // Not required for MVP (stub signing)
			RequireKeyless:  false,
			RequireRekor:    false,
			AllowedIssuers:  []string{},
			AllowedSubjects: []string{},
		},
		Custom: &CustomPolicy{
			CELEnabled:     false,
			CELExpressions: []CELExpression{},
			OPAEnabled:     false,
			PolicyFiles:    []string{},
			EntryPoint:     "data.provenix.allow",
		},
	}
}

// LoadConfig loads policy configuration from a file.
// Searches for provenix.yaml in the following locations (in order):
//   1. Explicitly provided path
//   2. ./provenix.yaml (current directory)
//   3. ./.provenix.yaml (hidden file)
//
// Note: Only searches in project directory, NEVER in ~/.config or /etc
func LoadConfig(path string) (*Config, error) {
	// If explicit path provided, use it
	if path != "" {
		return loadConfigFromFile(path)
	}

	// Search in project directory only
	searchPaths := []string{
		"provenix.yaml",
		".provenix.yaml",
	}

	for _, searchPath := range searchPaths {
		if _, err := os.Stat(searchPath); err == nil {
			return loadConfigFromFile(searchPath)
		}
	}

	// No config found, return default
	return DefaultConfig(), nil
}

// loadConfigFromFile loads configuration from a specific file.
func loadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Validate config
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &config, nil
}

// validateConfig validates the policy configuration.
func validateConfig(config *Config) error {
	// Version check
	if config.Version != "v1" {
		return fmt.Errorf("unsupported config version: %s (expected v1)", config.Version)
	}

	// Validate SBOM format if specified
	if config.SBOM != nil && config.SBOM.RequiredFormat != "" {
		validFormats := map[string]bool{
			"cyclonedx-json": true,
			"spdx-json":      true,
			"syft-json":      true,
		}
		if !validFormats[config.SBOM.RequiredFormat] {
			return fmt.Errorf("invalid SBOM format: %s (valid: cyclonedx-json, spdx-json, syft-json)", config.SBOM.RequiredFormat)
		}
	}

	// Validate vulnerability thresholds
	if config.Vulnerabilities != nil {
		if config.Vulnerabilities.MaxCritical != nil && *config.Vulnerabilities.MaxCritical < 0 {
			return fmt.Errorf("max_critical must be >= 0")
		}
		if config.Vulnerabilities.MaxHigh != nil && *config.Vulnerabilities.MaxHigh < 0 {
			return fmt.Errorf("max_high must be >= 0")
		}
		if config.Vulnerabilities.MaxMedium != nil && *config.Vulnerabilities.MaxMedium < 0 {
			return fmt.Errorf("max_medium must be >= 0")
		}
		if config.Vulnerabilities.MaxLow != nil && *config.Vulnerabilities.MaxLow < 0 {
			return fmt.Errorf("max_low must be >= 0")
		}
	}

	// Validate custom policy files exist if specified
	if config.Custom != nil && config.Custom.OPAEnabled {
		for _, policyFile := range config.Custom.PolicyFiles {
			if _, err := os.Stat(policyFile); err != nil {
				return fmt.Errorf("policy file not found: %s", policyFile)
			}
		}
	}

	return nil
}

// SaveConfig saves the configuration to a file.
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
}
