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

	// CELPolicyFiles is a list of external .cel policy files to load
	// Example: [".provenix/policies/security.cel", ".provenix/policies/compliance.cel"]
	CELPolicyFiles []string `yaml:"cel_policy_files,omitempty"`

	// CELEntryPoint is the name of the CEL expression to evaluate when using external files
	// If empty, all loaded expressions are evaluated
	// Example: "allow" (evaluates only the expression named "allow")
	CELEntryPoint string `yaml:"cel_entry_point,omitempty"`

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
	maxHigh := 5
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
		// TODO(Phase 6): License policy - not yet implemented
		// Will be enabled when license evaluation is implemented in engine.go
		Licenses: nil,
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

// ProductionConfig returns production-optimized policy configuration.
// Production defaults:
// - Stricter vulnerability thresholds (0 critical, 0 high, 5 medium)
// - Keyless signing via OIDC
// - Rekor transparency log enabled
// - Auto-update vulnerability database
func ProductionConfig() *Config {
	maxCritical := 0
	maxHigh := 0
	maxMedium := 5

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
		Licenses: nil,
		SBOM: &SBOMPolicy{
			RequiredFormat:  "",
			MinPackages:     0,
			RequireChecksum: true,
		},
		Signing: &SigningPolicy{
			Required:        false,
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
//
// Two formats are supported:
//
//  1. Standalone policy file (legacy / team-shared):
//     version: v1
//     vulnerabilities:
//     max_critical: 0
//
//  2. Unified provenix.yaml (recommended — tool config + policy in one file):
//     version: v1
//     sbom:
//     format: cyclonedx-json
//     policy:            ← policy lives under this key
//     vulnerabilities:
//     max_critical: 0
func loadConfigFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	// Detect unified provenix.yaml: parse as a raw node map and check for
	// a top-level "policy:" key.
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err == nil {
		if policyNode, ok := raw["policy"]; ok {
			// Unified format — extract the policy: sub-section.
			var cfg Config
			if err := policyNode.Decode(&cfg); err != nil {
				return nil, fmt.Errorf("failed to parse policy section in %s: %w", path, err)
			}
			// Inherit version from parent file when not set in sub-section.
			if cfg.Version == "" {
				cfg.Version = "v1"
			}
			if err := validateConfig(&cfg); err != nil {
				return nil, fmt.Errorf("invalid policy config in %s: %w", path, err)
			}
			return &cfg, nil
		}
	}

	// Standalone policy file — parse the whole document.
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

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

// SaveConfig saves the policy configuration to a file in standalone format.
// For writing to provenix.yaml (unified format), use SaveUnifiedConfig instead.
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

// SaveUnifiedConfig writes a full provenix.yaml containing both tool config
// defaults and the policy: sub-section. This is the recommended format for
// new projects — a single file manages all Provenix settings.
func SaveUnifiedConfig(policy *Config, path string) error {
	maxCritical := 0
	maxHigh := 5
	maxMedium := 10
	if policy.Vulnerabilities != nil {
		if policy.Vulnerabilities.MaxCritical != nil {
			maxCritical = *policy.Vulnerabilities.MaxCritical
		}
		if policy.Vulnerabilities.MaxHigh != nil {
			maxHigh = *policy.Vulnerabilities.MaxHigh
		}
		if policy.Vulnerabilities.MaxMedium != nil {
			maxMedium = *policy.Vulnerabilities.MaxMedium
		}
	}

	requireChecksum := true
	if policy.SBOM != nil {
		requireChecksum = policy.SBOM.RequireChecksum
	}

	entryPoint := "data.provenix.allow"
	if policy.Custom != nil && policy.Custom.EntryPoint != "" {
		entryPoint = policy.Custom.EntryPoint
	}

	content := fmt.Sprintf(`# provenix.yaml — Provenix configuration (tool config + policy in one file)
#
# Commit this file to your repository.
# Generated artifacts go to .provenix/ which should be in .gitignore.
#
# Config priority: CLI flags > env vars (PROVENIX_*) > this file > defaults
# Schema version of this config file
version: v1

# ==============================================================================
# Tool Configuration (Development Defaults)
# ==============================================================================
# These defaults optimize for local development:
# - Local key signing (fast, offline-capable)
# - No Rekor publishing (fast, private)
# - Manual database updates (offline-capable)
#
# For production, use provenix.prod.yaml or override via CLI flags:
#   provenix attest --config provenix.prod.yaml myapp:latest
#
sbom:
  # Options: cyclonedx-json, spdx-json, syft-json
  format: cyclonedx-json
  # Whether to embed source files in the SBOM (increases artifact size)
  include-files: false

scan:
  # Report vulnerabilities at this severity level and above
  min-severity: medium
  # Fail the build if any vulnerability reaches this severity level
  fail-on: critical
  database:
    # Auto-update vulnerability database (set false for offline development)
    auto-update: false
    # Maximum age of database before requiring update (hours)
    max-age: 168  # 7 days

signing:
  # Use local key signing for development (fast, no OIDC required)
  # Generate dev keys: provenix init --generate-keys
  mode: key
  key:
    # Path to private key for local signing
    # Run 'provenix init --generate-keys' to create .provenix/dev-key.pem
    path: .provenix/dev-key.pem

rekor:
  # Transparency log disabled for development (fast, private)
  # Enable in production: url: https://rekor.sigstore.dev
  url: ""

storage:
  # Output directory for generated attestations
  dir: .provenix/attestations

# ==============================================================================
# Policy
# ==============================================================================
policy:
  vulnerabilities:
    # Maximum number of Critical vulnerabilities allowed (0 = none)
    max_critical: %d
    # Maximum number of High vulnerabilities allowed
    max_high: %d
    # Maximum number of Medium vulnerabilities allowed
    max_medium: %d

  # TODO(Phase 6): License policy
  # licenses:
  #   allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
  #   denied: [GPL-3.0, AGPL-3.0]
  #   warn_on_unknown: true

  sbom:
    # Require the SBOM to include checksums for all components
    require_checksum: %v

  signing:
    # Whether a valid signature on the attestation is required
    required: false

  custom:
    # Enable custom policy evaluation using CEL (Common Expression Language)
    cel_enabled: false
    
    # External CEL policy files (optional)
    # cel_policy_files:
    #   - .provenix/policies/security.cel
    #   - .provenix/policies/compliance.cel
    
    # CEL entry point: evaluate only this named expression (optional)
    # If empty, all expressions are evaluated
    # cel_entry_point: allow
    
    # OPA integration (future - Phase 6)
    # Entry point for OPA evaluation
    entry_point: %s

# ==============================================================================
# Option Reference
# ==============================================================================
#
# version:
#   v1
#
# sbom.format:
#   cyclonedx-json  — CycloneDX format (JSON)
#   spdx-json       — SPDX format (JSON)
#   syft-json       — Syft native format (JSON)
#
# sbom.include-files:
#   true   — Embed source file paths in the SBOM
#   false  — Omit source files (smaller artifact)
#
# scan.min-severity:
#   critical | high | medium | low | negligible | unknown
#
# scan.fail-on:
#   critical | high | medium | low | negligible | unknown
#
# signing.mode:
#   keyless  — Sigstore OIDC-based signing (no key management)
#   key      — Sign with a local or KMS-managed private key
#
# policy.vulnerabilities.max_critical / max_high / max_medium:
#   Any non-negative integer. 0 means the policy fails on any occurrence.
#
# policy.sbom.require_checksum:
#   true | false
#
# policy.signing.required:
#   true  — Attestation must carry a valid signature
#   false — Signature is optional
#
# policy.custom.cel_enabled:
#   true  — Evaluate custom rules defined in CEL
#   false — Skip custom policy evaluation
#
# policy.custom.cel_policy_files:
#   List of external .cel files containing policy expressions
#   Example: [".provenix/policies/security.cel"]
#
# policy.custom.cel_entry_point:
#   Name of the expression to evaluate (leave empty to evaluate all)
#   Example: "allow" evaluates only the expression named "allow"
`, maxCritical, maxHigh, maxMedium, requireChecksum, entryPoint)

	// Create directory if needed
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
}

// SaveProductionConfig generates production-optimized configuration file.
// This creates provenix.prod.yaml with stricter security settings.
func SaveProductionConfig(policy *Config, path string) error {
	maxCritical := 0
	maxHigh := 0
	maxMedium := 5
	if policy.Vulnerabilities != nil {
		if policy.Vulnerabilities.MaxCritical != nil {
			maxCritical = *policy.Vulnerabilities.MaxCritical
		}
		if policy.Vulnerabilities.MaxHigh != nil {
			maxHigh = *policy.Vulnerabilities.MaxHigh
		}
		if policy.Vulnerabilities.MaxMedium != nil {
			maxMedium = *policy.Vulnerabilities.MaxMedium
		}
	}

	requireChecksum := true
	if policy.SBOM != nil {
		requireChecksum = policy.SBOM.RequireChecksum
	}

	entryPoint := "data.provenix.allow"
	if policy.Custom != nil && policy.Custom.EntryPoint != "" {
		entryPoint = policy.Custom.EntryPoint
	}

	content := fmt.Sprintf(`# provenix.prod.yaml — Production Configuration
#
# This file contains production-specific overrides for provenix.yaml.
# Use with: provenix attest --config provenix.prod.yaml myapp:latest
# Or set: export PROVENIX_CONFIG=provenix.prod.yaml
#
# Production optimizations:
# - Keyless signing (OIDC via Fulcio, no key management)
# - Rekor transparency log (public audit trail)
# - Auto-update vulnerability database (always latest data)
# - Stricter vulnerability thresholds (0 critical, 0 high, 5 medium)

version: v1

# ==============================================================================
# Tool Configuration (Production Overrides)
# ==============================================================================
sbom:
  format: cyclonedx-json
  include-files: false

scan:
  min-severity: medium
  fail-on: high
  database:
    # Always keep vulnerability database up-to-date in production
    auto-update: true
    # Maximum age before forcing update (24 hours)
    max-age: 24

signing:
  # Keyless signing via Sigstore OIDC (GitHub Actions, GitLab CI support)
  mode: keyless
  oidc:
    # Certificate authority endpoint
    fulcio-url: https://fulcio.sigstore.dev
    # OIDC issuer (auto-detected in CI environments)
    # issuer: https://token.actions.githubusercontent.com

rekor:
  # Publish signatures to public transparency log
  url: https://rekor.sigstore.dev

storage:
  dir: .provenix/attestations

# ==============================================================================
# Policy (Production Defaults)
# ==============================================================================
policy:
  vulnerabilities:
    # Production: Zero tolerance for critical vulnerabilities
    max_critical: %d
    # Production: Zero tolerance for high vulnerabilities
    max_high: %d
    # Production: Limited medium vulnerabilities allowed
    max_medium: %d

  # TODO(Phase 6): License policy
  # licenses:
  #   allowed: [MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC]
  #   denied: [GPL-3.0, AGPL-3.0]
  #   require_all_packages: true

  sbom:
    require_checksum: %v

  signing:
    # In production, signature verification should be enforced
    required: false

  custom:
    cel_enabled: false
    entry_point: %s

# ==============================================================================
# Usage Examples
# ==============================================================================
#
# CI/CD Integration:
#   export PROVENIX_CONFIG=provenix.prod.yaml
#   provenix attest $IMAGE_NAME:$TAG
#
# GitHub Actions:
#   - name: Attest with production settings
#     env:
#       PROVENIX_CONFIG: provenix.prod.yaml
#     run: provenix attest myapp:${{ github.sha }}
#
# One-time override:
#   provenix attest --config provenix.prod.yaml myapp:v1.0.0
#
# Configuration priority:
#   CLI flags > PROVENIX_CONFIG env var > provenix.yaml > defaults
`, maxCritical, maxHigh, maxMedium, requireChecksum, entryPoint)

	// Create directory if needed
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file %s: %w", path, err)
	}

	return nil
}
