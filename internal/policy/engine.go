package policy

import (
	"context"
	"fmt"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

// Engine evaluates policies against evidence.
type Engine struct {
	config *Config
}

// NewEngine creates a new policy engine with the given configuration.
func NewEngine(config *Config) *Engine {
	return &Engine{
		config: config,
	}
}

// Evaluate evaluates all policies against the provided evidence.
// Returns a list of violations and an error if evaluation fails.
func (e *Engine) Evaluate(ctx context.Context, ev *evidence.Evidence) (*Result, error) {
	if ev == nil {
		return nil, fmt.Errorf("evidence is required for policy evaluation")
	}

	result := &Result{
		Passed:     true,
		Violations: []Violation{},
		Warnings:   []Warning{},
	}

	// Evaluate vulnerability policies
	if e.config.Vulnerabilities != nil {
		violations, warnings := e.evaluateVulnerabilities(ev)
		result.Violations = append(result.Violations, violations...)
		result.Warnings = append(result.Warnings, warnings...)
	}

	// Evaluate license policies
	if e.config.Licenses != nil {
		violations, warnings := e.evaluateLicenses(ev)
		result.Violations = append(result.Violations, violations...)
		result.Warnings = append(result.Warnings, warnings...)
	}

	// Evaluate SBOM policies
	if e.config.SBOM != nil {
		violations, warnings := e.evaluateSBOM(ev)
		result.Violations = append(result.Violations, violations...)
		result.Warnings = append(result.Warnings, warnings...)
	}

	// Set overall pass/fail
	if len(result.Violations) > 0 {
		result.Passed = false
	}

	return result, nil
}

// evaluateVulnerabilities checks vulnerability-related policies.
func (e *Engine) evaluateVulnerabilities(ev *evidence.Evidence) ([]Violation, []Warning) {
	var violations []Violation
	var warnings []Warning

	if ev.VulnerabilityReport == nil {
		return violations, warnings
	}

	// Count vulnerabilities by severity
	severityCounts := make(map[scanner.Severity]int)
	for _, vuln := range ev.VulnerabilityReport.Vulnerabilities {
		severityCounts[vuln.Severity]++
	}

	// Check max allowed vulnerabilities per severity
	if e.config.Vulnerabilities.MaxCritical != nil && severityCounts[scanner.SeverityCritical] > *e.config.Vulnerabilities.MaxCritical {
		violations = append(violations, Violation{
			Type:     ViolationTypeVulnerability,
			Severity: SeverityHigh,
			Message:  fmt.Sprintf("Critical vulnerabilities exceed limit: %d > %d", severityCounts[scanner.SeverityCritical], *e.config.Vulnerabilities.MaxCritical),
			Details: map[string]interface{}{
				"count": severityCounts[scanner.SeverityCritical],
				"limit": *e.config.Vulnerabilities.MaxCritical,
			},
		})
	}

	if e.config.Vulnerabilities.MaxHigh != nil && severityCounts[scanner.SeverityHigh] > *e.config.Vulnerabilities.MaxHigh {
		violations = append(violations, Violation{
			Type:     ViolationTypeVulnerability,
			Severity: SeverityHigh,
			Message:  fmt.Sprintf("High vulnerabilities exceed limit: %d > %d", severityCounts[scanner.SeverityHigh], *e.config.Vulnerabilities.MaxHigh),
			Details: map[string]interface{}{
				"count": severityCounts[scanner.SeverityHigh],
				"limit": *e.config.Vulnerabilities.MaxHigh,
			},
		})
	}

	if e.config.Vulnerabilities.MaxMedium != nil && severityCounts[scanner.SeverityMedium] > *e.config.Vulnerabilities.MaxMedium {
		warnings = append(warnings, Warning{
			Type:    WarningTypeVulnerability,
			Message: fmt.Sprintf("Medium vulnerabilities exceed limit: %d > %d", severityCounts[scanner.SeverityMedium], *e.config.Vulnerabilities.MaxMedium),
		})
	}

	// Check if only fixed vulnerabilities are allowed
	if e.config.Vulnerabilities.OnlyFixed {
		unfixedCount := 0
		for _, vuln := range ev.VulnerabilityReport.Vulnerabilities {
			if vuln.FixedVersion == "" {
				unfixedCount++
			}
		}
		if unfixedCount > 0 {
			violations = append(violations, Violation{
				Type:     ViolationTypeVulnerability,
				Severity: SeverityMedium,
				Message:  fmt.Sprintf("Unfixed vulnerabilities found: %d", unfixedCount),
				Details: map[string]interface{}{
					"count": unfixedCount,
				},
			})
		}
	}

	return violations, warnings
}

// evaluateLicenses checks license-related policies.
func (e *Engine) evaluateLicenses(ev *evidence.Evidence) ([]Violation, []Warning) {
	var violations []Violation
	var warnings []Warning

	if e.config.Licenses == nil {
		return violations, warnings
	}

	if ev.SBOM == nil {
		return violations, warnings
	}

	// Extract licenses from SBOM
	licenses, err := ExtractLicenses(ev.SBOM.Content, string(ev.SBOM.Format))
	if err != nil {
		// Log error but don't fail - license check is not critical for MVP
		warnings = append(warnings, Warning{
			Type:    WarningTypeGeneral,
			Message: fmt.Sprintf("Failed to extract licenses from SBOM: %v", err),
		})
		return violations, warnings
	}

	unknownCount := 0
	for _, pkgLic := range licenses {
		// Check if package has no license information
		if len(pkgLic.Licenses) == 0 || pkgLic.LicenseText == "UNKNOWN" {
			unknownCount++
			if e.config.Licenses.WarnOnUnknown {
				warnings = append(warnings, Warning{
					Type:    WarningTypeUnknownLicense,
					Message: fmt.Sprintf("Package %s@%s has unknown license", pkgLic.PackageName, pkgLic.Version),
					Package: pkgLic.PackageName,
					Details: map[string]interface{}{
						"version": pkgLic.Version,
					},
				})
			}
			continue
		}

		// Check each license in the package
		for _, license := range pkgLic.Licenses {
			allowed, reason := CheckLicense(license, e.config.Licenses)
			if !allowed {
				violations = append(violations, Violation{
					Type:     ViolationTypeLicense,
					Severity: SeverityHigh,
					Message:  fmt.Sprintf("Package %s@%s has disallowed license: %s", pkgLic.PackageName, pkgLic.Version, license),
					Package:  pkgLic.PackageName,
					Details: map[string]interface{}{
						"version": pkgLic.Version,
						"license": license,
						"reason":  reason,
					},
				})
			}
		}
	}

	// Check if all packages are required to have licenses
	if e.config.Licenses.RequireAllPackages && unknownCount > 0 {
		violations = append(violations, Violation{
			Type:     ViolationTypeLicense,
			Severity: SeverityMedium,
			Message:  fmt.Sprintf("%d packages have unknown or missing licenses", unknownCount),
			Details: map[string]interface{}{
				"unknown_count": unknownCount,
			},
		})
	}

	return violations, warnings
}

// evaluateSBOM checks SBOM-related policies.
func (e *Engine) evaluateSBOM(ev *evidence.Evidence) ([]Violation, []Warning) {
	var violations []Violation
	var warnings []Warning

	if ev.SBOM == nil {
		violations = append(violations, Violation{
			Type:     ViolationTypeSBOM,
			Severity: SeverityHigh,
			Message:  "SBOM is required but not present",
		})
		return violations, warnings
	}

	// Check if required format is used
	if e.config.SBOM.RequiredFormat != "" && string(ev.SBOM.Format) != e.config.SBOM.RequiredFormat {
		violations = append(violations, Violation{
			Type:     ViolationTypeSBOM,
			Severity: SeverityMedium,
			Message:  fmt.Sprintf("SBOM format must be %s, got %s", e.config.SBOM.RequiredFormat, ev.SBOM.Format),
		})
	}

	return violations, warnings
}

// Result represents the outcome of policy evaluation.
type Result struct {
	Passed     bool        `json:"passed"`
	Violations []Violation `json:"violations"`
	Warnings   []Warning   `json:"warnings"`
}

// Violation represents a policy violation.
type Violation struct {
	Type     ViolationType          `json:"type"`
	Severity Severity               `json:"severity"`
	Message  string                 `json:"message"`
	Package  string                 `json:"package,omitempty"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// Warning represents a policy warning (non-blocking).
type Warning struct {
	Type    WarningType            `json:"type"`
	Message string                 `json:"message"`
	Package string                 `json:"package,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// ViolationType represents the type of policy violation.
type ViolationType string

const (
	ViolationTypeVulnerability ViolationType = "vulnerability"
	ViolationTypeLicense       ViolationType = "license"
	ViolationTypeSBOM          ViolationType = "sbom"
	ViolationTypeCustom        ViolationType = "custom"
)

// WarningType represents the type of policy warning.
type WarningType string

const (
	WarningTypeVulnerability   WarningType = "vulnerability"
	WarningTypeLicense         WarningType = "license"
	WarningTypeUnknownLicense  WarningType = "unknown_license"
	WarningTypeSBOM            WarningType = "sbom"
	WarningTypeCustom          WarningType = "custom"
	WarningTypeGeneral         WarningType = "general"
)

// Severity represents the severity of a violation.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)
