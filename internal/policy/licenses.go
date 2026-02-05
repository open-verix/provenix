package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractLicenses extracts license information from an SBOM.
// Supports CycloneDX and SPDX formats.
func ExtractLicenses(sbom []byte, format string) ([]PackageLicense, error) {
	switch {
	case strings.Contains(format, "cyclonedx"):
		return extractCycloneDXLicenses(sbom)
	case strings.Contains(format, "spdx"):
		return extractSPDXLicenses(sbom)
	case strings.Contains(format, "syft"):
		// Syft JSON format includes license info similar to CycloneDX
		return extractSyftLicenses(sbom)
	default:
		return nil, fmt.Errorf("unsupported SBOM format for license extraction: %s", format)
	}
}

// PackageLicense represents license information for a package.
type PackageLicense struct {
	PackageName string
	Version     string
	Licenses    []string // SPDX license identifiers
	LicenseText string   // License expression (e.g., "MIT OR Apache-2.0")
}

// CycloneDX structures (minimal, only what we need for license extraction)
type cycloneDXBOM struct {
	Components []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	Name     string              `json:"name"`
	Version  string              `json:"version"`
	Licenses []cycloneDXLicense  `json:"licenses,omitempty"`
}

type cycloneDXLicense struct {
	License *cycloneDXLicenseChoice `json:"license,omitempty"`
}

type cycloneDXLicenseChoice struct {
	ID   string `json:"id,omitempty"`   // SPDX identifier
	Name string `json:"name,omitempty"` // License name
}

// SPDX structures (minimal)
type spdxBOM struct {
	Packages []spdxPackage `json:"packages"`
}

type spdxPackage struct {
	Name             string `json:"name"`
	VersionInfo      string `json:"versionInfo,omitempty"`
	LicenseConcluded string `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string `json:"licenseDeclared,omitempty"`
}

// Syft JSON structures (minimal)
type syftBOM struct {
	Artifacts []syftArtifact `json:"artifacts"`
}

type syftArtifact struct {
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Licenses []syftLicense `json:"licenses,omitempty"`
}

type syftLicense struct {
	Value string `json:"value"`
	Type  string `json:"type"` // "declared" or "concluded"
}

// extractCycloneDXLicenses extracts licenses from CycloneDX SBOM.
func extractCycloneDXLicenses(sbom []byte) ([]PackageLicense, error) {
	var bom cycloneDXBOM
	if err := json.Unmarshal(sbom, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX SBOM: %w", err)
	}

	var licenses []PackageLicense
	for _, component := range bom.Components {
		var licenseIDs []string
		for _, lic := range component.Licenses {
			if lic.License != nil {
				if lic.License.ID != "" {
					licenseIDs = append(licenseIDs, lic.License.ID)
				} else if lic.License.Name != "" {
					licenseIDs = append(licenseIDs, lic.License.Name)
				}
			}
		}

		if len(licenseIDs) > 0 {
			licenses = append(licenses, PackageLicense{
				PackageName: component.Name,
				Version:     component.Version,
				Licenses:    licenseIDs,
				LicenseText: strings.Join(licenseIDs, " OR "),
			})
		} else {
			// Package with no license information
			licenses = append(licenses, PackageLicense{
				PackageName: component.Name,
				Version:     component.Version,
				Licenses:    []string{},
				LicenseText: "UNKNOWN",
			})
		}
	}

	return licenses, nil
}

// extractSPDXLicenses extracts licenses from SPDX SBOM.
func extractSPDXLicenses(sbom []byte) ([]PackageLicense, error) {
	var bom spdxBOM
	if err := json.Unmarshal(sbom, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse SPDX SBOM: %w", err)
	}

	var licenses []PackageLicense
	for _, pkg := range bom.Packages {
		// Prefer licenseConcluded, fallback to licenseDeclared
		licenseExpr := pkg.LicenseConcluded
		if licenseExpr == "" || licenseExpr == "NOASSERTION" {
			licenseExpr = pkg.LicenseDeclared
		}

		// Parse SPDX license expression (e.g., "MIT OR Apache-2.0")
		licenseIDs := parseSPDXExpression(licenseExpr)

		licenses = append(licenses, PackageLicense{
			PackageName: pkg.Name,
			Version:     pkg.VersionInfo,
			Licenses:    licenseIDs,
			LicenseText: licenseExpr,
		})
	}

	return licenses, nil
}

// extractSyftLicenses extracts licenses from Syft JSON SBOM.
func extractSyftLicenses(sbom []byte) ([]PackageLicense, error) {
	var bom syftBOM
	if err := json.Unmarshal(sbom, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse Syft SBOM: %w", err)
	}

	var licenses []PackageLicense
	for _, artifact := range bom.Artifacts {
		var licenseIDs []string
		for _, lic := range artifact.Licenses {
			if lic.Value != "" {
				licenseIDs = append(licenseIDs, lic.Value)
			}
		}

		if len(licenseIDs) > 0 {
			licenses = append(licenses, PackageLicense{
				PackageName: artifact.Name,
				Version:     artifact.Version,
				Licenses:    licenseIDs,
				LicenseText: strings.Join(licenseIDs, " OR "),
			})
		} else {
			licenses = append(licenses, PackageLicense{
				PackageName: artifact.Name,
				Version:     artifact.Version,
				Licenses:    []string{},
				LicenseText: "UNKNOWN",
			})
		}
	}

	return licenses, nil
}

// parseSPDXExpression parses an SPDX license expression into individual license IDs.
// This is a simple parser that handles common cases:
// - Single license: "MIT"
// - OR expression: "MIT OR Apache-2.0"
// - AND expression: "MIT AND BSD-3-Clause"
// - WITH expression: "Apache-2.0 WITH LLVM-exception"
//
// Note: This is a simplified parser. For production use, consider using
// a proper SPDX expression parser library.
func parseSPDXExpression(expr string) []string {
	if expr == "" || expr == "NOASSERTION" || expr == "NONE" {
		return []string{"UNKNOWN"}
	}

	// Split by common operators
	var licenses []string
	parts := strings.FieldsFunc(expr, func(r rune) bool {
		return r == '(' || r == ')' || r == ','
	})

	for _, part := range parts {
		part = strings.TrimSpace(part)
		// Remove operators
		part = strings.ReplaceAll(part, " OR ", " ")
		part = strings.ReplaceAll(part, " AND ", " ")
		part = strings.ReplaceAll(part, " WITH ", " ")

		tokens := strings.Fields(part)
		for _, token := range tokens {
			// Filter out keywords
			if token != "OR" && token != "AND" && token != "WITH" {
				licenses = append(licenses, token)
			}
		}
	}

	if len(licenses) == 0 {
		return []string{"UNKNOWN"}
	}

	return licenses
}

// CheckLicense checks if a license is allowed based on policy.
func CheckLicense(license string, policy *LicensePolicy) (allowed bool, reason string) {
	if policy == nil {
		return true, "" // No policy, allow all
	}

	// Check denied list first (takes precedence)
	for _, denied := range policy.DeniedLicenses {
		if strings.EqualFold(license, denied) {
			return false, fmt.Sprintf("license %s is explicitly denied", license)
		}
	}

	// If allowed list is specified, check it
	if len(policy.AllowedLicenses) > 0 {
		for _, allowed := range policy.AllowedLicenses {
			if strings.EqualFold(license, allowed) {
				return true, ""
			}
		}
		return false, fmt.Sprintf("license %s is not in the allowed list", license)
	}

	// No allowed list, and not denied, so allow
	return true, ""
}
