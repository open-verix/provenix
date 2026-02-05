package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/policy"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

func TestEngine_Evaluate_Vulnerabilities(t *testing.T) {
	tests := []struct {
		name          string
		config        *policy.Config
		vulns         []scanner.Vulnerability
		wantPassed    bool
		wantViolCount int
	}{
		{
			name: "no vulnerabilities - should pass",
			config: &policy.Config{
				Version: "v1",
				Vulnerabilities: &policy.VulnerabilityPolicy{
					MaxCritical: intPtr(0),
					MaxHigh:     intPtr(0),
					MaxMedium:   intPtr(10),
				},
			},
			vulns:         []scanner.Vulnerability{},
			wantPassed:    true,
			wantViolCount: 0,
		},
		{
			name: "1 critical - should fail",
			config: &policy.Config{
				Version: "v1",
				Vulnerabilities: &policy.VulnerabilityPolicy{
					MaxCritical: intPtr(0),
				},
			},
			vulns: []scanner.Vulnerability{
				{
					ID:       "CVE-2024-0001",
					Severity: scanner.SeverityCritical,
					Package:  "vulnerable-pkg",
					Version:  "1.0.0",
				},
			},
			wantPassed:    false,
			wantViolCount: 1,
		},
		{
			name: "within threshold - should pass",
			config: &policy.Config{
				Version: "v1",
				Vulnerabilities: &policy.VulnerabilityPolicy{
					MaxCritical: intPtr(1),
					MaxHigh:     intPtr(5),
				},
			},
			vulns: []scanner.Vulnerability{
				{ID: "CVE-2024-0001", Severity: scanner.SeverityCritical},
				{ID: "CVE-2024-0002", Severity: scanner.SeverityHigh},
				{ID: "CVE-2024-0003", Severity: scanner.SeverityHigh},
			},
			wantPassed:    true,
			wantViolCount: 0,
		},
		{
			name: "unfixed vulnerabilities with OnlyFixed - should fail",
			config: &policy.Config{
				Version: "v1",
				Vulnerabilities: &policy.VulnerabilityPolicy{
					OnlyFixed: true,
				},
			},
			vulns: []scanner.Vulnerability{
				{
					ID:           "CVE-2024-0001",
					Severity:     scanner.SeverityHigh,
					Package:      "unfixed-pkg",
					Version:      "1.0.0",
					FixedVersion: "", // No fix available
				},
			},
			wantPassed:    false,
			wantViolCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := policy.NewEngine(tt.config)
			
			ev := &evidence.Evidence{
				SBOM: &sbom.SBOM{
					Format:   sbom.FormatCycloneDXJSON,
					Artifact: "test-artifact",
					Content:  []byte(`{"components":[]}`),
					Checksum: "sha256:test",
				},
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: tt.vulns,
					ScannedAt:       time.Now(),
				},
			}

			result, err := engine.Evaluate(context.Background(), ev)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Passed != tt.wantPassed {
				t.Errorf("Evaluate() passed = %v, want %v", result.Passed, tt.wantPassed)
			}

			if len(result.Violations) != tt.wantViolCount {
				t.Errorf("Evaluate() violations count = %d, want %d", len(result.Violations), tt.wantViolCount)
			}
		})
	}
}

func TestEngine_Evaluate_Licenses(t *testing.T) {
	tests := []struct {
		name          string
		config        *policy.Config
		sbomContent   string
		wantPassed    bool
		wantViolCount int
	}{
		{
			name: "allowed license - should pass",
			config: &policy.Config{
				Version: "v1",
				Licenses: &policy.LicensePolicy{
					AllowedLicenses: []string{"MIT", "Apache-2.0"},
				},
			},
			sbomContent: `{
				"components": [
					{
						"name": "test-pkg",
						"version": "1.0.0",
						"licenses": [
							{"license": {"id": "MIT"}}
						]
					}
				]
			}`,
			wantPassed:    true,
			wantViolCount: 0,
		},
		{
			name: "denied license - should fail",
			config: &policy.Config{
				Version: "v1",
				Licenses: &policy.LicensePolicy{
					DeniedLicenses: []string{"GPL-3.0"},
				},
			},
			sbomContent: `{
				"components": [
					{
						"name": "gpl-pkg",
						"version": "1.0.0",
						"licenses": [
							{"license": {"id": "GPL-3.0"}}
						]
					}
				]
			}`,
			wantPassed:    false,
			wantViolCount: 1,
		},
		{
			name: "unknown license with warn - should pass with warning",
			config: &policy.Config{
				Version: "v1",
				Licenses: &policy.LicensePolicy{
					WarnOnUnknown: true,
				},
			},
			sbomContent: `{
				"components": [
					{
						"name": "unknown-pkg",
						"version": "1.0.0",
						"licenses": []
					}
				]
			}`,
			wantPassed:    true,
			wantViolCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := policy.NewEngine(tt.config)
			
			ev := &evidence.Evidence{
				SBOM: &sbom.SBOM{
					Format:   sbom.FormatCycloneDXJSON,
					Artifact: "test-artifact",
					Content:  []byte(tt.sbomContent),
					Checksum: "sha256:test",
				},
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: []scanner.Vulnerability{},
					ScannedAt:       time.Now(),
				},
			}

			result, err := engine.Evaluate(context.Background(), ev)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Passed != tt.wantPassed {
				t.Errorf("Evaluate() passed = %v, want %v", result.Passed, tt.wantPassed)
			}

			if len(result.Violations) != tt.wantViolCount {
				t.Errorf("Evaluate() violations count = %d, want %d", len(result.Violations), tt.wantViolCount)
			}
		})
	}
}

func TestExtractLicenses_CycloneDX(t *testing.T) {
	sbomData := []byte(`{
		"components": [
			{
				"name": "pkg1",
				"version": "1.0.0",
				"licenses": [
					{"license": {"id": "MIT"}}
				]
			},
			{
				"name": "pkg2",
				"version": "2.0.0",
				"licenses": [
					{"license": {"id": "Apache-2.0"}},
					{"license": {"id": "BSD-3-Clause"}}
				]
			},
			{
				"name": "pkg3",
				"version": "3.0.0",
				"licenses": []
			}
		]
	}`)

	licenses, err := policy.ExtractLicenses(sbomData, "cyclonedx-json")
	if err != nil {
		t.Fatalf("ExtractLicenses() error = %v", err)
	}

	if len(licenses) != 3 {
		t.Errorf("ExtractLicenses() count = %d, want 3", len(licenses))
	}

	// Check pkg1 - MIT
	if len(licenses[0].Licenses) != 1 || licenses[0].Licenses[0] != "MIT" {
		t.Errorf("pkg1 license = %v, want [MIT]", licenses[0].Licenses)
	}

	// Check pkg2 - Apache-2.0 OR BSD-3-Clause
	if len(licenses[1].Licenses) != 2 {
		t.Errorf("pkg2 licenses count = %d, want 2", len(licenses[1].Licenses))
	}

	// Check pkg3 - UNKNOWN
	if licenses[2].LicenseText != "UNKNOWN" {
		t.Errorf("pkg3 license text = %s, want UNKNOWN", licenses[2].LicenseText)
	}
}

func TestExtractLicenses_SPDX(t *testing.T) {
	sbomData := []byte(`{
		"packages": [
			{
				"name": "pkg1",
				"versionInfo": "1.0.0",
				"licenseConcluded": "MIT"
			},
			{
				"name": "pkg2",
				"versionInfo": "2.0.0",
				"licenseConcluded": "NOASSERTION",
				"licenseDeclared": "Apache-2.0"
			},
			{
				"name": "pkg3",
				"versionInfo": "3.0.0",
				"licenseConcluded": "MIT OR Apache-2.0"
			}
		]
	}`)

	licenses, err := policy.ExtractLicenses(sbomData, "spdx-json")
	if err != nil {
		t.Fatalf("ExtractLicenses() error = %v", err)
	}

	if len(licenses) != 3 {
		t.Errorf("ExtractLicenses() count = %d, want 3", len(licenses))
	}

	// Check pkg1 - MIT
	if len(licenses[0].Licenses) != 1 || licenses[0].Licenses[0] != "MIT" {
		t.Errorf("pkg1 license = %v, want [MIT]", licenses[0].Licenses)
	}

	// Check pkg2 - Falls back to licenseDeclared
	if len(licenses[1].Licenses) != 1 || licenses[1].Licenses[0] != "Apache-2.0" {
		t.Errorf("pkg2 license = %v, want [Apache-2.0]", licenses[1].Licenses)
	}

	// Check pkg3 - MIT OR Apache-2.0 (parsed into both)
	if len(licenses[2].Licenses) < 2 {
		t.Errorf("pkg3 licenses count = %d, want >= 2", len(licenses[2].Licenses))
	}
}

func TestCheckLicense(t *testing.T) {
	tests := []struct {
		name        string
		license     string
		policy      *policy.LicensePolicy
		wantAllowed bool
	}{
		{
			name:    "no policy - allow all",
			license: "MIT",
			policy:  nil,
			wantAllowed: true,
		},
		{
			name:    "in allowed list",
			license: "MIT",
			policy: &policy.LicensePolicy{
				AllowedLicenses: []string{"MIT", "Apache-2.0"},
			},
			wantAllowed: true,
		},
		{
			name:    "not in allowed list",
			license: "GPL-3.0",
			policy: &policy.LicensePolicy{
				AllowedLicenses: []string{"MIT", "Apache-2.0"},
			},
			wantAllowed: false,
		},
		{
			name:    "in denied list",
			license: "GPL-3.0",
			policy: &policy.LicensePolicy{
				DeniedLicenses: []string{"GPL-3.0", "AGPL-3.0"},
			},
			wantAllowed: false,
		},
		{
			name:    "not in denied list - allow",
			license: "MIT",
			policy: &policy.LicensePolicy{
				DeniedLicenses: []string{"GPL-3.0"},
			},
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, _ := policy.CheckLicense(tt.license, tt.policy)
			if allowed != tt.wantAllowed {
				t.Errorf("CheckLicense() = %v, want %v", allowed, tt.wantAllowed)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Test loading default config
	cfg, err := policy.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Version != "v1" {
		t.Errorf("Version = %s, want v1", cfg.Version)
	}

	if cfg.Vulnerabilities == nil {
		t.Error("Vulnerabilities policy is nil")
	}

	if cfg.Licenses == nil {
		t.Error("Licenses policy is nil")
	}
}

// Helper functions

func intPtr(i int) *int {
	return &i
}

func countBySeverity(vulns []scanner.Vulnerability, severity scanner.Severity) int {
	count := 0
	for _, v := range vulns {
		if v.Severity == severity {
			count++
		}
	}
	return count
}
