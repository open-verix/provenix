package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers/scanner"
)

func TestEvaluateCustomCELWithExternalFiles(t *testing.T) {
	// Create temporary directory for test policy files
	tmpDir, err := os.MkdirTemp("", "cel-integration-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test policy file
	policyFile := filepath.Join(tmpDir, "test-policy.cel")
	policyContent := `# Test policy
no_critical = input.vulnerabilities.critical == 0
max_high = input.vulnerabilities.high <= 5
allow = input.vulnerabilities.critical == 0 && input.vulnerabilities.high <= 5
`
	if err := os.WriteFile(policyFile, []byte(policyContent), 0644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name              string
		config            *Config
		evidence          *evidence.Evidence
		wantViolations    int
		wantErr           bool
		wantErrContains   string
	}{
		{
			name: "external file with entry point - pass",
			config: &Config{
				Custom: &CustomPolicy{
					CELEnabled:     true,
					CELPolicyFiles: []string{policyFile},
					CELEntryPoint:  "allow",
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: []scanner.Vulnerability{
						{Severity: scanner.SeverityHigh},
						{Severity: scanner.SeverityHigh},
						{Severity: scanner.SeverityHigh},
						{Severity: scanner.SeverityMedium},
						{Severity: scanner.SeverityLow},
					},
				},
			},
			wantViolations: 0,
			wantErr:        false,
		},
		{
			name: "external file with entry point - fail",
			config: &Config{
				Custom: &CustomPolicy{
					CELEnabled:     true,
					CELPolicyFiles: []string{policyFile},
					CELEntryPoint:  "allow",
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: []scanner.Vulnerability{
						{Severity: scanner.SeverityCritical}, // Fails no_critical
						{Severity: scanner.SeverityHigh},
						{Severity: scanner.SeverityHigh},
					},
				},
			},
			wantViolations: 1, // allow expression fails
			wantErr:        false,
		},
		{
			name: "external file without entry point - evaluate all",
			config: &Config{
				Custom: &CustomPolicy{
					CELEnabled:     true,
					CELPolicyFiles: []string{policyFile},
					// No CELEntryPoint - evaluates all expressions
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: func() []scanner.Vulnerability {
						vulns := []scanner.Vulnerability{
							{Severity: scanner.SeverityCritical}, // Fails no_critical
						}
						// Add 10 high vulnerabilities to fail max_high (> 5)
						for i := 0; i < 10; i++ {
							vulns = append(vulns, scanner.Vulnerability{Severity: scanner.SeverityHigh})
						}
						return vulns
					}(),
				},
			},
			wantViolations: 3, // no_critical, max_high, and allow all fail
			wantErr:        false,
		},
		{
			name: "non-existent entry point",
			config: &Config{
				Custom: &CustomPolicy{
					CELEnabled:     true,
					CELPolicyFiles: []string{policyFile},
					CELEntryPoint:  "nonexistent",
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
			},
			wantErr:         true,
			wantErrContains: "entry point",
		},
		{
			name: "non-existent file",
			config: &Config{
				Custom: &CustomPolicy{
					CELEnabled:     true,
					CELPolicyFiles: []string{filepath.Join(tmpDir, "nonexistent.cel")},
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
			},
			wantErr:         true,
			wantErrContains: "failed to load",
		},
		{
			name: "mix inline and external expressions",
			config: &Config{
				Custom: &CustomPolicy{
					CELEnabled: true,
					CELExpressions: []CELExpression{
						{
							Name: "inline_check",
							Expr: "input.vulnerabilities.medium <= 15",
						},
					},
					CELPolicyFiles: []string{policyFile},
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: func() []scanner.Vulnerability {
						// 20 medium vulnerabilities - fails inline_check
						vulns := make([]scanner.Vulnerability, 20)
						for i := range vulns {
							vulns[i] = scanner.Vulnerability{Severity: scanner.SeverityMedium}
						}
						return vulns
					}(),
				},
			},
			wantViolations: 1, // Only inline_check fails
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine(tt.config)
			violations, _, err := engine.evaluateCustomCEL(context.Background(), tt.evidence)

			if tt.wantErr {
				if err == nil {
					t.Errorf("evaluateCustomCEL() expected error, got nil")
					return
				}
				if tt.wantErrContains != "" && !contains(err.Error(), tt.wantErrContains) {
					t.Errorf("evaluateCustomCEL() error = %v, want error containing %q", err, tt.wantErrContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("evaluateCustomCEL() unexpected error = %v", err)
			}

			if len(violations) != tt.wantViolations {
				t.Errorf("evaluateCustomCEL() got %d violations, want %d", len(violations), tt.wantViolations)
				for i, v := range violations {
					t.Logf("  violation[%d]: %s", i, v.Message)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
