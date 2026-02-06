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

func TestCELEvaluator_Basic(t *testing.T) {
	tests := []struct {
		name        string
		expressions []policy.CELExpression
		input       map[string]interface{}
		wantResults map[string]bool
		wantErr     bool
	}{
		{
			name: "simple boolean expression - true",
			expressions: []policy.CELExpression{
				{
					Name: "always-true",
					Expr: "true",
				},
			},
			input: map[string]interface{}{},
			wantResults: map[string]bool{
				"always-true": true,
			},
			wantErr: false,
		},
		{
			name: "simple boolean expression - false",
			expressions: []policy.CELExpression{
				{
					Name: "always-false",
					Expr: "false",
				},
			},
			input: map[string]interface{}{},
			wantResults: map[string]bool{
				"always-false": false,
			},
			wantErr: false,
		},
		{
			name: "check vulnerability count",
			expressions: []policy.CELExpression{
				{
					Name: "no-vulns",
					Expr: "input.vulnerabilities.size() == 0",
				},
			},
			input: map[string]interface{}{
				"vulnerabilities": []interface{}{},
			},
			wantResults: map[string]bool{
				"no-vulns": true,
			},
			wantErr: false,
		},
		{
			name: "filter critical vulnerabilities",
			expressions: []policy.CELExpression{
				{
					Name: "no-critical",
					Expr: "input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0",
				},
			},
			input: map[string]interface{}{
				"vulnerabilities": []interface{}{
					map[string]interface{}{"severity": "High", "id": "CVE-1"},
					map[string]interface{}{"severity": "Medium", "id": "CVE-2"},
				},
			},
			wantResults: map[string]bool{
				"no-critical": true,
			},
			wantErr: false,
		},
		{
			name: "filter critical vulnerabilities - has critical",
			expressions: []policy.CELExpression{
				{
					Name: "no-critical",
					Expr: "input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0",
				},
			},
			input: map[string]interface{}{
				"vulnerabilities": []interface{}{
					map[string]interface{}{"severity": "Critical", "id": "CVE-1"},
					map[string]interface{}{"severity": "High", "id": "CVE-2"},
				},
			},
			wantResults: map[string]bool{
				"no-critical": false,
			},
			wantErr: false,
		},
		{
			name: "multiple expressions",
			expressions: []policy.CELExpression{
				{
					Name: "check-1",
					Expr: "input.value > 10",
				},
				{
					Name: "check-2",
					Expr: "input.name == 'test'",
				},
			},
			input: map[string]interface{}{
				"value": 15,
				"name":  "test",
			},
			wantResults: map[string]bool{
				"check-1": true,
				"check-2": true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evaluator, err := policy.NewCELEvaluator(tt.expressions)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCELEvaluator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			ctx := context.Background()
			results, err := evaluator.Evaluate(ctx, tt.input)
			if err != nil {
				t.Errorf("Evaluate() error = %v", err)
				return
			}

			for name, want := range tt.wantResults {
				got, exists := results[name]
				if !exists {
					t.Errorf("Result for '%s' not found", name)
					continue
				}
				if got != want {
					t.Errorf("Result for '%s' = %v, want %v", name, got, want)
				}
			}
		})
	}
}

func TestCELEvaluator_InvalidExpressions(t *testing.T) {
	tests := []struct {
		name        string
		expressions []policy.CELExpression
		wantErr     bool
		errContains string
	}{
		{
			name: "empty expressions",
			expressions: []policy.CELExpression{},
			wantErr:     true,
			errContains: "no CEL expressions provided",
		},
		{
			name: "missing name",
			expressions: []policy.CELExpression{
				{Expr: "true"},
			},
			wantErr:     true,
			errContains: "missing name",
		},
		{
			name: "missing expr",
			expressions: []policy.CELExpression{
				{Name: "test"},
			},
			wantErr:     true,
			errContains: "missing expr",
		},
		{
			name: "syntax error",
			expressions: []policy.CELExpression{
				{
					Name: "bad-syntax",
					Expr: "input.value ==",
				},
			},
			wantErr:     true,
			errContains: "failed to compile",
		},
		{
			name: "non-boolean return type",
			expressions: []policy.CELExpression{
				{
					Name: "returns-int",
					Expr: "42",
				},
			},
			wantErr:     true,
			errContains: "must return boolean",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := policy.NewCELEvaluator(tt.expressions)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCELEvaluator() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("Error message = %v, should contain %v", err.Error(), tt.errContains)
				}
			}
		})
	}
}

func TestEngine_Evaluate_CEL(t *testing.T) {
	tests := []struct {
		name          string
		config        *policy.Config
		evidence      *evidence.Evidence
		wantPassed    bool
		wantViolCount int
	}{
		{
			name: "CEL: no critical vulnerabilities - pass",
			config: &policy.Config{
				Version: "v1",
				Custom: &policy.CustomPolicy{
					CELEnabled: true,
					CELExpressions: []policy.CELExpression{
						{
							Name:    "no-critical",
							Expr:    "input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0",
							Message: "Critical vulnerabilities found",
						},
					},
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				SBOM: &sbom.SBOM{
					Format:   sbom.FormatCycloneDXJSON,
					Checksum: "sha256:test",
					Content:  []byte(`{}`),
				},
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: []scanner.Vulnerability{
						{ID: "CVE-1", Severity: scanner.SeverityHigh},
						{ID: "CVE-2", Severity: scanner.SeverityMedium},
					},
					ScannedAt: time.Now(),
				},
			},
			wantPassed:    true,
			wantViolCount: 0,
		},
		{
			name: "CEL: has critical vulnerabilities - fail",
			config: &policy.Config{
				Version: "v1",
				Custom: &policy.CustomPolicy{
					CELEnabled: true,
					CELExpressions: []policy.CELExpression{
						{
							Name:    "no-critical",
							Expr:    "input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0",
							Message: "Critical vulnerabilities found",
						},
					},
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				SBOM: &sbom.SBOM{
					Format:   sbom.FormatCycloneDXJSON,
					Checksum: "sha256:test",
					Content:  []byte(`{}`),
				},
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: []scanner.Vulnerability{
						{ID: "CVE-1", Severity: scanner.SeverityCritical},
						{ID: "CVE-2", Severity: scanner.SeverityHigh},
					},
					ScannedAt: time.Now(),
				},
			},
			wantPassed:    false,
			wantViolCount: 1,
		},
		{
			name: "CEL: multiple expressions - all pass",
			config: &policy.Config{
				Version: "v1",
				Custom: &policy.CustomPolicy{
					CELEnabled: true,
					CELExpressions: []policy.CELExpression{
						{
							Name:    "no-critical",
							Expr:    "input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0",
							Message: "Critical vulnerabilities found",
						},
						{
							Name:    "max-5-high",
							Expr:    "input.vulnerabilities.filter(v, v.severity == 'High').size() <= 5",
							Message: "Too many high vulnerabilities",
						},
					},
				},
			},
			evidence: &evidence.Evidence{
				Artifact: "test:latest",
				SBOM: &sbom.SBOM{
					Format:   sbom.FormatCycloneDXJSON,
					Checksum: "sha256:test",
					Content:  []byte(`{}`),
				},
				VulnerabilityReport: &scanner.Report{
					Vulnerabilities: []scanner.Vulnerability{
						{ID: "CVE-1", Severity: scanner.SeverityHigh},
						{ID: "CVE-2", Severity: scanner.SeverityMedium},
					},
					ScannedAt: time.Now(),
				},
			},
			wantPassed:    true,
			wantViolCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := policy.NewEngine(tt.config)
			ctx := context.Background()

			result, err := engine.Evaluate(ctx, tt.evidence)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Passed != tt.wantPassed {
				t.Errorf("Evaluate() passed = %v, want %v", result.Passed, tt.wantPassed)
			}

			if len(result.Violations) != tt.wantViolCount {
				t.Errorf("Evaluate() violations count = %d, want %d", len(result.Violations), tt.wantViolCount)
				for i, v := range result.Violations {
					t.Logf("  Violation %d: %s", i+1, v.Message)
				}
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
