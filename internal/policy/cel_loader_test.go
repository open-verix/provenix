package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseCELFile(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantCount   int
		wantNames   []string
		wantExprs   []string
		wantErr     bool
	}{
		{
			name: "single line expressions",
			content: `# Security policy
no_critical = vulnerabilities.critical == 0
max_high = vulnerabilities.high <= 5
`,
			wantCount: 2,
			wantNames: []string{"no_critical", "max_high"},
			wantExprs: []string{"vulnerabilities.critical == 0", "vulnerabilities.high <= 5"},
			wantErr:   false,
		},
		{
			name: "multi-line expression with backslash",
			content: `allow = vulnerabilities.critical == 0 && \
            vulnerabilities.high <= 5 && \
            vulnerabilities.medium <= 20
`,
			wantCount: 1,
			wantNames: []string{"allow"},
			// Note: leading whitespace from continuation lines is preserved
			wantExprs: []string{"vulnerabilities.critical == 0 && vulnerabilities.high <= 5 &&  vulnerabilities.medium <= 20"},
			wantErr:   false,
		},
		{
			name: "mixed single and multi-line",
			content: `no_critical = vulnerabilities.critical == 0

complex = vulnerabilities.critical == 0 && \
          vulnerabilities.high <= 10

simple = true
`,
			wantCount: 3,
			wantNames: []string{"no_critical", "complex", "simple"},
			wantErr:   false,
		},
		{
			name: "comments and empty lines",
			content: `# This is a comment

# Another comment
expr1 = true

# Inline expression
expr2 = false  # trailing comment is not supported yet but line is valid
`,
			wantCount: 2,
			wantNames: []string{"expr1", "expr2"},
			wantErr:   false,
		},
		{
			name: "invalid syntax - missing equals",
			content: `no_critical vulnerabilities.critical == 0
`,
			wantErr: true,
		},
		{
			name: "valid expression with spaces in name area",
			content: `no_critical_123 = vulnerabilities.critical == 0
`,
			wantCount: 1,
			wantNames: []string{"no_critical_123"},
			wantErr:   false,
		},
		{
			name: "invalid syntax - empty name",
			content: `= vulnerabilities.critical == 0
`,
			wantErr: true,
		},
		{
			name: "unclosed multi-line expression",
			content: `expr = first_part && \
            second_part && \
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpfile, err := os.CreateTemp("", "test-*.cel")
			if err != nil {
				t.Fatal(err)
			}
			defer os.Remove(tmpfile.Name())

			if _, err := tmpfile.Write([]byte(tt.content)); err != nil {
				t.Fatal(err)
			}
			if err := tmpfile.Close(); err != nil {
				t.Fatal(err)
			}

			// Parse file
			expressions, err := parseCELFile(tmpfile.Name())

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCELFile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseCELFile() error = %v", err)
			}

			if len(expressions) != tt.wantCount {
				t.Errorf("parseCELFile() got %d expressions, want %d", len(expressions), tt.wantCount)
			}

			for i, wantName := range tt.wantNames {
				if i >= len(expressions) {
					break
				}
				if expressions[i].Name != wantName {
					t.Errorf("expression[%d].Name = %q, want %q", i, expressions[i].Name, wantName)
				}
			}

			for i, wantExpr := range tt.wantExprs {
				if i >= len(expressions) {
					break
				}
				if expressions[i].Expr != wantExpr {
					t.Errorf("expression[%d].Expr = %q, want %q", i, expressions[i].Expr, wantExpr)
				}
			}
		})
	}
}

func TestLoadCELPolicyFiles(t *testing.T) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "cel-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	file1 := filepath.Join(tmpDir, "security.cel")
	file1Content := `# Security policy
no_critical = vulnerabilities.critical == 0
max_high = vulnerabilities.high <= 5
`
	if err := os.WriteFile(file1, []byte(file1Content), 0644); err != nil {
		t.Fatal(err)
	}

	file2 := filepath.Join(tmpDir, "compliance.cel")
	file2Content := `# Compliance policy
has_sbom = sbom.components.size() > 0
signed = signature != ""
`
	if err := os.WriteFile(file2, []byte(file2Content), 0644); err != nil {
		t.Fatal(err)
	}

	t.Run("load multiple files", func(t *testing.T) {
		expressions, err := LoadCELPolicyFiles([]string{file1, file2})
		if err != nil {
			t.Fatalf("LoadCELPolicyFiles() error = %v", err)
		}

		if len(expressions) != 4 {
			t.Errorf("LoadCELPolicyFiles() got %d expressions, want 4", len(expressions))
		}

		wantNames := []string{"no_critical", "max_high", "has_sbom", "signed"}
		for i, wantName := range wantNames {
			if expressions[i].Name != wantName {
				t.Errorf("expression[%d].Name = %q, want %q", i, expressions[i].Name, wantName)
			}
		}
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadCELPolicyFiles([]string{filepath.Join(tmpDir, "nonexistent.cel")})
		if err == nil {
			t.Error("LoadCELPolicyFiles() expected error for non-existent file, got nil")
		}
	})
}

func TestFilterExpressionsByName(t *testing.T) {
	expressions := []CELExpression{
		{Name: "expr1", Expr: "true"},
		{Name: "expr2", Expr: "false"},
		{Name: "allow", Expr: "expr1 && expr2"},
	}

	t.Run("filter by entry point", func(t *testing.T) {
		filtered := FilterExpressionsByName(expressions, "allow")
		if len(filtered) != 1 {
			t.Errorf("FilterExpressionsByName() got %d expressions, want 1", len(filtered))
		}
		if filtered[0].Name != "allow" {
			t.Errorf("FilterExpressionsByName() got name %q, want 'allow'", filtered[0].Name)
		}
	})

	t.Run("empty entry point returns all", func(t *testing.T) {
		filtered := FilterExpressionsByName(expressions, "")
		if len(filtered) != 3 {
			t.Errorf("FilterExpressionsByName() got %d expressions, want 3", len(filtered))
		}
	})

	t.Run("non-existent entry point returns empty", func(t *testing.T) {
		filtered := FilterExpressionsByName(expressions, "nonexistent")
		if len(filtered) != 0 {
			t.Errorf("FilterExpressionsByName() got %d expressions, want 0", len(filtered))
		}
	})
}
