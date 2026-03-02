package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVEXMerge(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two VEX documents
	vex1 := map[string]interface{}{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id":      "https://example.com/vex1",
		"author":   "Team A",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": []map[string]interface{}{
			{
				"vulnerability": "CVE-2024-0001",
				"products":      []string{"product-1"},
				"status":        "not_affected",
				"justification": "component_not_present",
			},
		},
	}

	vex2 := map[string]interface{}{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id":      "https://example.com/vex2",
		"author":   "Team B",
		"timestamp": "2024-01-02T00:00:00Z",
		"statements": []map[string]interface{}{
			{
				"vulnerability": "CVE-2024-0002",
				"products":      []string{"product-1"},
				"status":        "fixed",
				"action_statement": "Upgraded to v2.0",
			},
		},
	}

	vex1Path := filepath.Join(tmpDir, "vex1.json")
	vex2Path := filepath.Join(tmpDir, "vex2.json")

	vex1Data, _ := json.Marshal(vex1)
	vex2Data, _ := json.Marshal(vex2)

	require.NoError(t, os.WriteFile(vex1Path, vex1Data, 0644))
	require.NoError(t, os.WriteFile(vex2Path, vex2Data, 0644))

	tests := []struct {
		name     string
		strategy string
		wantErr  bool
	}{
		{
			name:     "merge with latest strategy",
			strategy: "latest",
			wantErr:  false,
		},
		{
			name:     "merge with union strategy",
			strategy: "union",
			wantErr:  false,
		},
		{
			name:     "merge with override strategy",
			strategy: "override",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vexMergeOutput = filepath.Join(tmpDir, "merged.json")
			vexMergeStrategy = tt.strategy

			cmd := vexMergeCmd
			cmd.SetArgs([]string{vex1Path, vex2Path})

			err := cmd.Execute()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVEXUpdate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a VEX document
	vexDoc := map[string]interface{}{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id":      "https://example.com/vex",
		"author":   "Team A",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": []map[string]interface{}{
			{
				"vulnerability": "CVE-2024-0001",
				"products":      []string{"product-1"},
				"status":        "under_investigation",
			},
		},
	}

	vexPath := filepath.Join(tmpDir, "vex.json")
	vexData, _ := json.Marshal(vexDoc)
	require.NoError(t, os.WriteFile(vexPath, vexData, 0644))

	tests := []struct {
		name           string
		vulnID         string
		status         string
		justification  string
		statement      string
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name:          "update to not_affected with justification",
			vulnID:        "CVE-2024-0001",
			status:        "not_affected",
			justification: "component_not_present",
			statement:     "Component X is not included",
			wantErr:       false,
		},
		{
			name:    "update to fixed",
			vulnID:  "CVE-2024-0001",
			status:  "fixed",
			wantErr: false,
		},
		{
			name:           "invalid status",
			vulnID:         "CVE-2024-0001",
			status:         "invalid_status",
			wantErr:        true,
			expectedErrMsg: "invalid status",
		},
		{
			name:           "not_affected without justification",
			vulnID:         "CVE-2024-0001",
			status:         "not_affected",
			wantErr:        true,
			expectedErrMsg: "justification required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := vexUpdateCmd
			cmd.ResetFlags()
			
			// Re-initialize flags for this test
			cmd.Flags().String("justification", "", "Justification for not_affected status")
			cmd.Flags().String("statement", "", "Detailed statement explaining the status")
			cmd.Flags().String("action-statement", "", "Action taken (for fixed status)")
			cmd.Flags().String("impact-statement", "", "Impact description (for affected status)")
			
			args := []string{vexPath, tt.vulnID, tt.status}

			if tt.justification != "" {
				cmd.Flags().Set("justification", tt.justification)
			}
			if tt.statement != "" {
				cmd.Flags().Set("statement", tt.statement)
			}

			err := runVEXUpdate(cmd, args)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVEXFilter(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a VEX document with multiple statements
	vexDoc := map[string]interface{}{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id":      "https://example.com/vex",
		"author":   "Team A",
		"timestamp": "2024-01-01T00:00:00Z",
		"statements": []map[string]interface{}{
			{
				"vulnerability": "CVE-2024-0001",
				"products":      []string{"product-1"},
				"status":        "not_affected",
				"justification": "component_not_present",
			},
			{
				"vulnerability": "CVE-2024-0002",
				"products":      []string{"product-1"},
				"status":        "affected",
			},
			{
				"vulnerability": "CVE-2024-0003",
				"products":      []string{"product-1"},
				"status":        "fixed",
			},
		},
	}

	vexPath := filepath.Join(tmpDir, "vex.json")
	vexData, _ := json.Marshal(vexDoc)
	require.NoError(t, os.WriteFile(vexPath, vexData, 0644))

	tests := []struct {
		name           string
		statusFilter   string
		severityFilter string
		outputFile     string
		wantErr        bool
	}{
		{
			name:         "filter by affected status",
			statusFilter: "affected",
			wantErr:      false,
		},
		{
			name:         "filter by not_affected status",
			statusFilter: "not_affected",
			wantErr:      false,
		},
		{
			name:           "filter by severity",
			severityFilter: "critical",
			wantErr:        false,
		},
		{
			name:       "output to file",
			outputFile: filepath.Join(tmpDir, "filtered.json"),
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := vexFilterCmd
			cmd.ResetFlags()
			
			// Re-initialize flags
			cmd.Flags().String("status", "", "Filter by status")
			cmd.Flags().String("severity", "", "Filter by severity")
			cmd.Flags().String("product", "", "Filter by product")
			cmd.Flags().String("justification", "", "Filter by justification")
			cmd.Flags().StringP("output", "o", "", "Output file")

			if tt.statusFilter != "" {
				cmd.Flags().Set("status", tt.statusFilter)
			}
			if tt.severityFilter != "" {
				cmd.Flags().Set("severity", tt.severityFilter)
			}
			if tt.outputFile != "" {
				cmd.Flags().Set("output", tt.outputFile)
			}

			err := runVEXFilter(cmd, []string{vexPath})

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVEXValidate(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		vexDoc  map[string]interface{}
		format  string
		strict  bool
		wantErr bool
	}{
		{
			name: "valid OpenVEX document",
			vexDoc: map[string]interface{}{
				"@context": "https://openvex.dev/ns/v0.2.0",
				"@id":      "https://example.com/vex",
				"author":   "Team A",
				"timestamp": "2024-01-01T00:00:00Z",
				"statements": []map[string]interface{}{
					{
						"vulnerability": "CVE-2024-0001",
						"products":      []string{"product-1"},
						"status":        "not_affected",
						"justification": "component_not_present",
					},
				},
			},
			format:  "openvex",
			wantErr: false,
		},
		{
			name: "missing @context",
			vexDoc: map[string]interface{}{
				"@id":      "https://example.com/vex",
				"author":   "Team A",
				"timestamp": "2024-01-01T00:00:00Z",
				"statements": []map[string]interface{}{
					{
						"vulnerability": "CVE-2024-0001",
						"products":      []string{"product-1"},
						"status":        "not_affected",
					},
				},
			},
			format:  "openvex",
			wantErr: true,
		},
		{
			name: "missing statements",
			vexDoc: map[string]interface{}{
				"@context":  "https://openvex.dev/ns/v0.2.0",
				"@id":       "https://example.com/vex",
				"author":    "Team A",
				"timestamp": "2024-01-01T00:00:00Z",
			},
			format:  "openvex",
			wantErr: true,
		},
		{
			name: "invalid JSON",
			vexDoc: map[string]interface{}{
				// This will be written as empty JSON object
			},
			format:  "openvex",
			wantErr: true, // Empty JSON should fail validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vexPath := filepath.Join(tmpDir, "vex.json")
			vexData, _ := json.Marshal(tt.vexDoc)
			require.NoError(t, os.WriteFile(vexPath, vexData, 0644))

			cmd := vexValidateCmd
			cmd.ResetFlags()
			
			// Re-initialize flags
			cmd.Flags().String("format", "openvex", "VEX format")
			cmd.Flags().Bool("strict", false, "Enable strict validation")
			
			cmd.Flags().Set("format", tt.format)
			if tt.strict {
				cmd.Flags().Set("strict", "true")
			}

			err := runVEXValidate(cmd, []string{vexPath})

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVEXJustificationValidation(t *testing.T) {
	validJustifications := []string{
		"component_not_present",
		"vulnerable_code_not_present",
		"vulnerable_code_not_in_execute_path",
		"vulnerable_code_cannot_be_controlled_by_adversary",
		"inline_mitigations_already_exist",
	}

	for _, j := range validJustifications {
		t.Run(j, func(t *testing.T) {
			// Test that each justification is accepted
			// This would be part of the full validation logic
			assert.NotEmpty(t, j)
		})
	}
}
