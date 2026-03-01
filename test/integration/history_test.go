package integration

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHistoryCommand(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	// Build provenix binary
	buildCmd := exec.Command("go", "build", "-o", "provenix-test", "./cmd/provenix")
	buildCmd.Dir = "../.."
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build provenix: %v", err)
	}
	defer os.Remove("../../provenix-test")

	// Create test directory structure
	tmpDir := t.TempDir()
	attestationsDir := filepath.Join(tmpDir, ".provenix", "attestations")
	if err := os.MkdirAll(attestationsDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create test attestations
	createTestAttestation(t, attestationsDir, "nginx:latest", "abc123def456789012345678", false)
	createTestAttestation(t, attestationsDir, "alpine:latest", "def456abc789012345678901", true)

	// Change to test directory
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

	tests := []struct {
		name           string
		args           []string
		expectError    bool
		expectContains []string
	}{
		{
			name:           "List all local attestations",
			args:           []string{"history", "--local-only", "--unpublished"},
			expectError:    false,
			expectContains: []string{"nginx:latest", "alpine:latest", "Found 2 attestation(s)"},
		},
		{
			name:           "List only published",
			args:           []string{"history", "--local-only"},
			expectError:    false,
			expectContains: []string{"alpine:latest", "Found 1 attestation(s)"},
		},
		{
			name:           "Filter by artifact name",
			args:           []string{"history", "alpine", "--local-only"},
			expectError:    false,
			expectContains: []string{"alpine:latest"},
		},
		{
			name:           "JSON output",
			args:           []string{"history", "--local-only", "--format", "json", "--unpublished"},
			expectError:    false,
			expectContains: []string{`"artifact"`, `"digest_sha256"`, `"timestamp"`},
		},
		{
			name:           "Markdown output",
			args:           []string{"history", "--local-only", "--format", "markdown", "--unpublished"},
			expectError:    false,
			expectContains: []string{"# Attestation History", "| Artifact |"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdArgs := append([]string{filepath.Join(originalWd, "../../provenix-test")}, tt.args...)
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			cmd.Dir = tmpDir

			output, err := cmd.CombinedOutput()
			if (err != nil) != tt.expectError {
				t.Errorf("Command error = %v, expectError %v\nOutput:\n%s", err, tt.expectError, output)
				return
			}

			outputStr := string(output)
			for _, expected := range tt.expectContains {
				if !strings.Contains(outputStr, expected) {
					t.Errorf("Output does not contain %q\nOutput:\n%s", expected, outputStr)
				}
			}
		})
	}
}

func createTestAttestation(t *testing.T, dir, artifact, digest string, published bool) {
	t.Helper()

	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []interface{}{
			map[string]interface{}{
				"name": artifact,
				"digest": map[string]interface{}{
					"sha256": digest,
				},
			},
		},
		"predicateType": "https://provenix.dev/attestation/v1",
		"predicate": map[string]interface{}{
			"metadata": map[string]interface{}{
				"generatedAt": time.Now().Format(time.RFC3339),
			},
		},
	}

	statementJSON, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	attestation := map[string]interface{}{
		"statementBase64": base64.StdEncoding.EncodeToString(statementJSON),
		"signature":       "test-signature",
		"publicKey":       "test-public-key",
	}

	if published {
		attestation["rekorUUID"] = "test-uuid-" + digest[:8]
	}

	attestationJSON, err := json.Marshal(attestation)
	if err != nil {
		t.Fatalf("Failed to marshal attestation: %v", err)
	}

	filename := filepath.Join(dir, "sha256-"+digest[:12]+".json")
	if err := os.WriteFile(filename, attestationJSON, 0644); err != nil {
		t.Fatalf("Failed to write attestation: %v", err)
	}
}
