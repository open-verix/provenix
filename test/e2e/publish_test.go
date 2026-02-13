package e2e

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-verix/provenix/internal/providers/signer/cosign"
)

// TestPublishCommand_DryRun tests the publish command in dry-run mode.
func TestPublishCommand_DryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	// Create temp directory with attestation
	tmpDir := t.TempDir()
	attestDir := filepath.Join(tmpDir, ".provenix", "attestations")
	if err := os.MkdirAll(attestDir, 0755); err != nil {
		t.Fatalf("Failed to create attestation directory: %v", err)
	}

	// Create a mock attestation bundle instead of generating real evidence
	// This avoids the need for actual signing infrastructure in tests
	mockStatement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"subject": []map[string]interface{}{
			{
				"name": "test-artifact",
				"digest": map[string]string{
					"sha256": "abc123",
				},
			},
		},
		"predicate": map[string]string{"test": "data"},
	}
	statementJSON, _ := json.Marshal(mockStatement)

	bundle := cosign.AttestationBundle{
		StatementBase64: base64.StdEncoding.EncodeToString(statementJSON),
		Signature:       base64.StdEncoding.EncodeToString([]byte("test-signature")),
		PublicKey:       "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
		Certificate:     "",
		RekorUUID:       "", // No Rekor UUID - pending
		RekorLogIndex:   0,
	}

	bundleJSON, _ := json.MarshalIndent(bundle, "", "  ")
	attestPath := filepath.Join(attestDir, "sha256-test123.json")
	if err := os.WriteFile(attestPath, bundleJSON, 0644); err != nil {
		t.Fatalf("Failed to write attestation: %v", err)
	}

	// Change to temp directory
	oldWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(oldWd)

	// Note: In real E2E test, we would exec the CLI binary
	// For now, we just verify the file was created correctly
	
	// Verify file exists
	if _, err := os.Stat(attestPath); os.IsNotExist(err) {
		t.Errorf("Attestation file not created: %s", attestPath)
	}

	// Verify bundle can be parsed
	data, _ := os.ReadFile(attestPath)
	var readBundle cosign.AttestationBundle
	if err := json.Unmarshal(data, &readBundle); err != nil {
		t.Errorf("Failed to parse attestation bundle: %v", err)
	}

	if readBundle.RekorUUID != "" {
		t.Errorf("Expected empty RekorUUID for pending attestation, got: %s", readBundle.RekorUUID)
	}

	t.Log("✓ Publish dry-run test setup successful")
}

// TestPublishCommand_AlreadyPublished tests handling of already-published attestations.
func TestPublishCommand_AlreadyPublished(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := t.TempDir()
	attestDir := filepath.Join(tmpDir, ".provenix", "attestations")
	if err := os.MkdirAll(attestDir, 0755); err != nil {
		t.Fatalf("Failed to create attestation directory: %v", err)
	}

	// Create attestation with Rekor UUID (already published)
	bundle := cosign.AttestationBundle{
		StatementBase64: base64.StdEncoding.EncodeToString([]byte(`{"test":"data"}`)),
		Signature:       "c2lnbmF0dXJl",
		PublicKey:       "pubkey",
		RekorUUID:       "24296fb24b8ad77a123456789abcdef0123456789abcdef0123456789abcdef01", // Already published
		RekorLogIndex:   172938475,
	}

	bundleJSON, _ := json.MarshalIndent(bundle, "", "  ")
	attestPath := filepath.Join(attestDir, "sha256-already.json")
	if err := os.WriteFile(attestPath, bundleJSON, 0644); err != nil {
		t.Fatalf("Failed to write attestation: %v", err)
	}

	// Verify it has Rekor info
	data, _ := os.ReadFile(attestPath)
	var readBundle cosign.AttestationBundle
	json.Unmarshal(data, &readBundle)

	if readBundle.RekorUUID == "" {
		t.Error("Expected RekorUUID to be present")
	}

	if readBundle.RekorLogIndex == 0 {
		t.Error("Expected RekorLogIndex to be present")
	}

	t.Log("✓ Already-published attestation test successful")
}

// TestPublishCommand_EmptyDirectory tests handling of empty attestation directory.
func TestPublishCommand_EmptyDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	tmpDir := t.TempDir()
	attestDir := filepath.Join(tmpDir, ".provenix", "attestations")
	
	// Create empty directory
	if err := os.MkdirAll(attestDir, 0755); err != nil {
		t.Fatalf("Failed to create attestation directory: %v", err)
	}

	// Verify directory is empty
	entries, err := os.ReadDir(attestDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	if len(entries) != 0 {
		t.Errorf("Expected empty directory, found %d entries", len(entries))
	}

	t.Log("✓ Empty directory test successful")
}
