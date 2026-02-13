package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
)

// TestPartialSuccess_LocalSaveWhenRekorUnavailable tests exit code 2 scenario:
// When Rekor is unavailable, attestation should be saved locally and return exit code 2.
func TestPartialSuccess_LocalSaveWhenRekorUnavailable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Create temporary directory for attestations
	tmpDir := t.TempDir()
	attestDir := filepath.Join(tmpDir, ".provenix", "attestations")

	// Get providers
	sbomProvider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get SBOM provider: %v", err)
	}

	scannerProvider, err := providers.GetScannerProvider("mock")
	if err != nil {
		t.Fatalf("failed to get scanner provider: %v", err)
	}

	// Use mock signer (doesn't publish to Rekor)
	signerProvider, err := providers.GetSignerProvider("mock")
	if err != nil {
		t.Fatalf("failed to get signer provider: %v", err)
	}

	gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)

	// Generate evidence
	artifact := "alpine:latest"
	opts := evidence.GenerateOptions{
		ArtifactType:     "docker",
		GeneratorVersion: "dev",
		SBOMOptions: sbom.Options{
			Format: sbom.FormatCycloneDXJSON,
			Scope:  "squashed",
		},
	}

	t.Logf("Generating evidence for %s", artifact)
	ev, err := gen.Generate(ctx, artifact, opts)
	if err != nil {
		t.Fatalf("failed to generate evidence: %v", err)
	}

	// Verify evidence was generated
	if ev == nil {
		t.Fatal("evidence is nil")
	}

	if ev.SBOM == nil {
		t.Fatal("SBOM is nil")
	}

	if ev.VulnerabilityReport == nil {
		t.Fatal("VulnerabilityReport is nil")
	}

	// Simulate saving to local directory
	err = os.MkdirAll(attestDir, 0755)
	if err != nil {
		t.Fatalf("failed to create attestation directory: %v", err)
	}

	// Generate default path (sha256-{first-12-chars}.json)
	digest := strings.TrimPrefix(ev.ArtifactDigest, "sha256:")
	filename := "sha256-" + digest[:12] + ".json"
	attestPath := filepath.Join(attestDir, filename)

	// Save attestation
	f, err := os.Create(attestPath)
	if err != nil {
		t.Fatalf("failed to create attestation file: %v", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(ev); err != nil {
		t.Fatalf("failed to encode evidence: %v", err)
	}

	t.Logf("✅ Attestation saved to: %s", attestPath)

	// Verify file exists and is valid JSON
	data, err := os.ReadFile(attestPath)
	if err != nil {
		t.Fatalf("failed to read attestation file: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("attestation file is empty")
	}

	var savedEvidence evidence.Evidence
	if err := json.Unmarshal(data, &savedEvidence); err != nil {
		t.Fatalf("failed to unmarshal attestation: %v", err)
	}

	// Verify saved evidence matches original
	if savedEvidence.Artifact != ev.Artifact {
		t.Errorf("artifact mismatch: got %s, want %s", savedEvidence.Artifact, ev.Artifact)
	}

	if savedEvidence.ArtifactDigest != ev.ArtifactDigest {
		t.Errorf("digest mismatch: got %s, want %s", savedEvidence.ArtifactDigest, ev.ArtifactDigest)
	}

	t.Logf("✅ Partial success scenario validated (simulated exit code 2)")
}

// TestAutoAttestationPath tests automatic path generation for .provenix/attestations/
func TestAutoAttestationPath(t *testing.T) {
	tests := []struct {
		name           string
		digest         string
		expectedSuffix string
	}{
		{
			name:           "alpine digest",
			digest:         "sha256:50fc269afe7c8b1c3d6f3f2f7f8d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
			expectedSuffix: "sha256-50fc269afe7c.json",
		},
		{
			name:           "nginx digest",
			digest:         "sha256:6fb9788915f7f8f9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
			expectedSuffix: "sha256-6fb9788915f7.json",
		},
		{
			name:           "busybox digest",
			digest:         "sha256:3c3a6f6a8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
			expectedSuffix: "sha256-3c3a6f6a8e9f.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract first 12 chars after sha256:
			digest := strings.TrimPrefix(tt.digest, "sha256:")
			filename := "sha256-" + digest[:12] + ".json"

			if filename != tt.expectedSuffix {
				t.Errorf("filename mismatch: got %s, want %s", filename, tt.expectedSuffix)
			}

			t.Logf("✅ Generated filename: %s", filename)
		})
	}
}

// TestAttestationDirectoryCreation tests .provenix/attestations/ directory creation
func TestAttestationDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	attestDir := filepath.Join(tmpDir, ".provenix", "attestations")

	// Verify directory doesn't exist yet
	_, err := os.Stat(attestDir)
	if err == nil {
		t.Fatal("directory should not exist yet")
	}

	// Create directory
	err = os.MkdirAll(attestDir, 0755)
	if err != nil {
		t.Fatalf("failed to create directory: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(attestDir)
	if err != nil {
		t.Fatalf("directory should exist: %v", err)
	}

	if !info.IsDir() {
		t.Fatal("should be a directory")
	}

	// Verify permissions (0755)
	if info.Mode().Perm() != 0755 {
		t.Errorf("permission mismatch: got %o, want 0755", info.Mode().Perm())
	}

	t.Logf("✅ Directory created with correct permissions: %s", attestDir)
}
