package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers/signer"
)

// TestSyftWithMockProviders validates that real Syft SBOM generation integrates
// correctly with mock scanning and signing providers.
//
// This test:
// - Uses real Syft provider for SBOM generation
// - Uses mock Grype provider for vulnerability scanning
// - Uses mock Cosign provider for signing
// - Validates end-to-end integration without hitting external services
func TestSyftWithMockProviders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get registered providers
	sbomProvider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get SBOM provider: %v", err)
	}

	scannerProvider, err := providers.GetScannerProvider("mock")
	if err != nil {
		t.Fatalf("failed to get scanner provider: %v", err)
	}

	signerProvider, err := providers.GetSignerProvider("mock")
	if err != nil {
		t.Fatalf("failed to get signer provider: %v", err)
	}

	// Create generator with real Syft + mock scan/sign
	gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)

	// Generate evidence for a real artifact (Alpine Linux image reference)
	artifactRef := "alpine:latest"
	opts := evidence.GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.FormatCycloneDXJSON,
		},
		ScanOptions: scanner.Options{},
		SignOptions: signer.Options{
			Mode:             signer.ModeKeyless,
			SkipTransparency: true, // Skip Rekor for tests
		},
		GeneratorVersion: "test-1.0.0",
	}

	ev, err := gen.Generate(ctx, artifactRef, opts)
	if err != nil {
		t.Fatalf("failed to generate evidence: %v", err)
	}

	// Validate evidence structure
	if ev == nil {
		t.Fatal("evidence is nil")
	}

	if ev.Artifact != artifactRef {
		t.Errorf("artifact mismatch: got %q, want %q", ev.Artifact, artifactRef)
	}

	if ev.ArtifactDigest == "" {
		t.Error("artifact digest is empty")
	}

	if ev.SBOM == nil {
		t.Error("SBOM is nil")
	}

	if ev.VulnerabilityReport == nil {
		t.Error("vulnerability report is nil")
	}

	if len(ev.Statement) == 0 {
		t.Error("statement is empty")
	}

	if ev.Signature == nil {
		t.Error("signature is nil")
	}

	if ev.Metadata == nil {
		t.Error("metadata is nil")
	}

	// Validate SBOM format
	if ev.SBOM.Format != sbom.FormatCycloneDXJSON {
		t.Errorf("SBOM format mismatch: got %s, want %s", ev.SBOM.Format, sbom.FormatCycloneDXJSON)
	}

	// Validate metadata
	if ev.Metadata.GeneratorVersion != opts.GeneratorVersion {
		t.Errorf("generator version mismatch: got %q, want %q", ev.Metadata.GeneratorVersion, opts.GeneratorVersion)
	}

	if ev.Metadata.SBOMProvider.Name != "syft" {
		t.Errorf("SBOM provider mismatch: got %q, want %q", ev.Metadata.SBOMProvider.Name, "syft")
	}

	if ev.Metadata.ScannerProvider.Name != "mock" {
		t.Errorf("scanner provider mismatch: got %q, want %q", ev.Metadata.ScannerProvider.Name, "mock")
	}

	if ev.Metadata.SignerProvider.Name != "mock" {
		t.Errorf("signer provider mismatch: got %q, want %q", ev.Metadata.SignerProvider.Name, "mock")
	}

	// Validate statement is valid JSON
	var stmt map[string]interface{}
	if err := json.Unmarshal(ev.Statement, &stmt); err != nil {
		t.Fatalf("statement is not valid JSON: %v", err)
	}

	t.Logf("✓ Evidence generation successful with real Syft + mock providers")
	t.Logf("  Artifact: %s", ev.Artifact)
	t.Logf("  Digest: %s", ev.ArtifactDigest)
	t.Logf("  SBOM Format: %s", ev.SBOM.Format)
	t.Logf("  Vulnerabilities: %d", len(ev.VulnerabilityReport.Vulnerabilities))
	t.Logf("  Generated: %s", ev.Metadata.GeneratedAt.String())
}

// TestProviderInteroperability validates that providers can be swapped without
// affecting evidence generation correctness.
//
// This test generates evidence with different provider combinations and verifies
// that the evidence structure is always valid.
func TestProviderInteroperability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tests := []struct {
		name       string
		sbomFormat sbom.Format
	}{
		{
			name:       "SBOM_SPDX",
			sbomFormat: sbom.FormatSPDXJSON,
		},
		{
			name:       "SBOM_CycloneDX",
			sbomFormat: sbom.FormatCycloneDXJSON,
		},
		{
			name:       "SBOM_SyftJSON",
			sbomFormat: sbom.FormatSyftJSON,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbomProvider, err := providers.GetSBOMProvider("syft")
			if err != nil {
				t.Fatalf("failed to get SBOM provider: %v", err)
			}

			scannerProvider, err := providers.GetScannerProvider("mock")
			if err != nil {
				t.Fatalf("failed to get scanner provider: %v", err)
			}

			signerProvider, err := providers.GetSignerProvider("mock")
			if err != nil {
				t.Fatalf("failed to get signer provider: %v", err)
			}

			gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)

			opts := evidence.GenerateOptions{
				SBOMOptions: sbom.Options{
					Format: tt.sbomFormat,
				},
				ScanOptions: scanner.Options{},
				SignOptions: signer.Options{
					Mode:             signer.ModeKeyless,
					SkipTransparency: true,
				},
				GeneratorVersion: "test-1.0.0",
			}

			ev, err := gen.Generate(ctx, "alpine:latest", opts)
			if err != nil {
				t.Fatalf("failed to generate evidence: %v", err)
			}

			// Validate evidence integrity
			if err := ev.Validate(); err != nil {
				t.Errorf("invalid evidence: %v", err)
			}

		if ev.SBOM.Format != tt.sbomFormat {
			t.Errorf("SBOM format mismatch: got %s, want %s", ev.SBOM.Format, tt.sbomFormat)
		}

			t.Logf("✓ Provider interoperability test passed for %s", tt.name)
		})
	}
}

// TestEvidenceSerialization validates that evidence can be serialized to JSON
// and deserialized without loss of information.
//
// This test:
// - Generates evidence
// - Marshals it to JSON
// - Unmarshals it back
// - Validates the result matches the original
func TestEvidenceSerialization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	sbomProvider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get SBOM provider: %v", err)
	}

	scannerProvider, err := providers.GetScannerProvider("mock")
	if err != nil {
		t.Fatalf("failed to get scanner provider: %v", err)
	}

	signerProvider, err := providers.GetSignerProvider("mock")
	if err != nil {
		t.Fatalf("failed to get signer provider: %v", err)
	}

	gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)

	opts := evidence.GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.FormatCycloneDXJSON,
		},
		ScanOptions: scanner.Options{},
		SignOptions: signer.Options{
			Mode:             signer.ModeKeyless,
			SkipTransparency: true,
		},
		GeneratorVersion: "test-1.0.0",
	}

	// Generate evidence
	original, err := gen.Generate(ctx, "alpine:latest", opts)
	if err != nil {
		t.Fatalf("failed to generate evidence: %v", err)
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal evidence: %v", err)
	}

	// Unmarshal back
	deserialized := &evidence.Evidence{}
	if err := json.Unmarshal(jsonData, deserialized); err != nil {
		t.Fatalf("failed to unmarshal evidence: %v", err)
	}

	// Validate critical fields match
	if deserialized.Artifact != original.Artifact {
		t.Errorf("artifact mismatch after deserialization")
	}

	if deserialized.ArtifactDigest != original.ArtifactDigest {
		t.Errorf("artifact digest mismatch after deserialization")
	}

	if string(deserialized.Statement) != string(original.Statement) {
		t.Errorf("statement mismatch after deserialization")
	}

	if deserialized.Metadata.GeneratorVersion != original.Metadata.GeneratorVersion {
		t.Errorf("generator version mismatch after deserialization")
	}

	t.Logf("✓ Evidence serialization successful (%d bytes)", len(jsonData))
}
