package e2e

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

// TestFullAttestationPipeline tests the complete atomic evidence generation:
// SBOM → Scan → Sign → Verify
// This is the core E2E test validating the Atomic Evidence Model.
func TestFullAttestationPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Get all providers
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

	// Create generator
	gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)

	// Step 1: Generate evidence (SBOM + Scan + Sign atomically)
	t.Log("Step 1: Generating atomic evidence...")
	startTime := time.Now()

	opts := evidence.GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.FormatCycloneDXJSON,
		},
		ScanOptions: scanner.Options{},
		SignOptions: signer.Options{
			Mode:             signer.ModeKeyless,
			SkipTransparency: true,
		},
		GeneratorVersion: "test-e2e-1.0.0",
	}

	ev, err := gen.Generate(ctx, "alpine:latest", opts)
	if err != nil {
		t.Fatalf("failed to generate evidence: %v", err)
	}

	duration := time.Since(startTime)
	t.Logf("✓ Evidence generated in %v", duration)

	// Step 2: Validate evidence structure
	t.Log("Step 2: Validating evidence structure...")

	if ev.Artifact != "alpine:latest" {
		t.Errorf("artifact mismatch: got %q", ev.Artifact)
	}

	if ev.ArtifactDigest == "" {
		t.Error("artifact digest is empty")
	}

	if ev.SBOM == nil {
		t.Fatal("SBOM is nil")
	}

	if ev.VulnerabilityReport == nil {
		t.Fatal("vulnerability report is nil")
	}

	if len(ev.Statement) == 0 {
		t.Fatal("statement is empty")
	}

	if ev.Signature == nil {
		t.Fatal("signature is nil")
	}

	if ev.Metadata == nil {
		t.Fatal("metadata is nil")
	}

	// Validate statement is valid JSON
	var stmt map[string]interface{}
	if err := json.Unmarshal(ev.Statement, &stmt); err != nil {
		t.Fatalf("statement is not valid JSON: %v", err)
	}

	t.Logf("✓ Evidence structure valid")
	t.Logf("  - Artifact: %s", ev.Artifact)
	t.Logf("  - Digest: %s", ev.ArtifactDigest)
	t.Logf("  - SBOM Format: %s", ev.SBOM.Format)
	t.Logf("  - Vulnerabilities: %d", len(ev.VulnerabilityReport.Vulnerabilities))
	t.Logf("  - Generated: %s", ev.Metadata.GeneratedAt.String())

	// Step 3: Validate atomicity
	t.Log("Step 3: Validating atomic evidence properties...")

	if err := ev.Validate(); err != nil {
		t.Fatalf("evidence validation failed: %v", err)
	}

	// Verify all components are from the same generation
	if ev.Metadata.GeneratorVersion != opts.GeneratorVersion {
		t.Errorf("generator version mismatch")
	}

	if ev.Metadata.SBOMProvider.Name != "syft" {
		t.Errorf("SBOM provider name mismatch")
	}

	t.Logf("✓ Evidence atomicity verified")
}

// TestAtomicEvidenceIntegrity validates that evidence maintains integrity
// through serialization and deserialization.
func TestAtomicEvidenceIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Get providers
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

	// Step 1: Generate evidence
	t.Log("Step 1: Generating evidence...")

	opts := evidence.GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.FormatSPDXJSON,
		},
		ScanOptions: scanner.Options{},
		SignOptions: signer.Options{
			Mode:             signer.ModeKeyless,
			SkipTransparency: true,
		},
		GeneratorVersion: "test-integrity-1.0.0",
	}

	original, err := gen.Generate(ctx, "nginx:latest", opts)
	if err != nil {
		t.Fatalf("failed to generate evidence: %v", err)
	}

	t.Logf("✓ Evidence generated")

	// Step 2: Serialize to JSON
	t.Log("Step 2: Serializing evidence to JSON...")

	jsonData, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal evidence: %v", err)
	}

	t.Logf("✓ Serialized: %d bytes", len(jsonData))

	// Step 3: Deserialize back
	t.Log("Step 3: Deserializing evidence...")

	deserialized := &evidence.Evidence{}
	if err := json.Unmarshal(jsonData, deserialized); err != nil {
		t.Fatalf("failed to unmarshal evidence: %v", err)
	}

	t.Logf("✓ Deserialized successfully")

	// Step 4: Verify integrity
	t.Log("Step 4: Verifying integrity...")

	if deserialized.Artifact != original.Artifact {
		t.Error("artifact mismatch after round-trip")
	}

	if deserialized.ArtifactDigest != original.ArtifactDigest {
		t.Error("artifact digest mismatch after round-trip")
	}

	if string(deserialized.Statement) != string(original.Statement) {
		t.Error("statement mismatch after round-trip")
	}

	if deserialized.Metadata.GeneratorVersion != original.Metadata.GeneratorVersion {
		t.Error("generator version mismatch after round-trip")
	}

	// Validate deserialized evidence is also valid
	if err := deserialized.Validate(); err != nil {
		t.Errorf("deserialized evidence validation failed: %v", err)
	}

	t.Logf("✓ Integrity verified - all critical fields preserved")
}

// TestMultipleSBOMFormats validates that the pipeline works with all SBOM formats.
func TestMultipleSBOMFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	formats := []struct {
		name   string
		format sbom.Format
	}{
		{"SPDX", sbom.FormatSPDXJSON},
		{"CycloneDX", sbom.FormatCycloneDXJSON},
		{"SyftJSON", sbom.FormatSyftJSON},
	}

	for _, fmt := range formats {
		t.Run(fmt.name, func(t *testing.T) {
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
					Format: fmt.format,
				},
				ScanOptions: scanner.Options{},
				SignOptions: signer.Options{
					Mode:             signer.ModeKeyless,
					SkipTransparency: true,
				},
				GeneratorVersion: "test-formats-1.0.0",
			}

			ev, err := gen.Generate(ctx, "alpine:latest", opts)
			if err != nil {
				t.Fatalf("failed to generate evidence: %v", err)
			}

			// Validate evidence
			if err := ev.Validate(); err != nil {
				t.Errorf("evidence validation failed: %v", err)
			}

			// Verify SBOM format
			if ev.SBOM.Format != fmt.format {
				t.Errorf("SBOM format mismatch: expected %s, got %s", fmt.format, ev.SBOM.Format)
			}

			// Verify serialization roundtrip
			jsonData, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("failed to marshal evidence: %v", err)
			}

			deserialized := &evidence.Evidence{}
			if err := json.Unmarshal(jsonData, deserialized); err != nil {
				t.Fatalf("failed to unmarshal evidence: %v", err)
			}

			if err := deserialized.Validate(); err != nil {
				t.Errorf("deserialized evidence validation failed: %v", err)
			}

			t.Logf("✓ Format %s: Evidence generated, serialized, and validated (%d bytes)", fmt.name, len(jsonData))
		})
	}
}
