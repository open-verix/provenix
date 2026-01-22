package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers"
)

// TestSyftProviderWithLocalDirectory tests SBOM generation from a local directory.
// This is a real integration test using actual Syft library APIs.
func TestSyftProviderWithLocalDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get syft provider: %v", err)
	}

	// Test with current directory
	opts := sbom.Options{
		Format:   sbom.FormatSyftJSON,
		Local:    true,
		Platform: "",
	}

	result, err := provider.Generate(ctx, ".", opts)
	if err != nil {
		t.Fatalf("failed to generate SBOM: %v", err)
	}

	// Validate result
	if result == nil {
		t.Error("expected SBOM, got nil")
	}

	if result.Format != sbom.FormatSyftJSON {
		t.Errorf("expected format %s, got %s", sbom.FormatSyftJSON, result.Format)
	}

	if result.Artifact != "." {
		t.Errorf("expected artifact '.', got %s", result.Artifact)
	}

	if result.Checksum == "" {
		t.Error("expected checksum, got empty")
	}

	// Verify content is valid JSON
	var jsonContent map[string]interface{}
	if err := json.Unmarshal(result.Content, &jsonContent); err != nil {
		t.Errorf("failed to parse SBOM content as JSON: %v", err)
	}

	if result.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt timestamp, got zero")
	}

	if result.ProviderName != "syft" {
		t.Errorf("expected provider name 'syft', got %s", result.ProviderName)
	}

	if result.ProviderVersion == "" {
		t.Error("expected provider version, got empty")
	}

	t.Logf("✓ SBOM generated successfully: %d bytes, format=%s", len(result.Content), result.Format)
}

// TestSyftProviderFormatSPDX tests SBOM generation with SPDX JSON format.
func TestSyftProviderFormatSPDX(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get syft provider: %v", err)
	}

	opts := sbom.Options{
		Format:   sbom.FormatSPDXJSON,
		Local:    true,
		Platform: "",
	}

	result, err := provider.Generate(ctx, ".", opts)
	if err != nil {
		t.Fatalf("failed to generate SBOM: %v", err)
	}

	if result.Format != sbom.FormatSPDXJSON {
		t.Errorf("expected format %s, got %s", sbom.FormatSPDXJSON, result.Format)
	}

	// Verify SPDX structure
	var spdxContent map[string]interface{}
	if err := json.Unmarshal(result.Content, &spdxContent); err != nil {
		t.Errorf("failed to parse SPDX content as JSON: %v", err)
	}

	if _, hasSPDXVersion := spdxContent["spdxVersion"]; !hasSPDXVersion {
		t.Error("SPDX JSON missing spdxVersion field")
	}

	t.Logf("✓ SPDX format test passed: %d bytes", len(result.Content))
}

// TestSyftProviderFormatCycloneDX tests SBOM generation with CycloneDX JSON format.
func TestSyftProviderFormatCycloneDX(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get syft provider: %v", err)
	}

	opts := sbom.Options{
		Format:   sbom.FormatCycloneDXJSON,
		Local:    true,
		Platform: "",
	}

	result, err := provider.Generate(ctx, ".", opts)
	if err != nil {
		t.Fatalf("failed to generate SBOM: %v", err)
	}

	if result.Format != sbom.FormatCycloneDXJSON {
		t.Errorf("expected format %s, got %s", sbom.FormatCycloneDXJSON, result.Format)
	}

	// Verify CycloneDX structure
	var cdxContent map[string]interface{}
	if err := json.Unmarshal(result.Content, &cdxContent); err != nil {
		t.Errorf("failed to parse CycloneDX content as JSON: %v", err)
	}

	if _, hasSpecVersion := cdxContent["specVersion"]; !hasSpecVersion {
		t.Error("CycloneDX JSON missing specVersion field")
	}

	if _, hasVersion := cdxContent["version"]; !hasVersion {
		t.Error("CycloneDX JSON missing version field")
	}

	t.Logf("✓ CycloneDX format test passed: %d bytes", len(result.Content))
}

// TestSyftProviderChecksumIntegrity verifies SHA256 checksum calculation.
func TestSyftProviderChecksumIntegrity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		t.Fatalf("failed to get syft provider: %v", err)
	}

	opts := sbom.Options{
		Format:   sbom.FormatSyftJSON,
		Local:    true,
		Platform: "",
	}

	result, err := provider.Generate(ctx, ".", opts)
	if err != nil {
		t.Fatalf("failed to generate SBOM: %v", err)
	}

	// Verify checksum matches content
	hash := sha256.Sum256(result.Content)
	expectedChecksum := hex.EncodeToString(hash[:])

	if result.Checksum != expectedChecksum {
		t.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, result.Checksum)
	}

	t.Logf("✓ Checksum integrity verified: %s", result.Checksum)
}
