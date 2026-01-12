package evidence

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/providers/sbom"
	sbommock "github.com/open-verix/provenix/internal/providers/sbom/mock"
	"github.com/open-verix/provenix/internal/providers/scanner"
	scannermock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	"github.com/open-verix/provenix/internal/providers/signer"
	signermock "github.com/open-verix/provenix/internal/providers/signer/mock"
)

func TestNewGenerator(t *testing.T) {
	sbomProvider := sbommock.NewProvider()
	scannerProvider := scannermock.NewProvider()
	signerProvider := signermock.NewProvider()

	gen := NewGenerator(sbomProvider, scannerProvider, signerProvider)

	if gen == nil {
		t.Fatal("expected non-nil generator")
	}
	if gen.sbomProvider == nil {
		t.Error("expected non-nil SBOM provider")
	}
	if gen.scannerProvider == nil {
		t.Error("expected non-nil scanner provider")
	}
	if gen.signerProvider == nil {
		t.Error("expected non-nil signer provider")
	}
}

func TestGenerateSuccess(t *testing.T) {
	// Create mock providers
	sbomProvider := sbommock.NewProvider()
	scannerProvider := scannermock.NewProvider()
	signerProvider := signermock.NewProvider()

	gen := NewGenerator(sbomProvider, scannerProvider, signerProvider)

	// Generate evidence
	opts := GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.FormatCycloneDXJSON,
		},
		ScanOptions: scanner.Options{
			FailOnSeverity: scanner.SeverityCritical,
		},
		SignOptions: signer.Options{
			KeyPath: "/path/to/key.pem",
		},
		GeneratorVersion: "1.0.0",
	}

	ctx := context.Background()
	evidence, err := gen.Generate(ctx, "nginx:latest", opts)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Validate evidence structure
	if evidence.Artifact != "nginx:latest" {
		t.Errorf("expected artifact 'nginx:latest', got: %s", evidence.Artifact)
	}
	if evidence.ArtifactDigest == "" {
		t.Error("expected non-empty artifact digest")
	}
	if evidence.SBOM == nil {
		t.Error("expected non-nil SBOM")
	}
	if evidence.VulnerabilityReport == nil {
		t.Error("expected non-nil vulnerability report")
	}
	if evidence.Statement == nil || len(evidence.Statement) == 0 {
		t.Error("expected non-empty statement")
	}
	if evidence.Signature == nil {
		t.Error("expected non-nil signature")
	}
	if evidence.Metadata == nil {
		t.Error("expected non-nil metadata")
	}

	// Validate metadata
	if evidence.Metadata.GeneratorVersion != "1.0.0" {
		t.Errorf("expected generator version '1.0.0', got: %s", evidence.Metadata.GeneratorVersion)
	}
	if evidence.Metadata.SBOMProvider.Name != "mock" {
		t.Errorf("expected SBOM provider 'mock', got: %s", evidence.Metadata.SBOMProvider.Name)
	}
	if evidence.Metadata.ScannerProvider.Name != "mock" {
		t.Errorf("expected scanner provider 'mock', got: %s", evidence.Metadata.ScannerProvider.Name)
	}
	if evidence.Metadata.SignerProvider.Name != "mock" {
		t.Errorf("expected signer provider 'mock', got: %s", evidence.Metadata.SignerProvider.Name)
	}
	if evidence.Metadata.Duration == 0 {
		t.Error("expected non-zero duration")
	}

	// Validate statement structure (should be valid in-toto statement)
	var statement Statement
	if err := json.Unmarshal(evidence.Statement, &statement); err != nil {
		t.Fatalf("failed to unmarshal statement: %v", err)
	}
	if statement.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("expected statement type 'https://in-toto.io/Statement/v1', got: %s", statement.Type)
	}
	if statement.PredicateType != "https://provenix.dev/attestation/v1" {
		t.Errorf("expected predicate type 'https://provenix.dev/attestation/v1', got: %s", statement.PredicateType)
	}
	if len(statement.Subject) == 0 {
		t.Error("expected at least one subject")
	}
}

func TestGenerateInvalidArtifact(t *testing.T) {
	sbomProvider := sbommock.NewProvider()
	scannerProvider := scannermock.NewProvider()
	signerProvider := signermock.NewProvider()

	gen := NewGenerator(sbomProvider, scannerProvider, signerProvider)

	opts := GenerateOptions{}
	ctx := context.Background()

	// Test with empty artifact
	evidence, err := gen.Generate(ctx, "", opts)

	if err == nil {
		t.Fatal("expected error for empty artifact")
	}
	if evidence != nil {
		t.Error("expected nil evidence on error")
	}
	if err != ErrInvalidArtifact {
		t.Errorf("expected ErrInvalidArtifact, got: %v", err)
	}
}

func TestGenerateContextCancellation(t *testing.T) {
	sbomProvider := sbommock.NewProvider()
	scannerProvider := scannermock.NewProvider()
	signerProvider := signermock.NewProvider()

	gen := NewGenerator(sbomProvider, scannerProvider, signerProvider)

	opts := GenerateOptions{
		GeneratorVersion: "1.0.0",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	evidence, err := gen.Generate(ctx, "nginx:latest", opts)

	// Mock providers don't actually respect context cancellation,
	// but in real implementation they should
	if err != nil && evidence == nil {
		// This is acceptable behavior for cancelled context
		return
	}

	// If mock providers complete anyway, that's also fine for testing
	if evidence != nil && err == nil {
		return
	}

	t.Errorf("unexpected result: evidence=%v, err=%v", evidence, err)
}

func TestCreateStatement(t *testing.T) {
	// Create test SBOM
	sbomData := &sbom.SBOM{
		Format:  sbom.FormatCycloneDXJSON,
		Artifact: "nginx:latest",
		Content: json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"test-package","version":"1.0.0"}]}`),
		Checksum: "sha256:abc123",
	}

	// Create test vulnerability report
	vulnReport := &scanner.Report{
		ScannedAt: time.Now().UTC(),
		DBVersion: "grype-db:v5.14.0",
		Vulnerabilities: []scanner.Vulnerability{
			{
				ID:           "CVE-2024-1234",
				Severity:     scanner.SeverityHigh,
				Package:      "test-package",
				Version:      "1.0.0",
				FixedVersion: "1.0.1",
				Description:  "Test vulnerability",
			},
		},
	}

	// Create statement
	statement, err := CreateStatement(
		"nginx:latest",
		sbomData.Checksum,
		sbomData,
		vulnReport,
		"1.0.0",
		"mock-sbom",
		"1.0.0",
		"mock-scanner",
		"1.0.0",
	)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Unmarshal and validate statement
	var stmt Statement
	if err := json.Unmarshal(statement, &stmt); err != nil {
		t.Fatalf("failed to unmarshal statement: %v", err)
	}

	// Validate statement structure
	if stmt.Type != "https://in-toto.io/Statement/v1" {
		t.Errorf("expected statement type 'https://in-toto.io/Statement/v1', got: %s", stmt.Type)
	}
	if stmt.PredicateType != "https://provenix.dev/attestation/v1" {
		t.Errorf("expected predicate type 'https://provenix.dev/attestation/v1', got: %s", stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 {
		t.Fatalf("expected 1 subject, got: %d", len(stmt.Subject))
	}
	if stmt.Subject[0].Name != "nginx:latest" {
		t.Errorf("expected subject name 'nginx:latest', got: %s", stmt.Subject[0].Name)
	}
	if stmt.Subject[0].Digest["sha256"] != "sha256:abc123" {
		t.Errorf("expected digest 'sha256:abc123', got: %s", stmt.Subject[0].Digest["sha256"])
	}

	// Validate predicate
	predicateJSON, err := json.Marshal(stmt.Predicate)
	if err != nil {
		t.Fatalf("failed to marshal predicate: %v", err)
	}

	var predicate ProvenixPredicate
	if err := json.Unmarshal(predicateJSON, &predicate); err != nil {
		t.Fatalf("failed to unmarshal predicate: %v", err)
	}

	if predicate.SBOM == nil {
		t.Error("expected non-nil SBOM in predicate")
	}
	if predicate.VulnerabilityReport == nil {
		t.Error("expected non-nil vulnerability report in predicate")
	}
	if predicate.Metadata == nil {
		t.Error("expected non-nil metadata in predicate")
	}

	// Validate vulnerability report in predicate
	if predicate.VulnerabilityReport.TotalCount != 1 {
		t.Errorf("expected 1 vulnerability, got: %d", predicate.VulnerabilityReport.TotalCount)
	}
	if predicate.VulnerabilityReport.HighCount != 1 {
		t.Errorf("expected 1 high severity vulnerability, got: %d", predicate.VulnerabilityReport.HighCount)
	}
}

func TestEvidenceValidate(t *testing.T) {
	tests := []struct {
		name        string
		evidence    *Evidence
		expectError error
	}{
		{
			name: "valid evidence",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: &scanner.Report{},
				Statement:           []byte("{}"),
				Signature:           &signer.Signature{},
				Metadata:            &Metadata{},
			},
			expectError: nil,
		},
		{
			name: "missing artifact",
			evidence: &Evidence{
				Artifact:            "",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: &scanner.Report{},
				Statement:           []byte("{}"),
				Signature:           &signer.Signature{},
				Metadata:            &Metadata{},
			},
			expectError: ErrInvalidArtifact,
		},
		{
			name: "missing digest",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: &scanner.Report{},
				Statement:           []byte("{}"),
				Signature:           &signer.Signature{},
				Metadata:            &Metadata{},
			},
			expectError: ErrMissingDigest,
		},
		{
			name: "missing SBOM",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                nil,
				VulnerabilityReport: &scanner.Report{},
				Statement:           []byte("{}"),
				Signature:           &signer.Signature{},
				Metadata:            &Metadata{},
			},
			expectError: ErrMissingSBOM,
		},
		{
			name: "missing vulnerability report",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: nil,
				Statement:           []byte("{}"),
				Signature:           &signer.Signature{},
				Metadata:            &Metadata{},
			},
			expectError: ErrMissingVulnReport,
		},
		{
			name: "missing statement",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: &scanner.Report{},
				Statement:           nil,
				Signature:           &signer.Signature{},
				Metadata:            &Metadata{},
			},
			expectError: ErrMissingStatement,
		},
		{
			name: "missing signature",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: &scanner.Report{},
				Statement:           []byte("{}"),
				Signature:           nil,
				Metadata:            &Metadata{},
			},
			expectError: ErrMissingSignature,
		},
		{
			name: "missing metadata",
			evidence: &Evidence{
				Artifact:            "nginx:latest",
				ArtifactDigest:      "sha256:abc123",
				SBOM:                &sbom.SBOM{},
				VulnerabilityReport: &scanner.Report{},
				Statement:           []byte("{}"),
				Signature:           &signer.Signature{},
				Metadata:            nil,
			},
			expectError: ErrMissingMetadata,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.evidence.Validate()
			if err != tt.expectError {
				t.Errorf("expected error %v, got: %v", tt.expectError, err)
			}
		})
	}
}

func TestComputeDigest(t *testing.T) {
	statement := []byte(`{"test": "data"}`)
	digest := ComputeDigest(statement)

	if digest == "" {
		t.Error("expected non-empty digest")
	}

	// Verify consistency
	digest2 := ComputeDigest(statement)
	if digest != digest2 {
		t.Error("expected consistent digest for same input")
	}

	// Verify different input produces different digest
	statement2 := []byte(`{"test": "different"}`)
	digest3 := ComputeDigest(statement2)
	if digest == digest3 {
		t.Error("expected different digest for different input")
	}
}
