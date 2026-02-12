package e2e

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/providers/signer/cosign"
)

// TestSignatureVerification_PreGenerated tests signature verification using pre-generated attestation.
// This test requires a valid attestation file created by:
// ./provenix attest alpine:latest --key .provenix/test.key --output /tmp/test-attestation.json
func TestSignatureVerification_PreGenerated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check for existing attestation files
	attestationPaths := []string{
		"/tmp/e2e-final.json",
		"/tmp/test-attestation.json",
		"/tmp/nginx-test.json",
	}

	var foundPath string
	for _, path := range attestationPaths {
		if _, err := os.Stat(path); err == nil {
			foundPath = path
			break
		}
	}

	if foundPath == "" {
		t.Skip("No pre-generated attestation found. Create one with: ./provenix attest alpine:latest --key .provenix/test.key --output /tmp/test-attestation.json")
	}

	t.Logf("Using attestation file: %s", foundPath)

	// Read attestation
	attestationJSON, err := os.ReadFile(foundPath)
	if err != nil {
		t.Fatalf("failed to read attestation: %v", err)
	}

	// Parse attestation bundle
	var bundle cosign.AttestationBundle
	if err := json.Unmarshal(attestationJSON, &bundle); err != nil {
		t.Fatalf("failed to parse attestation: %v", err)
	}

	// Verify attestation
	verifier := cosign.NewVerifier("")
	result, err := verifier.Verify(ctx, &bundle)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}

	// Validate results
	if !result.Valid {
		t.Errorf("verification failed: %v", result.Errors)
	}

	if !result.SignatureValid {
		t.Error("signature validation failed")
	}

	if result.Artifact == "" {
		t.Error("artifact name is empty")
	}

	t.Logf("✓ Signature verification PASSED for artifact: %s", result.Artifact)
}

// TestSignatureVerification_InvalidSignature tests that invalid signatures are correctly rejected.
func TestSignatureVerification_InvalidSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create bundle with tampered signature
	bundle := cosign.AttestationBundle{
		StatementBase64: "eyJ0ZXN0IjoidmFsdWUifQ==", // {"test":"value"}
		Signature:       "aW52YWxpZC1zaWduYXR1cmU=", // "invalid-signature"
		PublicKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
-----END PUBLIC KEY-----`,
	}

	verifier := cosign.NewVerifier("")
	result, err := verifier.Verify(ctx, &bundle)
	if err != nil {
		t.Fatalf("verification returned unexpected error: %v", err)
	}

	// Should fail validation
	if result.Valid {
		t.Error("tampered signature should not be valid")
	}

	if result.SignatureValid {
		t.Error("tampered signature should fail signature validation")
	}

	if len(result.Errors) == 0 {
		t.Error("expected error messages for invalid signature")
	}

	t.Log("✓ Invalid signature correctly rejected")
}

// TestSignatureVerification_MalformedBundle tests handling of malformed attestation bundles.
func TestSignatureVerification_MalformedBundle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping E2E test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tests := []struct {
		name   string
		bundle cosign.AttestationBundle
	}{
		{
			name: "invalid base64 statement",
			bundle: cosign.AttestationBundle{
				StatementBase64: "not-valid-base64!!!",
				Signature:       "c2lnbmF0dXJl",
				PublicKey:       "pubkey",
			},
		},
		{
			name: "missing public key and certificate",
			bundle: cosign.AttestationBundle{
				StatementBase64: "eyJ0ZXN0IjoidmFsdWUifQ==",
				Signature:       "c2lnbmF0dXJl",
			},
		},
	}

	verifier := cosign.NewVerifier("")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifier.Verify(ctx, &tt.bundle)
			
			// Either error during verification or invalid result
			if err == nil {
				if result.Valid {
					t.Error("malformed bundle should not be valid")
				}
			}
		})
	}
}
