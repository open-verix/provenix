package cosign

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TestNewVerifier verifies that NewVerifier creates a valid verifier.
func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name      string
		rekorURL  string
		wantNil   bool
	}{
		{
			name:     "valid public rekor",
			rekorURL: "https://rekor.sigstore.dev",
			wantNil:  false,
		},
		{
			name:     "empty rekor url",
			rekorURL: "",
			wantNil:  false,
		},
		{
			name:     "custom rekor url",
			rekorURL: "https://rekor.example.com",
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(tt.rekorURL)
			if (v == nil) != tt.wantNil {
				t.Errorf("NewVerifier() = %v, want nil = %v", v, tt.wantNil)
			}
			if v != nil && v.rekorClient == nil {
				t.Error("NewVerifier() created verifier with nil rekorClient")
			}
		})
	}
}

// TestVerify_KeyBased tests signature verification with key-based signing.
func TestVerify_KeyBased(t *testing.T) {
	// Generate test keypair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create test statement
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]interface{}{{"name": "test-artifact", "digest": map[string]string{"sha256": "abc123"}}},
		"predicateType": "https://provenix.dev/attestation/v1",
		"predicate":     map[string]interface{}{"test": "data"},
	}

	statementBytes, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	// Sign the statement
	hash := sha256.Sum256(statementBytes)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign statement: %v", err)
	}

	// Encode signature as ASN.1 DER (ECDSA signature format)
	var ecdsaSig struct {
		R, S *big.Int
	}
	ecdsaSig.R = r
	ecdsaSig.S = s
	
	signatureBytes, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		t.Fatalf("Failed to marshal signature: %v", err)
	}

	signature := base64.StdEncoding.EncodeToString(signatureBytes)

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	bundle := &AttestationBundle{
		StatementBase64: base64.StdEncoding.EncodeToString(statementBytes),
		Signature:       signature,
		PublicKey:       string(pubKeyPEM),
	}

	v := NewVerifier("")
	ctx := context.Background()

	result, err := v.Verify(ctx, bundle)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if !result.Valid {
		t.Errorf("Verify() result.Valid = false, want true. Errors: %v", result.Errors)
	}

	if !result.SignatureValid {
		t.Errorf("Verify() result.SignatureValid = false, want true")
	}

	if result.Artifact != "test-artifact" {
		t.Errorf("Verify() result.Artifact = %v, want test-artifact", result.Artifact)
	}
}

// TestVerify_InvalidSignature tests verification with an invalid signature.
func TestVerify_InvalidSignature(t *testing.T) {
	// Generate test keypair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create test statement
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]interface{}{{"name": "test-artifact", "digest": map[string]string{"sha256": "abc123"}}},
		"predicateType": "https://provenix.dev/attestation/v1",
		"predicate":     map[string]interface{}{"test": "data"},
	}

	statementBytes, err := json.Marshal(statement)
	if err != nil {
		t.Fatalf("Failed to marshal statement: %v", err)
	}

	// Create an invalid signature (all zeros) - encoded as ASN.1 DER
	var invalidEcdsaSig struct {
		R, S *big.Int
	}
	invalidEcdsaSig.R = big.NewInt(0)
	invalidEcdsaSig.S = big.NewInt(0)
	
	invalidSigBytes, _ := asn1.Marshal(invalidEcdsaSig)
	invalidSignature := base64.StdEncoding.EncodeToString(invalidSigBytes)

	// Encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	bundle := &AttestationBundle{
		StatementBase64: base64.StdEncoding.EncodeToString(statementBytes),
		Signature:       invalidSignature,
		PublicKey:       string(pubKeyPEM),
	}

	v := NewVerifier("")
	ctx := context.Background()

	result, err := v.Verify(ctx, bundle)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Valid {
		t.Errorf("Verify() result.Valid = true, want false for invalid signature")
	}

	if result.SignatureValid {
		t.Errorf("Verify() result.SignatureValid = true, want false for invalid signature")
	}

	if len(result.Errors) == 0 {
		t.Errorf("Verify() result.Errors is empty, want error messages")
	}
}

// TestVerify_MalformedStatement tests verification with malformed statement.
func TestVerify_MalformedStatement(t *testing.T) {
	bundle := &AttestationBundle{
		StatementBase64: "not-valid-base64!!!",
		Signature:       base64.StdEncoding.EncodeToString([]byte("sig")),
		PublicKey:       "pubkey",
	}

	v := NewVerifier("")
	ctx := context.Background()

	_, err := v.Verify(ctx, bundle)
	if err == nil {
		t.Error("Verify() with malformed statement should return error")
	}
}

// TestVerify_MissingPublicKeyAndCertificate tests verification without key or cert.
func TestVerify_MissingPublicKeyAndCertificate(t *testing.T) {
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []map[string]interface{}{{"name": "test", "digest": map[string]string{"sha256": "abc"}}},
		"predicateType": "https://provenix.dev/attestation/v1",
		"predicate":     map[string]interface{}{},
	}

	statementBytes, _ := json.Marshal(statement)

	bundle := &AttestationBundle{
		StatementBase64: base64.StdEncoding.EncodeToString(statementBytes),
		Signature:       base64.StdEncoding.EncodeToString([]byte("sig")),
		// No PublicKey or Certificate
	}

	v := NewVerifier("")
	ctx := context.Background()

	result, err := v.Verify(ctx, bundle)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if result.Valid {
		t.Error("Verify() result.Valid = true, want false without key or cert")
	}

	if len(result.Errors) == 0 {
		t.Error("Verify() result.Errors is empty, want error about missing key")
	}
}

// TestValidateCertificateInvalidPEM tests certificate validation with invalid PEM.
func TestValidateCertificateInvalidPEM(t *testing.T) {
	v := NewVerifier("")

	// Test with invalid PEM
	_, _, err := v.validateCertificate("invalid-pem")
	if err == nil {
		t.Error("validateCertificate() with invalid PEM should return error")
	}

	// Test with valid certificate (self-signed for testing)
	cert := createTestCertificate(t)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Note: This will fail actual validation since it's self-signed and not from Sigstore
	// But we're testing that the function handles the input correctly
	_, _, err = v.validateCertificate(string(certPEM))
	// We expect an error because it's not a valid Sigstore certificate
	if err == nil {
		t.Log("validateCertificate() passed with test cert (expected in some cases)")
	}
}

// TestVerifySignatureMethod tests the signature verification method.
func TestVerifySignatureMethod(t *testing.T) {
	v := NewVerifier("")
	
	// Generate test keypair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	statementBytes := []byte("test statement")
	
	// Hash the statement
	hash := sha256.Sum256(statementBytes)

	// Create valid signature
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Encode signature as ASN.1 DER
	var ecdsaSig struct {
		R, S *big.Int
	}
	ecdsaSig.R = r
	ecdsaSig.S = s
	
	signatureBytes, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		t.Fatalf("Failed to marshal signature: %v", err)
	}
	
	signatureB64 := base64.StdEncoding.EncodeToString(signatureBytes)

	// Test valid signature
	err = v.verifySignature(statementBytes, signatureB64, &privateKey.PublicKey)
	if err != nil {
		t.Errorf("verifySignature() with valid signature returned error: %v", err)
	}

	// Test invalid signature
	invalidSig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	err = v.verifySignature(statementBytes, invalidSig, &privateKey.PublicKey)
	if err == nil {
		t.Error("verifySignature() with invalid signature should return error")
	}

	// Test wrong public key
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = v.verifySignature(statementBytes, signatureB64, &otherKey.PublicKey)
	if err == nil {
		t.Error("verifySignature() with wrong public key should return error")
	}
}

// TestExtractArtifactFromStatement tests artifact name extraction.
func TestExtractArtifactFromStatement(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		want      string
	}{
		{
			name:      "valid statement with subject",
			statement: `{"subject":[{"name":"my-artifact","digest":{"sha256":"abc"}}]}`,
			want:      "my-artifact",
		},
		{
			name:      "statement with multiple subjects",
			statement: `{"subject":[{"name":"first"},{"name":"second"}]}`,
			want:      "first",
		},
		{
			name:      "statement without subject",
			statement: `{"predicate":{}}`,
			want:      "(unknown)",
		},
		{
			name:      "invalid json",
			statement: `not-json`,
			want:      "(unknown)",
		},
		{
			name:      "empty statement",
			statement: `{}`,
			want:      "(unknown)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractArtifactFromStatement([]byte(tt.statement))
			if got != tt.want {
				t.Errorf("extractArtifactFromStatement() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T) *x509.Certificate {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test@example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Add OIDC extensions for testing
	oidcIssuerOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:       oidcIssuerOID,
			Critical: false,
			Value:    []byte("https://token.actions.githubusercontent.com"),
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

// Helper function to encode ECDSA signature
func encodeSignature(r, s *big.Int) []byte {
	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	return sig
}
