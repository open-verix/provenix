package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	signerprovider "github.com/open-verix/provenix/internal/providers/signer"
)

// Verifier handles signature verification for attestations.
type Verifier struct {
	rekorClient *RekorClient
}

// NewVerifier creates a new signature verifier.
func NewVerifier(rekorURL string) *Verifier {
	return &Verifier{
		rekorClient: NewRekorClient(rekorURL),
	}
}

// VerificationResult contains the result of attestation verification.
type VerificationResult struct {
	Valid            bool                       `json:"valid"`
	Artifact         string                     `json:"artifact"`
	SignatureValid   bool                       `json:"signatureValid"`
	CertificateValid bool                       `json:"certificateValid"`
	RekorValid       bool                       `json:"rekorValid"`
	Identity         *VerifiedIdentity          `json:"identity,omitempty"`
	RekorEntry       *RekorEntryResponse        `json:"rekorEntry,omitempty"`
	Errors           []string                   `json:"errors,omitempty"`
}

// VerifiedIdentity contains information about the signer's identity.
type VerifiedIdentity struct {
	Subject  string `json:"subject"`  // Email or other OIDC identity
	Issuer   string `json:"issuer"`   // OIDC issuer (e.g., https://token.actions.githubusercontent.com)
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// AttestationBundle represents a signed attestation with all verification data.
type AttestationBundle struct {
	StatementBase64 string `json:"statementBase64"` // Base64-encoded statement JSON (exact signed bytes)
	Signature       string `json:"signature"`       // Base64-encoded signature
	Certificate     string `json:"certificate"`     // PEM-encoded certificate (keyless) or empty (key-based)
	PublicKey       string `json:"publicKey"`       // PEM-encoded public key (key-based) or empty (keyless)
	RekorUUID       string `json:"rekorUUID"`       // Rekor entry UUID
	RekorLogIndex   int    `json:"rekorLogIndex,omitempty"`
}

// Verify verifies an attestation bundle.
//
// Verification steps:
// 1. If certificate present (keyless):
//    - Validate certificate chain to Sigstore root CA
//    - Extract public key from certificate
//    - Verify OIDC identity from certificate extensions
// 2. If public key present (key-based):
//    - Use provided public key
// 3. Verify signature over statement using public key
// 4. If Rekor UUID present:
//    - Retrieve entry from Rekor
//    - Verify entry matches attestation
//    - Verify inclusion proof
//
// Returns VerificationResult with detailed validation status.
func (v *Verifier) Verify(ctx context.Context, bundle *AttestationBundle) (*VerificationResult, error) {
	// Decode base64-encoded statement to get exact signed bytes
	statementBytes, err := base64.StdEncoding.DecodeString(bundle.StatementBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode statement: %w", err)
	}

	result := &VerificationResult{
		Artifact: extractArtifactFromStatement(statementBytes),
	}

	var publicKey crypto.PublicKey

	// Step 1: Validate certificate (if present) and extract public key
	if bundle.Certificate != "" {
		var certErr error
		publicKey, result.Identity, certErr = v.validateCertificate(bundle.Certificate)
		if certErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("certificate validation failed: %v", certErr))
		} else {
			result.CertificateValid = true
		}
	} else if bundle.PublicKey != "" {
		// Key-based verification
		publicKey, err = parsePublicKey(bundle.PublicKey)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("public key parsing failed: %v", err))
		}
		result.CertificateValid = true // Not applicable for key-based
	} else {
		result.Errors = append(result.Errors, "no certificate or public key provided")
		return result, nil
	}

	// Step 2: Verify signature over statement
	if publicKey != nil {
		err = v.verifySignature(statementBytes, bundle.Signature, publicKey)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("signature verification failed: %v", err))
		} else {
			result.SignatureValid = true
		}
	}

	// Step 3: Verify Rekor entry (if present)
	if bundle.RekorUUID != "" {
		entry, err := v.verifyRekorEntry(ctx, bundle)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("rekor verification failed: %v", err))
		} else {
			result.RekorValid = true
			result.RekorEntry = entry
		}
	} else {
		result.RekorValid = true // Not applicable if no Rekor UUID
	}

	// Overall validity: all applicable checks must pass
	result.Valid = result.SignatureValid && result.CertificateValid && result.RekorValid && len(result.Errors) == 0

	return result, nil
}

// VerifyWithPublicKey verifies an attestation using a provided public key (key-based verification).
func (v *Verifier) VerifyWithPublicKey(ctx context.Context, statement []byte, signature string, publicKeyPEM string) error {
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	return v.verifySignature(statement, signature, publicKey)
}

// validateCertificate validates a certificate and extracts the signer's identity.
func (v *Verifier) validateCertificate(certPEM string) (crypto.PublicKey, *VerifiedIdentity, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate chain to Sigstore root CA
	// ValidateCertificateChain expects (certPEM, intermediatePEM, staging bool)
	// We need to encode cert back to PEM
	certPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := ValidateCertificateChain(certPEMBytes, nil, false); err != nil {
		return nil, nil, fmt.Errorf("certificate chain validation failed: %w", err)
	}

	// Check certificate expiry
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, nil, fmt.Errorf("certificate not yet valid (NotBefore: %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("certificate expired (NotAfter: %v)", cert.NotAfter)
	}

	// Extract OIDC identity from certificate extensions
	identity, err := extractOIDCIdentity(cert)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract OIDC identity: %w", err)
	}

	return cert.PublicKey, identity, nil
}

// extractOIDCIdentity extracts the signer's OIDC identity from certificate extensions.
func extractOIDCIdentity(cert *x509.Certificate) (*VerifiedIdentity, error) {
	identity := &VerifiedIdentity{
		NotBefore: cert.NotBefore.Format("2006-01-02T15:04:05Z"),
		NotAfter:  cert.NotAfter.Format("2006-01-02T15:04:05Z"),
	}

	// Fulcio certificate extensions (OID 1.3.6.1.4.1.57264.1.*)
	oidSubject := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuer := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSubject) {
			identity.Subject = string(ext.Value)
		}
		if ext.Id.Equal(oidIssuer) {
			identity.Issuer = string(ext.Value)
		}
	}

	if identity.Subject == "" {
		// Fallback: try SAN (Subject Alternative Name)
		if len(cert.EmailAddresses) > 0 {
			identity.Subject = cert.EmailAddresses[0]
		} else if len(cert.URIs) > 0 {
			identity.Subject = cert.URIs[0].String()
		}
	}

	if identity.Subject == "" {
		return nil, fmt.Errorf("no subject found in certificate")
	}

	return identity, nil
}

// verifySignature verifies an ECDSA signature over the statement.
func (v *Verifier) verifySignature(statement []byte, signatureB64 string, publicKey crypto.PublicKey) error {
	// Decode base64 signature
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Parse ECDSA signature (ASN.1 DER format: SEQUENCE { r INTEGER, s INTEGER })
	var ecdsaSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signatureBytes, &ecdsaSig); err != nil {
		return fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}

	// Hash the statement (SHA-256)
	hash := sha256.Sum256(statement)

	// Verify signature
	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA (got %T)", publicKey)
	}

	if !ecdsa.Verify(ecdsaPubKey, hash[:], ecdsaSig.R, ecdsaSig.S) {
		return fmt.Errorf("signature verification failed: invalid signature")
	}

	return nil
}

// verifyRekorEntry verifies that the Rekor entry matches the attestation.
func (v *Verifier) verifyRekorEntry(ctx context.Context, bundle *AttestationBundle) (*RekorEntryResponse, error) {
	// Retrieve entry from Rekor
	entry, err := v.rekorClient.GetEntry(ctx, bundle.RekorUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Rekor entry: %w", err)
	}

	// Verify inclusion proof
	if err := v.rekorClient.VerifyInclusionProof(ctx, bundle.RekorUUID); err != nil {
		return nil, fmt.Errorf("inclusion proof verification failed: %w", err)
	}

	// Verify that entry body matches attestation (hash, signature, public key)
	if err := v.verifyRekorEntryBody(entry, bundle); err != nil {
		return nil, fmt.Errorf("rekor entry body verification failed: %w", err)
	}

	return entry, nil
}

// verifyRekorEntryBody verifies that the Rekor entry body matches the attestation bundle.
// This ensures the logged data corresponds to what we're verifying.
func (v *Verifier) verifyRekorEntryBody(entry *RekorEntryResponse, bundle *AttestationBundle) error {
	// Decode base64-encoded body
	bodyBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return fmt.Errorf("failed to decode rekor entry body: %w", err)
	}

	// Parse hashedrekord structure
	var rekorBody struct {
		Kind       string `json:"kind"`
		APIVersion string `json:"apiVersion"`
		Spec       struct {
			Signature struct {
				Content   string `json:"content"` // base64-encoded signature
				PublicKey struct {
					Content string `json:"content"` // base64-encoded public key or cert
				} `json:"publicKey"`
			} `json:"signature"`
			Data struct {
				Hash struct {
					Algorithm string `json:"algorithm"`
					Value     string `json:"value"` // hex-encoded SHA256 hash
				} `json:"hash"`
			} `json:"data"`
		} `json:"spec"`
	}

	if err := json.Unmarshal(bodyBytes, &rekorBody); err != nil {
		return fmt.Errorf("failed to parse rekor entry body: %w", err)
	}

	// Verify kind
	if rekorBody.Kind != "hashedrekord" {
		return fmt.Errorf("unexpected rekor entry kind: %s (expected hashedrekord)", rekorBody.Kind)
	}

	// Verify signature matches
	if rekorBody.Spec.Signature.Content != bundle.Signature {
		return fmt.Errorf("rekor signature does not match bundle signature")
	}

	// Verify public key or certificate matches
	expectedPubKey := bundle.PublicKey
	if bundle.Certificate != "" {
		expectedPubKey = bundle.Certificate // For keyless, Rekor stores the certificate
	}
	if rekorBody.Spec.Signature.PublicKey.Content != expectedPubKey {
		return fmt.Errorf("rekor public key does not match bundle")
	}

	// Verify statement hash
	statementBytes, err := base64.StdEncoding.DecodeString(bundle.StatementBase64)
	if err != nil {
		return fmt.Errorf("failed to decode statement: %w", err)
	}

	computedHash := sha256.Sum256(statementBytes)
	computedHashHex := fmt.Sprintf("%x", computedHash)

	if rekorBody.Spec.Data.Hash.Value != computedHashHex {
		return fmt.Errorf("rekor hash mismatch: expected %s, got %s", computedHashHex, rekorBody.Spec.Data.Hash.Value)
	}

	if rekorBody.Spec.Data.Hash.Algorithm != "sha256" {
		return fmt.Errorf("unexpected hash algorithm: %s (expected sha256)", rekorBody.Spec.Data.Hash.Algorithm)
	}

	return nil
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(publicKeyPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	// Try parsing as PKIX public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		return pubKey, nil
	}

	// Try parsing as ECDSA public key
	ecdsaKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return ecdsaKey, nil
	}

	return nil, fmt.Errorf("failed to parse public key: %w", err)
}

// extractArtifactFromStatement extracts the artifact name from the statement.
func extractArtifactFromStatement(statement []byte) string {
	var s struct {
		Subject []struct {
			Name string `json:"name"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(statement, &s); err == nil && len(s.Subject) > 0 {
		return s.Subject[0].Name
	}
	return "(unknown)"
}

// VerifyKeyPath verifies an attestation using a public key from a file.
// If publicKeyPath is empty, uses the public key embedded in the attestation bundle.
func VerifyKeyPath(ctx context.Context, attestationPath, publicKeyPath, rekorURL string) (*VerificationResult, error) {
	// Read attestation file
	attestationJSON, err := os.ReadFile(attestationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file: %w", err)
	}

	var bundle AttestationBundle
	if err := json.Unmarshal(attestationJSON, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	// If public key path provided, read it and override bundle
	if publicKeyPath != "" {
		publicKeyPEM, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key file: %w", err)
		}
		bundle.PublicKey = string(publicKeyPEM)
		bundle.Certificate = "" // Clear certificate for key-based verification
	} else if bundle.PublicKey == "" && bundle.Certificate == "" {
		return nil, fmt.Errorf("no public key or certificate found in attestation bundle")
	}

	verifier := NewVerifier(rekorURL)
	return verifier.Verify(ctx, &bundle)
}

// VerifyKeyless verifies an attestation using the embedded certificate (keyless).
func VerifyKeyless(ctx context.Context, attestationPath, rekorURL string) (*VerificationResult, error) {
	// Read attestation file
	attestationJSON, err := os.ReadFile(attestationPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read attestation file: %w", err)
	}

	var bundle AttestationBundle
	if err := json.Unmarshal(attestationJSON, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse attestation: %w", err)
	}

	verifier := NewVerifier(rekorURL)
	return verifier.Verify(ctx, &bundle)
}

// Sign method integration: update Statement to include signature in attestation
func createAttestationBundle(statement *signerprovider.Statement, signature *signerprovider.Signature) (*AttestationBundle, error) {
	statementJSON, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}

	bundle := &AttestationBundle{
		StatementBase64: base64.StdEncoding.EncodeToString(statementJSON),
		Signature:       signature.Signature,
		Certificate:     signature.Certificate,
		PublicKey:       signature.PublicKey,
		RekorUUID:       signature.RekorEntry,
		RekorLogIndex:   int(signature.RekorLogIndex),
	}

	return bundle, nil
}
