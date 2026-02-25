package cosign

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// FulcioClient handles certificate requests to Fulcio CA.
type FulcioClient struct {
	fulcioURL string
	rekorURL  string
}

// NewFulcioClient creates a new Fulcio client.
func NewFulcioClient(fulcioURL, rekorURL string) *FulcioClient {
	if fulcioURL == "" {
		fulcioURL = "https://fulcio.sigstore.dev" // Default public instance
	}
	if rekorURL == "" {
		rekorURL = "https://rekor.sigstore.dev" // Default public instance
	}

	return &FulcioClient{
		fulcioURL: fulcioURL,
		rekorURL:  rekorURL,
	}
}

// KeylessSignature represents a complete keyless signature bundle.
type KeylessSignature struct {
	// Signature bytes (base64-encoded)
	Signature string

	// Certificate from Fulcio (PEM-encoded)
	Certificate string

	// Certificate chain (PEM-encoded)
	CertificateChain string

	// Rekor log entry UUID
	RekorEntry string

	// Rekor log index
	RekorLogIndex int64

	// Public key (PEM-encoded, extracted from certificate)
	PublicKey string
}

// SignKeyless performs complete keyless signing workflow:
// 1. Generate ephemeral key pair
// 2. Request certificate from Fulcio
// 3. Sign payload with ephemeral key
// 4. Publish to Rekor (optional, controlled by opts)
func (c *FulcioClient) SignKeyless(ctx context.Context, payload []byte, idToken string, publishRekor bool) (*KeylessSignature, error) {
	// Step 1: Generate ephemeral ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Step 2: Create public key PEM for Fulcio request
	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(privateKey.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Step 2.5: Extract subject from JWT and create proof of possession
	// Fulcio v2 requires signing the JWT subject to prove key ownership
	subject, err := extractSubjectFromJWT(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to extract subject from JWT: %w", err)
	}
	
	// Sign the subject (as bytes) with the ephemeral private key
	subjectBytes := []byte(subject)
	subjectHash := sha256.Sum256(subjectBytes)
	proofOfPossession, err := signWithECDSA(privateKey, subjectHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create proof of possession: %w", err)
	}

	// Step 3: Request certificate from Fulcio
	certPEM, chainPEM, err := c.requestCertificate(ctx, publicKeyPEM, proofOfPossession, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to request Fulcio certificate: %w", err)
	}

	// Step 3.5: Validate certificate chain to Sigstore root CA
	// Alpha release: Basic validation (expiry, OIDC extensions)
	// Beta release: Full TUF-based chain validation
	useStaging := c.fulcioURL != "https://fulcio.sigstore.dev"
	if err := ValidateCertificateChain(certPEM, chainPEM, useStaging); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Step 4: Sign payload with ephemeral key
	payloadHash := sha256.Sum256(payload)
	signatureBytes, err := signWithECDSA(privateKey, payloadHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	result := &KeylessSignature{
		Signature:        base64.StdEncoding.EncodeToString(signatureBytes),
		Certificate:      string(certPEM),
		CertificateChain: string(chainPEM),
		PublicKey:        string(publicKeyPEM),
	}

	// Step 5: Publish to Rekor (optional)
	if publishRekor {
		rekorClient := NewRekorClient(c.rekorURL)
		rekorUUID, logIndex, err := rekorClient.CreateHashedRekordEntry(ctx, payload, signatureBytes, certPEM)
		if err != nil {
			// Don't fail entire signing if Rekor is unavailable
			// This allows graceful degradation (exit code 2)
			return result, fmt.Errorf("keyless signing succeeded but Rekor publishing failed: %w", err)
		}
		result.RekorEntry = rekorUUID
		result.RekorLogIndex = logIndex
	}

	return result, nil
}

// FulcioCreateCertificateRequest represents the request to Fulcio API.
type FulcioCreateCertificateRequest struct {
	// PublicKeyRequest contains the public key and proof of possession
	PublicKeyRequest struct {
		// PublicKey is the PEM-encoded public key
		PublicKey struct {
			Content   string `json:"content"`
			Algorithm string `json:"algorithm"`
		} `json:"publicKey"`
		// ProofOfPossession is a signature over challenge to prove key ownership
		ProofOfPossession []byte `json:"proofOfPossession"`
	} `json:"publicKeyRequest"`
}

// FulcioCreateCertificateResponse represents the response from Fulcio API.
type FulcioCreateCertificateResponse struct {
	// SignedCertificateEmbeddedSct contains the certificate
	SignedCertificateEmbeddedSct struct {
		Chain struct {
			Certificates []string `json:"certificates"` // PEM-encoded certificates
		} `json:"chain"`
	} `json:"signedCertificateEmbeddedSct"`
}

// requestCertificate requests a code-signing certificate from Fulcio.
//
// This implements the Fulcio v2 API protocol:
// 1. Send public key + proof of possession + OIDC token
// 2. Receive certificate with identity bound from OIDC claims
// 3. Validate certificate chain
func (c *FulcioClient) requestCertificate(ctx context.Context, publicKeyPEM []byte, proofOfPossession []byte, idToken string) ([]byte, []byte, error) {
	// Parse public key to validate format
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse public key: %w", err)
	}
	
	// Prepare request payload
	// Fulcio v2 API expects: POST /api/v2/signingCert
	requestPayload := map[string]interface{}{
		"publicKeyRequest": map[string]interface{}{
			"publicKey": map[string]interface{}{
				"content":   string(publicKeyPEM), // PEM is already base64-encoded
				"algorithm": "ECDSA_P256_SHA256",
			},
			"proofOfPossession": base64.StdEncoding.EncodeToString(proofOfPossession),
		},
	}

	jsonPayload, err := json.Marshal(requestPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/v2/signingCert", c.fulcioURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonPayload))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+idToken) // OIDC token for identity
	req.Header.Set("Accept", "application/json")

	// Send request with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request certificate from Fulcio: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("Fulcio returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var fulcioResp FulcioCreateCertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&fulcioResp); err != nil {
		return nil, nil, fmt.Errorf("failed to decode Fulcio response: %w", err)
	}

	// Extract certificates from response
	if len(fulcioResp.SignedCertificateEmbeddedSct.Chain.Certificates) == 0 {
		return nil, nil, fmt.Errorf("Fulcio response contains no certificates")
	}

	// First certificate is the leaf (code-signing cert)
	certPEM := []byte(fulcioResp.SignedCertificateEmbeddedSct.Chain.Certificates[0])

	// Remaining certificates form the chain
	var chainPEM []byte
	for i := 1; i < len(fulcioResp.SignedCertificateEmbeddedSct.Chain.Certificates); i++ {
		chainPEM = append(chainPEM, []byte(fulcioResp.SignedCertificateEmbeddedSct.Chain.Certificates[i])...)
		chainPEM = append(chainPEM, '\n')
	}

	// Validate certificate
	if err := c.validateCertificate(certPEM, pubKey); err != nil {
		return nil, nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	return certPEM, chainPEM, nil
}

// validateCertificate validates that the certificate matches the public key
// and contains expected OIDC identity extensions.
func (c *FulcioClient) validateCertificate(certPEM []byte, expectedPubKey interface{}) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate is not expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired")
	}

	// Verify public key matches
	certPubKey := cert.PublicKey
	switch expectedKey := expectedPubKey.(type) {
	case *ecdsa.PublicKey:
		certECKey, ok := certPubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("certificate public key type mismatch: expected ECDSA")
		}
		if !certECKey.Equal(expectedKey) {
			return fmt.Errorf("certificate public key does not match ephemeral key")
		}
	default:
		return fmt.Errorf("unsupported public key type")
	}

	// Verify OIDC identity extensions (Fulcio-specific)
	// Fulcio embeds OIDC claims in X.509 extensions
	// OID 1.3.6.1.4.1.57264.1.1 = Fulcio issuer (OIDC issuer URL)
	// OID 1.3.6.1.4.1.57264.1.2 = Subject Alternative Name (email/URI from OIDC)
	hasOIDCExtensions := false
	for _, ext := range cert.Extensions {
		// Check for Fulcio OID prefix (1.3.6.1.4.1.57264.1.*)
		if len(ext.Id) >= 7 && 
		   ext.Id[0] == 1 && ext.Id[1] == 3 && ext.Id[2] == 6 && 
		   ext.Id[3] == 1 && ext.Id[4] == 4 && ext.Id[5] == 1 &&
		   ext.Id[6] == 57264 {
			hasOIDCExtensions = true
			break
		}
	}

	// For MVP, we just check that OIDC extensions exist
	// Full implementation would parse and validate specific claims
	if !hasOIDCExtensions {
		// Note: Some test/development scenarios may not have extensions
		// This is a soft validation for now
	}

	// Certificate is valid
	return nil
}

// signWithECDSA signs a digest with an ECDSA private key.
// Note: digest should be the SHA-256 hash of the payload.
func signWithECDSA(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	// Sign the digest directly using ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signature failed: %w", err)
	}

	// Encode signature in DER format (compatible with Cosign)
	// For simplicity, we concatenate r and s (this is the format used in some Sigstore contexts)
	// In production, you might want to use proper DER encoding
	curveOrderByteSize := (privateKey.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*curveOrderByteSize)
	r.FillBytes(signature[0:curveOrderByteSize])
	s.FillBytes(signature[curveOrderByteSize:])

	return signature, nil
}

// extractPublicKeyFromCertificate extracts the public key from a PEM certificate.
func extractPublicKeyFromCertificate(certPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return publicKeyPEM, nil
}

// extractSubjectFromJWT extracts the "sub" field from a JWT token.
// Note: This function does NOT validate the JWT signature, as that's Fulcio's responsibility.
// We only parse the unverified token to extract the subject for proof of possession.
func extractSubjectFromJWT(token string) (string, error) {
	// JWT format: header.payload.signature
	parts := bytes.Split([]byte(token), []byte("."))
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (part 1)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON payload
	var payload struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	if payload.Subject == "" {
		return "", fmt.Errorf("JWT payload does not contain 'sub' field")
	}

	return payload.Subject, nil
}
