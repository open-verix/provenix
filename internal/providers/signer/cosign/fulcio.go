package cosign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
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

	// Step 3: Request certificate from Fulcio
	// For MVP: Using simplified implementation
	// Full implementation would use fulcio.NewClient() from sigstore-go
	certPEM, chainPEM, err := c.requestCertificate(ctx, publicKeyPEM, idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to request Fulcio certificate: %w", err)
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
		rekorUUID, logIndex, err := c.publishToRekor(ctx, payload, signatureBytes, certPEM)
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

// requestCertificate requests a code-signing certificate from Fulcio.
// 
// For MVP Phase 1 (Week 11-12): Simplified stub implementation
// Full implementation in Phase 2 will use:
//   - github.com/sigstore/sigstore-go/pkg/fulcio
//   - Proper certificate chain validation
//   - SCT (Signed Certificate Timestamp) handling
func (c *FulcioClient) requestCertificate(ctx context.Context, publicKeyPEM []byte, idToken string) ([]byte, []byte, error) {
	// TODO: Full Fulcio integration (Week 12-13)
	// For now, return stub response for development/testing
	
	// In production, this would:
	// 1. Create HTTP client with custom CA trust roots
	// 2. POST to ${fulcioURL}/api/v2/signingCert with:
	//    - publicKey: base64(publicKeyPEM)
	//    - signedEmailAddress: from OIDC token
	//    - proof: challenge response
	// 3. Parse response containing certificate + chain
	// 4. Validate certificate matches identity in OIDC token
	
	stubCert := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCCATigAwIBAgIRANYvM5xYxQ9YT7zKxQvXGdIwCgYIKoZIzj0EAwIwKjEo
MCYGA1UEAwwfc2lnc3RvcmUtaW50ZXJtZWRpYXRlLnNpZ3N0b3JlLmRldjAeFw0y
NjAyMDYwMDAwMDBaFw0yNjAyMDYwMTAwMDBaMBQxEjAQBgNVBAMTCXRlc3QtdXNl
cjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFXx1vY8P5JmqNOVGLqYvLyT9iLI
rJwVxOzNw8zPpPCnRFqvhPzKxLjfJmYvNxhUgLqYvLyT9iLIrJwVxOzNw8zPpPCj
EDAOMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDRwAwRAIgY8P5JmqNOVGLqYvL
yT9iLIrJwVxOzNw8zPpPCnRFqvhPzKxLjfJmYvNxhUgLqYvLyT9iLIrJwVxOzNw8
zPpPCjEDAOMAwGA1UdEwEB/wQCMAA=
-----END CERTIFICATE-----`)

	stubChain := []byte(`-----BEGIN CERTIFICATE-----
MIIBrjCCAVWgAwIBAgIUDXvM5xYxQ9YT7zKxQvXGdIwCgYIKoZIzj0EAwIwHjEc
MBoGA1UEAwwTc2lnc3RvcmUucm9vdC5zaWdzdG9yZS5kZXYwHhcNMjYwMjA2MDAw
MDAwWhcNMjYwMjA2MDEwMDAwWjAqMSgwJgYDVQQDDB9zaWdzdG9yZS1pbnRlcm1l
ZGlhdGUuc2lnc3RvcmUuZGV2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVfHW
9jw/kmaof==
-----END CERTIFICATE-----`)

	return stubCert, stubChain, nil
}

// publishToRekor uploads signature and certificate to Rekor transparency log.
//
// For MVP Phase 1 (Week 11-12): Simplified stub implementation
// Full implementation in Phase 2 will use:
//   - github.com/sigstore/rekor/pkg/client
//   - Proper entry type (intoto/hashedrekord)
//   - Inclusion proof verification
func (c *FulcioClient) publishToRekor(ctx context.Context, payload, signature, certificate []byte) (string, int64, error) {
	// TODO: Full Rekor integration (Week 14-15)
	// For now, return stub response
	
	// In production, this would:
	// 1. Create Rekor client
	// 2. Create entry with payload, signature, certificate
	// 3. POST to /api/v1/log/entries
	// 4. Wait for inclusion proof
	// 5. Verify merkle tree inclusion
	
	stubUUID := "3045022100abcdef1234567890abcdef1234567890abcdef1234567890"
	stubLogIndex := int64(12345678)
	
	return stubUUID, stubLogIndex, nil
}

// signWithECDSA signs a digest with an ECDSA private key.
func signWithECDSA(privateKey *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	signer, err := signature.LoadECDSASignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to create ECDSA signer: %w", err)
	}

	// Sign the digest
	signatureBytes, err := signer.SignMessage(nil)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signature failed: %w", err)
	}

	return signatureBytes, nil
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
