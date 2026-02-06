package cosign

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/cosign/v2/pkg/signature"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"

	signerprovider "github.com/open-verix/provenix/internal/providers/signer"
)

// Provider implements signer.Provider using Cosign library.
type Provider struct {
	version string
}

// NewProvider creates a new Cosign-based signer provider.
func NewProvider() *Provider {
	return &Provider{
		version: "2.6.2",
	}
}

// Sign creates a cryptographic signature over the statement.
//
// For keyless mode (production):
// - Obtains OIDC token from environment (CI/CD or browser flow)
// - Requests ephemeral certificate from Fulcio
// - Signs statement with ephemeral key
// - Publishes to Rekor transparency log
//
// For key mode (development):
// - Reads private key from opts.KeyPath
// - Signs statement with the key
// - Optionally publishes to Rekor
//
// Data flows entirely in-memory with no temporary files.
func (p *Provider) Sign(ctx context.Context, statement *signerprovider.Statement, opts signerprovider.Options) (*signerprovider.Signature, error) {
	if statement == nil {
		return nil, fmt.Errorf("statement required for signing")
	}

	// Serialize statement to JSON
	statementBytes, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal statement: %w", err)
	}

	var sig *signerprovider.Signature

	switch opts.Mode {
	case signerprovider.ModeKeyless:
		sig, err = p.signKeyless(ctx, statement, statementBytes, opts)
	case signerprovider.ModeKey:
		sig, err = p.signWithKey(ctx, statement, statementBytes, opts)
	default:
		return nil, fmt.Errorf("unsupported signing mode: %s", opts.Mode)
	}

	if err != nil {
		return nil, err
	}

	return sig, nil
}

// signKeyless performs keyless signing using OIDC and Fulcio.
func (p *Provider) signKeyless(ctx context.Context, statement *signerprovider.Statement, payload []byte, opts signerprovider.Options) (*signerprovider.Signature, error) {
	// Step 1: Get OIDC token from CI/CD environment
	oidcProvider := NewOIDCTokenProvider(opts.OIDCClientID)
	idToken, err := oidcProvider.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain OIDC token: %w", err)
	}

	// Step 2: Create Fulcio client for keyless signing
	fulcioClient := NewFulcioClient(opts.FulcioURL, opts.RekorURL)

	// Step 3: Perform keyless signing (ephemeral key + Fulcio cert + Rekor)
	publishRekor := !opts.Local // Skip Rekor in local mode
	keylessSig, err := fulcioClient.SignKeyless(ctx, payload, idToken, publishRekor)
	if err != nil {
		// Check if this is a Rekor-only failure (partial success)
		if isRekorPublishError(err) {
			// Keyless signature succeeded, but Rekor publishing failed
			// Return signature with warning (caller can handle exit code 2)
			sig := &signerprovider.Signature{
				Statement:         statement,
				Signature:         keylessSig.Signature,
				Certificate:       keylessSig.Certificate,
				CertificateChain:  keylessSig.CertificateChain,
				PublicKey:         keylessSig.PublicKey,
				SignedAt:          time.Now().UTC(),
				SignerProvider:    p.Name(),
				SignerVersion:     p.Version(),
				RekorEntry:        "", // Empty indicates publishing failed
				RekorPublishError: err.Error(),
			}
			return sig, fmt.Errorf("signature created but Rekor publishing failed: %w", err)
		}
		return nil, fmt.Errorf("keyless signing failed: %w", err)
	}

	// Step 4: Create complete signature
	sig := &signerprovider.Signature{
		Statement:        statement,
		Signature:        keylessSig.Signature,
		Certificate:      keylessSig.Certificate,
		CertificateChain: keylessSig.CertificateChain,
		PublicKey:        keylessSig.PublicKey,
		SignedAt:         time.Now().UTC(),
		SignerProvider:   p.Name(),
		SignerVersion:    p.Version(),
		RekorEntry:       keylessSig.RekorEntry,
		RekorLogIndex:    keylessSig.RekorLogIndex,
	}

	return sig, nil
}

// isRekorPublishError checks if an error is specifically a Rekor publishing failure.
func isRekorPublishError(err error) bool {
	if err == nil {
		return false
	}
	// Check error message for Rekor-specific failures
	msg := err.Error()
	return contains(msg, "Rekor publishing failed") || contains(msg, "rekor")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// signWithKey performs signing with a local private key.
func (p *Provider) signWithKey(ctx context.Context, statement *signerprovider.Statement, payload []byte, opts signerprovider.Options) (*signerprovider.Signature, error) {
	if opts.KeyPath == "" {
		return nil, fmt.Errorf("key path required for key-based signing")
	}

	// Load signer using SignerFromKeyRef
	signer, err := signature.SignerFromKeyRef(ctx, opts.KeyPath, cosign.PassFunc(func(bool) ([]byte, error) {
		return []byte{}, nil // No passphrase for MVP
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to load signer: %w", err)
	}

	// Sign the payload
	var payloadReader io.Reader = &readerWrapper{data: payload}
	signatureBytes, err := signer.SignMessage(payloadReader, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Get public key
	publicKey, err := signer.PublicKey(signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Read original key for PEM encoding (simplified for MVP)
	keyBytes, err := os.ReadFile(opts.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Use key bytes as-is for MVP (assuming PEM format)
	publicKeyPEM := string(keyBytes)

	sig := &signerprovider.Signature{
		Statement:      statement,
		Signature:      base64.StdEncoding.EncodeToString(signatureBytes),
		PublicKey:      publicKeyPEM,
		SignedAt:       time.Now().UTC(),
		SignerProvider: p.Name(),
		SignerVersion:  p.Version(),
	}

	// Skip Rekor for MVP key-based signing
	_ = publicKey // Used in full implementation

	return sig, nil
}

// readerWrapper wraps a byte slice to implement io.Reader
type readerWrapper struct {
	data   []byte
	offset int
}

func (r *readerWrapper) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

// Verify verifies a signature and returns the verified statement.
//
// For keyless verification:
// - Verifies certificate chain
// - Checks certificate identity and OIDC issuer
// - Verifies Rekor entry
//
// For key-based verification:
// - Verifies signature with public key from opts.PublicKeyPath
//
// TODO: Implement verification (Week 13-16)
func (p *Provider) Verify(ctx context.Context, signature *signerprovider.Signature, opts signerprovider.VerifyOptions) (*signerprovider.Statement, error) {
	if signature == nil {
		return nil, fmt.Errorf("signature required for verification")
	}

	// Stub: Return statement as-is
	// Real implementation would verify the signature cryptographically
	return signature.Statement, nil
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "cosign"
}

// Version returns the provider version.
func (p *Provider) Version() string {
	return p.version
}

// init is removed to avoid duplicate provider registration.
// Providers are now registered manually in cmd/provenix/providers.go
// to prevent SQLite driver conflicts.

// Note: The following imports are available for future implementation:
// - github.com/sigstore/cosign/v2/cmd/cosign/cli/sign
// - github.com/sigstore/cosign/v2/cmd/cosign/cli/verify
// - github.com/sigstore/cosign/v2/pkg/cosign (Cosign operations)
// - github.com/sigstore/cosign/v2/pkg/oidc (OIDC token handling)
// - github.com/sigstore/cosign/v2/pkg/cosign/fulcio (Fulcio integration)
// - github.com/sigstore/cosign/v2/pkg/cosign/env (Environment configuration)
