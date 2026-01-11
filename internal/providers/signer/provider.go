package signer

import (
	"context"
)

// Provider defines the interface for signing and verification providers.
//
// Implementations must:
// - Support keyless signing via OIDC (production mode)
// - Support key-based signing (development/air-gapped mode)
// - Create in-toto attestation statements
// - Publish to Rekor transparency log (unless --skip-transparency)
// - Verify signatures with certificate identity checks
//
// Example implementation: Cosign provider in internal/providers/signer/cosign/
type Provider interface {
	// Sign creates a cryptographic signature over the statement.
	//
	// For keyless mode:
	// - Obtains an OIDC token from the environment (CI/CD or browser flow)
	// - Requests an ephemeral certificate from Fulcio
	// - Signs the statement with the ephemeral key
	// - Publishes to Rekor transparency log
	//
	// For key mode:
	// - Reads the private key from opts.KeyPath
	// - Signs the statement with the key
	// - Optionally publishes to Rekor
	//
	// The ctx parameter is used for cancellation and timeouts.
	//
	// Returns:
	// - *Signature: The signature with certificate/public key and Rekor entry
	// - error: Any error encountered during signing
	Sign(ctx context.Context, statement *Statement, opts Options) (*Signature, error)
	
	// Verify verifies a signature and returns the verified statement.
	//
	// For keyless verification:
	// - Verifies the certificate chain
	// - Checks certificate identity and OIDC issuer
	// - Verifies Rekor entry
	//
	// For key-based verification:
	// - Verifies signature with public key from opts.PublicKeyPath
	//
	// The ctx parameter is used for cancellation and timeouts.
	//
	// Returns:
	// - *Statement: The verified statement
	// - error: Any error encountered during verification
	Verify(ctx context.Context, signature *Signature, opts VerifyOptions) (*Statement, error)
	
	// Name returns the provider name (e.g., "cosign", "sigstore")
	Name() string
	
	// Version returns the provider version (e.g., "2.2.0")
	Version() string
}
