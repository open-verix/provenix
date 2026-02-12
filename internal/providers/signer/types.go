package signer

import (
	"encoding/json"
	"time"
)

// SigningMode represents the type of signing to perform.
type SigningMode string

const (
	// ModeKeyless uses OIDC-based keyless signing (default, production-recommended)
	ModeKeyless SigningMode = "keyless"
	
	// ModeKey uses a local private key (development/air-gapped only)
	ModeKey SigningMode = "key"
)

// Statement represents an in-toto attestation statement.
// This follows the in-toto attestation specification v0.1.0.
type Statement struct {
	// Type is always "https://in-toto.io/Statement/v0.1"
	Type string `json:"_type"`
	
	// Subject identifies what is being attested
	Subject []Subject `json:"subject"`
	
	// PredicateType identifies the type of predicate
	// For Provenix: "https://provenix.dev/attestation/v1"
	PredicateType string `json:"predicateType"`
	
	// Predicate contains the actual attestation content
	Predicate json.RawMessage `json:"predicate"`

	// RawJSON contains the raw JSON bytes of the statement (for verification)
	RawJSON json.RawMessage `json:"-"`
}

// Subject identifies an artifact in an attestation.
type Subject struct {
	// Name is the artifact identifier (e.g., image reference, file path)
	Name string `json:"name"`
	
	// Digest contains cryptographic hashes of the artifact
	Digest map[string]string `json:"digest"`
}

// Signature represents a cryptographic signature over a statement.
type Signature struct {
	// Statement is the signed in-toto statement
	Statement *Statement `json:"statement"`
	
	// Signature is the base64-encoded signature bytes
	Signature string `json:"signature"`
	
	// Certificate is the signing certificate (for keyless mode)
	Certificate string `json:"certificate,omitempty"`
	
	// CertificateChain is the full certificate chain (for keyless mode)
	CertificateChain string `json:"certificate_chain,omitempty"`
	
	// Chain is the certificate chain (for keyless mode, backwards compat)
	Chain []string `json:"chain,omitempty"`
	
	// PublicKey is the public key (for key mode)
	PublicKey string `json:"public_key,omitempty"`
	
	// RekorEntry is the Rekor transparency log entry UUID
	RekorEntry string `json:"rekor_entry,omitempty"`
	
	// RekorUUID is an alias for RekorEntry (for compatibility)
	RekorUUID string `json:"rekor_uuid,omitempty"`
	
	// RekorLogIndex is the log index in Rekor
	RekorLogIndex int64 `json:"rekor_log_index,omitempty"`
	
	// RekorPublishError indicates Rekor publishing failed (partial success)
	RekorPublishError string `json:"rekor_publish_error,omitempty"`
	
	// SignedAt is the timestamp when the signature was created
	SignedAt time.Time `json:"signed_at"`
	
	// SignerProvider is the name of the signer provider
	SignerProvider string `json:"signer_provider"`
	
	// SignerVersion is the version of the signer provider
	SignerVersion string `json:"signer_version"`
}

// Options configures signing behavior.
type Options struct {
	// Mode specifies the signing mode (keyless or key)
	Mode SigningMode
	
	// KeyPath is the path to the private key file (required for key mode)
	KeyPath string
	
	// FulcioURL is the Fulcio certificate authority URL (for keyless mode)
	FulcioURL string
	
	// RekorURL is the Rekor transparency log URL
	RekorURL string
	
	// OIDCIssuer is the OIDC issuer URL (for keyless mode)
	OIDCIssuer string
	
	// OIDCClientID is the OIDC client ID (for keyless mode)
	OIDCClientID string
	
	// SkipTransparency skips publishing to Rekor (air-gapped mode)
	SkipTransparency bool
	
	// Local indicates local-only mode (no Rekor publishing)
	Local bool
}

// DefaultOptions returns the default signing options.
func DefaultOptions() Options {
	return Options{
		Mode:             ModeKeyless,
		KeyPath:          "",
		FulcioURL:        "https://fulcio.sigstore.dev",
		RekorURL:         "https://rekor.sigstore.dev",
		OIDCIssuer:       "",
		OIDCClientID:     "sigstore",
		SkipTransparency: false,
	}
}

// Validate checks if the options are valid.
func (o Options) Validate() error {
	if o.Mode == ModeKey && o.KeyPath == "" {
		return &InvalidOptionsError{Message: "key mode requires --key-path"}
	}
	
	if o.Mode == ModeKeyless && o.FulcioURL == "" {
		return &InvalidOptionsError{Message: "keyless mode requires Fulcio URL"}
	}
	
	if !o.SkipTransparency && o.RekorURL == "" {
		return &InvalidOptionsError{Message: "Rekor URL required when transparency is enabled"}
	}
	
	return nil
}

// InvalidOptionsError is returned when signing options are invalid.
type InvalidOptionsError struct {
	Message string
}

func (e *InvalidOptionsError) Error() string {
	return "invalid signing options: " + e.Message
}

// VerifyOptions configures signature verification behavior.
type VerifyOptions struct {
	// CertificateIdentity is the expected certificate identity (for keyless verification)
	CertificateIdentity string
	
	// CertificateOIDCIssuer is the expected OIDC issuer (for keyless verification)
	CertificateOIDCIssuer string
	
	// PublicKeyPath is the path to the public key file (for key-based verification)
	PublicKeyPath string
	
	// RekorURL is the Rekor transparency log URL
	RekorURL string
	
	// SkipTransparency skips Rekor verification (air-gapped mode)
	SkipTransparency bool
}

// DefaultVerifyOptions returns the default verification options.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		CertificateIdentity:   "",
		CertificateOIDCIssuer: "",
		PublicKeyPath:         "",
		RekorURL:              "https://rekor.sigstore.dev",
		SkipTransparency:      false,
	}
}
