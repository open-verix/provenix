package mock

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
	
	"github.com/open-verix/provenix/internal/providers/signer"
)

// Provider is a mock signer provider for testing.
type Provider struct {
	// SignFunc allows tests to customize the Sign behavior
	SignFunc func(ctx context.Context, statement *signer.Statement, opts signer.Options) (*signer.Signature, error)
	
	// VerifyFunc allows tests to customize the Verify behavior
	VerifyFunc func(ctx context.Context, signature *signer.Signature, opts signer.VerifyOptions) (*signer.Statement, error)
	
	// NameValue is the provider name returned by Name()
	NameValue string
	
	// VersionValue is the provider version returned by Version()
	VersionValue string
}

// NewProvider creates a new mock signer provider with default behavior.
func NewProvider() *Provider {
	return &Provider{
		NameValue:    "mock",
		VersionValue: "1.0.0",
		SignFunc:     defaultSign,
		VerifyFunc:   defaultVerify,
	}
}

// Sign creates a mock signature for testing.
func (p *Provider) Sign(ctx context.Context, statement *signer.Statement, opts signer.Options) (*signer.Signature, error) {
	if p.SignFunc != nil {
		return p.SignFunc(ctx, statement, opts)
	}
	
	return defaultSign(ctx, statement, opts)
}

// Verify verifies a mock signature for testing.
func (p *Provider) Verify(ctx context.Context, signature *signer.Signature, opts signer.VerifyOptions) (*signer.Statement, error) {
	if p.VerifyFunc != nil {
		return p.VerifyFunc(ctx, signature, opts)
	}
	
	return defaultVerify(ctx, signature, opts)
}

// Name returns the provider name.
func (p *Provider) Name() string {
	if p.NameValue != "" {
		return p.NameValue
	}
	return "mock"
}

// Version returns the provider version.
func (p *Provider) Version() string {
	if p.VersionValue != "" {
		return p.VersionValue
	}
	return "1.0.0"
}

// defaultSign is the default mock signing function.
func defaultSign(ctx context.Context, statement *signer.Statement, opts signer.Options) (*signer.Signature, error) {
	// Check context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	// Skip validation for mock - we accept any options for testing
	
	// Generate a random mock signature
	sigBytes := make([]byte, 64)
	if _, err := rand.Read(sigBytes); err != nil {
		return nil, fmt.Errorf("failed to generate mock signature: %w", err)
	}
	
	signature := &signer.Signature{
		Statement:      statement,
		Signature:      base64.StdEncoding.EncodeToString(sigBytes),
		SignedAt:       time.Now(),
		SignerProvider: "mock",
		SignerVersion:  "1.0.0",
	}
	
	// Add mode-specific fields
	if opts.Mode == signer.ModeKeyless {
		signature.Certificate = "-----BEGIN CERTIFICATE-----\nMOCK CERTIFICATE\n-----END CERTIFICATE-----"
		signature.Chain = []string{
			"-----BEGIN CERTIFICATE-----\nMOCK CHAIN CERT 1\n-----END CERTIFICATE-----",
			"-----BEGIN CERTIFICATE-----\nMOCK CHAIN CERT 2\n-----END CERTIFICATE-----",
		}
		
		if !opts.SkipTransparency {
			signature.RekorEntry = "https://rekor.sigstore.dev/api/v1/log/entries/mock-entry-id"
		}
	} else {
		signature.PublicKey = "-----BEGIN PUBLIC KEY-----\nMOCK PUBLIC KEY\n-----END PUBLIC KEY-----"
	}
	
	return signature, nil
}

// defaultVerify is the default mock verification function.
func defaultVerify(ctx context.Context, signature *signer.Signature, opts signer.VerifyOptions) (*signer.Statement, error) {
	// Check context cancellation
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	// In a real implementation, this would verify the signature
	// For mock, we just return the statement if it exists
	if signature == nil || signature.Statement == nil {
		return nil, fmt.Errorf("invalid signature: missing statement")
	}
	
	// Mock verification always succeeds
	return signature.Statement, nil
}
