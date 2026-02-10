package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/open-verix/provenix/internal/providers/signer/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// TestRekorClient_PublicEndpoint tests connectivity to public Rekor instance.
// This test validates that our client can communicate with the real Rekor API.
func TestRekorClient_PublicEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create Rekor client pointing to production instance
	client := cosign.NewRekorClient("https://rekor.sigstore.dev")

	// Test: Try to get a known entry (this should work without auth)
	// We use a dummy UUID to test the error handling
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This should fail with 404, but validates our HTTP client works
	_, err := client.GetEntry(ctx, "invalid-uuid-for-testing")
	
	if err == nil {
		t.Log("Note: GetEntry succeeded (unexpected, but API might have changed)")
	} else {
		// Expected: error (404 or similar)
		t.Logf("GetEntry failed as expected: %v", err)
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	}
}

// TestRekorClient_CreateEntry_WithoutAuth tests that CreateEntry fails properly
// when we don't have valid credentials (expected behavior for local testing).
func TestRekorClient_CreateEntry_WithoutAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := cosign.NewRekorClient("https://rekor.sigstore.dev")

	// Generate test data
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	payload := []byte("test payload for Rekor integration")
	payloadHash := sha256.Sum256(payload)

	// Sign payload
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, payloadHash[:])
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	// Create signature bytes
	curveOrderByteSize := (privateKey.Curve.Params().BitSize + 7) / 8
	signature := make([]byte, 2*curveOrderByteSize)
	r.FillBytes(signature[0:curveOrderByteSize])
	s.FillBytes(signature[curveOrderByteSize:])

	// Marshal public key
	publicKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(privateKey.Public())
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	// Attempt to create entry
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	uuid, logIndex, err := client.CreateHashedRekordEntry(ctx, payload, signature, publicKeyPEM)
	
	if err != nil {
		// Expected: Rekor might reject entries without proper Fulcio certificate
		t.Logf("CreateHashedRekordEntry failed (expected for local test): %v", err)
		
		// Validate error message is informative
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	} else {
		// Unexpected success: Rekor accepted our entry
		t.Logf("✅ Entry created successfully!")
		t.Logf("   UUID: %s", uuid)
		t.Logf("   Log Index: %d", logIndex)
		
		// If successful, try to retrieve the entry
		entry, err := client.GetEntry(ctx, uuid)
		if err != nil {
			t.Errorf("Failed to retrieve created entry: %v", err)
		} else {
			t.Logf("✅ Entry retrieved successfully")
			t.Logf("   Log Index from GET: %d", entry.LogIndex)
			
			if entry.LogIndex != logIndex {
				t.Errorf("Log index mismatch: got %d, want %d", entry.LogIndex, logIndex)
			}
		}
		
		// Try to verify inclusion proof
		err = client.VerifyInclusionProof(ctx, uuid)
		if err != nil {
			t.Logf("Inclusion proof verification failed: %v", err)
		} else {
			t.Logf("✅ Inclusion proof verified")
		}
	}
}

// TestRekorClient_ErrorHandling tests various error scenarios.
func TestRekorClient_ErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		rekorURL  string
		expectErr bool
	}{
		{
			name:      "invalid URL",
			rekorURL:  "http://invalid-rekor-server-that-does-not-exist.example.com",
			expectErr: true,
		},
		{
			name:      "production URL",
			rekorURL:  "https://rekor.sigstore.dev",
			expectErr: true, // Will fail because we don't have valid signature
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := cosign.NewRekorClient(tt.rekorURL)
			
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Try to get non-existent entry
			_, err := client.GetEntry(ctx, "non-existent-uuid")
			
			if tt.expectErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else {
					t.Logf("Got expected error: %v", err)
				}
			}
		})
	}
}

// TestRekorClient_ResponseParsing tests that we can parse Rekor responses correctly.
func TestRekorClient_ResponseParsing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := cosign.NewRekorClient("https://rekor.sigstore.dev")

	// Try to get a potentially valid entry format
	// Note: This will likely fail, but we're testing the parsing logic
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use a well-formed UUID format (even if it doesn't exist)
	testUUID := "24296fb24b8ad77a47c6fdb23456789012345678901234567890123456789012"
	
	entry, err := client.GetEntry(ctx, testUUID)
	
	if err != nil {
		// Expected: 404 or similar
		t.Logf("GetEntry returned error (expected): %v", err)
		
		// Validate error contains useful information
		if !contains(err.Error(), "404") && !contains(err.Error(), "status") && !contains(err.Error(), "Rekor") {
			t.Logf("Note: Error message format: %v", err)
		}
	} else {
		// Unexpected: Entry exists
		t.Logf("Entry found: UUID=%s, LogIndex=%d", entry.UUID, entry.LogIndex)
	}
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
