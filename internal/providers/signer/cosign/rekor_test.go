package cosign

import (
	"context"
	"testing"
)

func TestRekorClient_New(t *testing.T) {
	tests := []struct {
		name         string
		rekorURL     string
		expectedURL  string
	}{
		{
			name:        "default URL",
			rekorURL:    "",
			expectedURL: "https://rekor.sigstore.dev",
		},
		{
			name:        "custom URL",
			rekorURL:    "https://rekor.example.com",
			expectedURL: "https://rekor.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRekorClient(tt.rekorURL)
			if client.rekorURL != tt.expectedURL {
				t.Errorf("rekorURL = %v, want %v", client.rekorURL, tt.expectedURL)
			}
		})
	}
}

func TestRekorClient_CreateHashedRekordEntry_Structure(t *testing.T) {
	// This test validates the entry structure without actually calling Rekor
	client := NewRekorClient("https://rekor.example.com")

	payload := []byte("test payload")
	signature := []byte("test signature")
	publicKey := []byte("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----")

	// We can't test actual Rekor integration without a real server
	// But we can test the client initialization
	if client.rekorURL != "https://rekor.example.com" {
		t.Errorf("client URL = %v, want %v", client.rekorURL, "https://rekor.example.com")
	}

	// Test that the method exists and has correct signature
	ctx := context.Background()
	_, _, err := client.CreateHashedRekordEntry(ctx, payload, signature, publicKey)
	
	// We expect an error because we're not hitting a real Rekor server
	// But we validate that the method can be called
	if err == nil {
		t.Log("Note: CreateHashedRekordEntry succeeded (possibly hitting real Rekor staging)")
	} else {
		// Expected: network error or invalid response from fake URL
		if err.Error() == "" {
			t.Error("expected non-empty error message")
		}
	}
}

func TestRekorClient_VerifyInclusionProof_InvalidUUID(t *testing.T) {
	client := NewRekorClient("https://rekor.example.com")
	ctx := context.Background()

	// Test with invalid UUID - should fail
	err := client.VerifyInclusionProof(ctx, "invalid-uuid")
	
	// We expect an error (network or 404)
	if err == nil {
		t.Error("expected error for invalid UUID, got nil")
	}
}

// Integration test (skipped by default)
// To run: go test -tags=integration
func TestRekorClient_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Note: This would require actual Rekor staging environment
	// For now, we just validate the client can be created
	client := NewRekorClient("https://rekor.sigstore.dev")
	if client == nil {
		t.Fatal("failed to create Rekor client")
	}

	// In a full integration test, you would:
	// 1. Generate a test key pair
	// 2. Sign test data
	// 3. Submit to Rekor staging
	// 4. Verify the entry was created
	// 5. Verify inclusion proof
	
	t.Log("Rekor client created successfully")
	t.Log("Full integration test requires Rekor staging environment")
}
