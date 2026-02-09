package cosign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RekorClient handles interactions with the Rekor transparency log.
type RekorClient struct {
	rekorURL string
}

// NewRekorClient creates a new Rekor client.
func NewRekorClient(rekorURL string) *RekorClient {
	if rekorURL == "" {
		rekorURL = "https://rekor.sigstore.dev" // Default public instance
	}
	return &RekorClient{
		rekorURL: rekorURL,
	}
}

// RekorEntryResponse represents a Rekor log entry response.
type RekorEntryResponse struct {
	UUID             string `json:"uuid"`
	Body             string `json:"body"`
	IntegratedTime   int64  `json:"integratedTime"`
	LogIndex         int64  `json:"logIndex"`
	LogID            string `json:"logID"`
	Verification     *RekorVerification `json:"verification,omitempty"`
}

// RekorVerification contains verification information for a Rekor entry.
type RekorVerification struct {
	InclusionProof *InclusionProof `json:"inclusionProof,omitempty"`
	SignedEntryTimestamp string `json:"signedEntryTimestamp,omitempty"`
}

// InclusionProof represents a Merkle tree inclusion proof.
type InclusionProof struct {
	TreeSize  int64    `json:"treeSize"`
	RootHash  string   `json:"rootHash"`
	LogIndex  int64    `json:"logIndex"`
	Hashes    []string `json:"hashes"`
}

// CreateEntry creates a new entry in the Rekor transparency log.
// This is a generic method that can handle different entry types.
func (r *RekorClient) CreateEntry(ctx context.Context, entry map[string]interface{}) (string, int64, error) {
	// Marshal entry to JSON
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return "", 0, fmt.Errorf("failed to marshal Rekor entry: %w", err)
	}

	// Create HTTP request
	url := fmt.Sprintf("%s/api/v1/log/entries", r.rekorURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(entryJSON))
	if err != nil {
		return "", 0, fmt.Errorf("failed to create Rekor request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Send request with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("failed to publish to Rekor: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", 0, fmt.Errorf("Rekor returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	// Rekor returns a map with UUID as key
	var rekorResp map[string]RekorEntryResponse
	if err := json.NewDecoder(resp.Body).Decode(&rekorResp); err != nil {
		return "", 0, fmt.Errorf("failed to decode Rekor response: %w", err)
	}

	// Extract UUID and log index from response
	for uuid, entryData := range rekorResp {
		return uuid, entryData.LogIndex, nil
	}

	return "", 0, fmt.Errorf("no entry UUID in Rekor response")
}

// CreateHashedRekordEntry creates a hashedrekord entry type.
// This is used for arbitrary artifact + signature pairs.
func (r *RekorClient) CreateHashedRekordEntry(ctx context.Context, payload, signature, publicKey []byte) (string, int64, error) {
	// Compute payload hash
	payloadHash := sha256.Sum256(payload)

	entry := map[string]interface{}{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]interface{}{
			"signature": map[string]interface{}{
				"content": base64.StdEncoding.EncodeToString(signature),
				"publicKey": map[string]interface{}{
					"content": base64.StdEncoding.EncodeToString(publicKey),
				},
			},
			"data": map[string]interface{}{
				"hash": map[string]interface{}{
					"algorithm": "sha256",
					"value":     fmt.Sprintf("%x", payloadHash),
				},
			},
		},
	}

	return r.CreateEntry(ctx, entry)
}

// GetEntry retrieves a Rekor entry by UUID.
func (r *RekorClient) GetEntry(ctx context.Context, uuid string) (*RekorEntryResponse, error) {
	url := fmt.Sprintf("%s/api/v1/log/entries/%s", r.rekorURL, uuid)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get Rekor entry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Rekor returned status %d: %s", resp.StatusCode, string(body))
	}

	var rekorResp map[string]RekorEntryResponse
	if err := json.NewDecoder(resp.Body).Decode(&rekorResp); err != nil {
		return nil, fmt.Errorf("failed to decode Rekor response: %w", err)
	}

	if entry, ok := rekorResp[uuid]; ok {
		return &entry, nil
	}

	return nil, fmt.Errorf("entry not found in response")
}

// VerifyInclusionProof verifies the Merkle tree inclusion proof for an entry.
// For MVP, this is a simplified implementation.
// Production would use full Merkle tree verification logic.
func (r *RekorClient) VerifyInclusionProof(ctx context.Context, uuid string) error {
	entry, err := r.GetEntry(ctx, uuid)
	if err != nil {
		return fmt.Errorf("failed to get entry for verification: %w", err)
	}

	if entry.Verification == nil || entry.Verification.InclusionProof == nil {
		return fmt.Errorf("no inclusion proof in entry")
	}

	// In production, verify:
	// 1. Hash chain from leaf to root matches rootHash
	// 2. LogIndex matches entry's index
	// 3. Signed Entry Timestamp (SET) signature is valid

	// For MVP, we just check that the proof exists
	proof := entry.Verification.InclusionProof
	if proof.TreeSize <= 0 {
		return fmt.Errorf("invalid tree size: %d", proof.TreeSize)
	}

	if proof.RootHash == "" {
		return fmt.Errorf("missing root hash")
	}

	if len(proof.Hashes) == 0 {
		return fmt.Errorf("missing proof hashes")
	}

	// Proof exists and has basic validity
	return nil
}
