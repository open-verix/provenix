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

// SearchByArtifactDigest searches Rekor for entries matching an artifact digest.
// Returns a list of matching entries, sorted by newest first.
func (r *RekorClient) SearchByArtifactDigest(ctx context.Context, digest string) ([]*RekorEntryResponse, error) {
	// Rekor search API endpoint
	url := fmt.Sprintf("%s/api/v1/index/retrieve", r.rekorURL)

	// Build search query
	searchQuery := map[string]interface{}{
		"hash": fmt.Sprintf("sha256:%s", digest),
	}

	queryJSON, err := json.Marshal(searchQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal search query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(queryJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search Rekor: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Rekor search returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response - returns list of UUIDs
	var uuids []string
	if err := json.NewDecoder(resp.Body).Decode(&uuids); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	if len(uuids) == 0 {
		return nil, nil // No entries found
	}

	// Fetch full entry details for each UUID
	entries := make([]*RekorEntryResponse, 0, len(uuids))
	for _, uuid := range uuids {
		entry, err := r.GetEntry(ctx, uuid)
		if err != nil {
			// Log warning but continue with other entries
			continue
		}
		entries = append(entries, entry)
	}

	// Sort by integrated time (newest first)
	// Simple bubble sort for small datasets (MVP)
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].IntegratedTime < entries[j].IntegratedTime {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	return entries, nil
}

// ExtractAttestationFromEntry extracts attestation data from a Rekor entry.
// Returns the in-toto statement, signature, and public key/certificate.
func (r *RekorClient) ExtractAttestationFromEntry(entry *RekorEntryResponse) (*AttestationBundle, error) {
	// Decode base64 body
	bodyBytes, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode entry body: %w", err)
	}

	// Parse entry body as JSON
	var bodyData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
		return nil, fmt.Errorf("failed to parse entry body: %w", err)
	}

	// Extract spec field
	spec, ok := bodyData["spec"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid entry format: missing spec")
	}

	// Extract signature data
	signatureData, ok := spec["signature"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid entry format: missing signature")
	}

	signatureContent, ok := signatureData["content"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid entry format: missing signature content")
	}

	// Extract public key or certificate
	var publicKey, certificate string
	if pubKeyData, ok := signatureData["publicKey"].(map[string]interface{}); ok {
		if content, ok := pubKeyData["content"].(string); ok {
			publicKey = content
		}
	}
	if certData, ok := signatureData["certificate"].(string); ok {
		certificate = certData
	}

	// Extract payload (the in-toto statement)
	dataField, ok := spec["data"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid entry format: missing data")
	}

	// The actual statement might be in different formats depending on entry type
	// For hashedrekord, we need to reconstruct from hash
	// For intoto, the statement is directly included
	var statementBase64 string
	
	// Try to find statement in various locations
	if content, ok := dataField["content"].(string); ok {
		statementBase64 = content
	} else if _, ok := dataField["hash"].(map[string]interface{}); ok {
		// For hashedrekord, we don't have the full statement in Rekor
		// This is a limitation - we can only verify, not retrieve the full attestation
		return nil, fmt.Errorf("hashedrekord entries don't contain full attestation data")
	}

	bundle := &AttestationBundle{
		StatementBase64: statementBase64,
		Signature:       signatureContent,
		PublicKey:       publicKey,
		Certificate:     certificate,
		RekorUUID:       entry.UUID,
		RekorLogIndex:   int(entry.LogIndex),
	}

	return bundle, nil
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
