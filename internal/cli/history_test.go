package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseTime(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"RFC3339", "2024-01-01T00:00:00Z", false},
		{"Today", "today", false},
		{"Yesterday", "yesterday", false},
		{"Weeks ago", "2 weeks ago", false},
		{"Days ago", "5 days ago", false},
		{"Hours ago", "3 hours ago", false},
		{"Invalid", "invalid time", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify result is a valid time
				if result.IsZero() {
					t.Errorf("parseTime(%q) returned zero time", tt.input)
				}

				// For relative times, verify it's before now
				if tt.input != "today" && result.After(now) {
					t.Errorf("parseTime(%q) returned future time: %v", tt.input, result)
				}
			}
		})
	}
}

func TestQueryLocalAttestations(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()
	attestationsDir := filepath.Join(tmpDir, ".provenix", "attestations")
	if err := os.MkdirAll(attestationsDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create test attestation
	statement := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject": []interface{}{
			map[string]interface{}{
				"name": "nginx:latest",
				"digest": map[string]interface{}{
					"sha256": "abc123def456",
				},
			},
		},
		"predicateType": "https://spdx.dev/Document/v2.3",
	}

	statementJSON, _ := json.Marshal(statement)
	payloadB64 := base64.StdEncoding.EncodeToString(statementJSON)

	attestation := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
		"metadata": map[string]interface{}{
			"rekorUUID":     "test-uuid-123",
			"rekorLogIndex": 456,
		},
	}

	attestationJSON, _ := json.Marshal(attestation)
	attestationPath := filepath.Join(attestationsDir, "nginx-latest.json")
	if err := os.WriteFile(attestationPath, attestationJSON, 0644); err != nil {
		t.Fatalf("Failed to write test attestation: %v", err)
	}

	// Change to test directory
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

	// Test query
	records, err := queryLocalAttestations("nginx", nil, nil, false)
	if err != nil {
		t.Fatalf("queryLocalAttestations() error = %v", err)
	}

	if len(records) != 1 {
		t.Fatalf("Expected 1 record, got %d", len(records))
	}

	record := records[0]
	if record.Artifact != "nginx:latest" {
		t.Errorf("Expected artifact 'nginx:latest', got %q", record.Artifact)
	}

	if record.DigestSHA256 != "abc123def456" {
		t.Errorf("Expected digest 'abc123def456', got %q", record.DigestSHA256)
	}

	if !record.Published {
		t.Errorf("Expected Published=true, got false")
	}

	if record.RekorUUID != "test-uuid-123" {
		t.Errorf("Expected RekorUUID 'test-uuid-123', got %q", record.RekorUUID)
	}

	if record.RekorLogIndex != 456 {
		t.Errorf("Expected RekorLogIndex 456, got %d", record.RekorLogIndex)
	}
}

func TestQueryLocalAttestations_TimeFilter(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()
	attestationsDir := filepath.Join(tmpDir, ".provenix", "attestations")
	if err := os.MkdirAll(attestationsDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Create attestation with specific timestamp
	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []interface{}{
			map[string]interface{}{
				"name": "alpine:latest",
				"digest": map[string]interface{}{
					"sha256": "xyz789",
				},
			},
		},
		"predicateType": "https://slsa.dev/provenance/v1",
	}

	statementJSON, _ := json.Marshal(statement)
	payloadB64 := base64.StdEncoding.EncodeToString(statementJSON)

	attestation := map[string]interface{}{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     payloadB64,
	}

	attestationJSON, _ := json.Marshal(attestation)
	attestationPath := filepath.Join(attestationsDir, "alpine-latest.json")
	if err := os.WriteFile(attestationPath, attestationJSON, 0644); err != nil {
		t.Fatalf("Failed to write test attestation: %v", err)
	}

	// Set file modification time to 2 days ago
	twoDaysAgo := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(attestationPath, twoDaysAgo, twoDaysAgo); err != nil {
		t.Fatalf("Failed to set file time: %v", err)
	}

	// Change to test directory
	originalWd, _ := os.Getwd()
	defer os.Chdir(originalWd)
	os.Chdir(tmpDir)

	// Test 1: Query with "since 1 day ago" (should return 0 results)
	oneDayAgo := time.Now().Add(-24 * time.Hour)
	records, err := queryLocalAttestations("", &oneDayAgo, nil, true) // Include unpublished
	if err != nil {
		t.Fatalf("queryLocalAttestations() error = %v", err)
	}

	if len(records) != 0 {
		t.Errorf("Expected 0 records (file is 2 days old), got %d", len(records))
	}

	// Test 2: Query with "since 3 days ago" (should return 1 result)
	threeDaysAgo := time.Now().Add(-72 * time.Hour)
	records, err = queryLocalAttestations("", &threeDaysAgo, nil, true) // Include unpublished
	if err != nil {
		t.Fatalf("queryLocalAttestations() error = %v", err)
	}

	if len(records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(records))
	}
}

func TestDeduplicateRecords(t *testing.T) {
	now := time.Now()

	records := []AttestationRecord{
		{Artifact: "nginx:latest", DigestSHA256: "abc123", Timestamp: now},
		{Artifact: "nginx:latest", DigestSHA256: "abc123", Timestamp: now}, // Duplicate
		{Artifact: "alpine:latest", DigestSHA256: "def456", Timestamp: now},
	}

	unique := deduplicateRecords(records)

	if len(unique) != 2 {
		t.Errorf("Expected 2 unique records, got %d", len(unique))
	}
}

func TestBase64DecodeString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"Valid", base64.StdEncoding.EncodeToString([]byte("test")), "test", false},
		{"Invalid", "not-base64!!!", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64DecodeString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64DecodeString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("base64DecodeString() = %v, want %v", got, tt.want)
			}
		})
	}
}
