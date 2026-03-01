package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	historyArtifact    string
	historySince       string
	historyUntil       string
	historyLocalOnly   bool
	historyUnpublished bool
	historyFormat      string
	historyLimit       int
)

var historyCmd = &cobra.Command{
	Use:   "history [artifact]",
	Short: "Query historical attestations for artifacts",
	Long: `Query historical attestations from Rekor transparency log and local storage.

This command searches for past attestations of software artifacts:
1. Rekor Transparency Log (Sigstore public registry for keyless signatures)
2. Local attestations (.provenix/attestations/ directory)

NOT GitHub commit/workflow history. GitHub's role is as identity provider
(OIDC issuer) for keyless signing, not as data source for queries.

Examples:
  # Query all attestations for an artifact
  provenix history nginx:latest

  # Query with time range
  provenix history nginx:latest --since "2024-01-01" --until "2024-12-31"

  # Query only local attestations (not published to Rekor)
  provenix history nginx:latest --local-only

  # Query unpublished attestations (exit code 2 scenarios)
  provenix history nginx:latest --unpublished

  # Output as JSON
  provenix history nginx:latest --format json

  # Limit results
  provenix history nginx:latest --limit 10`,
	Args: cobra.MaximumNArgs(1),
	RunE: runHistory,
}

func init() {
	historyCmd.Flags().StringVar(&historyArtifact, "artifact", "", "Artifact to query (can also use positional argument)")
	historyCmd.Flags().StringVar(&historySince, "since", "", "Start time (RFC3339 or relative: '2 weeks ago', 'yesterday')")
	historyCmd.Flags().StringVar(&historyUntil, "until", "", "End time (RFC3339 or relative: '1 week ago', 'today')")
	historyCmd.Flags().BoolVar(&historyLocalOnly, "local-only", false, "Query only local attestations (skip Rekor)")
	historyCmd.Flags().BoolVar(&historyUnpublished, "unpublished", false, "Include unpublished attestations (exit code 2)")
	historyCmd.Flags().StringVar(&historyFormat, "format", "table", "Output format: table, json, markdown")
	historyCmd.Flags().IntVar(&historyLimit, "limit", 100, "Maximum number of results to return")
}

// AttestationRecord represents a historical attestation record.
type AttestationRecord struct {
	Artifact        string    `json:"artifact"`
	DigestSHA256    string    `json:"digest_sha256"`
	Timestamp       time.Time `json:"timestamp"`
	Source          string    `json:"source"` // "rekor" or "local"
	RekorUUID       string    `json:"rekor_uuid,omitempty"`
	RekorLogIndex   int64     `json:"rekor_log_index,omitempty"`
	LocalPath       string    `json:"local_path,omitempty"`
	Published       bool      `json:"published"`
	PredicateType   string    `json:"predicate_type,omitempty"`
	CertSubject     string    `json:"cert_subject,omitempty"`
	CertIssuer      string    `json:"cert_issuer,omitempty"`
}

func runHistory(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get artifact from positional argument or flag
	artifact := historyArtifact
	if len(args) > 0 {
		artifact = args[0]
	}

	// Parse time range
	var sinceTime, untilTime *time.Time
	if historySince != "" {
		t, err := parseTime(historySince)
		if err != nil {
			return fmt.Errorf("invalid --since value: %w", err)
		}
		sinceTime = &t
	}
	if historyUntil != "" {
		t, err := parseTime(historyUntil)
		if err != nil {
			return fmt.Errorf("invalid --until value: %w", err)
		}
		untilTime = &t
	}

	// Collect attestations
	var records []AttestationRecord

	// Query Rekor (unless local-only)
	if !historyLocalOnly {
		rekorRecords, err := queryRekor(ctx, artifact, sinceTime, untilTime)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to query Rekor: %v\n", err)
		} else {
			records = append(records, rekorRecords...)
		}
	}

	// Query local attestations
	localRecords, err := queryLocalAttestations(artifact, sinceTime, untilTime, historyUnpublished)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to query local attestations: %v\n", err)
	} else {
		records = append(records, localRecords...)
	}

	// Deduplicate (same artifact+digest+timestamp)
	records = deduplicateRecords(records)

	// Sort by timestamp (newest first)
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	// Apply limit
	if historyLimit > 0 && len(records) > historyLimit {
		records = records[:historyLimit]
	}

	// Output results
	switch historyFormat {
	case "json":
		return outputJSON(records)
	case "markdown":
		return outputMarkdown(records)
	default:
		return outputTable(records)
	}
}

// queryRekor queries the Rekor transparency log for attestations.
func queryRekor(ctx context.Context, artifact string, since, until *time.Time) ([]AttestationRecord, error) {
	// Note: Rekor search requires artifact digest, not image name
	// For MVP, we'll skip Rekor search if artifact is specified
	// In production, we'd resolve artifact → digest first
	
	// TODO: Implement artifact → digest resolution
	// This requires pulling image manifest or reading local file
	// For now, return empty results with informational message
	
	if artifact != "" {
		// Cannot search Rekor by artifact name directly
		// Need digest resolution first (future enhancement)
		return []AttestationRecord{}, nil
	}
	
	return []AttestationRecord{}, nil
}

// queryLocalAttestations queries local .provenix/attestations/ directory.
func queryLocalAttestations(artifact string, since, until *time.Time, includeUnpublished bool) ([]AttestationRecord, error) {
	attestationsDir := ".provenix/attestations"
	
	// Check if directory exists
	if _, err := os.Stat(attestationsDir); os.IsNotExist(err) {
		return []AttestationRecord{}, nil
	}

	var records []AttestationRecord

	// Walk through attestation files
	err := filepath.Walk(attestationsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-JSON files
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Read attestation file
		data, err := os.ReadFile(path)
		if err != nil {
			return nil // Skip unreadable files
		}

		// Parse attestation
		var attestation map[string]interface{}
		if err := json.Unmarshal(data, &attestation); err != nil {
			return nil // Skip invalid JSON
		}

		// Extract metadata
		record := AttestationRecord{
			Source:    "local",
			LocalPath: path,
			Published: false, // Assume unpublished unless proven otherwise
		}

		// Extract timestamp (file modification time as fallback)
		record.Timestamp = info.ModTime()

		// Extract artifact and digest from attestation
		// Try new format (statementBase64)
		if statementB64, ok := attestation["statementBase64"].(string); ok {
			payloadJSON, err := base64DecodeString(statementB64)
			if err == nil {
				var statement map[string]interface{}
				if err := json.Unmarshal([]byte(payloadJSON), &statement); err == nil {
					// Extract subject
					if subjects, ok := statement["subject"].([]interface{}); ok && len(subjects) > 0 {
						if subject, ok := subjects[0].(map[string]interface{}); ok {
							if name, ok := subject["name"].(string); ok {
								record.Artifact = name
							}
							if digest, ok := subject["digest"].(map[string]interface{}); ok {
								if sha256, ok := digest["sha256"].(string); ok {
									record.DigestSHA256 = sha256
								}
							}
						}
					}

					// Extract predicate type
					if predicateType, ok := statement["predicateType"].(string); ok {
						record.PredicateType = predicateType
					}
				}
			}
		} else if payloadType, ok := attestation["payloadType"].(string); ok && payloadType == "application/vnd.in-toto+json" {
			// Try old format (payload + payloadType)
			if payloadB64, ok := attestation["payload"].(string); ok {
				payloadJSON, err := base64DecodeString(payloadB64)
				if err == nil {
					var statement map[string]interface{}
					if err := json.Unmarshal([]byte(payloadJSON), &statement); err == nil {
						// Extract subject
						if subjects, ok := statement["subject"].([]interface{}); ok && len(subjects) > 0 {
							if subject, ok := subjects[0].(map[string]interface{}); ok {
								if name, ok := subject["name"].(string); ok {
									record.Artifact = name
								}
								if digest, ok := subject["digest"].(map[string]interface{}); ok {
									if sha256, ok := digest["sha256"].(string); ok {
										record.DigestSHA256 = sha256
									}
								}
							}
						}

						// Extract predicate type
						if predicateType, ok := statement["predicateType"].(string); ok {
							record.PredicateType = predicateType
						}
					}
				}
			}
		}

		// Check if published (look for Rekor UUID)
		if rekorUUID, ok := attestation["rekorUUID"].(string); ok && rekorUUID != "" {
			record.Published = true
			record.RekorUUID = rekorUUID
		}
		
		// Also check metadata field (for compatibility)
		if metadata, ok := attestation["metadata"].(map[string]interface{}); ok {
			if rekorUUID, ok := metadata["rekorUUID"].(string); ok && rekorUUID != "" {
				record.Published = true
				record.RekorUUID = rekorUUID
				if logIndex, ok := metadata["rekorLogIndex"].(float64); ok {
					record.RekorLogIndex = int64(logIndex)
				}
			}
		}

		// Apply filters
		if artifact != "" && !strings.Contains(record.Artifact, artifact) {
			return nil // Skip non-matching artifacts
		}

		if !includeUnpublished && !record.Published {
			return nil // Skip unpublished if not requested
		}

		if since != nil && record.Timestamp.Before(*since) {
			return nil // Skip before start time
		}

		if until != nil && record.Timestamp.After(*until) {
			return nil // Skip after end time
		}

		records = append(records, record)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk attestations directory: %w", err)
	}

	return records, nil
}

// deduplicateRecords removes duplicate records based on artifact+digest+timestamp.
func deduplicateRecords(records []AttestationRecord) []AttestationRecord {
	seen := make(map[string]bool)
	var unique []AttestationRecord

	for _, record := range records {
		key := fmt.Sprintf("%s:%s:%d", record.Artifact, record.DigestSHA256, record.Timestamp.Unix())
		if !seen[key] {
			seen[key] = true
			unique = append(unique, record)
		}
	}

	return unique
}

// parseTime parses time string (RFC3339 or relative format).
func parseTime(s string) (time.Time, error) {
	// Try RFC3339 format first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}

	// Try relative formats
	now := time.Now()
	switch s {
	case "today":
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()), nil
	case "yesterday":
		return time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, now.Location()), nil
	}

	// Try parsing relative durations (e.g., "2 weeks ago", "1 hour ago")
	if strings.HasSuffix(s, " ago") {
		durationStr := strings.TrimSuffix(s, " ago")
		parts := strings.Fields(durationStr)
		if len(parts) == 2 {
			var amount int
			var unit string
			fmt.Sscanf(durationStr, "%d %s", &amount, &unit)

			var duration time.Duration
			switch {
			case strings.HasPrefix(unit, "second"):
				duration = time.Duration(amount) * time.Second
			case strings.HasPrefix(unit, "minute"):
				duration = time.Duration(amount) * time.Minute
			case strings.HasPrefix(unit, "hour"):
				duration = time.Duration(amount) * time.Hour
			case strings.HasPrefix(unit, "day"):
				duration = time.Duration(amount) * 24 * time.Hour
			case strings.HasPrefix(unit, "week"):
				duration = time.Duration(amount) * 7 * 24 * time.Hour
			case strings.HasPrefix(unit, "month"):
				duration = time.Duration(amount) * 30 * 24 * time.Hour
			case strings.HasPrefix(unit, "year"):
				duration = time.Duration(amount) * 365 * 24 * time.Hour
			default:
				return time.Time{}, fmt.Errorf("unknown time unit: %s", unit)
			}

			return now.Add(-duration), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid time format: %s (use RFC3339 or relative format like '2 weeks ago')", s)
}

// base64DecodeString decodes a base64-encoded string.
func base64DecodeString(s string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// outputJSON outputs records in JSON format.
func outputJSON(records []AttestationRecord) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(records)
}

// outputMarkdown outputs records in Markdown table format.
func outputMarkdown(records []AttestationRecord) error {
	if len(records) == 0 {
		fmt.Println("No attestations found.")
		return nil
	}

	fmt.Println("# Attestation History")
	fmt.Println()
	fmt.Println("| Artifact | Digest | Timestamp | Source | Published | Rekor UUID |")
	fmt.Println("|----------|--------|-----------|--------|-----------|------------|")

	for _, record := range records {
		digest := record.DigestSHA256
		if len(digest) > 12 {
			digest = digest[:12] + "..."
		}

		timestamp := record.Timestamp.Format("2006-01-02 15:04")
		published := "No"
		if record.Published {
			published = "Yes"
		}

		rekorUUID := record.RekorUUID
		if len(rekorUUID) > 16 {
			rekorUUID = rekorUUID[:16] + "..."
		}

		fmt.Printf("| %s | %s | %s | %s | %s | %s |\n",
			record.Artifact, digest, timestamp, record.Source, published, rekorUUID)
	}

	return nil
}

// outputTable outputs records in plain text table format.
func outputTable(records []AttestationRecord) error {
	if len(records) == 0 {
		fmt.Println("No attestations found.")
		return nil
	}

	fmt.Printf("Found %d attestation(s):\n\n", len(records))
	fmt.Println("ARTIFACT                  DIGEST        TIMESTAMP            SOURCE  PUBLISHED  REKOR UUID")
	fmt.Println("------------------------  ------------  -------------------  ------  ---------  --------------------")

	for _, record := range records {
		artifact := record.Artifact
		if len(artifact) > 24 {
			artifact = artifact[:21] + "..."
		}

		digest := record.DigestSHA256
		if len(digest) > 12 {
			digest = digest[:12]
		}

		timestamp := record.Timestamp.Format("2006-01-02 15:04:05")
		
		published := "No"
		if record.Published {
			published = "Yes"
		}

		rekorUUID := record.RekorUUID
		if len(rekorUUID) > 20 {
			rekorUUID = rekorUUID[:20]
		}

		fmt.Printf("%-24s  %-12s  %-19s  %-6s  %-9s  %-20s\n",
			artifact, digest, timestamp, record.Source, published, rekorUUID)
	}

	return nil
}
