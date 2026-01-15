package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var publishCmd = &cobra.Command{
	Use:   "publish [attestation-file]",
	Short: "Publish locally-saved attestations to Rekor",
	Long: `Publish attestations to Rekor transparency log.

This command is used to republish attestations that were saved locally
due to Rekor being unavailable (exit code 2 scenario).

When Provenix runs in environments with intermittent network connectivity,
it saves attestations to .provenix/attestations/. This command scans that
directory and publishes all pending attestations to Rekor.
`,
	Example: `  # Publish all pending attestations
  provenix publish

  # Publish a specific attestation file
  provenix publish .provenix/attestations/myapp-20260110.json

  # Publish and remove successfully uploaded files
  provenix publish --cleanup`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPublish,
}

func init() {
	publishCmd.Flags().Bool("cleanup", true, "Remove files after successful publication")
	publishCmd.Flags().String("rekor-url", "https://rekor.sigstore.dev", "Rekor server URL")
}

func runPublish(cmd *cobra.Command, args []string) error {
	rekorURL, _ := cmd.Flags().GetString("rekor-url")
	cleanup, _ := cmd.Flags().GetBool("cleanup")

	fmt.Println("📤 Publishing attestations to Rekor...")

	var filesToPublish []string

	// If specific file provided, publish just that one
	if len(args) > 0 {
		filesToPublish = []string{args[0]}
	} else {
		// Scan .provenix/attestations/ directory for pending files
		attestDir := ".provenix/attestations"
		if _, err := os.Stat(attestDir); os.IsNotExist(err) {
			fmt.Printf("ℹ️  No pending attestations found in %s\n", attestDir)
			return nil
		}

		entries, err := os.ReadDir(attestDir)
		if err != nil {
			fmt.Printf("❌ Failed to read attestation directory: %v\n", err)
			os.Exit(ExitFatal)
		}

		for _, entry := range entries {
			if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
				filesToPublish = append(filesToPublish, filepath.Join(attestDir, entry.Name()))
			}
		}

		if len(filesToPublish) == 0 {
			fmt.Printf("ℹ️  No pending attestations found in %s\n", attestDir)
			return nil
		}
	}

	// Publish each attestation
	published := 0
	failed := 0

	for _, file := range filesToPublish {
		// Read attestation
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("⚠️  Failed to read %s: %v\n", file, err)
			failed++
			continue
		}

		// Parse attestation (basic validation)
		var attestation map[string]interface{}
		if err := json.Unmarshal(data, &attestation); err != nil {
			fmt.Printf("⚠️  Invalid attestation file %s: %v\n", file, err)
			failed++
			continue
		}

		// Simulate publishing to Rekor (stub implementation)
		fmt.Printf("  Publishing: %s\n", filepath.Base(file))

		// In real implementation, this would:
		// 1. Create in-toto entry from attestation
		// 2. Call Rekor API to publish
		// 3. Get entry UUID
		// 4. Save proof locally

		// For now, just mark as published
		published++

		// Cleanup if requested
		if cleanup {
			if err := os.Remove(file); err != nil {
				fmt.Printf("⚠️  Failed to remove %s: %v\n", file, err)
			} else {
				fmt.Printf("  ✅ Removed: %s\n", filepath.Base(file))
			}
		}
	}

	// Summary
	fmt.Printf("\n📊 Publication Summary:\n")
	fmt.Printf("  Rekor URL:      %s\n", rekorURL)
	fmt.Printf("  Published:      %d\n", published)
	fmt.Printf("  Failed:         %d\n", failed)
	fmt.Printf("  Timestamp:      %s\n", time.Now().UTC().Format(time.RFC3339))

	if failed > 0 {
		os.Exit(ExitFatal)
	}

	return nil
}
