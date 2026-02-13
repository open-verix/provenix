package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/open-verix/provenix/internal/providers/signer/cosign"
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
	publishCmd.Flags().Bool("dry-run", false, "Show what would be published without actually publishing")
	publishCmd.Flags().Int("timeout", 30, "Timeout in seconds for each publication")
}

func runPublish(cmd *cobra.Command, args []string) error {
	rekorURL, _ := cmd.Flags().GetString("rekor-url")
	cleanup, _ := cmd.Flags().GetBool("cleanup")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	timeout, _ := cmd.Flags().GetInt("timeout")

	if dryRun {
		fmt.Println("🔍 Dry-run mode: No actual publishing will occur")
	} else {
		fmt.Println("📤 Publishing attestations to Rekor...")
	}

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
			return NewExitError(ExitFatal, fmt.Sprintf("failed to read attestation directory: %v", err))
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
	results := make(map[string]string) // filename -> result

	for _, file := range filesToPublish {
		fmt.Printf("\n📄 Processing: %s\n", filepath.Base(file))
		
		// Read attestation
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("  ❌ Failed to read: %v\n", err)
			results[file] = fmt.Sprintf("read error: %v", err)
			failed++
			continue
		}

		// Parse attestation bundle
		var bundle cosign.AttestationBundle
		if err := json.Unmarshal(data, &bundle); err != nil {
			fmt.Printf("  ❌ Invalid attestation format: %v\n", err)
			results[file] = fmt.Sprintf("parse error: %v", err)
			failed++
			continue
		}

		// Check if already published
		if bundle.RekorUUID != "" {
			fmt.Printf("  ℹ️  Already published (UUID: %s)\n", bundle.RekorUUID[:16]+"...")
			results[file] = "already published"
			published++
			
			// Cleanup if requested
			if cleanup && !dryRun {
				if err := os.Remove(file); err != nil {
					fmt.Printf("  ⚠️  Failed to remove: %v\n", err)
				} else {
					fmt.Printf("  🗑️  Removed local copy\n")
				}
			}
			continue
		}

		if dryRun {
			fmt.Printf("  ✓ Would publish to: %s\n", rekorURL)
			results[file] = "would publish"
			published++
			continue
		}

		// Decode statement for publishing
		statementBytes, err := base64.StdEncoding.DecodeString(bundle.StatementBase64)
		if err != nil {
			fmt.Printf("  ❌ Failed to decode statement: %v\n", err)
			results[file] = fmt.Sprintf("decode error: %v", err)
			failed++
			continue
		}

		// Publish to Rekor
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		defer cancel()

		rekorClient := cosign.NewRekorClient(rekorURL)
		
		// Decode signature
		signatureBytes, err := base64.StdEncoding.DecodeString(bundle.Signature)
		if err != nil {
			fmt.Printf("  ❌ Failed to decode signature: %v\n", err)
			results[file] = fmt.Sprintf("signature decode error: %v", err)
			failed++
			continue
		}

		// Get public key (from certificate or publicKey field)
		var publicKeyPEM []byte
		if bundle.Certificate != "" {
			publicKeyPEM = []byte(bundle.Certificate)
		} else if bundle.PublicKey != "" {
			publicKeyPEM = []byte(bundle.PublicKey)
		} else {
			fmt.Printf("  ❌ No certificate or public key found\n")
			results[file] = "missing public key"
			failed++
			continue
		}

		uuid, logIndex, err := rekorClient.CreateHashedRekordEntry(ctx, statementBytes, signatureBytes, publicKeyPEM)
		if err != nil {
			fmt.Printf("  ❌ Rekor publish failed: %v\n", err)
			results[file] = fmt.Sprintf("publish error: %v", err)
			failed++
			continue
		}

		fmt.Printf("  ✅ Published to Rekor\n")
		fmt.Printf("     UUID: %s\n", uuid)
		fmt.Printf("     Log Index: %d\n", logIndex)

		// Update attestation file with Rekor info
		bundle.RekorUUID = uuid
		bundle.RekorLogIndex = int(logIndex)

		updatedData, err := json.MarshalIndent(bundle, "", "  ")
		if err != nil {
			fmt.Printf("  ⚠️  Failed to marshal updated bundle: %v\n", err)
		} else {
			if err := os.WriteFile(file, updatedData, 0644); err != nil {
				fmt.Printf("  ⚠️  Failed to update file: %v\n", err)
			} else {
				fmt.Printf("  💾 Updated with Rekor info\n")
			}
		}

		results[file] = fmt.Sprintf("published: %s", uuid[:16]+"...")
		published++

		// Cleanup if requested
		if cleanup {
			if err := os.Remove(file); err != nil {
				fmt.Printf("  ⚠️  Failed to remove: %v\n", err)
			} else {
				fmt.Printf("  🗑️  Removed local copy\n")
			}
		}
	}

	// Summary
	fmt.Printf("\n")
	fmt.Println("============================================================")
	fmt.Println("📊 Publication Summary")
	fmt.Println("============================================================")
	fmt.Printf("Rekor URL:      %s\n", rekorURL)
	fmt.Printf("Total files:    %d\n", len(filesToPublish))
	fmt.Printf("Published:      %d ✅\n", published)
	fmt.Printf("Failed:         %d ❌\n", failed)
	fmt.Printf("Timestamp:      %s\n", time.Now().UTC().Format(time.RFC3339))
	
	if dryRun {
		fmt.Printf("\nℹ️  This was a dry-run. No changes were made.\n")
	}

	if failed > 0 {
		return NewExitError(ExitFatal, fmt.Sprintf("%d attestation(s) failed to publish", failed))
	}

	return nil
}
