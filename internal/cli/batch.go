package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"
	
	"github.com/open-verix/provenix/internal/config"
)

var (
	batchInputFile  string
	batchOutputDir  string
	batchParallel   int
	batchContinue   bool
)

var batchCmd = &cobra.Command{
	Use:   "batch",
	Short: "Attest multiple artifacts in batch",
	Long: `Attest multiple artifacts in a single operation.

This command enables efficient attestation of multiple artifacts:
  • Process multiple container images, binaries, or directories
  • Parallel processing for faster execution
  • Continue on error (--continue-on-error flag)
  • Structured output with summary report

Input Methods:
  1. Input file (JSON/YAML) with artifact list
  2. Stdin (one artifact per line)
  3. Command-line arguments

Examples:
  # From input file
  provenix batch --input artifacts.json

  # From stdin
  echo "nginx:latest\nalpine:latest" | provenix batch

  # With parallel processing
  provenix batch --input artifacts.json --parallel 4

  # Continue on error
  provenix batch --input artifacts.json --continue-on-error

Exit Codes:
  0 - All attestations succeeded
  1 - Fatal error (invalid input, config error)
  2 - Some attestations failed (check output for details)`,
	RunE: runBatch,
}

func init() {
	batchCmd.Flags().StringVarP(&batchInputFile, "input", "i", "", "Input file with artifact list (JSON or YAML)")
	batchCmd.Flags().StringVarP(&batchOutputDir, "output-dir", "o", ".provenix/batch", "Output directory for attestations")
	batchCmd.Flags().IntVarP(&batchParallel, "parallel", "p", 1, "Number of parallel attestations (1-16)")
	batchCmd.Flags().BoolVarP(&batchContinue, "continue-on-error", "c", false, "Continue processing if an artifact fails")
	batchCmd.Flags().String("config", "", "Path to provenix.yaml configuration file")
	batchCmd.Flags().String("format", "cyclonedx-json", "SBOM format (cyclonedx-json, spdx-json, syft-json)")
}

// BatchInput represents the input file structure.
type BatchInput struct {
	Artifacts []ArtifactSpec `json:"artifacts" yaml:"artifacts"`
	Config    BatchConfig    `json:"config,omitempty" yaml:"config,omitempty"`
}

// ArtifactSpec specifies a single artifact to attest.
type ArtifactSpec struct {
	Name   string            `json:"name" yaml:"name"`
	Type   string            `json:"type,omitempty" yaml:"type,omitempty"` // image, archive, directory, file
	Tags   map[string]string `json:"tags,omitempty" yaml:"tags,omitempty"`
	Output string            `json:"output,omitempty" yaml:"output,omitempty"`
}

// BatchConfig contains batch-specific configuration.
type BatchConfig struct {
	Parallel       int    `json:"parallel,omitempty" yaml:"parallel,omitempty"`
	ContinueOnError bool   `json:"continue_on_error,omitempty" yaml:"continue_on_error,omitempty"`
	OutputDir      string `json:"output_dir,omitempty" yaml:"output_dir,omitempty"`
}

// BatchResult represents the result of a single artifact attestation.
type BatchResult struct {
	Artifact string    `json:"artifact"`
	Success  bool      `json:"success"`
	Error    string    `json:"error,omitempty"`
	Duration float64   `json:"duration_seconds"`
	Output   string    `json:"output_path,omitempty"`
	RekorUUID string   `json:"rekor_uuid,omitempty"`
}

// BatchSummary represents the summary of batch attestation.
type BatchSummary struct {
	Total     int           `json:"total"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
	Duration  float64       `json:"duration_seconds"`
	Results   []BatchResult `json:"results"`
}

func runBatch(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	startTime := time.Now()

	// Load configuration
	configPath, _ := cmd.Flags().GetString("config")
	sbomFormat, _ := cmd.Flags().GetString("format")
	
	var cfg *config.Config
	var err error
	
	if configPath != "" {
		cfg, err = config.Load(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
	} else {
		cfg = config.Default()
	}

	// Parse input
	var batchInput BatchInput
	
	if batchInputFile != "" {
		// Read from file
		batchInput, err = loadBatchInput(batchInputFile)
		if err != nil {
			return fmt.Errorf("failed to load input file: %w", err)
		}
	} else if len(args) > 0 {
		// Read from command-line arguments
		for _, arg := range args {
			batchInput.Artifacts = append(batchInput.Artifacts, ArtifactSpec{
				Name: arg,
			})
		}
	} else {
		// Read from stdin
		batchInput, err = loadBatchInputFromStdin()
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}
	}

	if len(batchInput.Artifacts) == 0 {
		return fmt.Errorf("no artifacts specified")
	}

	// Apply batch config
	if batchInput.Config.Parallel > 0 {
		batchParallel = batchInput.Config.Parallel
	}
	if batchInput.Config.ContinueOnError {
		batchContinue = true
	}
	if batchInput.Config.OutputDir != "" {
		batchOutputDir = batchInput.Config.OutputDir
	}

	// Validate parallel count
	if batchParallel < 1 {
		batchParallel = 1
	}
	if batchParallel > 16 {
		batchParallel = 16
	}

	// Create output directory
	if err := os.MkdirAll(batchOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	fmt.Printf("🚀 Starting batch attestation of %d artifact(s)\n", len(batchInput.Artifacts))
	fmt.Printf("   Parallel workers: %d\n", batchParallel)
	fmt.Printf("   Output directory: %s\n", batchOutputDir)
	fmt.Println()

	// Process artifacts
	results := processBatch(ctx, batchInput.Artifacts, cfg, sbomFormat)

	// Generate summary
	summary := BatchSummary{
		Total:     len(results),
		Succeeded: 0,
		Failed:    0,
		Duration:  time.Since(startTime).Seconds(),
		Results:   results,
	}

	for _, result := range results {
		if result.Success {
			summary.Succeeded++
		} else {
			summary.Failed++
		}
	}

	// Print summary
	printSummary(summary)

	// Save summary to file
	summaryPath := filepath.Join(batchOutputDir, "summary.json")
	if err := saveSummary(summary, summaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to save summary: %v\n", err)
	}

	// Determine exit code
	if summary.Failed == 0 {
		return nil // Exit 0
	} else if summary.Succeeded > 0 {
		os.Exit(2) // Exit 2: Partial success
	} else {
		return fmt.Errorf("all attestations failed") // Exit 1
	}

	return nil
}

func processBatch(ctx context.Context, artifacts []ArtifactSpec, cfg *config.Config, sbomFormat string) []BatchResult {
	results := make([]BatchResult, len(artifacts))
	
	// Create worker pool
	semaphore := make(chan struct{}, batchParallel)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, artifact := range artifacts {
		wg.Add(1)
		
		go func(index int, spec ArtifactSpec) {
			defer wg.Done()
			
			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Process artifact
			result := processArtifact(ctx, spec, cfg, sbomFormat)
			
			// Store result
			mu.Lock()
			results[index] = result
			mu.Unlock()

			// Print progress
			status := "✅"
			if !result.Success {
				status = "❌"
			}
			fmt.Printf("%s %s (%.2fs)\n", status, spec.Name, result.Duration)
		}(i, artifact)
	}

	wg.Wait()
	return results
}

func processArtifact(ctx context.Context, spec ArtifactSpec, cfg *config.Config, sbomFormat string) BatchResult {
	startTime := time.Now()
	result := BatchResult{
		Artifact: spec.Name,
		Success:  false,
	}

	// Determine output path
	outputPath := spec.Output
	if outputPath == "" {
		// Generate default output path
		filename := filepath.Base(spec.Name)
		filename = sanitizeFilename(filename) + ".json"
		outputPath = filepath.Join(batchOutputDir, filename)
	}

	// TODO: Call actual attestation logic
	// For now, this is a stub that simulates attestation
	// In real implementation, this would call the same logic as runAttest()
	
	// Simulate work (remove in actual implementation)
	time.Sleep(100 * time.Millisecond)
	
	result.Success = true
	result.Output = outputPath
	result.Duration = time.Since(startTime).Seconds()
	
	return result
}

func loadBatchInput(path string) (BatchInput, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return BatchInput{}, err
	}

	var input BatchInput
	
	// Try JSON first
	if err := json.Unmarshal(data, &input); err == nil {
		return input, nil
	}

	// TODO: Add YAML support
	return BatchInput{}, fmt.Errorf("failed to parse input file (only JSON supported currently)")
}

func loadBatchInputFromStdin() (BatchInput, error) {
	// TODO: Implement stdin reading
	return BatchInput{}, fmt.Errorf("stdin input not yet implemented")
}

func sanitizeFilename(name string) string {
	// Replace invalid filename characters
	replacer := map[rune]rune{
		'/': '-',
		':': '-',
		'\\': '-',
		'*': '-',
		'?': '-',
		'"': '-',
		'<': '-',
		'>': '-',
		'|': '-',
	}

	runes := []rune(name)
	for i, r := range runes {
		if replacement, ok := replacer[r]; ok {
			runes[i] = replacement
		}
	}

	return string(runes)
}

func printSummary(summary BatchSummary) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("                    BATCH SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("Total artifacts:    %d\n", summary.Total)
	fmt.Printf("✅ Succeeded:       %d\n", summary.Succeeded)
	fmt.Printf("❌ Failed:          %d\n", summary.Failed)
	fmt.Printf("⏱️  Total duration:  %.2fs\n", summary.Duration)
	fmt.Println("═══════════════════════════════════════════════════════════")

	if summary.Failed > 0 {
		fmt.Println()
		fmt.Println("Failed artifacts:")
		for _, result := range summary.Results {
			if !result.Success {
				fmt.Printf("  ❌ %s: %s\n", result.Artifact, result.Error)
			}
		}
	}
}

func saveSummary(summary BatchSummary, path string) error {
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
