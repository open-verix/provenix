package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"nginx:latest", "nginx-latest"},
		{"my/path/image", "my-path-image"},
		{"image:v1.0", "image-v1.0"},
		{"normal-name", "normal-name"},
		{"image<>:?*|", "image------"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeFilename(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLoadBatchInput(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "batch.json")

	content := `{
  "artifacts": [
    {
      "name": "nginx:latest",
      "type": "image"
    },
    {
      "name": "alpine:latest",
      "type": "image"
    }
  ],
  "config": {
    "parallel": 2,
    "continue_on_error": true,
    "output_dir": "/tmp/output"
  }
}`

	if err := os.WriteFile(inputPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write input file: %v", err)
	}

	input, err := loadBatchInput(inputPath)
	if err != nil {
		t.Fatalf("loadBatchInput() error = %v", err)
	}

	if len(input.Artifacts) != 2 {
		t.Errorf("Expected 2 artifacts, got %d", len(input.Artifacts))
	}

	if input.Artifacts[0].Name != "nginx:latest" {
		t.Errorf("Expected first artifact 'nginx:latest', got %q", input.Artifacts[0].Name)
	}

	if input.Config.Parallel != 2 {
		t.Errorf("Expected parallel=2, got %d", input.Config.Parallel)
	}

	if !input.Config.ContinueOnError {
		t.Errorf("Expected continue_on_error=true, got false")
	}

	if input.Config.OutputDir != "/tmp/output" {
		t.Errorf("Expected output_dir='/tmp/output', got %q", input.Config.OutputDir)
	}
}

func TestPrintSummary(t *testing.T) {
	summary := BatchSummary{
		Total:     3,
		Succeeded: 2,
		Failed:    1,
		Duration:  1.5,
		Results: []BatchResult{
			{Artifact: "nginx:latest", Success: true, Duration: 0.5},
			{Artifact: "alpine:latest", Success: true, Duration: 0.4},
			{Artifact: "broken:image", Success: false, Error: "image not found", Duration: 0.6},
		},
	}

	// Just ensure it doesn't panic
	printSummary(summary)
}

func TestSaveSummary(t *testing.T) {
	tmpDir := t.TempDir()
	summaryPath := filepath.Join(tmpDir, "summary.json")

	summary := BatchSummary{
		Total:     2,
		Succeeded: 2,
		Failed:    0,
		Duration:  1.0,
		Results: []BatchResult{
			{Artifact: "nginx:latest", Success: true, Duration: 0.5},
			{Artifact: "alpine:latest", Success: true, Duration: 0.5},
		},
	}

	if err := saveSummary(summary, summaryPath); err != nil {
		t.Fatalf("saveSummary() error = %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(summaryPath); os.IsNotExist(err) {
		t.Errorf("Summary file was not created")
	}

	// Verify content
	data, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("Failed to read summary file: %v", err)
	}

	if len(data) == 0 {
		t.Errorf("Summary file is empty")
	}
}
