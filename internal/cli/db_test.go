package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGetDBPath(t *testing.T) {
	path, err := getDBPath()
	if err != nil {
		t.Fatalf("getDBPath() failed: %v", err)
	}

	// Should return path in .cache/grype/db
	if !filepath.IsAbs(path) {
		t.Errorf("Expected absolute path, got: %s", path)
	}

	expectedSuffix := filepath.Join(".cache", "grype", "db")
	if !endsWithPath(path, expectedSuffix) {
		t.Errorf("Expected path to end with %s, got: %s", expectedSuffix, path)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{name: "bytes", bytes: 512, expected: "512 B"},
		{name: "kilobytes", bytes: 1024, expected: "1.0 KB"},
		{name: "megabytes", bytes: 1024 * 1024, expected: "1.0 MB"},
		{name: "gigabytes", bytes: 1024 * 1024 * 1024, expected: "1.0 GB"},
		{name: "large", bytes: 5 * 1024 * 1024 * 1024, expected: "5.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %s, want %s", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		seconds  int
		expected string
	}{
		{name: "seconds", seconds: 30, expected: "30 seconds"},
		{name: "minutes", seconds: 120, expected: "2 minutes"},
		{name: "hours", seconds: 7200, expected: "2.0 hours"},
		{name: "one day", seconds: 86400, expected: "1 day"},
		{name: "days", seconds: 172800, expected: "2 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(time.Duration(tt.seconds) * time.Second)
			if result != tt.expected {
				t.Errorf("formatDuration(%ds) = %s, want %s", tt.seconds, result, tt.expected)
			}
		})
	}
}

func TestGetDirSize(t *testing.T) {
	// Create temporary directory with known size
	tmpDir, err := os.MkdirTemp("", "provenix-db-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create test files
	testFiles := []struct {
		name string
		size int
	}{
		{"file1.txt", 100},
		{"file2.txt", 200},
		{"subdir/file3.txt", 300},
	}

	for _, tf := range testFiles {
		filePath := filepath.Join(tmpDir, tf.name)
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("Failed to create subdirectory: %v", err)
		}
		if err := os.WriteFile(filePath, make([]byte, tf.size), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	// Test getDirSize
	size, err := getDirSize(tmpDir)
	if err != nil {
		t.Fatalf("getDirSize() failed: %v", err)
	}

	expectedSize := int64(600) // 100 + 200 + 300
	if size != expectedSize {
		t.Errorf("getDirSize() = %d, want %d", size, expectedSize)
	}
}

func TestGetDirSize_NonExistent(t *testing.T) {
	size, err := getDirSize("/nonexistent/path")
	if err == nil {
		t.Error("Expected error for non-existent path, got nil")
	}
	if size != 0 {
		t.Errorf("Expected size 0 for error case, got %d", size)
	}
}

// endsWithPath checks if path ends with the given suffix components.
func endsWithPath(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}
