package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.SBOM.Format != "cyclonedx-json" {
		t.Errorf("expected default SBOM format 'cyclonedx-json', got '%s'", cfg.SBOM.Format)
	}

	if cfg.Signing.Mode != "keyless" {
		t.Errorf("expected default signing mode 'keyless', got '%s'", cfg.Signing.Mode)
	}

	if cfg.Rekor.URL != "https://rekor.sigstore.dev" {
		t.Errorf("expected default Rekor URL, got '%s'", cfg.Rekor.URL)
	}
}

func TestLoadWithDefaults(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}

	// Load config without file (should use defaults)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.SBOM.Format != "cyclonedx-json" {
		t.Errorf("expected default format, got '%s'", cfg.SBOM.Format)
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}

	// Create config file
	configContent := `
sbom:
  format: spdx-json
scan:
  min-severity: high
signing:
  mode: key
  key:
    path: /tmp/test-key.pem
`
	configPath := filepath.Join(tmpDir, "provenix.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Create dummy key file to pass validation
	if err := os.WriteFile("/tmp/test-key.pem", []byte("dummy"), 0644); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}
	defer os.Remove("/tmp/test-key.pem")

	// Load config
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.SBOM.Format != "spdx-json" {
		t.Errorf("expected format 'spdx-json', got '%s'", cfg.SBOM.Format)
	}

	if cfg.Scan.MinSeverity != "high" {
		t.Errorf("expected min-severity 'high', got '%s'", cfg.Scan.MinSeverity)
	}

	if cfg.Signing.Mode != "key" {
		t.Errorf("expected signing mode 'key', got '%s'", cfg.Signing.Mode)
	}
}

func TestLoadFromExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create config file
	configContent := `
sbom:
  format: syft-json
`
	configPath := filepath.Join(tmpDir, "custom.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Load config from explicit path
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.SBOM.Format != "syft-json" {
		t.Errorf("expected format 'syft-json', got '%s'", cfg.SBOM.Format)
	}
}

func TestLoadWithEnvironmentVariables(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}

	// Set environment variable
	os.Setenv("PROVENIX_SBOM_FORMAT", "spdx-json")
	defer os.Unsetenv("PROVENIX_SBOM_FORMAT")

	// Load config
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	// Environment variable should override default
	if cfg.SBOM.Format != "spdx-json" {
		t.Errorf("expected format from env 'spdx-json', got '%s'", cfg.SBOM.Format)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			cfg:     Default(),
			wantErr: false,
		},
		{
			name: "invalid SBOM format",
			cfg: &Config{
				SBOM: SBOMConfig{Format: "invalid"},
				Scan: Default().Scan,
				Signing: SigningConfig{Mode: "keyless"},
				Output: OutputConfig{Format: "json"},
				Logging: LoggingConfig{Level: "info"},
				Storage: StorageConfig{Dir: ".provenix"},
			},
			wantErr: true,
			errMsg:  "invalid SBOM format",
		},
		{
			name: "invalid severity level",
			cfg: &Config{
				SBOM: Default().SBOM,
				Scan: ScanConfig{MinSeverity: "invalid"},
				Signing: SigningConfig{Mode: "keyless"},
				Output: OutputConfig{Format: "json"},
				Logging: LoggingConfig{Level: "info"},
				Storage: StorageConfig{Dir: ".provenix"},
			},
			wantErr: true,
			errMsg:  "invalid min-severity",
		},
		{
			name: "invalid signing mode",
			cfg: &Config{
				SBOM: Default().SBOM,
				Scan: Default().Scan,
				Signing: SigningConfig{Mode: "invalid"},
				Output: OutputConfig{Format: "json"},
				Logging: LoggingConfig{Level: "info"},
				Storage: StorageConfig{Dir: ".provenix"},
			},
			wantErr: true,
			errMsg:  "invalid signing mode",
		},
		{
			name: "key mode without key path",
			cfg: &Config{
				SBOM: Default().SBOM,
				Scan: Default().Scan,
				Signing: SigningConfig{
					Mode: "key",
					Key:  KeyConfig{Path: ""},
				},
				Output: OutputConfig{Format: "json"},
				Logging: LoggingConfig{Level: "info"},
				Storage: StorageConfig{Dir: ".provenix"},
			},
			wantErr: true,
			errMsg:  "key mode requires",
		},
		{
			name: "invalid output format",
			cfg: &Config{
				SBOM: Default().SBOM,
				Scan: Default().Scan,
				Signing: SigningConfig{Mode: "keyless"},
				Output: OutputConfig{Format: "invalid"},
				Logging: LoggingConfig{Level: "info"},
				Storage: StorageConfig{Dir: ".provenix"},
			},
			wantErr: true,
			errMsg:  "invalid output format",
		},
		{
			name: "absolute storage path",
			cfg: &Config{
				SBOM: Default().SBOM,
				Scan: Default().Scan,
				Signing: SigningConfig{Mode: "keyless"},
				Output: OutputConfig{Format: "json"},
				Logging: LoggingConfig{Level: "info"},
				Storage: StorageConfig{Dir: "/tmp/provenix"},
			},
			wantErr: true,
			errMsg:  "storage directory must be relative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.errMsg)
				} else if err.Error() == "" {
					t.Errorf("expected error message, got empty string")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}
