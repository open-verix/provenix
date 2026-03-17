package cli

import (
	"os"
	"testing"
)

func TestResolveConfigPath(t *testing.T) {
	// Save original env var and restore after test
	originalEnv := os.Getenv("PROVENIX_CONFIG")
	defer func() {
		if originalEnv != "" {
			os.Setenv("PROVENIX_CONFIG", originalEnv)
		} else {
			os.Unsetenv("PROVENIX_CONFIG")
		}
	}()

	tests := []struct {
		name      string
		flagValue string
		envValue  string
		want      string
	}{
		{
			name:      "CLI flag takes precedence",
			flagValue: "cli-config.yaml",
			envValue:  "env-config.yaml",
			want:      "cli-config.yaml",
		},
		{
			name:      "Environment variable used when flag empty",
			flagValue: "",
			envValue:  "env-config.yaml",
			want:      "env-config.yaml",
		},
		{
			name:      "Empty when both empty (default discovery)",
			flagValue: "",
			envValue:  "",
			want:      "",
		},
		{
			name:      "CLI flag used when non-empty",
			flagValue: "/path/to/config.yaml",
			envValue:  "",
			want:      "/path/to/config.yaml",
		},
		{
			name:      "Env var used when flag empty",
			flagValue: "",
			envValue:  "provenix.prod.yaml",
			want:      "provenix.prod.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv("PROVENIX_CONFIG", tt.envValue)
			} else {
				os.Unsetenv("PROVENIX_CONFIG")
			}

			got := resolveConfigPath(tt.flagValue)
			if got != tt.want {
				t.Errorf("resolveConfigPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Save original env var and restore after test
	originalEnv := os.Getenv("PROVENIX_CONFIG")
	defer func() {
		if originalEnv != "" {
			os.Setenv("PROVENIX_CONFIG", originalEnv)
		} else {
			os.Unsetenv("PROVENIX_CONFIG")
		}
	}()

	t.Run("loads default config when no file specified", func(t *testing.T) {
		os.Unsetenv("PROVENIX_CONFIG")

		cfg, err := loadConfig("")
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg == nil {
			t.Fatal("loadConfig() returned nil config")
		}

		// Check default values are set
		if cfg.SBOM.Format == "" {
			t.Error("expected default SBOM format, got empty string")
		}
	})

	t.Run("respects PROVENIX_CONFIG environment variable", func(t *testing.T) {
		// Create a temporary config file
		tmpfile, err := os.CreateTemp("", "provenix-test-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpfile.Name())

		configContent := `version: v1
sbom:
  format: spdx-json
scan:
  min-severity: high
`
		if _, err := tmpfile.Write([]byte(configContent)); err != nil {
			t.Fatal(err)
		}
		if err := tmpfile.Close(); err != nil {
			t.Fatal(err)
		}

		// Set environment variable
		os.Setenv("PROVENIX_CONFIG", tmpfile.Name())

		cfg, err := loadConfig("")
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.SBOM.Format != "spdx-json" {
			t.Errorf("expected SBOM format 'spdx-json', got '%s'", cfg.SBOM.Format)
		}

		if cfg.Scan.MinSeverity != "high" {
			t.Errorf("expected MinSeverity 'high', got '%s'", cfg.Scan.MinSeverity)
		}
	})

	t.Run("CLI flag takes precedence over environment variable", func(t *testing.T) {
		// Create two temporary config files
		envFile, err := os.CreateTemp("", "provenix-env-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(envFile.Name())

		if _, err := envFile.Write([]byte("version: v1\nsbom:\n  format: syft-json\n")); err != nil {
			t.Fatal(err)
		}
		if err := envFile.Close(); err != nil {
			t.Fatal(err)
		}

		flagFile, err := os.CreateTemp("", "provenix-flag-*.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(flagFile.Name())

		if _, err := flagFile.Write([]byte("version: v1\nsbom:\n  format: cyclonedx-json\n")); err != nil {
			t.Fatal(err)
		}
		if err := flagFile.Close(); err != nil {
			t.Fatal(err)
		}

		// Set environment variable
		os.Setenv("PROVENIX_CONFIG", envFile.Name())

		// Load with explicit flag (should override env var)
		cfg, err := loadConfig(flagFile.Name())
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}

		if cfg.SBOM.Format != "cyclonedx-json" {
			t.Errorf("expected SBOM format from flag file 'cyclonedx-json', got '%s'", cfg.SBOM.Format)
		}
	})
}
