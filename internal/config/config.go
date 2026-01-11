package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the complete Provenix configuration.
type Config struct {
	SBOM    SBOMConfig    `mapstructure:"sbom"`
	Scan    ScanConfig    `mapstructure:"scan"`
	Signing SigningConfig `mapstructure:"signing"`
	Rekor   RekorConfig   `mapstructure:"rekor"`
	Output  OutputConfig  `mapstructure:"output"`
	Storage StorageConfig `mapstructure:"storage"`
	Logging LoggingConfig `mapstructure:"logging"`
}

// SBOMConfig configures SBOM generation behavior.
type SBOMConfig struct {
	Format       string   `mapstructure:"format"`
	IncludeFiles bool     `mapstructure:"include-files"`
	Catalogers   []string `mapstructure:"catalogers"`
}

// ScanConfig configures vulnerability scanning behavior.
type ScanConfig struct {
	MinSeverity string         `mapstructure:"min-severity"`
	FailOn      string         `mapstructure:"fail-on"`
	ShowFixed   bool           `mapstructure:"show-fixed"`
	Database    DatabaseConfig `mapstructure:"database"`
}

// DatabaseConfig configures vulnerability database behavior.
type DatabaseConfig struct {
	AutoUpdate bool `mapstructure:"auto-update"`
	MaxAge     int  `mapstructure:"max-age"`
}

// SigningConfig configures signing behavior.
type SigningConfig struct {
	Mode   string     `mapstructure:"mode"`
	OIDC   OIDCConfig `mapstructure:"oidc"`
	Key    KeyConfig  `mapstructure:"key"`
}

// OIDCConfig configures OIDC-based keyless signing.
type OIDCConfig struct {
	Provider  string `mapstructure:"provider"`
	FulcioURL string `mapstructure:"fulcio-url"`
}

// KeyConfig configures local key-based signing.
type KeyConfig struct {
	Path        string `mapstructure:"path"`
	PasswordEnv string `mapstructure:"password-env"`
}

// RekorConfig configures Rekor transparency log behavior.
type RekorConfig struct {
	URL     string      `mapstructure:"url"`
	Timeout int         `mapstructure:"timeout"`
	Retry   RetryConfig `mapstructure:"retry"`
}

// RetryConfig configures retry behavior.
type RetryConfig struct {
	MaxAttempts  int `mapstructure:"max-attempts"`
	InitialDelay int `mapstructure:"initial-delay"`
	MaxDelay     int `mapstructure:"max-delay"`
}

// OutputConfig configures output behavior.
type OutputConfig struct {
	File        string `mapstructure:"file"`
	Format      string `mapstructure:"format"`
	Pretty      bool   `mapstructure:"pretty"`
	IncludeSBOM bool   `mapstructure:"include-sbom"`
	IncludeScan bool   `mapstructure:"include-scan"`
}

// StorageConfig configures local storage behavior.
type StorageConfig struct {
	Dir           string `mapstructure:"dir"`
	RetentionDays int    `mapstructure:"retention-days"`
}

// LoggingConfig configures logging behavior.
type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"`
	Timestamps bool   `mapstructure:"timestamps"`
}

// Default returns the default configuration.
func Default() *Config {
	return &Config{
		SBOM: SBOMConfig{
			Format:       "cyclonedx-json",
			IncludeFiles: false,
			Catalogers:   []string{},
		},
		Scan: ScanConfig{
			MinSeverity: "medium",
			FailOn:      "critical",
			ShowFixed:   true,
			Database: DatabaseConfig{
				AutoUpdate: true,
				MaxAge:     24,
			},
		},
		Signing: SigningConfig{
			Mode: "keyless",
			OIDC: OIDCConfig{
				Provider:  "auto",
				FulcioURL: "https://fulcio.sigstore.dev",
			},
			Key: KeyConfig{
				Path:        "",
				PasswordEnv: "",
			},
		},
		Rekor: RekorConfig{
			URL:     "https://rekor.sigstore.dev",
			Timeout: 30,
			Retry: RetryConfig{
				MaxAttempts:  3,
				InitialDelay: 1,
				MaxDelay:     10,
			},
		},
		Output: OutputConfig{
			File:        "attestation.json",
			Format:      "json",
			Pretty:      true,
			IncludeSBOM: true,
			IncludeScan: true,
		},
		Storage: StorageConfig{
			Dir:           ".provenix/attestations",
			RetentionDays: 30,
		},
		Logging: LoggingConfig{
			Level:      "info",
			Format:     "text",
			Timestamps: true,
		},
	}
}

// Load loads configuration from file, environment variables, and defaults.
//
// Configuration priority (highest to lowest):
//  1. Environment variables (PROVENIX_*)
//  2. Configuration file (provenix.yaml)
//  3. Default values
//
// The configPath parameter specifies the path to the configuration file.
// If empty, the loader searches for provenix.yaml in the current directory.
//
// NEVER searches in:
//   - ~/.config/provenix/
//   - /etc/provenix/
//
// This is intentional - Provenix uses project-scoped configuration only.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Configure Viper
	v.SetConfigName("provenix")
	v.SetConfigType("yaml")
	v.SetEnvPrefix("PROVENIX")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	// Determine config file location
	if configPath != "" {
		// Explicit path provided
		v.SetConfigFile(configPath)
	} else {
		// Search in current directory only (project-scoped)
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		v.AddConfigPath(cwd)
	}

	// Read config file (optional - use defaults if not found)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file found but had an error
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found - use defaults (this is OK)
	}

	// Unmarshal into Config struct
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return cfg, nil
}

// setDefaults sets default values in Viper.
func setDefaults(v *viper.Viper) {
	defaults := Default()

	// SBOM defaults
	v.SetDefault("sbom.format", defaults.SBOM.Format)
	v.SetDefault("sbom.include-files", defaults.SBOM.IncludeFiles)

	// Scan defaults
	v.SetDefault("scan.min-severity", defaults.Scan.MinSeverity)
	v.SetDefault("scan.fail-on", defaults.Scan.FailOn)
	v.SetDefault("scan.show-fixed", defaults.Scan.ShowFixed)
	v.SetDefault("scan.database.auto-update", defaults.Scan.Database.AutoUpdate)
	v.SetDefault("scan.database.max-age", defaults.Scan.Database.MaxAge)

	// Signing defaults
	v.SetDefault("signing.mode", defaults.Signing.Mode)
	v.SetDefault("signing.oidc.provider", defaults.Signing.OIDC.Provider)
	v.SetDefault("signing.oidc.fulcio-url", defaults.Signing.OIDC.FulcioURL)

	// Rekor defaults
	v.SetDefault("rekor.url", defaults.Rekor.URL)
	v.SetDefault("rekor.timeout", defaults.Rekor.Timeout)
	v.SetDefault("rekor.retry.max-attempts", defaults.Rekor.Retry.MaxAttempts)
	v.SetDefault("rekor.retry.initial-delay", defaults.Rekor.Retry.InitialDelay)
	v.SetDefault("rekor.retry.max-delay", defaults.Rekor.Retry.MaxDelay)

	// Output defaults
	v.SetDefault("output.file", defaults.Output.File)
	v.SetDefault("output.format", defaults.Output.Format)
	v.SetDefault("output.pretty", defaults.Output.Pretty)
	v.SetDefault("output.include-sbom", defaults.Output.IncludeSBOM)
	v.SetDefault("output.include-scan", defaults.Output.IncludeScan)

	// Storage defaults
	v.SetDefault("storage.dir", defaults.Storage.Dir)
	v.SetDefault("storage.retention-days", defaults.Storage.RetentionDays)

	// Logging defaults
	v.SetDefault("logging.level", defaults.Logging.Level)
	v.SetDefault("logging.format", defaults.Logging.Format)
	v.SetDefault("logging.timestamps", defaults.Logging.Timestamps)
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate SBOM format
	validFormats := map[string]bool{
		"cyclonedx-json": true,
		"spdx-json":      true,
		"syft-json":      true,
	}
	if !validFormats[c.SBOM.Format] {
		return fmt.Errorf("invalid SBOM format: %s (must be cyclonedx-json, spdx-json, or syft-json)", c.SBOM.Format)
	}

	// Validate scan severity levels
	validSeverities := map[string]bool{
		"":           true, // Empty is valid (means all)
		"negligible": true,
		"low":        true,
		"medium":     true,
		"high":       true,
		"critical":   true,
	}
	if !validSeverities[c.Scan.MinSeverity] {
		return fmt.Errorf("invalid min-severity: %s", c.Scan.MinSeverity)
	}
	if !validSeverities[c.Scan.FailOn] {
		return fmt.Errorf("invalid fail-on severity: %s", c.Scan.FailOn)
	}

	// Validate signing mode
	if c.Signing.Mode != "keyless" && c.Signing.Mode != "key" {
		return fmt.Errorf("invalid signing mode: %s (must be keyless or key)", c.Signing.Mode)
	}

	// Validate key mode has key path
	if c.Signing.Mode == "key" && c.Signing.Key.Path == "" {
		return fmt.Errorf("key mode requires signing.key.path to be set")
	}

	// Validate key file exists if provided
	if c.Signing.Key.Path != "" {
		if _, err := os.Stat(c.Signing.Key.Path); os.IsNotExist(err) {
			return fmt.Errorf("signing key not found: %s", c.Signing.Key.Path)
		}
	}

	// Validate output format
	if c.Output.Format != "json" && c.Output.Format != "yaml" {
		return fmt.Errorf("invalid output format: %s (must be json or yaml)", c.Output.Format)
	}

	// Validate logging level
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLevels[c.Logging.Level] {
		return fmt.Errorf("invalid logging level: %s", c.Logging.Level)
	}

	// Validate storage directory is not absolute path outside project
	if filepath.IsAbs(c.Storage.Dir) {
		return fmt.Errorf("storage directory must be relative to project root: %s", c.Storage.Dir)
	}

	return nil
}
