package cli

import (
	"os"

	"github.com/open-verix/provenix/internal/config"
)

// resolveConfigPath resolves the configuration file path from CLI flag or environment variable.
//
// Priority (highest to lowest):
//  1. CLI flag (--config)
//  2. Environment variable (PROVENIX_CONFIG)
//  3. Empty string (triggers default discovery: ./provenix.yaml)
//
// Example:
//   configPath := resolveConfigPath(cmd.Flags().GetString("config"))
//   cfg, err := config.Load(configPath)
func resolveConfigPath(flagValue string) string {
	// Priority 1: CLI flag
	if flagValue != "" {
		return flagValue
	}

	// Priority 2: Environment variable
	if envValue := os.Getenv("PROVENIX_CONFIG"); envValue != "" {
		return envValue
	}

	// Priority 3: Default discovery (empty string signals config.Load to search ./provenix.yaml)
	return ""
}

// loadConfig loads configuration using the standard priority resolution.
//
// This is a convenience wrapper that:
//  1. Resolves config path from flag and environment variable
//  2. Loads config from resolved path
//  3. Returns default config if no file found
//
// Example:
//   cfg, err := loadConfig(cmd.Flags().GetString("config"))
//   if err != nil {
//       return fmt.Errorf("failed to load config: %w", err)
//   }
func loadConfig(flagValue string) (*config.Config, error) {
	configPath := resolveConfigPath(flagValue)

	if configPath != "" {
		// Explicit config file specified
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, err
		}
		return cfg, nil
	}

	// No explicit config - try default discovery
	cfg, err := config.Load("")
	if err != nil {
		return nil, err
	}
	return cfg, nil
}
