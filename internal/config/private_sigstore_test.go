package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPrivateSigstoreConfig(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "provenix.yaml")

	configContent := `version: v1

signing:
  mode: keyless
  oidc:
    provider: auto
    fulcio-url: https://fulcio.example.com
    issuer: https://keycloak.example.com/realms/mycompany

rekor:
  url: https://rekor.example.com
  timeout: 30
  tuf-root: /etc/provenix/tuf/root.json
  insecure-skip-verify: false

vulnerabilities:
  max_critical: 0
  max_high: 0

licenses:
  allowed:
    - MIT
  denied:
    - GPL-3.0

sbom:
  format: cyclonedx-json
  require_checksum: true
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	// Load configuration
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify OIDC configuration
	if cfg.Signing.OIDC.FulcioURL != "https://fulcio.example.com" {
		t.Errorf("Expected Fulcio URL 'https://fulcio.example.com', got %q", cfg.Signing.OIDC.FulcioURL)
	}

	if cfg.Signing.OIDC.Issuer != "https://keycloak.example.com/realms/mycompany" {
		t.Errorf("Expected OIDC issuer 'https://keycloak.example.com/realms/mycompany', got %q", cfg.Signing.OIDC.Issuer)
	}

	// Verify Rekor configuration
	if cfg.Rekor.URL != "https://rekor.example.com" {
		t.Errorf("Expected Rekor URL 'https://rekor.example.com', got %q", cfg.Rekor.URL)
	}

	if cfg.Rekor.TUFRoot != "/etc/provenix/tuf/root.json" {
		t.Errorf("Expected TUF root '/etc/provenix/tuf/root.json', got %q", cfg.Rekor.TUFRoot)
	}

	if cfg.Rekor.InsecureSkipVerify != false {
		t.Errorf("Expected InsecureSkipVerify false, got %v", cfg.Rekor.InsecureSkipVerify)
	}
}

func TestDefaultConfigPrivateSigstore(t *testing.T) {
	cfg := Default()

	// Verify default values
	if cfg.Signing.OIDC.FulcioURL != "https://fulcio.sigstore.dev" {
		t.Errorf("Expected default Fulcio URL 'https://fulcio.sigstore.dev', got %q", cfg.Signing.OIDC.FulcioURL)
	}

	if cfg.Signing.OIDC.Issuer != "" {
		t.Errorf("Expected empty default OIDC issuer, got %q", cfg.Signing.OIDC.Issuer)
	}

	if cfg.Rekor.URL != "https://rekor.sigstore.dev" {
		t.Errorf("Expected default Rekor URL 'https://rekor.sigstore.dev', got %q", cfg.Rekor.URL)
	}

	if cfg.Rekor.TUFRoot != "" {
		t.Errorf("Expected empty default TUF root, got %q", cfg.Rekor.TUFRoot)
	}

	if cfg.Rekor.InsecureSkipVerify != false {
		t.Errorf("Expected default InsecureSkipVerify false, got %v", cfg.Rekor.InsecureSkipVerify)
	}
}

func TestInsecureSkipVerify(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "provenix.yaml")

	configContent := `version: v1

rekor:
  url: https://rekor.local.dev
  insecure-skip-verify: true
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !cfg.Rekor.InsecureSkipVerify {
		t.Errorf("Expected InsecureSkipVerify true, got false")
	}
}
