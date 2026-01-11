package providers

import (
	"testing"
	
	"github.com/open-verix/provenix/internal/providers/sbom"
	sbomMock "github.com/open-verix/provenix/internal/providers/sbom/mock"
	"github.com/open-verix/provenix/internal/providers/scanner"
	scannerMock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	"github.com/open-verix/provenix/internal/providers/signer"
	signerMock "github.com/open-verix/provenix/internal/providers/signer/mock"
)

func TestRegisterAndGetSBOMProvider(t *testing.T) {
	// Clear existing providers
	sbomMutex.Lock()
	sbomProviders = make(map[string]sbom.Provider)
	sbomMutex.Unlock()
	
	// Create and register a mock provider
	mockProvider := sbomMock.NewProvider()
	RegisterSBOMProvider("test-sbom", mockProvider)
	
	// Retrieve the provider
	provider, err := GetSBOMProvider("test-sbom")
	if err != nil {
		t.Fatalf("failed to get SBOM provider: %v", err)
	}
	
	if provider.Name() != "mock" {
		t.Errorf("expected provider name 'mock', got '%s'", provider.Name())
	}
	
	// Try to get a non-existent provider
	_, err = GetSBOMProvider("nonexistent")
	if err == nil {
		t.Error("expected error when getting non-existent provider")
	}
	
	providerErr, ok := err.(*ProviderNotFoundError)
	if !ok {
		t.Errorf("expected ProviderNotFoundError, got %T", err)
	}
	
	if providerErr.Type != "SBOM" || providerErr.Name != "nonexistent" {
		t.Errorf("incorrect error details: %v", providerErr)
	}
}

func TestListSBOMProviders(t *testing.T) {
	// Clear existing providers
	sbomMutex.Lock()
	sbomProviders = make(map[string]sbom.Provider)
	sbomMutex.Unlock()
	
	// Initially should be empty
	providers := ListSBOMProviders()
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
	
	// Register some providers
	RegisterSBOMProvider("provider1", sbomMock.NewProvider())
	RegisterSBOMProvider("provider2", sbomMock.NewProvider())
	
	providers = ListSBOMProviders()
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}
	
	// Check that both names are present
	names := make(map[string]bool)
	for _, name := range providers {
		names[name] = true
	}
	
	if !names["provider1"] || !names["provider2"] {
		t.Errorf("provider names not found: %v", providers)
	}
}

func TestRegisterAndGetScannerProvider(t *testing.T) {
	// Clear existing providers
	scannerMutex.Lock()
	scannerProviders = make(map[string]scanner.Provider)
	scannerMutex.Unlock()
	
	// Create and register a mock provider
	mockProvider := scannerMock.NewProvider()
	RegisterScannerProvider("test-scanner", mockProvider)
	
	// Retrieve the provider
	provider, err := GetScannerProvider("test-scanner")
	if err != nil {
		t.Fatalf("failed to get scanner provider: %v", err)
	}
	
	if provider.Name() != "mock" {
		t.Errorf("expected provider name 'mock', got '%s'", provider.Name())
	}
	
	// Try to get a non-existent provider
	_, err = GetScannerProvider("nonexistent")
	if err == nil {
		t.Error("expected error when getting non-existent provider")
	}
	
	providerErr, ok := err.(*ProviderNotFoundError)
	if !ok {
		t.Errorf("expected ProviderNotFoundError, got %T", err)
	}
	
	if providerErr.Type != "Scanner" || providerErr.Name != "nonexistent" {
		t.Errorf("incorrect error details: %v", providerErr)
	}
}

func TestListScannerProviders(t *testing.T) {
	// Clear existing providers
	scannerMutex.Lock()
	scannerProviders = make(map[string]scanner.Provider)
	scannerMutex.Unlock()
	
	// Initially should be empty
	providers := ListScannerProviders()
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
	
	// Register some providers
	RegisterScannerProvider("provider1", scannerMock.NewProvider())
	RegisterScannerProvider("provider2", scannerMock.NewProvider())
	
	providers = ListScannerProviders()
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}
	
	// Check that both names are present
	names := make(map[string]bool)
	for _, name := range providers {
		names[name] = true
	}
	
	if !names["provider1"] || !names["provider2"] {
		t.Errorf("provider names not found: %v", providers)
	}
}

func TestRegisterAndGetSignerProvider(t *testing.T) {
	// Clear existing providers
	signerMutex.Lock()
	signerProviders = make(map[string]signer.Provider)
	signerMutex.Unlock()
	
	// Create and register a mock provider
	mockProvider := signerMock.NewProvider()
	RegisterSignerProvider("test-signer", mockProvider)
	
	// Retrieve the provider
	provider, err := GetSignerProvider("test-signer")
	if err != nil {
		t.Fatalf("failed to get signer provider: %v", err)
	}
	
	if provider.Name() != "mock" {
		t.Errorf("expected provider name 'mock', got '%s'", provider.Name())
	}
	
	// Try to get a non-existent provider
	_, err = GetSignerProvider("nonexistent")
	if err == nil {
		t.Error("expected error when getting non-existent provider")
	}
	
	providerErr, ok := err.(*ProviderNotFoundError)
	if !ok {
		t.Errorf("expected ProviderNotFoundError, got %T", err)
	}
	
	if providerErr.Type != "Signer" || providerErr.Name != "nonexistent" {
		t.Errorf("incorrect error details: %v", providerErr)
	}
}

func TestListSignerProviders(t *testing.T) {
	// Clear existing providers
	signerMutex.Lock()
	signerProviders = make(map[string]signer.Provider)
	signerMutex.Unlock()
	
	// Initially should be empty
	providers := ListSignerProviders()
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}
	
	// Register some providers
	RegisterSignerProvider("provider1", signerMock.NewProvider())
	RegisterSignerProvider("provider2", signerMock.NewProvider())
	
	providers = ListSignerProviders()
	if len(providers) != 2 {
		t.Errorf("expected 2 providers, got %d", len(providers))
	}
	
	// Check that both names are present
	names := make(map[string]bool)
	for _, name := range providers {
		names[name] = true
	}
	
	if !names["provider1"] || !names["provider2"] {
		t.Errorf("provider names not found: %v", providers)
	}
}

func TestProviderNotFoundError(t *testing.T) {
	err := &ProviderNotFoundError{
		Type: "SBOM",
		Name: "missing",
	}
	
	expected := "SBOM provider not found: missing"
	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}
