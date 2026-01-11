package providers

import (
	"fmt"
	"sync"
	
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers/signer"
)

var (
	// sbomProviders stores registered SBOM providers
	sbomProviders = make(map[string]sbom.Provider)
	sbomMutex     sync.RWMutex
	
	// scannerProviders stores registered scanner providers
	scannerProviders = make(map[string]scanner.Provider)
	scannerMutex     sync.RWMutex
	
	// signerProviders stores registered signer providers
	signerProviders = make(map[string]signer.Provider)
	signerMutex     sync.RWMutex
)

// RegisterSBOMProvider registers an SBOM provider by name.
// This should be called in init() functions of provider implementations.
//
// Example:
//   func init() {
//       providers.RegisterSBOMProvider("syft", &syft.Provider{})
//   }
func RegisterSBOMProvider(name string, provider sbom.Provider) {
	sbomMutex.Lock()
	defer sbomMutex.Unlock()
	
	sbomProviders[name] = provider
}

// GetSBOMProvider retrieves a registered SBOM provider by name.
// Returns an error if the provider is not found.
func GetSBOMProvider(name string) (sbom.Provider, error) {
	sbomMutex.RLock()
	defer sbomMutex.RUnlock()
	
	provider, ok := sbomProviders[name]
	if !ok {
		return nil, &ProviderNotFoundError{
			Type: "SBOM",
			Name: name,
		}
	}
	
	return provider, nil
}

// ListSBOMProviders returns all registered SBOM provider names.
func ListSBOMProviders() []string {
	sbomMutex.RLock()
	defer sbomMutex.RUnlock()
	
	names := make([]string, 0, len(sbomProviders))
	for name := range sbomProviders {
		names = append(names, name)
	}
	
	return names
}

// RegisterScannerProvider registers a scanner provider by name.
// This should be called in init() functions of provider implementations.
//
// Example:
//   func init() {
//       providers.RegisterScannerProvider("grype", &grype.Provider{})
//   }
func RegisterScannerProvider(name string, provider scanner.Provider) {
	scannerMutex.Lock()
	defer scannerMutex.Unlock()
	
	scannerProviders[name] = provider
}

// GetScannerProvider retrieves a registered scanner provider by name.
// Returns an error if the provider is not found.
func GetScannerProvider(name string) (scanner.Provider, error) {
	scannerMutex.RLock()
	defer scannerMutex.RUnlock()
	
	provider, ok := scannerProviders[name]
	if !ok {
		return nil, &ProviderNotFoundError{
			Type: "Scanner",
			Name: name,
		}
	}
	
	return provider, nil
}

// ListScannerProviders returns all registered scanner provider names.
func ListScannerProviders() []string {
	scannerMutex.RLock()
	defer scannerMutex.RUnlock()
	
	names := make([]string, 0, len(scannerProviders))
	for name := range scannerProviders {
		names = append(names, name)
	}
	
	return names
}

// RegisterSignerProvider registers a signer provider by name.
// This should be called in init() functions of provider implementations.
//
// Example:
//   func init() {
//       providers.RegisterSignerProvider("cosign", &cosign.Provider{})
//   }
func RegisterSignerProvider(name string, provider signer.Provider) {
	signerMutex.Lock()
	defer signerMutex.Unlock()
	
	signerProviders[name] = provider
}

// GetSignerProvider retrieves a registered signer provider by name.
// Returns an error if the provider is not found.
func GetSignerProvider(name string) (signer.Provider, error) {
	signerMutex.RLock()
	defer signerMutex.RUnlock()
	
	provider, ok := signerProviders[name]
	if !ok {
		return nil, &ProviderNotFoundError{
			Type: "Signer",
			Name: name,
		}
	}
	
	return provider, nil
}

// ListSignerProviders returns all registered signer provider names.
func ListSignerProviders() []string {
	signerMutex.RLock()
	defer signerMutex.RUnlock()
	
	names := make([]string, 0, len(signerProviders))
	for name := range signerProviders {
		names = append(names, name)
	}
	
	return names
}

// ProviderNotFoundError is returned when a provider is not registered.
type ProviderNotFoundError struct {
	Type string
	Name string
}

func (e *ProviderNotFoundError) Error() string {
	return fmt.Sprintf("%s provider not found: %s", e.Type, e.Name)
}
