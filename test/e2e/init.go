package e2e

import (
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom/syft"
	grypemock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	signermock "github.com/open-verix/provenix/internal/providers/signer/mock"
	
	// Import SQLite driver for Syft
	_ "modernc.org/sqlite"
)

// init registers all providers for E2E testing
func init() {
	// Register Syft SBOM provider
	providers.RegisterSBOMProvider("syft", syft.NewProvider())

	// Register Mock providers for scan and sign
	providers.RegisterScannerProvider("mock", &grypemock.Provider{})
	providers.RegisterSignerProvider("mock", &signermock.Provider{})
	
	// Note: Real Grype and Cosign providers are registered in real_providers_test.go
	// to avoid SQLite driver conflicts during package initialization
}
