package integration

import (
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom/mock"
	"github.com/open-verix/provenix/internal/providers/sbom/syft"
	grypemock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	signermock "github.com/open-verix/provenix/internal/providers/signer/mock"
	
	// Import SQLite driver for Syft
	_ "modernc.org/sqlite"
)

// init registers all providers for testing
func init() {
	// Register Syft SBOM provider
	providers.RegisterSBOMProvider("syft", syft.NewProvider())

	// Register Mock providers
	providers.RegisterSBOMProvider("mock-sbom", &mock.Provider{})
	providers.RegisterScannerProvider("mock", &grypemock.Provider{})
	providers.RegisterSignerProvider("mock", &signermock.Provider{})
}
