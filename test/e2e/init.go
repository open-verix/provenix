package e2e

import (
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom/syft"
	grypemock "github.com/open-verix/provenix/internal/providers/scanner/mock"
	signermock "github.com/open-verix/provenix/internal/providers/signer/mock"
)

// init registers all providers for E2E testing
func init() {
	// Register Syft SBOM provider
	providers.RegisterSBOMProvider("syft", syft.NewProvider())

	// Register Mock providers for scan and sign
	providers.RegisterScannerProvider("mock", &grypemock.Provider{})
	providers.RegisterSignerProvider("mock", &signermock.Provider{})
}
