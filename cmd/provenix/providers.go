package main

import (
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom/syft"
	"github.com/open-verix/provenix/internal/providers/scanner/grype"
	"github.com/open-verix/provenix/internal/providers/signer/cosign"
)

// init registers all providers.
// Manual registration to avoid SQLite driver conflicts.
// Note: SQLite driver is automatically registered by Syft/Grype dependencies.
func init() {
	providers.RegisterSBOMProvider("syft", syft.NewProvider())
	providers.RegisterScannerProvider("grype", grype.NewProvider())
	providers.RegisterSignerProvider("cosign", cosign.NewProvider())
}
