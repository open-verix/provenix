package main

import (
	_ "github.com/open-verix/provenix/internal/providers/sbom/syft"
	_ "github.com/open-verix/provenix/internal/providers/scanner/grype"
	_ "github.com/open-verix/provenix/internal/providers/signer/cosign"
)

// This file ensures all providers are registered when the main package loads.
// Using blank imports forces the provider package init() functions to run.
