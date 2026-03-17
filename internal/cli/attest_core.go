package cli

import (
	"context"
	"fmt"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/providers"
	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers/signer"
)

// CoreAttestOptions encapsulates all parameters needed to generate an attestation.
// Shared between the `attest` and `batch` commands to avoid duplicated logic.
type CoreAttestOptions struct {
	// Artifact is the target to attest (image reference, file path, directory).
	Artifact string

	// Config holds the loaded provenix configuration.
	Config *coreConfig

	// SBOMFormat controls the output format (cyclonedx-json, spdx-json, syft-json).
	SBOMFormat string

	// OutputPath is the file path to save the attestation JSON.
	// If empty, the caller is responsible for saving.
	OutputPath string

	// SkipTransparency disables Rekor publishing when true.
	SkipTransparency bool

	// GeneratorVersion is the version string embedded in the attestation metadata.
	GeneratorVersion string
}

// coreConfig is a minimal view of config fields consumed by GenerateAttestation.
// It mirrors the fields used from internal/policy/config.Config to avoid a
// circular dependency between cli and policy packages when testing.
type coreConfig struct {
	SBOMFormat       string
	SigningMode       string
	KeyPath          string
	FulcioURL        string
	RekorURL         string
	FailOnSeverity   string
}

// CoreAttestResult contains the output of a successful attestation.
type CoreAttestResult struct {
	// Evidence is the complete generated evidence object.
	Evidence *evidence.Evidence

	// SavedPath is the file path where the attestation was written.
	// Empty when OutputPath was not provided in CoreAttestOptions.
	SavedPath string

	// RekorUUID is the transparency log entry UUID, empty when Rekor was skipped.
	RekorUUID string
}

// GenerateAttestation performs the full attestation pipeline for a single artifact:
//
//  1. Retrieves registered providers (Syft, Grype, Cosign).
//     Returns an error immediately if any provider is not registered — no mock
//     fallback in production code.
//  2. Builds evidence.GenerateOptions from opts.
//  3. Calls gen.Generate() — the atomic SBOM → Scan → Sign pipeline.
//  4. Saves the attestation to opts.OutputPath when non-empty.
//
// This function is the single source of truth for attestation logic and is
// called by both runAttest() (attest.go) and processArtifact() (batch.go).
func GenerateAttestation(ctx context.Context, opts CoreAttestOptions) (*CoreAttestResult, error) {
	if opts.Artifact == "" {
		return nil, fmt.Errorf("artifact must not be empty")
	}

	// --- 1. Acquire providers (hard fail — no mock fallback) ---

	sbomProvider, err := providers.GetSBOMProvider("syft")
	if err != nil {
		return nil, fmt.Errorf("SBOM provider unavailable: %w", err)
	}

	scannerProvider, err := providers.GetScannerProvider("grype")
	if err != nil {
		return nil, fmt.Errorf("scanner provider unavailable: %w", err)
	}

	signerProvider, err := providers.GetSignerProvider("cosign")
	if err != nil {
		return nil, fmt.Errorf("signer provider unavailable: %w", err)
	}

	// --- 2. Build generation options from CoreAttestOptions ---

	skipTransparency := opts.SkipTransparency
	if opts.Config != nil && opts.Config.RekorURL == "" {
		skipTransparency = true
	}

	rekorURL := ""
	if opts.Config != nil {
		rekorURL = opts.Config.RekorURL
	}

	genOpts := evidence.GenerateOptions{
		SBOMOptions: sbom.Options{
			Format: sbom.Format(opts.SBOMFormat),
		},
		ScanOptions: scanner.Options{
			FailOnSeverity: scanner.Severity(failOnSeverity(opts.Config)),
		},
		SignOptions: signer.Options{
			Mode:             signer.SigningMode(signingMode(opts.Config)),
			KeyPath:          keyPath(opts.Config),
			FulcioURL:        fulcioURL(opts.Config),
			RekorURL:         rekorURL,
			OIDCClientID:     "sigstore",
			SkipTransparency: skipTransparency,
		},
		GeneratorVersion: opts.GeneratorVersion,
	}

	// --- 3. Generate evidence (atomic: SBOM → Scan → Sign, no temp files) ---

	gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)

	ev, err := gen.Generate(ctx, opts.Artifact, genOpts)
	if err != nil {
		return nil, fmt.Errorf("evidence generation failed for %s: %w", opts.Artifact, err)
	}

	// --- 4. Save to file if an output path was provided ---

	savedPath := ""
	if opts.OutputPath != "" {
		if err := saveEvidence(ev, opts.OutputPath); err != nil {
			return nil, fmt.Errorf("failed to save attestation: %w", err)
		}
		savedPath = opts.OutputPath
	}

	// --- 5. Extract Rekor UUID if published ---

	rekorUUID := ""
	if ev.Signature != nil {
		rekorUUID = ev.Signature.RekorEntry
	}

	return &CoreAttestResult{
		Evidence:  ev,
		SavedPath: savedPath,
		RekorUUID: rekorUUID,
	}, nil
}

// buildCoreConfig converts the fields used by attest.go / batch.go into the
// flat coreConfig view consumed by GenerateAttestation.
//
// This keeps the shared attestation logic independent of the full
// internal/policy.Config struct and makes unit testing straightforward:
// tests can construct a coreConfig directly without a real config file.
func buildCoreConfig(
	sbomFormat string,
	signingMode string,
	keyPath string,
	fulcioURL string,
	rekorURL string,
	failOnSeverity string,
) *coreConfig {
	return &coreConfig{
		SBOMFormat:     sbomFormat,
		SigningMode:    signingMode,
		KeyPath:        keyPath,
		FulcioURL:      fulcioURL,
		RekorURL:       rekorURL,
		FailOnSeverity: failOnSeverity,
	}
}

// --- helpers to safely dereference optional coreConfig ---

func failOnSeverity(cfg *coreConfig) string {
	if cfg == nil {
		return "critical"
	}
	return cfg.FailOnSeverity
}

func signingMode(cfg *coreConfig) string {
	if cfg == nil {
		return "keyless"
	}
	return cfg.SigningMode
}

func keyPath(cfg *coreConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.KeyPath
}

func fulcioURL(cfg *coreConfig) string {
	if cfg == nil {
		return ""
	}
	return cfg.FulcioURL
}
