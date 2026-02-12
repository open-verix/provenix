package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/open-verix/provenix/internal/providers/sbom"
	"github.com/open-verix/provenix/internal/providers/scanner"
	"github.com/open-verix/provenix/internal/providers/signer"
)

// Generator creates atomic evidence for software artifacts.
//
// It orchestrates SBOM generation, vulnerability scanning, and signing
// in a single atomic operation with no temporary files.
//
// Critical: All data flows in-memory to prevent TOCTOU vulnerabilities.
type Generator struct {
	sbomProvider    sbom.Provider
	scannerProvider scanner.Provider
	signerProvider  signer.Provider
}

// NewGenerator creates a new evidence generator.
func NewGenerator(
	sbomProvider sbom.Provider,
	scannerProvider scanner.Provider,
	signerProvider signer.Provider,
) *Generator {
	return &Generator{
		sbomProvider:    sbomProvider,
		scannerProvider: scannerProvider,
		signerProvider:  signerProvider,
	}
}

// Generate generates atomic evidence for an artifact.
//
// This method executes the following atomic pipeline:
//  1. Generate SBOM (in-memory)
//  2. Scan vulnerabilities using SBOM (in-memory)
//  3. Create in-toto statement from SBOM + vulnerability report
//  4. Sign the statement
//
// All operations are performed in-memory to ensure atomicity and prevent
// time-of-check to time-of-use (TOCTOU) vulnerabilities.
//
// Exit semantics:
//   - Returns Evidence + nil error on complete success
//   - Returns nil + error on any failure (caller handles exit codes)
func (g *Generator) Generate(
	ctx context.Context,
	artifact string,
	opts GenerateOptions,
) (*Evidence, error) {
	startTime := time.Now()

	// Validate inputs
	if artifact == "" {
		return nil, ErrInvalidArtifact
	}

	// Step 1: Generate SBOM (in-memory)
	sbomData, err := g.generateSBOM(ctx, artifact, opts.SBOMOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSBOMGeneration, err)
	}

	// Extract artifact digest from SBOM metadata
	artifactDigest := extractDigest(sbomData)
	if artifactDigest == "" {
		return nil, fmt.Errorf("%w: failed to extract artifact digest from SBOM", ErrMissingDigest)
	}

	// Step 2: Scan vulnerabilities (in-memory, using SBOM)
	vulnReport, err := g.scanVulnerabilities(ctx, sbomData, opts.ScanOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVulnerabilityScan, err)
	}

	// Step 3: Create in-toto statement
	statement, err := g.createStatement(
		artifact,
		artifactDigest,
		sbomData,
		vulnReport,
		opts.GeneratorVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStatementCreation, err)
	}

	// Step 4: Sign the statement
	signature, err := g.signStatement(ctx, statement, opts.SignOptions)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigning, err)
	}

	// Create evidence
	evidence := &Evidence{
		Artifact:            artifact,
		ArtifactDigest:      artifactDigest,
		SBOM:                sbomData,
		VulnerabilityReport: vulnReport,
		Statement:           statement,
		Signature:           signature,
		Metadata: &Metadata{
			GeneratedAt:      time.Now().UTC(),
			GeneratorVersion: opts.GeneratorVersion,
			SBOMProvider: ProviderInfo{
				Name:    g.sbomProvider.Name(),
				Version: g.sbomProvider.Version(),
			},
			ScannerProvider: ProviderInfo{
				Name:    g.scannerProvider.Name(),
				Version: g.scannerProvider.Version(),
			},
			SignerProvider: ProviderInfo{
				Name:    g.signerProvider.Name(),
				Version: g.signerProvider.Version(),
			},
			Duration: time.Since(startTime),
		},
	}

	// Validate evidence structure
	if err := evidence.Validate(); err != nil {
		return nil, fmt.Errorf("%w: validation failed: %v", ErrGenerationFailed, err)
	}

	return evidence, nil
}

// generateSBOM generates SBOM for the artifact.
func (g *Generator) generateSBOM(
	ctx context.Context,
	artifact string,
	opts sbom.Options,
) (*sbom.SBOM, error) {
	return g.sbomProvider.Generate(ctx, artifact, opts)
}

// scanVulnerabilities scans vulnerabilities using the SBOM.
func (g *Generator) scanVulnerabilities(
	ctx context.Context,
	sbomData *sbom.SBOM,
	opts scanner.Options,
) (*scanner.Report, error) {
	// Create scan input with SBOM
	input := scanner.ScanInput{
		SBOM: sbomData,
	}
	return g.scannerProvider.Scan(ctx, input, opts)
}

// createStatement creates an in-toto attestation statement.
func (g *Generator) createStatement(
	artifact string,
	artifactDigest string,
	sbomData *sbom.SBOM,
	vulnReport *scanner.Report,
	generatorVersion string,
) ([]byte, error) {
	return CreateStatement(
		artifact,
		artifactDigest,
		sbomData,
		vulnReport,
		generatorVersion,
		g.sbomProvider.Name(),
		g.sbomProvider.Version(),
		g.scannerProvider.Name(),
		g.scannerProvider.Version(),
	)
}

// signStatement signs the in-toto statement.
func (g *Generator) signStatement(
	ctx context.Context,
	statementJSON []byte,
	opts signer.Options,
) (*signer.Signature, error) {
	// Parse the JSON statement into a Statement struct
	var stmt Statement
	if err := json.Unmarshal(statementJSON, &stmt); err != nil {
		return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
	}

	// Convert to signer.Statement
	// Marshal predicate to json.RawMessage
	predicateJSON, err := json.Marshal(stmt.Predicate)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal predicate: %w", err)
	}

	signerStmt := &signer.Statement{
		Type:          stmt.Type,
		Subject:       convertSubjects(stmt.Subject),
		PredicateType: stmt.PredicateType,
		Predicate:     predicateJSON,
		RawJSON:       statementJSON, // Store raw JSON for verification
	}

	return g.signerProvider.Sign(ctx, signerStmt, opts)
}

// extractDigest extracts the artifact digest from SBOM.
func extractDigest(sbomData *sbom.SBOM) string {
	// Use the SBOM checksum as the artifact digest
	// The checksum represents the SHA256 of the SBOM content
	return sbomData.Checksum
}

// convertSubjects converts evidence.Subject to signer.Subject.
func convertSubjects(subjects []Subject) []signer.Subject {
	result := make([]signer.Subject, len(subjects))
	for i, s := range subjects {
		result[i] = signer.Subject{
			Name:   s.Name,
			Digest: s.Digest,
		}
	}
	return result
}
