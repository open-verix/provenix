package evidence

import "errors"

var (
	// ErrInvalidArtifact indicates the artifact identifier is invalid
	ErrInvalidArtifact = errors.New("invalid artifact identifier")

	// ErrMissingDigest indicates the artifact digest is missing
	ErrMissingDigest = errors.New("artifact digest is required")

	// ErrMissingSBOM indicates the SBOM is missing
	ErrMissingSBOM = errors.New("SBOM is required")

	// ErrMissingVulnReport indicates the vulnerability report is missing
	ErrMissingVulnReport = errors.New("vulnerability report is required")

	// ErrMissingStatement indicates the in-toto statement is missing
	ErrMissingStatement = errors.New("in-toto statement is required")

	// ErrMissingSignature indicates the signature is missing
	ErrMissingSignature = errors.New("signature is required")

	// ErrMissingMetadata indicates the metadata is missing
	ErrMissingMetadata = errors.New("metadata is required")

	// ErrGenerationFailed indicates evidence generation failed
	ErrGenerationFailed = errors.New("evidence generation failed")

	// ErrSBOMGeneration indicates SBOM generation failed
	ErrSBOMGeneration = errors.New("SBOM generation failed")

	// ErrVulnerabilityScan indicates vulnerability scanning failed
	ErrVulnerabilityScan = errors.New("vulnerability scan failed")

	// ErrStatementCreation indicates in-toto statement creation failed
	ErrStatementCreation = errors.New("statement creation failed")

	// ErrSigning indicates signing failed
	ErrSigning = errors.New("signing failed")
)
