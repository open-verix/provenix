package cli

import (
	"fmt"
	"os"
)

// ExitError represents a CLI error with an explicit exit code.
// Codes follow Provenix semantics:
//   0 - success
//   1 - fatal error
//   2 - partial success (saved locally, Rekor unavailable)
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return ""
}

// NewExitError creates a new ExitError with the given code and message.
func NewExitError(code int, message string) *ExitError {
	return &ExitError{
		Code: code,
		Err:  fmt.Errorf(message),
	}
}

// Exit codes following Provenix's Atomic Evidence Failure Model.
// See docs/atomic_evidence_failure_model.md for detailed semantics.
const (
	// ExitSuccess indicates complete success:
	// - SBOM generated
	// - Vulnerabilities scanned
	// - Attestation signed
	// - Published to Rekor (if enabled)
	ExitSuccess = 0

	// ExitFatal indicates a fatal error:
	// - Cryptographic failure (signing/verification failed)
	// - Artifact not found or inaccessible
	// - Invalid configuration
	// - Critical policy violation (if strict mode enabled)
	ExitFatal = 1

	// ExitPartialSuccess indicates partial success:
	// - SBOM generated ✓
	// - Vulnerabilities scanned ✓
	// - Attestation signed ✓
	// - Rekor publishing FAILED ✗ (but attestation saved locally)
	//
	// This enables graceful degradation in CI/CD pipelines.
	// The attestation can be re-published later using `provenix publish`.
	ExitPartialSuccess = 2
)

// ExitCode maps any error to an exit code following Provenix semantics.
// Unknown errors default to 1.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*ExitError); ok {
		return ee.Code
	}
	return 1
}

// GetExitCodeName returns a human-readable name for the exit code.
func GetExitCodeName(code int) string {
	switch code {
	case ExitSuccess:
		return "Success"
	case ExitFatal:
		return "Fatal Error"
	case ExitPartialSuccess:
		return "Partial Success"
	default:
		return fmt.Sprintf("Unknown (%d)", code)
	}
}

// ExitWithMessage exits with the specified code and message.
func ExitWithMessage(code int, format string, args ...interface{}) {
	if format != "" {
		if code == ExitSuccess {
			fmt.Printf(format+"\n", args...)
		} else {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}
	}
	os.Exit(code)
}
