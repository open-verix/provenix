package cli

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

// Exit codes
const (
    ExitSuccess        = 0
    ExitFatal          = 1
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
