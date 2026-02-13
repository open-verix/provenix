package cli

import (
	"errors"
	"testing"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{
			name:     "nil error returns 0",
			err:      nil,
			expected: ExitSuccess,
		},
		{
			name:     "ExitError with code 2 returns 2",
			err:      &ExitError{Code: ExitPartialSuccess, Err: errors.New("rekor unavailable")},
			expected: ExitPartialSuccess,
		},
		{
			name:     "ExitError with code 1 returns 1",
			err:      &ExitError{Code: ExitFatal, Err: errors.New("signing failed")},
			expected: ExitFatal,
		},
		{
			name:     "regular error returns 1",
			err:      errors.New("some error"),
			expected: ExitFatal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExitCode(tt.err)
			if got != tt.expected {
				t.Errorf("ExitCode() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestGetExitCodeName(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{ExitSuccess, "Success"},
		{ExitFatal, "Fatal Error"},
		{ExitPartialSuccess, "Partial Success"},
		{99, "Unknown (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := GetExitCodeName(tt.code)
			if got != tt.expected {
				t.Errorf("GetExitCodeName(%d) = %q, want %q", tt.code, got, tt.expected)
			}
		})
	}
}

func TestExitError_Error(t *testing.T) {
	tests := []struct {
		name     string
		exitErr  *ExitError
		expected string
	}{
		{
			name:     "error with message",
			exitErr:  &ExitError{Code: ExitPartialSuccess, Err: errors.New("test error")},
			expected: "test error",
		},
		{
			name:     "error without message",
			exitErr:  &ExitError{Code: ExitSuccess, Err: nil},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.exitErr.Error()
			if got != tt.expected {
				t.Errorf("ExitError.Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}
