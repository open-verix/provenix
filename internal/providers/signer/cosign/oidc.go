package cosign

import (
	"context"
	"fmt"
	"os"

	"github.com/sigstore/cosign/v2/pkg/providers"
)

// OIDCTokenProvider handles OIDC token acquisition from various CI/CD environments.
type OIDCTokenProvider struct {
	clientID string
}

// NewOIDCTokenProvider creates a new OIDC token provider.
func NewOIDCTokenProvider(clientID string) *OIDCTokenProvider {
	return &OIDCTokenProvider{
		clientID: clientID,
	}
}

// GetToken retrieves an OIDC token from the environment.
// 
// Detection order:
// 1. GitHub Actions (ACTIONS_ID_TOKEN_REQUEST_URL)
// 2. GitLab CI (CI_JOB_JWT_V2)
// 3. Google Cloud Build (GOOGLE_APPLICATION_CREDENTIALS)
// 4. Environment variable (SIGSTORE_ID_TOKEN)
// 5. Interactive browser flow (fallback)
func (p *OIDCTokenProvider) GetToken(ctx context.Context) (string, error) {
	// Try GitHub Actions first
	if isGitHubActions() {
		token, err := p.getGitHubActionsToken(ctx)
		if err == nil {
			return token, nil
		}
		// Log error but continue to other providers
		fmt.Fprintf(os.Stderr, "Warning: GitHub Actions OIDC token retrieval failed: %v\n", err)
	}

	// Try GitLab CI
	if isGitLabCI() {
		token, err := p.getGitLabCIToken(ctx)
		if err == nil {
			return token, nil
		}
		fmt.Fprintf(os.Stderr, "Warning: GitLab CI OIDC token retrieval failed: %v\n", err)
	}

	// Try environment variable
	if envToken := os.Getenv("SIGSTORE_ID_TOKEN"); envToken != "" {
		return envToken, nil
	}

	// Fallback to Cosign's built-in provider (supports multiple backends)
	// This will fail if no providers are enabled (non-CI environment)
	token, err := providers.Provide(ctx, p.clientID)
	if err != nil {
		return "", fmt.Errorf("no OIDC token available: not in CI/CD environment and no SIGSTORE_ID_TOKEN set. Use --key for local development: %w", err)
	}

	return token, nil
}

// isGitHubActions checks if running in GitHub Actions environment.
func isGitHubActions() bool {
	return os.Getenv("GITHUB_ACTIONS") == "true" &&
		os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != ""
}

// isGitLabCI checks if running in GitLab CI environment.
func isGitLabCI() bool {
	return os.Getenv("GITLAB_CI") == "true" &&
		os.Getenv("CI_JOB_JWT_V2") != ""
}

// getGitHubActionsToken retrieves OIDC token from GitHub Actions.
func (p *OIDCTokenProvider) getGitHubActionsToken(ctx context.Context) (string, error) {
	// GitHub Actions OIDC token is available via providers.GitHub()
	// The cosign library handles the HTTP request to ACTIONS_ID_TOKEN_REQUEST_URL
	token, err := providers.Provide(ctx, "sigstore")
	if err != nil {
		return "", fmt.Errorf("GitHub Actions token retrieval failed: %w", err)
	}
	return token, nil
}

// getGitLabCIToken retrieves OIDC token from GitLab CI.
func (p *OIDCTokenProvider) getGitLabCIToken(ctx context.Context) (string, error) {
	// GitLab provides JWT token directly in environment variable
	token := os.Getenv("CI_JOB_JWT_V2")
	if token == "" {
		return "", fmt.Errorf("CI_JOB_JWT_V2 environment variable not set")
	}
	return token, nil
}

// GetEnvironmentInfo returns information about the detected CI/CD environment.
func GetEnvironmentInfo() map[string]string {
	info := make(map[string]string)

	if isGitHubActions() {
		info["provider"] = "github-actions"
		info["repository"] = os.Getenv("GITHUB_REPOSITORY")
		info["workflow"] = os.Getenv("GITHUB_WORKFLOW")
		info["run_id"] = os.Getenv("GITHUB_RUN_ID")
		info["ref"] = os.Getenv("GITHUB_REF")
		info["sha"] = os.Getenv("GITHUB_SHA")
		info["actor"] = os.Getenv("GITHUB_ACTOR")
	} else if isGitLabCI() {
		info["provider"] = "gitlab-ci"
		info["project"] = os.Getenv("CI_PROJECT_PATH")
		info["pipeline_id"] = os.Getenv("CI_PIPELINE_ID")
		info["job_id"] = os.Getenv("CI_JOB_ID")
		info["ref"] = os.Getenv("CI_COMMIT_REF_NAME")
		info["sha"] = os.Getenv("CI_COMMIT_SHA")
		info["user"] = os.Getenv("GITLAB_USER_LOGIN")
	} else {
		info["provider"] = "unknown"
		info["interactive"] = "true"
	}

	return info
}
