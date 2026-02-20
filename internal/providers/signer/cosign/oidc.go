package cosign

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
	// Get the token request URL and token
	requestURL := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	requestToken := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	
	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("GitHub Actions OIDC environment variables not properly set")
	}

	// Construct request URL with audience
	audience := "sigstore"
	fullURL := fmt.Sprintf("%s&audience=%s", requestURL, audience)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Add("Authorization", "Bearer "+requestToken)
	req.Header.Add("Accept", "application/json; api-version=2.0")
	req.Header.Add("Content-Type", "application/json")

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResponse struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResponse.Value == "" {
		return "", fmt.Errorf("empty token received from GitHub Actions")
	}

	return tokenResponse.Value, nil
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
