package evidence

import (
	"encoding/json"
	"time"
)

// SLSA Provenance v1.0 structures
// Reference: https://slsa.dev/spec/v1.0/provenance

const (
	// PredicateTypeSLSAProvenance is the predicate type for SLSA Provenance v1.0
	PredicateTypeSLSAProvenance = "https://slsa.dev/provenance/v1"
)

// SLSAProvenance represents a SLSA Provenance v1.0 predicate.
type SLSAProvenance struct {
	BuildDefinition BuildDefinition `json:"buildDefinition"`
	RunDetails      RunDetails      `json:"runDetails"`
}

// BuildDefinition describes all of the inputs to the build.
type BuildDefinition struct {
	// BuildType identifies the template for how to perform the build.
	// For Provenix, this identifies the type of artifact being built.
	BuildType string `json:"buildType"`

	// ExternalParameters are the parameters under external control.
	// These MUST be verified by consumers.
	ExternalParameters map[string]interface{} `json:"externalParameters"`

	// InternalParameters are under the control of the builder.
	// Optional, for debugging and incident response.
	InternalParameters map[string]interface{} `json:"internalParameters,omitempty"`

	// ResolvedDependencies are artifacts needed at build time.
	// Best effort completeness through SLSA Build L3.
	ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
}

// RunDetails contains details specific to this particular execution.
type RunDetails struct {
	Builder  Builder       `json:"builder"`
	Metadata BuildMetadata `json:"metadata"`

	// Byproducts are additional artifacts generated during the build
	// (e.g., logs, fully evaluated configuration).
	Byproducts []ResourceDescriptor `json:"byproducts,omitempty"`
}

// Builder identifies the build platform that executed the build.
type Builder struct {
	// ID is the URI indicating the transitive closure of the trusted build platform.
	// This determines the SLSA Build level.
	ID string `json:"id"`

	// BuilderDependencies are dependencies used by the orchestrator.
	BuilderDependencies []ResourceDescriptor `json:"builderDependencies,omitempty"`

	// Version maps component names to their versions.
	Version map[string]string `json:"version,omitempty"`
}

// BuildMetadata contains metadata about this particular build execution.
type BuildMetadata struct {
	// InvocationID uniquely identifies this build invocation.
	InvocationID string `json:"invocationId,omitempty"`

	// StartedOn is when the build started (RFC3339).
	StartedOn string `json:"startedOn,omitempty"`

	// FinishedOn is when the build completed (RFC3339).
	FinishedOn string `json:"finishedOn,omitempty"`
}

// ResourceDescriptor describes an artifact or resource.
type ResourceDescriptor struct {
	// URI is a URI used to identify the resource or artifact globally.
	URI string `json:"uri,omitempty"`

	// Digest is a set of cryptographic digests of the resource.
	Digest map[string]string `json:"digest,omitempty"`

	// Name is a machine-readable identifier for the resource.
	Name string `json:"name,omitempty"`

	// DownloadLocation is where the resource can be downloaded.
	DownloadLocation string `json:"downloadLocation,omitempty"`

	// MediaType is the MIME type of the resource.
	MediaType string `json:"mediaType,omitempty"`

	// Content is the contents of the resource (base64-encoded).
	Content json.RawMessage `json:"content,omitempty"`

	// Annotations contains additional metadata.
	Annotations map[string]interface{} `json:"annotations,omitempty"`
}

// CreateSLSAProvenance creates a SLSA Provenance v1.0 predicate for Provenix attestations.
//
// This is a minimal implementation that records:
// - Build type (artifact type)
// - External parameters (artifact reference, platform)
// - Internal parameters (Provenix configuration)
// - Builder information (Provenix version, execution environment)
// - Execution metadata (timestamps, invocation ID)
func CreateSLSAProvenance(
	artifact string,
	artifactType string, // e.g., "container", "binary", "directory"
	platform string,
	provenixVersion string,
	startedAt time.Time,
	finishedAt time.Time,
	invocationID string,
	buildEnv map[string]string, // CI environment variables
) *SLSAProvenance {
	// Determine build type URI based on artifact type
	buildType := determineBuildType(artifactType)

	// External parameters - visible to and controlled by users
	externalParams := map[string]interface{}{
		"artifact": artifact,
	}
	if platform != "" {
		externalParams["platform"] = platform
	}

	// Internal parameters - controlled by Provenix
	internalParams := map[string]interface{}{
		"artifactType": artifactType,
	}

	// Builder information
	builder := Builder{
		ID: "https://github.com/open-verix/provenix",
		Version: map[string]string{
			"provenix": provenixVersion,
		},
	}

	// Add CI platform information if available
	if ciPlatform, detected := detectCIPlatform(buildEnv); detected {
		builder.Version["ci-platform"] = ciPlatform
	}

	// Build metadata
	metadata := BuildMetadata{}
	if invocationID != "" {
		metadata.InvocationID = invocationID
	}
	if !startedAt.IsZero() {
		metadata.StartedOn = startedAt.Format(time.RFC3339)
	}
	if !finishedAt.IsZero() {
		metadata.FinishedOn = finishedAt.Format(time.RFC3339)
	}

	return &SLSAProvenance{
		BuildDefinition: BuildDefinition{
			BuildType:          buildType,
			ExternalParameters: externalParams,
			InternalParameters: internalParams,
		},
		RunDetails: RunDetails{
			Builder:  builder,
			Metadata: metadata,
		},
	}
}

// determineBuildType returns the SLSA build type URI based on artifact type.
func determineBuildType(artifactType string) string {
	// Use Provenix-specific build type URIs
	// These should resolve to documentation explaining the build process
	baseURI := "https://github.com/open-verix/provenix/buildtypes"

	switch artifactType {
	case "container", "docker":
		return baseURI + "/container/v1"
	case "binary", "executable":
		return baseURI + "/binary/v1"
	case "directory", "filesystem":
		return baseURI + "/directory/v1"
	case "archive", "oci-archive":
		return baseURI + "/archive/v1"
	default:
		return baseURI + "/generic/v1"
	}
}

// detectCIPlatform detects the CI platform from environment variables.
func detectCIPlatform(env map[string]string) (string, bool) {
	// GitHub Actions
	if env["GITHUB_ACTIONS"] == "true" {
		return "github-actions", true
	}

	// GitLab CI
	if env["GITLAB_CI"] == "true" {
		return "gitlab-ci", true
	}

	// Jenkins
	if env["JENKINS_URL"] != "" {
		return "jenkins", true
	}

	// CircleCI
	if env["CIRCLECI"] == "true" {
		return "circleci", true
	}

	// Travis CI
	if env["TRAVIS"] == "true" {
		return "travis-ci", true
	}

	// Azure Pipelines
	if env["TF_BUILD"] == "true" {
		return "azure-pipelines", true
	}

	return "", false
}
