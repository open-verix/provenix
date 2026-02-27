package evidence

import (
	"testing"
	"time"
)

func TestCreateSLSAProvenance(t *testing.T) {
	tests := []struct {
		name         string
		artifact     string
		artifactType string
		platform     string
		version      string
		buildEnv     map[string]string
		wantBuildType string
		wantCI       string
	}{
		{
			name:          "Container artifact",
			artifact:      "nginx:latest",
			artifactType:  "container",
			platform:      "linux/amd64",
			version:       "0.1.0",
			buildEnv:      map[string]string{},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/container/v1",
			wantCI:        "",
		},
		{
			name:          "Binary artifact",
			artifact:      "./myapp",
			artifactType:  "binary",
			platform:      "",
			version:       "0.1.0",
			buildEnv:      map[string]string{},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/binary/v1",
			wantCI:        "",
		},
		{
			name:         "GitHub Actions environment",
			artifact:     "myimage:v1.0",
			artifactType: "container",
			platform:     "linux/arm64",
			version:      "0.1.0",
			buildEnv: map[string]string{
				"GITHUB_ACTIONS": "true",
				"GITHUB_WORKFLOW": "CI",
			},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/container/v1",
			wantCI:        "github-actions",
		},
		{
			name:         "GitLab CI environment",
			artifact:     "myapp:latest",
			artifactType: "container",
			platform:     "",
			version:      "0.2.0",
			buildEnv: map[string]string{
				"GITLAB_CI": "true",
			},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/container/v1",
			wantCI:        "gitlab-ci",
		},
		{
			name:          "Directory artifact",
			artifact:      "/path/to/dir",
			artifactType:  "directory",
			platform:      "",
			version:       "0.1.0",
			buildEnv:      map[string]string{},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/directory/v1",
			wantCI:        "",
		},
		{
			name:          "Archive artifact",
			artifact:      "archive.tar",
			artifactType:  "archive",
			platform:      "",
			version:       "0.1.0",
			buildEnv:      map[string]string{},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/archive/v1",
			wantCI:        "",
		},
		{
			name:          "Unknown artifact type defaults to generic",
			artifact:      "something",
			artifactType:  "unknown",
			platform:      "",
			version:       "0.1.0",
			buildEnv:      map[string]string{},
			wantBuildType: "https://github.com/open-verix/provenix/buildtypes/generic/v1",
			wantCI:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startedAt := time.Now().UTC()
			finishedAt := startedAt.Add(5 * time.Second)
			invocationID := "test-invocation-123"

			provenance := CreateSLSAProvenance(
				tt.artifact,
				tt.artifactType,
				tt.platform,
				tt.version,
				startedAt,
				finishedAt,
				invocationID,
				tt.buildEnv,
			)

			// Verify build type
			if provenance.BuildDefinition.BuildType != tt.wantBuildType {
				t.Errorf("BuildType = %v, want %v", provenance.BuildDefinition.BuildType, tt.wantBuildType)
			}

			// Verify external parameters
			if provenance.BuildDefinition.ExternalParameters["artifact"] != tt.artifact {
				t.Errorf("ExternalParameters[artifact] = %v, want %v",
					provenance.BuildDefinition.ExternalParameters["artifact"], tt.artifact)
			}

			if tt.platform != "" {
				if provenance.BuildDefinition.ExternalParameters["platform"] != tt.platform {
					t.Errorf("ExternalParameters[platform] = %v, want %v",
						provenance.BuildDefinition.ExternalParameters["platform"], tt.platform)
				}
			}

			// Verify internal parameters
			if provenance.BuildDefinition.InternalParameters["artifactType"] != tt.artifactType {
				t.Errorf("InternalParameters[artifactType] = %v, want %v",
					provenance.BuildDefinition.InternalParameters["artifactType"], tt.artifactType)
			}

			// Verify builder ID
			expectedBuilderID := "https://github.com/open-verix/provenix"
			if provenance.RunDetails.Builder.ID != expectedBuilderID {
				t.Errorf("Builder.ID = %v, want %v", provenance.RunDetails.Builder.ID, expectedBuilderID)
			}

			// Verify builder version
			if provenance.RunDetails.Builder.Version["provenix"] != tt.version {
				t.Errorf("Builder.Version[provenix] = %v, want %v",
					provenance.RunDetails.Builder.Version["provenix"], tt.version)
			}

			// Verify CI platform detection
			if tt.wantCI != "" {
				if provenance.RunDetails.Builder.Version["ci-platform"] != tt.wantCI {
					t.Errorf("Builder.Version[ci-platform] = %v, want %v",
						provenance.RunDetails.Builder.Version["ci-platform"], tt.wantCI)
				}
			} else {
				if _, exists := provenance.RunDetails.Builder.Version["ci-platform"]; exists {
					t.Errorf("Builder.Version[ci-platform] should not exist, but got %v",
						provenance.RunDetails.Builder.Version["ci-platform"])
				}
			}

			// Verify metadata
			if provenance.RunDetails.Metadata.InvocationID != invocationID {
				t.Errorf("Metadata.InvocationID = %v, want %v",
					provenance.RunDetails.Metadata.InvocationID, invocationID)
			}

			if provenance.RunDetails.Metadata.StartedOn != startedAt.Format(time.RFC3339) {
				t.Errorf("Metadata.StartedOn = %v, want %v",
					provenance.RunDetails.Metadata.StartedOn, startedAt.Format(time.RFC3339))
			}

			if provenance.RunDetails.Metadata.FinishedOn != finishedAt.Format(time.RFC3339) {
				t.Errorf("Metadata.FinishedOn = %v, want %v",
					provenance.RunDetails.Metadata.FinishedOn, finishedAt.Format(time.RFC3339))
			}
		})
	}
}

func TestDetectCIPlatform(t *testing.T) {
	tests := []struct {
		name         string
		env          map[string]string
		wantPlatform string
		wantDetected bool
	}{
		{
			name: "GitHub Actions",
			env: map[string]string{
				"GITHUB_ACTIONS": "true",
			},
			wantPlatform: "github-actions",
			wantDetected: true,
		},
		{
			name: "GitLab CI",
			env: map[string]string{
				"GITLAB_CI": "true",
			},
			wantPlatform: "gitlab-ci",
			wantDetected: true,
		},
		{
			name: "Jenkins",
			env: map[string]string{
				"JENKINS_URL": "https://jenkins.example.com",
			},
			wantPlatform: "jenkins",
			wantDetected: true,
		},
		{
			name: "CircleCI",
			env: map[string]string{
				"CIRCLECI": "true",
			},
			wantPlatform: "circleci",
			wantDetected: true,
		},
		{
			name: "Travis CI",
			env: map[string]string{
				"TRAVIS": "true",
			},
			wantPlatform: "travis-ci",
			wantDetected: true,
		},
		{
			name: "Azure Pipelines",
			env: map[string]string{
				"TF_BUILD": "true",
			},
			wantPlatform: "azure-pipelines",
			wantDetected: true,
		},
		{
			name:         "No CI environment",
			env:          map[string]string{},
			wantPlatform: "",
			wantDetected: false,
		},
		{
			name: "Unrecognized environment",
			env: map[string]string{
				"SOME_OTHER_VAR": "value",
			},
			wantPlatform: "",
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			platform, detected := detectCIPlatform(tt.env)

			if detected != tt.wantDetected {
				t.Errorf("detectCIPlatform() detected = %v, want %v", detected, tt.wantDetected)
			}

			if platform != tt.wantPlatform {
				t.Errorf("detectCIPlatform() platform = %v, want %v", platform, tt.wantPlatform)
			}
		})
	}
}

func TestDetermineBuildType(t *testing.T) {
	tests := []struct {
		name         string
		artifactType string
		want         string
	}{
		{
			name:         "Container type",
			artifactType: "container",
			want:         "https://github.com/open-verix/provenix/buildtypes/container/v1",
		},
		{
			name:         "Docker type",
			artifactType: "docker",
			want:         "https://github.com/open-verix/provenix/buildtypes/container/v1",
		},
		{
			name:         "Binary type",
			artifactType: "binary",
			want:         "https://github.com/open-verix/provenix/buildtypes/binary/v1",
		},
		{
			name:         "Executable type",
			artifactType: "executable",
			want:         "https://github.com/open-verix/provenix/buildtypes/binary/v1",
		},
		{
			name:         "Directory type",
			artifactType: "directory",
			want:         "https://github.com/open-verix/provenix/buildtypes/directory/v1",
		},
		{
			name:         "Filesystem type",
			artifactType: "filesystem",
			want:         "https://github.com/open-verix/provenix/buildtypes/directory/v1",
		},
		{
			name:         "Archive type",
			artifactType: "archive",
			want:         "https://github.com/open-verix/provenix/buildtypes/archive/v1",
		},
		{
			name:         "OCI archive type",
			artifactType: "oci-archive",
			want:         "https://github.com/open-verix/provenix/buildtypes/archive/v1",
		},
		{
			name:         "Unknown type defaults to generic",
			artifactType: "unknown",
			want:         "https://github.com/open-verix/provenix/buildtypes/generic/v1",
		},
		{
			name:         "Empty type defaults to generic",
			artifactType: "",
			want:         "https://github.com/open-verix/provenix/buildtypes/generic/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := determineBuildType(tt.artifactType)
			if got != tt.want {
				t.Errorf("determineBuildType() = %v, want %v", got, tt.want)
			}
		})
	}
}
