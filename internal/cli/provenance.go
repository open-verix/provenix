package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/open-verix/provenix/internal/evidence"
)

var (
	provenanceOutput     string
	provenanceArtifact   string
	provenanceType       string
	provenancePlatform   string
	provenanceInvocation string
)

// proveCmd represents the prove command
var proveCmd = &cobra.Command{
	Use:   "prove [artifact]",
	Short: "Generate SLSA provenance attestation",
	Long: `Generate SLSA Provenance v1.0 attestation for a software artifact.

This command creates a SLSA-compliant provenance attestation that records:
- Build type and parameters
- Builder information (Provenix version, CI platform)
- Execution metadata (timestamps, invocation ID)

The provenance can be used for:
- SLSA Build Level compliance verification
- Supply chain transparency
- Build reproducibility tracking

Exit Codes:
  0 - Success (provenance generated)
  1 - Error (invalid parameters, generation failed)`,
	Example: `  # Generate provenance for a container image
  provenix prove nginx:latest --type container

  # Generate provenance with custom output
  provenix prove ./myapp --type binary --output provenance.json

  # Generate provenance with platform specification
  provenix prove myimage:v1.0 --type container --platform linux/amd64`,
	Args: cobra.ExactArgs(1),
	RunE: runProvenance,
}

func init() {
	rootCmd.AddCommand(proveCmd)

	proveCmd.Flags().StringVarP(&provenanceOutput, "output", "o", "",
		"Output file path (default: stdout)")
	proveCmd.Flags().StringVar(&provenanceType, "type", "container",
		"Artifact type: container, binary, directory, archive")
	proveCmd.Flags().StringVar(&provenancePlatform, "platform", "",
		"Target platform (e.g., linux/amd64, linux/arm64)")
	proveCmd.Flags().StringVar(&provenanceInvocation, "invocation-id", "",
		"Build invocation ID (default: auto-generated UUID)")
}

func runProvenance(cmd *cobra.Command, args []string) error {
	artifact := args[0]

	// Generate invocation ID if not provided
	invocationID := provenanceInvocation
	if invocationID == "" {
		invocationID = uuid.New().String()
	}

	// Record start and finish times
	startedAt := time.Now().UTC()

	// Collect build environment variables
	buildEnv := collectBuildEnvironment()

	// Create SLSA provenance
	provenancePredicate := evidence.CreateSLSAProvenance(
		artifact,
		provenanceType,
		provenancePlatform,
		Version, // Provenix version from root.go
		startedAt,
		time.Now().UTC(), // Finish time (minimal processing)
		invocationID,
		buildEnv,
	)

	// Create in-toto statement with SLSA provenance predicate
	statement := evidence.Statement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []evidence.Subject{
			{
				Name:   artifact,
				Digest: map[string]string{
					// Note: For full implementation, compute actual digest
					"sha256": "placeholder-digest-would-be-computed",
				},
			},
		},
		PredicateType: evidence.PredicateTypeSLSAProvenance,
		Predicate:     provenancePredicate,
	}

	// Marshal to JSON
	outputJSON, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal provenance: %w", err)
	}

	// Write output
	if provenanceOutput != "" {
		if err := os.WriteFile(provenanceOutput, outputJSON, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("SLSA provenance written to: %s\n", provenanceOutput)
	} else {
		fmt.Println(string(outputJSON))
	}

	return nil
}

// collectBuildEnvironment collects relevant environment variables for CI detection.
func collectBuildEnvironment() map[string]string {
	envVars := []string{
		"GITHUB_ACTIONS",
		"GITHUB_WORKFLOW",
		"GITHUB_RUN_ID",
		"GITHUB_RUN_NUMBER",
		"GITHUB_REPOSITORY",
		"GITLAB_CI",
		"CI_PIPELINE_ID",
		"CI_PROJECT_PATH",
		"JENKINS_URL",
		"BUILD_ID",
		"CIRCLECI",
		"CIRCLE_BUILD_NUM",
		"TRAVIS",
		"TRAVIS_BUILD_NUMBER",
		"TF_BUILD",
		"BUILD_BUILDID",
	}

	env := make(map[string]string)
	for _, key := range envVars {
		if val := os.Getenv(key); val != "" {
			env[key] = val
		}
	}

	return env
}
