package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-verix/provenix/internal/evidence"
	"github.com/open-verix/provenix/internal/policy"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Policy management commands",
	Long: `Manage and evaluate policy configurations.

Policy commands allow you to:
- Check evidence against policy rules
- Initialize default policy configuration
- Validate policy configuration files`,
}

var policyCheckCmd = &cobra.Command{
	Use:   "check [evidence-file]",
	Short: "Check evidence against policy rules",
	Long: `Evaluate evidence against policy configuration.

This command loads policy configuration (from --config or provenix.yaml)
and evaluates the provided evidence file. It checks:
- Vulnerability thresholds (max critical/high/medium)
- License compliance (allowed/denied lists)
- SBOM requirements (format, package count)

Exit Codes:
  0 - Policy check passed (no violations)
  1 - Policy check failed (violations found)
  2 - Error during evaluation`,
	Example: `  # Check evidence with default policy
  provenix policy check attestation.json

  # Check with custom policy config
  provenix policy check attestation.json --config custom-policy.yaml

  # Output results as JSON
  provenix policy check attestation.json --output results.json`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyCheck,
}

var policyInitCmd = &cobra.Command{
	Use:   "init [path]",
	Short: "Initialize default policy configuration",
	Long: `Create a default policy configuration file.

This command generates a provenix.yaml file with sensible defaults:
- Max 0 critical/high vulnerabilities, max 10 medium
- Common permissive licenses allowed (MIT, Apache-2.0, BSD, ISC)
- Copyleft licenses denied (GPL-3.0, AGPL-3.0)
- Warn on unknown licenses

You can customize the generated file for your project's needs.`,
	Example: `  # Create provenix.yaml in current directory
  provenix policy init

  # Create custom-policy.yaml
  provenix policy init custom-policy.yaml`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPolicyInit,
}

var policyValidateCmd = &cobra.Command{
	Use:   "validate [config-file]",
	Short: "Validate policy configuration file",
	Long: `Check if a policy configuration file is valid.

Validates:
- YAML syntax
- Schema version compatibility
- Policy constraint values
- File path references (for OPA policies)`,
	Example: `  # Validate provenix.yaml
  provenix policy validate

  # Validate specific file
  provenix policy validate custom-policy.yaml`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPolicyValidate,
}

var (
	policyConfigPath string
	policyOutputPath string
	policyOutputJSON bool
	policyForceOverwrite bool
)

func init() {
	policyCmd.AddCommand(policyCheckCmd)
	policyCmd.AddCommand(policyInitCmd)
	policyCmd.AddCommand(policyValidateCmd)

	// Policy check flags
	policyCheckCmd.Flags().StringVarP(&policyConfigPath, "config", "c", "", "Path to policy configuration file")
	policyCheckCmd.Flags().StringVarP(&policyOutputPath, "output", "o", "", "Output file for results (JSON format)")
	policyCheckCmd.Flags().BoolVar(&policyOutputJSON, "json", false, "Output results in JSON format")

	// Policy init flags
	policyInitCmd.Flags().BoolVarP(&policyForceOverwrite, "force", "f", false, "Overwrite existing file")
}

func runPolicyCheck(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	evidencePath := args[0]

	// Load evidence from file
	evidenceData, err := os.ReadFile(evidencePath)
	if err != nil {
		return fmt.Errorf("failed to read evidence file: %w", err)
	}

	var ev evidence.Evidence
	if err := json.Unmarshal(evidenceData, &ev); err != nil {
		return fmt.Errorf("failed to parse evidence file: %w", err)
	}

	// Load policy configuration
	cfg, err := policy.LoadConfig(policyConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load policy configuration: %w", err)
	}

	// Create policy engine
	engine := policy.NewEngine(cfg)

	// Evaluate evidence
	result, err := engine.Evaluate(ctx, &ev)
	if err != nil {
		return fmt.Errorf("failed to evaluate policy: %w", err)
	}

	// Output results
	if err := outputPolicyResults(result, cmd); err != nil {
		return err
	}

	// Exit with appropriate code
	if !result.Passed {
		return &ExitError{
			Code: ExitFatal,
			Err:  fmt.Errorf("policy check failed"),
		}
	}

	return nil
}

func runPolicyInit(cmd *cobra.Command, args []string) error {
	// Determine output path
	outputPath := "provenix.yaml"
	if len(args) > 0 {
		outputPath = args[0]
	}

	// Check if file already exists
	if _, err := os.Stat(outputPath); err == nil && !policyForceOverwrite {
		return fmt.Errorf("file %s already exists (use --force to overwrite)", outputPath)
	}

	// Create default config
	cfg := policy.DefaultConfig()

	// Save to file
	if err := policy.SaveConfig(cfg, outputPath); err != nil {
		return fmt.Errorf("failed to save configuration: %w", err)
	}

	cmd.Printf("Created policy configuration: %s\n", outputPath)
	cmd.Println("\nReview and customize the configuration for your project:")
	cmd.Printf("  - Adjust vulnerability thresholds under 'vulnerabilities'\n")
	cmd.Printf("  - Modify allowed/denied licenses under 'licenses'\n")
	cmd.Printf("  - Set SBOM requirements under 'sbom'\n")
	cmd.Printf("\nRun 'provenix policy validate %s' to verify your changes.\n", outputPath)

	return nil
}

func runPolicyValidate(cmd *cobra.Command, args []string) error {
	// Determine config path
	configPath := ""
	if len(args) > 0 {
		configPath = args[0]
	}

	// Load and validate config
	cfg, err := policy.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// If we got here, config is valid
	usedPath := configPath
	if usedPath == "" {
		// Determine which file was loaded
		for _, p := range []string{"provenix.yaml", ".provenix.yaml"} {
			if _, err := os.Stat(p); err == nil {
				usedPath = p
				break
			}
		}
		if usedPath == "" {
			usedPath = "default configuration"
		}
	}

	cmd.Printf("✓ Policy configuration is valid: %s\n", usedPath)
	cmd.Println("\nConfiguration summary:")
	cmd.Printf("  Version: %s\n", cfg.Version)

	if cfg.Vulnerabilities != nil {
		cmd.Println("  Vulnerabilities:")
		if cfg.Vulnerabilities.MaxCritical != nil {
			cmd.Printf("    - Max critical: %d\n", *cfg.Vulnerabilities.MaxCritical)
		}
		if cfg.Vulnerabilities.MaxHigh != nil {
			cmd.Printf("    - Max high: %d\n", *cfg.Vulnerabilities.MaxHigh)
		}
		if cfg.Vulnerabilities.MaxMedium != nil {
			cmd.Printf("    - Max medium: %d\n", *cfg.Vulnerabilities.MaxMedium)
		}
		if cfg.Vulnerabilities.OnlyFixed {
			cmd.Println("    - Only fixed vulnerabilities allowed")
		}
	}

	if cfg.Licenses != nil {
		cmd.Println("  Licenses:")
		if len(cfg.Licenses.AllowedLicenses) > 0 {
			cmd.Printf("    - Allowed: %d licenses\n", len(cfg.Licenses.AllowedLicenses))
		}
		if len(cfg.Licenses.DeniedLicenses) > 0 {
			cmd.Printf("    - Denied: %d licenses\n", len(cfg.Licenses.DeniedLicenses))
		}
	}

	if cfg.SBOM != nil && cfg.SBOM.RequiredFormat != "" {
		cmd.Printf("  SBOM:\n")
		cmd.Printf("    - Required format: %s\n", cfg.SBOM.RequiredFormat)
	}

	return nil
}

func outputPolicyResults(result *policy.Result, cmd *cobra.Command) error {
	// JSON output to file
	if policyOutputPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}

		dir := filepath.Dir(policyOutputPath)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		}

		if err := os.WriteFile(policyOutputPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write results: %w", err)
		}

		cmd.Printf("Policy results saved to: %s\n", policyOutputPath)
		return nil
	}

	// JSON output to stdout
	if policyOutputJSON {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
		cmd.Println(string(data))
		return nil
	}

	// Human-readable output
	if result.Passed {
		cmd.Println("✓ Policy check passed")
	} else {
		cmd.Println("✗ Policy check failed")
	}

	if len(result.Violations) > 0 {
		cmd.Printf("\n%d Violations:\n", len(result.Violations))
		for i, v := range result.Violations {
			cmd.Printf("\n%d. [%s] %s\n", i+1, v.Severity, v.Message)
			if v.Package != "" {
				cmd.Printf("   Package: %s\n", v.Package)
			}
			if len(v.Details) > 0 {
				cmd.Printf("   Details: %v\n", v.Details)
			}
		}
	}

	if len(result.Warnings) > 0 {
		cmd.Printf("\n%d Warnings:\n", len(result.Warnings))
		for i, w := range result.Warnings {
			cmd.Printf("\n%d. [%s] %s\n", i+1, w.Type, w.Message)
			if w.Package != "" {
				cmd.Printf("   Package: %s\n", w.Package)
			}
		}
	}

	if result.Passed && len(result.Warnings) == 0 {
		cmd.Println("No violations or warnings found.")
	}

	return nil
}
