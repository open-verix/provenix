# Provenix Project Guidelines for AI Assistants

## Project Overview

Provenix is a **Policy-Driven Software Supply Chain Orchestrator** written in Go 1.22+.

**Core Mission:** Generate atomic evidence (SBOM + Vulnerability Scan + Signature) for software artifacts with cryptographic integrity guarantees.

**Key Differentiator:** Atomic Evidence model - ensures SBOM and vulnerability reports represent the exact state of the artifact at signing time (no TOCTOU vulnerabilities).

---

## Architecture Principles

### 1. Atomic Evidence Model

**Definition:** Evidence E = (Artifact A, SBOM C, Vulnerability Report V, Signature σ) where σ signs the complete in-toto Statement containing A, C, and V.

**Critical Rules:**

- All data must flow in-memory (NO temporary files)
- SBOM generation and vulnerability scanning must be atomic
- Signature σ must cover the complete statement
- No time-of-check to time-of-use (TOCTOU) vulnerabilities

### 2. Provider Abstraction Pattern

**NEVER directly couple to upstream libraries.** Always use provider interfaces:

```go
// ✅ CORRECT
type SBOMProvider interface {
    Generate(ctx context.Context, artifact string, opts Options) (*SBOM, error)
    Name() string
    Version() string
}

// ❌ WRONG
import "github.com/anchore/syft/syft"
func generateSBOM() {
    syft.CatalogPackages(...) // Direct coupling
}
```

**Why:** Enables future plugin architecture and decouples from upstream API changes.

### 3. Exit Code Semantics

- **Exit 0:** Complete success (attestation signed AND published to Rekor)
- **Exit 1:** Fatal error (cryptographic failure, artifact not found, invalid signature)
- **Exit 2:** Partial success (attestation generated and saved locally, but Rekor publishing failed)

**Never use other exit codes.** Exit 2 enables CI/CD graceful degradation.

### 4. Configuration Philosophy

**Project-Scoped Only:**

- Search for `provenix.yaml` in project root ONLY
- NEVER search `~/.config/provenix/` or `/etc/provenix/`
- NEVER create global configuration files

**Priority Order:**

1. CLI flags (`--config`)
2. Environment variables (`PROVENIX_*`)
3. `provenix.yaml` in project root
4. Embedded defaults

---

## Code Style & Best Practices

### Go Conventions

- Follow [Effective Go](https://go.dev/doc/effective_go)
- Use `gofmt` and `golangci-lint`
- Package names: lowercase, no underscores
- Exported types: Start with capital letter + godoc comment

### Error Handling

**Always wrap errors with context:**

```go
// ✅ CORRECT
if err != nil {
    return nil, fmt.Errorf("failed to generate SBOM for %s: %w", artifact, err)
}

// ❌ WRONG
if err != nil {
    return nil, err  // Lost context
}
```

**Never panic in library code:**

```go
// ❌ WRONG
if artifact == "" {
    panic("artifact cannot be empty")
}

// ✅ CORRECT
if artifact == "" {
    return nil, errors.New("artifact cannot be empty")
}
```

### Logging

Use structured logging with `logrus`:

```go
log.WithFields(log.Fields{
    "artifact": artifact,
    "duration": time.Since(start),
}).Info("SBOM generation completed")
```

### Interfaces Over Concrete Types

```go
// ✅ CORRECT
func ProcessEvidence(provider SBOMProvider, artifact string) error

// ❌ WRONG
func ProcessEvidence(syft *SyftProvider, artifact string) error
```

---

## Dependencies

### Pinned Versions (NEVER use version ranges)

```go
require (
    github.com/anchore/syft v0.100.0      // Fixed
    github.com/anchore/grype v0.70.0      // Fixed
    github.com/sigstore/cosign/v2 v2.2.0  // Fixed
    github.com/spf13/cobra v1.8.0         // Fixed
    github.com/spf13/viper v1.18.0        // Fixed
)
```

**Why:** Build reproducibility, audit trail integrity, dogfooding (Provenix attests itself).

**Update Policy:** Quarterly reviews, 24-48h response for security patches.

### Import Guidelines

```go
// ✅ CORRECT - Via provider interface
import "github.com/open-verix/provenix/internal/providers/sbom"

// ⚠️ USE SPARINGLY - Only in provider implementations
import "github.com/anchore/syft/syft"

// ❌ WRONG - Never in business logic
import "github.com/anchore/syft/syft"
```

---

## Testing Requirements

### Coverage Target: 80%+

**Unit Tests:**

- Mock all external dependencies
- Test error paths
- Test edge cases (empty strings, nil pointers, etc.)

**Integration Tests:**

- Use real Docker images (nginx:latest, alpine:latest)
- Test OCI archives
- Test directory scanning

**E2E Tests:**

- Full pipeline: SBOM → Scan → Sign → Publish
- Test against Sigstore staging environment
- Verify exit codes

### Test File Naming

```
internal/evidence/generator.go
internal/evidence/generator_test.go  # Unit tests

test/integration/attest_test.go      # Integration tests
test/e2e/full_pipeline_test.go       # E2E tests
```

---

## Security Considerations

### No Private Key Storage

- **ONLY keyless signing** using OIDC (GitHub/GitLab)
- Local keys allowed for development (`--key` flag)
- NEVER store keys in config files or environment variables

### Input Validation

```go
// ✅ CORRECT
func ValidateArtifact(artifact string) error {
    if artifact == "" {
        return errors.New("artifact cannot be empty")
    }
    if strings.Contains(artifact, "..") {
        return errors.New("path traversal detected")
    }
    return nil
}
```

### Context Timeouts

Always use `context.Context` with timeouts:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

evidence, err := generator.Generate(ctx, artifact, opts)
```

---

## CLI Design Principles

### POSIX Conventions

- Flags: `--flag` (long), `-f` (short)
- Boolean flags: `--local` (no value needed)
- Help: `--help`, `-h`
- Version: `--version`, `-v`

### Progressive Disclosure

**Simple by default:**

```bash
provenix attest myapp
```

**Advanced options available:**

```bash
provenix attest myapp \
  --format spdx \
  --output attestation.json \
  --key path/to/key.pem \
  --config provenix.yaml
```

### Clear Help Text

```go
var attestCmd = &cobra.Command{
    Use:   "attest [artifact]",
    Short: "Generate SBOM, scan vulnerabilities, and create signed attestation",
    Long: `Generate atomic evidence for a software artifact.

This command:
1. Generates SBOM using Syft
2. Scans vulnerabilities using Grype
3. Creates in-toto statement
4. Signs with Cosign (keyless via OIDC)
5. Publishes to Rekor transparency log

Exit Codes:
  0 - Complete success (signed and published)
  1 - Fatal error (cryptographic failure)
  2 - Partial success (saved locally, Rekor unavailable)`,
    Example: `  # Attest a Docker image
  provenix attest nginx:latest

  # Attest a local binary
  provenix attest --local ./myapp

  # Use custom configuration
  provenix attest myapp --config custom.yaml`,
    Args: cobra.ExactArgs(1),
    Run:  runAttest,
}
```

---

## Common Pitfalls to Avoid

### ❌ DON'T: Call External Binaries

```go
// ❌ WRONG
cmd := exec.Command("syft", "nginx:latest", "-o", "cyclonedx-json")
output, _ := cmd.Output()

// ✅ CORRECT
sbom, err := syftProvider.Generate(ctx, "nginx:latest", opts)
```

### ❌ DON'T: Use Temporary Files

```go
// ❌ WRONG
tmpFile, _ := os.CreateTemp("", "sbom-*.json")
syft.WriteSBOM(tmpFile)
grype.ScanFile(tmpFile.Name())

// ✅ CORRECT - In-memory pipeline
sbom, _ := syftProvider.Generate(ctx, artifact, opts)
report, _ := grypeProvider.Scan(ctx, sbom, opts)
```

### ❌ DON'T: Use Global State

```go
// ❌ WRONG
var globalConfig *Config

func LoadConfig() {
    globalConfig = parseYAML("provenix.yaml")
}

// ✅ CORRECT
func LoadConfig(path string) (*Config, error) {
    return parseYAML(path)
}
```

### ❌ DON'T: Panic in Production Code

```go
// ❌ WRONG
func MustLoadConfig() *Config {
    cfg, err := LoadConfig()
    if err != nil {
        panic(err)
    }
    return cfg
}

// ✅ CORRECT
func LoadConfig() (*Config, error) {
    // Return errors, let caller decide
}
```

### ❌ DON'T: Hardcode Sigstore URLs

```go
// ❌ WRONG
const REKOR_URL = "https://rekor.sigstore.dev"

// ✅ CORRECT - Use config
type SignerOptions struct {
    RekorURL  string // Configurable, defaults to public Rekor
    FulcioURL string
}
```

---

## Documentation Standards

### Godoc for All Exported Types

```go
// Generator creates atomic evidence for software artifacts.
//
// It orchestrates SBOM generation, vulnerability scanning, and signing
// in a single atomic operation with no temporary files.
//
// Example:
//   gen := evidence.NewGenerator(sbomProvider, scannerProvider, signerProvider)
//   evidence, err := gen.Generate(ctx, "nginx:latest", opts)
type Generator struct {
    sbomProvider    sbom.Provider
    scannerProvider scanner.Provider
    signerProvider  signer.Provider
}
```

### Update docs/ When Changing Behavior

If you modify:

- CLI commands → Update `docs/cli_specification.md`
- Configuration → Update `docs/configuration.md`
- Exit codes → Update `docs/atomic_evidence_failure_model.md`
- Dependencies → Update `docs/TechnicalStack.md` and `docs/compatibility-matrix.md`

---

## Useful References

### Internal Documentation

- `docs/atomic_evidence_failure_model.md` - Exit code semantics, failure handling
- `docs/cli_specification.md` - Complete CLI command reference
- `docs/configuration.md` - Configuration file format and discovery
- `docs/TechnicalStack.md` - Technology choices and dependency management
- `docs/compatibility-matrix.md` - Version compatibility and testing
- `docs/roadmap.md` - Development phases and timeline
- `docs/implementation-plan.md` - Week-by-week implementation tasks

### External References

- [in-toto Specification](https://github.com/in-toto/attestation/tree/main/spec)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore Documentation](https://docs.sigstore.dev/)
- [Syft API Docs](https://pkg.go.dev/github.com/anchore/syft)
- [Grype API Docs](https://pkg.go.dev/github.com/anchore/grype)
- [Cosign API Docs](https://pkg.go.dev/github.com/sigstore/cosign/v2)

---

## Project-Specific Patterns

### Provider Registration

```go
func init() {
    providers.RegisterSBOMProvider("syft", &syft.SyftProvider{})
    providers.RegisterScannerProvider("grype", &grype.GrypeProvider{})
    providers.RegisterSignerProvider("cosign", &cosign.CosignProvider{})
}
```

### Evidence Generation Flow

```go
// 1. Generate SBOM (in-memory)
sbom, err := sbomProvider.Generate(ctx, artifact, opts)

// 2. Scan vulnerabilities (in-memory, using SBOM)
report, err := scannerProvider.Scan(ctx, sbom, opts)

// 3. Create in-toto statement
statement := createStatement(artifact, sbom, report)

// 4. Sign statement
signature, err := signerProvider.Sign(ctx, statement, opts)

// 5. Publish to Rekor (with fallback)
err = rekorProvider.Publish(ctx, evidence)
if err != nil {
    saveLocal(evidence)
    os.Exit(2) // Partial success
}
```

### Configuration Loading

```go
// Project-scoped discovery
func LoadConfig(projectRoot string) (*Config, error) {
    paths := []string{
        filepath.Join(projectRoot, "provenix.yaml"),
        filepath.Join(projectRoot, ".provenix.yaml"),
    }

    for _, path := range paths {
        if fileExists(path) {
            return parseConfig(path)
        }
    }

    return defaultConfig(), nil
}
```

---

## Development Workflow

### Before Committing

```bash
# Format code
go fmt ./...

# Run linter
golangci-lint run

# Run tests
go test ./... -v -cover

# Verify builds
go build ./cmd/provenix
```

### Git Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add OIDC token retrieval for GitHub Actions
fix: prevent path traversal in artifact validation
docs: update CLI specification with verify command
test: add integration test for Docker image attestation
chore: update Syft to v0.100.1 for security patch
```

---

## Questions to Ask Before Implementing

1. **Does this introduce TOCTOU vulnerabilities?** (If yes, redesign)
2. **Can this work without temporary files?** (If no, reconsider)
3. **Is this tightly coupled to a specific library?** (If yes, add abstraction)
4. **Does this work in air-gapped environments?** (Consider `--local` mode)
5. **What happens if Rekor is unavailable?** (Should exit 2 and save locally)
6. **Is this testable with mocks?** (If no, refactor)
7. **Does this need to be in the public API (pkg/)?** (Probably not - use internal/)

---

**This file is automatically loaded by GitHub Copilot and other AI assistants when working in this repository.**

**Last Updated:** 2026-01-10
