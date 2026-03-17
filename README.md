🛡️ Provenix

The Policy-Driven Software Supply Chain Orchestrator

Provenix is an intent-first security orchestrator that generates atomic, cryptographically bound evidence for software artifacts. It abstracts tools like Cosign, Syft, and Grype into a single, policy-centric workflow—without forcing users to learn or operate those tools directly.

Provenix observes and records. It does not silently enforce.

⸻

Core Concept: Atomic Evidence

Atomic Evidence means:

All evidence (SBOM, vulnerability results, provenance) is generated in a single execution context and cryptographically bound to the exact artifact digest at the moment of attestation.

It does not mean that all checks must pass.
• Evidence may contain gaps
• External publishing may partially fail
• Integrity must never be broken

If atomicity is violated → Provenix fails hard.

⸻

Formal Definition of Atomic Evidence

Let E = (A, C, T, σ) represent evidence, where:
• A: Artifact (digest: SHA256)
• C: Context (SBOM, Vulnerabilities, Provenance)
• T: Timestamp (execution time)
• σ: Cryptographic signature

Atomicity Conditions:

1. σ signs the hash of the complete in-toto Statement containing all c ∈ C
2. All c ∈ C are embedded in the signed payload (not separately hashed)
3. T is unique within a single execution session
4. Generation order of C is deterministic (SBOM → Scan → Attestation)
5. Digest of A is finalized before generating any c ∈ C

Non-Atomic Cases (Violations):

    •	SBOM and Scan generated in separate processes
    •	Artifact modified during evidence generation
    •	Signature hash differs from SBOM generation hash

Implementation Guarantees:

    •	Memory pipeline directly connects SBOM → Grype (no intermediate files)
    •	Artifact hash computed once at start, referenced thereafter
    •	All components share the same execution_id
    •	TOCTOU (Time-of-Check to Time-of-Use) attacks prevented by design

⸻

Zero-Config First (MVP Philosophy)

Provenix is designed so that OSS maintainers can run it with zero configuration:

provenix attest <artifact>

No keys. No YAML. No CI glue code.

For local development without signing:

provenix attest <artifact> --local

Important Design Choice

When no configuration file is provided:

Provenix automatically generates an in-memory default policy.

This is not only acceptable — it is recommended.
• Users get safe, predictable behavior
• Defaults are explicit and documented
• Generated policy is shown in logs (--debug)

⸻

Implicit Default Policy (Zero Config)

The following policies are implicitly applied when provenix.yaml is absent.

1. Identity Policy
   • Strategy: Keyless (OIDC)
   • Identity source:
   • CI: GitHub Actions / GitLab CI (auto-detected)
   • Local: local://user@host

No private keys are ever managed by the user.

⸻

2. Attestation Policy
   • Tool: Cosign
   • Format: in-toto Statement v1
   • Scope: Minimal, honest provenance

Included:
• Artifact digest
• Execution environment
• Source reference (if detectable)
• SBOM summary
• Vulnerability scan summary

Explicitly NOT claimed (MVP scope):
• SLSA L3/L4 compliance (generates evidence but doesn't enforce L3 requirements)
• Code review or approval guarantees
• Hermetic build environment
• Dependency pinning verification

Note: SLSA L3 compliance enforcement is planned for post-MVP (see docs/roadmap.md).

⸻

3. SBOM Policy
   • Enabled by default
   • Tool: Syft (library mode)
   • Format: CycloneDX JSON

SBOM is:
• Generated in-memory
• Never written as a standalone file
• Cryptographically bound into the attestation

This prevents TOCTOU-style replacement.

⸻

4. Vulnerability Scan Policy (Default: ENABLED)
   • Enabled by default
   • Tool: Grype
   • Mode: Observe

Behavior:
• Vulnerabilities are detected and recorded
• Severity counts are embedded in attestation
• Build is NOT blocked by findings

Vulnerabilities are treated as evidence gaps, not failures.

⸻

5. License Checks
   • ❌ Not implemented in MVP
   • ❌ No implicit or explicit license enforcement

This is intentionally excluded to keep scope honest.

⸻

6. Enforcement Mode
   • Mode: Observer (fixed in zero-config)

Rules:
• Cryptographic failures → exit 1
• Evidence gaps → recorded, exit 2
• Infra failures → degraded, exit 2

Provenix never blocks silently.

Note: In observe mode, vulnerabilities and infrastructure failures produce exit 2 (partial success), allowing CI to decide whether to fail or warn.

⸻

7. Transparency Policy
   • Rekor publish:
   • CI: enabled by default
   • Local: disabled by default

If Rekor is unavailable:
• Local attestation is still produced
• Failure is explicitly recorded

Evidence is never discarded.

⸻

Configuration Philosophy

Provenix follows a **Progressive Configuration** model:

• **Zero-Config (Default)**: Works out of the box with safe defaults
• **Minimal Config**: Add constraints without managing complexity  
• **Enterprise Control**: Full policy enforcement

**`provenix.yaml` is completely optional.** When absent, Provenix uses safe built-in defaults.

Configuration is discovered within your project directory only (never searches `~/.provenix/` or `/etc/provenix/`).

**Project Initialization:**

```bash
provenix init  # Generates provenix.yaml + provenix.prod.yaml + .provenix/ structure
```

This creates:

- `provenix.yaml` - Development defaults (fast, offline, private)
- `provenix.prod.yaml` - Production defaults (keyless, Rekor, strict)
- `.provenix/` - Directory for generated artifacts

**Switching Configurations:**

```bash
# Use development config (default)
provenix attest myapp:latest

# Use production config via environment variable
export PROVENIX_CONFIG=provenix.prod.yaml
provenix attest myapp:latest

# Or via CLI flag
provenix attest myapp:latest --config provenix.prod.yaml
```

For detailed configuration options, see `docs/configuration.md`.

⸻

Environment-Specific Configuration

Provenix provides separate defaults for development and production environments:

**Development (Default)**

Fast, offline-capable, private:

- Local key signing (~7 seconds per attestation)
- No Rekor publishing (private development)
- Manual vulnerability database updates
- Looser vulnerability thresholds

```bash
# Initialize project with dev keys
provenix init --generate-keys

# Attest with development defaults (uses provenix.yaml)
provenix attest myapp:latest
```

**Production**

Strict, transparent, publicly auditable:

- Keyless signing via OIDC (~40 seconds per attestation)
- Rekor transparency log publishing
- Auto-updating vulnerability database
- Strict vulnerability thresholds

```bash
# Attest with production config
provenix attest myapp:v1.0.0 --config provenix.prod.yaml

# Or set via environment variable
export PROVENIX_CONFIG=provenix.prod.yaml
provenix attest myapp:v1.0.0
```

**Rationale:**

Development speed matters. Waiting 40 seconds per attestation (OIDC + Rekor) is unacceptable for iterative development. Publishing every dev build to a permanent public log raises privacy concerns.

Production transparency matters. Keyless signing and public transparency logs provide cryptographic proof of authenticity for released artifacts.

For team recommendations, see `provenix.prod.yaml` for production overrides.

⸻

## Batch Processing

Provenix supports batch attestation for processing multiple artifacts efficiently with parallel processing.

```bash
# Attest multiple artifacts
provenix batch nginx:latest alpine:latest myapp:v1.0.0 --parallel 4

# From input file (JSON or YAML)
provenix batch --input artifacts.yaml
```

For detailed usage, examples, and CI/CD integration, see [`explains/batch-usage-guide-for-provenix-examples.md`](explains/batch-usage-guide-for-provenix-examples.md).

⸻

## Database Management

**Vulnerability Database Commands**

Provenix provides commands to manage the Grype vulnerability database:

```bash
# View database status
provenix db status

# Force database update
provenix db update

# Clean old database versions
provenix db clean
```

The database is stored at `~/.cache/grype/db` and auto-updates based on `provenix.yaml` settings:

- Development: Manual updates (offline-capable)
- Production: Auto-update (max age: 24 hours)

⸻

Configuration File (Optional, Opt-In)

Advanced users may provide provenix.yaml to:
• Enforce strict policies
• Declare SLSA intent
• Add organization-specific rules

Example:

version: 0.1
identity:
strategy: keyless
issuer: github

attestations:

- type: provenance
- type: vulnerability-scan
  on_failure: warn

enforcement:
mode: strict

Providing a config only adds constraints — it never weakens defaults.

⸻

What Provenix Explicitly Does NOT Guarantee

Provenix is precise about its boundaries.

It does NOT guarantee:
• That source code was reviewed or approved
• That dependencies are authentic or trustworthy
• That the build environment is hardened
• That runtime behavior is secure

It guarantees only what it can prove.

⸻

Failure Model (Atomic by Design)

Provenix classifies failures into three categories:

1. Cryptographic Failure → Exit 1 (hard stop)
   - Signature verification failed
   - Hash mismatch between components
   - Attestation integrity violated

2. Evidence Gap → Exit 2 (recorded, continue)
   - Vulnerabilities detected (observe mode)
   - Unsigned commits, dirty working tree
   - Missing optional checks

3. Infrastructure Failure → Exit 2 (degraded, continue)
   - Rekor unreachable
   - Network timeout
   - Local attestation saved, publish incomplete

Exit Code Summary:
• 0: Complete success (all evidence generated and published)
• 1: Fatal failure (cryptographic or policy violation)
• 2: Partial success (evidence generated, publishing failed)

Atomic Evidence succeeds when imperfection is explicit.

⸻

Summary
• Zero-config is a first-class feature
• Default policies are safe, minimal, and honest
• Vulnerability scanning is enabled by default
• Attestations are always generated with Cosign
• Enforcement is explicit and opt-in

Provenix records reality. You decide what to enforce.
