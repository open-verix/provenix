# Provenix Policy Configuration Example

This directory contains example policy configurations for different use cases.

## Quick Start

Initialize a default policy configuration:

```bash
provenix policy init
```

This creates `provenix.yaml` with sensible defaults.

## Policy Configuration

### Basic Example

```yaml
version: v1

vulnerabilities:
  max_critical: 0 # No critical vulnerabilities allowed
  max_high: 0 # No high vulnerabilities allowed
  max_medium: 10 # Up to 10 medium vulnerabilities allowed
  only_fixed: false # Allow unfixed vulnerabilities

licenses:
  allowed:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
  denied:
    - GPL-3.0 # Copyleft license
    - AGPL-3.0 # Strong copyleft
  warn_on_unknown: true

sbom:
  required_format: "" # Any format (cyclonedx-json, spdx-json, syft-json)
  require_checksum: true
```

### Strict Security Policy

For production environments with zero-tolerance for vulnerabilities:

```yaml
version: v1

vulnerabilities:
  max_critical: 0
  max_high: 0
  max_medium: 0
  max_low: 5
  only_fixed: true # Only allow vulnerabilities with available fixes
  fail_on_any: false

licenses:
  allowed:
    - MIT
    - Apache-2.0
    - BSD-3-Clause
  denied:
    - GPL-3.0
    - AGPL-3.0
    - LGPL-3.0
  require_all_packages: true # All packages must have identified licenses

sbom:
  required_format: "cyclonedx-json"
  min_packages: 1
  require_checksum: true
```

### Relaxed Development Policy

For development/testing environments:

```yaml
version: v1

vulnerabilities:
  max_critical: 5
  max_high: 20
  max_medium: 100
  only_fixed: false

licenses:
  denied:
    - AGPL-3.0 # Only deny extreme copyleft
  warn_on_unknown: true

sbom:
  require_checksum: false
```

### Open Source Project Policy

For open-source projects that accept GPL:

```yaml
version: v1

vulnerabilities:
  max_critical: 0
  max_high: 2
  max_medium: 20
  only_fixed: false

licenses:
  # No allowed list - accept most licenses
  denied:
    - SSPL-1.0 # Server Side Public License (problematic)
  warn_on_unknown: true

sbom:
  required_format: "spdx-json" # SPDX for compliance
  require_checksum: true
```

## Using Policies

### Check Evidence Against Policy

```bash
# Use default policy (provenix.yaml in current directory)
provenix policy check attestation.json

# Use custom policy
provenix policy check attestation.json --config strict-policy.yaml

# Output results as JSON
provenix policy check attestation.json --json

# Save results to file
provenix policy check attestation.json --output results.json
```

### Validate Policy Configuration

```bash
# Validate default policy
provenix policy validate

# Validate specific file
provenix policy validate custom-policy.yaml
```

### Example Output

```
✓ Policy check passed
No violations or warnings found.
```

```
✗ Policy check failed

2 Violations:

1. [high] Package gpl-package@1.0.0 has disallowed license: GPL-3.0
   Package: gpl-package
   Details: map[license:GPL-3.0 reason:license GPL-3.0 is explicitly denied version:1.0.0]

2. [high] Vulnerabilities found: critical=1, high=2, medium=5
   Details: map[critical:1 high:2 medium:5]

1 Warnings:

1. [unknown_license] Package unknown-pkg@2.0.0 has unknown license
   Package: unknown-pkg
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Policy Check

on: [push, pull_request]

jobs:
  policy-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate Evidence
        run: |
          provenix attest myapp --output attestation.json

      - name: Check Policy
        run: |
          provenix policy check attestation.json --config .github/provenix.yaml

      - name: Upload Evidence
        if: success()
        uses: actions/upload-artifact@v4
        with:
          name: attestation
          path: attestation.json
```

### GitLab CI

```yaml
policy-check:
  stage: test
  script:
    - provenix attest myapp --output attestation.json
    - provenix policy check attestation.json
  artifacts:
    paths:
      - attestation.json
    when: on_success
```

## Policy Fields Reference

### Vulnerabilities

- `max_critical`: Maximum critical vulnerabilities allowed (default: 0)
- `max_high`: Maximum high vulnerabilities allowed (default: 0)
- `max_medium`: Maximum medium vulnerabilities allowed (default: 10)
- `max_low`: Maximum low vulnerabilities allowed
- `only_fixed`: Require all vulnerabilities to have fixes available
- `ignore_ids`: List of CVE/GHSA IDs to ignore
- `fail_on_any`: Fail if any vulnerabilities found (regardless of severity)

### Licenses

- `allowed`: List of allowed SPDX license identifiers (if set, only these are allowed)
- `denied`: List of denied SPDX license identifiers (takes precedence over allowed)
- `require_all_packages`: Require all packages to have identified licenses
- `warn_on_unknown`: Warn when packages have unknown licenses

### SBOM

- `required_format`: Required SBOM format (`cyclonedx-json`, `spdx-json`, `syft-json`)
- `min_packages`: Minimum number of packages expected in SBOM
- `require_checksum`: Require SBOM to have a checksum

### Signing (Phase 3 - Week 11-16)

- `required`: Make signing mandatory
- `require_keyless`: Require keyless signing (OIDC + Fulcio)
- `require_rekor`: Require Rekor transparency log entry
- `allowed_issuers`: List of allowed OIDC issuers
- `allowed_subjects`: List of allowed OIDC subjects (patterns)

### Custom (Week 10 - OPA Integration)

- `opa_enabled`: Enable Open Policy Agent integration
- `policy_files`: List of Rego policy files
- `entry_point`: OPA policy entrypoint (default: `data.provenix.allow`)

## Best Practices

1. **Start Strict, Relax Later**: Begin with strict policies and relax as needed
2. **Separate Environments**: Use different policies for dev/staging/production
3. **Version Control**: Store policy files in version control
4. **Regular Reviews**: Review and update policies quarterly
5. **Document Exceptions**: Add comments explaining why specific thresholds were chosen
6. **Test Policies**: Use `provenix policy validate` in CI/CD

## Troubleshooting

### Policy check fails with "invalid config version"

Ensure your policy file has `version: v1` at the top.

### Unknown license warnings

If packages have missing license information:

- Check if SBOM format supports license extraction (CycloneDX, SPDX)
- Set `warn_on_unknown: false` to suppress warnings
- Set `require_all_packages: false` to allow unknown licenses

### Too many violations

Gradually adjust thresholds:

1. Run `provenix policy check attestation.json` to see current counts
2. Adjust `max_*` values in policy configuration
3. Re-run validation

## Next Steps

- Week 10: OPA (Open Policy Agent) integration for custom rules
- Week 11-16: Signing policy enforcement (keyless, Rekor)
- Week 17-20: CI/CD integration examples

For more information, see:

- [CLI Specification](../docs/cli_specification.md)
- [Configuration Guide](../docs/configuration.md)
- [Roadmap](../docs/roadmap.md)
