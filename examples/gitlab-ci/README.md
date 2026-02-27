# GitLab CI Examples for Provenix

This directory contains GitLab CI/CD pipeline examples for integrating Provenix into your workflow.

## Available Examples

### 1. Go Application Attestation

**File:** [go-application.gitlab-ci.yml](go-application.gitlab-ci.yml)

Demonstrates:

- Building a Go application
- Generating attestation with Provenix
- Keyless signing via GitLab OIDC
- Verification and reporting
- Deploying to GitLab Package Registry

### 2. Docker Image Attestation

**File:** [docker-image.gitlab-ci.yml](docker-image.gitlab-ci.yml)

Demonstrates:

- Building and pushing Docker images
- Attesting images by digest
- GitLab Container Registry integration
- Security reporting

### 3. Policy Enforcement

**File:** [policy-enforcement.gitlab-ci.yml](policy-enforcement.gitlab-ci.yml)

Demonstrates:

- Security policy gates
- Failing builds on policy violations
- VEX document generation for triage
- Conditional deployment based on security checks

## Setup Instructions

### 1. Enable GitLab OIDC for Sigstore

Add this to your pipeline configuration:

```yaml
id_tokens:
  GITLAB_OIDC_TOKEN:
    aud: sigstore # Required for Fulcio keyless signing
```

### 2. Create Policy Configuration

Create `provenix.yaml` in your repository root:

```yaml
policy:
  vulnerability_thresholds:
    critical: 0
    high: 5
    medium: 20

  licenses:
    allowed:
      - MIT
      - Apache-2.0
      - BSD-3-Clause
    denied:
      - GPL-3.0
      - AGPL-3.0
```

### 3. Use in Your Pipeline

Copy one of the example files to your repository as `.gitlab-ci.yml`:

```bash
cp go-application.gitlab-ci.yml .gitlab-ci.yml
```

Or include it in your existing pipeline:

```yaml
include:
  - local: "examples/gitlab-ci/go-application.gitlab-ci.yml"
```

## GitLab Features Integration

### Dependency Scanning

Provenix generates CycloneDX SBOMs that GitLab can parse:

```yaml
artifacts:
  reports:
    cyclonedx: attestation.json
```

### Security Dashboard

View vulnerabilities in GitLab Security Dashboard by using the SBOM report.

### Package Registry

Store attestations alongside binaries:

```yaml
script:
  - |
    curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
         --upload-file attestation.json \
         "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/myapp/${CI_COMMIT_TAG}/attestation.json"
```

## Environment Variables

| Variable               | Description                    | Required             |
| ---------------------- | ------------------------------ | -------------------- |
| `GITLAB_OIDC_TOKEN`    | OIDC token for keyless signing | Yes (auto-generated) |
| `CI_REGISTRY`          | GitLab Container Registry URL  | Yes (auto-set)       |
| `CI_REGISTRY_USER`     | Registry username              | Yes (auto-set)       |
| `CI_REGISTRY_PASSWORD` | Registry password              | Yes (auto-set)       |
| `PROVENIX_VERSION`     | Provenix version to use        | No (default: 0.1.0)  |

## Troubleshooting

### OIDC Token Issues

If keyless signing fails, ensure:

1. Your GitLab instance supports OIDC tokens (GitLab 15.7+)
2. The `aud` claim is set to `sigstore`
3. Pipeline has `id_tokens` configuration

### Rekor Timeout

If Rekor is unavailable in your environment:

```yaml
script:
  - provenix attest myapp --skip-transparency --output attestation.json
```

This will save attestation locally (exit code 2) without publishing to Rekor.

### Large Images

For large Docker images, increase timeout:

```yaml
attest-image:
  timeout: 30m # Increase from default 1h
```

## Best Practices

1. **Cache Grype Database**: Cache `/tmp/grype-db` between jobs
2. **Use Image Digests**: Always attest using `@sha256:...` format
3. **Store Attestations**: Keep attestations for compliance (90+ days)
4. **Policy as Code**: Version control `provenix.yaml` with your code
5. **Fail Fast**: Run policy checks before deployment

## Additional Resources

- [GitLab OIDC Documentation](https://docs.gitlab.com/ee/ci/cloud_services/)
- [Provenix Documentation](../../docs/)
- [Sigstore Documentation](https://docs.sigstore.dev/)
