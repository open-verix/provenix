# Post-MVP Roadmap: Software Integrity (Dog Fooding)

**Status:** Planning  
**Target Start:** Week 8 (Post Phase 1 Completion)  
**Last Updated:** 2026-01-21

---

## Overview

This document outlines the **Dog Fooding** implementation plan for Provenix. After completing MVP (core attestation functionality), the immediate next step is to apply Provenix to itself and its dependencies to validate the atomic evidence model in a real-world supply chain scenario.

---

## Dog Fooding Implementation (Week 8-12)

### Objective

Apply Provenix to itself and all dependencies (direct + indirect) to:
1. Validate the atomic evidence model in real-world scenarios
2. Establish complete supply chain transparency for Provenix
3. Discover usability issues early through self-use
4. Build credibility by demonstrating "we eat our own dog food"

---

### Stage 1: Provenix Self-Attestation (Week 8)

#### GitHub Actions Workflow

```yaml
# .github/workflows/attest-provenix.yml
name: Attest Provenix Binary

on:
  push:
    tags: ["v*"]
  workflow_dispatch:

jobs:
  attest:
    runs-on: ubuntu-latest
    permissions:
      id-token: write # OIDC token for keyless signing
      contents: write # Upload attestation to releases

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.25.0"

      # Reproducible build
      - name: Build Provenix
        run: |
          go build -trimpath -buildvcs \
            -ldflags="-s -w -X main.version=${{ github.ref_name }}" \
            -o provenix ./cmd/provenix

      # Dog Fooding: Attest Provenix with itself
      - name: Generate Attestation
        run: |
          ./provenix attest provenix \
            --format cyclonedx-json \
            --output attestation.json

      # Publish to Rekor transparency log
      - name: Publish to Rekor
        run: |
          ./provenix publish attestation.json

      # Verify attestation works
      - name: Verify Attestation
        run: |
          ./provenix verify attestation.json

      # Save artifacts
      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: provenix-attestation-${{ github.ref_name }}
          path: |
            provenix
            attestation.json

      # Attach to GitHub release
      - name: Upload to Release
        if: startsWith(github.ref, 'refs/tags/')
        uses: softprops/action-gh-release@v1
        with:
          files: |
            provenix
            attestation.json
```

#### Expected Outputs

**Attestation Structure:**

```json
{
  "artifact": "provenix",
  "artifact_digest": "sha256:...",
  "sbom": {
    "format": "cyclonedx-json",
    "artifact": "provenix",
    "content": "...",
    "checksum": "sha256:...",
    "generated_at": "2026-01-21T00:00:00Z",
    "provider_name": "syft",
    "provider_version": "v1.40.0"
  },
  "vulnerability_report": {
    "vulnerabilities": [
      // CVEs found in dependencies
    ],
    "summary": {
      "critical": 0,
      "high": 0,
      "medium": 2,
      "low": 5
    }
  },
  "signature": {
    "certificate": "...",
    "rekor_entry": "https://rekor.sigstore.dev/api/v1/log/entries/...",
    "signed_at": "2026-01-21T00:00:00Z"
  },
  "metadata": {
    "generated_at": "2026-01-21T00:00:00Z",
    "generator_version": "v1.0.0",
    "sbom_provider": {
      "name": "syft",
      "version": "v1.40.0"
    },
    "scanner_provider": {
      "name": "grype",
      "version": "v0.70.0"
    },
    "signer_provider": {
      "name": "cosign",
      "version": "v2.2.0"
    }
  }
}
```

**SBOM Coverage:**

- **Direct Dependencies:** 5 packages
  - github.com/anchore/stereoscope v0.1.17
  - github.com/anchore/syft v1.40.0
  - github.com/spf13/cobra v1.10.2
  - github.com/spf13/viper v1.21.0
  - modernc.org/sqlite v1.42.2

- **Indirect Dependencies:** ~250 packages (all transitive deps)

---

### Stage 2: Dependency Attestation Analysis (Week 9)

#### Dependency Tree Report

```bash
# Generate comprehensive dependency report
provenix report dependencies \
  --include-indirect \
  --output dependency-report.md

# Example output structure:
## Provenix v1.0.0 Dependency Report

### Direct Dependencies (5)

1. **github.com/anchore/syft v1.40.0**
   - License: Apache-2.0
   - Vulnerabilities: 0
   - Transitive Dependencies: 120
   - Attestation: ✅ Available (signed by Anchore)
   - Rekor Entry: https://rekor.sigstore.dev/...

2. **github.com/spf13/cobra v1.10.2**
   - License: Apache-2.0
   - Vulnerabilities: 0
   - Transitive Dependencies: 3
   - Attestation: ❌ Not available
   - Note: Widely trusted OSS project

### Indirect Dependencies (248)

- ✅ 234 packages: No known vulnerabilities
- ⚠️  12 packages: Low severity CVEs
- 🔴 2 packages: Medium severity (require review)

### License Distribution

- Apache-2.0: 180 packages
- MIT: 50 packages
- BSD-3-Clause: 15 packages
- Others: 3 packages

### Security Summary

- Total Packages: 253
- Total CVEs: 14 (0 critical, 0 high, 2 medium, 12 low)
- Supply Chain Risk: Low
- Attestation Coverage: 20% (5/253 packages)
```

#### Implementation

```go
// cmd/report_dependencies.go
type DependencyReport struct {
    Artifact          string
    TotalPackages     int
    DirectDeps        []*Dependency
    IndirectDeps      []*Dependency
    VulnerabilitySummary *VulnSummary
    LicenseDistribution  map[string]int
    AttestationCoverage  float64
}

func generateDependencyReport(evidence *Evidence) (*DependencyReport, error) {
    report := &DependencyReport{
        Artifact: evidence.Artifact,
        DirectDeps: extractDirectDependencies(evidence.SBOM),
        IndirectDeps: extractIndirectDependencies(evidence.SBOM),
    }

    // Analyze vulnerabilities
    report.VulnerabilitySummary = analyzeVulnerabilities(evidence.VulnerabilityReport)

    // License distribution
    report.LicenseDistribution = analyzeLicenses(evidence.SBOM)

    // Check attestation availability for each dep
    report.AttestationCoverage = calculateAttestationCoverage(report.DirectDeps)

    return report, nil
}
```

---

### Stage 3: Supply Chain Integrity Verification (Week 10)

#### Recursive Dependency Verification

```bash
# Verify Provenix and all direct dependencies
provenix verify --recursive --depth 1 provenix

# Output:
# ✅ provenix: Valid attestation (signed, Rekor verified)
#    ├─ ✅ github.com/anchore/syft@v1.40.0: Valid
#    ├─ ⚠️  github.com/spf13/cobra@v1.10.2: No attestation (trusted)
#    ├─ ✅ github.com/spf13/viper@v1.21.0: Valid
#    └─ ⚠️  modernc.org/sqlite@v1.42.2: No attestation
#
# Summary:
# - Total Dependencies: 5
# - Attested: 2 (40%)
# - Trusted (no attestation): 3 (60%)
# - Failed: 0 (0%)
#
# Result: PASS (all critical paths verified)
```

#### Weekly Automated Scans

```yaml
# .github/workflows/weekly-supply-chain-scan.yml
name: Weekly Supply Chain Scan

on:
  schedule:
    - cron: "0 0 * * 0" # Every Sunday
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Latest Provenix
        run: |
          go build -o provenix ./cmd/provenix

      - name: Generate Fresh Attestation
        run: |
          ./provenix attest provenix \
            --output attestation-$(date +%Y%m%d).json

      - name: Verify Dependency Integrity
        run: |
          ./provenix verify --recursive attestation-*.json

      - name: Generate Report
        run: |
          ./provenix report dependencies \
            --include-indirect \
            --output SUPPLY_CHAIN_REPORT.md

      - name: Create Issue if Vulnerabilities Found
        if: failure()
        uses: peter-evans/create-issue-from-file@v5
        with:
          title: "⚠️ Weekly Supply Chain Scan: New Vulnerabilities Detected"
          content-filepath: SUPPLY_CHAIN_REPORT.md
          labels: security, supply-chain, automated

      - name: Commit Report
        run: |
          git config user.name "provenix-bot"
          git config user.email "bot@provenix.dev"
          git add SUPPLY_CHAIN_REPORT.md
          git commit -m "chore: weekly supply chain report"
          git push
```

---

### Stage 4: Public Transparency (Week 11-12)

#### SBOM Publication

```yaml
# .github/workflows/publish-sbom.yml
name: Publish SBOM

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - name: Download Release Attestation
        uses: actions/download-artifact@v4
        with:
          name: provenix-attestation-${{ github.event.release.tag_name }}

      - name: Extract SBOM
        run: |
          jq '.sbom.content' attestation.json > sbom.json

      - name: Publish to SBOM Registry
        run: |
          # Upload to centralized SBOM repository
          curl -X POST https://sbom-registry.example.com/api/v1/sbom \
            -H "Authorization: Bearer ${{ secrets.SBOM_REGISTRY_TOKEN }}" \
            -F "sbom=@sbom.json" \
            -F "artifact=provenix@${{ github.event.release.tag_name }}"

      - name: Update README Badge
        run: |
          # Update README with SBOM badge
          echo "[![SBOM](https://img.shields.io/badge/SBOM-Available-green)](https://sbom-registry.example.com/provenix)" >> README.md
```

#### Vulnerability Disclosure

Create `SECURITY.md`:

````markdown
# Security Policy

## Supply Chain Transparency

Provenix maintains complete attestation for all releases:

- **SBOM:** CycloneDX JSON format
- **Vulnerability Scan:** Grype database (updated weekly)
- **Signature:** Keyless signing via GitHub OIDC
- **Transparency Log:** Rekor entries for all releases

### Latest Release Security Status

| Release | SBOM | Vulnerabilities | Attestation | Rekor Entry |
|---------|------|-----------------|-------------|-------------|
| v1.0.0  | [📄](attestation.json) | 0 Critical, 0 High, 2 Medium | ✅ Verified | [🔗](https://rekor.sigstore.dev/...) |

### Dependency Security

Total Dependencies: 253 packages (5 direct, 248 indirect)

**Vulnerability Summary:**
- Critical: 0
- High: 0
- Medium: 2 (under review)
- Low: 12 (accepted risk)

Full dependency report: [SUPPLY_CHAIN_REPORT.md](SUPPLY_CHAIN_REPORT.md)

## Reporting Vulnerabilities

Please report security vulnerabilities to: security@provenix.dev

Expected response time: 24-48 hours
````

---

## Success Metrics

### Dog Fooding KPIs

| Metric | Target | Tracking |
|--------|--------|----------|
| Provenix Attestation Coverage | 100% of releases | GitHub Actions |
| Direct Dependency Attestations | > 50% | Weekly scan |
| Vulnerability Response Time | < 48 hours | GitHub Issues |
| SBOM Availability | 100% public | Release artifacts |
| Rekor Transparency Log | 100% signed | Cosign verification |

### Quality Indicators

- ✅ **Build Reproducibility:** Same source = same binary
- ✅ **Attestation Integrity:** No TOCTOU vulnerabilities detected
- ✅ **Supply Chain Visibility:** Complete dependency graph published
- ✅ **Community Trust:** Public Rekor entries for all releases

---

## Documentation Deliverables

1. **User Guide:** "How to Verify Provenix Attestations"
2. **Blog Post:** "Dog Fooding Software Supply Chain Security"
3. **Video Tutorial:** "Understanding Provenix Supply Chain Transparency"
4. **Best Practices:** "Implementing Attestation in Your Projects"

---

## Next Steps After Dog Fooding

Once Dog Fooding is complete (Week 12):

1. **Community Feedback:** Gather user experience insights
2. **Performance Tuning:** Optimize based on real-world data
3. **Feature Prioritization:** Decide next phase based on usage patterns
4. **Marketing Materials:** Use Dog Fooding results as proof of concept

---

**Timeline:**

```
Week 8:  Provenix self-attestation (Stage 1)
Week 9:  Dependency analysis (Stage 2)
Week 10: Recursive verification (Stage 3)
Week 11-12: Public transparency (Stage 4)
Week 13+: Evaluate feedback and consider advanced features
```

**Success Criteria:**

- ✅ 100% of Provenix releases have signed attestations
- ✅ Weekly supply chain scans automated in CI/CD
- ✅ Public SBOM and vulnerability reports published
- ✅ Documentation complete and publicly available
- ✅ Zero critical/high vulnerabilities in production releases

---

## Why Dog Fooding First?

**Validate the Tool by Using It:**

- Provenix must generate attestations for itself
- Proves atomic evidence model works in production
- Identifies UX/API issues before external users
- Demonstrates commitment to software supply chain security

**Build Trust Through Transparency:**

- Public SBOM shows exactly what dependencies Provenix uses
- Vulnerability reports demonstrate proactive security
- Signed attestations prove cryptographic integrity
- Rekor transparency log provides public audit trail

**Learn Before Expanding:**

- Real-world usage exposes edge cases
- Performance bottlenecks become apparent
- Documentation gaps are discovered
- User feedback informs feature priorities

---

## What Comes After Dog Fooding?

**Evaluate based on feedback:**

- If performance is limiting adoption → Optimize (parallel processing, caching)
- If users need custom policies → Build policy engine
- If air-gapped deployments are requested → Add offline support
- If multi-format output is needed → Extend format support

**Possible Future Enhancements (Not Planned Yet):**

- Performance optimization (parallel SBOM generation, caching)
- Policy engine (custom security policies, compliance rules)
- Air-gapped environment support (offline bundles)
- Multi-format output (SLSA provenance, VEX, CSAF)
- Continuous verification (runtime monitoring, K8s admission controllers)
- Supply chain visualization (dependency graphs)
- CI/CD integrations (GitHub Actions, GitLab CI, Jenkins)
- OCI registry integration (attach attestations to images)
- Enterprise features (multi-tenancy, RBAC, audit trails)

**Decision Point:** Week 13+ after Dog Fooding completion and user feedback analysis.

---

## Conclusion

**Post-MVP Focus:** Software Integrity through Dog Fooding (Week 8-12)

**Primary Goal:** Validate Provenix by applying it to itself, proving the atomic evidence model works in production.

**Key Deliverables:**

1. Automated GitHub Actions workflow for Provenix attestation
2. Public SBOM and vulnerability reports (docs/security/)
3. Supply chain verification documentation (SECURITY.md)
4. Recursive dependency analysis (253 packages tracked)

**Success Metric:** 100% of Provenix releases have verified attestations published to Rekor transparency log.

**Next Steps:** After successful Dog Fooding validation, gather user feedback to prioritize future development (performance, policies, integrations, or enterprise features).

---

**Last Updated:** 2026-01-10
