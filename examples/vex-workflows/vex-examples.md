# VEX Workflow Examples

This document contains practical examples of VEX workflows for common scenarios.

## Example 1: Container Image Triage

### Scenario
You've scanned a production container image and need to triage 50 vulnerabilities.

```bash
# 1. Generate attestation
provenix attest myapp:v1.2.3 -o attestation.json

# 2. Generate VEX from attestation
provenix vex generate attestation.json -o vex-initial.json

# 3. Review vulnerabilities
cat vex-initial.json | jq '.statements[] | {vuln: .vulnerability, status: .status}'

# 4. Triage each vulnerability

# Example: Alpine uses musl, not glibc
provenix vex update vex-initial.json CVE-2024-1234 not_affected \
  --justification component_not_present \
  --statement "Alpine Linux uses musl libc. CVE-2024-1234 only affects glibc."

# Example: Vulnerable endpoint disabled
provenix vex update vex-initial.json CVE-2024-5678 not_affected \
  --justification vulnerable_code_not_in_execute_path \
  --statement "Debug endpoint /api/debug is disabled in production via -ldflags '-X main.debug=false'"

# Example: Patched upstream
provenix vex update vex-initial.json CVE-2024-9999 fixed \
  --action-statement "Upgraded nginx from 1.20 to 1.24.0"

# 5. Filter for remaining issues
provenix vex filter vex-initial.json --status affected --severity critical,high
```

## Example 2: Multi-Team VEX Workflow

### Scenario
Development team generates VEX, security team reviews, compliance team filters.

```bash
# Development Team
provenix attest myapp:v2.0.0 -o attestation-v2.0.0.json
provenix vex generate attestation-v2.0.0.json -o vex-dev.json

# Security Team Review
# Mark false positives
provenix vex update vex-dev.json CVE-2024-1111 not_affected \
  --justification vulnerable_code_not_present \
  --statement "Reviewed source code - vulnerable function not present in our fork"

provenix vex update vex-dev.json CVE-2024-2222 not_affected \
  --justification inline_mitigations_already_exist \
  --statement "Input validation prevents exploitation. Verified by penetration test PT-2024-01"

# Save security team's assessment
cp vex-dev.json vex-security.json

# Compliance Team Filtering
# Extract only exploitable vulnerabilities for report
provenix vex filter vex-security.json \
  --status affected,fixed \
  --severity critical,high \
  -o compliance-report-q1-2024.json

# Count by status
echo "Not Affected: $(provenix vex filter vex-security.json --status not_affected | jq '.statements | length')"
echo "Affected: $(provenix vex filter vex-security.json --status affected | jq '.statements | length')"
echo "Fixed: $(provenix vex filter vex-security.json --status fixed | jq '.statements | length')"
```

## Example 3: Continuous VEX Updates in CI/CD

### Scenario
Automatically generate and update VEX on every build.

```bash
#!/bin/bash
# .github/workflows/scripts/update-vex.sh

set -e

VERSION=$1
IMAGE="myapp:${VERSION}"
ATTESTATION="attestation-${VERSION}.json"
VEX_NEW="vex-${VERSION}.json"
VEX_MERGED="vex-latest.json"

# 1. Generate attestation
provenix attest "${IMAGE}" -o "${ATTESTATION}"

# 2. Generate VEX
provenix vex generate "${ATTESTATION}" -o "${VEX_NEW}"

# 3. Load historical VEX data
if [ -f "${VEX_MERGED}" ]; then
  # Merge with historical data (keep latest statements)
  provenix vex merge "${VEX_MERGED}" "${VEX_NEW}" \
    --strategy latest \
    -o "${VEX_MERGED}.tmp"
  mv "${VEX_MERGED}.tmp" "${VEX_MERGED}"
else
  cp "${VEX_NEW}" "${VEX_MERGED}"
fi

# 4. Validate VEX
provenix vex validate "${VEX_MERGED}" --strict

# 5. Policy check: Block if critical affected
CRITICAL_COUNT=$(provenix vex filter "${VEX_MERGED}" \
  --status affected \
  --severity critical | \
  jq '.statements | length')

if [ "${CRITICAL_COUNT}" -gt 0 ]; then
  echo "❌ ${CRITICAL_COUNT} critical vulnerabilities found"
  echo "Please triage before deployment"
  exit 1
fi

echo "✅ VEX validation passed"
```

### GitHub Actions Workflow

```yaml
# .github/workflows/vex-update.yml
name: VEX Management

on:
  push:
    branches: [main]
  pull_request:

jobs:
  vex:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Provenix
        run: |
          wget https://github.com/open-verix/provenix/releases/download/v0.1.0-alpha.1/provenix_linux_amd64
          chmod +x provenix_linux_amd64
          sudo mv provenix_linux_amd64 /usr/local/bin/provenix
      
      - name: Generate and Update VEX
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          ./scripts/update-vex.sh ${{ github.sha }}
      
      - name: Upload VEX Artifact
        uses: actions/upload-artifact@v3
        with:
          name: vex-documents
          path: vex-*.json
      
      - name: Comment PR with VEX Summary
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const vex = JSON.parse(fs.readFileSync('vex-latest.json', 'utf8'));
            
            const affected = vex.statements.filter(s => s.status === 'affected').length;
            const notAffected = vex.statements.filter(s => s.status === 'not_affected').length;
            const fixed = vex.statements.filter(s => s.status === 'fixed').length;
            
            const body = `## VEX Summary
            
            - ✅ Not Affected: ${notAffected}
            - 🔧 Fixed: ${fixed}
            - ⚠️ Affected: ${affected}
            
            See artifact for full VEX document.`;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: body
            });
```

## Example 4: VEX Merging Strategies

### Scenario
Multiple security assessments need to be combined.

```bash
# Team A's assessment (January)
cat > vex-team-a.json <<EOF
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/team-a",
  "author": "Team A",
  "timestamp": "2024-01-15T10:00:00Z",
  "statements": [
    {
      "vulnerability": "CVE-2024-1111",
      "products": ["myapp:v1.0"],
      "status": "not_affected",
      "justification": "component_not_present"
    }
  ]
}
EOF

# Team B's assessment (February - more recent)
cat > vex-team-b.json <<EOF
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/team-b",
  "author": "Team B",
  "timestamp": "2024-02-01T10:00:00Z",
  "statements": [
    {
      "vulnerability": "CVE-2024-1111",
      "products": ["myapp:v1.0"],
      "status": "affected",
      "impact_statement": "Re-evaluated - vulnerability confirmed"
    }
  ]
}
EOF

# Strategy 1: Latest (keeps Team B's assessment - more recent)
provenix vex merge vex-team-a.json vex-team-b.json \
  --strategy latest \
  -o vex-latest.json

# Strategy 2: Union (keeps both assessments)
provenix vex merge vex-team-a.json vex-team-b.json \
  --strategy union \
  -o vex-union.json

# Strategy 3: Override (Team B completely overrides Team A)
provenix vex merge vex-team-a.json vex-team-b.json \
  --strategy override \
  -o vex-override.json

# Review merge results
echo "Latest strategy:"
cat vex-latest.json | jq '.statements[] | {vuln: .vulnerability, status: .status, author: .author}'

echo "Union strategy:"
cat vex-union.json | jq '.statements[] | {vuln: .vulnerability, status: .status, author: .author}'
```

## Example 5: VEX Filtering for Reports

### Scenario
Generate various compliance and security reports.

```bash
# Generate base VEX
provenix vex generate attestation.json -o vex.json

# Report 1: Executive Summary (critical/high only)
provenix vex filter vex.json --severity critical,high -o report-executive.json

# Report 2: Action Required (affected vulnerabilities)
provenix vex filter vex.json --status affected -o report-action-required.json

# Report 3: False Positives (not affected)
provenix vex filter vex.json --status not_affected -o report-false-positives.json

# Report 4: Remediated (fixed)
provenix vex filter vex.json --status fixed -o report-remediated.json

# Generate HTML report
cat > report.html <<EOF
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <style>
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .critical { background-color: #f44336; color: white; }
        .high { background-color: #ff9800; }
        .medium { background-color: #ffeb3b; }
    </style>
</head>
<body>
    <h1>Vulnerability Assessment Report</h1>
    <h2>Summary</h2>
    <ul>
        <li>Critical/High: $(provenix vex filter vex.json --severity critical,high | jq '.statements | length')</li>
        <li>Affected: $(provenix vex filter vex.json --status affected | jq '.statements | length')</li>
        <li>Not Affected: $(provenix vex filter vex.json --status not_affected | jq '.statements | length')</li>
        <li>Fixed: $(provenix vex filter vex.json --status fixed | jq '.statements | length')</li>
    </ul>
</body>
</html>
EOF
```

## Example 6: Bulk VEX Updates

### Scenario
Update multiple vulnerabilities from a CSV file.

```bash
# vulnerabilities.csv format:
# CVE-ID,Status,Justification,Statement
# CVE-2024-1111,not_affected,component_not_present,Alpine uses musl not glibc
# CVE-2024-2222,fixed,,Upgraded to 2.0.1
# CVE-2024-3333,not_affected,vulnerable_code_not_in_execute_path,Admin API disabled

# Bulk update script
cat vulnerabilities.csv | tail -n +2 | while IFS=, read cve status justification statement; do
  if [ -n "$justification" ]; then
    provenix vex update vex.json "$cve" "$status" \
      --justification "$justification" \
      --statement "$statement"
  else
    provenix vex update vex.json "$cve" "$status" \
      --statement "$statement"
  fi
  echo "✅ Updated $cve: $status"
done
```

## Example 7: VEX Validation in Pre-Commit Hook

### Scenario
Ensure VEX documents are valid before committing.

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Validate all VEX documents
VEX_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.vex\.json$')

if [ -z "$VEX_FILES" ]; then
  exit 0
fi

echo "Validating VEX documents..."

for vex in $VEX_FILES; do
  echo "  Checking $vex"
  
  if ! provenix vex validate "$vex" --strict; then
    echo "❌ VEX validation failed for $vex"
    echo "Please fix validation errors before committing"
    exit 1
  fi
done

echo "✅ All VEX documents valid"
exit 0
```

## Example 8: VEX + Policy Enforcement

### Scenario
Combine VEX with OPA/CEL policies.

```bash
# Generate VEX
provenix vex generate attestation.json -o vex.json

# OPA policy: policy.rego
cat > policy.rego <<EOF
package vex

# Deny if any critical vulnerabilities are affected
deny[msg] {
    statement := input.statements[_]
    statement.status == "affected"
    statement.severity == "critical"
    msg := sprintf("Critical vulnerability %s is affected", [statement.vulnerability])
}

# Require justification for not_affected
deny[msg] {
    statement := input.statements[_]
    statement.status == "not_affected"
    not statement.justification
    msg := sprintf("Vulnerability %s marked not_affected without justification", [statement.vulnerability])
}
EOF

# Evaluate policy
opa eval --data policy.rego --input vex.json 'data.vex.deny'

# CEL policy: vex-policy.yaml
cat > vex-policy.yaml <<EOF
apiVersion: policy.provenix.dev/v1alpha1
kind: VEXPolicy
metadata:
  name: production-vex-policy
spec:
  rules:
    - name: no-critical-affected
      expression: |
        !statements.exists(s, s.status == "affected" && s.severity == "critical")
      message: "Critical affected vulnerabilities not allowed"
    
    - name: justification-required
      expression: |
        statements.filter(s, s.status == "not_affected")
          .all(s, has(s.justification))
      message: "All not_affected statements must have justification"
EOF

# Evaluate CEL policy
provenix policy eval vex.json --policy vex-policy.yaml
```

## Next Steps

- See [vex-workflows-guide.md](vex-workflows-guide.md) for complete VEX documentation
- Check [policy-examples.md](../examples/policy-examples.md) for VEX policy integration
- Review [ci-cd-integration-guide.md](ci-cd-integration-guide.md) for automation

