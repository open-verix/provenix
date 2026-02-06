# CEL Custom Policy Examples

This guide demonstrates how to write custom policy rules using **Common Expression Language (CEL)** in Provenix.

## Overview

CEL expressions allow you to create flexible, custom policies that evaluate evidence data (SBOM, vulnerabilities, artifact metadata) without writing Go code or Rego.

**Key Concepts:**

- **Expressions return boolean**: `true` = policy passed, `false` = policy violated
- **Input variable**: Access evidence data via `input` map
- **Filter operations**: Use `.filter()`, `.size()`, `.exists()` for list operations
- **Type safety**: Compile-time type checking prevents runtime errors

---

## Input Data Structure

CEL expressions receive evidence data as an `input` map:

```javascript
{
  "artifact": "nginx:1.21.0",
  "sbom": {
    "format": "cyclonedx-json",
    "checksum": "sha256:abc123..."
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-12345",
      "severity": "Critical",
      "package": "openssl",
      "version": "1.1.1k",
      "fixed_version": "1.1.1l",
      "description": "Buffer overflow vulnerability"
    }
  ],
  "vulnerability_count": 1
}
```

---

## Basic Examples

### 1. No Critical Vulnerabilities

**Requirement:** Block deployments with any critical vulnerabilities.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: no-critical-vulnerabilities
      expr: |
        input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0
      message: "Critical vulnerabilities found - deployment blocked"
```

**How it works:**

1. `input.vulnerabilities` - access vulnerability array
2. `.filter(v, v.severity == 'Critical')` - keep only critical vulns
3. `.size() == 0` - ensure filtered list is empty

---

### 2. Vulnerability Count Threshold

**Requirement:** Allow up to 5 high vulnerabilities, but fail if exceeded.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: max-high-vulnerabilities
      expr: |
        input.vulnerabilities.filter(v, v.severity == 'High').size() <= 5
      message: "Too many high vulnerabilities (limit: 5)"
```

---

### 3. No Unfixed Critical Vulnerabilities

**Requirement:** Allow critical vulns ONLY if a fix is available.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: no-unfixed-critical
      expr: |
        input.vulnerabilities
          .filter(v, v.severity == 'Critical' && v.fixed_version == '')
          .size() == 0
      message: "Unfixed critical vulnerabilities found"
```

**Logic:**

- `v.fixed_version == ''` - no fix available
- Combined with `v.severity == 'Critical'` - critical AND unfixed

---

## Advanced Filtering

### 4. Specific Package Vulnerability Check

**Requirement:** Block if `openssl` has high+ vulnerabilities.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: no-openssl-high-vulns
      expr: |
        input.vulnerabilities.filter(v, 
          v.package.contains('openssl') && 
          (v.severity == 'High' || v.severity == 'Critical')
        ).size() == 0
      message: "High/Critical vulnerabilities found in OpenSSL"
```

---

### 5. Multiple Severity Thresholds

**Requirement:** Different limits for different severity levels.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: severity-thresholds
      expr: |
        input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0 &&
        input.vulnerabilities.filter(v, v.severity == 'High').size() <= 5 &&
        input.vulnerabilities.filter(v, v.severity == 'Medium').size() <= 20
      message: "Vulnerability thresholds exceeded (Critical:0, High:5, Medium:20)"
```

---

## SBOM Validation

### 6. Require Specific SBOM Format

**Requirement:** Only accept CycloneDX JSON format.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: require-cyclonedx
      expr: |
        input.sbom.format == 'cyclonedx-json'
      message: "SBOM must be in CycloneDX JSON format"
```

---

### 7. Artifact Naming Convention

**Requirement:** Enforce semantic versioning in image tags.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: semver-tag
      expr: |
        input.artifact.matches('^[^:]+:v?[0-9]+\\.[0-9]+\\.[0-9]+')
      message: "Artifact must use semantic versioning (e.g., myapp:v1.2.3)"
```

**Regex explanation:**

- `^[^:]+:` - image name followed by `:`
- `v?` - optional `v` prefix
- `[0-9]+\\.[0-9]+\\.[0-9]+` - three dot-separated numbers

---

## Environment-Specific Policies

### 8. Production-Only Strict Policy

**Requirement:** Different rules for production vs development.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    # Production: zero tolerance
    - name: production-zero-critical
      expr: |
        !input.artifact.contains('prod') || 
        input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0
      message: "Production images cannot have critical vulnerabilities"

    # Development: allow up to 3 critical
    - name: dev-limited-critical
      expr: |
        !input.artifact.contains('dev') || 
        input.vulnerabilities.filter(v, v.severity == 'Critical').size() <= 3
      message: "Development images: critical vulnerabilities limited to 3"
```

**Logic pattern:**

- `!condition || check` - "if condition, then check must pass"
- If artifact doesn't match, expression returns `true` (passes)

---

## Complex Vulnerability Analysis

### 9. CVE Age Check (Future Enhancement)

**Note:** Requires additional metadata in vulnerability reports.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: no-old-critical-cves
      expr: |
        input.vulnerabilities.filter(v,
          v.severity == 'Critical' &&
          v.published_days_ago > 30
        ).size() == 0
      message: "Critical CVEs older than 30 days found"
```

---

### 10. Combined Policy with Multiple Checks

**Requirement:** Production-ready criteria.

```yaml
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: production-ready
      expr: |
        input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0 &&
        input.vulnerabilities.filter(v, v.severity == 'High').size() <= 2 &&
        input.sbom.format == 'cyclonedx-json' &&
        input.artifact.matches(r':v\\d+\\.\\d+\\.\\d+$')
      message: "Failed production readiness check"
```

**Combines:**

- Zero critical vulnerabilities
- Max 2 high vulnerabilities
- CycloneDX SBOM format
- Semantic version tag

---

## CEL Syntax Reference

### Operators

| Operator             | Example                                        | Description    |
| -------------------- | ---------------------------------------------- | -------------- |
| `==`                 | `v.severity == 'High'`                         | Equality       |
| `!=`                 | `v.fixed_version != ''`                        | Inequality     |
| `>`, `<`, `>=`, `<=` | `v.score > 7.5`                                | Comparison     |
| `&&`, `\|\|`         | `v.severity == 'High' && v.package == 'nginx'` | Logical AND/OR |
| `!`                  | `!input.artifact.contains('test')`             | Logical NOT    |

### String Methods

| Method            | Example                                   | Description     |
| ----------------- | ----------------------------------------- | --------------- |
| `.contains(s)`    | `input.artifact.contains('prod')`         | Substring check |
| `.startsWith(s)`  | `v.id.startsWith('CVE-')`                 | Prefix check    |
| `.endsWith(s)`    | `v.package.endsWith('.so')`               | Suffix check    |
| `.matches(regex)` | `input.artifact.matches(r':\\d+\\.\\d+')` | Regex match     |

### List Methods

| Method             | Example                                 | Description     |
| ------------------ | --------------------------------------- | --------------- |
| `.size()`          | `input.vulnerabilities.size()`          | Get list length |
| `.filter(v, expr)` | `list.filter(v, v.severity == 'High')`  | Filter items    |
| `.exists(v, expr)` | `list.exists(v, v.id == 'CVE-123')`     | Check existence |
| `.all(v, expr)`    | `list.all(v, v.severity != 'Critical')` | All items match |

---

## Best Practices

### 1. Use Descriptive Names

```yaml
# ❌ BAD
- name: check1
  expr: ...

# ✅ GOOD
- name: no-critical-vulnerabilities
  expr: ...
```

### 2. Add Clear Messages

```yaml
# ❌ BAD
message: "Failed"

# ✅ GOOD
message: "Critical vulnerabilities found: deployment blocked per security policy"
```

### 3. Test Incrementally

Start with simple expressions, test, then add complexity:

```yaml
# Step 1: Test basic filtering
expr: input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0

# Step 2: Add package filter
expr: |
  input.vulnerabilities.filter(v,
    v.severity == 'Critical' && v.package == 'openssl'
  ).size() == 0

# Step 3: Add fix availability check
expr: |
  input.vulnerabilities.filter(v,
    v.severity == 'Critical' &&
    v.package == 'openssl' &&
    v.fixed_version == ''
  ).size() == 0
```

### 4. Use Multi-Line for Readability

```yaml
# ❌ HARD TO READ
expr: input.vulnerabilities.filter(v, v.severity == 'Critical' && v.fixed_version == '').size() == 0

# ✅ EASY TO READ
expr: |
  input.vulnerabilities.filter(v,
    v.severity == 'Critical' &&
    v.fixed_version == ''
  ).size() == 0
```

---

## Testing Your Policies

### Using `provenix policy check`

```bash
# 1. Create policy file
cat > provenix.yaml <<EOF
version: v1
custom:
  cel_enabled: true
  cel_expressions:
    - name: no-critical
      expr: |
        input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0
      message: "Critical vulnerabilities found"
EOF

# 2. Generate evidence
provenix attest nginx:latest

# 3. Check policy
provenix policy check --policy provenix.yaml --evidence attestation.json
```

### Expected Output

**Pass:**

```
✅ Policy evaluation passed
- No violations detected
```

**Fail:**

```
❌ Policy evaluation failed

Violations:
  - [Custom Policy] no-critical
    Message: Critical vulnerabilities found
    Details: CEL expression evaluated to false
```

---

## Common Patterns

### Pattern 1: Allowlist

```yaml
# Allow only specific packages
- name: allowed-packages
  expr: |
    input.vulnerabilities.all(v, 
      v.package.matches(r'^(nginx|openssl|glibc)$')
    )
  message: "Vulnerabilities found in non-allowed packages"
```

### Pattern 2: Blocklist

```yaml
# Block specific vulnerable packages
- name: block-log4j
  expr: |
    !input.vulnerabilities.exists(v, 
      v.package.contains('log4j') && v.severity == 'Critical'
    )
  message: "Critical Log4j vulnerability detected"
```

### Pattern 3: Conditional Check

```yaml
# Check only if artifact matches pattern
- name: prod-strict-check
  expr: |
    !input.artifact.contains('prod') ||
    (input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0 &&
     input.vulnerabilities.filter(v, v.severity == 'High').size() <= 5)
  message: "Production image failed security check"
```

---

## Debugging Tips

### 1. Validate Expression Syntax

Use `provenix policy validate`:

```bash
provenix policy validate --policy provenix.yaml
```

### 2. Check Compilation Errors

If expression fails to compile:

```
Error: failed to compile CEL expression 'no-critical':
  ERROR: <input>:2:5: undeclared reference to 'vuln'
```

**Fix:** Use correct variable names (`v` not `vuln`).

### 3. Test with Sample Data

Create minimal test evidence:

```json
{
  "artifact": "test:latest",
  "vulnerabilities": [{ "severity": "Critical", "id": "CVE-TEST" }]
}
```

---

## Migration from OPA (Future)

If you plan to add OPA support later, CEL expressions can be converted:

**CEL:**

```yaml
expr: input.vulnerabilities.filter(v, v.severity == 'Critical').size() == 0
```

**OPA Rego equivalent:**

```rego
deny[msg] {
    critical := [v | v := input.vulnerabilities[_]; v.severity == "Critical"]
    count(critical) > 0
    msg := "Critical vulnerabilities found"
}
```

---

## Performance Considerations

- **Filter early:** Apply `.filter()` before `.size()` to reduce iterations
- **Avoid redundant filters:** Combine conditions in single filter
- **Use exists() when possible:** Faster than `.filter().size() > 0`

**❌ SLOW:**

```yaml
expr: |
  input.vulnerabilities.filter(v, v.severity == 'Critical').size() > 0 &&
  input.vulnerabilities.filter(v, v.severity == 'Critical' && v.package == 'openssl').size() > 0
```

**✅ FAST:**

```yaml
expr: |
  input.vulnerabilities.exists(v, 
    v.severity == 'Critical' && v.package == 'openssl'
  )
```

---

## Further Reading

- [CEL Specification](https://github.com/google/cel-spec)
- [CEL Go Tutorial](https://github.com/google/cel-go/tree/master/examples)
- [Provenix Configuration Reference](../docs/configuration.md)
- [Policy CLI Commands](../docs/cli_specification.md#policy-commands)

---

**Last Updated:** 2026-01-10
