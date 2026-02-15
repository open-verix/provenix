# Week 18-19 Manual Testing Guide

**Date:** 2026-02-16  
**Target:** Phase 3 - Transparency & Publishing (Week 18-19)  
**Features:**
- Week 18: `provenix publish` command
- Week 19: Enhanced `provenix verify` with Rekor queries

---

## Prerequisites

### 1. Build Provenix

**Recommended (with progress display):**
```bash
cd /Users/masato/provenix
make build
```

**Output:**
```
==========================================
Building provenix...
Version:    dev
Commit:     b7064de
Build Date: 2026-02-16T10:30:00Z
==========================================
✅ Build successful: ./provenix
Binary version: dev (b7064de)
```

**Alternative build methods:**
```bash
# Verbose build (shows all compiled packages)
make build-verbose

# Quick build (no version info)
make quick

# Manual build (no output unless error)
go build -o provenix ./cmd/provenix
```

### 2. Generate Test Key (if not exists)
```bash
mkdir -p .provenix
openssl ecparam -genkey -name prime256v1 -noout -out .provenix/test.key
openssl ec -in .provenix/test.key -pubout -out .provenix/test.pub
```

### 3. Verify Binary
```bash
./provenix version
./provenix --help
```

---

## Week 18: `provenix publish` Command Testing

### Test 1: Basic Help Display

**Command:**
```bash
./provenix publish --help
```

**Expected Output:**
- Command description
- Flag options: `--cleanup`, `--dry-run`, `--timeout`, `--rekor-url`
- Usage examples

**Verification:**
- [ ] Help text displays correctly
- [ ] All flags documented
- [ ] Examples are clear

---

### Test 2: Create Local Attestations for Testing

**Step 1: Generate attestation with Rekor unavailable (simulates Week 17 behavior)**
```bash
# This will create attestation and save locally when Rekor fails
./provenix attest alpine:latest \
  --key .provenix/test.key \
  --output .provenix/attestations/test-alpine.json \
  --skip-transparency
```

**Step 2: Verify local attestation was created**
```bash
ls -lh .provenix/attestations/
cat .provenix/attestations/test-alpine.json | jq '.'
```

**Expected:**
- File exists in `.provenix/attestations/`
- JSON structure with: `statement_base64`, `signature`, `publicKey`
- `rekorUUID` should be empty string `""`
- `rekorLogIndex` should be `0`

**Verification:**
- [ ] File created successfully
- [ ] JSON is valid
- [ ] No Rekor metadata (UUID/LogIndex empty)

---

### Test 3: Dry-Run Mode

**Command:**
```bash
./provenix publish --dry-run
```

**Expected Output:**
```
🔍 Scanning for pending attestations...
  Directory: /Users/masato/provenix/.provenix/attestations

📋 Would publish 1 pending attestation(s)
  • test-alpine.json (dry-run mode, not published)

ℹ️  Dry-run mode: No changes made
```

**Verification:**
- [ ] Lists pending attestations
- [ ] No actual Rekor publishing
- [ ] Files remain unchanged
- [ ] Exit code 0

---

### Test 4: Empty Directory Handling

**Setup:**
```bash
# Temporarily move attestations
mkdir -p /tmp/provenix-backup
mv .provenix/attestations/*.json /tmp/provenix-backup/ 2>/dev/null || true
```

**Command:**
```bash
./provenix publish --dry-run
```

**Expected Output:**
```
🔍 Scanning for pending attestations...
  Directory: /Users/masato/provenix/.provenix/attestations

📋 No pending attestations found
```

**Cleanup:**
```bash
mv /tmp/provenix-backup/*.json .provenix/attestations/ 2>/dev/null || true
```

**Verification:**
- [ ] Handles empty directory gracefully
- [ ] No errors
- [ ] Exit code 0

---

### Test 5: Already-Published Detection

**Setup: Create a mock published attestation**
```bash
cat > .provenix/attestations/already-published.json <<'EOF'
{
  "statement_base64": "eyJ0ZXN0IjoidGVzdCJ9",
  "signature": "c2lnbmF0dXJl",
  "publicKey": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
  "rekorUUID": "24296fb24b8ad77a123456789abcdef0123456789abcdef0123456789abcdef01",
  "rekorLogIndex": 172938475
}
EOF
```

**Command:**
```bash
./provenix publish --dry-run
```

**Expected Output:**
```
📋 Found 2 attestation file(s)
  ✓ already-published.json [ALREADY PUBLISHED]
    Rekor UUID: 24296fb24b8ad77a...
    Log Index:  172938475
  • test-alpine.json (pending)
```

**Cleanup:**
```bash
rm .provenix/attestations/already-published.json
```

**Verification:**
- [ ] Detects RekorUUID correctly
- [ ] Skips already-published files
- [ ] Reports status clearly

---

### Test 6: Invalid Bundle Handling

**Setup: Create invalid attestation**
```bash
cat > .provenix/attestations/invalid.json <<'EOF'
{
  "invalid": "data"
}
EOF
```

**Command:**
```bash
./provenix publish --dry-run
```

**Expected:**
- Warning or error for invalid bundle
- Other valid attestations still processed
- Exit code 1 or 2 (depending on implementation)

**Cleanup:**
```bash
rm .provenix/attestations/invalid.json
```

**Verification:**
- [ ] Detects invalid bundles
- [ ] Shows helpful error message
- [ ] Doesn't crash

---

### Test 7: Actual Rekor Publishing (Optional - requires Rekor access)

**⚠️ WARNING: This will publish to Sigstore staging Rekor**

**Command:**
```bash
# Use staging Rekor
./provenix publish \
  --rekor-url https://rekor.sigstore.dev \
  --timeout 60
```

**Expected Flow:**
1. Scans `.provenix/attestations/`
2. Validates bundles
3. Publishes to Rekor
4. Updates files with UUID and LogIndex
5. Displays success summary

**Manual Verification:**
```bash
# Check updated file
cat .provenix/attestations/test-alpine.json | jq '.rekorUUID, .rekorLogIndex'

# Verify on Rekor
# Copy UUID and search at https://search.sigstore.dev/
```

**Verification:**
- [ ] Publishing succeeds
- [ ] Files updated with Rekor metadata
- [ ] UUID and LogIndex present
- [ ] Can verify on Rekor search

---

### Test 8: Cleanup Mode

**Setup: Ensure published attestation exists**
```bash
# After Test 7, or create mock published attestation
cat > .provenix/attestations/cleanup-test.json <<'EOF'
{
  "statement_base64": "eyJ0ZXN0IjoidGVzdCJ9",
  "signature": "c2lnbmF0dXJl",
  "publicKey": "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
  "rekorUUID": "24296fb24b8ad77a123456789abcdef0123456789abcdef0123456789abcdef99",
  "rekorLogIndex": 999999
}
EOF
```

**Command:**
```bash
./provenix publish --cleanup --dry-run
```

**Expected Output:**
```
📋 Would delete 1 already-published attestation(s) (cleanup mode)
  • cleanup-test.json

ℹ️  Dry-run mode: No changes made
```

**Actual Cleanup (without dry-run):**
```bash
# BE CAREFUL: This deletes files
./provenix publish --cleanup
```

**Verification:**
- [ ] Dry-run shows what would be deleted
- [ ] Actual cleanup removes published files
- [ ] Pending attestations remain

---

## Week 19: Enhanced `provenix verify` Testing

### Test 9: Verify Command Help

**Command:**
```bash
./provenix verify --help
```

**Expected Output:**
- New `--digest` flag documented
- New `--all` flag documented
- Examples showing Rekor query usage

**Verification:**
- [ ] New flags present
- [ ] Help text updated
- [ ] Examples clear

---

### Test 10: Traditional Verification (Local File)

**Setup: Use attestation from Week 18**
```bash
# Copy a local attestation
cp .provenix/attestations/test-alpine.json ./attestation.json
```

**Command:**
```bash
./provenix verify alpine:latest --attestation attestation.json
```

**Expected Output:**
```
🔍 Verifying attestation for: alpine:latest
  Using key-based verification (embedded public key)

📋 Verification Results:
  Artifact:          alpine:latest
  Signature Valid:   ✓ (valid)
  Certificate Valid: ✓ (valid)
  Rekor Valid:       ✓ (valid)

✅ Verification PASSED
```

**Verification:**
- [ ] Reads local file correctly
- [ ] Verifies signature
- [ ] Shows clear results
- [ ] Exit code 0 on success

---

### Test 11: Verify with Rekor Query (Digest Mode)

**⚠️ Prerequisites:**
- Attestation must be published to Rekor (from Test 7)
- Need actual artifact digest

**Step 1: Get artifact digest**
```bash
# For Docker image
docker pull alpine:latest
docker inspect alpine:latest | jq -r '.[0].RepoDigests[0]'
# Example output: alpine@sha256:abc123def456...

# Extract just the hash
DIGEST="abc123def456..."  # Replace with actual hash
```

**Step 2: Query Rekor**
```bash
./provenix verify alpine:latest --digest sha256:$DIGEST
```

**Expected Output:**
```
🔍 Verifying attestation for: alpine:latest
🌐 Querying Rekor for attestations matching digest: sha256:abc123...
  Found 2 attestation(s) in Rekor
  Using latest attestation (use --all to see all)

📋 Attestation 1/1:
  UUID:       24296fb24b8ad77a...
  Log Index:  172938475
  Timestamp:  2026-02-16T10:30:00Z

📋 Verification Results:
  [... verification details ...]

✅ Verification PASSED
```

**Verification:**
- [ ] Queries Rekor successfully
- [ ] Finds attestations by digest
- [ ] Extracts and verifies automatically
- [ ] Shows Rekor metadata

---

### Test 12: Show All Attestations (--all flag)

**Command:**
```bash
./provenix verify alpine:latest --digest sha256:$DIGEST --all
```

**Expected:**
- Lists ALL attestations found in Rekor
- Shows details for each (UUID, LogIndex, Timestamp)
- Verifies each attestation individually

**Verification:**
- [ ] Shows multiple attestations if available
- [ ] Sorted by newest first
- [ ] Verifies each one

---

### Test 13: No Attestations Found

**Command:**
```bash
# Use a non-existent digest
./provenix verify myapp --digest sha256:0000000000000000000000000000000000000000000000000000000000000000
```

**Expected Output:**
```
🔍 Verifying attestation for: myapp
🌐 Querying Rekor for attestations matching digest: sha256:0000...
❌ No attestations found in Rekor for this digest
  Digest: sha256:0000...
  Hint: Ensure the artifact was attested and published to Rekor
```

**Verification:**
- [ ] Handles not-found gracefully
- [ ] Shows helpful error message
- [ ] Provides troubleshooting hint
- [ ] Exit code 1

---

### Test 14: Verbose Mode with Rekor Query

**Command:**
```bash
./provenix verify alpine:latest --digest sha256:$DIGEST --verbose
```

**Expected:**
- Detailed attestation data (JSON)
- Full certificate chain details
- Rekor entry body
- Extended verification information

**Verification:**
- [ ] Shows detailed output
- [ ] JSON formatted correctly
- [ ] All metadata visible

---

### Test 15: Fallback Behavior (No Digest, No Local File)

**Setup: Remove local attestation.json**
```bash
rm attestation.json 2>/dev/null || true
```

**Command:**
```bash
./provenix verify alpine:latest
```

**Expected Output:**
```
🔍 Verifying attestation for: alpine:latest
❌ No attestation file found
  Use --attestation to specify attestation file
  Or use --digest to query Rekor
  Or place attestation.json in current directory
```

**Verification:**
- [ ] Detects missing file
- [ ] Shows helpful error with options
- [ ] Exit code 1

---

## Integration Test: Full Workflow

### Test 16: End-to-End Attestation & Verification

**Step 1: Generate attestation (Rekor unavailable - simulated)**
```bash
./provenix attest alpine:latest \
  --key .provenix/test.key \
  --output .provenix/attestations/e2e-test.json \
  --skip-transparency
```

**Step 2: Verify locally saved attestation**
```bash
./provenix verify alpine:latest \
  --attestation .provenix/attestations/e2e-test.json
```

**Step 3: List pending attestations (dry-run)**
```bash
./provenix publish --dry-run
```

**Step 4: Publish to Rekor (optional - if Rekor access available)**
```bash
./provenix publish --timeout 60
```

**Step 5: Query from Rekor and verify**
```bash
# Get digest from attestation
DIGEST=$(cat .provenix/attestations/e2e-test.json | jq -r '.statement_base64' | base64 -d | jq -r '.subject[0].digest.sha256')
./provenix verify alpine:latest --digest sha256:$DIGEST
```

**Step 6: Cleanup published attestations**
```bash
./provenix publish --cleanup --dry-run  # Preview
./provenix publish --cleanup            # Actual cleanup
```

**Verification:**
- [ ] Full workflow completes successfully
- [ ] Each step produces expected output
- [ ] Files created/updated correctly
- [ ] Cleanup works as expected

---

## Common Issues & Troubleshooting

### Issue 1: "Rekor unavailable"

**Symptoms:**
```
❌ Failed to publish to Rekor: connection refused
```

**Solutions:**
1. Check internet connection
2. Verify Rekor URL: `--rekor-url https://rekor.sigstore.dev`
3. Use `--skip-transparency` for local-only testing

---

### Issue 2: "Invalid attestation bundle"

**Symptoms:**
```
⚠️  Failed to validate bundle: missing required field
```

**Solutions:**
1. Check JSON structure: `jq '.' attestation.json`
2. Verify required fields: `statement_base64`, `signature`, `publicKey` or `certificate`
3. Re-generate attestation if corrupted

---

### Issue 3: "No attestations found in Rekor"

**Symptoms:**
```
❌ No attestations found in Rekor for this digest
```

**Solutions:**
1. Verify digest is correct
2. Check if attestation was actually published: `ls .provenix/attestations/ | grep rekorUUID`
3. Try querying Rekor directly: https://search.sigstore.dev/

---

### Issue 4: Permission denied on .provenix/

**Symptoms:**
```
Error: failed to create directory: permission denied
```

**Solutions:**
```bash
chmod -R 755 .provenix/
mkdir -p .provenix/attestations
```

---

## Test Results Template

### Test Execution Log

**Date:** ___________  
**Tester:** ___________  
**Provenix Version:** ___________

| Test # | Test Name | Status | Notes |
|--------|-----------|--------|-------|
| 1 | Help Display | ⬜ | |
| 2 | Create Local Attestations | ⬜ | |
| 3 | Dry-Run Mode | ⬜ | |
| 4 | Empty Directory | ⬜ | |
| 5 | Already-Published Detection | ⬜ | |
| 6 | Invalid Bundle Handling | ⬜ | |
| 7 | Actual Rekor Publishing | ⬜ | |
| 8 | Cleanup Mode | ⬜ | |
| 9 | Verify Help | ⬜ | |
| 10 | Traditional Verification | ⬜ | |
| 11 | Verify with Rekor Query | ⬜ | |
| 12 | Show All Attestations | ⬜ | |
| 13 | No Attestations Found | ⬜ | |
| 14 | Verbose Mode | ⬜ | |
| 15 | Fallback Behavior | ⬜ | |
| 16 | Full E2E Workflow | ⬜ | |

**Legend:**
- ⬜ Not tested
- ✅ Passed
- ❌ Failed
- ⚠️ Passed with issues

---

## Quick Reference: Command Summary

### Week 18 Commands
```bash
# Dry-run mode
./provenix publish --dry-run

# Actual publishing
./provenix publish

# With cleanup
./provenix publish --cleanup

# Custom Rekor URL
./provenix publish --rekor-url https://rekor.example.com

# With timeout
./provenix publish --timeout 60
```

### Week 19 Commands
```bash
# Verify with local file
./provenix verify <artifact> --attestation <file>

# Verify from Rekor
./provenix verify <artifact> --digest sha256:<hash>

# Show all attestations
./provenix verify <artifact> --digest sha256:<hash> --all

# Verbose output
./provenix verify <artifact> --digest sha256:<hash> --verbose

# With public key
./provenix verify <artifact> --public-key key.pub
```

---

**Testing Checklist Complete!**

For any issues or questions, refer to:
- [Week 18 Test Report](../docs/week18-test-report.md)
- [Implementation Plan](../docs/implementation-plan.md)
- [CLI Specification](../docs/cli_specification.md)
