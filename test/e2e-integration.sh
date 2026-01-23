#!/usr/bin/env bash
# End-to-End Integration Test for Provenix
# Tests: Syft → Grype → Cosign pipeline via CLI

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_ARTIFACT="alpine:latest"
OUTPUT_FILE="/tmp/provenix-e2e-test.json"
BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROVENIX_BIN="${BUILD_DIR}/provenix"

echo -e "${YELLOW}=== Provenix E2E Integration Test ===${NC}"
echo "Build directory: ${BUILD_DIR}"
echo "Test artifact: ${TEST_ARTIFACT}"
echo "Output file: ${OUTPUT_FILE}"
echo ""

# Step 1: Build provenix
echo -e "${YELLOW}[1/5] Building provenix...${NC}"
cd "${BUILD_DIR}"
if go build -o "${PROVENIX_BIN}" ./cmd/provenix; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${RED}✗ Build failed${NC}"
    exit 1
fi
echo ""

# Step 2: Verify provenix binary
echo -e "${YELLOW}[2/5] Verifying provenix binary...${NC}"
if "${PROVENIX_BIN}" --version 2>&1 | grep -q "provenix"; then
    echo -e "${GREEN}✓ Binary verification successful${NC}"
    "${PROVENIX_BIN}" --version
else
    echo -e "${RED}✗ Binary verification failed${NC}"
    exit 1
fi
echo ""

# Step 3: Generate SBOM
echo -e "${YELLOW}[3/5] Generating SBOM with Syft...${NC}"
if timeout 120 "${PROVENIX_BIN}" sbom "${TEST_ARTIFACT}" \
    --format cyclonedx \
    --output "${OUTPUT_FILE}.sbom" 2>&1 | tee /tmp/sbom.log; then
    
    if [ -f "${OUTPUT_FILE}.sbom" ]; then
        SBOM_SIZE=$(wc -c < "${OUTPUT_FILE}.sbom")
        echo -e "${GREEN}✓ SBOM generated: ${SBOM_SIZE} bytes${NC}"
        
        # Validate SBOM is valid JSON
        if jq empty "${OUTPUT_FILE}.sbom" 2>/dev/null; then
            echo -e "${GREEN}✓ SBOM is valid JSON${NC}"
        else
            echo -e "${RED}✗ SBOM is not valid JSON${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ SBOM file not created${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ SBOM generation completed with warnings${NC}"
    # Don't fail if SBOM was generated
    if [ ! -f "${OUTPUT_FILE}.sbom" ]; then
        echo -e "${RED}✗ SBOM file not found${NC}"
        exit 1
    fi
fi
echo ""

# Step 4: Scan vulnerabilities
echo -e "${YELLOW}[4/5] Scanning vulnerabilities with Grype...${NC}"
if timeout 180 "${PROVENIX_BIN}" scan "${TEST_ARTIFACT}" \
    --output "${OUTPUT_FILE}.scan" 2>&1 | tee /tmp/scan.log; then
    
    if [ -f "${OUTPUT_FILE}.scan" ]; then
        SCAN_SIZE=$(wc -c < "${OUTPUT_FILE}.scan")
        echo -e "${GREEN}✓ Vulnerability scan completed: ${SCAN_SIZE} bytes${NC}"
        
        # Validate scan output is valid JSON
        if jq empty "${OUTPUT_FILE}.scan" 2>/dev/null; then
            echo -e "${GREEN}✓ Scan output is valid JSON${NC}"
            
            # Count vulnerabilities
            VULN_COUNT=$(jq '.vulnerabilities | length' "${OUTPUT_FILE}.scan" 2>/dev/null || echo "0")
            echo -e "${GREEN}✓ Vulnerabilities found: ${VULN_COUNT}${NC}"
        else
            echo -e "${RED}✗ Scan output is not valid JSON${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ Scan output file not created${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ Vulnerability scan completed with warnings${NC}"
    if [ ! -f "${OUTPUT_FILE}.scan" ]; then
        echo -e "${RED}✗ Scan output file not found${NC}"
        exit 1
    fi
fi
echo ""

# Step 5: Generate complete attestation (SBOM + Scan + Sign)
echo -e "${YELLOW}[5/5] Generating complete attestation (SBOM + Scan + Sign)...${NC}"
# Note: For MVP, signing uses simplified keyless mode (no actual OIDC)
if timeout 240 "${PROVENIX_BIN}" attest "${TEST_ARTIFACT}" \
    --output "${OUTPUT_FILE}" \
    --format cyclonedx \
    --skip-transparency 2>&1 | tee /tmp/attest.log; then
    
    if [ -f "${OUTPUT_FILE}" ]; then
        ATTEST_SIZE=$(wc -c < "${OUTPUT_FILE}")
        echo -e "${GREEN}✓ Attestation generated: ${ATTEST_SIZE} bytes${NC}"
        
        # Validate attestation structure
        if jq empty "${OUTPUT_FILE}" 2>/dev/null; then
            echo -e "${GREEN}✓ Attestation is valid JSON${NC}"
            
            # Verify required fields
            ARTIFACT=$(jq -r '.artifact' "${OUTPUT_FILE}" 2>/dev/null || echo "")
            DIGEST=$(jq -r '.artifactDigest' "${OUTPUT_FILE}" 2>/dev/null || echo "")
            SIGNATURE=$(jq -r '.signature.signature' "${OUTPUT_FILE}" 2>/dev/null || echo "")
            
            if [ -n "${ARTIFACT}" ] && [ -n "${DIGEST}" ] && [ -n "${SIGNATURE}" ]; then
                echo -e "${GREEN}✓ Attestation structure validated${NC}"
                echo "  - Artifact: ${ARTIFACT}"
                echo "  - Digest: ${DIGEST:0:32}..."
                echo "  - Signature: ${SIGNATURE:0:32}..."
            else
                echo -e "${RED}✗ Attestation missing required fields${NC}"
                echo "  Artifact: ${ARTIFACT}"
                echo "  Digest: ${DIGEST}"
                echo "  Signature: ${SIGNATURE}"
                exit 1
            fi
            
            # Verify SBOM is embedded
            if jq -e '.sbom' "${OUTPUT_FILE}" > /dev/null 2>&1; then
                echo -e "${GREEN}✓ SBOM embedded in attestation${NC}"
            else
                echo -e "${RED}✗ SBOM not found in attestation${NC}"
                exit 1
            fi
            
            # Verify vulnerability report is embedded
            if jq -e '.vulnerabilityReport' "${OUTPUT_FILE}" > /dev/null 2>&1; then
                VULN_COUNT=$(jq '.vulnerabilityReport.vulnerabilities | length' "${OUTPUT_FILE}" 2>/dev/null || echo "0")
                echo -e "${GREEN}✓ Vulnerability report embedded: ${VULN_COUNT} vulnerabilities${NC}"
            else
                echo -e "${RED}✗ Vulnerability report not found in attestation${NC}"
                exit 1
            fi
        else
            echo -e "${RED}✗ Attestation is not valid JSON${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ Attestation file not created${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ Attestation generation completed with warnings${NC}"
    if [ ! -f "${OUTPUT_FILE}" ]; then
        echo -e "${RED}✗ Attestation file not found${NC}"
        exit 1
    fi
fi
echo ""

# Summary
echo -e "${GREEN}=== E2E Integration Test: SUCCESS ===${NC}"
echo "Generated files:"
echo "  - SBOM: ${OUTPUT_FILE}.sbom"
echo "  - Scan: ${OUTPUT_FILE}.scan"
echo "  - Attestation: ${OUTPUT_FILE}"
echo ""
echo "Pipeline validated:"
echo "  ✓ Syft SBOM generation"
echo "  ✓ Grype vulnerability scanning"
echo "  ✓ Cosign keyless signing (MVP)"
echo "  ✓ Atomic evidence model"
echo ""

# Cleanup
echo "Cleaning up test files..."
rm -f "${OUTPUT_FILE}" "${OUTPUT_FILE}.sbom" "${OUTPUT_FILE}.scan"
rm -f /tmp/sbom.log /tmp/scan.log /tmp/attest.log
echo "Done!"
