#!/bin/bash
# Documentation Validation Script
# Validates that CLI implementation matches cli_specification.md

set -e

PROVENIX="./provenix"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "Provenix Documentation Validation"
echo "======================================"
echo ""

# Counters
TOTAL=0
PASSED=0
FAILED=0
WARNINGS=0

# Test function
test_command() {
    local cmd="$1"
    local description="$2"
    TOTAL=$((TOTAL + 1))
    
    echo -n "Testing: $description ... "
    
    if $cmd &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC}"
        FAILED=$((FAILED + 1))
        return 1
    fi
}

# Test command exists (should show help, not error)
test_exists() {
    local cmd="$1"
    local description="$2"
    TOTAL=$((TOTAL + 1))
    
    echo -n "Exists: $description ... "
    
    if $PROVENIX $cmd --help &>/dev/null; then
        echo -e "${GREEN}✓${NC}"
        PASSED=$((PASSED + 1))
        return 0
    else
        echo -e "${RED}✗${NC}"
        FAILED=$((FAILED + 1))
        echo "  Command not found: provenix $cmd"
        return 1
    fi
}

echo "Phase 1: Command Existence Check"
echo "-----------------------------------"

# Core commands (Section 2.1)
test_exists "attest" "attest command"
test_exists "sbom" "sbom command"
test_exists "scan" "scan command"

# Batch attestation (Section 2.3)
test_exists "batch" "batch command"

# Historical querying (Section 2.4)
test_exists "history" "history command"

# VEX management (Section 2.5)
test_exists "vex" "vex command"
test_exists "vex generate" "vex generate subcommand"
test_exists "vex update" "vex update subcommand"
test_exists "vex merge" "vex merge subcommand"
test_exists "vex filter" "vex filter subcommand"
test_exists "vex validate" "vex validate subcommand"

# Policy management (Section 2.6)
test_exists "policy" "policy command"
test_exists "policy check" "policy check subcommand"
test_exists "policy init" "policy init subcommand"
test_exists "policy validate" "policy validate subcommand"

# Report generation (Section 2.7)
test_exists "report" "report command"
test_exists "report dependencies" "report dependencies subcommand"

# Configuration (Section 2.8)
test_exists "init" "init command"

# Verification (Section 2.9)
test_exists "verify" "verify command"

# Artifact management (Section 2.10)
test_exists "publish" "publish command"

# Additional commands
test_exists "version" "version command"
test_exists "completion" "completion command"

echo ""
echo "Phase 2: Flag Validation"
echo "-----------------------------------"

# Check critical flags for attest
echo -n "attest --config flag ... "
if $PROVENIX attest --help 2>&1 | grep -q "\--config"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo -n "attest --output flag ... "
if $PROVENIX attest --help 2>&1 | grep -q "\--output"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo -n "attest --key flag ... "
if $PROVENIX attest --help 2>&1 | grep -q "\--key"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

# Check batch flags
echo -n "batch --input flag ... "
if $PROVENIX batch --help 2>&1 | grep -q "\--input"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo -n "batch --parallel flag ... "
if $PROVENIX batch --help 2>&1 | grep -q "\--parallel"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo -n "batch --continue-on-error flag ... "
if $PROVENIX batch --help 2>&1 | grep -q "\--continue-on-error"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

# Check history flags
echo -n "history --since flag ... "
if $PROVENIX history --help 2>&1 | grep -q "\--since"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo -n "history --format flag ... "
if $PROVENIX history --help 2>&1 | grep -q "\--format"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo -n "history --local-only flag ... "
if $PROVENIX history --help 2>&1 | grep -q "\--local-only"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

# Check verify flags
echo -n "verify --attestation flag ... "
if $PROVENIX verify --help 2>&1 | grep -q "\--attestation"; then
    echo -e "${GREEN}✓${NC}"
    PASSED=$((PASSED + 1))
else
    echo -e "${RED}✗${NC}"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))

echo ""
echo "======================================"
echo "Summary"
echo "======================================"
echo "Total tests: $TOTAL"
echo -e "${GREEN}Passed: $PASSED${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED${NC}"
else
    echo "Failed: $FAILED"
fi
if [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}Warnings: $WARNINGS${NC}"
fi
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please review the output above.${NC}"
    exit 1
fi
