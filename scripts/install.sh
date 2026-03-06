#!/bin/bash
# Provenix Installation Script
# Automatically detects OS and architecture, downloads the latest release

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="open-verix/provenix"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="provenix"

echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  Provenix Installation Script${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo ""

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux*)
        OS_TYPE="linux"
        ;;
    Darwin*)
        OS_TYPE="darwin"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        OS_TYPE="windows"
        BINARY_NAME="provenix.exe"
        ;;
    *)
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_TYPE="amd64"
        ;;
    aarch64|arm64)
        ARCH_TYPE="arm64"
        ;;
    *)
        echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}✓ Detected OS: ${OS_TYPE}${NC}"
echo -e "${GREEN}✓ Detected Architecture: ${ARCH_TYPE}${NC}"
echo ""

# Get latest version
echo -e "${YELLOW}→ Fetching latest release...${NC}"
LATEST_RELEASE=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_RELEASE" ]; then
    echo -e "${RED}❌ Failed to fetch latest release${NC}"
    echo "Please check: https://github.com/${REPO}/releases"
    exit 1
fi

echo -e "${GREEN}✓ Latest version: ${LATEST_RELEASE}${NC}"
echo ""

# Construct download URL
if [ "$OS_TYPE" = "windows" ]; then
    ARCHIVE_NAME="provenix_${LATEST_RELEASE}_${OS_TYPE}_${ARCH_TYPE}.zip"
else
    ARCHIVE_NAME="provenix_${LATEST_RELEASE}_${OS_TYPE}_${ARCH_TYPE}.tar.gz"
fi

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/${ARCHIVE_NAME}"
CHECKSUM_URL="https://github.com/${REPO}/releases/download/${LATEST_RELEASE}/checksums.txt"

echo -e "${YELLOW}→ Downloading ${ARCHIVE_NAME}...${NC}"
echo -e "   ${DOWNLOAD_URL}"

# Download archive
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

cd "$TMP_DIR"

if ! curl -fL -o "${ARCHIVE_NAME}" "${DOWNLOAD_URL}"; then
    echo -e "${RED}❌ Download failed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Downloaded${NC}"
echo ""

# Download and verify checksum
echo -e "${YELLOW}→ Verifying checksum...${NC}"
if curl -fL -o checksums.txt "${CHECKSUM_URL}"; then
    if command -v sha256sum &> /dev/null; then
        if grep "${ARCHIVE_NAME}" checksums.txt | sha256sum -c -; then
            echo -e "${GREEN}✓ Checksum verified${NC}"
        else
            echo -e "${RED}❌ Checksum verification failed${NC}"
            exit 1
        fi
    elif command -v shasum &> /dev/null; then
        if grep "${ARCHIVE_NAME}" checksums.txt | shasum -a 256 -c -; then
            echo -e "${GREEN}✓ Checksum verified${NC}"
        else
            echo -e "${RED}❌ Checksum verification failed${NC}"
            exit 1
        fi
    else
        echo -e "${YELLOW}⚠️  sha256sum not found, skipping checksum verification${NC}"
    fi
else
    echo -e "${YELLOW}⚠️  Could not download checksums, skipping verification${NC}"
fi
echo ""

# Extract archive
echo -e "${YELLOW}→ Extracting archive...${NC}"
if [ "$OS_TYPE" = "windows" ]; then
    unzip -q "${ARCHIVE_NAME}"
else
    tar -xzf "${ARCHIVE_NAME}"
fi

if [ ! -f "${BINARY_NAME}" ]; then
    echo -e "${RED}❌ Binary not found in archive${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Extracted${NC}"
echo ""

# Install binary
echo -e "${YELLOW}→ Installing to ${INSTALL_DIR}...${NC}"

# Check if we have write permission
if [ -w "${INSTALL_DIR}" ]; then
    mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
else
    echo -e "${YELLOW}   (requires sudo)${NC}"
    sudo mv "${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo -e "${GREEN}✓ Installed${NC}"
echo ""

# Verify installation
echo -e "${YELLOW}→ Verifying installation...${NC}"
if command -v provenix &> /dev/null; then
    INSTALLED_VERSION=$(provenix --version 2>&1 | head -1 || echo "unknown")
    echo -e "${GREEN}✓ Installation successful${NC}"
    echo ""
    echo -e "${GREEN}${INSTALLED_VERSION}${NC}"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}🎉 Provenix is ready to use!${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Get started:"
    echo -e "  ${BLUE}provenix --help${NC}"
    echo -e "  ${BLUE}provenix attest --help${NC}"
    echo ""
    echo "Documentation:"
    echo -e "  ${BLUE}https://github.com/${REPO}${NC}"
    echo ""
else
    echo -e "${RED}❌ Installation verification failed${NC}"
    echo "Please make sure ${INSTALL_DIR} is in your PATH"
    exit 1
fi
