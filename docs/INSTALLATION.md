# Provenix Installation Guide

This guide covers multiple installation methods for Provenix across different operating systems.

## Quick Install (Recommended)

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.sh | bash
```

### Windows (PowerShell - Run as Administrator)

```powershell
iwr -useb https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.ps1 | iex
```

---

## Manual Installation

### macOS

#### Apple Silicon (M1/M2/M3/M4)

```bash
# Download latest release
VERSION=$(curl -s https://api.github.com/repos/open-verix/provenix/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO "https://github.com/open-verix/provenix/releases/download/${VERSION}/provenix_${VERSION}_darwin_arm64.tar.gz"

# Extract
tar -xzf "provenix_${VERSION}_darwin_arm64.tar.gz"

# Install
sudo mv provenix /usr/local/bin/
sudo chmod +x /usr/local/bin/provenix

# Verify
provenix --version
```

#### Intel Mac

```bash
VERSION=$(curl -s https://api.github.com/repos/open-verix/provenix/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO "https://github.com/open-verix/provenix/releases/download/${VERSION}/provenix_${VERSION}_darwin_amd64.tar.gz"
tar -xzf "provenix_${VERSION}_darwin_amd64.tar.gz"
sudo mv provenix /usr/local/bin/
provenix --version
```

### Linux

#### AMD64

```bash
VERSION=$(curl -s https://api.github.com/repos/open-verix/provenix/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO "https://github.com/open-verix/provenix/releases/download/${VERSION}/provenix_${VERSION}_linux_amd64.tar.gz"
tar -xzf "provenix_${VERSION}_linux_amd64.tar.gz"
sudo mv provenix /usr/local/bin/
provenix --version
```

#### ARM64

```bash
VERSION=$(curl -s https://api.github.com/repos/open-verix/provenix/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO "https://github.com/open-verix/provenix/releases/download/${VERSION}/provenix_${VERSION}_linux_arm64.tar.gz"
tar -xzf "provenix_${VERSION}_linux_arm64.tar.gz"
sudo mv provenix /usr/local/bin/
provenix --version
```

### Windows

#### Using PowerShell

```powershell
# Get latest version
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/open-verix/provenix/releases/latest"
$Version = $Release.tag_name

# Download
Invoke-WebRequest -Uri "https://github.com/open-verix/provenix/releases/download/$Version/provenix_${Version}_windows_amd64.zip" -OutFile "provenix.zip"

# Extract
Expand-Archive -Path provenix.zip -DestinationPath .

# Move to a directory in PATH (requires admin)
Move-Item provenix.exe C:\Windows\System32\

# Or create a dedicated directory
New-Item -ItemType Directory -Path "C:\Program Files\provenix" -Force
Move-Item provenix.exe "C:\Program Files\provenix\"
# Add C:\Program Files\provenix to PATH manually

# Verify
provenix --version
```

---

## Verify Installation

After installation, verify the checksum:

```bash
# Download checksums
VERSION=$(curl -s https://api.github.com/repos/open-verix/provenix/releases/latest | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO "https://github.com/open-verix/provenix/releases/download/${VERSION}/checksums.txt"

# Verify (macOS/Linux)
sha256sum -c checksums.txt 2>/dev/null | grep provenix

# Or on macOS
shasum -a 256 -c checksums.txt 2>/dev/null | grep provenix
```

---

## Build from Source

### Prerequisites

- Go 1.25.7 or later
- Git

### Steps

```bash
# Clone repository
git clone https://github.com/open-verix/provenix.git
cd provenix

# Build
make build

# Install
sudo cp provenix /usr/local/bin/

# Or use Go install
make install
```

### Cross-Platform Build

```bash
# Install GoReleaser
brew install goreleaser  # macOS
# Or download from: https://goreleaser.com/install/

# Build for all platforms
make build-all

# Binaries will be in dist/ directory
ls -lh dist/*/provenix*
```

---

## Installation via Package Managers

### Homebrew (macOS/Linux) - Coming Soon

```bash
# Add tap (after homebrew-tap repository is created)
brew tap open-verix/tap

# Install
brew install provenix

# Update
brew upgrade provenix
```

### Docker

```bash
# Pull image
docker pull ghcr.io/open-verix/provenix:latest

# Run
docker run --rm ghcr.io/open-verix/provenix:latest --version

# Alias for convenience
alias provenix='docker run --rm -v $(pwd):/workspace ghcr.io/open-verix/provenix:latest'
provenix --help
```

---

## Upgrading

### Script Installation

Re-run the installation script:

```bash
# macOS/Linux
curl -fsSL https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.sh | bash

# Windows
iwr -useb https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.ps1 | iex
```

### Manual Upgrade

Download and replace the binary with the latest version using the manual installation steps above.

---

## Uninstallation

### macOS/Linux

```bash
# Remove binary
sudo rm /usr/local/bin/provenix

# Remove config (optional)
rm -rf ~/.config/provenix
```

### Windows

```powershell
# Remove binary
Remove-Item "C:\Program Files\provenix\provenix.exe"

# Or if installed to System32
Remove-Item "C:\Windows\System32\provenix.exe"

# Remove from PATH if manually added
```

---

## Troubleshooting

### macOS: "provenix" cannot be opened because the developer cannot be verified

```bash
# Allow the binary
sudo xattr -d com.apple.quarantine /usr/local/bin/provenix

# Or in System Preferences:
# Security & Privacy → General → "Allow apps downloaded from:"
```

### Linux: Permission denied

```bash
# Make binary executable
chmod +x /usr/local/bin/provenix

# Or verify permissions
ls -l /usr/local/bin/provenix
```

### Command not found

Ensure the installation directory is in your PATH:

```bash
# Check PATH
echo $PATH

# Add to PATH (macOS/Linux - add to ~/.bashrc or ~/.zshrc)
export PATH="/usr/local/bin:$PATH"

# Reload shell
source ~/.bashrc  # or ~/.zshrc
```

### Windows: PATH not updated

After adding to PATH, restart your terminal or run:

```powershell
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
```

---

## Next Steps

After installation:

1. **Verify installation:**
   ```bash
   provenix --version
   provenix --help
   ```

2. **Check examples:**
   - [provenix-examples repository](https://github.com/open-verix/provenix-examples)
   - [CLI Specification](../docs/drafts/cli_specification.md)

3. **Generate your first attestation:**
   ```bash
   provenix attest myapp:latest --key cosign.key
   ```

---

## Support

- **Documentation:** https://github.com/open-verix/provenix
- **Issues:** https://github.com/open-verix/provenix/issues
- **Discussions:** https://github.com/open-verix/provenix/discussions
