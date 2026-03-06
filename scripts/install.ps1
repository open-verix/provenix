# Provenix Installation Script for Windows
# Run with: iwr -useb https://raw.githubusercontent.com/open-verix/provenix/main/scripts/install.ps1 | iex

$ErrorActionPreference = "Stop"

# Configuration
$Repo = "open-verix/provenix"
$BinaryName = "provenix.exe"
$InstallDir = "$env:ProgramFiles\provenix"

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host "  Provenix Installation Script for Windows" -ForegroundColor Blue
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host ""

# Detect architecture
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
Write-Host "✓ Detected Architecture: $Arch" -ForegroundColor Green
Write-Host ""

# Get latest release
Write-Host "→ Fetching latest release..." -ForegroundColor Yellow
try {
    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $Release.tag_name
    Write-Host "✓ Latest version: $Version" -ForegroundColor Green
} catch {
    Write-Host "❌ Failed to fetch latest release" -ForegroundColor Red
    Write-Host "Please check: https://github.com/$Repo/releases"
    exit 1
}
Write-Host ""

# Construct download URL
$ArchiveName = "provenix_${Version}_windows_${Arch}.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$ArchiveName"
$ChecksumUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"

Write-Host "→ Downloading $ArchiveName..." -ForegroundColor Yellow
Write-Host "   $DownloadUrl"

# Create temp directory
$TempDir = New-Item -ItemType Directory -Path "$env:TEMP\provenix-install-$(Get-Random)" -Force

try {
    # Download archive
    $ArchivePath = Join-Path $TempDir $ArchiveName
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ArchivePath -UseBasicParsing
    Write-Host "✓ Downloaded" -ForegroundColor Green
    Write-Host ""

    # Download checksums
    Write-Host "→ Verifying checksum..." -ForegroundColor Yellow
    try {
        $ChecksumPath = Join-Path $TempDir "checksums.txt"
        Invoke-WebRequest -Uri $ChecksumUrl -OutFile $ChecksumPath -UseBasicParsing
        
        # Verify checksum
        $ExpectedHash = (Get-Content $ChecksumPath | Select-String $ArchiveName).ToString().Split()[0]
        $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLower()
        
        if ($ActualHash -eq $ExpectedHash) {
            Write-Host "✓ Checksum verified" -ForegroundColor Green
        } else {
            Write-Host "❌ Checksum verification failed" -ForegroundColor Red
            Write-Host "Expected: $ExpectedHash"
            Write-Host "Actual:   $ActualHash"
            exit 1
        }
    } catch {
        Write-Host "⚠️  Could not verify checksum, skipping" -ForegroundColor Yellow
    }
    Write-Host ""

    # Extract archive
    Write-Host "→ Extracting archive..." -ForegroundColor Yellow
    Expand-Archive -Path $ArchivePath -DestinationPath $TempDir -Force
    
    $BinaryPath = Join-Path $TempDir $BinaryName
    if (-not (Test-Path $BinaryPath)) {
        Write-Host "❌ Binary not found in archive" -ForegroundColor Red
        exit 1
    }
    Write-Host "✓ Extracted" -ForegroundColor Green
    Write-Host ""

    # Create install directory
    Write-Host "→ Installing to $InstallDir..." -ForegroundColor Yellow
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Copy binary
    Copy-Item -Path $BinaryPath -Destination $InstallDir -Force
    Write-Host "✓ Installed" -ForegroundColor Green
    Write-Host ""

    # Add to PATH if not already there
    $Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($Path -notlike "*$InstallDir*") {
        Write-Host "→ Adding to system PATH..." -ForegroundColor Yellow
        try {
            [Environment]::SetEnvironmentVariable(
                "Path",
                "$Path;$InstallDir",
                "Machine"
            )
            Write-Host "✓ Added to PATH (restart terminal to take effect)" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Could not add to PATH automatically" -ForegroundColor Yellow
            Write-Host "   Please add manually: $InstallDir"
        }
        Write-Host ""
    }

    # Verify installation
    Write-Host "→ Verifying installation..." -ForegroundColor Yellow
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    $InstalledPath = Join-Path $InstallDir $BinaryName
    if (Test-Path $InstalledPath) {
        try {
            $VersionOutput = & $InstalledPath --version 2>&1 | Select-Object -First 1
            Write-Host "✓ Installation successful" -ForegroundColor Green
            Write-Host ""
            Write-Host $VersionOutput -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Binary installed but could not run --version" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host "🎉 Provenix is ready to use!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Get started:" -ForegroundColor White
    Write-Host "  provenix --help" -ForegroundColor Blue
    Write-Host "  provenix attest --help" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Documentation:" -ForegroundColor White
    Write-Host "  https://github.com/$Repo" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Note: Restart your terminal to ensure PATH changes take effect" -ForegroundColor Yellow
    Write-Host ""

} finally {
    # Cleanup
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
