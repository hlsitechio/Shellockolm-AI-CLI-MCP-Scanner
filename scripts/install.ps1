#Requires -Version 5.1
<#
.SYNOPSIS
    Shellockolm - One-line installer for Windows
.DESCRIPTION
    Automatically installs Python dependencies and sets up Shellockolm
.EXAMPLE
    .\install.ps1
.EXAMPLE
    iex (irm https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install.ps1)
#>

$ErrorActionPreference = "Stop"

# Colors
function Write-Success { param($msg) Write-Host "✓ $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "→ $msg" -ForegroundColor Cyan }
function Write-Warn { param($msg) Write-Host "⚠ $msg" -ForegroundColor Yellow }
function Write-Fail { param($msg) Write-Host "✗ $msg" -ForegroundColor Red }

# Banner
Write-Host ""
Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                            ║" -ForegroundColor Cyan
Write-Host "║         🔍 Shellockolm Installer          ║" -ForegroundColor Cyan
Write-Host "║    Security Scanner for React/Node.js      ║" -ForegroundColor Cyan
Write-Host "║                                            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Detect if running from web (one-liner) or local
$IsRemoteInstall = $MyInvocation.MyCommand.Path -eq $null
$ScriptLocation = if ($IsRemoteInstall) { $PWD.Path } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
# For local install, go up one level to repo root (scripts/ -> repo/)
$ScriptDir = if ($IsRemoteInstall) { $PWD.Path } else { Split-Path -Parent $ScriptLocation }

if ($IsRemoteInstall) {
    Write-Info "Remote installation detected"
    Write-Info "Cloning repository..."
    
    # Check if git is installed
    try {
        $null = git --version
    } catch {
        Write-Fail "Git is not installed. Please install Git first:"
        Write-Host "  → https://git-scm.com/download/win" -ForegroundColor Yellow
        exit 1
    }
    
    # Clone repo
    $InstallPath = Join-Path $env:USERPROFILE "shellockolm"
    if (Test-Path $InstallPath) {
        Write-Warn "Directory already exists: $InstallPath"
        $response = Read-Host "Remove and reinstall? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Remove-Item $InstallPath -Recurse -Force
        } else {
            Write-Info "Using existing directory"
            Set-Location $InstallPath
            git pull origin main
        }
    } else {
        git clone https://github.com/hlsitechio/shellockolm.git $InstallPath
        Set-Location $InstallPath
    }
    
    $ScriptDir = $InstallPath
    Write-Success "Repository cloned to: $InstallPath"
}

# Step 1: Check Python
Write-Info "Checking Python installation..."
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)\.(\d+)") {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Write-Fail "Python 3.10+ required. Found: $pythonVersion"
            Write-Host "  → Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
            exit 1
        }
        
        Write-Success "Python detected: $pythonVersion"
    }
} catch {
    Write-Fail "Python not found in PATH"
    Write-Host "  → Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  → Make sure to check 'Add Python to PATH' during installation" -ForegroundColor Yellow
    exit 1
}

# Step 2: Check pip
Write-Info "Checking pip..."
try {
    $pipVersion = python -m pip --version
    Write-Success "pip detected: $pipVersion"
} catch {
    Write-Fail "pip not found"
    Write-Info "Installing pip..."
    python -m ensurepip --default-pip
    Write-Success "pip installed"
}

# Step 3: Upgrade pip
Write-Info "Upgrading pip to latest version..."
python -m pip install --upgrade pip --quiet
Write-Success "pip upgraded"

# Step 4: Install requirements
Write-Info "Installing dependencies from requirements.txt..."
$requirementsPath = Join-Path $ScriptDir "requirements.txt"

if (-not (Test-Path $requirementsPath)) {
    Write-Fail "requirements.txt not found at: $requirementsPath"
    exit 1
}

try {
    python -m pip install -r $requirementsPath --quiet
    Write-Success "All dependencies installed"
} catch {
    Write-Fail "Failed to install dependencies"
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Step 5: Verify installation
Write-Info "Verifying installation..."
$cliPath = Join-Path $ScriptDir "src\cli.py"

if (-not (Test-Path $cliPath)) {
    Write-Fail "cli.py not found at: $cliPath"
    exit 1
}

# Test import of key dependencies
$testScript = @"
import sys
try:
    import rich
    import typer
    import requests
    import packaging
    print("OK")
except ImportError as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
"@

$testResult = $testScript | python
if ($testResult -eq "OK") {
    Write-Success "Installation verified"
} else {
    Write-Fail "Verification failed"
    exit 1
}

# Step 6: Create desktop shortcut (optional)
Write-Host ""
$createShortcut = Read-Host "Create desktop shortcut for quick access? (Y/n)"
if ($createShortcut -ne 'n' -and $createShortcut -ne 'N') {
    try {
        $WshShell = New-Object -ComObject WScript.Shell
        $ShortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "Shellockolm.lnk"
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)
        $Shortcut.TargetPath = "python.exe"
        $Shortcut.Arguments = "`"$cliPath`""
        $Shortcut.WorkingDirectory = $ScriptDir
        $Shortcut.Description = "Shellockolm Security Scanner"
        $Shortcut.Save()
        Write-Success "Desktop shortcut created"
    } catch {
        Write-Warn "Could not create shortcut: $($_.Exception.Message)"
    }
}

# Step 7: Add to PATH (optional)
Write-Host ""
$addToPath = Read-Host "Add Shellockolm to PATH for global access? (Y/n)"
if ($addToPath -ne 'n' -and $addToPath -ne 'N') {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$ScriptDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$ScriptDir", "User")
        Write-Success "Added to PATH (restart terminal to use 'shellockolm' command)"
        
        # Create wrapper script
        $wrapperPath = Join-Path $ScriptDir "shellockolm.bat"
        @"
@echo off
python "$cliPath" %*
"@ | Set-Content $wrapperPath
        
        Write-Success "Created 'shellockolm' command wrapper"
    } else {
        Write-Info "Already in PATH"
    }
}

# Success message
Write-Host ""
Write-Host "╔════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                                            ║" -ForegroundColor Green
Write-Host "║          ✓ Installation Complete!         ║" -ForegroundColor Green
Write-Host "║                                            ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

Write-Host "Quick Start:" -ForegroundColor Cyan
Write-Host "  1. Scan current directory:" -ForegroundColor White
Write-Host "     python src\cli.py scan ." -ForegroundColor Yellow
Write-Host ""
Write-Host "  2. Launch interactive shell:" -ForegroundColor White
Write-Host "     python src\cli.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "  3. Scan a specific project:" -ForegroundColor White
Write-Host "     python src\cli.py scan C:\path\to\project" -ForegroundColor Yellow
Write-Host ""

if ($addToPath -ne 'n' -and $addToPath -ne 'N') {
    Write-Host "  Or use the global command (after restarting terminal):" -ForegroundColor White
    Write-Host "     shellockolm scan ." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "  → README: https://github.com/hlsitechio/shellockolm" -ForegroundColor White
Write-Host "  → Issues: https://github.com/hlsitechio/shellockolm/issues" -ForegroundColor White
Write-Host ""

# Offer to run first scan
Write-Host ""
$runNow = Read-Host "Run your first scan now? (Y/n)"
if ($runNow -ne 'n' -and $runNow -ne 'N') {
    Write-Host ""
    python $cliPath
}
