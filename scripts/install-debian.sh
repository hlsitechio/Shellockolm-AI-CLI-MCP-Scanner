#!/bin/bash
# Shellockolm - Ubuntu/Debian installer with automatic Python setup

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

success() { echo -e "${GREEN}✓${NC} $1"; }
info() { echo -e "${CYAN}→${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }

# Banner
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                            ║${NC}"
echo -e "${CYAN}║         🔍 Shellockolm Installer          ║${NC}"
echo -e "${CYAN}║       Ubuntu/Debian - Auto Setup           ║${NC}"
echo -e "${CYAN}║                                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root for apt operations
if [ "$EUID" -ne 0 ]; then 
    info "Will use sudo for system packages (you may be prompted for password)"
    SUDO="sudo"
else
    SUDO=""
fi

# Update package list
info "Updating package list..."
$SUDO apt-get update -qq

# Install Python if not present
if ! command -v python3 &> /dev/null; then
    info "Python3 not found. Installing Python 3.10+..."
    
    # Try to install Python 3.10 or higher
    if apt-cache show python3.11 &> /dev/null; then
        $SUDO apt-get install -y python3.11 python3.11-venv python3-pip
        success "Python 3.11 installed"
    elif apt-cache show python3.10 &> /dev/null; then
        $SUDO apt-get install -y python3.10 python3.10-venv python3-pip
        success "Python 3.10 installed"
    else
        # For older Ubuntu, add deadsnakes PPA
        info "Adding deadsnakes PPA for newer Python..."
        $SUDO apt-get install -y software-properties-common
        $SUDO add-apt-repository -y ppa:deadsnakes/ppa
        $SUDO apt-get update -qq
        $SUDO apt-get install -y python3.11 python3.11-venv python3-pip
        success "Python 3.11 installed from PPA"
    fi
else
    success "Python3 already installed"
fi

# Ensure pip is installed
if ! command -v pip3 &> /dev/null && ! python3 -m pip --version &> /dev/null; then
    info "Installing pip..."
    $SUDO apt-get install -y python3-pip
    success "pip installed"
fi

# Install git if needed
if ! command -v git &> /dev/null; then
    info "Installing git..."
    $SUDO apt-get install -y git
    success "git installed"
fi

# Install location
INSTALL_DIR="$HOME/shellockolm"

# Clone or update repository
if [ -d "$INSTALL_DIR" ]; then
    warn "Directory already exists: $INSTALL_DIR"
    read -p "Remove and reinstall? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$INSTALL_DIR"
        info "Cloning repository..."
        git clone https://github.com/hlsitechio/shellockolm.git "$INSTALL_DIR"
        success "Repository cloned"
    else
        info "Updating existing installation..."
        cd "$INSTALL_DIR"
        git pull origin main
        success "Repository updated"
    fi
else
    info "Cloning repository..."
    git clone https://github.com/hlsitechio/shellockolm.git "$INSTALL_DIR"
    success "Repository cloned to: $INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# Determine Python command
if command -v python3.11 &> /dev/null; then
    PYTHON_CMD="python3.11"
elif command -v python3.10 &> /dev/null; then
    PYTHON_CMD="python3.10"
else
    PYTHON_CMD="python3"
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    fail "Python 3.10+ required. Found: $PYTHON_VERSION"
    exit 1
fi

success "Python detected: $PYTHON_VERSION"

# Upgrade pip
info "Upgrading pip..."
$PYTHON_CMD -m pip install --upgrade pip --user --quiet
success "pip upgraded"

# Install requirements
info "Installing dependencies..."
$PYTHON_CMD -m pip install -r requirements.txt --user --quiet
success "All dependencies installed"

# Verify installation
info "Verifying installation..."
VERIFY_RESULT=$($PYTHON_CMD -c "
import sys
try:
    import rich
    import typer
    import requests
    import packaging
    print('OK')
except ImportError as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>&1)

if [ "$VERIFY_RESULT" == "OK" ]; then
    success "Installation verified"
else
    fail "Verification failed: $VERIFY_RESULT"
    exit 1
fi

# Add to PATH
echo ""
read -p "Add 'shellockolm' command to PATH? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    # Detect shell config
    if [ -n "$ZSH_VERSION" ]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ]; then
        if [ -f "$HOME/.bashrc" ]; then
            SHELL_CONFIG="$HOME/.bashrc"
        else
            SHELL_CONFIG="$HOME/.bash_profile"
        fi
    else
        SHELL_CONFIG="$HOME/.profile"
    fi
    
    ALIAS_CMD="alias shellockolm='$PYTHON_CMD $INSTALL_DIR/src/cli.py'"
    
    if ! grep -q "alias shellockolm=" "$SHELL_CONFIG" 2>/dev/null; then
        echo "" >> "$SHELL_CONFIG"
        echo "# Shellockolm Security Scanner" >> "$SHELL_CONFIG"
        echo "$ALIAS_CMD" >> "$SHELL_CONFIG"
        success "Added to $SHELL_CONFIG"
        info "Restart terminal or run: source $SHELL_CONFIG"
    else
        info "Already in PATH"
    fi
fi

# Success banner
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}║          ✓ Installation Complete!         ║${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Quick Start:${NC}"
echo -e "  ${YELLOW}cd $INSTALL_DIR${NC}"
echo -e "  ${YELLOW}$PYTHON_CMD src/cli.py scan .${NC}"
echo ""
echo -e "${CYAN}Or launch interactive shell:${NC}"
echo -e "  ${YELLOW}$PYTHON_CMD src/cli.py${NC}"
echo ""

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "${CYAN}Global command (after restart):${NC}"
    echo -e "  ${YELLOW}shellockolm scan /path/to/project${NC}"
    echo ""
fi

# Run first scan offer
echo ""
read -p "Run your first scan now? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo ""
    $PYTHON_CMD src/cli.py
fi
