#!/bin/bash
# Shellockolm - Arch Linux installer with automatic Python setup

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
echo -e "${CYAN}║         Arch Linux - Auto Setup            ║${NC}"
echo -e "${CYAN}║                                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    info "Will use sudo for system packages (you may be prompted for password)"
    SUDO="sudo"
else
    SUDO=""
fi

# Update package database
info "Updating package database..."
$SUDO pacman -Sy --noconfirm

# Install Python if not present
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    info "Python not found. Installing Python..."
    $SUDO pacman -S --noconfirm python python-pip
    success "Python installed"
else
    success "Python already installed"
fi

# Ensure pip is installed
if ! command -v pip &> /dev/null && ! python -m pip --version &> /dev/null; then
    info "Installing pip..."
    $SUDO pacman -S --noconfirm python-pip
    success "pip installed"
fi

# Install git if needed
if ! command -v git &> /dev/null; then
    info "Installing git..."
    $SUDO pacman -S --noconfirm git
    success "git installed"
fi

# Determine Python command (Arch uses 'python' for Python 3)
if command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3"
fi

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    fail "Python 3.10+ required. Found: $PYTHON_VERSION"
    info "Run: sudo pacman -S python"
    exit 1
fi

success "Python detected: $PYTHON_VERSION"

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
