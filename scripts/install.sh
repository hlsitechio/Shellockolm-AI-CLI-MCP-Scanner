#!/bin/bash
# Shellockolm - One-line installer for Linux/Mac

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

success() { echo -e "${GREEN}✓${NC} $1"; }
info() { echo -e "${CYAN}→${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }

# Banner
echo ""
echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║                                            ║${NC}"
echo -e "${CYAN}║         🔍 Shellockolm Installer          ║${NC}"
echo -e "${CYAN}║    Security Scanner for React/Node.js      ║${NC}"
echo -e "${CYAN}║                                            ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

# Detect install location
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

# Check Python version
info "Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    fail "Python not found"
    echo "  Install Python 3.10+ from: https://www.python.org/downloads/"
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    fail "Python 3.10+ required. Found: $PYTHON_VERSION"
    echo "  Download from: https://www.python.org/downloads/"
    exit 1
fi

success "Python detected: $PYTHON_VERSION"

# Check pip
info "Checking pip..."
if $PYTHON_CMD -m pip --version &> /dev/null; then
    success "pip detected"
else
    fail "pip not found"
    info "Installing pip..."
    $PYTHON_CMD -m ensurepip --default-pip
    success "pip installed"
fi

# Upgrade pip
info "Upgrading pip..."
$PYTHON_CMD -m pip install --upgrade pip --quiet
success "pip upgraded"

# Install requirements
info "Installing dependencies..."
if [ ! -f "requirements.txt" ]; then
    fail "requirements.txt not found"
    exit 1
fi

$PYTHON_CMD -m pip install -r requirements.txt --quiet
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
    # Detect shell config file
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

# Success message
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}║          ✓ Installation Complete!         ║${NC}"
echo -e "${GREEN}║                                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
echo ""

echo -e "${CYAN}Quick Start:${NC}"
echo -e "  1. Scan current directory:"
echo -e "     ${YELLOW}$PYTHON_CMD src/cli.py scan .${NC}"
echo ""
echo -e "  2. Launch interactive shell:"
echo -e "     ${YELLOW}$PYTHON_CMD src/cli.py${NC}"
echo ""
echo -e "  3. Scan a specific project:"
echo -e "     ${YELLOW}$PYTHON_CMD src/cli.py scan /path/to/project${NC}"
echo ""

if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo -e "  Or use the global command (after restarting terminal):"
    echo -e "     ${YELLOW}shellockolm scan .${NC}"
    echo ""
fi

echo -e "${CYAN}Documentation:${NC}"
echo "  → README: https://github.com/hlsitechio/shellockolm"
echo "  → Issues: https://github.com/hlsitechio/shellockolm/issues"
echo ""

# Offer to run first scan
echo ""
read -p "Run your first scan now? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    echo ""
    $PYTHON_CMD src/cli.py
fi
