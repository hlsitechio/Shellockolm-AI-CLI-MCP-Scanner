# 🎨 Shellockolm Color Themes

## Dark Theme (Default)

Shellockolm uses a **dark theme** optimized for modern development environments with dark backgrounds (VS Code Dark+, Terminal dark mode, etc.).

---

## Color Palette

### Detective Theme Colors

Our color scheme is inspired by Sherlock Holmes' detective work - bright, clear, and unmistakable.

| Color Name | ANSI Code | RGB Equivalent | Usage |
|------------|-----------|----------------|-------|
| **DETECTIVE** | `\033[1;93m` | Bright Yellow Bold | Sherlock branding, banners |
| **TITLE** | `\033[1;97m` | Bright White Bold | Section headers, emphasis |
| **INFO** | `\033[96m` | Bright Cyan | Information, case details |
| **SUCCESS** | `\033[92m` | Bright Green | Safe projects, fixes applied |
| **WARNING** | `\033[93m` | Bright Yellow | Warnings, pending actions |
| **DANGER** | `\033[1;91m` | Bright Red Bold | Vulnerabilities, critical issues |
| **HIGHLIGHT** | `\033[95m` | Bright Magenta | Special features, server components |
| **PATH** | `\033[94m` | Bright Blue | File paths, directories |
| **COMMAND** | `\033[3;92m` | Bright Green Italic | CLI commands, fixes |
| **SUBTITLE** | `\033[3;96m` | Bright Cyan Italic | Taglines, descriptions |

---

## Implementation

### scan.py (Rich Library)

Uses the Rich library's Theme system for advanced formatting:

```python
from rich.theme import Theme

dark_theme = Theme({
    "info": "bright_cyan",
    "warning": "bright_yellow",
    "danger": "bright_red bold",
    "success": "bright_green",
    "highlight": "bright_magenta",
    "path": "bright_blue",
    "command": "bright_green italic",
    "title": "bold bright_white",
    "subtitle": "bright_cyan italic",
    "detective": "bright_yellow bold"
})

console = Console(theme=dark_theme)
console.print("[detective]🔍 SHELLOCKOLM[/detective]")
```

### scan_simple.py (ANSI Codes)

Uses raw ANSI escape codes for Windows compatibility:

```python
class Colors:
    DETECTIVE = '\033[1;93m'     # Bright Yellow Bold
    TITLE = '\033[1;97m'         # Bright White Bold
    INFO = '\033[96m'            # Bright Cyan
    SUCCESS = '\033[92m'         # Bright Green
    # ... etc

print(f"{Colors.DETECTIVE}🔍 SHELLOCKOLM{Colors.RESET}")
```

---

## Windows Compatibility

For Windows CMD/PowerShell support, we use the `colorama` library:

```python
try:
    import colorama
    colorama.init()
except ImportError:
    pass  # Colors still work on Unix-like systems
```

Install colorama:
```bash
pip install colorama
```

---

## Visual Examples

### Banner Output
```
══════════════════════════════════════════════════════════════════
          🔍 SHELLOCKOLM - SECURITY DETECTIVE
       CVE-2025-55182 & CVE-2025-66478 Scanner
                   CVSS 10.0 CRITICAL
══════════════════════════════════════════════════════════════════
       Elementary security for complex codebases
```

### Vulnerability Detection
```
┌─ Case #1: /projects/my-app
│  ⚠️  React Version:       19.0.0
│  ✅ Recommended Version: 19.0.1
│  🌐 Next.js Version:     15.0.0 ⚠️
│  ✅ Next.js Recommended: 15.0.5
│  🔧 Server Components:   ✅ Detected
└─
```

### Remediation Steps
```
┌─ Case #1: /projects/my-app
│  cd /projects/my-app
│  npm install react@19.0.1 react-dom@19.0.1
│  npm install next@15.0.5
│  npm run build
└─ ✓ Case resolved
```

---

## Customization

### Change Colors for Light Themes

If you use a light terminal background, modify the Colors class:

```python
class Colors:
    # Dark colors for light backgrounds
    DETECTIVE = '\033[33m'       # Normal Yellow
    TITLE = '\033[30m'           # Black
    INFO = '\033[36m'            # Normal Cyan
    SUCCESS = '\033[32m'         # Normal Green
    WARNING = '\033[33m'         # Normal Yellow
    DANGER = '\033[31m'          # Normal Red
    HIGHLIGHT = '\033[35m'       # Normal Magenta
    PATH = '\033[34m'            # Normal Blue
    COMMAND = '\033[3;32m'       # Green Italic
    SUBTITLE = '\033[3;36m'      # Cyan Italic
    RESET = '\033[0m'
```

### Disable Colors Entirely

Set the `NO_COLOR` environment variable:

```bash
export NO_COLOR=1
python src/scan.py
```

Or modify the code:

```python
class Colors:
    # All empty - no colors
    DETECTIVE = ''
    TITLE = ''
    # ... etc
    RESET = ''
```

---

## ANSI Escape Code Reference

### Text Formatting
- `\033[1m` - Bold
- `\033[3m` - Italic
- `\033[4m` - Underline
- `\033[0m` - Reset all

### Standard Colors (30-37)
- 30 = Black
- 31 = Red
- 32 = Green
- 33 = Yellow
- 34 = Blue
- 35 = Magenta
- 36 = Cyan
- 37 = White

### Bright Colors (90-97)
- 90 = Bright Black (Gray)
- 91 = Bright Red
- 92 = Bright Green
- 93 = Bright Yellow
- 94 = Bright Blue
- 95 = Bright Magenta
- 96 = Bright Cyan
- 97 = Bright White

**We use bright colors (90-97) for better visibility on dark backgrounds.**

---

## Accessibility

### Color Blindness Considerations

Our palette is designed with deuteranopia/protanopia in mind:

- **Red (Danger)** - Always paired with ⚠️ emoji
- **Green (Success)** - Always paired with ✅ emoji
- **Blue (Paths)** - Distinct from red/green
- **Yellow (Detective/Warning)** - High contrast

### High Contrast Mode

For maximum accessibility, use only:
- Bright White (97) for normal text
- Bright Red (91) for errors
- Reset for everything else

---

## Terminal Compatibility

### Tested Terminals

✅ **Fully Supported:**
- Windows Terminal
- PowerShell 7+
- VS Code Integrated Terminal
- iTerm2 (macOS)
- GNOME Terminal (Linux)
- Kitty
- Alacritty

⚠️ **Limited Support:**
- CMD.exe (requires colorama)
- PowerShell 5.1 (basic colors only)

❌ **Not Supported:**
- Very old terminals without ANSI support
- Terminals with `NO_COLOR=1` set

---

## Emoji Support

Our theme uses these emojis for universal understanding:

| Emoji | Meaning | Color Context |
|-------|---------|---------------|
| 🔍 | Investigation, Scanning | DETECTIVE (Yellow) |
| ⚠️ | Vulnerability, Warning | DANGER/WARNING (Red/Yellow) |
| ✅ | Success, Safe, Fix | SUCCESS (Green) |
| 🚨 | Critical Alert | DANGER (Red) |
| 📂 | Project, Directory | INFO (Cyan) |
| 🌐 | Next.js | WARNING (Yellow) |
| 🔧 | Server Components | HIGHLIGHT (Magenta) |
| 📦 | Package | WARNING (Yellow) |
| 🎉 | All Clear | SUCCESS (Green) |

**Emojis work without color**, ensuring accessibility even when colors are disabled.

---

## Philosophy

> *"Elementary, my dear developer!"*

Our color scheme follows these principles:

1. **Bright is Right**: Use bright colors (90-97) for dark backgrounds
2. **Consistency**: Same color always means the same thing
3. **Redundancy**: Icons + Colors + Text = Triple reinforcement
4. **Clarity**: Never ambiguous - Red = bad, Green = good
5. **Detective Theme**: Yellow for Sherlock branding

---

## FAQ

**Q: Why bright colors instead of normal colors?**
A: Bright colors (ANSI 90-97) have much better visibility on dark terminal backgrounds. Normal colors (30-37) appear dim and hard to read.

**Q: Can I use Shellockolm with a light theme?**
A: Yes, but you'll need to modify the Colors class to use normal colors (30-37) instead of bright colors (90-97).

**Q: What if colors don't work?**
A: Install `colorama` for Windows, or check if your terminal supports ANSI escape codes. You can also set `NO_COLOR=1` to disable colors.

**Q: Why "DETECTIVE" for yellow?**
A: Sherlock Holmes inspired our project name (Shellockolm). Yellow = magnifying glass 🔍 = investigation = detective work!

---

**🔍 Elementary security for complex codebases**
