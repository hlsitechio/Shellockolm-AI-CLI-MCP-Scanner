# Contributing to CVE-2025-55182 Security Tools

Thank you for your interest in contributing to this security project! We welcome contributions from the community to help protect React developers worldwide from critical vulnerabilities.

## 🌟 How You Can Contribute

There are many ways to contribute to this project:

- 🐛 **Report bugs** - Found an issue? Let us know!
- 💡 **Suggest features** - Have ideas for improvements?
- 📖 **Improve documentation** - Help make the docs clearer
- 🔧 **Submit code** - Fix bugs or add features
- 🧪 **Write tests** - Improve code coverage
- 🌍 **Translate** - Help make the tools available in other languages
- ⭐ **Spread the word** - Share with other developers

## 🚀 Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Python 3.10+** installed
- **Git** for version control
- **GitHub account** for pull requests
- Familiarity with Python and security concepts

### Fork and Clone

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/cve-2025-55182-tools.git
   cd cve-2025-55182-tools
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/hlsitechio/cve-2025-55182-tools.git
   ```

### Development Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies (if available)
pip install pytest black flake8 mypy
```

## 📝 Contribution Workflow

### 1. Create a Branch

Always create a new branch for your work:

```bash
# Update your main branch
git checkout main
git pull upstream main

# Create feature branch
git checkout -b feature/your-feature-name
# or for bug fixes:
git checkout -b fix/issue-description
```

**Branch naming conventions**:
- `feature/add-xyz` - New features
- `fix/issue-123` - Bug fixes
- `docs/update-readme` - Documentation
- `refactor/cleanup-xyz` - Code refactoring
- `test/add-xyz-tests` - Test additions

### 2. Make Your Changes

- Write clean, readable code
- Follow existing code style
- Add comments for complex logic
- Update documentation as needed
- Add tests for new features

### 3. Test Your Changes

```bash
# Run the scanner
python scan_simple.py ./test_data

# Run auto-fix (dry run)
python auto_fix.py ./test_data --no-backup

# Run tests (if available)
pytest tests/

# Check code style
black --check .
flake8 .
```

### 4. Commit Your Changes

Write clear, descriptive commit messages:

```bash
# Stage your changes
git add .

# Commit with descriptive message
git commit -m "Add feature: vulnerability detection for Vue.js

- Implement Vue.js package.json parsing
- Add version detection logic
- Update scanner to include Vue projects
- Add tests for Vue detection

Closes #123"
```

**Commit message format**:
```
<type>: <short summary>

<detailed description>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

### 5. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/your-feature-name
```

Then:
1. Go to the original repository on GitHub
2. Click "New Pull Request"
3. Select your branch
4. Fill in the PR template
5. Submit!

## 📋 Pull Request Guidelines

### PR Title Format

```
[Type] Short description (50 chars or less)
```

Examples:
- `[Feature] Add support for Angular vulnerability scanning`
- `[Fix] Resolve Windows path handling in scanner`
- `[Docs] Update installation instructions for macOS`

### PR Description Template

```markdown
## Description
Brief description of what this PR does

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Related Issues
Closes #(issue number)
Relates to #(issue number)

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing
Describe how you tested your changes:
- [ ] Tested on Windows
- [ ] Tested on Linux
- [ ] Tested on macOS
- [ ] Added new tests
- [ ] All tests pass

## Screenshots (if applicable)
Add screenshots here

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
```

### Review Process

1. **Automated checks** will run (when CI/CD is set up)
2. **Maintainers review** your code
3. **Address feedback** by pushing new commits
4. **Approval** - Once approved, your PR will be merged!

## 🎨 Code Style Guidelines

### Python Style

We follow **PEP 8** with these conventions:

```python
# Good
def scan_directory(path: str, recursive: bool = True) -> Dict[str, Any]:
    """
    Scan directory for vulnerable projects.

    Args:
        path: Directory path to scan
        recursive: Whether to scan recursively

    Returns:
        Dictionary containing scan results
    """
    results = {}
    # Implementation
    return results

# Bad
def scanDir(p,r=True):
    results={}
    return results
```

**Key points**:
- Use **4 spaces** for indentation (not tabs)
- **Type hints** for function parameters and return values
- **Docstrings** for all public functions/classes
- **Max line length**: 88 characters (Black formatter)
- **Variable names**: `snake_case`
- **Class names**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`

### Documentation Style

- Use **Markdown** for all documentation
- Include **code examples** where helpful
- Keep **line length reasonable** (80-100 chars)
- Use **clear headings** and **bullet points**

## 🧪 Testing Guidelines

### Writing Tests

```python
import pytest
from scanner import CVEScanner

def test_scanner_detects_vulnerable_version():
    """Test that scanner correctly identifies vulnerable React versions"""
    scanner = CVEScanner()
    # Test implementation
    assert scanner.is_vulnerable("19.0.0") == True
    assert scanner.is_vulnerable("19.0.1") == False

def test_scanner_handles_invalid_version():
    """Test that scanner gracefully handles invalid version strings"""
    scanner = CVEScanner()
    with pytest.raises(ValueError):
        scanner.is_vulnerable("invalid")
```

### Test Coverage

- Aim for **80%+ code coverage**
- Test **edge cases** and **error conditions**
- Include **integration tests** for workflows
- Test on **multiple platforms** when possible

## 📚 Documentation Guidelines

### When to Update Docs

Update documentation when you:
- Add new features
- Change existing behavior
- Fix bugs that affect usage
- Add new configuration options
- Change CLI arguments

### Where to Update

- **README.md** - Main usage guide
- **CHANGELOG.md** - Version history
- **Code comments** - Complex logic
- **Docstrings** - All public APIs
- **Examples** - Usage examples

## 🐛 Bug Reports

### Before Reporting

1. **Search existing issues** - Your bug might already be reported
2. **Test with latest version** - Bug might be already fixed
3. **Gather information** - OS, Python version, error messages

### Bug Report Template

```markdown
**Description**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Run command: `python scan_simple.py /path`
2. See error

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: Windows 11
- Python Version: 3.11.5
- Tool Version: 1.0.0

**Error Messages**
```
Paste full error traceback here
```

**Additional Context**
Any other relevant information
```

## 💡 Feature Requests

### Feature Request Template

```markdown
**Feature Description**
Clear description of the proposed feature

**Use Case**
Why is this feature needed? What problem does it solve?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
Other solutions you've considered

**Additional Context**
Mockups, examples, references
```

## 🔒 Security Vulnerabilities

**DO NOT** report security vulnerabilities publicly!

See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## 📜 Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

By participating, you agree to:
- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards others

## 🏆 Recognition

Contributors will be recognized in:
- **README.md** - Contributors section
- **CHANGELOG.md** - Release credits
- **GitHub** - Automatic contributor list

## 📞 Getting Help

Need help contributing?

- 💬 **GitHub Discussions** - Ask questions
- 📧 **Email maintainers** - For private questions
- 📖 **Documentation** - Check existing docs first

## 🎯 Priority Areas

We especially welcome contributions in:

### High Priority
- 🔍 **Additional CVE detection** - Support for other React vulnerabilities
- 🧪 **Test coverage** - Comprehensive test suite
- 🌐 **Framework support** - Vue, Angular, Svelte scanners
- 🚀 **Performance** - Optimize scanning for large codebases

### Medium Priority
- 📚 **Documentation** - Improve guides and examples
- 🐛 **Bug fixes** - Address reported issues
- 🎨 **UI/UX** - Better CLI output formatting
- 🌍 **Internationalization** - Multi-language support

### Nice to Have
- 📊 **Reporting** - Enhanced report formats (PDF, HTML)
- 🔌 **IDE integrations** - VS Code extension
- 📦 **Package managers** - PyPI publishing
- 🤖 **CI/CD** - GitHub Actions workflows

## 📝 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Thank You!

Every contribution, no matter how small, helps make the JavaScript/React ecosystem more secure. Thank you for being part of this mission!

---

**Questions?** Open an issue or start a discussion. We're here to help!

**First time contributing?** Welcome! We're happy to mentor new contributors. Look for issues tagged with `good-first-issue`.
