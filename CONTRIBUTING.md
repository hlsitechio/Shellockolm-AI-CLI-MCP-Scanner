# Contributing to Shellockolm

**Thanks for helping make software more secure!** 🔒

## 🚀 Quick Start (60 Seconds)

**1. Get the code:**
```bash
git clone https://github.com/YOUR_USERNAME/shellockolm.git
cd shellockolm
```

**2. Install dependencies:**
```bash
pip install -r requirements.txt
```

**3. Make your changes**

**4. Test it works:**
```bash
python src/cli.py scan ./test_data
```

**5. Submit PR**

Done! ✅

---

## 💡 Ways to Contribute

- 🐛 **Fix bugs** - Check [issues](https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/issues)
- ✨ **Add features** - New scanners, CVE detection, etc.
- 📖 **Improve docs** - Clearer = better
- 🧪 **Add tests** - Coverage is good
- ⭐ **Star the repo** - Helps visibility

## 🛠️ Development Setup

**Need:** Python 3.10+, Git, GitHub account

**Fork → Clone → Install → Code → Test → PR**

## 📤 Submitting Changes

**1. Create a branch:**
```bash
git checkout -b fix/your-fix-name
```

**2. Make changes**

**3. Commit:**
```bash
git add .
git commit -m "Fix: describe what you fixed"
```

**4. Push and create PR:**
```bash
git push origin fix/your-fix-name
```

**Branch names:**
- `fix/` - Bug fixes
- `feat/` - New features
- `docs/` - Documentation
- `test/` - Tests

## ✅ Pull Request Checklist

**Your PR should:**
- [ ] Fix one thing (not ten things)
- [ ] Work when tested locally
- [ ] Include what changed in PR description
- [ ] Not break existing features

**We'll review within 48 hours.**

## 📝 Code Style

**Match existing code style.** If you see:
```python
def scan_directory(path: str) -> Dict[str, Any]:
    """Scan a directory."""
    return results
```

**Do that.** ✅

**Don't do this:**
```python
def scanDir(p):return r
```

**Key rules:**
- Type hints (`str`, `bool`, `Dict`, etc.)
- Docstrings for functions
- 4 spaces (not tabs)
- `snake_case` for functions/variables

## 🧪 Testing

**Before submitting:**
```bash
python src/cli.py scan ./test_data
```

**If it works, you're good.** ✅

**Bonus points:** Add tests if you're adding major features.

### Changing a detection rule? Measure it.

A malware/supply-chain pattern is only as good as its false-positive rate on
real code, so a rule change ships with a before/after measurement over installed
packages — not an estimate. `scripts/corpus_sweep.py` is that measurement:

```bash
# Walk your machine's node_modules trees once (the slow half — reusable).
python scripts/corpus_sweep.py inventory --root /path/to/projects -o corpus.inv.jsonl

# Sweep before your change, and again after.
python scripts/corpus_sweep.py sweep -i corpus.inv.jsonl -o before.jsonl
python scripts/corpus_sweep.py sweep -i corpus.inv.jsonl -o after.jsonl

# What actually moved.
python scripts/corpus_sweep.py diff before.jsonl after.jsonl --fail-on-new-dangers
```

The sweep is resumable (`--resume`), caps per-file reads (`--max-file-bytes`),
and *counts* everything it could not read — a package it never opened is never
part of a "zero false positives over N packages" claim. Paste the `diff` totals
into your PR.

## 🐛 Found a Bug?

**Open an issue with:**
- What you did
- What happened
- What should have happened
- Error message (if any)
- OS & Python version

That's it. We'll handle the rest.

---

## 💡 Feature Ideas?

**Open an issue describing:**
- What you want
- Why you want it
- How it helps

We'll discuss and prioritize.

## 🎯 What We Need Most

**High priority:**
- 🔍 New CVE detection
- 🧪 More tests
- 🌐 Support for Vue/Angular/Svelte
- 🚀 Performance improvements

**Also welcome:**
- 📖 Better docs
- 🐛 Bug fixes
- 🎨 UI improvements

---

## 🔒 Security Issues

**Found a security bug?** Don't open a public issue.

See [SECURITY.md](SECURITY.md) for private reporting.

---

## 📜 Code of Conduct

**Be nice. Don't be a jerk.**

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

---

## 🙏 Thanks!

Every contribution helps make software more secure.

**Questions?** [Open an issue](https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/issues) or ask in [Discussions](https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/discussions).

**First-time contributor?** Look for [`good-first-issue`](https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/labels/good-first-issue) tags.
