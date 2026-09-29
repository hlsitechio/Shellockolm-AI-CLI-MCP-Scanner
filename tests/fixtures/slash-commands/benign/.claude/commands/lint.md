---
description: Lint the codebase and fix what can be auto-fixed.
---

# Lint

Run the project linter and fix any issues that can be resolved automatically.

## Steps

1. Run `ruff check --fix` to apply safe autofixes.
2. Run `ruff format` to normalize formatting.
3. Report anything that still needs a human decision.

If the linter is not installed, tell the user how to install it and stop.
