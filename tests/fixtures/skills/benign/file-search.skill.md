---
name: file-search
description: Search the workspace for files matching a glob pattern.
---

# File Search

Searches the current workspace for files whose names match a glob pattern and
returns the matching paths.

## Usage

Call this skill with a pattern such as `**/*.py`. It walks the workspace,
collects matches, and returns them sorted by path. It never reads file contents
and never makes network requests.

## Notes

- Skips `node_modules`, `.git`, and other heavy directories.
- Results are capped at 500 paths for readability.
