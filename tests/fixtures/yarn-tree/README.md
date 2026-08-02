# yarn dependency-tree ground-truth corpus (build-loop follow-up F32)

A **real** yarn v1 project, vendored so `tests/test_yarn_dependency_tree.py` can check
the tree builder against yarn's own answer with no network and no yarn install in CI.

| file | what it is |
| --- | --- |
| `package.json` | the project manifest — the only place the root's *direct* dependencies are recorded |
| `yarn.lock` | the lockfile yarn 1.22.22 wrote for it (85 installed packages, depth 8) |
| `ground-truth.json` | yarn's own answer, recorded once (see below) |

This is **not** part of `tests/fixtures/manifest.json`. That manifest describes the
agent supply-chain corpus — artifacts labelled by which `AGENT-*` rule they must (not)
trip. These files are dependency-resolution inputs, not model-facing artifacts, and no
detection rule applies to them; `tests/test_fixture_corpus.py` excludes this directory
by name for the same reason it excludes `legit-corpus/`.

## How `ground-truth.json` was recorded

```bash
yarn install --ignore-scripts --non-interactive   # writes yarn.lock
yarn list --json --no-progress --silent > yarnlist.json
```

* `edges` — every `parent|child` pair `yarn list` reports (144). A package's children in
  that listing are the descriptors it requires, which is exactly the edge set the tree
  must reproduce.
* `listed_packages` — the flat listing's `name@version` entries (84).
* `installed_on_disk` — every `(name, version)` read from the real `node_modules` tree
  (85). It is one larger than `listed_packages` on purpose: `yarn list` dedupes its flat
  listing **by name**, so a package installed at two versions appears once. `ms` is
  installed at both `2.0.0` (hoisted) and `2.1.3` (nested under `send/`), and only the
  on-disk set records that — which makes it the authority for "did the tree claim a copy
  that exists".
* `nested_resolutions` — the two `ms` edges spelled out. They are the F32 bug in one
  line: the old parser keyed packages by bare name, so both parents got whichever `ms`
  block was parsed first.

The project pins nothing beyond `package.json`'s ranges, so re-running the commands
above against a newer registry will legitimately produce different versions. Regenerate
`ground-truth.json` alongside `yarn.lock` if you ever refresh it — never by hand.
