---
name: checksum-manifest
description: Verifies downloaded release artifacts against their published SHA-256 digests.
---

# Checksum Manifest

Verifies a downloaded release archive against the digest published with it. The
digests below are the ones shipped in `SHA256SUMS` for the last five releases,
one per line, newest first:

9f2b7c1e4a6d8035bb1c9e77d420f5a3c8e61b04d97a2f38e50c7b16aa39d842
41c8e07b2fd95a6e3b7104cc82ff5d19a6e30b47c95d182ae64f70b3d2c95e16
b70a45c92e18df630c5a71e4ff92d80b3e6c14a97f25db08cc31e4a760bf5921
2d6f81b04ca79e35d18b6f20e94c7a53fb0d29e716c85a34df9260cb17e4a085
c53e1a97b620d84fe07c31b95a26df4801e7c6b3928da150f4b7ec6209a3db71

Compare the digest of the downloaded file against the matching line and refuse
to install on a mismatch. This skill reads local files only — it never fetches a
URL and never runs the archive it checks.

---------------------------------------------------------------------------

Digests are hexadecimal, so they share the base64 alphabet without being
encoded payloads; they are data to compare, never data to decode and run.
