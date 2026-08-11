# Codex RE Config

Portable Codex reversing harness configuration exported on 2026-08-11.

This repository contains the source-control friendly harness pieces from the export:

- `.local/bin/codex` as a relative symlink to the bundled launcher
- `.codex/skills`
- `.codex/rules`
- `.codex/plugins`
- `.codex/config.example.toml`

The original archive also contained `.codex/packages/standalone/releases/0.146.0-x86_64-unknown-linux-musl`.
That runtime package is intentionally not tracked here because it contains a 311 MB executable,
which exceeds GitHub's normal per-file limit without Git LFS.

The reversing-specific skills are:

- `.codex/skills/binaryninja-gold-re`
- `.codex/skills/malcat-triage`

Excluded on purpose from the repository:

- `.codex/auth.json`
- conversation history and sessions
- logs, memories, goals, shell snapshots, and SQLite state
- local caches that reflect usage
- local project/work directories
- machine-specific `.codex/config.toml` project trust entries and MCP paths
- `installation_id`
- bundled standalone runtime binaries

Install on another machine:

1. Clone this repository into the target home directory, or copy its contents into `$HOME`.
2. Ensure `$HOME/.local/bin` is on `PATH`.
3. Create a fresh `$HOME/.codex/config.toml` from `.codex/config.example.toml` if desired.
4. Install or restore Codex on the target machine so `.codex/packages/standalone/current/bin/codex` exists.
5. Authenticate on the target machine using the normal Codex login flow.

The exported standalone package was Linux x86_64 musl. Use the official installer instead if the
target machine has a different architecture or OS.
