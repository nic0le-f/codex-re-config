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

## Resume a case

For a new sample, use the path returned by intake. New cases get an
`index.json`, an empty candidate index, and directories for tasks and hunt
jobs. The index identifies the expected gold and report paths before those
artifacts exist. Existing cases keep their index and metadata. A legacy
case without an index can use the standard map in memory.

```sh
skill=~/.codex/skills/binaryninja-gold-re/scripts
case_dir=$(python3 "$skill/bngold_case.py" init "$sample") && cd "$case_dir"
```

Start Codex in the case directory. Use one task ID per deliverable.

```sh
handoff=~/.codex/skills/binaryninja-gold-re/scripts/case_handoff.py
python3 "$handoff" . start-task review-hits \
  --scope "Review candidates from the selected job" \
  --deliverable "Update hunting/candidates.json" \
  --done-when "Each in-scope hash has evidence or an explicit unknown"

# In a later session, load the existing checkpoint.
python3 "$handoff" . start-task review-hits
```

The command returns the case map and checkpoint together. An existing task
is opened unchanged, including a completed checkpoint. It uses the Codex
thread ID when available. Pass `--session-id` explicitly if needed.
Paths in the map and task records are relative to the case root. Keep raw
hunt exports in place and record each job's rule SHA-256 and hit-list path.
Use one entry per full hash in `hunting/candidates.json`, under the
`candidates` key. Each entry can link multiple job IDs and an existing
assessment. Record a pending disposition when the only evidence is a hit.

From this checkout, run:

```sh
handoff=.codex/skills/binaryninja-gold-re/scripts/case_handoff.py
python3 "$handoff" "$case_dir" index
python3 "$handoff" "$case_dir" lookup "$sample_sha256"
python3 "$handoff" "$case_dir" import-hits "$job_id"
python3 "$handoff" "$case_dir" record-task review-hits \
  --session-id "$codex_session_id" --scope "Review the selected hit list" \
  --status in-progress --evidence hunting/candidates.json \
  --next-action "Check the existing candidate dispositions"
python3 "$handoff" "$case_dir" task review-hits
```

The importer reads `hunting/jobs/<job-id>.json` with `job_id`, `hit_list`
and `hits` (unique count). It merges job links into existing candidate
records and preserves dispositions. Use a new job ID for a changed export.

`record-task` updates the checkpoint for that ID and preserves the
deliverable and completion criteria set at kickoff. Include the current
evidence, outputs and open questions each time. The command reads case metadata only and uses the existing Codex
sign-in workflow.

## User guide and tests

See the [user manual](docs/USER-MANUAL.md) for the daily workflow and the
[work log](docs/WORK-LOG.md) for implementation and verification updates.

The metadata tools and regression suite use Python 3.11 or later. The YARA
fixture requires local `yara` and `yarac`. The optional Binary Ninja
integration test compiles a benign ELF with a local C compiler and opens it
statically.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
PYTHONDONTWRITEBYTECODE=1 bnpython3 -m unittest discover -s tests -p test_gold_integration.py -v
```

Run both commands from the repository root. The ordinary Python suite
skips the Binary Ninja test when its module is unavailable.
