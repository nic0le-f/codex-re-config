# Codex RE harness user manual

Use the harness from a signed-in Codex session. Start Codex inside the specific
case directory under `~/re-cases` so the session is easy to find in Workspace
Monitor. The scripts below run locally with Python 3.11 or newer. Binary Ninja operations
use the installed `bnpython3`.

## Open or create a case

In your shell, set the script path and pass the sample you need to examine.

```sh
scripts="$HOME/.codex/skills/binaryninja-gold-re/scripts"
case_dir=$(python3 "$scripts/bngold_case.py" init "/path/to/sample") && cd "$case_dir"
```

Intake returns the existing case if the bytes match its full SHA-256. If more
than one existing case matches, intake lists them for review. Keep the case
directory as your working directory. Its `index.json` points to the manifest,
expected report and gold paths, tasks, and hunt records. A new case may have
an index before those outputs exist. A legacy case without an index can use
the standard paths returned by the handoff command.

## Start, checkpoint, or resume a task

Give a task one primary deliverable. Choose a stable ID you can search for
later. Include a verification check in `--done-when`.

```sh
python3 "$scripts/case_handoff.py" . start-task verify-report \
  --scope "Check one report conclusion against its cited evidence" \
  --deliverable "Update reports/final.md with the verified conclusion" \
  --done-when "The conclusion cites inspectable local evidence or states the unknown"
```

In a new Codex session, use the same case directory and task ID.

```sh
python3 "$scripts/case_handoff.py" . start-task verify-report
```

The output includes the case map and saved checkpoint. Start with the evidence
paths that are relevant to the task. A completed task stays completed when
opened. To supply the session ID explicitly, use `--session-id`.

Save a checkpoint when a result is verified, the deliverable is ready, or a
blocker changes what happens next. Include current evidence, output paths and
open questions. This updates the checkpoint while preserving the kickoff
deliverable and completion criteria.

```sh
python3 "$scripts/case_handoff.py" . record-task verify-report \
  --session-id "$CODEX_THREAD_ID" --scope "Check one report conclusion" \
  --status completed --output reports/final.md \
  --evidence evidence/review-note.md
```

A prompt can be short:

```text
Resume task verify-report from the case checkpoint.
Verify the selected claim against its primary evidence. Update the case
report and record the evidence path and any unresolved point in the checkpoint.
```

## Register and review a hunt

Give each submitted job its own ID. Keep the exact rule file and machine-readable
hit list from the service. The hit list should contain one full SHA-256 per
line. Record the service, date window, and intended scope while the job details
are still available. Preserve the archive for each job if the active rule
changes. Keep family labels as leads and record the primary evidence behind
any case-specific conclusion.

If you maintain an active rule in the case, register its purpose and current
revision first. This keeps previous revisions by content hash.

```sh
python3 "$scripts/case_handoff.py" . register-rule "$rule_id" \
  --rule "/path/to/active.yar" --purpose "Screen candidates for manual review"
```

Register each completed job with its submitted revision.

```sh
python3 "$scripts/case_handoff.py" . register-hunt "$job_id" \
  --service "VirusTotal Retrohunt" --scope "Window and collection reviewed" \
  --start-date 2026-01-01 --end-date 2026-01-31 \
  --rule "/path/to/submitted.yar" --hit-list "/path/to/hits.txt"
```

This command archives existing local inputs and merges the hits into the
candidate index. Submission and downloads happen separately. Pass
`--expected-count` when the service provides a count of unique hit hashes.
The result shows how many candidates were new and how many already had an
assessment in the case. An identical retry is safe. If registration saves
the archive but importing stops, correct the reported problem and repeat
the command with the same inputs. For a changed export, use a new job ID.

## Review candidates from a hunt

Look up a full hash before starting analysis. One candidate can link to
multiple hunt jobs. A hit is a lead and the relationship assessment needs
its own evidence. Keep the evidence and conclusion in the owning case and
cross-reference them from other cases where useful.

```sh
python3 "$scripts/case_handoff.py" . lookup "$sample_sha256"
python3 "$scripts/case_handoff.py" . lookup "$sample_sha256" \
  --cases-dir "$HOME/re-cases"
```

The cross-case lookup displays each case's own assessment and the status of
linked files. A prior assessment can inform the current review. Preserve
separate conclusions for separate case questions. Save the disposition with
a case-relative report path. The command records the report digest so a
later cross-case lookup can flag changed evidence.

```sh
python3 "$scripts/case_handoff.py" . record-assessment "$sample_sha256" \
  --disposition relationship-unresolved \
  --assessment reports/candidate-review.md
```

Use `--sample` with a case-relative path when that case owns a downloaded
copy. Omit it when the review refers to an existing sample elsewhere.

## Validate a frozen YARA revision

Use a known-positive fixture and a representative negative fixture. The
command uses the archived rule for the job and requires `yara` and `yarac`.
You can repeat the fixture flags. The receipt under `hunting/validation/`
records engine version, rule hash, fixture hashes and expectations. A failed
expectation still produces a receipt and returns a failing exit status.

```sh
python3 "$scripts/case_handoff.py" . validate-rule "$job_id" \
  --positive "/path/to/known-positive-fixture" \
  --negative "/path/to/negative-fixture"
```

## Get independent review

Gold promotion requires an independent approval. Start family-attribution
and material report correction tasks with `--task-type family-attribution`
or `--task-type material-report-correction`. Use `--task-type gold-bndb`
for a gold task. Its completion uses the same case-level approval as
promotion and expects `gold/gold.bndb` among the task outputs.
Routine work can use `re`, `triage`, `hunting`, or `yara`.

For a task, first save its output paths with `record-task --status in-progress`.
The author requests review under the task ID for attribution or correction. For gold, use the reserved
subject `gold` after saving the base, claims, and verdicts.

```sh
python3 "$scripts/case_handoff.py" . request-review gold --session-id "$CODEX_THREAD_ID"
```

A separate reviewer runs the following with evidence they inspected. Replace
`gold` with the task ID for a high-impact checkpoint.

```sh
python3 "$scripts/case_handoff.py" . record-review gold \
  --kind session --reviewer "Independent validator" --verdict approve \
  --evidence evidence/review-note.md --summary "Checked the claims against primary evidence"
```

A subagent uses `--kind subagent`; a human uses `--kind human --reviewer-id ID`.
A signed-in Codex review defaults to that session's thread ID. Provide
`--model MODEL` if known. The gate rejects the author thread as a reviewer.
The receipt records identities and checked files and relies on the accuracy
of human attestations. Use `--verdict request-changes` when evidence is
insufficient. Once approved, keep the reviewed files unchanged while
marking the task complete or promoting gold. Changed outputs, claim inputs,
or review evidence require a current verdict. A fresh request is needed
when the review subject changed.

## Review a gold database update

Use `$binaryninja-gold-re` in Codex for the evidence and review workflow.
Define which names, signatures, local variables and comments are in scope.
Ask for an explicit list of unresolved items and the checks that support
the saved database. The apply script stages and reopens a candidate,
keeps a previous database for rollback, and records what was checked in a
manifest under `gold/manifests/`.

```sh
bnpython="/path/to/BinaryNinja/bnpython3"
"$bnpython" "$scripts/bn_apply_claims.py" . \
  --require-claim approved-signature --require-claim approved-local-name
```

Use IDs from the case's claim records. An independent gold receipt and all explicitly required claim verdicts must be current to promote. The manifest and coverage report explain what
was applied and what remains unresolved. The case manifest identifies
the expected sample or payload. A mismatched base database blocks promotion.
If the target changed, preserve the old database lanes and verify the new
target before rebuilding the base. See `reports/gold_readiness.json` for the
status of the latest apply.

If a gold update needs to be undone, use the previous database's actual
SHA-256 from the manifest. Review which version you're restoring first.

```sh
"$bnpython" "$scripts/bn_apply_claims.py" . --rollback "$previous_gold_sha256"
```

## Keep evidence and storage manageable

Save full tool output in the case. Put a short result and exact paths in the
checkpoint. Use findings to record conclusions you want to reuse, and use a
superseding finding when a conclusion changes. Keep stable evidence references
in the report so someone can inspect the underlying result without searching
your old conversation.

```sh
python3 "$scripts/case_handoff.py" . evidence evidence/review-note.md --limit 2048
python3 "$scripts/case_handoff.py" . record-finding report-claim-v1 \
  --summary "The report claim is supported by the local evidence" \
  --evidence evidence/review-note.md
python3 "$scripts/case_handoff.py" . record-finding report-claim-v2 \
  --summary "The evidence supports a narrower conclusion" \
  --evidence evidence/correction.md --supersedes report-claim-v1
python3 "$scripts/case_handoff.py" . findings
```

Use the excerpt's `next_offset` as `--offset` to read the next page. The
limit is applied to source bytes. Finding IDs are stable and the output
keeps the earlier conclusion in history. Link the current finding from
the canonical report.

```sh
python3 "$scripts/case_handoff.py" . inventory --limit 30
python3 "$scripts/case_handoff.py" . inventory --cases-dir "$HOME/re-cases" --limit 30
```

Inventory storage before proposing consolidation. An identical SHA-256
identifies identical bytes. A separate gold snapshot may have rollback value
even if it no longer appears in the current report. Review path references
and keep a record of any archive location. The inventory scans known case
metadata for references. Check free-form notes and external references before
acting on its archive candidates.

## Monitor the work

On this workstation, open [Workspace Monitor](http://127.0.0.1:8765) and
choose **Reverse engineering**. Search by the Codex thread ID or a distinctive
task title. The monitor groups case-directory Codex sessions alongside
standalone REHarness runs where present. Use the case checkpoint to find
the verified outputs and primary evidence.

## Run the harness checks

Run from the `codex-re-config` checkout. The case workflow tests create
temporary cases and cover intake, handoff, local hunt archives and recovery,
evidence, findings and storage. The frozen rule test uses the local YARA
engine if installed.

```sh
python3 -B -m unittest discover -s tests -p 'test_case_workflow.py' -v
```

Run the gold integration fixture with the Binary Ninja interpreter and a C
compiler installed. It compiles a benign ELF and loads it for analysis.

```sh
bnpython="/path/to/BinaryNinja/bnpython3"
PYTHONDONTWRITEBYTECODE=1 "$bnpython" -m unittest discover \
  -s tests -p 'test_gold_integration.py' -v
```

The [work log](WORK-LOG.md) records which tests were run and what they found.
