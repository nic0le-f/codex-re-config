# Case handoff, hunts, and findings

## Checkpoints are part of case work

For requested analysis or changes to case artifacts, Codex creates or resumes
a task and saves the checkpoint without waiting for a separate user request.
A question answered from existing records can stay read-only. A helper called
by a broader workflow should return its artifacts to the owning task.

Use the current case when it owns the input. For a new sample, use the case
root from intake. Run `case_handoff.py CASE_DIR start-task TASK_ID` to read the
case map and checkpoint. Reuse the task ID for the same deliverable. For a
new task, supply `--scope`, `--deliverable`, `--done-when`, and the applicable
`--task-type`. Legacy cases use standard paths when the index is absent.

Run `record-task` at meaningful progress points and before returning. Record
the session ID, scope, status, output paths, verified evidence, open questions,
and next action. Use `in-progress` if work remains and `blocked` if a prerequisite
prevents completion. If the session ID cannot be determined, pass
`--session-id unavailable` so the checkpoint can still be saved. The user
manual has full command examples.

## Hunt and evidence follow-ups

Use `lookup SHA256` before repeating analysis.

Use `case_handoff.py CASE register-hunt` to archive an exported hunt job
and link its hits to local candidate records. The command reports existing
assessments. Keep the rule used and hit list as captured by the service.
For known benign fixtures, `validate-rule` compiles and checks that frozen
rule version against local positive and negative controls.

The fact exporters put detailed results on disk. Use
`case_handoff.py CASE evidence PATH --offset BYTE --limit BYTES` for
targeted excerpts. Link a verified conclusion to case evidence with
`record-finding`. Use a new finding ID and `--supersedes` to correct it.
The final report links to the current findings.

Use `start-task --task-type family-attribution` or `--task-type material-report-correction` for these high-impact deliverables. Save outputs in an in-progress checkpoint, request review under the task ID, and complete the task once the independent approval matches the saved outputs. For a `gold-bndb` task, use the case-level gold approval for promotion and completion.


## Case paths

The case root contains `case.json`, the index and checkpoints, and the
following analysis paths:

| Location | Purpose |
|---|---|
| `sample/original.bin` | Delivered input |
| `binja/base.bndb` | Base analysis |
| `work/analyst.bndb`, `work/validator.bndb` | Separate analysis lanes |
| `evidence/bn_facts.json` | Binary Ninja evidence |
| `claims/claims.jsonl`, `claims/verdicts.jsonl` | Proposals and decisions |
| `reviews/gold.json`, `gold/manifests/` | Approval and promotion records |
| `gold/gold.bndb`, `reports/final.md` | Gold database and final report |
| `triage/`, `recovered_tree/` | Triage and source-tree outputs when available |
