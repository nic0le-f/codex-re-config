# Case handoff, hunts, and findings

Start in the case root returned by intake. Use `scripts/case_handoff.py CASE_DIR start-task TASK_ID` to read the case map and checkpoint together. Supply `--scope`, `--deliverable`, and `--done-when` for a new task. Legacy cases use standard paths when the index is absent.

Use `lookup SHA256` before repeating analysis. Update the checkpoint with `record-task` at meaningful progress points and handoff. Include the session ID, scope, output paths, evidence references, open questions, and next action. The repository user manual has full command examples.

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
