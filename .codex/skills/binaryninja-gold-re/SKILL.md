---
name: binaryninja-gold-re
description: Use for static Binary Ninja analysis of PE or ELF binaries when the deliverable is a validated gold BNDB or evidence-backed recovery of functions, types, or source structure. Covers case intake, claims, independent validation, and gold promotion.
---

# Binary Ninja Gold RE

Use static Binary Ninja evidence. Never execute the sample. Malcat, YARA, capa, anomaly labels, and public reports can guide review. Accepted claims require primary evidence. Use only case files and resources relevant to the task.

## Workflow

Set `scripts` to this skill’s `scripts/` directory, `case_dir` to the case root,
and `bnpython` to the installed Binary Ninja interpreter.

1. **Open the case.** Run `python3 "$scripts/bngold_case.py" init "$sample"`.
   Work from the returned directory under `~/re-cases` by default. Intake
   reuses one full-SHA-256 match. If it finds multiple matches, review their
   references before consolidation. Read [sample lineage](references/sample-lineage.md)
   for payloads or alternate case roots. Follow [case handoff](references/case-handoff.md)
   to start or resume the task before analysis and save its checkpoint before replying.
2. **Prepare evidence.** Reuse relevant outputs under `triage/` from
   `static-malware-triage`. Collect optional Malcat leads when needed. Run
   `"$bnpython" "$scripts/bn_export_facts.py" "$case_dir"` to prepare the base
   and separate analyst and validator databases. Read [binary formats](references/binary-formats.md)
   when selecting PE or ELF evidence or using Go and DWARF tools.
3. **Propose and validate claims.** Work in `work/analyst.bndb`. Save proposed
   edits in `claims/claims.jsonl` and verdicts in `claims/verdicts.jsonl`.
   Read [claims and validation](references/claims-and-validation.md) for
   the schema, naming rules, and evidence rubric. Have the independent
   validator inspect `work/validator.bndb`, `evidence/bn_facts.json`, and
   the proposed claims. Keep analyst notes and the analyst database outside
   blind review. Use `needs_human` when the evidence cannot resolve competing
   interpretations. Run `python3 "$scripts/bngold_case.py" validate-claims "$case_dir"`.
4. **Request and record independent approval.** The author freezes the base,
   claims, and verdicts:

   ```sh
   python3 "$scripts/case_handoff.py" "$case_dir" request-review gold
   ```

   A distinct validator records the verdict and primary evidence checked.
   This example uses a separate Codex session, which supplies its thread ID.
   A subagent uses `--kind subagent`. A human uses `--kind human --reviewer-id ID`.
   Include `--model MODEL` if known. Use `--verdict request-changes` when the
   evidence is insufficient. If approval is unavailable, keep the work
   pending. Re-review changed inputs or evidence before promotion.

   ```sh
   python3 "$scripts/case_handoff.py" "$case_dir" record-review gold \
     --kind session --reviewer "Independent validator" --verdict approve \
     --evidence evidence/review-note.md --summary "Checked claims against primary evidence"
   ```

5. **Promote after approval.** Apply accepted claims:

   ```sh
   "$bnpython" "$scripts/bn_apply_claims.py" "$case_dir"
   ```

   The script reopens and verifies the candidate before replacing gold. It
   records the result in `gold/manifests/` and retains the previous database
   at `gold/previous.bndb`.
6. **Report and checkpoint.** Run `python3 "$scripts/bngold_report.py" "$case_dir"`.
   Return the `gold/gold.bndb` path when promoted, or the blocker if pending.
   Report accepted, rejected and unresolved claim counts, supported
   function/type/source-tree highlights, remaining unknowns, and checks
   performed within the reviewed scope. Save full results in the case and
   use bounded excerpts in session context. Save a checkpoint even if review
   or another dependency blocks completion.
