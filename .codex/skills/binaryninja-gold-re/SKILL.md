---
name: binaryninja-gold-re
description: Use this skill when Codex is asked to reverse engineer a PE or ELF binary, malware sample, implant, loader, unpacked payload, or native executable with Binary Ninja and produce a validated gold-standard BNDB. It creates a case workspace, performs static-only analysis, optionally uses malcat-triage as an initial lead generator, emits structured claims for function names/types/structures/comments/source-tree reconstruction, runs an adversarial validation pass, and applies only accepted claims to a final gold.bndb. Trigger on requests like "analyze this binary", "make a gold BNDB", "recover types/functions/source tree", or "reverse this PE/ELF"; never execute the sample.
---

# Binary Ninja Gold RE

## Operating Rule

Produce a gold BNDB by evidence-gated edits, not by direct speculation. The analyst may propose claims, but only accepted claims are applied to `gold.bndb`.

Do not execute the sample. Static Binary Ninja analysis is the source of truth. Malcat triage may be used first when available, but Malcat/YARA/capa/anomaly results are heuristic leads only.

## Default Workflow

1. Create a case workspace:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bngold_case.py" init /path/to/sample --cases-dir "$HOME/re-cases"
```

Intake checks the full SHA-256 against existing case manifests. If it finds
one match, use the returned path and its existing lineage. If intake reports
multiple matches, resolve references before consolidating any files.

Override the cases root with `--cases-dir` or the `BNGOLD_CASES_DIR` environment variable.

If the file you hand in is itself a payload rather than the delivered sample, record where it came from — otherwise the report attributes every finding to a file with no provenance:

```bash
... init /path/to/payload.bin --parent-sha256 <sha256 of delivered file> --parent-note "upx -d"
```

If you unpack inside the case, register the payload instead. This writes `sample/unpacked_NN.bin`, appends a lineage entry with parent hash, method and tool, and repoints `analysis_target` so every later step operates on the payload:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bngold_case.py" add-unpacked CASE_DIR /path/to/unpacked.bin \
  --method upx --tool "upx 4.2.4" --notes "single layer"
```

`bn_export_facts.py`, `elf_go_context.py` and `elf_go_type_layout.py` resolve `analysis_target` from `case.json`, so they follow the payload automatically. The report's Sample Lineage section states which file the gold BNDB describes.

2. Optionally run `$malcat-triage` against the original sample and save outputs in `triage/`.

3. Create base/analyst/validator BNDBs and export normalized facts:

```bash
/path/to/BinaryNinja/binaryninja/bnpython3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bn_export_facts.py" CASE_DIR
```

4. For ELF files, especially Go binaries, extract loader/compiler context:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/elf_go_context.py" CASE_DIR
```

This writes `evidence/file_info.txt`, `evidence/app_symbols.txt`, `evidence/go_context.json`, and, when DWARF line paths exist, `recovered_tree/source_tree.md`.

5. For Go ELF binaries with DWARF, extract application type-layout evidence before making struct/type claims:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/elf_go_type_layout.py" CASE_DIR
```

This writes `evidence/go_type_layouts.json` and `evidence/go_type_layouts.md`. Use these files to support `type_definition` claims with DIE offsets, byte sizes, member offsets, and member names. Do not claim field types or padding unless they are supported by DWARF, ABI layout, or Binary Ninja access evidence.

6. Analyze in `work/analyst.bndb`. Emit proposed edits into `claims/claims.jsonl`; do not write final claims directly into `gold/gold.bndb`.

7. Validate from clean evidence:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bngold_case.py" validate-claims CASE_DIR
```

Use a separate validator agent/session when possible. The validator must inspect `work/validator.bndb`, `evidence/bn_facts.json`, and `claims/claims.jsonl`, but not analyst notes or `work/analyst.bndb`.

8. Apply only accepted claims:

```bash
/path/to/BinaryNinja/binaryninja/bnpython3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bn_apply_claims.py" CASE_DIR
```

`bn_apply_claims.py` applies accepted `type_definition` claims first as one dependency-sorted batch, then applies function names, comments, data names, and source-file comments.

9. Generate a final report:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bngold_report.py" CASE_DIR
```

Report final state: accepted claims, rejected claims, `needs_human`, unresolved functions/types, and recovered source tree.

## Claim Rules

Every proposed edit must be a JSONL claim with:

```json
{"claim_id":"fn_401000_name","kind":"function_name","target":"0x401000","proposed_value":"mw_config_parse_c2_list","confidence":"high","evidence":["xref string config","calls fopen/fgets","writes config struct offsets"],"status":"proposed"}
```

Supported claim kinds:
- `function_name`: meaningful behavior name for a function address.
- `function_signature`: C function declaration, keyed by function address.
- `local_variable_name`: name keyed by a target object with `function` (address string) and `identifier` (numeric Binary Ninja variable ID from the analyzed function’s HLIL variable list).
- `address_comment`: evidence-backed note keyed by instruction address.
- `function_comment`: concise evidence-backed behavior note.
- `data_name`: semantic name for a data address or symbol.
- `type_definition`: C type/enum/struct declaration.
- `source_file`: recovered source-tree assignment for addresses or symbols.

`target` is always VA hex (`0x17F32A60`), never EA decimal.

## Naming

`snake_case`, and every renamed symbol carries the `mw_` prefix.

| Category | Pattern | Example |
|---|---|---|
| C2 | `mw_c2_<action>` | `mw_c2_send_beacon` |
| Persistence | `mw_persist_<method>` | `mw_persist_reg_run_key` |
| Evasion | `mw_evasion_<technique>` | `mw_evasion_check_debugger` |
| Credentials | `mw_cred_<target>` | `mw_cred_dump_lsass` |
| Crypto | `mw_crypto_<algo>` | `mw_crypto_xor_decrypt` |
| Collection | `mw_collect_<what>` | `mw_collect_screenshot` |
| Discovery | `mw_enum_<what>` | `mw_enum_processes` |
| Injection | `mw_inject_<method>` | `mw_inject_process_hollow` |
| Config | `mw_config_<action>` | `mw_config_parse_c2_list` |
| Utility | `mw_util_<purpose>` | `mw_util_resolve_api` |
| Strings | `mw_str_<action>` | `mw_str_deobfuscate` |
| Init | `mw_init_<what>` | `mw_init_comms` |

Variables: `mw_buf_<purpose>`, `mw_h_<target>`, `mw_<what>_size`. Data labels: `mw_encrypted_strings_blob`, `mw_c2_config_block`.

The prefix marks a symbol as analyst-supplied, so a glance at the symbol list separates recovered names from Binary Ninja's defaults and from real symbols the binary shipped with. Do not prefix names the binary already provided — an exported `main` or a DWARF-recovered Go symbol stays as it is.

**No `_likely` suffix.** Uncertainty lives in `claim.status` and the validator's `needs_human` verdict, not in the symbol name. A name is either supported by evidence and applied, or it is not applied — hedging in the identifier means every downstream reader inherits the doubt without the reasoning.

Avoid vague names like `handle_data`, `process_buffer`, `do_work`, or names copied from heuristics without code evidence.

## Validation Model

The validator must attack each claim before accepting it:
- Ask whether the evidence supports the exact name/type/comment, not just a related idea.
- Reject claims backed only by Malcat, YARA, capa, VirusTotal, MalwareBazaar, OTX, public-report text, or analyst intuition. `validate-claims` now enforces the all-lead-only case in code and fails the run; you still have to catch the mixed case, where one real code observation is padding for a heuristic hunch.
- Mark `needs_human` when two plausible interpretations have equal evidence.
- Require type claims to cite offset/size/access evidence, allocation size, ABI/API signatures, or consistent data-flow.
- Require function names to cite local code behavior: strings, imports, constants, xrefs, call graph position, data-flow, and side effects.
- Check the proposed name follows the `mw_` taxonomy and carries no `_likely` suffix. Check it says what the evidence says: `mw_c2_send_beacon` needs evidence of beaconing — periodicity, a check-in payload, a C2 endpoint — not merely that the function sends bytes. If the evidence supports `mw_c2_send_data`, reject and say so.
- Require source-tree claims to cite clusters: call relationships, shared state/types, common API families, or protocol boundaries.

Validator outputs go to `claims/verdicts.jsonl` with status `accepted`, `rejected`, or `needs_human`.

## Workspace Contract

Use this layout:

```text
CASE_DIR/
  sample/original.bin
  sample/unpacked_NN.bin        when unpacking occurred in-case
  case.json
  binja/base.bndb
  work/analyst.bndb
  work/validator.bndb
  gold/gold.bndb
  evidence/bn_facts.json
  claims/claims.jsonl
  claims/verdicts.jsonl
  reports/final.md
  recovered_tree/
  triage/
```

Do not use unrelated project directories as fixtures or prior art unless the user explicitly names them.

## PE and ELF Coverage

For PE, prioritize imports/exports, resources, TLS callbacks, service/registry/network/crypto/process APIs, packer artifacts, overlay, and suspicious section permissions.

For ELF, prioritize dynamic symbols, PLT/GOT usage, init/fini arrays, interpreter/RPATH/RUNPATH, libc/OpenSSL/curl/pthread/syscall usage, embedded paths, stripped symbols, and unusual segment permissions.

Normalize evidence so the claim/validation logic is shared across PE and ELF.

## Go ELF Handling

When `file` or Binary Ninja indicates a Go binary:
- Treat DWARF line paths and Go symbols as primary evidence for source-tree recovery.
- Separate application package symbols from Go runtime, standard library, and third-party dependency symbols before choosing review targets.
- Prefer claims on application-owned packages first; do not curate the Go runtime unless the user asks.
- Use `evidence/app_symbols.txt` and `evidence/go_context.json` to identify app entry points, package clusters, build metadata, and source paths.
- Use `evidence/go_type_layouts.json` and `evidence/go_type_layouts.md` for DWARF-backed struct layout evidence.
- For statically linked Go binaries, expect very large function counts. Focus claims on package clusters, command handlers, protocol handlers, config/build metadata, network/client setup, persistence/service logic, and crypto/compression routines.
- Do not claim full struct layout recovery just because DWARF type names exist. Field-offset claims need `elf_go_type_layout.py` output or equivalent offset/access evidence plus validator acceptance.

The apply command builds and reopens a candidate before replacing gold.
It retains the previous database at `gold/previous.bndb` and records the
base digest, gold digest, applied claim IDs and verification in a manifest
under `gold/manifests/`.

## Local case handoff

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

## Resume Existing Case Work

For session context, start with a short summary of the current result,
evidence IDs or bounded excerpts. Save full decompiler exports and tool
results to case files and reference their paths when needed.

Start in the case root returned by intake. Use
`scripts/case_handoff.py CASE_DIR start-task TASK_ID` to read the case map
and existing checkpoint together. For a new task, supply `--scope`,
`--deliverable`, and `--done-when`. New cases have an index from intake.
For legacy cases without one, the command returns the standard paths.

For hunt follow-ups, use `lookup SHA256` to find prior assessments and
job IDs. Update the checkpoint with `record-task` after meaningful
progress and at handoff. Include the Codex session ID, scope, output paths,
evidence references, open questions and next action. See the repository
README for command examples.

## Output Standard

The final answer must report:
- path to `gold/gold.bndb`
- counts of accepted/rejected/needs-human claims
- high-value recovered function/type/source-tree highlights
- unresolved areas and why they remain unresolved
- tests or script checks run

Never claim “every type/function is resolved” unless the unresolved list is empty and the validator accepted the relevant claims.
