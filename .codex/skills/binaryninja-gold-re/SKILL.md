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
{"claim_id":"fn_401000_name","kind":"function_name","target":"0x401000","proposed_value":"parse_config_file","confidence":"high","evidence":["xref string config","calls fopen/fgets","writes config struct offsets"],"status":"proposed"}
```

Supported claim kinds:
- `function_name`: meaningful behavior name for a function address.
- `function_comment`: concise evidence-backed behavior note.
- `data_name`: semantic name for a data address or symbol.
- `type_definition`: C type/enum/struct declaration.
- `source_file`: recovered source-tree assignment for addresses or symbols.

Use names like `parse_config_file`, `decrypt_network_packet`, `build_http_request`, `load_persistence_config`. Avoid vague names like `handle_data`, `process_buffer`, `do_work`, or names copied from heuristics without code evidence.

## Validation Model

The validator must attack each claim before accepting it:
- Ask whether the evidence supports the exact name/type/comment, not just a related idea.
- Reject claims backed only by Malcat, YARA, capa, public-report text, or analyst intuition.
- Mark `needs_human` when two plausible interpretations have equal evidence.
- Require type claims to cite offset/size/access evidence, allocation size, ABI/API signatures, or consistent data-flow.
- Require function names to cite local code behavior: strings, imports, constants, xrefs, call graph position, data-flow, and side effects.
- Require source-tree claims to cite clusters: call relationships, shared state/types, common API families, or protocol boundaries.

Validator outputs go to `claims/verdicts.jsonl` with status `accepted`, `rejected`, or `needs_human`.

## Workspace Contract

Use this layout:

```text
CASE_DIR/
  sample/original.bin
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

## Output Standard

The final answer must report:
- path to `gold/gold.bndb`
- counts of accepted/rejected/needs-human claims
- high-value recovered function/type/source-tree highlights
- unresolved areas and why they remain unresolved
- tests or script checks run

Never claim “every type/function is resolved” unless the unresolved list is empty and the validator accepted the relevant claims.
