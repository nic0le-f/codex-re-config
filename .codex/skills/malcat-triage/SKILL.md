---
name: malcat-triage
description: Collect Malcat-specific static evidence for a local file when requested or when quick triage or gold RE needs Malcat leads. Use static-malware-triage for a first-pass verdict. Treat Malcat findings as leads that require independent evidence.
metadata:
  short-description: Initial Malcat triage for PE/ELF samples
---

# Malcat Triage

## Purpose

Use Malcat for fast static triage before deep reversing. This skill produces leads: format, architecture, sections/regions, entropy anomalies, YARA/signature hits, capa-style capabilities when available, imports/symbols, strings, carved/virtual files, and packer/container hints.

Malcat output is heuristic evidence. It may prioritize Binary Ninja analysis, but it must not be the sole basis for final function names, types, structures, or gold BNDB edits.

## Default Workflow

For a direct case task, follow [case handoff](../binaryninja-gold-re/references/case-handoff.md)
to start or resume a `triage` task and save its checkpoint before replying.
When another skill calls Malcat as a helper, return evidence paths to the
owning task. For case work, put the Malcat outputs beneath the case's `triage/`.

1. Confirm the target path is a local file and do not execute it.
2. Run headless Malcat triage:

```bash
python3 "$HOME/.codex/skills/malcat-triage/scripts/malcat_triage.py" "$sample" --out "triage/$task_id/malcat"
```

3. If the helper fails, fall back to Malcat's bundled report script:

```bash
/path/to/malcat/bin/malcat.report.py /path/to/sample
```

Use `-r` with `malcat.report.py` when nested/carved/virtual files matter.

4. Summarize triage as:
   - file identity: hashes, size, format, arch, OS/platform
   - initial risk hints: packer, high entropy, overlays, malformed headers, suspicious regions
   - capability leads: network, crypto, process injection, persistence, anti-analysis, file/registry/process activity
   - useful anchors: strings, imports/symbols, resources, carved files, entrypoints
   - next Binary Ninja targets: functions/import clusters/strings to inspect first

## Evidence Policy

- Treat YARA, capa, Kesakode, and anomaly results as `external_heuristic`.
- A heuristic can create a lead or priority, not a final conclusion.
- For gold BNDB work, require local Binary Ninja evidence: code flow, xrefs, constants, imports, data refs, call signatures, field-offset usage, or decompiler evidence.
- If Malcat and Binary Ninja disagree, preserve both facts and investigate; do not force them to agree.
- Never execute the sample as part of this skill.

## PE and ELF Guidance

For PE files, look for:
- imports/exports, resources, TLS callbacks, overlay, .NET/native distinction
- service, registry, WinHTTP/WinINet, Winsock, CryptoAPI/BCrypt, process-injection APIs
- packer/unpacker indicators, malformed section layout, suspicious writable+executable regions

For ELF files, look for:
- dynamic symbols, PLT/GOT imports, init/fini arrays, interpreter, RPATH/RUNPATH
- libc/OpenSSL/curl/pthread/syscall usage, embedded paths, config names, IPC/network strings
- stripped symbols, packed sections, abnormal segment permissions, high-entropy payload regions

## Output Contract

When used inside a larger reverse-engineering harness, write or return:

```text
malcat_triage.json
malcat_report.txt
```

`malcat_triage.json` is machine-readable and suitable for an evidence store. `malcat_report.txt` is human-readable context.

Final user-facing summaries must clearly separate:
- **Observed facts** from Malcat parsing.
- **Heuristic detections** from signatures/capa/anomalies.
- **Recommended BN follow-up** that still needs proof.
