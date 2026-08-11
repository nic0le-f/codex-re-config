---
name: malcat-triage
description: Use this skill for initial static triage of suspicious binaries, malware samples, PE files, ELF files, packed files, shellcode, archives, embedded files, or reverse-engineering targets with Malcat. It runs Malcat headless reports and optional JSON extraction to surface YARA/capa-style detections, anomalies, packer hints, strings, sections/regions, symbols, carved files, and triage leads before deeper Binary Ninja reversing. Use this as a lead generator only; do not treat Malcat, YARA, capa, or anomaly labels as final proof for gold BNDB names or types.
metadata:
  short-description: Initial Malcat triage for PE/ELF samples
---

# Malcat Triage

## Purpose

Use Malcat for fast static triage before deep reversing. This skill produces leads: format, architecture, sections/regions, entropy anomalies, YARA/signature hits, capa-style capabilities when available, imports/symbols, strings, carved/virtual files, and packer/container hints.

Malcat output is heuristic evidence. It may prioritize Binary Ninja analysis, but it must not be the sole basis for final function names, types, structures, or gold BNDB edits.

## Default Workflow

1. Confirm the target path is a local file and do not execute it.
2. Run headless Malcat triage:

```bash
python3 "$HOME/.codex/skills/malcat-triage/scripts/malcat_triage.py" /path/to/sample --out /tmp/malcat-triage
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
