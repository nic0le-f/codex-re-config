# PE and ELF coverage

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

## ELF and Go tools

For ELF files, especially Go binaries, extract loader/compiler context:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/elf_go_context.py" CASE_DIR
```

This writes `evidence/file_info.txt`, `evidence/app_symbols.txt`, `evidence/go_context.json`, and, when DWARF line paths exist, `recovered_tree/source_tree.md`.

For Go ELF binaries with DWARF, extract application type-layout evidence before making struct/type claims:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/elf_go_type_layout.py" CASE_DIR
```

This writes `evidence/go_type_layouts.json` and `evidence/go_type_layouts.md`. Use these files to support `type_definition` claims with DIE offsets, byte sizes, member offsets, and member names. Do not claim field types or padding unless they are supported by DWARF, ABI layout, or Binary Ninja access evidence.
