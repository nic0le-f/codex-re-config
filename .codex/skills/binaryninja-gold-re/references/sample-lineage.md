# Sample lineage

Override the cases root with `--cases-dir` or the `BNGOLD_CASES_DIR` environment variable.

If the file you hand in is itself a payload rather than the delivered sample, record where it came from — otherwise the report attributes every finding to a file with no provenance:

```bash
python3 "$scripts/bngold_case.py" init "$payload" \
  --parent-sha256 "$parent_sha256" --parent-note "$parent_note"
```

If you unpack inside the case, register the payload instead. This writes `sample/unpacked_NN.bin`, appends a lineage entry with parent hash, method and tool, and repoints `analysis_target` so every later step operates on the payload:

```bash
python3 "$HOME/.codex/skills/binaryninja-gold-re/scripts/bngold_case.py" add-unpacked CASE_DIR /path/to/unpacked.bin \
  --method upx --tool "upx 4.2.4" --notes "single layer"
```

`bn_export_facts.py`, `elf_go_context.py` and `elf_go_type_layout.py` resolve `analysis_target` from `case.json`, so they follow the payload automatically. The report's Sample Lineage section states which file the gold BNDB describes.
