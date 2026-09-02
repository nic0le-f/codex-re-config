#!/usr/bin/env bnpython3
"""Create BNDB lanes and export normalized Binary Ninja facts for PE/ELF RE."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import binaryninja as bn


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def save_database(bv: bn.BinaryView, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not bv.create_database(str(path)):
        raise RuntimeError(f"failed to save BNDB: {path}")


def symbol_rows(symbols: list[Any], limit: int = 10000) -> list[dict[str, Any]]:
    rows = []
    for sym in symbols[:limit]:
        rows.append({"name": sym.name, "address": hex(sym.address), "type": str(sym.type)})
    return rows


def analysis_target(case_dir: Path) -> Path:
    """The file the gold BNDB describes — the unpacked payload once one is registered."""
    case_path = case_dir / "case.json"
    rel = "sample/original.bin"
    if case_path.exists():
        case = json.loads(case_path.read_text(encoding="utf-8"))
        rel = case.get("analysis_target") or rel
    target = case_dir / rel
    if not target.exists():
        raise FileNotFoundError(f"analysis target missing: {target}")
    return target


def export_facts(case_dir: Path) -> dict[str, Any]:
    sample = analysis_target(case_dir)
    base_bndb = case_dir / "binja" / "base.bndb"
    analyst_bndb = case_dir / "work" / "analyst.bndb"
    validator_bndb = case_dir / "work" / "validator.bndb"

    print(f"[bngold] loading {base_bndb if base_bndb.exists() else sample}", flush=True)
    bv = bn.load(str(base_bndb if base_bndb.exists() else sample))
    if bv is None:
        raise RuntimeError(f"failed to load {sample}")
    print("[bngold] running Binary Ninja analysis", flush=True)
    bv.update_analysis_and_wait()
    print(f"[bngold] saving base BNDB: {base_bndb}", flush=True)
    save_database(bv, base_bndb)
    print("[bngold] creating analyst and validator BNDB lanes", flush=True)
    shutil.copy2(base_bndb, analyst_bndb)
    shutil.copy2(base_bndb, validator_bndb)

    print("[bngold] exporting strings", flush=True)
    strings = []
    for s in bv.strings[:10000]:
        strings.append({"address": hex(s.start), "length": s.length, "value": str(s.value)})

    print("[bngold] exporting functions and call graph", flush=True)
    functions = []
    for func in bv.functions:
        callees = sorted({hex(callee.start) for callee in func.callees})
        callers = sorted({hex(caller.start) for caller in func.callers})
        refs = []
        for ref in bv.get_code_refs(func.start):
            refs.append({"function": hex(ref.function.start), "address": hex(ref.address)})
        functions.append(
            {
                "address": hex(func.start),
                "name": func.name,
                "symbol_type": str(func.symbol.type) if func.symbol else "",
                "confidence": str(func.analysis_skipped) if hasattr(func, "analysis_skipped") else "",
                "callees": callees,
                "callers": callers,
                "code_refs": refs[:100],
                "basic_blocks": len(list(func.basic_blocks)),
            }
        )

    print("[bngold] exporting sections and symbols", flush=True)
    sections = []
    for name, section in bv.sections.items():
        sections.append(
            {
                "name": name,
                "start": hex(section.start),
                "end": hex(section.end),
                "length": section.length,
                "semantics": str(section.semantics),
            }
        )

    facts = {
        "sample": {
            "path": str(sample),
            "relative_path": str(sample.relative_to(case_dir)),
            "sha256": sha256_file(sample),
            "size": sample.stat().st_size,
        },
        "binary_view": {
            "view_type": bv.view_type,
            "platform": str(bv.platform) if bv.platform else "",
            "arch": str(bv.arch) if bv.arch else "",
            "entry_point": hex(bv.entry_point) if bv.entry_point else "",
            "start": hex(bv.start),
            "end": hex(bv.end),
        },
        "sections": sections,
        "imports": symbol_rows(list(bv.get_symbols_of_type(bn.SymbolType.ImportedFunctionSymbol))),
        "exports": symbol_rows(list(bv.get_symbols_of_type(bn.SymbolType.FunctionSymbol))),
        "data_symbols": symbol_rows(list(bv.get_symbols_of_type(bn.SymbolType.DataSymbol))),
        "strings": strings,
        "functions": functions,
        "evidence_policy": "Binary Ninja static facts. Use these as primary evidence for claims.",
    }
    return facts


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 1:
        print(f"usage: {sys.argv[0]} CASE_DIR", file=sys.stderr)
        return 2
    case_dir = Path(argv[0]).expanduser().resolve()
    facts = export_facts(case_dir)
    out = case_dir / "evidence" / "bn_facts.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
