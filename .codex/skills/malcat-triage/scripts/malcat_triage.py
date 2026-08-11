#!/usr/bin/env python3
"""Headless Malcat triage wrapper.

Produces a compact JSON summary and a Malcat text report. The sample is never
executed; this uses Malcat's static analysis bindings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MALCAT_ROOTS = [
    Path.home() / "Applications" / "malcat_ubuntu25_pro_v0_9_14",
    Path.home() / "share" / "malcat_ubuntu25_pro_v0_9_14",
]


def find_malcat_root() -> Path:
    for root in MALCAT_ROOTS:
        if (root / "bin" / "malcat.report.py").exists():
            return root
    raise FileNotFoundError("Malcat install not found in expected locations")


def add_malcat_to_path(root: Path) -> None:
    sys.path.insert(0, str(root / "bin"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stringify(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return repr(value)


def safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def collect_metadata(analysis: Any) -> dict[str, Any]:
    items: dict[str, Any] = {}
    metadata = getattr(analysis, "metadata", None)
    if isinstance(metadata, dict):
        for key, value in metadata.items():
            items[stringify(key)] = stringify(value)
    elif metadata:
        try:
            for category, values in metadata:
                if isinstance(values, dict):
                    for key, value in values.items():
                        items[f"{category}.{key}"] = stringify(value)
                else:
                    items[stringify(category)] = stringify(values)
        except Exception:
            items["raw"] = stringify(metadata)
    return items


def collect_regions(analysis: Any) -> list[dict[str, Any]]:
    regions = []
    amap = getattr(analysis, "map", None)
    if amap is None:
        return regions
    for region in list(amap):
        regions.append(
            {
                "name": getattr(region, "name", ""),
                "physical_offset": safe_int(getattr(region, "phys", None)),
                "physical_size": safe_int(getattr(region, "phys_size", None)),
                "virtual_address": safe_int(getattr(region, "virt", None)),
                "virtual_size": safe_int(getattr(region, "virt_size", None)),
                "read": bool(getattr(region, "read", False)),
                "write": bool(getattr(region, "write", False)),
                "execute": bool(getattr(region, "exec", False)),
            }
        )
    return regions


def collect_signatures(analysis: Any, limit: int) -> list[dict[str, Any]]:
    signatures = []
    sigs = getattr(analysis, "sigs", None)
    if sigs is None:
        return signatures
    for sig in list(sigs)[:limit]:
        matches = []
        for pattern in list(getattr(sig, "patterns", []))[:20]:
            for offset, size in list(getattr(pattern, "matches", []))[:20]:
                matches.append(
                    {
                        "pattern": getattr(pattern, "id", ""),
                        "offset": safe_int(offset),
                        "size": safe_int(size),
                    }
                )
        signatures.append(
            {
                "name": getattr(sig, "name", ""),
                "id": getattr(sig, "id", ""),
                "type": stringify(getattr(sig, "type", "")),
                "namespace": getattr(sig, "namespace", ""),
                "matches": matches,
            }
        )
    return signatures


def collect_strings(analysis: Any, limit: int) -> list[dict[str, Any]]:
    strings = []
    for item in list(getattr(analysis, "strings", []))[:limit]:
        strings.append(
            {
                "text": getattr(item, "text", ""),
                "address": safe_int(getattr(item, "address", None)),
                "type": stringify(getattr(item, "type", "")),
                "encoding": stringify(getattr(item, "encoding", "")),
                "tag": stringify(getattr(item, "tag", "")),
                "score": safe_int(getattr(item, "score", None)),
                "entropy": safe_int(getattr(item, "entropy", None)),
            }
        )
    return strings


def collect_symbols(analysis: Any, limit: int) -> list[dict[str, Any]]:
    symbols = []
    syms = getattr(analysis, "syms", None)
    amap = getattr(analysis, "map", None)
    if syms is None or amap is None:
        return symbols
    try:
        iterator = syms[0 : len(amap)]
    except Exception:
        return symbols
    for sym in list(iterator)[:limit]:
        symbols.append(
            {
                "name": getattr(sym, "name", ""),
                "type": stringify(getattr(sym, "type", "")),
                "address": safe_int(getattr(sym, "address", None)),
            }
        )
    return symbols


def collect_carved(analysis: Any, limit: int) -> list[dict[str, Any]]:
    rows = []
    for collection_name in ("carved", "vfiles"):
        collection = getattr(analysis, collection_name, None)
        if collection is None:
            continue
        try:
            items = list(collection)
        except Exception:
            continue
        for item in items[:limit]:
            rows.append(
                {
                    "source": collection_name,
                    "name": getattr(item, "name", getattr(item, "path", "")),
                    "path": getattr(item, "path", ""),
                    "type": stringify(getattr(item, "type", "")),
                    "category": stringify(getattr(item, "category", "")),
                    "address": safe_int(getattr(item, "address", None)),
                    "size": safe_int(getattr(item, "size", None)),
                }
            )
    return rows[:limit]


def run_report(root: Path, sample: Path, out_dir: Path, recursive: bool) -> Path:
    report_path = out_dir / "malcat_report.txt"
    cmd = [str(root / "bin" / "malcat.report.py")]
    if recursive:
        cmd.append("-r")
    cmd.append(str(sample))
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    report_path.write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        raise RuntimeError(f"malcat.report.py failed with exit code {proc.returncode}")
    return report_path


def analyse_sample(sample: Path, args: argparse.Namespace) -> dict[str, Any]:
    root = find_malcat_root()
    add_malcat_to_path(root)
    import malcat  # type: ignore

    analysis = malcat.analyse(
        str(sample),
        options={"num_threads": args.threads},
        use_file_mapping=sample.stat().st_size > 256 * 1024 * 1024,
    )
    analysis.raise_if_failed()

    return {
        "tool": "malcat",
        "tool_role": "initial_triage_external_heuristic",
        "sample": {
            "path": str(sample),
            "size": sample.stat().st_size,
            "sha256": sha256_file(sample),
        },
        "analysis": {
            "type": stringify(getattr(analysis, "type", "")),
            "format": stringify(getattr(analysis, "type", "")),
            "architecture": stringify(getattr(analysis, "architecture", "")),
            "metadata": collect_metadata(analysis),
        },
        "regions": collect_regions(analysis),
        "signatures": collect_signatures(analysis, args.signature_limit),
        "strings": collect_strings(analysis, args.string_limit),
        "symbols": collect_symbols(analysis, args.symbol_limit),
        "carved_files": collect_carved(analysis, args.carved_limit),
        "evidence_policy": "Use as triage leads only; validate final claims in Binary Ninja.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run static Malcat triage and emit JSON.")
    parser.add_argument("sample", help="Path to PE, ELF, shellcode, archive, or other sample")
    parser.add_argument("--out", default=".", help="Output directory")
    parser.add_argument("--threads", type=int, default=0)
    parser.add_argument("--recursive-report", action="store_true")
    parser.add_argument("--string-limit", type=int, default=200)
    parser.add_argument("--symbol-limit", type=int, default=200)
    parser.add_argument("--signature-limit", type=int, default=200)
    parser.add_argument("--carved-limit", type=int, default=100)
    args = parser.parse_args()

    sample = Path(args.sample).expanduser().resolve()
    if not sample.exists():
        raise FileNotFoundError(sample)
    if not stat.S_ISREG(sample.stat().st_mode):
        raise ValueError(f"not a regular file: {sample}")

    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    triage = analyse_sample(sample, args)
    json_path = out_dir / "malcat_triage.json"
    json_path.write_text(json.dumps(triage, indent=2, sort_keys=True), encoding="utf-8")

    root = find_malcat_root()
    report_path = run_report(root, sample, out_dir, args.recursive_report)

    print(json.dumps({"json": str(json_path), "report": str(report_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
