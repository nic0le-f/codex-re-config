#!/usr/bin/env python3
"""Extract ELF/Go context for Binary Ninja gold RE cases.

This script is static-only. It uses file/readelf outputs to recover Go build
context, application symbols, and DWARF source paths that are useful for claims.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


STD_PREFIXES = (
    "archive/",
    "bufio.",
    "bytes.",
    "compress/",
    "container/",
    "context.",
    "crypto/",
    "database/",
    "debug/",
    "embed.",
    "encoding/",
    "errors.",
    "flag.",
    "fmt.",
    "go/",
    "hash/",
    "html/",
    "image/",
    "internal/",
    "io.",
    "io/",
    "log.",
    "log/",
    "math.",
    "math/",
    "mime/",
    "net.",
    "net/",
    "os.",
    "os/",
    "path.",
    "path/",
    "reflect.",
    "regexp.",
    "runtime.",
    "runtime/",
    "slices.",
    "sort.",
    "strconv.",
    "strings.",
    "sync.",
    "sync/",
    "syscall.",
    "testing/",
    "text/",
    "time.",
    "unicode/",
    "unsafe.",
)

NOISY_ROOTS = {
    "vendor",
    "text",
    "github.com",
    "golang.org",
    "gopkg.in",
    "google.golang.org",
    "crypto",
    "internal",
    "net",
    "runtime",
}


def run_tool(cmd: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return 127, f"missing tool: {cmd[0]}"
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") + (exc.stderr or "")
        return 124, output + f"\nTIMEOUT after {timeout}s"
    return proc.returncode, proc.stdout + proc.stderr


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_symbols(text: str) -> list[dict[str, Any]]:
    rows = []
    sym_re = re.compile(
        r"^\s*(?P<num>\d+):\s+(?P<value>[0-9a-fA-F]+)\s+(?P<size>\d+)\s+"
        r"(?P<type>\S+)\s+(?P<bind>\S+)\s+(?P<vis>\S+)\s+(?P<ndx>\S+)\s+(?P<name>.+?)\s*$"
    )
    for line in text.splitlines():
        match = sym_re.match(line)
        if not match:
            continue
        name = match.group("name").strip()
        if not name:
            continue
        rows.append(
            {
                "address": "0x" + match.group("value").lower(),
                "size": int(match.group("size")),
                "type": match.group("type"),
                "bind": match.group("bind"),
                "section": match.group("ndx"),
                "name": name,
            }
        )
    return rows


def is_go_runtime_or_dependency(name: str, app_roots: set[str]) -> bool:
    if name.startswith(STD_PREFIXES):
        return True
    if name.startswith("type:") or name.startswith("go:") or name.startswith("runtime."):
        return True
    if "/" in name:
        first = name.split("/", 1)[0]
        return first not in app_roots
    return False


def infer_app_roots(symbols: list[dict[str, Any]], paths: list[str]) -> set[str]:
    project_roots: Counter[str] = Counter()
    for path in paths:
        match = re.search(r"/(?:code|workspace|work|projects?)/([^/]+)/", path, re.IGNORECASE)
        if match:
            candidate = match.group(1)
            if candidate not in NOISY_ROOTS and not candidate.startswith("."):
                project_roots[candidate] += 1
    if project_roots:
        best_count = project_roots.most_common(1)[0][1]
        return {
            root for root, count in project_roots.items()
            if count >= max(2, best_count // 2)
        }

    counts: Counter[str] = Counter()
    for path in paths:
        parts = [part for part in Path(path).parts if part and part != os.sep]
        for marker in ("code", "src", "workspace", "work"):
            if marker in parts:
                index = parts.index(marker)
                if index + 1 < len(parts):
                    candidate = parts[index + 1]
                    if candidate not in NOISY_ROOTS and not candidate.startswith("."):
                        counts[candidate] += 50
    for sym in symbols:
        name = sym["name"]
        if "/" not in name:
            continue
        first = name.split("/", 1)[0]
        if first and first not in NOISY_ROOTS and not name.startswith(STD_PREFIXES) and "." not in first:
            counts[first] += 1
    if not counts:
        return set()
    best_root, best_count = counts.most_common(1)[0]
    return {best_root} | {
        root for root, count in counts.items()
        if root not in NOISY_ROOTS and count >= max(25, best_count // 2)
    }


def extract_go_paths(decoded_line_text: str) -> list[str]:
    paths = set()
    for match in re.finditer(r"(/[^\s:]+?\.go)\b", decoded_line_text):
        paths.add(match.group(1))
    return sorted(paths)


def common_module_root(paths: list[str], app_roots: set[str]) -> str:
    for root in sorted(app_roots, key=len, reverse=True):
        marker = f"/{root}/"
        for path in paths:
            if marker in path:
                return path.split(marker, 1)[0] + marker.rstrip("/")
    if not paths:
        return ""
    common = os.path.commonpath(paths)
    while common and not common.endswith(".go") and Path(common).suffix:
        common = os.path.dirname(common)
    return common


def filter_app_paths(paths: list[str], app_roots: set[str]) -> list[str]:
    if not app_roots:
        return []
    app_paths = []
    for path in paths:
        if any(f"/{root}/" in path for root in app_roots):
            app_paths.append(path)
    return sorted(set(app_paths))


def is_app_symbol(name: str, app_roots: set[str]) -> bool:
    return any(
        name == root
        or name.startswith(root + "/")
        or name.startswith(root + ".")
        for root in app_roots
    )


def source_tree_markdown(paths: list[str], module_root: str, app_roots: set[str]) -> str:
    if not paths:
        return "# Recovered Source Tree\n\nNo DWARF decoded Go source paths were recovered.\n"
    root_name = sorted(app_roots)[0] if app_roots else Path(module_root).name or "recovered"
    rels = []
    for path in paths:
        rel = path
        if module_root and path.startswith(module_root + "/"):
            rel = path[len(module_root) + 1 :]
        elif f"/{root_name}/" in path:
            rel = path.split(f"/{root_name}/", 1)[1]
        rels.append(rel)
    lines = ["# Recovered Source Tree", "", "Evidence source: DWARF decoded line paths.", "", "```text", f"{root_name}/"]
    tree: dict[str, set[str]] = defaultdict(set)
    root_files = []
    for rel in sorted(set(rels)):
        parts = rel.split("/")
        if len(parts) == 1:
            root_files.append(parts[0])
        else:
            tree["/".join(parts[:-1])].add(parts[-1])
    for file_name in sorted(root_files):
        lines.append(f"  {file_name}")
    for directory in sorted(tree):
        indent = "  " * (directory.count("/") + 1)
        lines.append(f"  {directory}/")
        for file_name in sorted(tree[directory]):
            lines.append(f"{indent}  {file_name}")
    lines.extend(["```", ""])
    return "\n".join(lines)


def analysis_target(case_dir: Path) -> Path:
    """The file the gold BNDB describes — the unpacked payload once one is registered."""
    case_path = case_dir / "case.json"
    rel = "sample/original.bin"
    if case_path.exists():
        case = json.loads(case_path.read_text(encoding="utf-8"))
        rel = case.get("analysis_target") or rel
    return case_dir / rel


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract ELF/Go evidence for a gold RE case")
    parser.add_argument("case_dir")
    args = parser.parse_args()

    case_dir = Path(args.case_dir).expanduser().resolve()
    sample = analysis_target(case_dir)
    evidence_dir = case_dir / "evidence"
    if not sample.exists():
        raise FileNotFoundError(sample)

    file_code, file_text = run_tool(["file", str(sample)], timeout=30)
    write_text(evidence_dir / "file_info.txt", file_text)

    sym_code, sym_text = run_tool(["readelf", "-sW", str(sample)], timeout=180)
    write_text(evidence_dir / "readelf_symbols.txt", sym_text)
    symbols = parse_symbols(sym_text) if sym_code == 0 else []

    line_code, line_text = run_tool(["readelf", "--debug-dump=decodedline", str(sample)], timeout=180)
    write_text(evidence_dir / "readelf_decodedline.txt", line_text)
    paths = extract_go_paths(line_text) if line_code == 0 else []

    app_roots = infer_app_roots(symbols, paths)
    app_paths = filter_app_paths(paths, app_roots)
    app_symbols = [
        sym for sym in symbols
        if app_roots
        and is_app_symbol(sym["name"], app_roots)
        and not is_go_runtime_or_dependency(sym["name"], app_roots)
    ]
    app_symbols.sort(key=lambda row: (row["name"], row["address"]))
    app_symbol_text = "\n".join(
        f"{row['address']} {row['size']:>6} {row['type']:<7} {row['name']}"
        for row in app_symbols
    )
    write_text(evidence_dir / "app_symbols.txt", app_symbol_text + ("\n" if app_symbol_text else ""))

    module_root = common_module_root(app_paths, app_roots)
    if app_paths:
        write_text(case_dir / "recovered_tree" / "source_tree.md", source_tree_markdown(app_paths, module_root, app_roots))

    context = {
        "sample": str(sample),
        "file_returncode": file_code,
        "readelf_symbols_returncode": sym_code,
        "readelf_decodedline_returncode": line_code,
        "is_go": "Go BuildID" in file_text or any(".go" in path for path in paths),
        "app_roots": sorted(app_roots),
        "module_root": module_root,
        "source_paths": app_paths,
        "all_source_path_count": len(paths),
        "symbol_counts": {
            "all": len(symbols),
            "app": len(app_symbols),
        },
        "notes": [
            "Use app_symbols.txt to prioritize application-owned functions/data.",
            "Use DWARF paths as source-tree evidence, not as type-layout proof.",
            "Do not curate Go runtime or dependency functions unless explicitly requested.",
        ],
    }
    write_json(evidence_dir / "go_context.json", context)
    print(evidence_dir / "go_context.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
