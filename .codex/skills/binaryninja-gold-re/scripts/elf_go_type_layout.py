#!/usr/bin/env python3
"""Extract Go DWARF type-layout evidence from readelf output.

This script is static-only. It summarizes application-owned DWARF structs with
byte sizes and member offsets so type-definition claims can cite concrete layout
evidence before being validated and applied to the gold BNDB.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ENTRY_RE = re.compile(r"^\s*<(?P<level>\d+)><(?P<offset>[0-9a-fA-F]+)>:.*\((?P<tag>DW_TAG_[^)]+)\)")
ATTR_RE = re.compile(r"^\s*<(?P<attr_off>[0-9a-fA-F]+)>\s+(?P<attr>DW_AT_[A-Za-z0-9_]+)\s*:\s*(?P<value>.*)$")


def run_readelf_info(sample: Path, out: Path) -> str:
    if out.exists() and out.stat().st_size:
        return out.read_text(encoding="utf-8", errors="replace")
    proc = subprocess.run(
        ["readelf", "--debug-dump=info", str(sample)],
        text=True,
        capture_output=True,
        timeout=240,
        check=False,
    )
    text = proc.stdout + proc.stderr
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(f"readelf --debug-dump=info failed with exit code {proc.returncode}")
    return text


def clean_value(value: str) -> str:
    value = value.strip()
    if "\t" in value:
        value = value.split("\t", 1)[0].strip()
    return value


def parse_int(value: str) -> int | None:
    value = clean_value(value)
    try:
        return int(value, 0)
    except ValueError:
        return None


def load_app_roots(case_dir: Path) -> list[str]:
    path = case_dir / "evidence" / "go_context.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("app_roots", [])


def parse_structs(text: str, app_roots: list[str]) -> list[dict[str, Any]]:
    root_prefixes = tuple(root + "/" for root in app_roots)
    structs: list[dict[str, Any]] = []
    stack: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_member: dict[str, Any] | None = None

    for line in text.splitlines():
        entry = ENTRY_RE.match(line)
        if entry:
            level = int(entry.group("level"))
            tag = entry.group("tag")
            while stack and stack[-1]["level"] >= level:
                popped = stack.pop()
                if popped.get("kind") == "member":
                    current_member = None
                if popped.get("kind") == "struct":
                    if current and current.get("name"):
                        structs.append(current)
                    current = None

            if tag == "DW_TAG_structure_type":
                current = {
                    "die_offset": "0x" + entry.group("offset").lower(),
                    "name": "",
                    "byte_size": None,
                    "members": [],
                }
                stack.append({"level": level, "kind": "struct"})
                current_member = None
            elif tag == "DW_TAG_member" and current is not None:
                current_member = {"name": "", "offset": None, "type_ref": ""}
                current["members"].append(current_member)
                stack.append({"level": level, "kind": "member"})
            else:
                stack.append({"level": level, "kind": "other"})
            continue

        attr = ATTR_RE.match(line)
        if not attr:
            continue
        attr_name = attr.group("attr")
        value = clean_value(attr.group("value"))
        if current_member is not None:
            if attr_name == "DW_AT_name":
                current_member["name"] = value
            elif attr_name == "DW_AT_data_member_location":
                current_member["offset"] = parse_int(value)
            elif attr_name == "DW_AT_type":
                current_member["type_ref"] = value
        elif current is not None:
            if attr_name == "DW_AT_name":
                current["name"] = value
            elif attr_name == "DW_AT_byte_size":
                current["byte_size"] = parse_int(value)

    while stack:
        popped = stack.pop()
        if popped.get("kind") == "struct" and current and current.get("name"):
            structs.append(current)
            current = None

    if root_prefixes:
        structs = [
            row for row in structs
            if row.get("name", "").startswith(root_prefixes)
            and not row.get("name", "").startswith("noalg.struct")
            and row.get("byte_size") is not None
        ]
    return structs


def write_markdown(path: Path, structs: list[dict[str, Any]]) -> None:
    lines = ["# Go DWARF Type Layouts", "", "Evidence source: `readelf --debug-dump=info`.", ""]
    if not structs:
        lines.append("No application-owned DWARF structures were recovered.")
    for struct in structs:
        lines.append(f"## `{struct['name']}`")
        lines.append("")
        lines.append(f"- DIE: `{struct['die_offset']}`")
        lines.append(f"- Byte size: `{struct['byte_size']}`")
        lines.append("")
        lines.append("| Offset | Member | Type Ref |")
        lines.append("| ---: | --- | --- |")
        for member in struct["members"]:
            offset = "" if member.get("offset") is None else f"0x{member['offset']:x}"
            lines.append(f"| `{offset}` | `{member.get('name', '')}` | `{member.get('type_ref', '')}` |")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def analysis_target(case_dir: Path) -> Path:
    """The file the gold BNDB describes — the unpacked payload once one is registered."""
    case_path = case_dir / "case.json"
    rel = "sample/original.bin"
    if case_path.exists():
        case = json.loads(case_path.read_text(encoding="utf-8"))
        rel = case.get("analysis_target") or rel
    return case_dir / rel


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract Go DWARF struct layout evidence")
    parser.add_argument("case_dir")
    parser.add_argument("--max-structs", type=int, default=200)
    args = parser.parse_args()

    case_dir = Path(args.case_dir).expanduser().resolve()
    sample = analysis_target(case_dir)
    evidence = case_dir / "evidence"
    if not sample.exists():
        raise FileNotFoundError(sample)

    text = run_readelf_info(sample, evidence / "readelf_info.txt")
    app_roots = load_app_roots(case_dir)
    structs = parse_structs(text, app_roots)[: args.max_structs]
    out_json = evidence / "go_type_layouts.json"
    out_md = evidence / "go_type_layouts.md"
    out_json.write_text(json.dumps({"app_roots": app_roots, "structs": structs}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(out_md, structs)
    print(out_json)
    print(out_md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
