#!/usr/bin/env bnpython3
"""Apply accepted claims to gold/gold.bndb."""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import binaryninja as bn


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def parse_addr(value: str) -> int:
    return int(str(value), 0)


def accepted_claims(case_dir: Path) -> list[dict[str, Any]]:
    claims = {row["claim_id"]: row for row in read_jsonl(case_dir / "claims" / "claims.jsonl")}
    verdicts = read_jsonl(case_dir / "claims" / "verdicts.jsonl")
    accepted = []
    for verdict in verdicts:
        if verdict.get("status") == "accepted" and verdict.get("claim_id") in claims:
            accepted.append(claims[verdict["claim_id"]])
    return accepted


def type_defs_in(c_code: str) -> set[str]:
    names = set(re.findall(r"\btypedef\s+struct\s+([A-Za-z_][A-Za-z0-9_]*)\b", c_code))
    names |= set(re.findall(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", c_code))
    names |= set(re.findall(r"\btypedef\s+enum\s+([A-Za-z_][A-Za-z0-9_]*)\b", c_code))
    names |= set(re.findall(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{", c_code))
    return names


def type_refs_in(c_code: str) -> set[str]:
    refs = set(re.findall(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\b", c_code))
    refs |= set(re.findall(r"\benum\s+([A-Za-z_][A-Za-z0-9_]*)\b", c_code))
    return refs - type_defs_in(c_code)


def sort_type_claims(type_claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    defs_by_claim = {claim["claim_id"]: type_defs_in(str(claim["proposed_value"])) for claim in type_claims}
    def_owner = {}
    for claim_id, names in defs_by_claim.items():
        for name in names:
            def_owner.setdefault(name, claim_id)
    all_def_names = set(def_owner)

    deps = {}
    for claim in type_claims:
        claim_id = claim["claim_id"]
        c_code = str(claim["proposed_value"])
        refs = type_refs_in(c_code)
        refs |= set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", c_code)) & all_def_names
        refs -= defs_by_claim.get(claim_id, set())
        deps[claim_id] = {
            def_owner[ref]
            for ref in refs
            if ref in def_owner and def_owner[ref] != claim_id
        }

    pending = {claim["claim_id"]: claim for claim in type_claims}
    ordered = []
    while pending:
        ready = sorted(
            claim_id for claim_id in pending
            if not (deps.get(claim_id, set()) & pending.keys())
        )
        if not ready:
            ordered.extend(pending[claim_id] for claim_id in sorted(pending))
            break
        for claim_id in ready:
            ordered.append(pending.pop(claim_id))
    return ordered


def apply_type_claims(bv: bn.BinaryView, type_claims: list[dict[str, Any]]) -> list[str]:
    if not type_claims:
        return []
    ordered = sort_type_claims(type_claims)
    chunks = [str(claim["proposed_value"]).strip() for claim in ordered if str(claim["proposed_value"]).strip()]
    combined = "\n\n".join(chunks) + "\n"
    try:
        bv.parse_types_from_string(combined)
    except Exception as exc:
        raise RuntimeError(
            "failed to apply accepted type definitions as a dependency-sorted batch"
        ) from exc
    return [claim["claim_id"] for claim in ordered]


def apply_claim(bv: bn.BinaryView, claim: dict[str, Any]) -> None:
    kind = claim["kind"]
    target = claim["target"]
    value = claim["proposed_value"]
    if kind == "function_name":
        func = bv.get_function_at(parse_addr(target))
        if func is None:
            raise RuntimeError(f"function not found for claim {claim['claim_id']}: {target}")
        func.name = str(value)
    elif kind == "function_comment":
        bv.set_comment_at(parse_addr(target), str(value))
    elif kind == "data_name":
        bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, parse_addr(target), str(value)))
    elif kind == "type_definition":
        raise RuntimeError("type_definition claims must be applied via apply_type_claims")
    elif kind == "source_file":
        comment = f"Recovered source file: {value}\nEvidence: {'; '.join(map(str, claim.get('evidence', [])))}"
        bv.set_comment_at(parse_addr(target), comment)
    else:
        raise RuntimeError(f"unsupported claim kind: {kind}")


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 1:
        print(f"usage: {sys.argv[0]} CASE_DIR", file=sys.stderr)
        return 2
    case_dir = Path(argv[0]).expanduser().resolve()
    base = case_dir / "binja" / "base.bndb"
    gold = case_dir / "gold" / "gold.bndb"
    if not base.exists():
        raise FileNotFoundError(base)
    gold.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(base, gold)
    bv = bn.load(str(gold))
    if bv is None:
        raise RuntimeError(f"failed to load {gold}")
    claims = accepted_claims(case_dir)
    type_order = apply_type_claims(bv, [claim for claim in claims if claim.get("kind") == "type_definition"])
    applied = {"type_definition": type_order, "other": []}
    for claim in claims:
        if claim.get("kind") == "type_definition":
            continue
        apply_claim(bv, claim)
        applied["other"].append(claim["claim_id"])
    bv.update_analysis_and_wait()
    if not bv.create_database(str(gold)):
        raise RuntimeError(f"failed to save {gold}")
    report_path = case_dir / "reports" / "applied_claims.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(applied, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(gold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
