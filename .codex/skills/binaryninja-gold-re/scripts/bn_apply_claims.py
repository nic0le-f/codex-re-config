#!/usr/bin/env bnpython3
"""Apply accepted claims to gold/gold.bndb."""

from __future__ import annotations

import fcntl
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import binaryninja as bn

from bngold_case import sha256_file, validate_claim


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
    latest = {verdict.get("claim_id"): verdict.get("status") for verdict in verdicts}
    accepted = [claim for cid, claim in claims.items() if latest.get(cid) == "accepted"]
    errors = [error for index, claim in enumerate(accepted, 1) for error in validate_claim(claim, index)]
    if errors:
        raise ValueError("\n".join(errors))
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
    elif kind == "function_signature":
        func = bv.get_function_at(parse_addr(target))
        if func is None:
            raise RuntimeError(f"function not found for claim {claim['claim_id']}: {target}")
        signature, _ = bv.parse_type_string(value)
        if not isinstance(signature, bn.FunctionType):
            raise ValueError(f"claim {claim['claim_id']} does not declare a function")
        func.type = signature
    elif kind == "local_variable_name":
        _, variable = resolve_local(bv, target)
        variable.set_name_async(value)
    elif kind in {"function_comment", "address_comment"}:
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


def resolve_local(bv, target):
    func = bv.get_function_at(parse_addr(target["function"]))
    if func is not None and func.hlil is not None:
        matches = [var for var in func.hlil.vars if var.identifier == target["identifier"]]
        if len(matches) == 1:
            return func, matches[0]
    raise RuntimeError(f"cannot uniquely resolve local variable: {target}")


def verify_saved(path, claims):
    reopened = bn.load(str(path))
    if reopened is None:
        raise RuntimeError(f"failed to reopen {path}")
    try:
        for claim in claims:
            kind, target, value = claim["kind"], claim["target"], claim["proposed_value"]
            if kind == "function_signature":
                expected, _ = reopened.parse_type_string(value)
                function = reopened.get_function_at(parse_addr(target))
                if (
                    function is None
                    or str(function.type) != str(expected)
                    or function.type.calling_convention != expected.calling_convention
                ):
                    raise RuntimeError(f"signature did not persist: {claim['claim_id']}")
            if kind == "local_variable_name":
                _, variable = resolve_local(reopened, target)
                if variable.name != value:
                    raise RuntimeError(f"local rename did not persist: {claim['claim_id']}")
    finally:
        reopened.file.close()


def build_gold(case_dir, base, gold, staging):
    claims = accepted_claims(case_dir)
    source = staging / "base.bndb"
    candidate = staging / "candidate.bndb"
    shutil.copy2(base, source)
    base_digest = sha256_file(source)
    bv = bn.load(str(source))
    if bv is None:
        raise RuntimeError(f"failed to load {source}")
    try:
        types = [claim for claim in claims if claim["kind"] == "type_definition"]
        type_order = apply_type_claims(bv, types)
        applied = {"type_definition": type_order, "other": []}
        for kind_group in (
            {"function_signature"},
            {"function_name", "function_comment", "address_comment", "data_name", "source_file"},
            {"local_variable_name"},
        ):
            for claim in claims:
                if claim["kind"] in kind_group:
                    apply_claim(bv, claim)
                    applied["other"].append(claim["claim_id"])
            bv.update_analysis_and_wait()
        if not bv.create_database(str(candidate)):
            raise RuntimeError(f"failed to save {candidate}")
    finally:
        bv.file.close()
    verify_saved(candidate, claims)

    previous = gold.with_name("previous.bndb")
    previous_digest = None
    if gold.exists():
        previous_copy = staging / previous.name
        shutil.copy2(gold, previous_copy)
        previous_digest = sha256_file(previous_copy)
        previous_copy.replace(previous)
    applied.update(
        base_sha256=base_digest,
        gold_sha256=sha256_file(candidate),
        previous_gold_sha256=previous_digest,
        rollback_path=str(previous.relative_to(case_dir)) if previous_digest else None,
        verification=["database reopened", "function signatures and local names checked"],
    )
    # Publish a digest-keyed manifest before replacing the database.
    manifest_dir = gold.parent / "manifests"
    manifest_dir.mkdir(exist_ok=True)
    manifest = staging / "manifest.json"
    manifest.write_text(json.dumps(applied, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    shutil.copyfile(manifest, staging / "version.json")
    (staging / "version.json").replace(manifest_dir / f"{applied['gold_sha256']}.json")
    candidate.replace(gold)
    report_dir = case_dir / "reports"
    report_dir.mkdir(exist_ok=True)
    manifest.replace(report_dir / "applied_claims.json")


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print(f"usage: {sys.argv[0]} CASE_DIR", file=sys.stderr)
        return 2
    case_dir = Path(argv[0]).expanduser().resolve()
    base = case_dir / "binja" / "base.bndb"
    gold = case_dir / "gold" / "gold.bndb"
    if not base.is_file():
        raise FileNotFoundError(base)
    gold.parent.mkdir(parents=True, exist_ok=True)
    with (gold.parent / ".apply.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix=".apply-", dir=gold.parent) as temporary:
            build_gold(case_dir, base, gold, Path(temporary))
    print(gold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
