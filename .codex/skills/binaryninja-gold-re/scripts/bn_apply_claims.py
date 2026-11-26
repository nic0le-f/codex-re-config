#!/usr/bin/env bnpython3
"""Apply accepted claims to gold/gold.bndb."""

from __future__ import annotations

import argparse
import fcntl
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import binaryninja as bn

from bn_export_facts import analysis_target, verify_base_target
from case_review import ReviewRequired, verify_review

from bngold_case import read_jsonl, sha256_file, validate_claim
from case_handoff import write_json


def parse_addr(value: str) -> int:
    return int(str(value), 0)


def accepted_claims(case_dir: Path) -> list[dict[str, Any]]:
    rows = read_jsonl(case_dir / "claims" / "claims.jsonl")
    claims = {row["claim_id"]: row for row in rows}
    if len(claims) != len(rows):
        raise ValueError("duplicate claim IDs in claims ledger")
    verdicts = read_jsonl(case_dir / "claims" / "verdicts.jsonl")
    latest = {verdict.get("claim_id"): verdict.get("status") for verdict in verdicts}
    if any(cid not in claims and status == "accepted" for cid, status in latest.items()):
        raise ValueError("accepted verdict has no corresponding claim")
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


def apply_type_claims(bv: bn.BinaryView, type_claims: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    if not type_claims:
        return [], []
    ordered = sort_type_claims(type_claims)
    chunks = [str(claim["proposed_value"]).strip() for claim in ordered if str(claim["proposed_value"]).strip()]
    combined = "\n\n".join(chunks) + "\n"
    try:
        parsed = bv.parse_types_from_string(combined)
        if not parsed.types:
            raise ValueError("accepted type definitions did not declare named types")
        bv.define_user_types(list(parsed.types.items()), None)
    except Exception as exc:
        raise RuntimeError(
            "failed to apply accepted type definitions as a dependency-sorted batch"
        ) from exc
    return [claim["claim_id"] for claim in ordered], [str(name) for name in parsed.types]


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
    elif kind == "data_name":
        bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, parse_addr(target), str(value)))
    elif kind == "type_definition":
        raise RuntimeError("type_definition claims must be applied via apply_type_claims")
    else:
        raise RuntimeError(f"unsupported claim kind: {kind}")


def resolve_local(bv, target):
    func = bv.get_function_at(parse_addr(target["function"]))
    if func is not None and func.hlil is not None:
        matches = [var for var in func.hlil.vars if var.identifier == target["identifier"]]
        if len(matches) == 1:
            return func, matches[0]
    raise RuntimeError(f"cannot uniquely resolve local variable: {target}")


def comment_text(claim):
    value = claim["proposed_value"]
    if claim["kind"] == "source_file":
        evidence = "; ".join(map(str, claim.get("evidence", [])))
        return f"Recovered source file: {value}\nEvidence: {evidence}"
    return str(value)


COMMENT_KINDS = {"function_comment", "address_comment", "source_file"}


def verify_saved(path, claims, defined_types, source_digest):
    reopened = bn.load(str(path))
    if reopened is None:
        raise RuntimeError(f"failed to reopen {path}")
    try:
        verify_base_target(reopened, source_digest)
        for name in defined_types:
            if reopened.get_type_by_name(name) is None:
                raise RuntimeError(f"type definition did not persist: {name}")
        for claim in claims:
            kind, target, value = claim["kind"], claim["target"], claim["proposed_value"]
            if kind == "function_name":
                function = reopened.get_function_at(parse_addr(target))
                if function is None or function.name != value:
                    raise RuntimeError(f"function rename did not persist: {claim['claim_id']}")
            if kind == "data_name":
                symbol = reopened.get_symbol_at(parse_addr(target))
                if symbol is None or symbol.name != value:
                    raise RuntimeError(f"data rename did not persist: {claim['claim_id']}")
            if kind in COMMENT_KINDS:
                expected = comment_text(claim)
                if expected not in reopened.get_comment_at(parse_addr(target)):
                    raise RuntimeError(f"comment did not persist: {claim['claim_id']}")
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


def build_gold(case_dir, base, gold, staging, required):
    review = verify_review(case_dir, "gold")
    frozen_claims = staging / "claims"
    frozen_claims.mkdir()
    approved = {entry["path"]: entry["sha256"] for entry in review["subject_inputs"]["files"]}
    for name in ("claims.jsonl", "verdicts.jsonl"):
        relative = f"claims/{name}"
        frozen = frozen_claims / name
        shutil.copy2(case_dir / relative, frozen)
        if sha256_file(frozen) != approved[relative]:
            raise ReviewRequired(f"gold review is stale: {relative} changed")
    claims = accepted_claims(staging)
    unresolved = sorted(set(required) - {claim["claim_id"] for claim in claims})
    readiness = case_dir / "reports" / "gold_readiness.json"
    result = {
        "requested_claims": sorted(set(required)),
        "unresolved_claims": unresolved,
        "status": "building" if not unresolved else "unresolved",
    }
    write_json(readiness, result)
    if unresolved:
        raise ValueError(f"requested claims are unresolved: {', '.join(unresolved)}")
    sample, sample_digest = analysis_target(case_dir)
    source = staging / "base.bndb"
    candidate = staging / "candidate.bndb"
    shutil.copy2(base, source)
    base_digest = sha256_file(source)
    if base_digest != approved["binja/base.bndb"]:
        raise ReviewRequired("gold review is stale: base database changed")
    bv = bn.load(str(source))
    if bv is None:
        raise RuntimeError(f"failed to load {source}")
    try:
        types = [claim for claim in claims if claim["kind"] == "type_definition"]
        verify_base_target(bv, sample_digest)
        type_order, defined_types = apply_type_claims(bv, types)
        applied = {"type_definition": type_order, "other": []}
        for kind_group in (
            {"function_signature"},
            {"function_name", "data_name"},
            {"local_variable_name"},
        ):
            for claim in claims:
                if claim["kind"] in kind_group:
                    apply_claim(bv, claim)
                    applied["other"].append(claim["claim_id"])
            bv.update_analysis_and_wait()
        comments = {}
        for claim in claims:
            if claim["kind"] in COMMENT_KINDS:
                comments.setdefault(parse_addr(claim["target"]), []).append(comment_text(claim))
                applied["other"].append(claim["claim_id"])
        for address, texts in comments.items():
            bv.set_comment_at(address, "\n\n".join(dict.fromkeys(texts)))
        if not bv.create_database(str(candidate)):
            raise RuntimeError(f"failed to save {candidate}")
    finally:
        bv.file.close()
    verify_saved(candidate, claims, defined_types, sample_digest)

    if verify_review(case_dir, "gold") != review:
        raise ValueError("gold review changed during the build")

    previous = gold.with_name("previous.bndb")
    previous_digest = None
    if gold.exists():
        previous_copy = staging / previous.name
        shutil.copy2(gold, previous_copy)
        previous_digest = sha256_file(previous_copy)
        previous_copy.replace(previous)
    applied.update(
        base_sha256=base_digest,
        independent_review=review,
        analysis_target=str(sample.relative_to(case_dir)),
        analysis_target_sha256=sample_digest,
        requested_claims=result["requested_claims"],
        unresolved_claims=result["unresolved_claims"],
        gold_sha256=sha256_file(candidate),
        previous_gold_sha256=previous_digest,
        rollback_path=str(previous.relative_to(case_dir)) if previous_digest else None,
        verification=["database reopened", "applied annotations checked"],
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
    write_json(readiness, {**result, "status": "verified", "gold_sha256": applied["gold_sha256"]})


def rollback_gold(case_dir, gold, staging, expected):
    current_digest = sha256_file(gold)
    manifest_dir = gold.parent / "manifests"
    manifest = json.loads((manifest_dir / f"{current_digest}.json").read_text(encoding="utf-8"))
    previous = gold.with_name("previous.bndb")
    if manifest.get("previous_gold_sha256") != expected or sha256_file(previous) != expected:
        raise ValueError("requested SHA-256 does not identify the retained rollback copy")
    replacement = staging / "rollback.bndb"
    shutil.copy2(previous, replacement)
    _, target_digest = analysis_target(case_dir)
    verify_saved(replacement, [], [], target_digest)
    if sha256_file(replacement) != expected:
        raise ValueError("rollback copy changed during restore")
    replacement.replace(gold)
    restored_manifest = manifest_dir / f"{expected}.json"
    if restored_manifest.is_file():
        applied = json.loads(restored_manifest.read_text(encoding="utf-8"))
    else:
        applied = {"gold_sha256": expected, "verification": ["database reopened"]}
    write_json(case_dir / "reports" / "applied_claims.json", applied)
    write_json(case_dir / "reports" / "gold_readiness.json", {
        "status": "rolled-back", "gold_sha256": expected, "replaced_gold_sha256": current_digest,
    })


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--require-claim", action="append", default=[])
    modes.add_argument("--rollback", help="restore the retained previous gold by SHA-256")
    args = parser.parse_args(argv)
    case_dir = args.case.expanduser().resolve()
    base = case_dir / "binja" / "base.bndb"
    gold = case_dir / "gold" / "gold.bndb"
    if args.rollback and not re.fullmatch(r"[0-9a-fA-F]{64}", args.rollback):
        parser.error("--rollback requires a full SHA-256")
    if not args.rollback and not base.is_file():
        parser.error(f"base database does not exist: {base}")
    gold.parent.mkdir(parents=True, exist_ok=True)
    with (gold.parent / ".apply.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix=".apply-", dir=gold.parent) as temporary:
            staging = Path(temporary)
            if args.rollback:
                rollback_gold(case_dir, gold, staging, args.rollback.lower())
            else:
                try:
                    (case_dir / "reviews").mkdir(exist_ok=True)
                    with (case_dir / "reviews" / ".review.lock").open("a") as review_lock:
                        fcntl.flock(review_lock, fcntl.LOCK_SH)
                        build_gold(case_dir, base, gold, staging, args.require_claim)
                except (OSError, ValueError, RuntimeError) as exc:
                    readiness = case_dir / "reports" / "gold_readiness.json"
                    report = json.loads(readiness.read_text()) if readiness.is_file() else {}
                    status = report.get("status") if report.get("status") == "unresolved" else "failed"
                    if isinstance(exc, ReviewRequired):
                        status = "review-required"
                    write_json(readiness, {**report, "status": status, "error": str(exc)})
                    raise
    print(gold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
