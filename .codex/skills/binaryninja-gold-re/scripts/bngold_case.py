#!/usr/bin/env python3
"""Case and claim utilities for the Binary Ninja gold RE workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path
from typing import Any


VALID_KINDS = {
    "function_name",
    "function_comment",
    "data_name",
    "type_definition",
    "source_file",
}
VALID_STATUS = {"proposed", "accepted", "rejected", "needs_human"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def init_case(args: argparse.Namespace) -> int:
    sample = Path(args.sample).expanduser().resolve()
    if not sample.exists():
        raise FileNotFoundError(sample)
    if not stat.S_ISREG(sample.stat().st_mode):
        raise ValueError(f"not a regular file: {sample}")

    digest = sha256_file(sample)
    stem = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in sample.name)
    case_dir = Path(args.cases_dir).expanduser().resolve() / f"{stem}_{digest[:12]}"
    for subdir in (
        "sample",
        "binja",
        "work",
        "gold",
        "evidence",
        "claims",
        "reports",
        "recovered_tree",
        "triage",
    ):
        (case_dir / subdir).mkdir(parents=True, exist_ok=True)
    original = case_dir / "sample" / "original.bin"
    if not original.exists():
        shutil.copy2(sample, original)
    case = {
        "sample_name": sample.name,
        "original_path": str(sample),
        "case_dir": str(case_dir),
        "sha256": digest,
        "static_only": True,
        "format": "unknown_until_bn_export",
    }
    write_json(case_dir / "case.json", case)
    for path in (case_dir / "claims" / "claims.jsonl", case_dir / "claims" / "verdicts.jsonl"):
        path.touch(exist_ok=True)
    print(case_dir)
    return 0


def validate_claim(claim: dict[str, Any], index: int) -> list[str]:
    errors = []
    prefix = f"claim[{index}]"
    for key in ("claim_id", "kind", "target", "proposed_value", "evidence", "status"):
        if key not in claim:
            errors.append(f"{prefix}: missing {key}")
    if claim.get("kind") not in VALID_KINDS:
        errors.append(f"{prefix}: invalid kind {claim.get('kind')!r}")
    if claim.get("status") not in VALID_STATUS:
        errors.append(f"{prefix}: invalid status {claim.get('status')!r}")
    evidence = claim.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{prefix}: evidence must be a non-empty list")
    if claim.get("kind") == "type_definition" and "typedef" not in str(claim.get("proposed_value", "")) and "struct" not in str(claim.get("proposed_value", "")) and "enum" not in str(claim.get("proposed_value", "")):
        errors.append(f"{prefix}: type_definition proposed_value should contain C type text")
    return errors


def validate_claims(args: argparse.Namespace) -> int:
    case_dir = Path(args.case_dir).expanduser().resolve()
    claims = read_jsonl(case_dir / "claims" / "claims.jsonl")
    verdicts = read_jsonl(case_dir / "claims" / "verdicts.jsonl")
    errors = []
    seen = set()
    for index, claim in enumerate(claims, 1):
        errors.extend(validate_claim(claim, index))
        claim_id = claim.get("claim_id")
        if claim_id in seen:
            errors.append(f"claim[{index}]: duplicate claim_id {claim_id}")
        seen.add(claim_id)

    verdict_by_id = {}
    for index, verdict in enumerate(verdicts, 1):
        claim_id = verdict.get("claim_id")
        status = verdict.get("status")
        if not claim_id:
            errors.append(f"verdict[{index}]: missing claim_id")
        if status not in {"accepted", "rejected", "needs_human"}:
            errors.append(f"verdict[{index}]: invalid status {status!r}")
        verdict_by_id[claim_id] = verdict

    counts = {"claims": len(claims), "accepted": 0, "rejected": 0, "needs_human": 0, "unreviewed": 0}
    for claim in claims:
        verdict = verdict_by_id.get(claim.get("claim_id"))
        if verdict:
            counts[verdict["status"]] += 1
        else:
            counts["unreviewed"] += 1

    summary = {"ok": not errors, "errors": errors, "counts": counts}
    write_json(case_dir / "claims" / "validation_summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not errors else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Binary Ninja gold RE case utilities")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="create a case workspace")
    p_init.add_argument("sample")
    p_init.add_argument("--cases-dir", default=str(Path.home() / "re-cases"))
    p_init.set_defaults(func=init_case)

    p_validate = sub.add_parser("validate-claims", help="validate claim/verdict JSONL shape")
    p_validate.add_argument("case_dir")
    p_validate.set_defaults(func=validate_claims)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
