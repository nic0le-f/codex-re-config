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

DEFAULT_CASES_DIR = os.environ.get("BNGOLD_CASES_DIR", str(Path.home() / "re-cases"))

# Evidence sources that may prioritise work but must never be the sole backing
# for an accepted claim. Enforces the evidence policy in SKILL.md, which was
# previously prose only.
LEAD_ONLY_SOURCES = (
    "malcat",
    "yara",
    "capa",
    "virustotal",
    "vt:",
    "malwarebazaar",
    "otx",
    "public report",
)


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
        # The file the gold BNDB actually describes. Rewritten by add-unpacked so
        # a report never silently attributes findings to a file nobody else can
        # reproduce from the delivered sample.
        "analysis_target": "sample/original.bin",
        "analysis_target_sha256": digest,
        "lineage": [],
    }
    # When the sample handed in is itself a payload, record where it came from.
    # Without this the report claims findings about a file with no provenance.
    parent_sha = getattr(args, "parent_sha256", "") or ""
    parent_note = getattr(args, "parent_note", "") or ""
    if parent_sha or parent_note:
        case["delivered_parent"] = {
            "sha256": parent_sha,
            "note": parent_note,
        }
    write_json(case_dir / "case.json", case)
    for path in (case_dir / "claims" / "claims.jsonl", case_dir / "claims" / "verdicts.jsonl"):
        path.touch(exist_ok=True)
    print(case_dir)
    return 0


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def add_unpacked(args: argparse.Namespace) -> int:
    """Record an unpacked payload and repoint the case at it."""
    case_dir = Path(args.case_dir).expanduser().resolve()
    case_path = case_dir / "case.json"
    case = read_json(case_path, None)
    if case is None:
        raise FileNotFoundError(case_path)

    payload = Path(args.payload).expanduser().resolve()
    if not payload.exists():
        raise FileNotFoundError(payload)
    if not stat.S_ISREG(payload.stat().st_mode):
        raise ValueError(f"not a regular file: {payload}")

    lineage = case.setdefault("lineage", [])
    index = len(lineage) + 1
    dest_rel = f"sample/unpacked_{index:02d}.bin"
    dest = case_dir / dest_rel
    shutil.copy2(payload, dest)

    digest = sha256_file(dest)
    parent_rel = case.get("analysis_target", "sample/original.bin")
    parent_sha = case.get("analysis_target_sha256", case.get("sha256", ""))

    lineage.append(
        {
            "step": index,
            "path": dest_rel,
            "sha256": digest,
            "size": dest.stat().st_size,
            "parent_path": parent_rel,
            "parent_sha256": parent_sha,
            "method": args.method,
            "tool": args.tool,
            "notes": args.notes or "",
        }
    )
    case["analysis_target"] = dest_rel
    case["analysis_target_sha256"] = digest
    write_json(case_path, case)
    print(dest)
    return 0


def naming_errors(claim: dict[str, Any], prefix: str) -> list[str]:
    """Enforce the mw_ taxonomy on analyst-supplied symbol names.

    Only function_name and data_name propose symbols. type_definition is a C
    declaration, source_file is a path, and function_comment is prose.
    """
    if claim.get("kind") not in {"function_name", "data_name"}:
        return []

    name = str(claim.get("proposed_value", ""))
    errors = []
    if not name.startswith("mw_"):
        errors.append(
            f"{prefix}: proposed_value {name!r} must carry the mw_ prefix. "
            f"If the binary already supplies this name, there is nothing to claim."
        )
    if name != name.lower():
        errors.append(f"{prefix}: proposed_value {name!r} must be snake_case")
    if name.endswith("_likely") or "_likely_" in name:
        errors.append(
            f"{prefix}: drop the _likely suffix from {name!r}. Uncertainty belongs in "
            f"claim.status and the validator's needs_human verdict, not in the symbol."
        )
    return errors


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
    errors.extend(naming_errors(claim, prefix))
    evidence = claim.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append(f"{prefix}: evidence must be a non-empty list")
    elif all(
        any(source in str(item).lower() for source in LEAD_ONLY_SOURCES) for item in evidence
    ):
        errors.append(
            f"{prefix}: every evidence item is a lead-only source "
            f"({', '.join(LEAD_ONLY_SOURCES)}); needs local code evidence"
        )
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
    p_init.add_argument("--cases-dir", default=DEFAULT_CASES_DIR)
    p_init.add_argument(
        "--parent-sha256",
        default="",
        help="SHA-256 of the file this sample was extracted or unpacked from, "
        "when you are handing in a payload rather than the delivered file",
    )
    p_init.add_argument(
        "--parent-note",
        default="",
        help="how the sample was obtained from its parent, e.g. 'upx -d' or 'dumped at OEP'",
    )
    p_init.set_defaults(func=init_case)

    p_unpack = sub.add_parser(
        "add-unpacked", help="record an unpacked payload and repoint the case at it"
    )
    p_unpack.add_argument("case_dir")
    p_unpack.add_argument("payload", help="path to the unpacked file")
    p_unpack.add_argument("--method", required=True, help="e.g. upx, manual-dump, oledump")
    p_unpack.add_argument("--tool", required=True, help="e.g. 'upx 4.2.4'")
    p_unpack.add_argument("--notes", default="")
    p_unpack.set_defaults(func=add_unpacked)

    p_validate = sub.add_parser("validate-claims", help="validate claim/verdict JSONL shape")
    p_validate.add_argument("case_dir")
    p_validate.set_defaults(func=validate_claims)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
