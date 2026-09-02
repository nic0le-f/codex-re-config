#!/usr/bin/env python3
"""Generate a concise final report for a Binary Ninja gold RE case."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


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


def read_text(path: Path, default: str = "") -> str:
    if not path.exists():
        return default
    return path.read_text(encoding="utf-8", errors="replace")


def verdict_counts(verdicts: list[dict[str, Any]], total_claims: int) -> dict[str, int]:
    counts = {"accepted": 0, "rejected": 0, "needs_human": 0}
    for row in verdicts:
        status = row.get("status")
        if status in counts:
            counts[status] += 1
    counts["unreviewed"] = max(0, total_claims - sum(counts.values()))
    return counts


def accepted_by_kind(claims: list[dict[str, Any]], verdicts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    accepted_ids = {row.get("claim_id") for row in verdicts if row.get("status") == "accepted"}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for claim in claims:
        if claim.get("claim_id") in accepted_ids:
            grouped.setdefault(claim.get("kind", "unknown"), []).append(claim)
    return grouped


def lineage_lines(case: dict[str, Any]) -> list[str]:
    """State which file the gold BNDB actually describes.

    Without this a report silently attributes every finding to the delivered
    sample, even when the analysis ran on an unpacked payload.
    """
    lines = []
    parent = case.get("delivered_parent")
    if parent:
        lines.append(
            f"- Handed in as a payload extracted from `{parent.get('sha256') or 'unknown parent'}`"
            + (f" — {parent['note']}" if parent.get("note") else "")
        )

    lineage = case.get("lineage") or []
    if not lineage:
        lines.append(
            f"- No unpacking performed in-case. The gold BNDB describes "
            f"`sample/original.bin` (`{case.get('sha256', '')}`)."
        )
        return lines

    lines.append(f"- Delivered sample: `sample/original.bin` (`{case.get('sha256', '')}`)")
    for step in lineage:
        lines.append(
            f"- Step {step.get('step')}: `{step.get('parent_path')}` → `{step.get('path')}` "
            f"via {step.get('method')} ({step.get('tool')}) — `{step.get('sha256')}`"
            + (f" — {step['notes']}" if step.get("notes") else "")
        )
    lines.append(
        f"- **The gold BNDB describes `{case.get('analysis_target')}`, not the delivered sample.**"
    )
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate reports/final.md for a gold RE case")
    parser.add_argument("case_dir")
    args = parser.parse_args()

    case_dir = Path(args.case_dir).expanduser().resolve()
    case = read_json(case_dir / "case.json", {})
    facts = read_json(case_dir / "evidence" / "bn_facts.json", {})
    go_context = read_json(case_dir / "evidence" / "go_context.json", {})
    type_layouts = read_json(case_dir / "evidence" / "go_type_layouts.json", {})
    applied_claims = read_json(case_dir / "reports" / "applied_claims.json", {})
    claims = read_jsonl(case_dir / "claims" / "claims.jsonl")
    verdicts = read_jsonl(case_dir / "claims" / "verdicts.jsonl")
    counts = verdict_counts(verdicts, len(claims))
    grouped = accepted_by_kind(claims, verdicts)

    sample_name = case.get("sample_name", "sample")
    bv = facts.get("binary_view", {})
    sample = facts.get("sample", {})
    source_tree = read_text(case_dir / "recovered_tree" / "source_tree.md")
    report_lines = [
        f"# {sample_name} Gold BNDB Report",
        "",
        "## Artifacts",
        "",
        f"- Gold BNDB: `{case_dir / 'gold' / 'gold.bndb'}`",
        f"- BN facts: `{case_dir / 'evidence' / 'bn_facts.json'}`",
        f"- Claims: `{case_dir / 'claims' / 'claims.jsonl'}`",
        f"- Verdicts: `{case_dir / 'claims' / 'verdicts.jsonl'}`",
        "",
        "## Sample Lineage",
        "",
    ]
    report_lines.extend(lineage_lines(case))
    report_lines.extend(
        [
            "",
            "## Observed Facts",
            "",
            f"- Sample: `{sample_name}`",
            f"- SHA-256: `{case.get('sha256') or sample.get('sha256', '')}`",
            f"- Size: `{sample.get('size', '')}` bytes",
            f"- Binary Ninja view: `{bv.get('view_type', '')}` `{bv.get('arch', '')}` `{bv.get('platform', '')}`",
            f"- Entry point: `{bv.get('entry_point', '')}`",
            f"- Functions exported: `{len(facts.get('functions', []))}`",
            f"- Strings exported: `{len(facts.get('strings', []))}`",
            f"- Sections exported: `{len(facts.get('sections', []))}`",
        ]
    )
    if go_context:
        report_lines.extend(
            [
                f"- Go binary: `{go_context.get('is_go')}`",
                f"- Application roots: `{', '.join(go_context.get('app_roots', []))}`",
                f"- DWARF source paths: `{len(go_context.get('source_paths', []))}`",
                f"- Application symbols: `{go_context.get('symbol_counts', {}).get('app', 0)}`",
            ]
        )
    if type_layouts:
        report_lines.append(f"- DWARF app struct layouts: `{len(type_layouts.get('structs', []))}`")
    if applied_claims:
        report_lines.append(f"- Applied type definitions: `{len(applied_claims.get('type_definition', []))}`")
    report_lines.extend(
        [
            "",
            "## Claim Status",
            "",
            f"- Accepted: {counts['accepted']}",
            f"- Rejected: {counts['rejected']}",
            f"- Needs human: {counts['needs_human']}",
            f"- Unreviewed: {counts['unreviewed']}",
            "",
            "## Accepted Highlights",
            "",
        ]
    )
    if not grouped:
        report_lines.append("- No accepted claims yet.")
    else:
        for kind in sorted(grouped):
            report_lines.append(f"- `{kind}`: {len(grouped[kind])}")
            for claim in grouped[kind][:8]:
                report_lines.append(f"  - `{claim.get('target')}` -> `{claim.get('proposed_value')}`")
    report_lines.extend(["", "## Source Tree", ""])
    if source_tree:
        report_lines.append(source_tree)
    else:
        report_lines.append("No recovered source tree has been generated yet.")
    report_lines.extend(
        [
            "",
            "## Unresolved Areas",
            "",
            "- Review rejected, needs-human, and unreviewed claims before calling the BNDB gold-standard complete.",
            "- Runtime/library functions and compiler-generated code should remain uncurated unless they affect application behavior.",
            "- Type/struct layouts require dedicated offset/access evidence and validator acceptance.",
            "",
            "## Checks Run",
            "",
            "- Binary Ninja fact export if `evidence/bn_facts.json` exists.",
            "- Claim/verdict validation if `claims/validation_summary.json` exists.",
            "- ELF/Go context extraction if `evidence/go_context.json` exists.",
            "- Go type-layout extraction if `evidence/go_type_layouts.json` exists.",
            "- Accepted-claim application if `reports/applied_claims.json` exists.",
        ]
    )
    out = case_dir / "reports" / "final.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(report_lines) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
