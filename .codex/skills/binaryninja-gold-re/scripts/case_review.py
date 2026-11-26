"""Bind an independent review to the bytes and scope being approved."""

import hashlib
import json
import os
from datetime import datetime, timezone

from case_records import file_digest, inside


class ReviewRequired(ValueError):
    """Promotion or completion needs a current independent approval."""


def subject_inputs(case, subject, checkpoint=None):
    if subject == "gold":
        paths = ("case.json", "binja/base.bndb", "claims/claims.jsonl", "claims/verdicts.jsonl")
        scope = {"subject": subject}
    else:
        if checkpoint is None:
            checkpoint = json.loads(inside(case, f"tasks/{subject}.json").read_text())
        if checkpoint.get("task_type") == "gold-bndb":
            raise ValueError("request review under the gold subject for a gold BNDB task")
        if not checkpoint.get("review_required"):
            raise ValueError("mark this task as high-impact before requesting review")
        paths = sorted(set(checkpoint.get("outputs", [])) | set(checkpoint.get("evidence", [])))
        if not checkpoint.get("outputs"):
            raise ValueError("save the task output paths before requesting review")
        scope = {key: checkpoint.get(key) for key in ("task_id", "task_type", "scope", "deliverable", "done_when", "outputs", "evidence")}
    scope["files"] = fingerprints(case, paths)
    return scope


def snapshot_digest(inputs):
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def subject_snapshot(case, subject, checkpoint=None):
    return snapshot_digest(subject_inputs(case, subject, checkpoint))


def fingerprints(case, paths):
    rows = []
    for name in paths:
        path = inside(case, name)
        if not path.is_file():
            raise ValueError(f"review input must be a case file: {name}")
        rows.append({"path": str(path.relative_to(case)), "sha256": file_digest(path)})
    return rows


def review_path(case, subject):
    return inside(case, f"reviews/{subject}.json")


def read_review(case, subject):
    path = review_path(case, subject)
    return json.loads(path.read_text()) if path.is_file() else None


def verify_review(case, subject, checkpoint=None):
    record = read_review(case, subject)
    if not record or record.get("status") != "verified":
        raise ReviewRequired(f"independent approval required for {subject}: request-review, then record-review")
    if record["subject_sha256"] != subject_snapshot(case, subject, checkpoint):
        raise ReviewRequired(f"review for {subject} is stale: inputs changed")
    evidence = record.get("evidence", [])
    if not evidence or fingerprints(case, [item["path"] for item in evidence]) != evidence:
        raise ReviewRequired(f"review for {subject} is stale: evidence changed")
    return record


def verify_task_review(case, checkpoint):
    if checkpoint.get("task_type") != "gold-bndb":
        return verify_review(case, checkpoint["task_id"], checkpoint)
    review = verify_review(case, "gold")
    gold = inside(case, "gold/gold.bndb")
    if "gold/gold.bndb" not in checkpoint.get("outputs", []) or not gold.is_file():
        raise ReviewRequired("promote the approved gold database and record gold/gold.bndb as an output")
    digest = file_digest(gold)
    manifest = inside(case, f"gold/manifests/{digest}.json")
    if not manifest.is_file() or json.loads(manifest.read_text()).get("independent_review") != review:
        raise ReviewRequired("the current gold database was not promoted with this review")
    return review


def review_update(case, args, current):
    now = datetime.now(timezone.utc).isoformat()
    if args.command == "request-review":
        if not args.session_id or not args.session_id.strip():
            raise ValueError("supply the author thread ID with --session-id")
        authors = [args.session_id]
        if args.subject != "gold":
            task = json.loads(inside(case, f"tasks/{args.subject}.json").read_text())
            if task.get("session_id") != args.session_id:
                raise ValueError("the request must identify the task's current author thread")
            if task.get("first_session_id") and task["first_session_id"] not in authors:
                authors.append(task["first_session_id"])
        inputs = subject_inputs(case, args.subject)
        return {
            "subject": args.subject, "status": "pending", "author_session_id": args.session_id,
            "subject_sha256": snapshot_digest(inputs), "subject_inputs": inputs,
            "author_session_ids": authors, "requested_at": now,
        }
    if not current:
        raise ValueError("request the review before recording a verdict")
    if current["subject_sha256"] != subject_snapshot(case, args.subject):
        raise ValueError("review request is stale: request review again")
    if not args.reviewer.strip() or not args.summary.strip():
        raise ValueError("reviewer and review summary must be nonempty")
    authors = current.get("author_session_ids", [current["author_session_id"]])
    if not args.reviewer_id or not args.reviewer_id.strip():
        raise ValueError("supply the distinct reviewer identity with --reviewer-id")
    current_thread = os.getenv("CODEX_THREAD_ID") or os.getenv("CODEX_SESSION_ID")
    if args.kind != "human" and current_thread and args.reviewer_id != current_thread:
        raise ValueError("automated reviewer ID must match the executing Codex thread")
    if args.reviewer_id.strip().casefold() in {author.strip().casefold() for author in authors}:
        raise ValueError("the reviewer must be independent of the author thread")
    return {
        **current, "status": "verified" if args.verdict == "approve" else "changes-requested",
        "reviewer": args.reviewer, "reviewer_id": args.reviewer_id, "reviewer_kind": args.kind,
        "model": args.model, "verdict": args.verdict, "summary": args.summary,
        "evidence": fingerprints(case, args.evidence), "reviewed_at": now,
    }
