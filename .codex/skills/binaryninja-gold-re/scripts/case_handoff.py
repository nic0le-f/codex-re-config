#!/usr/bin/env python3
"""Find prior case work and record task handoffs without reading transcripts."""

import argparse
import fcntl
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import tempfile


def read_json(path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def write_json(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(record, stream, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def task_id(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", value):
        raise argparse.ArgumentTypeError("use 1–80 lowercase letters, digits, or hyphens")
    return value


def sha256(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("supply a full SHA-256")
    return value.lower()


def import_hits(case, job_id):
    index_path = case / "hunting" / "candidates.json"
    job = read_json(case / "hunting" / "jobs" / f"{job_id}.json")
    if job["job_id"] != job_id:
        raise ValueError("job ID differs from its record")
    hit_path = (case / job["hit_list"]).resolve()
    if not hit_path.is_relative_to(case):
        raise ValueError("hit list must be inside the case")
    hashes = {sha256(value) for value in hit_path.read_text(encoding="utf-8").split()}
    if len(hashes) != job["hits"]:
        raise ValueError("unique hashes in hit list differ from the recorded hit count")
    with index_path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = read_json(index_path) if index_path.exists() else {"schema_version": 1, "candidates": {}}
        candidates = data["candidates"]
        added = 0
        linked = 0
        for digest in sorted(hashes):
            if digest not in candidates:
                candidates[digest] = {"jobs": [], "disposition": "pending-assessment"}
                added += 1
            jobs = candidates[digest].setdefault("jobs", [])
            if job_id not in jobs:
                jobs.append(job_id)
                linked += 1
        if linked or not index_path.exists():
            write_json(index_path, data)
    return {"job_id": job_id, "hits": len(hashes), "added": added, "linked": linked}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("index", help="show links into the case")
    lookup = commands.add_parser("lookup", help="find a candidate by full SHA-256")
    lookup.add_argument("sha256", type=sha256)
    importer = commands.add_parser("import-hits", help="merge an archived hit list into the candidate index")
    importer.add_argument("job_id", type=task_id)
    task = commands.add_parser("task", help="read the latest task checkpoint")
    task.add_argument("task_id", type=task_id)
    save = commands.add_parser("record-task", help="save or replace a complete task checkpoint")
    save.add_argument("task_id", type=task_id)
    save.add_argument("--session-id", required=True)
    save.add_argument("--scope", required=True)
    save.add_argument("--status", choices=("in-progress", "blocked", "completed"), required=True)
    save.add_argument("--output", action="append", default=[])
    save.add_argument("--evidence", action="append", default=[])
    save.add_argument("--open-question", action="append", default=[])
    save.add_argument("--next-action")
    args = parser.parse_args()
    case = args.case.expanduser().resolve()
    if not (case / "case.json").is_file():
        parser.error(f"no case.json in {case}")
    try:
        if args.command == "index":
            result = read_json(case / "index.json")
        elif args.command == "import-hits":
            result = import_hits(case, args.job_id)
        elif args.command == "lookup":
            candidates = case / "hunting" / "candidates.json"
            entry = read_json(candidates)["candidates"].get(args.sha256) if candidates.is_file() else None
            if entry is None:
                print(f"No candidate record for {args.sha256}")
                return 1
            result = {"sha256": args.sha256, **entry}
        else:
            path = case / "tasks" / f"{args.task_id}.json"
            if args.command == "task":
                result = read_json(path)
            else:
                result = {
                    "task_id": args.task_id,
                    "session_id": args.session_id,
                    "scope": args.scope,
                    "status": args.status,
                    "outputs": args.output,
                    "evidence": args.evidence,
                    "open_questions": args.open_question,
                    "next_action": args.next_action,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                write_json(path, result)
    except (OSError, ValueError, KeyError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
