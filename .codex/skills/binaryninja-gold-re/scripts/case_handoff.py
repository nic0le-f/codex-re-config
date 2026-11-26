#!/usr/bin/env python3
"""Find prior case work and record task handoffs without reading transcripts."""

import argparse
import fcntl
from datetime import date, datetime, timezone
from hashlib import sha256 as digest_sha256
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from case_review import read_review, review_path, review_update, verify_task_review

from case_records import bounded_excerpt, candidate, cross_case_lookup, file_digest, inside, storage_inventory


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


def default_index(manifest):
    return {
        "schema_version": 1,
        "case_sha256": manifest.get("sha256"),
        "case_manifest": "case.json",
        "gold_database": "gold/gold.bndb",
        "main_report": "reports/final.md",
        "hunt_jobs": {},
        "hunt_job_directory": "hunting/jobs",
        "candidate_index": "hunting/candidates.json",
        "task_directory": "tasks",
    }


def case_index(case):
    path = case / "index.json"
    index = read_json(path) if path.is_file() else default_index(read_json(case / "case.json"))
    bundles = (case / "hunting" / "jobs").glob("*/job.json")
    for bundle in sorted(bundles):
        if bundle.parent.name.startswith("."):
            continue
        index.setdefault("hunt_jobs", {}).setdefault(bundle.parent.name, str(bundle.relative_to(case)))
    return index


def start_or_record_task(case, args):
    tasks = case / "tasks"
    path = tasks / f"{args.task_id}.json"
    if args.command == "start-task" and path.is_file():
        # Checkpoints are replaced atomically, so opening an existing task is a read-only operation.
        return {"mode": "resume", "case_index": case_index(case), "task": read_json(path)}
    tasks.mkdir(exist_ok=True)
    with (tasks / ".checkpoint.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = read_json(path) if path.is_file() else {}
        if args.command == "start-task":
            if current:
                return {"mode": "resume", "case_index": case_index(case), "task": current}
            if not all(value and value.strip() for value in (args.scope, args.deliverable, args.done_when)):
                raise ValueError("a new task requires --scope, --deliverable, and --done-when")
            index = case_index(case)
            result = {
                "task_id": args.task_id,
                "session_id": args.session_id,
                "first_session_id": args.session_id,
                "scope": args.scope,
                "task_type": args.task_type,
                "review_required": args.task_type in {"gold-bndb", "family-attribution", "material-report-correction"},
                "deliverable": args.deliverable,
                "done_when": args.done_when,
                "status": "in-progress",
                "outputs": [],
                "evidence": [],
                "open_questions": [],
                "next_action": None,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            write_json(path, result)
            return {"mode": "start", "case_index": index, "task": result}

        result = {
            **current,
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
        if args.status == "completed" and result.get("review_required"):
            (case / "reviews").mkdir(exist_ok=True)
            with (case / "reviews" / ".review.lock").open("a") as review_lock:
                fcntl.flock(review_lock, fcntl.LOCK_SH)
                verify_task_review(case, result)
                write_json(path, result)
        else:
            write_json(path, result)
        return result


def task_id(value):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", value):
        raise argparse.ArgumentTypeError("use 1–80 lowercase letters, digits, or hyphens")
    return value


def sha256(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("supply a full SHA-256")
    return value.lower()


def hunt_job(case, job_id):
    jobs = case / "hunting" / "jobs"
    record = jobs / job_id / "job.json"
    if not record.is_file():
        record = jobs / f"{job_id}.json"
    job = read_json(inside(case, record))
    if job["job_id"] != job_id:
        raise ValueError("job ID differs from its record")
    return job


def hit_hashes(hit_list):
    return {sha256(value) for value in hit_list.decode("utf-8").split()}


def register_rule(case, args):
    content = args.rule.read_bytes()
    if not content or not args.purpose.strip():
        raise ValueError("rule and purpose must be nonempty")
    digest = digest_sha256(content).hexdigest()
    relative = Path("hunting/rules") / args.rule_id
    folder = inside(case, relative)
    folder.mkdir(parents=True, exist_ok=True)
    with (folder / ".rule.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        revision = inside(case, relative / "revisions" / f"{digest}.yar")
        if revision.is_file():
            if revision.read_bytes() != content:
                raise ValueError("existing rule revision has a checksum mismatch")
        else:
            revision.parent.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".rule-", dir=revision.parent) as staging:
                copy = Path(staging) / "revision.yar"
                copy.write_bytes(content)
                copy.replace(revision)
        current = {
            "rule_id": args.rule_id, "purpose": args.purpose,
            "sha256": digest, "path": str(revision.relative_to(case)),
        }
        write_json(folder / "current.json", current)
    return current


def register_hunt(case, args):
    start = date.fromisoformat(args.start_date)
    end = date.fromisoformat(args.end_date)
    if end < start:
        raise ValueError("end date precedes start date")
    rule = args.rule.read_bytes()
    hit_list = args.hit_list.read_bytes()
    hashes = hit_hashes(hit_list)
    if args.expected_count is not None and len(hashes) != args.expected_count:
        raise ValueError("unique hashes in hit list differ from the expected hit count")
    if not rule or not args.service.strip() or not args.scope.strip():
        raise ValueError("rule, service, and scope must be nonempty")

    relative = Path("hunting") / "jobs" / args.job_id
    bundle = inside(case, relative)
    bundle.parent.mkdir(parents=True, exist_ok=True)
    job = {
        "schema_version": 1,
        "job_id": args.job_id,
        "service": args.service,
        "scope": args.scope,
        "start_date": start.isoformat(),
        "end_date": end.isoformat(),
        "rule": str(relative / "rule.yar"),
        "rule_sha256": digest_sha256(rule).hexdigest(),
        "hit_list": str(relative / "hits.txt"),
        "hit_list_sha256": digest_sha256(hit_list).hexdigest(),
        "hits": len(hashes),
    }
    with (bundle.parent / ".register.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if bundle.with_suffix(".json").exists():
            raise ValueError("job ID belongs to a legacy record")
        if bundle.exists():
            if hunt_job(case, args.job_id) != job:
                raise ValueError("job ID is already registered with different inputs")
            if inside(case, job["rule"]).read_bytes() != rule:
                raise ValueError("archived rule differs from registered input")
        else:
            with tempfile.TemporaryDirectory(prefix=".register-", dir=bundle.parent) as staging:
                staged_bundle = Path(staging) / "job"
                staged_bundle.mkdir()
                (staged_bundle / "rule.yar").write_bytes(rule)
                (staged_bundle / "hits.txt").write_bytes(hit_list)
                write_json(staged_bundle / "job.json", job)
                staged_bundle.replace(bundle)
    return import_hits(case, args.job_id)


def import_hits(case, job_id):
    index_path = inside(case, "hunting/candidates.json")
    job = hunt_job(case, job_id)
    raw_hits = inside(case, job["hit_list"]).read_bytes()
    if job.get("hit_list_sha256") and digest_sha256(raw_hits).hexdigest() != job["hit_list_sha256"]:
        raise ValueError("archived hit list differs from registered input")
    hashes = hit_hashes(raw_hits)
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
    assessed = sorted(digest for digest in hashes if candidates[digest].get("assessment"))
    return {
        "job_id": job_id, "hits": len(hashes), "added": added, "linked": linked,
        "assessed": len(assessed), "assessed_examples": assessed[:20],
    }


def record_assessment(case, args):
    assessment = inside(case, args.assessment)
    if not assessment.is_file():
        raise ValueError("assessment must identify a case-local report file")
    index_path = inside(case, "hunting/candidates.json")
    index_path.parent.mkdir(parents=True, exist_ok=True)
    with index_path.with_suffix(".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        data = read_json(index_path) if index_path.exists() else {"schema_version": 1, "candidates": {}}
        entry = data["candidates"].setdefault(args.sha256, {"jobs": []})
        entry.update({
            "disposition": args.disposition,
            "assessment": str(assessment.relative_to(case)),
            "assessment_sha256": file_digest(assessment),
        })
        if args.sample:
            sample = inside(case, args.sample)
            if not sample.is_file() or file_digest(sample) != args.sha256:
                raise ValueError("local sample does not match the candidate SHA-256")
            entry["local_sample"] = str(sample.relative_to(case))
        write_json(index_path, data)
    return {"sha256": args.sha256, **entry}


def record_finding(case, args):
    evidence = []
    for value in args.evidence:
        path = inside(case, value)
        if not path.is_file():
            raise ValueError(f"finding evidence does not exist: {value}")
        evidence.append({"path": str(path.relative_to(case)), "sha256": file_digest(path)})
    if not args.summary.strip():
        raise ValueError("finding summary must be nonempty")
    folder = inside(case, "findings")
    folder.mkdir(exist_ok=True)
    record = {
        "finding_id": args.finding_id,
        "summary": args.summary,
        "evidence": evidence,
        "supersedes": args.supersedes,
    }
    path = inside(case, folder / f"{args.finding_id}.json")
    with (folder / ".findings.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        history = findings(case)
        if path.is_file():
            if read_json(path) == record:
                return record
            raise ValueError("finding already exists with different content. Use a new finding ID")
        if args.supersedes and args.supersedes not in {entry["finding_id"] for entry in history["current"]}:
            raise ValueError("--supersedes must identify a current finding")
        write_json(path, record)
    return record


def findings(case):
    records = [read_json(path) for path in sorted((case / "findings").glob("*.json"))]
    superseded = {entry["supersedes"] for entry in records}
    return {
        "current": [entry for entry in records if entry["finding_id"] not in superseded],
        "history": records,
    }


def validate_rule(case, args):
    job = hunt_job(case, args.job_id)
    rule = job["rule"]
    digest = job.get("rule_sha256")
    if isinstance(rule, dict):  # legacy records
        digest = rule["sha256"]
        rule = rule["path"]
    path = inside(case, rule)
    original = path.read_bytes()
    if digest_sha256(original).hexdigest() != digest:
        raise ValueError("archived rule checksum does not match its job")
    # A frozen rule must be independently reproducible without external includes.
    if re.search(rb'\binclude\s*"', original):
        raise ValueError("rule validation requires a standalone rule without include directives")

    def yara(*command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError(result.stderr.strip()[:2048] or "YARA command failed")
        return result.stdout.strip()

    version = yara("yara", "--version")
    checks = []
    with tempfile.TemporaryDirectory(prefix="case-yara-") as staging:
        source = Path(staging) / "rule.yar"
        source.write_bytes(original)
        compiled = str(Path(staging) / "rule.compiled")
        yara("yarac", str(source), compiled)
        for expected, inputs in ((True, args.positive), (False, args.negative)):
            for fixture in inputs:
                fixture = fixture.resolve()
                if not fixture.is_file():
                    raise ValueError(f"validation input must be a regular file: {fixture}")
                before = file_digest(fixture)
                matched = bool(int(yara("yara", "-C", "-c", compiled, str(fixture))))
                if file_digest(fixture) != before:
                    raise ValueError(f"validation input changed: {fixture}")
                checks.append({"file": fixture.name, "sha256": before, "expected": expected, "matched": matched})

    result = {
        "job_id": args.job_id, "yara_version": version, "rule_sha256": digest,
        "passed": all(row["expected"] == row["matched"] for row in checks),
        "checks": checks,
    }
    key = digest_sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
    output = inside(case, Path("hunting/validation") / f"{args.job_id}-{key}.json")
    write_json(output, result)
    return {"passed": result["passed"], "checks": len(checks), "record": str(output.relative_to(case))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("index", help="show links into the case")
    lookup = commands.add_parser("lookup", help="find a candidate by full SHA-256")
    lookup.add_argument("sha256", type=sha256)
    lookup.add_argument("--cases-dir", type=Path, help="also read prior assessments in these case directories")
    assessment = commands.add_parser("record-assessment", help="record a case-local candidate disposition")
    assessment.add_argument("sha256", type=sha256)
    assessment.add_argument("--disposition", type=task_id, required=True)
    assessment.add_argument("--assessment", required=True)
    assessment.add_argument("--sample")
    excerpt = commands.add_parser("evidence", help="read a bounded byte excerpt from an evidence file")
    excerpt.add_argument("path")
    excerpt.add_argument("--offset", type=int, default=0)
    excerpt.add_argument("--limit", type=int, default=2048)
    finding = commands.add_parser("record-finding", help="record a verified finding linked to local evidence")
    finding.add_argument("finding_id", type=task_id)
    finding.add_argument("--summary", required=True)
    finding.add_argument("--evidence", required=True, action="append")
    finding.add_argument("--supersedes", type=task_id)
    commands.add_parser("findings", help="show current findings and their history")
    validate = commands.add_parser("validate-rule", help="validate a frozen rule against local fixtures")
    validate.add_argument("job_id", type=task_id)
    validate.add_argument("--positive", type=Path, action="append", required=True)
    validate.add_argument("--negative", type=Path, action="append", required=True)
    inventory = commands.add_parser("inventory", help="inventory local artifacts without moving them")
    inventory.add_argument("--limit", type=int, default=50)
    inventory.add_argument("--cases-dir", type=Path, help="inventory the entire case root")
    revision = commands.add_parser("register-rule", help="record the purpose and current revision of a local rule")
    revision.add_argument("rule_id", type=task_id)
    revision.add_argument("--rule", type=Path, required=True)
    revision.add_argument("--purpose", required=True)
    register = commands.add_parser("register-hunt", help="archive and import a local hunt export")
    register.add_argument("job_id", type=task_id)
    register.add_argument("--service", required=True)
    register.add_argument("--scope", required=True)
    register.add_argument("--start-date", required=True)
    register.add_argument("--end-date", required=True)
    register.add_argument("--rule", type=Path, required=True)
    register.add_argument("--hit-list", type=Path, required=True)
    register.add_argument("--expected-count", type=int)
    importer = commands.add_parser("import-hits", help="merge an archived hit list into the candidate index")
    importer.add_argument("job_id", type=task_id)
    start = commands.add_parser("start-task", help="open a checkpoint or start a task")
    start.add_argument("task_id", type=task_id)
    start.add_argument("--session-id", default=os.getenv("CODEX_THREAD_ID") or os.getenv("CODEX_SESSION_ID"))
    start.add_argument("--scope")
    start.add_argument("--task-type", choices=("re", "triage", "hunting", "yara",
                       "gold-bndb", "family-attribution", "material-report-correction"))
    start.add_argument("--deliverable")
    start.add_argument("--done-when")
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
    request = commands.add_parser("request-review", help="freeze the current gold or task inputs for review")
    request.add_argument("subject", type=task_id)
    request.add_argument("--session-id", default=os.getenv("CODEX_THREAD_ID") or os.getenv("CODEX_SESSION_ID"))
    verdict = commands.add_parser("record-review", help="record an independent verdict for approved inputs")
    verdict.add_argument("subject", type=task_id)
    verdict.add_argument("--reviewer", required=True)
    verdict.add_argument("--reviewer-id", default=os.getenv("CODEX_THREAD_ID") or os.getenv("CODEX_SESSION_ID"))
    verdict.add_argument("--kind", choices=("subagent", "session", "human"), required=True)
    verdict.add_argument("--model")
    verdict.add_argument("--verdict", choices=("approve", "request-changes"), required=True)
    verdict.add_argument("--evidence", action="append", required=True)
    verdict.add_argument("--summary", required=True)
    args = parser.parse_args()
    if args.command in {"task", "start-task", "record-task"} and args.task_id == "gold":
        parser.error("gold is reserved for case-level gold review")
    case = args.case.expanduser().resolve()
    if not (case / "case.json").is_file():
        parser.error(f"no case.json in {case}")
    try:
        if args.command == "index":
            result = case_index(case)
        elif args.command == "register-rule":
            result = register_rule(case, args)
        elif args.command == "register-hunt":
            result = register_hunt(case, args)
        elif args.command == "import-hits":
            result = import_hits(case, args.job_id)
        elif args.command == "lookup":
            entry = candidate(case, args.sha256)
            if args.cases_dir is not None:
                root = args.cases_dir.expanduser().resolve()
                if not root.is_dir():
                    raise ValueError(f"no cases directory: {root}")
                result = {"sha256": args.sha256, "local": entry, "matches": cross_case_lookup(args.sha256, root)}
            elif entry is None:
                print(f"No candidate record for {args.sha256}")
                return 1
            else:
                result = {"sha256": args.sha256, **entry}
        elif args.command == "record-assessment":
            result = record_assessment(case, args)
        elif args.command == "evidence":
            result = bounded_excerpt(case, args.path, args.offset, args.limit)
        elif args.command == "record-finding":
            result = record_finding(case, args)
        elif args.command == "findings":
            result = findings(case)
        elif args.command == "validate-rule":
            result = validate_rule(case, args)
        elif args.command == "inventory":
            root = args.cases_dir.expanduser().resolve() if args.cases_dir else case
            result = storage_inventory(root, args.limit)
        elif args.command in {"request-review", "record-review"}:
            path = review_path(case, args.subject)
            path.parent.mkdir(exist_ok=True)
            with (path.parent / ".review.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                result = review_update(case, args, read_review(case, args.subject))
                write_json(path, result)
        elif args.command == "task":
            result = read_json(case / "tasks" / f"{args.task_id}.json")
        else:
            result = start_or_record_task(case, args)
    except (OSError, ValueError, KeyError, argparse.ArgumentTypeError, subprocess.TimeoutExpired) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))
    return int(args.command == "validate-rule" and not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
