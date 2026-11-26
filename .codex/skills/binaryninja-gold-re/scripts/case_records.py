"""Local evidence, prior assessments and storage inspection."""

import hashlib
import json
import os
from pathlib import Path


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bounded_excerpt(case, relative, offset, limit):
    path = inside(case, relative)
    if not path.is_file():
        raise ValueError("evidence must be a regular file")
    if offset < 0 or not 1 <= limit <= 8192:
        raise ValueError("offset must be nonnegative and limit must be 1–8192 bytes")
    with path.open("rb") as handle:
        handle.seek(offset)
        raw = handle.read(limit + 1)
    return {
        "path": str(path.relative_to(case)),
        "offset": offset,
        "next_offset": offset + limit if len(raw) > limit else None,
        "text": raw[:limit].decode("utf-8", errors="replace"),
    }


def inside(case, relative):
    path = (case / relative).resolve()
    if not path.is_relative_to(case):
        raise ValueError(f"path must be inside the case: {relative}")
    return path


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def case_dirs(root):
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not name.startswith(".") and name not in {
            "binja", "claims", "evidence", "files", "gold", "reports", "sample", "triage", "work",
        })
        if "case.json" in files:
            yield Path(folder)


def candidate(case, sha256):
    index = case / "hunting" / "candidates.json"
    if index.is_file():
        return read(index)["candidates"].get(sha256)
    return None


def checked_reference(case, path, sha256=None):
    if path is None:
        return None
    try:
        resolved = inside(case, path)
        if not resolved.is_file():
            status = "missing"
        elif sha256 and file_digest(resolved) != sha256:
            status = "digest-mismatch"
        else:
            status = "available"
    except (OSError, ValueError):
        status = "unavailable"
    return {"path": path, "status": status}


def cross_case_lookup(sha256, root):
    result = []
    for case in case_dirs(root):
        entry = candidate(case, sha256)
        primary = read(case / "case.json").get("sha256") == sha256
        if not primary and entry is None:
            continue
        entry = entry or {}
        sample = "sample/original.bin" if primary else entry.get("local_sample")
        result.append({
            "case": str(case),
            "primary_sample": primary,
            "candidate": entry,
            "sample": checked_reference(case, sample, sha256),
            "assessment": checked_reference(case, entry.get("assessment"), entry.get("assessment_sha256")),
        })
    return result


def values(data):
    if isinstance(data, str):
        yield data
    elif isinstance(data, list):
        for item in data:
            yield from values(item)
    elif isinstance(data, dict):
        for item in data.values():
            yield from values(item)


def case_references(case):
    metadata = [case / "case.json", case / "index.json", case / "hunting" / "candidates.json"]
    for folder in ("tasks", "findings", "reviews", "hunting/jobs", "hunting/rules", "gold/manifests"):
        metadata.extend((case / folder).rglob("*.json"))
    referenced = set()
    for path in metadata:
        if not path.is_file() or path.is_symlink():
            continue
        for value in values(read(path)):
            try:
                target = inside(case, value)
                if target.is_file():
                    referenced.add(target)
            except (OSError, ValueError):
                continue
    for active_file in ("gold/gold.bndb", "gold/previous.bndb", "sample/original.bin"):
        if (case / active_file).is_file():
            referenced.add(case / active_file)
    return referenced


def storage_inventory(root, limit):
    if not 1 <= limit <= 250:
        raise ValueError("limit must be between 1 and 250")
    if not root.is_dir():
        raise ValueError(f"no cases directory: {root}")
    cases = list(case_dirs(root))
    referenced = {str(path.relative_to(root)) for case in cases for path in case_references(case)}
    gold_dirs = {case / "gold" for case in cases}
    by_size = {}
    unreferenced_gold = []
    file_count = 0
    total_bytes = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if not name.startswith("."))
        for name in sorted(files):
            path = Path(folder) / name
            if path.is_symlink() or not path.is_file() or name.startswith("."):
                continue
            size = path.stat().st_size
            by_size.setdefault(size, []).append(path)
            file_count += 1
            total_bytes += size
            relative = str(path.relative_to(root))
            if path.parent in gold_dirs and ".bndb" in path.name and relative not in referenced:
                unreferenced_gold.append(relative)
    duplicates = []
    for size, paths in by_size.items():
        if size == 0 or len(paths) < 2:
            continue
        hashes = {}
        for path in paths:
            hashes.setdefault(file_digest(path), []).append(path)
        for digest, matches in hashes.items():
            if len(matches) > 1:
                physical = {(path.stat().st_dev, path.stat().st_ino) for path in matches}
                duplicates.append({
                    "sha256": digest, "bytes_each": size, "path_count": len(matches),
                    "physical_copies": len(physical),
                    "paths": [str(path.relative_to(root)) for path in matches[:limit]],
                })
    return {
        "root": str(root),
        "cases": len(cases),
        "files": file_count,
        "bytes": total_bytes,
        "reference_scope": "case index, candidate index, task, finding and review records, hunt and gold manifests",
        "referenced_count": len(referenced),
        "referenced_examples": sorted(referenced)[:limit],
        "duplicate_group_count": len(duplicates),
        "duplicate_examples": duplicates[:limit],
        "archive_candidate_count": len(unreferenced_gold),
        "archive_candidates": unreferenced_gold[:limit],
    }
