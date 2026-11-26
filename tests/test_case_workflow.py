"""Regression tests for local case and hunt metadata."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / ".codex/skills/binaryninja-gold-re/scripts"
sys.path.insert(0, str(SCRIPTS))
import case_handoff


def call(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)],
                          text=True, capture_output=True)


class CaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.cases = self.root / "cases"
        self.sample = self.root / "fixture.bin"
        self.sample.write_bytes(b"benign fixture")
        self.digest = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        result = self.intake(self.sample)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.case = Path(result.stdout.strip())

    def intake(self, sample):
        return call("bngold_case.py", "init", sample, "--cases-dir", self.cases)

    def command(self, *args, status=0):
        result = call("case_handoff.py", self.case, *args)
        self.assertEqual(result.returncode, status, result.stderr)
        return json.loads(result.stdout) if result.stdout else None

    def inputs(self):
        rule = self.root / "rule.yar"
        rule.write_text('rule regression_fixture { strings: $marker = "benign marker" condition: $marker }\n')
        hits = self.root / "hits.txt"
        hits.write_text(f"{self.digest}\n{'a' * 64}\n")
        return rule, hits

    def register(self, job, rule, hits, *, status=0, expected_count=2):
        return self.command("register-hunt", job, "--service", "local-export", "--scope", "fixture scope",
                            "--start-date", "2026-01-01", "--end-date", "2026-01-31",
                            "--rule", rule, "--hit-list", hits, "--expected-count", expected_count, status=status)

    def test_intake_reuses_alias_and_preserves_annotations(self):
        alias = self.root / "renamed.bin"
        alias.write_bytes(self.sample.read_bytes())
        manifest = self.case / "case.json"
        data = json.loads(manifest.read_text())
        data["note"] = "preserve this metadata"
        manifest.write_text(json.dumps(data))
        with ThreadPoolExecutor() as pool:
            results = list(pool.map(self.intake, [alias] * 4))
        self.assertTrue(all(result.stdout.strip() == str(self.case) for result in results))
        self.assertEqual(json.loads(manifest.read_text())["note"], data["note"])
        clone = self.cases / "legacy-case"
        shutil.copytree(self.case, clone)
        failure = self.intake(alias)
        self.assertNotEqual(failure.returncode, 0)
        self.assertIn(str(clone), failure.stderr)

    def test_checkpoint_concurrent_start_and_resume(self):
        args = ("start-task", "review", "--session-id", "fixture", "--scope", "local",
                "--deliverable", "report", "--done-when", "verified")
        with ThreadPoolExecutor() as pool:
            results = list(pool.map(lambda _: self.command(*args), range(4)))
        self.assertEqual([entry["mode"] for entry in results].count("start"), 1)
        self.command("record-task", "review", "--session-id", "second", "--scope", "local",
                     "--status", "completed", "--output", "reports/result.md", "--evidence", "evidence/example.txt")
        checkpoint = self.command("start-task", "review")["task"]
        self.assertEqual(checkpoint["deliverable"], "report")
        self.assertEqual(checkpoint["outputs"], ["reports/result.md"])
        self.assertEqual(checkpoint["evidence"], ["evidence/example.txt"])

    def test_existing_checkpoint_resumes_without_write_lock(self):
        started = self.command("start-task", "read-only", "--session-id", "fixture",
                               "--scope", "review", "--deliverable", "report",
                               "--done-when", "reviewed")
        lock = self.case / "tasks/.checkpoint.lock"
        lock.unlink()
        path = self.case / "tasks/read-only.json"
        original = path.read_bytes()
        resumed = self.command("start-task", "read-only")
        self.assertEqual(resumed["mode"], "resume")
        self.assertEqual(resumed["task"], started["task"])
        self.assertFalse(lock.exists())
        self.assertEqual(path.read_bytes(), original)

    def test_hunt_archive_retry_overlap_and_conflict(self):
        rule, hits = self.inputs()
        before = rule.read_bytes()
        first = self.register("job-one", rule, hits)
        self.assertEqual(first["added"], 2)
        index = self.case / "hunting/candidates.json"
        data = json.loads(index.read_text())
        data["candidates"][self.digest]["assessment"] = "reports/result.md"
        index.write_text(json.dumps(data))
        self.assertEqual(self.register("job-one", rule, hits)["linked"], 0)
        rule.write_text("rule changed { condition: true }")
        self.assertIsNone(self.register("job-one", rule, hits, status=2))
        second = self.register("job-two", rule, hits)
        self.assertEqual(second["assessed"], 1)
        candidate = self.command("lookup", self.digest)
        self.assertEqual(candidate["jobs"], ["job-one", "job-two"])
        self.assertEqual(candidate["assessment"], "reports/result.md")
        self.assertEqual((self.case / "hunting/jobs/job-one/rule.yar").read_bytes(), before)
        self.assertIn("job-two", self.command("index")["hunt_jobs"])

    def test_registration_recovers_from_failed_projection(self):
        rule, hits = self.inputs()
        args = SimpleNamespace(job_id="recover", service="local-export", scope="test",
                               start_date="2026-01-01", end_date="2026-02-01",
                               rule=rule, hit_list=hits, expected_count=2)
        original = case_handoff.write_json
        index = self.case / "hunting/candidates.json"
        before = index.read_bytes()

        def fail_projection(path, data):
            if path == index:
                raise OSError("simulated write failure")
            original(path, data)

        with patch.object(case_handoff, "write_json", side_effect=fail_projection):
            with self.assertRaisesRegex(OSError, "simulated"):
                case_handoff.register_hunt(self.case, args)
        self.assertEqual(index.read_bytes(), before)
        self.assertTrue((self.case / "hunting/jobs/recover/job.json").is_file())
        self.assertEqual(case_handoff.register_hunt(self.case, args)["linked"], 2)

    def test_rejects_bad_hash_count_and_paths(self):
        rule, hits = self.inputs()
        self.assertIsNone(self.register("count", rule, hits, status=2, expected_count=3))
        hits.write_text("not-a-hash")
        self.assertIsNone(self.register("bad-hash", rule, hits, status=2))
        self.command("evidence", "../../outside", status=2)
        self.command("lookup", "short", status=2)
        self.assertEqual(list((self.case / "hunting/jobs").glob("*/job.json")), [])

    def test_bounded_evidence_and_findings_supersession(self):
        relative = "evidence/large.txt"
        text = self.case / relative
        text.write_bytes(b"0123456789" * 100_000)
        excerpt = self.command("evidence", relative, "--offset", 7, "--limit", 6)
        self.assertEqual(excerpt["text"], "789012")
        self.assertEqual(excerpt["next_offset"], 13)
        self.assertEqual(text.stat().st_size, 1_000_000)
        self.command("record-finding", "old", "--summary", "initial", "--evidence", relative)
        self.command("record-finding", "new", "--summary", "corrected", "--evidence", relative, "--supersedes", "old")
        findings = self.command("findings")
        self.assertEqual([entry["finding_id"] for entry in findings["current"]], ["new"])
        self.assertEqual({entry["finding_id"] for entry in findings["history"]}, {"old", "new"})
        report = call("bngold_report.py", self.case)
        self.assertEqual(report.returncode, 0, report.stderr)
        self.assertIn("../findings/new.json", (self.case / "reports/final.md").read_text())

    def test_cross_case_lookup_retains_local_verdict_and_detects_missing_evidence(self):
        other = self.cases / "other-case"
        shutil.copytree(self.case, other)
        (other / "sample/original.bin").unlink()
        rule, hits = self.inputs()
        self.register("shared", rule, hits)
        index = self.case / "hunting/candidates.json"
        data = json.loads(index.read_text())
        row = data["candidates"][self.digest]
        row.update({"assessment": "reports/result.md", "disposition": "related"})
        index.write_text(json.dumps(data))
        matches = self.command("lookup", self.digest, "--cases-dir", self.cases)["matches"]
        by_case = {Path(entry["case"]).name: entry for entry in matches}
        self.assertEqual(by_case["other-case"]["sample"]["status"], "missing")
        self.assertEqual(by_case[self.case.name]["candidate"]["disposition"], "related")
        self.assertEqual(by_case[self.case.name]["assessment"]["status"], "missing")

    def test_canonical_rule_retains_historical_revision(self):
        rule, hits = self.inputs()
        before = rule.read_bytes()
        first = self.command("register-rule", "fixture-rule", "--rule", rule, "--purpose", "benign fixture")
        revision = self.case / first["path"]
        self.register("stable-job", revision, hits)
        rule.write_text("rule changed { condition: false }")
        second = self.command("register-rule", "fixture-rule", "--rule", rule, "--purpose", "benign fixture")
        self.assertNotEqual(first["sha256"], second["sha256"])
        self.assertEqual(revision.read_bytes(), before)
        self.assertEqual((self.case / "hunting/jobs/stable-job/rule.yar").read_bytes(), before)

    def test_assessment_report_fingerprint_reports_stale_data(self):
        report = self.case / "reports/review.txt"
        report.write_text("A signed-off fixture assessment")
        self.command("record-assessment", self.digest, "--disposition", "unresolved",
                     "--assessment", "reports/review.txt", "--sample", "sample/original.bin")
        result = self.command("lookup", self.digest, "--cases-dir", self.cases)["matches"][0]
        self.assertEqual(result["assessment"]["status"], "available")
        report.write_text("Changed without updating the assessment")
        result = self.command("lookup", self.digest, "--cases-dir", self.cases)["matches"][0]
        self.assertEqual(result["assessment"]["status"], "digest-mismatch")

    def test_inventory_distinguishes_references_duplicates_and_archive_candidates(self):
        for name in ("gold.bndb", "paired.bndb", "older.bndb"):
            (self.case / "gold" / name).write_bytes(b"older" if name == "older.bndb" else b"same bytes")
        self.command("record-task", "keep", "--session-id", "fixture", "--scope", "test",
                     "--status", "completed", "--output", "gold/paired.bndb")
        before = sorted(self.case.rglob("*"))
        result = self.command("inventory")
        self.assertIn("gold/paired.bndb", result["referenced_examples"])
        self.assertEqual(result["archive_candidates"], ["gold/older.bndb"])
        self.assertIn("gold/gold.bndb", result["duplicate_examples"][0]["paths"])
        self.assertEqual(sorted(self.case.rglob("*")), before)
        self.assertEqual(self.command("inventory", "--cases-dir", self.cases)["cases"], 1)

    @unittest.skipUnless(shutil.which("yara") and shutil.which("yarac"), "YARA executables unavailable")
    def test_yara_validates_archived_revision_and_records_failures(self):
        rule, hits = self.inputs()
        self.register("validate", rule, hits)
        rule.write_text("rule changed { condition: false }")
        pos = self.root / "positive"
        pos.write_bytes(b"a benign marker")
        result = self.command("validate-rule", "validate", "--positive", pos, "--negative", self.sample)
        self.assertTrue(result["passed"])
        saved = json.loads((self.case / result["record"]).read_text())
        self.assertEqual(saved["checks"][0]["matched"], True)
        self.assertTrue(saved["yara_version"])
        failed = self.command("validate-rule", "validate", "--positive", self.sample, "--negative", pos, status=1)
        self.assertFalse(failed["passed"])
        self.assertTrue((self.case / failed["record"]).is_file())
