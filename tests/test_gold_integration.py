"""Optional Binary Ninja regression against a compiled, never executed fixture."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

try:
    import binaryninja as bn
except ImportError:
    bn = None


SCRIPTS = Path(__file__).resolve().parents[1] / ".codex/skills/binaryninja-gold-re/scripts"


def command(script, *args):
    return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)],
                          text=True, capture_output=True)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(bn is not None and shutil.which("cc"), "requires bnpython3 and a C compiler")
class GoldIntegrationTests(unittest.TestCase):
    def test_annotations_requested_coverage_target_and_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.exercise(Path(temporary))

    def run_script(self, script, *args):
        result = command(script, *args)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result

    def exercise(self, root):
        source = root / "fixture.c"
        source.write_text("""int fixture_global = 5;
        void fixture_offset(volatile int *value) { *value += 1; }
        int fixture_sum(int incoming) {
            volatile int adjusted = fixture_global + incoming;
            fixture_offset(&adjusted);
            return adjusted;
        }
        int main(void) { return fixture_sum(2); }
        """)
        fixture = root / "fixture.elf"
        subprocess.run(["cc", "-g", "-O0", "-fno-pie", "-no-pie", str(source), "-o", str(fixture)], check=True)
        result = self.run_script("bngold_case.py", "init", fixture, "--cases-dir", root / "cases")
        case = Path(result.stdout.strip())
        self.run_script("bn_export_facts.py", case)
        base = bn.load(str(case / "binja/base.bndb"))
        try:
            function = base.get_functions_by_name("fixture_sum")[0]
            address = hex(function.start)
            instruction = hex(list(function.instructions)[1][1])
            local = next(item.identifier for item in function.hlil.vars if item.name == "rax")
            symbol = hex(base.get_symbols_by_name("fixture_global")[0].address)
        finally:
            base.file.close()

        def claim(identifier, kind, target, value):
            return {
                "claim_id": identifier, "kind": kind, "target": target, "proposed_value": value,
                "evidence": ["local fixture source"], "status": "accepted",
            }

        claims = [
            claim("outer", "type_definition", "FixtureOuter", "typedef struct FixtureOuter { FixtureInner child; } FixtureOuter;"),
            claim("inner", "type_definition", "FixtureInner", "typedef struct FixtureInner { int value; } FixtureInner;"),
            claim("name", "function_name", address, "mw_fixture_sum"),
            claim("signature", "function_signature", address, "int fixture_sum(int incoming)"),
            claim("local", "local_variable_name", {"function": address, "identifier": local}, "verified_value"),
            claim("data", "data_name", symbol, "mw_fixture_global"),
            claim("comment", "function_comment", address, "returns the adjusted fixture value"),
            claim("instruction", "address_comment", instruction, "fixture instruction"),
            claim("source", "source_file", address, "fixture.c"),
        ]

        def save_claims():
            (case / "claims/claims.jsonl").write_text("".join(f"{json.dumps(row)}\n" for row in claims))
            verdicts = [{"claim_id": row["claim_id"], "status": "accepted"} for row in claims]
            (case / "claims/verdicts.jsonl").write_text("".join(f"{json.dumps(row)}\n" for row in verdicts))

        def approve():
            self.run_script("case_handoff.py", case, "request-review", "gold", "--session-id", "author")
            self.run_script("case_handoff.py", case, "record-review", "gold",
                            "--reviewer", "Fixture reviewer", "--reviewer-id", "reviewer",
                            "--kind", "human", "--verdict", "approve",
                            "--evidence", "case.json", "--summary", "Fixture inputs checked")

        save_claims()
        apply = "bn_apply_claims.py"
        gold = case / "gold/gold.bndb"
        required = [argument for row in claims for argument in ("--require-claim", row["claim_id"])]
        unreviewed = command(apply, case, *required)
        self.assertNotEqual(unreviewed.returncode, 0)
        self.assertFalse(gold.exists())
        approve()
        self.run_script("case_handoff.py", case, "start-task", "fixture-gold", "--session-id",
                        "author", "--task-type", "gold-bndb", "--scope", "Fixture",
                        "--deliverable", "Gold", "--done-when", "Verified")
        self.run_script(apply, case, *required)
        self.run_script("case_handoff.py", case, "record-task", "fixture-gold", "--session-id",
                        "author", "--scope", "Fixture", "--status", "completed", "--output", "gold/gold.bndb")
        first = digest(gold)
        self.assertIn("requested_claims", json.loads((case / "gold/manifests" / f"{first}.json").read_text()))
        saved = bn.load(str(gold))
        try:
            function = saved.get_function_at(int(address, 0))
            self.assertEqual(function.name, "mw_fixture_sum")
            self.assertEqual(function.type.parameters[0].name, "incoming")
            self.assertIn("verified_value", {item.name for item in function.hlil.vars})
            self.assertEqual(saved.get_symbol_at(int(symbol, 0)).name, "mw_fixture_global")
            self.assertIsNotNone(saved.get_type_by_name("FixtureInner"))
            self.assertIsNotNone(saved.get_type_by_name("FixtureOuter"))
            saved_comment = saved.get_comment_at(int(address, 0))
            self.assertIn("returns the adjusted fixture value", saved_comment)
            self.assertIn("Recovered source file: fixture.c", saved_comment)
            self.assertEqual(saved.get_comment_at(int(instruction, 0)), "fixture instruction")
        finally:
            saved.file.close()

        failure = command(apply, case, "--require-claim", "missing")
        self.assertNotEqual(failure.returncode, 0)
        self.assertEqual(digest(gold), first)
        readiness = json.loads((case / "reports/gold_readiness.json").read_text())
        self.assertEqual(readiness["unresolved_claims"], ["missing"])

        claims[2]["proposed_value"] = "mw_fixture_sum_revised"
        save_claims()
        stale = command(apply, case, *required)
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn("stale", stale.stderr)
        self.assertEqual(digest(gold), first)
        approve()
        self.run_script(apply, case, *required)
        second = digest(gold)
        self.assertNotEqual(first, second)
        wrong_rollback = command(apply, case, "--rollback", "a" * 64)
        self.assertNotEqual(wrong_rollback.returncode, 0)
        self.assertEqual(digest(gold), second)
        manifest = (case / "case.json").read_bytes()
        changed = root / "payload.elf"
        changed.write_bytes(fixture.read_bytes() + b"different benign data")
        self.run_script("bngold_case.py", "add-unpacked", case, changed, "--method", "fixture", "--tool", "python")
        rejected_rollback = command(apply, case, "--rollback", first)
        self.assertNotEqual(rejected_rollback.returncode, 0)
        self.assertIn("differs from the current analysis target", rejected_rollback.stderr)
        self.assertEqual(digest(gold), second)
        rejected_export = command("bn_export_facts.py", case)
        self.assertNotEqual(rejected_export.returncode, 0)
        self.assertIn("differs from the current analysis target", rejected_export.stderr)
        approve()
        rejected_apply = command(apply, case)
        self.assertNotEqual(rejected_apply.returncode, 0)
        readiness = json.loads((case / "reports/gold_readiness.json").read_text())
        self.assertEqual(readiness["status"], "failed")
        self.assertIn("differs from the current analysis target", readiness["error"])
        self.assertEqual(digest(gold), second)
        (case / "case.json").write_bytes(manifest)
        self.run_script(apply, case, "--rollback", first)
        self.assertEqual(digest(gold), first)
        self.assertEqual(json.loads((case / "reports/gold_readiness.json").read_text())["status"], "rolled-back")
