import json
from pathlib import Path
import subprocess
import sys
import unittest

from audit import run_audit, utc

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"


class AuditTests(unittest.TestCase):
    def run_example(self, name):
        return run_audit(*( (DEMO / file).read_bytes()
                            for file in (name, "sources.csv", "policy.json")))

    def test_clean_example(self):
        result = self.run_example("clean.csv")
        self.assertTrue(result["passed"])
        self.assertEqual(sum(result["samples_by_split"].values()), 5)
        self.assertEqual(result["findings"], [])

    def test_leaky_example_exposes_independent_findings(self):
        result = self.run_example("leaky.csv")
        self.assertFalse(result["passed"])
        self.assertEqual(result["findings_by_check"], {
            "cutoff_outside_partition": 1, "future_feature": 1, "label_predates_cutoff": 1,
            "label_unavailable_at_freeze": 1, "shared_entity": 2, "shared_payload": 2,
            "undeclared_source": 1,
        })
        payload = [x["row_id"] for x in result["findings"] if x["check_name"] == "shared_payload"]
        self.assertEqual(set(payload), {"r2", "r4"})

    def test_timezone_normalization(self):
        self.assertEqual(utc("2026-04-30T05:30:00+05:30"), utc("2026-04-30T00:00:00Z"))
        with self.assertRaises(ValueError):
            utc("2026-04-30T00:00:00")

    def test_missing_split_rejected(self):
        records = (DEMO / "clean.csv").read_text(encoding="utf-8").splitlines()
        subset = "\n".join(row for row in records if ",test," not in row).encode()
        with self.assertRaisesRegex(ValueError, "every split"):
            run_audit(subset, (DEMO / "sources.csv").read_bytes(), (DEMO / "policy.json").read_bytes())

    def test_cli_exit_codes_and_determinism(self):
        def call(dataset):
            return subprocess.run([sys.executable, "audit.py", "demo/" + dataset, "demo/sources.csv",
                                   "demo/policy.json"], cwd=ROOT, text=True, capture_output=True)
        clean = call("clean.csv")
        bad = call("leaky.csv")
        self.assertEqual((clean.returncode, bad.returncode, call("missing.csv").returncode), (0, 2, 1))
        self.assertEqual(bad.stdout, call("leaky.csv").stdout)
        self.assertEqual(len(json.loads(bad.stdout)["input_sha256"]["dataset"]), 64)

    def test_bad_policy_schema(self):
        with self.assertRaisesRegex(ValueError, "policy requires"):
            run_audit(b"", b"", b"{}")

