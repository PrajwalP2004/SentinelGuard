"""
Dedicated Unit Tests for Phase 5A: Security Retest Agent.

Verifies:
1. Genuinely remediated finding is classified as REMEDIATED with HIGH confidence.
2. Vulnerability that remains present is classified as NOT_REMEDIATED.
3. Partially remediated finding is classified as PARTIALLY_REMEDIATED.
4. Missing target file is classified as NOT_TESTABLE without false remediation claims.
5. Unreadable file or simulated read failure is classified as NOT_TESTABLE.
6. Path traversal attempt is rejected and classified as NOT_TESTABLE.
7. Symlink escaping repository root is rejected and classified as NOT_TESTABLE.
8. Oversized file exceeding inspection ceiling is rejected and classified as NOT_TESTABLE.
9. Remediation plan without corresponding code change is classified as NOT_REMEDIATED.
10. Unrelated security keywords in comments or strings do not cause false positive REMEDIATED status.
11. Unknown finding IDs and unsupported finding types are classified as NOT_TESTABLE.
12. Missing and duplicate finding IDs are safely handled and counted in total_retested.
13. Malformed findings and remediation records (None, non-dict, missing keys) do not crash the agent.
14. Empty inputs and multiple findings targeting the same file are processed correctly.
15. Confidence and regression reporting are truthful and evidence-grounded.
16. Summary counts strictly match total_retested and results are deterministic across repeated runs.
"""

import os
import shutil
import tempfile
import unittest
from typing import Any, Dict, List

from src.phase5a.retest import SecurityRetestAgent


class TestPhase5ASecurityRetestAgent(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_phase5a_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Genuinely Remediated Finding
    # -------------------------------------------------------------------------
    def test_genuinely_remediated_finding(self):
        target_file = os.path.join(self.test_dir, "db.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(
                "import sqlite3\n"
                "def get_user(uid):\n"
                "    con = sqlite3.connect('test.db')\n"
                "    cur = con.cursor()\n"
                "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
                "    return cur.fetchone()\n"
            )

        finding = {
            "finding_id": "RED-SQL-01",
            "title": "SQL Injection",
            "affected_files": ["db.py"],
            "validation_status": "PROBABLE"
        }
        rem = {
            "finding_id": "RED-SQL-01",
            "remediation": "Use parameterized queries with placeholder syntax."
        }

        agent = SecurityRetestAgent(self.test_dir, [finding], [rem])
        res = agent.retest()

        self.assertEqual(res["summary"]["total_retested"], 1)
        self.assertEqual(res["summary"]["remediated"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "REMEDIATED")
        self.assertEqual(record["confidence"], "HIGH")
        self.assertIn("db.py", record["inspected_files"])
        self.assertFalse(record["regression_detected"])

    # -------------------------------------------------------------------------
    # 2. Vulnerability Remains Present
    # -------------------------------------------------------------------------
    def test_vulnerability_remains_present(self):
        target_file = os.path.join(self.test_dir, "db.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(
                "import sqlite3\n"
                "def get_user(uid):\n"
                "    con = sqlite3.connect('test.db')\n"
                "    cur = con.cursor()\n"
                "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
                "    return cur.fetchone()\n"
            )

        finding = {
            "finding_id": "RED-SQL-01",
            "title": "SQL Injection",
            "affected_files": ["db.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["not_remediated"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_REMEDIATED")
        self.assertEqual(record["confidence"], "HIGH")
        self.assertIn("Dynamic SQL formatting detected", record["evidence"])

    # -------------------------------------------------------------------------
    # 3. Partially Remediated Finding
    # -------------------------------------------------------------------------
    def test_partially_remediated_finding(self):
        # RED-INJ-01: hyphen check present, but missing '--' separator
        p0_dir = os.path.join(self.test_dir, "src", "phase0")
        os.makedirs(p0_dir, exist_ok=True)
        target_file = os.path.join(p0_dir, "ingestion.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(
                "def clone_repo(source, target):\n"
                "    if source.startswith('-'): raise ValueError('Invalid source')\n"
                "    subprocess.run(['git', 'clone', source, target])\n"
            )

        finding = {
            "finding_id": "RED-INJ-01",
            "title": "Git Option Injection",
            "affected_files": ["src/phase0/ingestion.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["partially_remediated"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "PARTIALLY_REMEDIATED")
        self.assertIn("Partial Git option defense", record["evidence"])

    # -------------------------------------------------------------------------
    # 4. Missing Target File
    # -------------------------------------------------------------------------
    def test_missing_target_file(self):
        finding = {
            "finding_id": "RED-SQL-01",
            "title": "SQL Injection",
            "affected_files": ["missing/does_not_exist.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["not_testable"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_TESTABLE")
        self.assertIn("MISSING_FILE", record["evidence"])
        self.assertNotEqual(record["final_status"], "REMEDIATED")

    # -------------------------------------------------------------------------
    # 5. Unreadable File or Read Failure
    # -------------------------------------------------------------------------
    def test_unreadable_file_read_failure(self):
        # Target path is a directory instead of a file
        sub_dir = os.path.join(self.test_dir, "dir_as_file.py")
        os.makedirs(sub_dir, exist_ok=True)

        finding = {
            "finding_id": "RED-SECRET-01",
            "title": "Hardcoded Secret",
            "affected_files": ["dir_as_file.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["not_testable"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_TESTABLE")
        self.assertIn("IS_DIRECTORY", record["evidence"])

    # -------------------------------------------------------------------------
    # 6. Path Traversal Attempt
    # -------------------------------------------------------------------------
    def test_path_traversal_attempt(self):
        finding = {
            "finding_id": "RED-CMD-01",
            "title": "Command Execution",
            "affected_files": ["../../etc/shadow", "..\\windows\\system32\\calc.exe"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["not_testable"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_TESTABLE")
        self.assertIn("TRAVERSAL_REJECTED", record["evidence"])

    # -------------------------------------------------------------------------
    # 7. Symlink Escaping Repository Root
    # -------------------------------------------------------------------------
    def test_symlink_escape_rejected(self):
        if not hasattr(os, "symlink"):
            self.skipTest("Platform does not support symlinks")

        # Create an external directory outside self.test_dir
        ext_dir = tempfile.mkdtemp(prefix="ext_outside_")
        ext_file = os.path.join(ext_dir, "outside.py")
        with open(ext_file, "w", encoding="utf-8") as f:
            f.write("import os\nos.system('calc')\n")

        link_path = os.path.join(self.test_dir, "symlink_escape.py")
        try:
            os.symlink(ext_file, link_path)
        except (OSError, NotImplementedError):
            shutil.rmtree(ext_dir, ignore_errors=True)
            self.skipTest("Symlink creation requires administrative privileges on this platform")

        try:
            finding = {
                "finding_id": "RED-CMD-01",
                "affected_files": ["symlink_escape.py"]
            }
            agent = SecurityRetestAgent(self.test_dir, [finding])
            res = agent.retest()

            self.assertEqual(res["summary"]["not_testable"], 1)
            record = res["retest_results"][0]
            self.assertEqual(record["final_status"], "NOT_TESTABLE")
            self.assertIn("TRAVERSAL_REJECTED", record["evidence"])
        finally:
            shutil.rmtree(ext_dir, ignore_errors=True)

    def test_symlink_escape_containment_mocked(self):
        from unittest.mock import patch
        finding = {
            "finding_id": "RED-CMD-01",
            "affected_files": ["symlink_escape_mock.py"]
        }
        agent = SecurityRetestAgent(self.test_dir, [finding])

        # Simulate islink=True, exists=True, isdir=False, and realpath pointing outside root
        with patch("os.path.islink", return_value=True), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.isdir", return_value=False), \
             patch("os.path.realpath", side_effect=lambda p: "C:\\outside\\file.py" if "symlink_escape_mock" in p else agent.root_path):
            res = agent.retest()

        self.assertEqual(res["summary"]["not_testable"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_TESTABLE")
        self.assertIn("TRAVERSAL_REJECTED", record["evidence"])


    # -------------------------------------------------------------------------
    # 8. Oversized File & Bounded-Read Behavior
    # -------------------------------------------------------------------------
    def test_oversized_file_bounded_read(self):
        target_file = os.path.join(self.test_dir, "huge.py")
        # Write small file but temporarily configure agent ceiling to 50 bytes
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("# " + "A" * 200 + "\nimport sqlite3\n")

        finding = {
            "finding_id": "RED-SQL-01",
            "affected_files": ["huge.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        agent.MAX_FILE_SIZE = 50  # Enforce tiny ceiling for test

        res = agent.retest()
        self.assertEqual(res["summary"]["not_testable"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_TESTABLE")
        self.assertIn("OVERSIZED", record["evidence"])

    # -------------------------------------------------------------------------
    # 9. Remediation Recommendation with No Code Change
    # -------------------------------------------------------------------------
    def test_remediation_recommendation_without_code_change(self):
        target_file = os.path.join(self.test_dir, "app.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("import os\nos.system('echo ' + user_input)\n")

        finding = {
            "finding_id": "RED-CMD-01",
            "title": "Command Injection",
            "affected_files": ["app.py"]
        }
        # Blue team suggested a fix, but code remains vulnerable
        rem = {
            "finding_id": "RED-CMD-01",
            "remediation": "Replace os.system with subprocess.run(['echo', user_input], shell=False)."
        }

        agent = SecurityRetestAgent(self.test_dir, [finding], [rem])
        res = agent.retest()

        # Must report NOT_REMEDIATED despite the presence of the remediation recommendation
        self.assertEqual(res["summary"]["not_remediated"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_REMEDIATED")
        self.assertEqual(record["remediation_tested"], rem["remediation"])

    # -------------------------------------------------------------------------
    # 10. False Positives Caused by Unrelated Security Keywords
    # -------------------------------------------------------------------------
    def test_false_positives_unrelated_keywords(self):
        # Deserialization test: code has comment mentioning "sha256" and "hash", but STILL calls pickle.load
        target_file = os.path.join(self.test_dir, "model.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(
                "import pickle\n"
                "# TODO: compute sha256 hash or hmac before loading\n"
                "def load_weights(path):\n"
                "    with open(path, 'rb') as f:\n"
                "        return pickle.load(f)\n"
            )

        finding = {
            "finding_id": "RED-DESER-01",
            "affected_files": ["model.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        # Unrelated keywords in comments must NOT cause false positive REMEDIATED status
        self.assertEqual(res["summary"]["not_remediated"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_REMEDIATED")

        # Output overwrite test: pipeline.py has os.path.abspath, but NO containment check
        target_pipe = os.path.join(self.test_dir, "pipeline.py")
        with open(target_pipe, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "out = os.path.abspath(args.output)\n"
                "with open(out, 'w') as f: f.write('data')\n"
            )

        finding_file = {
            "finding_id": "RED-FILE-01",
            "affected_files": ["pipeline.py"]
        }
        agent_file = SecurityRetestAgent(self.test_dir, [finding_file])
        res_file = agent_file.retest()

        # abspath alone without containment check is NOT_REMEDIATED
        self.assertEqual(res_file["summary"]["not_remediated"], 1)

    # -------------------------------------------------------------------------
    # 11. Unknown Finding IDs and Unsupported Types
    # -------------------------------------------------------------------------
    def test_unknown_and_unsupported_finding_ids(self):
        target_file = os.path.join(self.test_dir, "custom.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("def custom(): pass\n")

        finding = {
            "finding_id": "RED-CUSTOM-999",
            "title": "Custom Weakness",
            "affected_files": ["custom.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["not_testable"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "NOT_TESTABLE")
        self.assertIn("No automated static retest rule implemented", record["result"])

    # -------------------------------------------------------------------------
    # 12. Missing and Duplicate Finding IDs
    # -------------------------------------------------------------------------
    def test_missing_and_duplicate_finding_ids(self):
        target_file = os.path.join(self.test_dir, "db.py")
        with open(target_file, "w", encoding="utf-8") as f:
            f.write("import sqlite3\ncur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n")

        findings = [
            {"title": "Missing ID Finding"},  # Missing ID
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"]},
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"]},  # Duplicate ID
        ]

        agent = SecurityRetestAgent(self.test_dir, findings)
        res = agent.retest()

        # All 3 entries are accounted for
        self.assertEqual(res["summary"]["total_retested"], 3)
        self.assertEqual(res["summary"]["not_testable"], 1)  # Malformed one
        self.assertEqual(res["summary"]["remediated"], 2)   # Both duplicate SQL findings

    # -------------------------------------------------------------------------
    # 13. Malformed Findings and Remediation Records
    # -------------------------------------------------------------------------
    def test_malformed_findings_and_remediations(self):
        malformed_findings = [
            None,
            "string_item",
            [],
            {},
            {"finding_id": None},
            {"finding_id": ""},
            {"finding_id": 123},
        ]
        malformed_remediations = [
            None,
            "junk",
            {"missing_fid": True},
            {"finding_id": None},
        ]

        agent = SecurityRetestAgent(self.test_dir, malformed_findings, malformed_remediations)
        res = agent.retest()

        self.assertEqual(res["summary"]["total_retested"], len(malformed_findings))
        self.assertEqual(res["summary"]["not_testable"], len(malformed_findings))
        for r in res["retest_results"]:
            self.assertEqual(r["final_status"], "NOT_TESTABLE")

    # -------------------------------------------------------------------------
    # 14. Empty Inputs and Multiple Findings for the Same File
    # -------------------------------------------------------------------------
    def test_empty_inputs_and_multiple_findings_same_file(self):
        # Empty input
        agent_empty = SecurityRetestAgent(self.test_dir, [], [])
        res_empty = agent_empty.retest()
        self.assertEqual(res_empty["summary"]["total_retested"], 0)
        self.assertEqual(len(res_empty["retest_results"]), 0)

        # Multiple findings for the same file
        app_file = os.path.join(self.test_dir, "app.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write(
                "import sqlite3, os\n"
                "cur.execute('SELECT * FROM u WHERE id = ?', (1,))\n"  # Remediated SQL
                "os.system('echo ' + input())\n"                       # Unremediated Command
            )

        multi_findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["app.py"]},
            {"finding_id": "RED-CMD-01", "affected_files": ["app.py"]},
        ]

        agent_multi = SecurityRetestAgent(self.test_dir, multi_findings)
        res_multi = agent_multi.retest()

        self.assertEqual(res_multi["summary"]["total_retested"], 2)
        self.assertEqual(res_multi["summary"]["remediated"], 1)
        self.assertEqual(res_multi["summary"]["not_remediated"], 1)

    # -------------------------------------------------------------------------
    # 15. Confidence and Regression Reporting
    # -------------------------------------------------------------------------
    def test_confidence_and_regression_reporting(self):
        app_file = os.path.join(self.test_dir, "server.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write("DEBUG = False\n")

        finding = {
            "finding_id": "RED-DEBUG-01",
            "affected_files": ["server.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        record = res["retest_results"][0]
        self.assertIn(record["confidence"], {"HIGH", "MEDIUM", "LOW"})
        self.assertFalse(record["regression_detected"])
        self.assertEqual(record["regression_test_status"], "NOT_ASSESSED")

    # -------------------------------------------------------------------------
    # 16. Correct Summary Counts & Deterministic Output
    # -------------------------------------------------------------------------
    def test_summary_counts_and_determinism(self):
        app_file = os.path.join(self.test_dir, "app.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write("DEBUG = False\n")

        findings = [
            {"finding_id": "RED-DEBUG-01", "affected_files": ["app.py"]},
            {"finding_id": "RED-SQL-01", "affected_files": ["missing.py"]},
            {"finding_id": "RED-CUSTOM-01", "affected_files": ["app.py"]},
            {"title": "Malformed"},
        ]

        agent1 = SecurityRetestAgent(self.test_dir, findings)
        res1 = agent1.retest()

        agent2 = SecurityRetestAgent(self.test_dir, findings)
        res2 = agent2.retest()

        # Determinism
        self.assertEqual(res1, res2)

        # Summary integrity
        summary = res1["summary"]
        self.assertEqual(summary["total_retested"], len(res1["retest_results"]))
        sum_statuses = (
            summary["remediated"] + summary["partially_remediated"] +
            summary["not_remediated"] + summary["not_testable"] +
            summary["false_positive"]
        )
        self.assertEqual(sum_statuses, summary["total_retested"])

    # -------------------------------------------------------------------------
    # 17. analyze() Method Compatibility
    # -------------------------------------------------------------------------
    def test_analyze_method_interface_compatibility(self):
        finding = {"finding_id": "RED-SQL-01", "affected_files": ["missing.py"]}
        agent = SecurityRetestAgent(self.test_dir, [finding])
        res_retest = agent.retest()
        res_analyze = agent.analyze()
        self.assertEqual(res_retest, res_analyze)

    # -------------------------------------------------------------------------
    # 18. Insufficient Evidence Results in NOT_TESTABLE
    # -------------------------------------------------------------------------
    def test_insufficient_evidence_resulting_in_not_testable(self):
        # Create a file that has no database or command operations
        blank_file = os.path.join(self.test_dir, "blank.py")
        with open(blank_file, "w", encoding="utf-8") as f:
            f.write("# Simple utility without database or command operations\nvalue = 42\n")

        finding_sql = {
            "finding_id": "RED-SQL-01",
            "title": "SQL Injection",
            "affected_files": ["blank.py"]
        }
        finding_cmd = {
            "finding_id": "RED-CMD-01",
            "title": "Command Execution",
            "affected_files": ["blank.py"]
        }

        agent = SecurityRetestAgent(self.test_dir, [finding_sql, finding_cmd])
        res = agent.retest()

        # Both must be NOT_TESTABLE because evidence is insufficient
        self.assertEqual(res["summary"]["not_testable"], 2)
        self.assertEqual(res["summary"]["remediated"], 0)
        for r in res["retest_results"]:
            self.assertEqual(r["final_status"], "NOT_TESTABLE")
            self.assertEqual(r["confidence"], "LOW")
            self.assertIn("No", r["result"])

    # -------------------------------------------------------------------------
    # 19. FALSE_POSITIVE Supported by Explicit Evidence
    # -------------------------------------------------------------------------
    def test_false_positive_supported_by_explicit_evidence(self):
        finding = {
            "finding_id": "RED-CRYPTO-01",
            "title": "Weak Hashing in Cache Digest",
            "affected_files": ["cache.py"],
            "validation_status": "FALSE_POSITIVE",
            "evidence": "MD5 used strictly as a non-security cache digest."
        }

        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()

        self.assertEqual(res["summary"]["false_positive"], 1)
        record = res["retest_results"][0]
        self.assertEqual(record["final_status"], "FALSE_POSITIVE")
        self.assertEqual(record["confidence"], "HIGH")
        self.assertIn("false positive", record["result"].lower())

    # -------------------------------------------------------------------------
    # 20. Absolute Paths Policy and Containment
    # -------------------------------------------------------------------------
    def test_absolute_paths_handling(self):
        # 1. Valid absolute path pointing INSIDE repository root
        inside_file = os.path.join(self.test_dir, "inside.py")
        with open(inside_file, "w", encoding="utf-8") as f:
            f.write("DEBUG = False\n")

        finding_inside = {
            "finding_id": "RED-DEBUG-01",
            "affected_files": [inside_file]  # Absolute path inside repo root
        }
        agent_inside = SecurityRetestAgent(self.test_dir, [finding_inside])
        res_inside = agent_inside.retest()
        self.assertEqual(res_inside["summary"]["remediated"], 1)

        # 2. Absolute path pointing OUTSIDE repository root
        outside_path = "C:\\Windows\\System32\\drivers\\etc\\hosts" if os.name == "nt" else "/etc/passwd"
        finding_outside = {
            "finding_id": "RED-DEBUG-01",
            "affected_files": [outside_path]  # Absolute path outside repo root
        }
        agent_outside = SecurityRetestAgent(self.test_dir, [finding_outside])
        res_outside = agent_outside.retest()
        self.assertEqual(res_outside["summary"]["not_testable"], 1)
        self.assertIn("TRAVERSAL_REJECTED", res_outside["retest_results"][0]["evidence"])

    # -------------------------------------------------------------------------
    # 21. Integration with Actual Phase 3A and Phase 4A Output
    # -------------------------------------------------------------------------
    def test_integration_with_actual_phase3a_and_phase4a_output(self):
        from src.phase3a.red_team import RedTeamSecurityAgent
        from src.phase4a.blue_team import BlueTeamDefensiveAgent

        # Setup vulnerable code in self.test_dir
        srv_file = os.path.join(self.test_dir, "server.py")
        with open(srv_file, "w", encoding="utf-8") as f:
            f.write(
                "import os, sqlite3\n"
                "def find_user(uid):\n"
                "    con = sqlite3.connect('app.db')\n"
                "    cur = con.cursor()\n"
                "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
                "    os.system(f'echo user {uid}')\n"
            )

        # 1. Run Phase 3A Red Team Agent
        p0 = {"source_files": [{"path": "server.py"}]}
        agent3a = RedTeamSecurityAgent(root_path=self.test_dir, phase0_inventory=p0)
        p3a_output = agent3a.analyze()
        self.assertTrue(len(p3a_output["findings"]) > 0)

        # 2. Run Phase 4A Blue Team Agent
        agent4a = BlueTeamDefensiveAgent(
            root_path=self.test_dir,
            phase3a_findings=p3a_output["findings"]
        )
        p4a_output = agent4a.analyze()
        self.assertTrue(p4a_output["total_plans"] > 0)

        # 3. Run Phase 5A Retest on the unpatched code
        agent5a = SecurityRetestAgent(
            root_path=self.test_dir,
            phase3a_findings=p3a_output["findings"],
            phase4a_remediations=p4a_output["remediation_plans"]
        )
        p5a_output = agent5a.retest()

        # Both findings should be detected as NOT_REMEDIATED on unpatched code
        self.assertEqual(p5a_output["summary"]["total_retested"], len(p3a_output["findings"]))
        self.assertTrue(p5a_output["summary"]["not_remediated"] >= 1)

        # 4. Patch the code and re-test
        with open(srv_file, "w", encoding="utf-8") as f:
            f.write(
                "import subprocess, sqlite3\n"
                "def find_user(uid):\n"
                "    con = sqlite3.connect('app.db')\n"
                "    cur = con.cursor()\n"
                "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"
                "    subprocess.run(['echo', 'user', str(uid)], shell=False)\n"
            )

        agent5a_patched = SecurityRetestAgent(
            root_path=self.test_dir,
            phase3a_findings=p3a_output["findings"],
            phase4a_remediations=p4a_output["remediation_plans"]
        )
        p5a_patched_output = agent5a_patched.retest()

        # Now findings should be REMEDIATED!
        self.assertEqual(p5a_patched_output["summary"]["not_remediated"], 0)
        self.assertEqual(p5a_patched_output["summary"]["remediated"], len(p3a_output["findings"]))

    # -------------------------------------------------------------------------
    # Section 8 Focused Verification Tests (Scenarios 1 - 9)
    # -------------------------------------------------------------------------

    def test_hardcoded_secret_remaining_despite_unrelated_env_lookup(self):
        fpath = os.path.join(self.test_dir, "auth_secret.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "PORT = os.getenv('PORT', '8080')\n"
                "JWT_SECRET = 'super_secret_production_key_12345'\n"
            )
        finding = {"finding_id": "RED-SECRET-01", "affected_files": ["auth_secret.py"]}
        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_secret_correctly_sourced_from_relevant_env(self):
        fpath = os.path.join(self.test_dir, "auth_clean.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "JWT_SECRET = os.getenv('JWT_SECRET')\n"
            )
        finding = {"finding_id": "RED-SECRET-01", "affected_files": ["auth_clean.py"]}
        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()
        self.assertEqual(res["summary"]["remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "REMEDIATED")

    def test_debug_mode_remaining_enabled_despite_unrelated_env(self):
        fpath = os.path.join(self.test_dir, "web_debug.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "PORT = os.getenv('PORT', '5000')\n"
                "DEBUG = True\n"
            )
        finding = {"finding_id": "RED-DEBUG-01", "affected_files": ["web_debug.py"]}
        agent = SecurityRetestAgent(self.test_dir, [finding])
        res = agent.retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

        fpath_default = os.path.join(self.test_dir, "web_default.py")
        with open(fpath_default, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "DEBUG = os.getenv('DEBUG', 'True') == 'True'\n"
            )
        finding_def = {"finding_id": "RED-DEBUG-01", "affected_files": ["web_default.py"]}
        res_def = SecurityRetestAgent(self.test_dir, [finding_def]).retest()
        self.assertEqual(res_def["summary"]["partially_remediated"], 1)

    def test_unrelated_signature_function_does_not_protect_deserialization(self):
        fpath = os.path.join(self.test_dir, "deser_trap.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import hmac, pickle\n"
                "def verify_api_token(token, key):\n"
                "    return hmac.compare_digest(token, key)\n\n"
                "def load_untrusted_model(path):\n"
                "    with open(path, 'rb') as f:\n"
                "        return pickle.load(f)\n"
            )
        finding = {"finding_id": "RED-DESER-01", "affected_files": ["deser_trap.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_correctly_ordered_authenticity_check_with_pickle(self):
        fpath = os.path.join(self.test_dir, "deser_guarded.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import hmac, pickle\n"
                "def load_verified_model(data, sig, key):\n"
                "    expected = hmac.new(key, data, 'sha256').digest()\n"
                "    if not hmac.compare_digest(sig, expected):\n"
                "        raise ValueError('Tampered model')\n"
                "    return pickle.loads(data)\n"
            )
        finding = {"finding_id": "RED-DESER-01", "affected_files": ["deser_guarded.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["partially_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "PARTIALLY_REMEDIATED")

    def test_parameterized_query_unrelated_to_vulnerable_query(self):
        fpath = os.path.join(self.test_dir, "sql_mixed.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "def get_user(cur, uid):\n"
                "    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n\n"
                "def search_products(cur, query):\n"
                "    cur.execute(f'SELECT * FROM products WHERE name = {query}')\n"
            )
        finding = {"finding_id": "RED-SQL-01", "affected_files": ["sql_mixed.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_safe_subprocess_invocation_with_unvalidated_dangerous_cli(self):
        fpath = os.path.join(self.test_dir, "cli_invoke.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import subprocess\n"
                "def clone(repo_url):\n"
                "    subprocess.run(['git', 'clone', repo_url, '/target'])\n"
            )
        finding = {"finding_id": "RED-CMD-01", "affected_files": ["cli_invoke.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["partially_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "PARTIALLY_REMEDIATED")

    def test_unrelated_security_helpers_do_not_remediate(self):
        # CORS: wildcard origins configured despite an ALLOWED_ORIGINS definition
        f_cors = os.path.join(self.test_dir, "cors_unrelated.py")
        with open(f_cors, "w", encoding="utf-8") as f:
            f.write("ALLOWED_ORIGINS = ['https://trusted.com']\nCORS(app, origins='*')\n")
        res_cors = SecurityRetestAgent(self.test_dir, [{"finding_id": "RED-CORS-01", "affected_files": ["cors_unrelated.py"]}]).retest()
        self.assertEqual(res_cors["summary"]["not_remediated"], 1)

        # SSRF: helper exists but not called on the request path
        f_ssrf = os.path.join(self.test_dir, "ssrf_unrelated.py")
        with open(f_ssrf, "w", encoding="utf-8") as f:
            f.write(
                "import requests\n"
                "def validate_url(url):\n"
                "    return True\n"
                "def fetch(target):\n"
                "    return requests.get(target)\n"
            )
        res_ssrf = SecurityRetestAgent(self.test_dir, [{"finding_id": "RED-SSRF-01", "affected_files": ["ssrf_unrelated.py"]}]).retest()
        self.assertEqual(res_ssrf["summary"]["not_remediated"], 1)

        # XXE: import defusedxml but parsed with standard ElementTree without restriction
        f_xxe = os.path.join(self.test_dir, "xxe_unrelated.py")
        with open(f_xxe, "w", encoding="utf-8") as f:
            f.write(
                "import defusedxml\n"
                "import xml.etree.ElementTree as ET\n"
                "def parse_xml(data):\n"
                "    return ET.fromstring(data)\n"
            )
        res_xxe = SecurityRetestAgent(self.test_dir, [{"finding_id": "RED-XXE-01", "affected_files": ["xxe_unrelated.py"]}]).retest()
        self.assertEqual(res_xxe["summary"]["not_remediated"], 1)

    def test_archive_limits_not_enforced_before_extraction(self):
        f_arch = os.path.join(self.test_dir, "arch_unenforced.py")
        with open(f_arch, "w", encoding="utf-8") as f:
            f.write(
                "import zipfile\n"
                "MAX_SIZE = 100 * 1024 * 1024\n"
                "def extract_file(path, out):\n"
                "    with zipfile.ZipFile(path, 'r') as zf:\n"
                "        zf.extractall(out)\n"
            )
        finding = {"finding_id": "RED-DOS-01", "affected_files": ["arch_unenforced.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_hardcoded_secret_fallback_in_env_lookup(self):
        fpath = os.path.join(self.test_dir, "secret_fallback.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("import os\nSECRET_KEY = os.getenv('SECRET_KEY', 'hardcoded_fallback_secret_xyz123')\n")
        finding = {"finding_id": "RED-SECRET-01", "affected_files": ["secret_fallback.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_debug_mode_false_overridden_by_alternate_code_path(self):
        fpath = os.path.join(self.test_dir, "debug_override.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "DEBUG = False\n"
                "# Configuration override later in startup:\n"
                "if True:\n"
                "    DEBUG = True\n"
            )
        finding = {"finding_id": "RED-DEBUG-01", "affected_files": ["debug_override.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_path_containment_checked_for_different_path_than_write(self):
        fpath = os.path.join(self.test_dir, "unrelated_containment.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "os.path.commonpath([base_dir, config_file])\n"
                "with open(user_destination, 'w') as f:\n"
                "    f.write('unprotected output')\n"
            )
        finding = {"finding_id": "RED-FILE-01", "affected_files": ["unrelated_containment.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_safe_https_alongside_unsafe_dynamic_http_request(self):
        fpath = os.path.join(self.test_dir, "ssrf_mixed.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import requests\n"
                "requests.get('https://trusted-api.domain.com')\n"
                "def forward(user_url):\n"
                "    return requests.get(user_url)\n"
            )
        finding = {"finding_id": "RED-SSRF-01", "affected_files": ["ssrf_mixed.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_tls_verification_disabled_for_vulnerable_request_despite_safe_request(self):
        fpath = os.path.join(self.test_dir, "tls_mixed.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "import requests\n"
                "requests.get('https://internal.service.com', verify=True)\n"
                "requests.get('https://legacy.partner.com', verify=False)\n"
            )
        finding = {"finding_id": "RED-TLS-01", "affected_files": ["tls_mixed.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_archive_member_symlink_rejection_missing(self):
        fpath = os.path.join(self.test_dir, "arch_symlink_missing.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(
                "# helper for symlink in comments\n"
                "import zipfile\n"
                "def extract(archive, dest):\n"
                "    with zipfile.ZipFile(archive) as zf:\n"
                "        zf.extractall(dest)\n"
            )
        finding = {"finding_id": "RED-FILE-02", "affected_files": ["arch_symlink_missing.py"]}
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_upstream_false_positive_contradicted_by_active_vulnerability(self):
        fpath = os.path.join(self.test_dir, "active_vuln.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("DEBUG = True\n")
        finding = {
            "finding_id": "RED-DEBUG-01",
            "validation_status": "FALSE_POSITIVE",
            "evidence": "Asserted benign upstream",
            "affected_files": ["active_vuln.py"]
        }
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        # Must detect contradiction and report NOT_REMEDIATED
        self.assertEqual(res["summary"]["not_remediated"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_REMEDIATED")

    def test_upstream_false_positive_without_evidence_or_source_returns_not_testable(self):
        finding = {
            "finding_id": "RED-DEBUG-01",
            "validation_status": "FALSE_POSITIVE",
            "evidence": "",
            "affected_files": []
        }
        res = SecurityRetestAgent(self.test_dir, [finding]).retest()
        self.assertEqual(res["summary"]["not_testable"], 1)
        self.assertEqual(res["retest_results"][0]["final_status"], "NOT_TESTABLE")

    def test_file_size_limits_boundary_conditions(self):
        # Test exact boundary condition: exactly at limit vs 1 byte over limit
        f_exact = os.path.join(self.test_dir, "exact.py")
        content = b"# exact size test\nDEBUG = False\n"
        with open(f_exact, "wb") as f:
            f.write(content)

        agent = SecurityRetestAgent(self.test_dir, [{"finding_id": "RED-DEBUG-01", "affected_files": ["exact.py"]}])
        agent.MAX_FILE_SIZE = len(content)  # Exactly at limit
        res_exact = agent.retest()
        self.assertEqual(res_exact["summary"]["remediated"], 1)

        # 1 byte over limit
        agent_over = SecurityRetestAgent(self.test_dir, [{"finding_id": "RED-DEBUG-01", "affected_files": ["exact.py"]}])
        agent_over.MAX_FILE_SIZE = len(content) - 1  # 1 byte below file size
        res_over = agent_over.retest()
        self.assertEqual(res_over["summary"]["not_testable"], 1)
        self.assertIn("OVERSIZED", res_over["retest_results"][0]["evidence"])

    def test_multibyte_text_near_byte_boundary(self):
        f_mb = os.path.join(self.test_dir, "multibyte.py")
        # 10 4-byte emojis = 40 bytes UTF-8, but only 10 Unicode characters!
        with open(f_mb, "wb") as f:
            f.write(("🔒" * 10 + "\nDEBUG = False\n").encode("utf-8"))

        agent = SecurityRetestAgent(self.test_dir, [{"finding_id": "RED-DEBUG-01", "affected_files": ["multibyte.py"]}])
        # Byte ceiling of 20 bytes should reject this file even though character count is small
        agent.MAX_FILE_SIZE = 20
        res = agent.retest()
        self.assertEqual(res["summary"]["not_testable"], 1)
        self.assertIn("OVERSIZED", res["retest_results"][0]["evidence"])

    def test_aggregate_inspection_byte_limit(self):
        f1 = os.path.join(self.test_dir, "f1.py")
        f2 = os.path.join(self.test_dir, "f2.py")
        with open(f1, "wb") as f: f.write(b"DEBUG = False\n" * 5)  # ~70 bytes
        with open(f2, "wb") as f: f.write(b"DEBUG = False\n" * 5)  # ~70 bytes

        finding1 = {"finding_id": "RED-DEBUG-01", "affected_files": ["f1.py"]}
        finding2 = {"finding_id": "RED-DEBUG-01", "affected_files": ["f2.py"]}

        agent = SecurityRetestAgent(self.test_dir, [finding1, finding2])
        agent.MAX_FILE_SIZE = 200
        agent.MAX_AGGREGATE_BYTES = 100  # Budget allows first file, but rejects second file!

        res = agent.retest()
        self.assertEqual(res["summary"]["total_retested"], 2)
        self.assertEqual(res["summary"]["remediated"], 1)
        self.assertEqual(res["summary"]["not_testable"], 1)
        self.assertIn("Aggregate inspection budget", res["retest_results"][1]["evidence"])


if __name__ == "__main__":
    unittest.main()



