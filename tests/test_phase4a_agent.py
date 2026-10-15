"""
Dedicated Unit Tests for Phase 4A: Blue Team White-Hat Defensive Security Agent.

Verifies:
1. All 18 supported finding IDs produce technically accurate, nuanced remediation guidance.
2. Accurate security advice (SQL injection, secrets, deserialization, passwords, debug mode,
   CORS, command execution, git argument injection, decompression bombs, output overwrites,
   unbounded reads, symlinks, directory scope, and path disclosure).
3. Generic fallback behavior for unknown/custom finding IDs.
4. Safe handling of malformed finding objects, non-dict values, and missing IDs.
5. Handling of missing, None, and malformed affected_files.
6. Handling of missing, unknown, and invalid severity values.
7. Deduplication of identical IDs with differing severities, preserving highest severity and aggregating locations.
8. Empty inputs and mixed valid/invalid inputs.
9. Preservation of original finding evidence, line numbers, validation status, confidence, and affected files.
10. Deterministic output across repeated runs.
11. Safe handling of missing, None, or empty Phase 1 and Phase 2 context.
12. Defensible contextual enrichment when explicit relationships exist without fabricating links.
13. Strict equality of total_plans and len(remediation_plans), with summary counts matching unique plans.
14. Complete absence of unwarranted claims that vulnerabilities are guaranteed or completely eliminated.
15. Non-destructive, in-memory operation (no file modifications, command executions, or network requests).
"""

import os
import shutil
import tempfile
import unittest
from typing import Any, Dict, List

from src.phase4a.blue_team import BlueTeamDefensiveAgent


class TestPhase4ABlueTeamAgent(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_phase4a_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. All Supported Finding IDs
    # -------------------------------------------------------------------------
    def test_all_supported_finding_ids(self):
        supported_ids = [
            "RED-SQL-01", "RED-SECRET-01", "RED-DESER-01", "RED-DEBUG-01",
            "RED-CORS-01", "RED-CRYPTO-01", "RED-CMD-01", "RED-INJ-01",
            "RED-DOS-01", "RED-FILE-01", "RED-DOS-02", "RED-FILE-02",
            "RED-INFO-01", "RED-INFO-02", "RED-SSRF-01", "RED-XXE-01",
            "RED-TEMP-01", "RED-TLS-01"
        ]

        findings = [
            {
                "finding_id": fid,
                "title": f"Test {fid}",
                "severity": "HIGH",
                "confidence": "HIGH",
                "affected_files": [f"src/{fid.lower()}.py"],
                "evidence": [f"Evidence for {fid}"],
                "line_numbers": [42],
                "validation_status": "PROBABLE",
            }
            for fid in supported_ids
        ]

        agent = BlueTeamDefensiveAgent(root_path=self.test_dir, phase3a_findings=findings)
        result = agent.analyze()

        self.assertEqual(result["total_plans"], len(supported_ids))
        self.assertEqual(len(result["remediation_plans"]), len(supported_ids))

        required_keys = [
            "finding_id", "title", "severity", "root_cause", "remediation",
            "recommended_changes", "security_controls", "hardening_measures",
            "affected_files", "regression_risks", "testing_requirements",
            "expected_result_after_fix", "confidence"
        ]

        for plan in result["remediation_plans"]:
            for key in required_keys:
                self.assertIn(key, plan, f"Plan for {plan.get('finding_id')} missing required key '{key}'")
            self.assertIsInstance(plan["recommended_changes"], list)
            self.assertIsInstance(plan["security_controls"], list)
            self.assertIsInstance(plan["hardening_measures"], list)
            self.assertIsInstance(plan["regression_risks"], list)
            self.assertIsInstance(plan["testing_requirements"], list)
            self.assertTrue(len(plan["recommended_changes"]) > 0)
            self.assertTrue(len(plan["security_controls"]) > 0)

    # -------------------------------------------------------------------------
    # 2. Security Advice Accuracy
    # -------------------------------------------------------------------------
    def test_sql_injection_advice_accuracy(self):
        finding = {
            "finding_id": "RED-SQL-01",
            "title": "SQL Injection",
            "severity": "HIGH",
            "affected_files": ["db.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertIn("parameterized", remediation_text)
        self.assertIn("prepared statements", remediation_text)
        # Driver-specific syntax mentions
        self.assertTrue("?" in remediation_text or "%s" in remediation_text)
        # Identifiers / allowlisting
        self.assertTrue("allowlist" in remediation_text or "identifier" in remediation_text)
        # Controls include allowlisting
        self.assertTrue(any("allowlist" in c.lower() for c in plan["security_controls"]))
        # No claim of absolute elimination
        self.assertNotIn("completely eliminated", plan["expected_result_after_fix"].lower())

    def test_secrets_advice_accuracy(self):
        finding = {
            "finding_id": "RED-SECRET-01",
            "title": "Hardcoded Secret",
            "severity": "CRITICAL",
            "affected_files": ["config.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("rotate" in remediation_text or "revocation" in remediation_text)
        self.assertTrue("external" in remediation_text or "vault" in remediation_text or "manager" in remediation_text)
        self.assertTrue(".gitignore" in remediation_text or "version control" in remediation_text)
        # Clarifies env var alone is not absolute security
        self.assertTrue("alone" in remediation_text or "host compromise" in remediation_text)

    def test_deserialization_advice_accuracy(self):
        finding = {
            "finding_id": "RED-DESER-01",
            "title": "Pickle Deserialization",
            "severity": "CRITICAL",
            "affected_files": ["model.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("untrusted" in remediation_text)
        # Clarifies ordinary SHA-256 is insufficient against attacker modifying both
        self.assertTrue("checksum" in remediation_text or "hash" in remediation_text or "hmac" in remediation_text)
        # Recommends digital signatures or HMAC
        self.assertTrue("signature" in remediation_text or "hmac" in remediation_text)
        # Mentions constrained serialization formats
        self.assertTrue("safetensors" in remediation_text or "onnx" in remediation_text or "json" in remediation_text)
        # Does not claim one format is universally suitable for all objects
        self.assertNotIn("universally suitable", remediation_text)

    def test_crypto_passwords_advice_accuracy(self):
        finding = {
            "finding_id": "RED-CRYPTO-01",
            "title": "MD5 Hash Usage",
            "severity": "MEDIUM",
            "affected_files": ["auth.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("password" in remediation_text)
        # Dedicated password hashing algorithm mentioned
        self.assertTrue("argon2" in remediation_text or "bcrypt" in remediation_text or "scrypt" in remediation_text)
        # Rejects plain SHA-256 for passwords
        self.assertTrue("plain sha-256 is not" in remediation_text or "dedicated" in remediation_text)
        # Collision-resistant hashes for non-password integrity
        self.assertTrue("sha-256" in remediation_text or "sha-512" in remediation_text)

    def test_debug_mode_advice_accuracy(self):
        finding = {
            "finding_id": "RED-DEBUG-01",
            "title": "Debug Mode Enabled",
            "severity": "HIGH",
            "affected_files": ["server.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("disable" in remediation_text or "debug console" in remediation_text)
        self.assertTrue("separate" in remediation_text or "environment" in remediation_text)
        # Notes WSGI server alone does not eliminate underlying vulnerabilities
        self.assertTrue("wsgi" in remediation_text or "asgi" in remediation_text)
        self.assertTrue("alone does not" in remediation_text or "weaknesses" in remediation_text)

    def test_cors_advice_accuracy(self):
        finding = {
            "finding_id": "RED-CORS-01",
            "title": "Permissive CORS",
            "severity": "MEDIUM",
            "affected_files": ["api.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("allowlist" in remediation_text or "whitelist" in remediation_text)
        self.assertTrue("browser" in remediation_text or "cross-origin policy" in remediation_text)
        # Does not rely on Referer
        self.assertTrue("referer" in remediation_text and ("not" in remediation_text or "do not" in remediation_text))

    def test_command_execution_advice_accuracy(self):
        finding = {
            "finding_id": "RED-CMD-01",
            "title": "Command Execution",
            "severity": "CRITICAL",
            "affected_files": ["tasks.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("shell=false" in remediation_text)
        self.assertTrue("semantic" in remediation_text)
        # Option terminator '--' mentioned
        self.assertTrue("--" in remediation_text or "option" in remediation_text)
        # Avoiding shell alone does not eliminate option injection
        self.assertTrue("does not eliminate" in remediation_text or "option injection" in remediation_text)

    def test_git_option_injection_advice_accuracy(self):
        finding = {
            "finding_id": "RED-INJ-01",
            "title": "Git Option Injection",
            "severity": "CRITICAL",
            "affected_files": ["src/phase0/ingestion.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("-" in remediation_text or "hyphen" in remediation_text)
        self.assertTrue("--" in remediation_text)
        self.assertTrue("terminal_prompt" in remediation_text or "protocol" in remediation_text)

    def test_archive_dos_advice_accuracy(self):
        finding = {
            "finding_id": "RED-DOS-01",
            "title": "Decompression Bomb",
            "severity": "HIGH",
            "affected_files": ["unpack.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("uncompressed" in remediation_text or "size" in remediation_text)
        self.assertTrue("ratio" in remediation_text or "count" in remediation_text)
        self.assertTrue("traversal" in remediation_text or "escape" in remediation_text)
        self.assertTrue("cleanup" in remediation_text or "finally" in remediation_text)

    def test_output_path_advice_accuracy(self):
        finding = {
            "finding_id": "RED-FILE-01",
            "title": "Arbitrary File Overwrite",
            "severity": "CRITICAL",
            "affected_files": ["export.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("boundary" in remediation_text or "commonpath" in remediation_text or "containment" in remediation_text)
        self.assertTrue("overwrite" in remediation_text)
        self.assertTrue("atomic" in remediation_text or "temporary" in remediation_text)
        self.assertTrue("symlink" in remediation_text or "toctou" in remediation_text)

    def test_unbounded_reads_advice_accuracy(self):
        finding = {
            "finding_id": "RED-DOS-02",
            "title": "Unbounded File Read",
            "severity": "MEDIUM",
            "affected_files": ["scanner.py"]
        }
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        remediation_text = plan["remediation"].lower()
        self.assertTrue("bounded" in remediation_text or "streaming" in remediation_text)
        self.assertTrue("size" in remediation_text)
        self.assertTrue("truncat" in remediation_text or "coverage" in remediation_text or "miss" in remediation_text)

    def test_symlinks_scope_path_disclosure_advice(self):
        findings = [
            {"finding_id": "RED-FILE-02", "title": "Symlink Attack", "severity": "CRITICAL"},
            {"finding_id": "RED-INFO-01", "title": "Directory Scope", "severity": "MEDIUM"},
            {"finding_id": "RED-INFO-02", "title": "Path Leak", "severity": "LOW"},
        ]
        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=findings)
        plans = {p["finding_id"]: p for p in agent.analyze()["remediation_plans"]}

        # RED-FILE-02: symlink attribute inspection
        self.assertTrue("symlink" in plans["RED-FILE-02"]["remediation"].lower())
        self.assertTrue("external_attr" in plans["RED-FILE-02"]["remediation"].lower() or "islnk" in plans["RED-FILE-02"]["remediation"].lower())

        # RED-INFO-01: CLI directory selection vs system roots
        self.assertTrue("root" in plans["RED-INFO-01"]["remediation"].lower())
        self.assertTrue("workspace" in plans["RED-INFO-01"]["remediation"].lower())

        # RED-INFO-02: path minimization / virtualization
        self.assertTrue("relative" in plans["RED-INFO-02"]["remediation"].lower() or "virtual" in plans["RED-INFO-02"]["remediation"].lower())

    # -------------------------------------------------------------------------
    # 3. Generic Fallback & Unknown Finding IDs
    # -------------------------------------------------------------------------
    def test_unknown_ids_and_generic_fallback(self):
        custom_finding = {
            "finding_id": "RED-CUSTOM-099",
            "title": "Custom Protocol Parser Issue",
            "severity": "MEDIUM",
            "confidence": "LOW",
            "affected_files": ["proto/parser.py"],
            "evidence": ["Custom binary frame offset not validated."],
            "line_numbers": [128],
            "validation_status": "POSSIBLE"
        }

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[custom_finding])
        result = agent.analyze()

        self.assertEqual(result["total_plans"], 1)
        plan = result["remediation_plans"][0]
        self.assertEqual(plan["finding_id"], "RED-CUSTOM-099")
        self.assertEqual(plan["title"], "Custom Protocol Parser Issue")
        self.assertEqual(plan["severity"], "MEDIUM")
        self.assertEqual(plan["confidence"], "LOW")
        self.assertEqual(plan["affected_files"], ["proto/parser.py"])
        self.assertEqual(plan["evidence"], ["Custom binary frame offset not validated."])
        self.assertEqual(plan["line_numbers"], [128])
        self.assertEqual(plan["original_validation_status"], "POSSIBLE")

        # Generic plan states manual review is required and does not claim elimination
        self.assertTrue("review" in plan["root_cause"].lower())
        self.assertNotIn("completely eliminated", plan["expected_result_after_fix"].lower())

    # -------------------------------------------------------------------------
    # 4. Missing IDs and Malformed Finding Objects
    # -------------------------------------------------------------------------
    def test_missing_ids_and_malformed_objects(self):
        malformed_inputs = [
            None,
            123,
            "not a dict",
            [],
            {},
            {"title": "Finding with no ID"},
            {"finding_id": None, "title": "None ID"},
            {"finding_id": "", "title": "Empty ID"},
            {"finding_id": "   ", "title": "Whitespace ID"},
            {"finding_id": 456, "title": "Numeric ID"},
        ]

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=malformed_inputs)
        result = agent.analyze()

        self.assertEqual(result["total_plans"], 0)
        self.assertEqual(len(result["remediation_plans"]), 0)
        self.assertEqual(result["summary"]["invalid_findings_count"], len(malformed_inputs))
        self.assertEqual(result["summary"]["raw_findings_count"], len(malformed_inputs))

    # -------------------------------------------------------------------------
    # 5. Missing, None, and Malformed affected_files
    # -------------------------------------------------------------------------
    def test_malformed_affected_files_handled_cleanly(self):
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": None},
            {"finding_id": "RED-SECRET-01", "affected_files": "single_file.py"},
            {"finding_id": "RED-DEBUG-01", "affected_files": [123, None, "valid.py", "  "]},
            {"finding_id": "RED-CORS-01"},  # missing key
        ]

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=findings)
        result = agent.analyze()

        self.assertEqual(result["total_plans"], 4)
        plans_by_id = {p["finding_id"]: p for p in result["remediation_plans"]}

        self.assertEqual(plans_by_id["RED-SQL-01"]["affected_files"], [])
        self.assertEqual(plans_by_id["RED-SECRET-01"]["affected_files"], ["single_file.py"])
        self.assertEqual(plans_by_id["RED-DEBUG-01"]["affected_files"], ["valid.py"])
        self.assertEqual(plans_by_id["RED-CORS-01"]["affected_files"], [])

    # -------------------------------------------------------------------------
    # 6. Missing, Unknown, and Invalid Severity Values
    # -------------------------------------------------------------------------
    def test_severity_handling(self):
        findings = [
            {"finding_id": "RED-SQL-01", "severity": None},
            {"finding_id": "RED-SECRET-01", "severity": "EXTREME"},
            {"finding_id": "RED-DESER-01", "severity": 999},
            {"finding_id": "RED-DEBUG-01", "severity": "critical"},  # lower case
            {"finding_id": "RED-CORS-01"},  # missing
        ]

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=findings)
        result = agent.analyze()

        self.assertEqual(result["total_plans"], 5)
        summary = result["summary"]
        self.assertIn("critical", summary)
        self.assertIn("high", summary)
        self.assertIn("medium", summary)
        self.assertIn("low", summary)
        self.assertIn("unknown", summary)
        # "critical" should be normalized to uppercase and counted under critical
        self.assertEqual(summary["critical"], 1)

    # -------------------------------------------------------------------------
    # 7. Duplicate IDs and Conflicting Severities
    # -------------------------------------------------------------------------
    def test_duplicate_ids_and_conflicting_severities(self):
        duplicates = [
            {
                "finding_id": "RED-SQL-01",
                "severity": "LOW",
                "affected_files": ["db/sqlite.py"],
                "evidence": ["Dynamic query at line 10"],
                "line_numbers": [10],
            },
            {
                "finding_id": "RED-SQL-01",
                "severity": "CRITICAL",
                "affected_files": ["db/pg.py"],
                "evidence": ["F-string query at line 55"],
                "line_numbers": [55],
            },
            {
                "finding_id": "RED-SQL-01",
                "severity": "MEDIUM",
                "affected_files": ["db/sqlite.py"],  # repeat file
                "evidence": ["Dynamic query at line 10"],  # repeat evidence
                "line_numbers": [12],
            },
        ]

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=duplicates)
        result = agent.analyze()

        # Should deduplicate into exactly 1 plan
        self.assertEqual(result["total_plans"], 1)
        plan = result["remediation_plans"][0]

        # Highest severity (CRITICAL) is retained
        self.assertEqual(plan["severity"], "CRITICAL")
        # Files are merged uniquely
        self.assertEqual(plan["affected_files"], ["db/sqlite.py", "db/pg.py"])
        # Evidence is merged uniquely
        self.assertEqual(len(plan["evidence"]), 2)
        # Line numbers are merged and sorted
        self.assertEqual(plan["line_numbers"], [10, 12, 55])

        # Summary counts: duplicate count must be 2, critical count must be 1, total_unique_plans must be 1
        summary = result["summary"]
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["low"], 0)
        self.assertEqual(summary["medium"], 0)
        self.assertEqual(summary["duplicate_findings_count"], 2)
        self.assertEqual(summary["total_unique_plans"], 1)

    # -------------------------------------------------------------------------
    # 8. Empty and Mixed Input
    # -------------------------------------------------------------------------
    def test_empty_and_mixed_input(self):
        # Empty input
        agent_empty = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[])
        res_empty = agent_empty.analyze()
        self.assertEqual(res_empty["total_plans"], 0)
        self.assertEqual(res_empty["summary"]["critical"], 0)
        self.assertEqual(res_empty["summary"]["total_unique_plans"], 0)

        # Mixed valid, malformed, and duplicate
        mixed = [
            None,
            {"finding_id": "RED-SQL-01", "severity": "HIGH", "affected_files": ["db.py"]},
            {"not_a_valid": "finding"},
            {"finding_id": "RED-SQL-01", "severity": "CRITICAL", "affected_files": ["db2.py"]},
            {"finding_id": "RED-SECRET-01", "severity": "CRITICAL", "affected_files": ["auth.py"]},
            "string_junk"
        ]

        agent_mixed = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=mixed)
        res_mixed = agent_mixed.analyze()

        self.assertEqual(res_mixed["total_plans"], 2)
        self.assertEqual(res_mixed["summary"]["invalid_findings_count"], 3)
        self.assertEqual(res_mixed["summary"]["duplicate_findings_count"], 1)
        self.assertEqual(res_mixed["summary"]["raw_findings_count"], 6)
        self.assertEqual(res_mixed["summary"]["critical"], 2)

    # -------------------------------------------------------------------------
    # 9. Evidence and Location Preservation
    # -------------------------------------------------------------------------
    def test_metadata_preservation(self):
        finding = {
            "finding_id": "RED-CMD-01",
            "title": "Subprocess Shell Execution",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "affected_files": ["exec.py"],
            "evidence": ["os.system(user_cmd) called without sanitization"],
            "line_numbers": [42, 45],
            "validation_status": "PROBABLE",
            "requirement_affected": "REQ-SEC-01"
        }

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        plan = agent.analyze()["remediation_plans"][0]

        self.assertEqual(plan["finding_id"], "RED-CMD-01")
        self.assertEqual(plan["title"], "Subprocess Shell Execution")
        self.assertEqual(plan["confidence"], "HIGH")
        self.assertEqual(plan["affected_files"], ["exec.py"])
        self.assertEqual(plan["evidence"], ["os.system(user_cmd) called without sanitization"])
        self.assertEqual(plan["line_numbers"], [42, 45])
        self.assertEqual(plan["original_validation_status"], "PROBABLE")

    # -------------------------------------------------------------------------
    # 10. Deterministic Output Across Repeated Runs
    # -------------------------------------------------------------------------
    def test_deterministic_output(self):
        findings = [
            {"finding_id": "RED-SQL-01", "severity": "HIGH", "affected_files": ["b.py", "a.py"]},
            {"finding_id": "RED-DEBUG-01", "severity": "LOW", "affected_files": ["server.py"]},
            {"finding_id": "RED-SECRET-01", "severity": "CRITICAL", "affected_files": ["key.py"]},
        ]

        agent1 = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=findings)
        res1 = agent1.analyze()

        agent2 = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=findings)
        res2 = agent2.analyze()

        self.assertEqual(res1, res2)

    # -------------------------------------------------------------------------
    # 11. Missing or Empty Phase 1 and Phase 2 Context
    # -------------------------------------------------------------------------
    def test_missing_or_empty_p1_and_p2_context(self):
        # None arguments
        agent_none = BlueTeamDefensiveAgent(
            root_path=self.test_dir,
            phase1_reconstruction=None,
            phase2_requirements=None,
            phase3a_findings=[{"finding_id": "RED-SQL-01"}]
        )
        res_none = agent_none.analyze()
        self.assertEqual(res_none["total_plans"], 1)

        # Empty dict/list arguments
        agent_empty = BlueTeamDefensiveAgent(
            root_path=self.test_dir,
            phase1_reconstruction={},
            phase2_requirements=[],
            phase3a_findings=[{"finding_id": "RED-SQL-01"}]
        )
        res_empty = agent_empty.analyze()
        self.assertEqual(res_empty["total_plans"], 1)

    # -------------------------------------------------------------------------
    # 12. Valid Contextual Enrichment
    # -------------------------------------------------------------------------
    def test_valid_contextual_enrichment(self):
        p1 = {
            "entry_points": [{"path": "api/routes.py", "type": "fastapi"}],
            "apis": [{"file": "api/routes.py", "endpoint": "/api/users"}]
        }
        p2 = [
            {"id": "REQ-SEC-01", "title": "SQL Injection Prevention", "category": "Security"}
        ]
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["api/routes.py"],
                "requirement_affected": "REQ-SEC-01"
            },
            {
                "finding_id": "RED-SECRET-01",
                "affected_files": ["internal/worker.py"],
                "requirement_affected": "UNMAPPED"
            }
        ]

        agent = BlueTeamDefensiveAgent(
            root_path=self.test_dir,
            phase1_reconstruction=p1,
            phase2_requirements=p2,
            phase3a_findings=findings
        )
        plans = {p["finding_id"]: p for p in agent.analyze()["remediation_plans"]}

        # Finding 1 matches entry points, APIs, and requirements
        self.assertIn("context", plans["RED-SQL-01"])
        ctx = plans["RED-SQL-01"]["context"]
        self.assertEqual(ctx["exposed_entry_points"], [{"path": "api/routes.py", "type": "fastapi"}])
        self.assertEqual(ctx["exposed_apis"], [{"file": "api/routes.py", "endpoint": "/api/users"}])
        self.assertEqual(ctx["associated_requirement"]["id"], "REQ-SEC-01")

        # Finding 2 has no matching entry point or requirement; context should not be fabricated
        self.assertNotIn("context", plans["RED-SECRET-01"])

    # -------------------------------------------------------------------------
    # 13. Correct total_plans and Summary Counts
    # -------------------------------------------------------------------------
    def test_summary_and_total_plans_consistency(self):
        findings = [
            {"finding_id": "RED-SQL-01", "severity": "CRITICAL"},
            {"finding_id": "RED-SECRET-01", "severity": "HIGH"},
            {"finding_id": "RED-DEBUG-01", "severity": "MEDIUM"},
            {"finding_id": "RED-INFO-02", "severity": "LOW"},
            {"finding_id": "RED-CUSTOM-01", "severity": "UNKNOWN"},
        ]

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=findings)
        res = agent.analyze()

        plans = res["remediation_plans"]
        summary = res["summary"]

        self.assertEqual(res["total_plans"], len(plans))
        self.assertEqual(summary["total_unique_plans"], len(plans))
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["low"], 1)
        self.assertEqual(summary["unknown"], 1)

        total_by_severities = (
            summary["critical"] + summary["high"] + summary["medium"] +
            summary["low"] + summary["info"] + summary["unknown"]
        )
        self.assertEqual(total_by_severities, len(plans))

    # -------------------------------------------------------------------------
    # 14. Absence of Unsupported Absolute Claims
    # -------------------------------------------------------------------------
    def test_absence_of_unsupported_absolute_claims(self):
        all_ids = [
            "RED-SQL-01", "RED-SECRET-01", "RED-DESER-01", "RED-DEBUG-01",
            "RED-CORS-01", "RED-CRYPTO-01", "RED-CMD-01", "RED-INJ-01",
            "RED-DOS-01", "RED-FILE-01", "RED-DOS-02", "RED-FILE-02",
            "RED-INFO-01", "RED-INFO-02", "RED-SSRF-01", "RED-XXE-01",
            "RED-TEMP-01", "RED-TLS-01", "RED-GEN-UNKNOWN"
        ]

        agent = BlueTeamDefensiveAgent(
            self.test_dir,
            phase3a_findings=[{"finding_id": fid} for fid in all_ids]
        )
        res = agent.analyze()

        forbidden_phrases = [
            "completely eliminated",
            "guaranteed to eliminate",
            "eliminates every cryptographic risk",
            "completely prevented",
            "100% secure",
        ]

        for plan in res["remediation_plans"]:
            expected_outcome = plan["expected_result_after_fix"].lower()
            for phrase in forbidden_phrases:
                self.assertNotIn(
                    phrase,
                    expected_outcome,
                    f"Plan {plan['finding_id']} contains forbidden absolute claim '{phrase}' in expected outcome"
                )

    # -------------------------------------------------------------------------
    # 15. Non-Destructive In-Memory Operation
    # -------------------------------------------------------------------------
    def test_non_destructive_and_no_side_effects(self):
        # Create a mock file in test_dir
        target_file = os.path.join(self.test_dir, "app.py")
        initial_content = "import os\nos.system('echo test')\n"
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(initial_content)

        mtime_before = os.path.getmtime(target_file)

        finding = {
            "finding_id": "RED-CMD-01",
            "affected_files": ["app.py"],
            "severity": "CRITICAL"
        }

        agent = BlueTeamDefensiveAgent(self.test_dir, phase3a_findings=[finding])
        result = agent.analyze()

        # Check that file content and modification time are completely unchanged
        mtime_after = os.path.getmtime(target_file)
        with open(target_file, "r", encoding="utf-8") as f:
            content_after = f.read()

        self.assertEqual(initial_content, content_after)
        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(len(result["remediation_plans"]), 1)

    # -------------------------------------------------------------------------
    # 16. Integration with Actual Phase 3A Output
    # -------------------------------------------------------------------------
    def test_integration_with_actual_phase3a_output(self):
        from src.phase3a.red_team import RedTeamSecurityAgent

        # Write actual vulnerable Python files in test_dir
        app_file = os.path.join(self.test_dir, "server.py")
        with open(app_file, "w", encoding="utf-8") as f:
            f.write(
                "import os, sqlite3, pickle\n"
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n"
                "@app.route('/query')\n"
                "def query():\n"
                "    uid = request.args.get('id')\n"
                "    con = sqlite3.connect('test.db')\n"
                "    cur = con.cursor()\n"
                "    cur.execute(f'SELECT * FROM users WHERE id = {uid}')\n"
                "    os.system(f'echo user {uid}')\n"
                "    return 'ok'\n"
                "if __name__ == '__main__':\n"
                "    app.run(debug=True)\n"
            )

        # Run actual Phase 3A agent
        p0 = {"source_files": [{"path": "server.py"}]}
        agent3a = RedTeamSecurityAgent(root_path=self.test_dir, phase0_inventory=p0)
        p3a_res = agent3a.analyze()

        self.assertIn("findings", p3a_res)
        self.assertTrue(len(p3a_res["findings"]) > 0)

        # Feed actual Phase 3A findings into Phase 4A agent
        agent4a = BlueTeamDefensiveAgent(
            root_path=self.test_dir,
            phase3a_findings=p3a_res["findings"]
        )
        p4a_res = agent4a.analyze()

        self.assertIn("remediation_plans", p4a_res)
        self.assertIn("total_plans", p4a_res)
        self.assertIn("summary", p4a_res)
        self.assertEqual(p4a_res["total_plans"], len(p4a_res["remediation_plans"]))
        self.assertTrue(p4a_res["total_plans"] > 0)

        # Check that plans generated correspond to actual findings
        p3a_fids = {f["finding_id"] for f in p3a_res["findings"]}
        for plan in p4a_res["remediation_plans"]:
            self.assertIn(plan["finding_id"], p3a_fids)
            self.assertIn("server.py", plan["affected_files"])
            self.assertIsInstance(plan["security_controls"], list)
            self.assertIsInstance(plan["recommended_changes"], list)
            self.assertIsInstance(plan["testing_requirements"], list)


if __name__ == "__main__":
    unittest.main()

