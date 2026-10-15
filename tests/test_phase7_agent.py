"""
Unit, regression, security, boundary, and integration tests for Phase 7:
CrossDomainAnalysisAgent (Cross-Domain Software Engineering Analysis).

Covers:
- Section 12.A: Archive-quota verification tests (all 13 distinct cases + checks before/after extraction, nested functions, misleading variables, unenforced checks, generic evidence)
- Section 12.B: Relationship tests for all 6 IDs (positive, negative, missing evidence, weak evidence, duplicate records, regex variations)
- Section 12.C: Robustness tests (omitted inputs, None, empty objects, wrong types, malformed records)
- Section 12.D: Output and determinism tests (exact counters, determinism, input immutability)
- Section 12.E: Security and source inspection tests (path traversal rejected, oversized files skipped)
- Section 12.F: Downstream Phase 8, Phase 9, and full pipeline integration tests
"""

import os
import shutil
import tempfile
import unittest
from typing import Dict, Any, List

from src.phase7.cross_domain import CrossDomainAnalysisAgent
from src.phase8.recommendations import RecommendationEngineAgent
from src.phase9.report import FinalReportGeneratorAgent
from pipeline import run_pipeline


class TestPhase7CrossDomainAgent(unittest.TestCase):
    """Exhaustive test suite for Phase 7 CrossDomainAnalysisAgent."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_phase7_")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_file(self, rel_path: str, content: str) -> str:
        full_path = os.path.join(self.test_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        return full_path

    # =========================================================================
    # Group A: Archive-Quota Verification Tests (All Distinct Cases)
    # =========================================================================

    def test_archive_quota_case1_risk_identified_no_remediation(self):
        """1. Risk identified, no remediation (Phase 3A finding only -> verified=False, no REL-SEC-PERF-01)."""
        findings = [{"finding_id": "RED-DOS-01", "finding_type": "decompression_bomb", "title": "Zip Bomb Risk"}]
        agent = CrossDomainAnalysisAgent(phase3a_findings=findings)

        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "RISK_IDENTIFIED")
        self.assertFalse(quota_state["verified"])

        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertNotIn("REL-SEC-PERF-01", rel_ids)

    def test_archive_quota_case2_remediation_plan_exists_no_implementation(self):
        """2. Remediation plan exists, no verified implementation (Phase 4A remediation only -> verified=False)."""
        remediations = [{"remediation_id": "REM-DOS-01", "finding_id": "RED-DOS-01", "title": "Implement Zip Quotas"}]
        agent = CrossDomainAnalysisAgent(phase4a_remediations=remediations)

        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "PLANNED_ONLY")
        self.assertFalse(quota_state["verified"])

        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertNotIn("REL-SEC-PERF-01", rel_ids)

    def test_archive_quota_case3_partial_remediation(self):
        """3. Partial remediation (Phase 5A PARTIALLY_REMEDIATED -> PARTIALLY_VERIFIED, verified=False, partial note)."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "PARTIALLY_REMEDIATED",
                "evidence": "Member count quota enforced; cumulative uncompressed size check pending",
                "result": "Partial archive quotas active"
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)

        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "PARTIALLY_VERIFIED")
        self.assertFalse(quota_state["verified"])
        self.assertFalse(quota_state["full_verification"])
        self.assertTrue(quota_state["partial_verification"])

        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertIn("REL-SEC-PERF-01", rel_ids)
        rel = next(r for r in res["cross_domain_relationships"] if r["relationship_id"] == "REL-SEC-PERF-01")
        self.assertIn("PARTIALLY_REMEDIATED", rel["evidence"])
        self.assertIn("Partial pre-scan validation", rel["consequence"])

    def test_archive_quota_case4_remediated_status_without_specific_evidence(self):
        """4. Remediated status with missing evidence -> UNVERIFIED, verified=False."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "",
                "result": ""
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "UNVERIFIED")
        self.assertFalse(quota_state["verified"])
        self.assertFalse(quota_state["full_verification"])
        self.assertFalse(quota_state["partial_verification"])

        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertNotIn("REL-SEC-PERF-01", rel_ids)

    def test_archive_quota_case_remediated_generic_evidence(self):
        """Remediated status with generic non-empty evidence -> UNVERIFIED, verified=False."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Resolved during sprint code review.",
                "result": "Completed"
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "UNVERIFIED")
        self.assertFalse(quota_state["verified"])
        self.assertFalse(quota_state["full_verification"])
        self.assertFalse(quota_state["partial_verification"])

        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertNotIn("REL-SEC-PERF-01", rel_ids)

    def test_archive_quota_case5_retest_explicitly_verifies_particular_control(self):
        """5. Retest explicitly verifies a particular control -> VERIFIED_PRESENT."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Pre-extraction inspection checks max_uncompressed_bytes (100MB) and max_files (5000)",
                "result": "Decompression bomb mitigation active"
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "VERIFIED_PRESENT")
        self.assertTrue(quota_state["verified"])

        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertIn("REL-SEC-PERF-01", rel_ids)
        rel = next(r for r in res["cross_domain_relationships"] if r["relationship_id"] == "REL-SEC-PERF-01")
        self.assertIn("max_uncompressed_bytes", rel["evidence"])

    def test_archive_quota_case6_false_positive_status(self):
        """6. False-positive status -> NOT_ASSESSED, verified=False."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "FALSE_POSITIVE",
                "evidence": "Archive extraction in test fixture is benign"
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "NOT_ASSESSED")
        self.assertFalse(quota_state["verified"])

        res = agent.analyze()
        self.assertNotIn("REL-SEC-PERF-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_archive_quota_case7_not_assessed_or_not_testable_status(self):
        """7. Not-assessed or not-testable status -> NOT_ASSESSED, verified=False."""
        for status in ("NOT_TESTABLE", "NOT_ASSESSED"):
            retest = {
                "retest_results": [{
                    "finding_id": "RED-DOS-01",
                    "final_status": status,
                    "evidence": "No archive test files available"
                }]
            }
            agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
            quota_state = agent.evaluate_archive_quota_state()
            self.assertEqual(quota_state["state"], "NOT_ASSESSED")
            self.assertFalse(quota_state["verified"])

        res = agent.analyze()
        self.assertNotIn("REL-SEC-PERF-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_archive_quota_case8_unknown_or_malformed_status(self):
        """8. Unknown or malformed status -> NOT_ASSESSED, verified=False."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": 99999,  # malformed integer status
                "evidence": None
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "NOT_ASSESSED")
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_case9_phase1_truthy_flag_without_evidence(self):
        """9. Truthy Phase 1 flag without corroborating evidence -> verified=False."""
        p1 = {"has_zip_quota": True}
        agent = CrossDomainAnalysisAgent(phase1_reconstruction=p1)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

        res = agent.analyze()
        self.assertNotIn("REL-SEC-PERF-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_archive_quota_case10_source_keywords_only_in_comments(self):
        """10. Source file containing keywords only in comments -> AST ignores comments, verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("# In this file, limit_bytes and MAX_SIZE protect against decompression bombs\n")
            f.write("def extract_all(zf, dest):\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_case11_source_checks_unrelated_to_extraction_path(self):
        """11. Source file with checks unrelated to the extraction path -> verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def check_size(data):\n")
            f.write("    if len(data) > 1000:\n")
            f.write("        return False\n")
            f.write("    return True\n\n")
            f.write("def extract_archive(zf, dest):\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_case12_actual_relevant_checks_before_extraction(self):
        """12. Actual relevant checks before extraction -> VERIFIED_PRESENT, verified=True."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def safe_extract(zf, dest):\n")
            f.write("    total_size = 0\n")
            f.write("    for info in zf.infolist():\n")
            f.write("        total_size += info.file_size\n")
            f.write("        if total_size > 100000000:\n")
            f.write("            raise ValueError('File too large')\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "VERIFIED_PRESENT")
        self.assertTrue(quota_state["verified"])
        self.assertIn("uncompressed size limits", quota_state["evidence"])

    def test_archive_quota_source_per_member_without_cumulative(self):
        """Source file with per-member size check but no cumulative size limit -> PARTIALLY_VERIFIED, verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def safe_extract(zf, dest):\n")
            f.write("    for info in zf.infolist():\n")
            f.write("        if info.file_size > 100000000:\n")
            f.write("            raise ValueError('File too large')\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "PARTIALLY_VERIFIED")
        self.assertFalse(quota_state["verified"])
        self.assertFalse(quota_state["full_verification"])
        self.assertTrue(quota_state["partial_verification"])
        self.assertIn("per-member uncompressed size", quota_state["evidence"])

    def test_archive_quota_source_member_count_without_total_size(self):
        """Source file with member count cap but no uncompressed size limit -> PARTIALLY_VERIFIED, verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def safe_extract(zf, dest):\n")
            f.write("    if len(zf.infolist()) > 5000:\n")
            f.write("        raise ValueError('Too many files')\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "PARTIALLY_VERIFIED")
        self.assertFalse(quota_state["verified"])
        self.assertFalse(quota_state["full_verification"])
        self.assertTrue(quota_state["partial_verification"])
        self.assertIn("member count caps", quota_state["evidence"])

    def test_archive_quota_conflicting_retest_and_source(self):
        """Conflicting evidence: Phase 5A says REMEDIATED, but repository source code has bare extraction -> CONFLICTING_EVIDENCE, verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def extract_repo(zf, dest):\n    zf.extractall(dest)\n")

        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Pre-extraction quotas validated in Phase 0 ingestion."
            }]
        }
        agent = CrossDomainAnalysisAgent(root_path=self.test_dir, phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "CONFLICTING_EVIDENCE")
        self.assertFalse(quota_state["verified"])
        self.assertFalse(quota_state["full_verification"])
        self.assertFalse(quota_state["partial_verification"])
        self.assertIn("conflicting evidence", quota_state["evidence"].lower())

        res = agent.analyze()
        self.assertNotIn("REL-SEC-PERF-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_archive_quota_conflicting_phase1_and_retest_not_remediated(self):
        """Phase 1 claims enforced quotas, but Phase 5A retest proves NOT_REMEDIATED -> RISK_IDENTIFIED."""
        p1 = {"archive_controls": {"enforced": True, "description": "Decompression quota asserted in metadata"}}
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "NOT_REMEDIATED",
                "evidence": "Decompression bomb vulnerability verified still reachable in code."
            }]
        }
        agent = CrossDomainAnalysisAgent(phase1_reconstruction=p1, phase5a_retest=retest)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "RISK_IDENTIFIED")
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_source_checks_after_extraction(self):
        """Check occurring after extraction call does NOT guard extraction -> verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def unsafe_extract(zf, dest):\n")
            f.write("    zf.extractall(dest)\n")
            f.write("    if os.path.getsize(dest) > 100000000:\n")
            f.write("        raise ValueError('Too large after extraction')\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_source_nested_function_checks(self):
        """Check inside nested function does not guard outer extraction -> verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def outer_extract(zf, dest):\n")
            f.write("    def inner_checker(info):\n")
            f.write("        if info.file_size > 1000000:\n")
            f.write("            raise ValueError('File too large')\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_source_misleading_variable_names(self):
        """Variables defined without an enclosing If guard -> verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def extract_with_unused_vars(zf, dest):\n")
            f.write("    MAX_BYTES = 100000000\n")
            f.write("    MAX_FILES = 5000\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_source_unenforced_condition(self):
        """If condition that does not raise, return, break, or exit -> verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def unenforced_check_extract(zf, dest):\n")
            f.write("    for info in zf.infolist():\n")
            f.write("        if info.file_size > 100000000:\n")
            f.write("            dummy_val = 1\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_source_missing_checks(self):
        """Bare extraction without any checks -> verified=False."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def bare_extract(zf, dest):\n")
            f.write("    zf.extractall(dest)\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_archive_quota_case13_no_archive_information(self):
        """13. No archive-related information -> NOT_FOUND, verified=False."""
        agent = CrossDomainAnalysisAgent()
        quota_state = agent.evaluate_archive_quota_state()
        self.assertEqual(quota_state["state"], "NOT_FOUND")
        self.assertFalse(quota_state["verified"])

    # =========================================================================
    # Group B: Relationship Tests for all 6 IDs
    # =========================================================================

    # --- 1. REL-SMELL-SEC-01 ---
    def test_rel_smell_sec_01_positive(self):
        """REL-SMELL-SEC-01 emitted when genuine silent exception smell is present with evidence."""
        smells = [{
            "smell_id": "SMELL-SILENT-EXCEPTION",
            "category": "Poor Exception Handling",
            "file": "src/phase1/reconstruction.py",
            "function_or_class": "reconstruct",
            "evidence": "Except handler catches 'Exception' with a silent pass statement.",
            "explanation": "Silently swallows parsing errors."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertIn("REL-SMELL-SEC-01", rel_ids)
        rel = next(r for r in res["cross_domain_relationships"] if r["relationship_id"] == "REL-SMELL-SEC-01")
        self.assertIn("src/phase1/reconstruction.py:reconstruct", rel["evidence"])

    def test_rel_smell_sec_01_negative_logged_or_reraised(self):
        """REL-SMELL-SEC-01 not emitted when handler logs error or re-raises."""
        smells = [
            {
                "smell_id": "SMELL-EXCEPT-LOGGED",
                "category": "Poor Exception Handling",
                "file": "src/service.py",
                "function_or_class": "handle",
                "evidence": "logger.error('Failed to parse request', exc_info=True)",
                "explanation": "Catches exception but records detailed log."
            },
            {
                "smell_id": "SMELL-EXCEPT-RERAISE",
                "category": "Poor Exception Handling",
                "file": "src/db.py",
                "function_or_class": "query",
                "evidence": "except Exception: clean(); raise",
                "explanation": "Cleans up and re-raises."
            }
        ]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertNotIn("REL-SMELL-SEC-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_smell_sec_01_missing_evidence_not_emitted(self):
        """REL-SMELL-SEC-01 not emitted when smell has no evidence or file."""
        smells = [{"smell_id": "SMELL-SILENT-EXCEPTION", "category": "Poor Exception Handling", "evidence": "", "file": ""}]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertNotIn("REL-SMELL-SEC-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    # --- 2. REL-SEC-PERF-01 ---
    def test_rel_sec_perf_01_positive(self):
        """REL-SEC-PERF-01 emitted when archive quotas are verified."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Pre-extraction quotas validated in Phase 0 ingestion."
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        res = agent.analyze()
        self.assertIn("REL-SEC-PERF-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_sec_perf_01_negative_unremediated(self):
        """REL-SEC-PERF-01 not emitted when retest is NOT_REMEDIATED."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "NOT_REMEDIATED",
                "evidence": "Extraction occurs without quota checks"
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        res = agent.analyze()
        self.assertNotIn("REL-SEC-PERF-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    # --- 3. REL-ARCH-SEC-01 ---
    def test_rel_arch_sec_01_positive(self):
        """REL-ARCH-SEC-01 emitted when requirement specifies zero external dependencies."""
        reqs = [{
            "requirement_id": "REQ-NFR-05",  # arbitrary ID, not hardcoded REQ-NFR-02
            "description": "Core engine must operate with zero external dependencies, standard library only."
        }]
        agent = CrossDomainAnalysisAgent(phase2_requirements=reqs)
        res = agent.analyze()
        self.assertIn("REL-ARCH-SEC-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_arch_sec_01_positive_standard_library_only(self):
        """REL-ARCH-SEC-01 emitted when requirement specifies standard library only."""
        reqs = [{
            "requirement_id": "REQ-STD-01",
            "description": "Implementation must rely on Python standard library only without external packages."
        }]
        agent = CrossDomainAnalysisAgent(phase2_requirements=reqs)
        res = agent.analyze()
        self.assertIn("REL-ARCH-SEC-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_arch_sec_01_negative_req_nfr_02_with_different_meaning(self):
        """REL-ARCH-SEC-01 must NOT be emitted if REQ-NFR-02 is about latency or memory, not dependencies."""
        reqs = [{
            "requirement_id": "REQ-NFR-02",
            "description": "System memory usage must not exceed 256MB during peak load."
        }]
        agent = CrossDomainAnalysisAgent(phase2_requirements=reqs)
        res = agent.analyze()
        self.assertNotIn("REL-ARCH-SEC-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_arch_sec_01_negative_dependency_injection(self):
        """REL-ARCH-SEC-01 must NOT be emitted when text mentions dependency injection or package managers."""
        reqs = [{
            "requirement_id": "REQ-ARCH-03",
            "description": "Use dependency injection for service decoupling and manage dependencies with pip."
        }]
        agent = CrossDomainAnalysisAgent(phase2_requirements=reqs)
        res = agent.analyze()
        self.assertNotIn("REL-ARCH-SEC-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    # --- 4. REL-SMELL-SCALE-01 ---
    def test_rel_smell_scale_01_positive(self):
        """REL-SMELL-SCALE-01 emitted when inventory/traversal method has long method smell."""
        smells = [{
            "smell_id": "SMELL-LONG-METHOD",
            "category": "Long Method",
            "file": "src/phase0/ingestion.py",
            "function_or_class": "inventory",
            "evidence": "Function spans 120 lines combining filesystem directory traversal and 9 categorization rules."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertIn("REL-SMELL-SCALE-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_smell_scale_01_negative_unrelated_long_method(self):
        """REL-SMELL-SCALE-01 not emitted for unrelated calculator or helper function."""
        smells = [{
            "smell_id": "SMELL-LONG-METHOD",
            "category": "Long Method",
            "file": "src/utils/math_helper.py",
            "function_or_class": "matrix_solve",
            "evidence": "Spans 90 lines of linear algebra equations."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertNotIn("REL-SMELL-SCALE-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    # --- 5. REL-ARCH-MAINT-01 ---
    def test_rel_arch_maint_01_positive(self):
        """REL-ARCH-MAINT-01 emitted when primitive obsession smell involves inter-phase contracts."""
        smells = [{
            "smell_id": "SMELL-PRIMITIVE-OBSESSION",
            "category": "Inappropriate Abstractions / Primitive Obsession",
            "file": "src/phase1/reconstruction.py",
            "function_or_class": "data_exchange",
            "evidence": "Phase contract boundaries pass raw untyped dictionaries without schema models."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertIn("REL-ARCH-MAINT-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_arch_maint_01_negative_business_logic_primitive_obsession(self):
        """REL-ARCH-MAINT-01 not emitted when primitive obsession is inside internal business calculations."""
        smells = [{
            "smell_id": "SMELL-PRIMITIVE-OBSESSION",
            "category": "Inappropriate Abstractions / Primitive Obsession",
            "file": "src/billing.py",
            "function_or_class": "calc_tax",
            "evidence": "Uses raw floats for monetary currency values instead of Decimal."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertNotIn("REL-ARCH-MAINT-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    # --- 6. REL-SEC-MAINT-01 ---
    def test_rel_sec_maint_01_positive(self):
        """REL-SEC-MAINT-01 emitted when duplicate CLI output / stream sanitization is present."""
        smells = [{
            "smell_id": "SMELL-DUPLICATE-CODE",
            "category": "Duplicate Code",
            "file": "pipeline.py",
            "function_or_class": "safe_write_output",
            "evidence": "CLI safe_write_output and stdout stream reconfiguration duplicated between pipeline.py and ingest.py."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertIn("REL-SEC-MAINT-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_sec_maint_01_positive_sanitization_variants(self):
        """REL-SEC-MAINT-01 emitted when duplicate code sanitizes CLI stdout stream."""
        smells = [{
            "smell_id": "SMELL-DUPLICATE-CODE-CLI",
            "category": "Duplicate Code",
            "file": "cli.py",
            "function_or_class": "emit_results",
            "evidence": "Duplicated logic for sanitizing stdout streams and path traversal boundary check."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertIn("REL-SEC-MAINT-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_rel_sec_maint_01_negative_duplicate_math_helpers(self):
        """REL-SEC-MAINT-01 not emitted for duplicate math helpers (e.g. euclidean distance)."""
        smells = [{
            "smell_id": "SMELL-DUPLICATE-MATH",
            "category": "Duplicate Code",
            "file": "src/math/geom.py",
            "function_or_class": "calculate_euclidean_distance",
            "evidence": "Duplicated math helper between geom.py and trig.py."
        }]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()
        self.assertNotIn("REL-SEC-MAINT-01", [r["relationship_id"] for r in res["cross_domain_relationships"]])

    def test_positive_all_six_relationships_emitted(self):
        """All 6 relationships emitted deterministically when all verified evidence is provided."""
        agent = CrossDomainAnalysisAgent(
            phase2_requirements=[{"requirement_id": "REQ-NFR-02", "description": "zero external dependencies"}],
            phase5a_retest={
                "retest_results": [{
                    "finding_id": "RED-DOS-01",
                    "final_status": "REMEDIATED",
                    "evidence": "Pre-extraction quotas validated in Phase 0 ingestion."
                }]
            },
            phase6_smells=[
                {"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "file": "src/a.py", "evidence": "except Exception: pass"},
                {"smell_id": "SMELL-SCALE", "category": "Long Method", "file": "src/phase0/ingest.py", "function_or_class": "inventory", "evidence": "Monolithic directory traversal"},
                {"smell_id": "SMELL-PRIMITIVE", "category": "Inappropriate Abstractions / Primitive Obsession", "file": "src/pipeline.py", "evidence": "Phase contract boundaries pass untyped dicts"},
                {"smell_id": "SMELL-DUP-CLI", "category": "Duplicate Code", "file": "pipeline.py", "function_or_class": "safe_write_output", "evidence": "CLI safe_write_output duplicated"}
            ]
        )
        res = agent.analyze()
        self.assertEqual(res["total_relationships"], 6)
        self.assertEqual(len(res["cross_domain_relationships"]), 6)

        expected_ids = {
            "REL-SMELL-SEC-01", "REL-SEC-PERF-01", "REL-ARCH-SEC-01",
            "REL-SMELL-SCALE-01", "REL-ARCH-MAINT-01", "REL-SEC-MAINT-01"
        }
        emitted_ids = {r["relationship_id"] for r in res["cross_domain_relationships"]}
        self.assertEqual(expected_ids, emitted_ids)

    # =========================================================================
    # Group C: Input Robustness & Malformed Data Tests
    # =========================================================================

    def test_robustness_all_inputs_none_or_missing(self):
        """Handles omitted or None arguments without crashing, returning 0 relationships."""
        agent1 = CrossDomainAnalysisAgent()
        res1 = agent1.analyze()
        self.assertEqual(res1["total_relationships"], 0)

        agent2 = CrossDomainAnalysisAgent(
            root_path=None,
            phase1_reconstruction=None,
            phase2_requirements=None,
            phase3a_findings=None,
            phase4a_remediations=None,
            phase5a_retest=None,
            phase6_smells=None
        )
        res2 = agent2.analyze()
        self.assertEqual(res2["total_relationships"], 0)

    def test_robustness_wrong_outer_container_types(self):
        """Non-list or non-dict container types are safely handled as empty collections."""
        agent = CrossDomainAnalysisAgent(
            phase1_reconstruction="not_a_dict",  # type: ignore
            phase2_requirements={"req": 1},      # type: ignore
            phase3a_findings=12345,              # type: ignore
            phase4a_remediations=True,           # type: ignore
            phase5a_retest=[1, 2, 3],            # type: ignore
            phase6_smells="smells_string"        # type: ignore
        )
        res = agent.analyze()
        self.assertEqual(res["total_relationships"], 0)

    def test_robustness_malformed_list_members_and_fields(self):
        """Malformed list items (None, numbers, booleans, nested lists) do not crash analysis."""
        reqs = [
            None,
            123,
            "just_a_string",
            {"requirement_id": None, "description": 999},
            {"requirement_id": 42, "description": True},
            {"requirement_id": "REQ-NFR-02", "description": "zero external dependencies"}
        ]
        smells = [
            None,
            {"smell_id": None, "category": None},
            {"smell_id": 999, "category": 888, "evidence": False},
            {"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "file": "src/x.py", "evidence": "except: pass"}
        ]
        agent = CrossDomainAnalysisAgent(phase2_requirements=reqs, phase6_smells=smells)  # type: ignore
        res = agent.analyze()

        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertIn("REL-ARCH-SEC-01", rel_ids)
        self.assertIn("REL-SMELL-SEC-01", rel_ids)

    def test_robustness_no_input_mutation(self):
        """The agent must never mutate caller's lists or dictionaries in place."""
        reqs = [{"requirement_id": "REQ-NFR-02", "description": "zero external dependencies"}]
        smells = [{"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "file": "src/x.py", "evidence": "pass"}]
        reqs_copy = [dict(r) for r in reqs]
        smells_copy = [dict(s) for s in smells]

        agent = CrossDomainAnalysisAgent(phase2_requirements=reqs, phase6_smells=smells)
        _ = agent.analyze()

        self.assertEqual(reqs, reqs_copy)
        self.assertEqual(smells, smells_copy)

    def test_robustness_duplicate_input_findings_do_not_duplicate_relationships(self):
        """Supplying multiple matching findings for the same relationship must not duplicate relationship IDs."""
        smells = [
            {"smell_id": "SMELL-SILENT-1", "category": "Poor Exception Handling", "file": "src/x.py", "evidence": "except: pass"},
            {"smell_id": "SMELL-SILENT-2", "category": "Poor Exception Handling", "file": "src/y.py", "evidence": "except Exception: pass"},
            {"smell_id": "SMELL-SILENT-3", "category": "Poor Exception Handling", "file": "src/z.py", "evidence": "swallowed error"}
        ]
        agent = CrossDomainAnalysisAgent(phase6_smells=smells)
        res = agent.analyze()

        rel_ids = [r["relationship_id"] for r in res["cross_domain_relationships"]]
        self.assertEqual(rel_ids.count("REL-SMELL-SEC-01"), 1)
        self.assertEqual(res["total_relationships"], 1)

    # =========================================================================
    # Group D: Summary Counting, Uniqueness, & Determinism Tests
    # =========================================================================

    def test_summary_counts_strictly_match_relationships(self):
        """Domain interaction counts must strictly match the returned relationships without collisions."""
        agent = CrossDomainAnalysisAgent(
            phase2_requirements=[{"requirement_id": "REQ-NFR-02", "description": "zero external dependencies"}],
            phase6_smells=[
                {"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "file": "src/x.py", "evidence": "except: pass"},
                {"smell_id": "SMELL-DUP", "category": "Duplicate Code", "file": "cli.py", "function_or_class": "safe_write_output", "evidence": "CLI output sanitization duplicated"}
            ]
        )
        res = agent.analyze()

        self.assertEqual(res["total_relationships"], 3)
        self.assertEqual(res["domain_interactions"]["code_smell_security"], 1)
        self.assertEqual(res["domain_interactions"]["security_performance"], 0)
        self.assertEqual(res["domain_interactions"]["architecture_security"], 1)
        self.assertEqual(res["domain_interactions"]["code_smell_scalability"], 0)
        self.assertEqual(res["domain_interactions"]["architecture_maintainability"], 0)
        self.assertEqual(res["domain_interactions"]["security_maintainability"], 1)

        total_sum = sum(res["domain_interactions"].values())
        self.assertEqual(total_sum, res["total_relationships"])

    def test_determinism_and_no_stale_state_between_calls(self):
        """Calling analyze() multiple times on the same instance produces identical results."""
        agent = CrossDomainAnalysisAgent(
            phase2_requirements=[{"requirement_id": "REQ-NFR-02", "description": "zero external dependencies"}]
        )
        res1 = agent.analyze()
        res2 = agent.analyze()

        self.assertEqual(res1["total_relationships"], res2["total_relationships"])
        self.assertEqual(res1["cross_domain_relationships"], res2["cross_domain_relationships"])
        self.assertEqual(res1["domain_interactions"], res2["domain_interactions"])

    # =========================================================================
    # Group E: Security & Source Inspection Tests
    # =========================================================================

    def test_security_source_inspection_path_traversal_rejected(self):
        """Files outside the root_path via path traversal (../) are rejected."""
        outside_dir = tempfile.mkdtemp(prefix="outside_root_")
        self.addCleanup(lambda: shutil.rmtree(outside_dir, ignore_errors=True))

        secret_file = os.path.join(outside_dir, "secret.py")
        with open(secret_file, "w") as f:
            f.write("def extractall(): MAX_SIZE = 100")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    def test_security_source_inspection_oversized_file_skipped(self):
        """Files exceeding 1MB limit during static source inspection are safely skipped."""
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)

        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def extractall(): MAX_SIZE = 100\n")
            f.write("# " + ("A" * 1024 * 1024 * 2) + "\n")

        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        quota_state = agent.evaluate_archive_quota_state()
        self.assertFalse(quota_state["verified"])

    # =========================================================================
    # Group F: Integration Tests (Phase 8, Phase 9, and Full Pipeline)
    # =========================================================================

    def test_integration_downstream_phase8_and_phase9(self):
        """Verifies Phase 7 output is successfully consumed by Phase 8 and Phase 9."""
        agent7 = CrossDomainAnalysisAgent(
            phase2_requirements=[{"requirement_id": "REQ-NFR-02", "description": "zero external dependencies"}],
            phase5a_retest={
                "retest_results": [{
                    "finding_id": "RED-DOS-01",
                    "final_status": "REMEDIATED",
                    "evidence": "Decompression quota verified."
                }]
            },
            phase6_smells=[{"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "file": "src/x.py", "evidence": "except: pass"}]
        )
        p7_output = agent7.analyze()

        # Phase 8 recommendation engine
        agent8 = RecommendationEngineAgent(phase7_relationships=p7_output["cross_domain_relationships"])
        p8_output = agent8.generate_recommendations()
        self.assertIn("recommendations", p8_output)

        # Phase 9 report generator
        agent9 = FinalReportGeneratorAgent(phase7_cross_domain=p7_output)
        md_report = agent9.generate_markdown_report()
        self.assertIn("CROSS-DOMAIN FINDINGS", md_report)
        self.assertIn("REL-SMELL-SEC-01", md_report)

    def test_integration_pipeline_e2e(self):
        """Verifies end-to-end execution of Phase 7 within run_pipeline."""
        dummy_repo = tempfile.mkdtemp(prefix="pipeline_test_repo_")
        self.addCleanup(lambda: shutil.rmtree(dummy_repo, ignore_errors=True))

        with open(os.path.join(dummy_repo, "app.py"), "w") as f:
            f.write("def run():\n    try:\n        pass\n    except Exception:\n        pass\n")

        res = run_pipeline(source=dummy_repo, source_type="dir", phase="7")
        self.assertIn("cross_domain_relationships", res)
        self.assertIn("total_relationships", res)
        self.assertIn("domain_interactions", res)

    # =========================================================================
    # Group G: Dedicated Regression Tests for Verification Semantics and Partial Remediation
    # =========================================================================

    def test_regression_partial_remediation_returns_verified_false(self):
        """Regression: Partial remediation must return verified=False, partial_verification=True, full_verification=False."""
        # Case A: Phase 5A retest has final_status="PARTIALLY_REMEDIATED"
        retest_a = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "PARTIALLY_REMEDIATED",
                "evidence": "Member count check in place; cumulative size check unverified"
            }]
        }
        agent_a = CrossDomainAnalysisAgent(phase5a_retest=retest_a)
        res_a = agent_a.evaluate_archive_quota_state()
        self.assertEqual(res_a["state"], "PARTIALLY_VERIFIED")
        self.assertFalse(res_a["verified"], "Partial remediation MUST set verified=False")
        self.assertFalse(res_a["full_verification"])
        self.assertTrue(res_a["partial_verification"])

        # Case B: Retest evidence explicitly indicates partial implementation
        retest_b = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Partial implementation: per-member check validated, cumulative limit pending"
            }]
        }
        agent_b = CrossDomainAnalysisAgent(phase5a_retest=retest_b)
        res_b = agent_b.evaluate_archive_quota_state()
        self.assertEqual(res_b["state"], "PARTIALLY_VERIFIED")
        self.assertFalse(res_b["verified"], "Partial implementation note MUST set verified=False")
        self.assertFalse(res_b["full_verification"])
        self.assertTrue(res_b["partial_verification"])

        # Case C: Source AST only has per-member size check
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def extract(zf, dest):\n    for i in zf.infolist():\n        if i.file_size > 1000: raise Exception()\n    zf.extractall(dest)\n")
        agent_c = CrossDomainAnalysisAgent(root_path=self.test_dir)
        res_c = agent_c.evaluate_archive_quota_state()
        self.assertEqual(res_c["state"], "PARTIALLY_VERIFIED")
        self.assertFalse(res_c["verified"], "Partial source controls MUST set verified=False")
        self.assertFalse(res_c["full_verification"])
        self.assertTrue(res_c["partial_verification"])

    def test_regression_generic_remediation_evidence_not_full_verification(self):
        """Regression: Generic remediation evidence must not produce full verification or verified=True."""
        generic_samples = [
            "Resolved during sprint code review.",
            "Issue resolved and closed.",
            "Completed security remediation task.",
            "Code updated per recommendations.",
            "Fix verified by team lead.",
        ]
        for sample in generic_samples:
            retest = {
                "retest_results": [{
                    "finding_id": "RED-DOS-01",
                    "final_status": "REMEDIATED",
                    "evidence": sample
                }]
            }
            agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
            res = agent.evaluate_archive_quota_state()
            self.assertEqual(res["state"], "UNVERIFIED", f"Sample '{sample}' should be UNVERIFIED")
            self.assertFalse(res["verified"], f"Sample '{sample}' must return verified=False")
            self.assertFalse(res["full_verification"])
            self.assertFalse(res["partial_verification"])

            analysis = agent.analyze()
            rel_ids = [r["relationship_id"] for r in analysis["cross_domain_relationships"]]
            self.assertNotIn("REL-SEC-PERF-01", rel_ids, f"Generic evidence '{sample}' must not emit REL-SEC-PERF-01")

    def test_regression_conflicting_evidence_not_full_verification(self):
        """Regression: Conflicting evidence must not produce full verification or verified=True."""
        # Retest claims REMEDIATED with validated quotas, but source code extraction is unguarded
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write("def unshielded_extract(zf, dest):\n    zf.extractall(dest)\n")

        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Pre-extraction quotas validated in Phase 0 ingestion."
            }]
        }
        agent = CrossDomainAnalysisAgent(root_path=self.test_dir, phase5a_retest=retest)
        res = agent.evaluate_archive_quota_state()
        self.assertEqual(res["state"], "CONFLICTING_EVIDENCE")
        self.assertFalse(res["verified"], "Conflicting evidence MUST set verified=False")
        self.assertFalse(res["full_verification"])
        self.assertFalse(res["partial_verification"])

        analysis = agent.analyze()
        rel_ids = [r["relationship_id"] for r in analysis["cross_domain_relationships"]]
        self.assertNotIn("REL-SEC-PERF-01", rel_ids, "Conflicting evidence must not emit REL-SEC-PERF-01")

    def test_regression_missing_evidence_remains_unverified(self):
        """Regression: Missing or empty evidence must remain unverified with verified=False."""
        for empty_ev in ("", "   ", None):
            retest = {
                "retest_results": [{
                    "finding_id": "RED-DOS-01",
                    "final_status": "REMEDIATED",
                    "evidence": empty_ev,
                    "result": ""
                }]
            }
            agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
            res = agent.evaluate_archive_quota_state()
            self.assertEqual(res["state"], "UNVERIFIED")
            self.assertFalse(res["verified"], "Missing evidence MUST set verified=False")
            self.assertFalse(res["full_verification"])
            self.assertFalse(res["partial_verification"])

            analysis = agent.analyze()
            rel_ids = [r["relationship_id"] for r in analysis["cross_domain_relationships"]]
            self.assertNotIn("REL-SEC-PERF-01", rel_ids, "Missing evidence must not emit REL-SEC-PERF-01")

    def test_regression_keywords_alone_not_full_verification(self):
        """Regression: Remediation keywords alone without test verification evidence must not produce full verification."""
        keyword_samples = [
            "Code mentions quota and max_bytes.",
            "Archive module has compression ratio and member count variables.",
            "Zip bomb defense keywords added to documentation.",
            "Decompression bomb quota max_bytes limit mentioned.",
        ]
        for sample in keyword_samples:
            retest = {
                "retest_results": [{
                    "finding_id": "RED-DOS-01",
                    "final_status": "REMEDIATED",
                    "evidence": sample
                }]
            }
            agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
            res = agent.evaluate_archive_quota_state()
            self.assertNotEqual(res["state"], "VERIFIED_PRESENT", f"Sample '{sample}' must not be VERIFIED_PRESENT")
            self.assertFalse(res["verified"], f"Sample '{sample}' must return verified=False")
            self.assertFalse(res["full_verification"])

    def test_regression_concrete_tested_evidence_returns_verified_true(self):
        """Regression: Concrete, sufficient evidence of successful verification may return verified=True."""
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "REMEDIATED",
                "evidence": "Pre-extraction inspection checks max_uncompressed_bytes (100MB) and max_files (5000) passed."
            }]
        }
        agent = CrossDomainAnalysisAgent(phase5a_retest=retest)
        res = agent.evaluate_archive_quota_state()
        self.assertEqual(res["state"], "VERIFIED_PRESENT")
        self.assertTrue(res["verified"], "Concrete tested evidence MUST return verified=True")
        self.assertTrue(res["full_verification"])
        self.assertFalse(res["partial_verification"])

        analysis = agent.analyze()
        rel_ids = [r["relationship_id"] for r in analysis["cross_domain_relationships"]]
        self.assertIn("REL-SEC-PERF-01", rel_ids, "Concrete tested evidence MUST emit REL-SEC-PERF-01")
        rel = next(r for r in analysis["cross_domain_relationships"] if r["relationship_id"] == "REL-SEC-PERF-01")
        self.assertNotIn("Partial", rel["consequence"])

    def test_regression_fully_verified_findings_retain_full_verification_state(self):
        """Regression: Fully verified findings must retain full_verification=True, partial_verification=False."""
        # Source-level full verification (cumulative size before extraction)
        ingest_path = os.path.join(self.test_dir, "src", "phase0", "ingestion.py")
        os.makedirs(os.path.dirname(ingest_path), exist_ok=True)
        with open(ingest_path, "w", encoding="utf-8") as f:
            f.write(
                "def extract(zf, dest):\n"
                "    total_size = 0\n"
                "    for i in zf.infolist():\n"
                "        total_size += i.file_size\n"
                "        if total_size > 50000000:\n"
                "            raise ValueError('Total size exceeded')\n"
                "    zf.extractall(dest)\n"
            )
        agent = CrossDomainAnalysisAgent(root_path=self.test_dir)
        res = agent.evaluate_archive_quota_state()
        self.assertEqual(res["state"], "VERIFIED_PRESENT")
        self.assertTrue(res["verified"])
        self.assertTrue(res["full_verification"])
        self.assertFalse(res["partial_verification"])


if __name__ == "__main__":
    unittest.main()
