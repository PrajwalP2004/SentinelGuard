"""
Unit, regression, boundary, and integration tests for Phase 8:
RecommendationEngineAgent (Senior Software Engineering Recommendation Engine).

Covers:
1. Input robustness, omitted arguments, wrong container types, and immutability.
2. Phase 1 reconstruction integration (traceable architectural facts without invention).
3. Phase 2 requirements integration (traceable requirement linking).
4. Phase 3A & Phase 4A integration (root cause, recommended changes, hardening, arbitrary finding IDs).
5. Phase 5A retest status integration (remediated, partially remediated, unresolved, conflicting, unverified).
6. Phase 6 & Phase 7 smells and cross-domain interactions (REL-SMELL-SEC-01, REL-SEC-PERF-01, REL-SMELL-SCALE-01).
7. Phase 7 standalone architectural recommendations (REL-ARCH-SEC-01, REL-ARCH-MAINT-01, REL-SEC-MAINT-01).
8. Deduplication across phases and provenance tracking.
9. Downstream Phase 9 compatibility and markdown rendering.
"""

import copy
import unittest
from typing import Dict, Any, List

from src.phase8.recommendations import RecommendationEngineAgent
from src.phase9.report import FinalReportGeneratorAgent


class TestPhase8RecommendationEngine(unittest.TestCase):
    """Exhaustive test suite for RecommendationEngineAgent."""

    REQUIRED_REC_KEYS = [
        "recommendation_id", "problem", "evidence", "requirement_affected",
        "current_implementation", "recommended_change", "technical_reasoning",
        "alternatives", "trade_offs", "implementation_complexity",
        "security_impact", "maintainability_impact", "cost_considerations",
        "dependencies", "priority", "confidence"
    ]
    VALID_PRIORITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

    def _assert_valid_recommendation_schema(self, rec: Dict[str, Any]):
        for key in self.REQUIRED_REC_KEYS:
            self.assertIn(key, rec, f"Recommendation missing required key: {key}")
            self.assertIsInstance(rec[key], str, f"Key '{key}' should be a string")
            self.assertTrue(len(rec[key]) > 0, f"Key '{key}' should not be empty")
        self.assertIn(rec["priority"], self.VALID_PRIORITIES)
        self.assertTrue(rec["recommendation_id"].startswith("REC-"))

    # =========================================================================
    # Group 1: Input Robustness & Container Handling
    # =========================================================================

    def test_all_inputs_omitted_or_none(self):
        """Initializes with no arguments or None without crashing, returning valid baseline recommendations."""
        agent = RecommendationEngineAgent()
        res = agent.generate_recommendations()

        self.assertIn("recommendations", res)
        self.assertIn("total_recommendations", res)
        self.assertIn("summary", res)
        self.assertGreaterEqual(res["total_recommendations"], 3)
        for r in res["recommendations"]:
            self._assert_valid_recommendation_schema(r)

    def test_wrong_container_types_handled_gracefully(self):
        """Handles dicts instead of lists, invalid types, and malformed list elements."""
        agent = RecommendationEngineAgent(
            phase1_reconstruction="not_a_dict",  # type: ignore
            phase2_requirements={"requirements": [{"requirement_id": "REQ-01", "title": "Core"}]},  # type: ignore
            phase3a_findings={"findings": [{"finding_id": "RED-SQL-01"}]},  # type: ignore
            phase4a_remediations={"remediation_plans": [{"finding_id": "RED-SQL-01"}]},  # type: ignore
            phase5a_retest=[{"finding_id": "RED-SQL-01", "final_status": "REMEDIATED"}],  # type: ignore
            phase6_smells={"code_smells": [{"smell_id": "SMELL-01", "category": "Poor Exception Handling"}]},  # type: ignore
            phase7_relationships={"cross_domain_relationships": [{"relationship_id": "REL-ARCH-SEC-01"}]}  # type: ignore
        )
        res = agent.generate_recommendations()
        self.assertGreaterEqual(res["total_recommendations"], 1)
        for r in res["recommendations"]:
            self._assert_valid_recommendation_schema(r)

    def test_input_immutability(self):
        """Ensures the agent does not mutate caller's data in place."""
        orig_findings = [{"finding_id": "RED-SQL-01", "affected_files": ["app.py"]}]
        findings_copy = copy.deepcopy(orig_findings)

        agent = RecommendationEngineAgent(phase3a_findings=orig_findings)
        agent.generate_recommendations()

        self.assertEqual(orig_findings, findings_copy)

    # =========================================================================
    # Group 2: Phase 1 Reconstruction Integration (Traceable Facts)
    # =========================================================================

    def test_phase1_database_and_framework_context_enrichment(self):
        """Enriches recommendations with concrete database facts without inventing details."""
        p1 = {
            "project_summary": {"name": "InventoryApp"},
            "databases": [{"type": "SQLite", "file": "data.db"}],
            "frameworks": ["Flask"]
        }
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["db.py"]}]
        agent = RecommendationEngineAgent(phase1_reconstruction=p1, phase3a_findings=findings)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertIn("SQLite", sql_rec["evidence"])

    def test_phase1_does_not_invent_facts_when_absent(self):
        """When Phase 1 lacks database metadata, does not invent specific database names."""
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["query.py"]}]
        agent = RecommendationEngineAgent(phase1_reconstruction={}, phase3a_findings=findings)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertNotIn("Database detected in Phase 1", sql_rec["evidence"])

    # =========================================================================
    # Group 3: Phase 2 Requirement Linking
    # =========================================================================

    def test_phase2_requirement_linking_explicit_id(self):
        """Links recommendations to verified Phase 2 requirements matching explicit finding IDs."""
        reqs = [
            {"requirement_id": "REQ-SEC-01", "title": "Database Input Parameterization"},
            {"requirement_id": "REQ-NFR-03", "title": "Diagnostic Logging Standards"}
        ]
        findings = [{"finding_id": "RED-SQL-01", "requirement_affected": "REQ-SEC-01"}]
        agent = RecommendationEngineAgent(phase2_requirements=reqs, phase3a_findings=findings)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertEqual(sql_rec["requirement_affected"], "REQ-SEC-01: Database Input Parameterization")

    def test_phase2_requirement_linking_by_category(self):
        """Matches recommendations by category when finding lacks explicit requirement ID."""
        reqs = [
            {"requirement_id": "REQ-LOG-01", "category": "observability", "title": "Structured Log Output"}
        ]
        smells = [{"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "evidence": "except: pass"}]
        agent = RecommendationEngineAgent(phase2_requirements=reqs, phase6_smells=smells)
        res = agent.generate_recommendations()

        silent_rec = next(r for r in res["recommendations"] if "Silent" in r["problem"])
        self.assertIn("REQ-LOG-01", silent_rec["requirement_affected"])

    # =========================================================================
    # Group 4: Phase 3A & Phase 4A Remediation Plan Integration
    # =========================================================================

    def test_phase4a_remediation_plan_enriches_recommendation(self):
        """Incorporate root causes, recommended changes, hardening, and regression risks from Phase 4A."""
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["src/db.py"]}]
        plans = [{
            "finding_id": "RED-SQL-01",
            "root_cause": "Dynamic string concatenation in cursor.execute mixes code and data.",
            "remediation": "Use driver parameter placeholders (? for SQLite).",
            "recommended_changes": ["Replace string format with tuple parameter"],
            "hardening_measures": ["Adopt ORM with schema-level validation"],
            "regression_risks": ["Driver placeholder syntax variations must match engine"]
        }]
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase4a_remediations=plans)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertIn("Dynamic string concatenation", sql_rec["technical_reasoning"])
        self.assertIn("Driver placeholder syntax variations", sql_rec["trade_offs"])

    def test_custom_upstream_finding_not_silently_discarded(self):
        """Findings with arbitrary/custom IDs (e.g. RED-XSS-01) are synthesized rather than silently dropped."""
        findings = [{
            "finding_id": "RED-XSS-01",
            "title": "Reflected Cross-Site Scripting in Search Query",
            "affected_files": ["src/views/search.py"],
            "severity": "HIGH",
            "evidence": "Template renders query parameter directly without HTML escaping.",
            "impact": "Session hijacking via injected JavaScript."
        }]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        rec_problems = [r["problem"] for r in res["recommendations"]]
        self.assertTrue(any("RED-XSS-01" in p for p in rec_problems))

    # =========================================================================
    # Group 5: Phase 5A Retest Status Integration
    # =========================================================================

    def test_retest_remediated_downgrades_priority_and_recommends_regression_testing(self):
        """REMEDIATED status downgrades priority from CRITICAL/HIGH to LOW and focuses on regression guard."""
        findings = [{"finding_id": "RED-SQL-01", "severity": "CRITICAL"}]
        retest = {
            "retest_results": [{
                "finding_id": "RED-SQL-01",
                "final_status": "REMEDIATED",
                "result": "Parameterized query placeholders validated across all database calls.",
                "evidence": "db.py lines 12-15 use cursor.execute('SELECT ...', (uid,))"
            }]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertEqual(sql_rec["priority"], "LOW")
        self.assertIn("Maintain and continuously verify", sql_rec["problem"])
        self.assertIn("REMEDIATED", sql_rec["current_implementation"])

    def test_retest_partially_remediated_highlights_residual_risk(self):
        """PARTIALLY_REMEDIATED status retains elevated priority and explicitly highlights remaining risk."""
        findings = [{"finding_id": "RED-SQL-01", "severity": "CRITICAL"}]
        retest = {
            "retest_results": [{
                "finding_id": "RED-SQL-01",
                "final_status": "PARTIALLY_REMEDIATED",
                "result": "User query parameterized, but admin filter remains dynamic.",
                "remaining_risk": "Admin search endpoint vulnerable to SQL injection."
            }]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertEqual(sql_rec["priority"], "HIGH")
        self.assertIn("partial controls leave", sql_rec["problem"].lower())
        self.assertIn("Admin search endpoint vulnerable", sql_rec["current_implementation"])

    def test_retest_not_remediated_maintains_critical_priority(self):
        """NOT_REMEDIATED status maintains critical/high priority reflecting active exploitability."""
        findings = [{"finding_id": "RED-SQL-01", "severity": "CRITICAL"}]
        retest = {
            "retest_results": [{
                "finding_id": "RED-SQL-01",
                "final_status": "NOT_REMEDIATED",
                "result": "Query still constructed using f-strings.",
                "remaining_risk": "Arbitrary SQL execution remains possible."
            }]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertEqual(sql_rec["priority"], "CRITICAL")

    def test_retest_untested_or_missing_not_assumed_remediated(self):
        """Missing retest data or NOT_TESTABLE status is NOT assumed remediated; preserves original priority."""
        findings = [{"finding_id": "RED-CMD-01", "severity": "CRITICAL"}]
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest={})
        res = agent.generate_recommendations()

        cmd_rec = next(r for r in res["recommendations"] if "RED-CMD-01" in r["problem"] or "command execution" in r["problem"].lower())
        self.assertEqual(cmd_rec["priority"], "CRITICAL")
        self.assertIn("CRITICAL", [r["priority"] for r in res["recommendations"]])

    def test_retest_conflicting_evidence_triggers_verification_recommendation(self):
        """Conflicting evidence triggers manual review warning and CONFLICTED status."""
        findings = [{"finding_id": "RED-DOS-01", "severity": "HIGH"}]
        retest = {
            "retest_results": [{
                "finding_id": "RED-DOS-01",
                "final_status": "CONFLICTED",
                "result": "Retest asserted REMEDIATED but static source inspection detected unshielded extraction.",
                "evidence": "Conflicting evidence between test fixture and repository source code."
            }]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        dos_rec = next(r for r in res["recommendations"] if "RED-DOS-01" in r["problem"])
        self.assertIn("conflicting evidence", dos_rec["problem"].lower())
        self.assertEqual(dos_rec["priority"], "HIGH")

    # =========================================================================
    # Group 6: Phase 6 & Phase 7 Cross-Domain Influences
    # =========================================================================

    def test_phase7_rel_smell_sec_01_elevates_silent_exception_priority(self):
        """REL-SMELL-SEC-01 elevates silent exception suppression priority and notes audit impact."""
        smells = [{"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "evidence": "except Exception: pass"}]
        rels = [{
            "relationship_id": "REL-SMELL-SEC-01",
            "relationship": "Code Smell Undermines Security Observability",
            "consequence": "Unhandled exceptions in component execution are discarded without diagnostic logging."
        }]
        agent = RecommendationEngineAgent(phase6_smells=smells, phase7_relationships=rels)
        res = agent.generate_recommendations()

        silent_rec = next(r for r in res["recommendations"] if "Silent" in r["problem"])
        self.assertEqual(silent_rec["priority"], "HIGH")
        self.assertIn("REL-SMELL-SEC-01", silent_rec["security_impact"])

    def test_phase7_rel_sec_perf_01_enriches_dos_tradeoffs(self):
        """REL-SEC-PERF-01 enriches RED-DOS-01 recommendation with latency overhead trade-off."""
        findings = [{"finding_id": "RED-DOS-01", "severity": "HIGH"}]
        rels = [{
            "relationship_id": "REL-SEC-PERF-01",
            "relationship": "Defensive Security Quota Pre-Scan Adds Potential Computational Overhead",
            "consequence": "Pre-scan validation loops across archive entries introduce computational processing overhead."
        }]
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase7_relationships=rels)
        res = agent.generate_recommendations()

        dos_rec = next(r for r in res["recommendations"] if "RED-DOS-01" in r["problem"])
        self.assertIn("REL-SEC-PERF-01", dos_rec["trade_offs"])

    def test_phase7_rel_smell_scale_01_highlights_traversal_bottleneck(self):
        """REL-SMELL-SCALE-01 enriches traversal smell recommendation with scalability bottleneck."""
        smells = [{
            "smell_id": "SMELL-SCALE",
            "category": "Long Method",
            "function_or_class": "inventory",
            "evidence": "Deep nesting and 120 lines in directory traversal."
        }]
        rels = [{
            "relationship_id": "REL-SMELL-SCALE-01",
            "relationship": "Monolithic Traversal Logic Poses Potential Scalability Constraint",
            "consequence": "High cyclomatic complexity represents a plausible scaling bottleneck under large file counts."
        }]
        agent = RecommendationEngineAgent(phase6_smells=smells, phase7_relationships=rels)
        res = agent.generate_recommendations()

        scale_rec = next(r for r in res["recommendations"] if "REL-SMELL-SCALE-01" in r["problem"])
        self.assertIn("scalability bottleneck", scale_rec["problem"].lower())

    # =========================================================================
    # Group 7: Standalone Phase 7 Architectural Recommendations
    # =========================================================================

    def test_phase7_standalone_architectural_recommendations(self):
        """Distinct Phase 7 relationships (REL-ARCH-SEC-01, REL-ARCH-MAINT-01, REL-SEC-MAINT-01) generate architectural recommendations."""
        rels = [
            {
                "relationship_id": "REL-ARCH-SEC-01",
                "evidence": "Zero external dependencies requirement.",
                "consequence": "Standard library reliance shifts maintenance responsibility to internal code.",
                "recommended_action": "Maintain zero-dependency constraint backed by unit test harnesses."
            },
            {
                "relationship_id": "REL-ARCH-MAINT-01",
                "evidence": "Phase contract boundaries pass untyped dictionaries.",
                "consequence": "Untyped dictionaries increase coupling and schema drift risks.",
                "recommended_action": "Formalize inter-phase data exchange using TypedDict schemas."
            },
            {
                "relationship_id": "REL-SEC-MAINT-01",
                "evidence": "Duplicated CLI output sanitization across entry points.",
                "consequence": "Duplicated sanitization logic risks divergent updates.",
                "recommended_action": "Consolidate duplicated CLI sanitization into a shared utility."
            }
        ]
        agent = RecommendationEngineAgent(phase7_relationships=rels)
        res = agent.generate_recommendations()

        rec_problems = [r["problem"] for r in res["recommendations"]]
        self.assertTrue(any("REL-ARCH-SEC-01" in p for p in rec_problems))
        self.assertTrue(any("REL-ARCH-MAINT-01" in p for p in rec_problems))
        self.assertTrue(any("REL-SEC-MAINT-01" in p for p in rec_problems))

    # =========================================================================
    # Group 8: Deduplication & Provenance Across Phases
    # =========================================================================

    def test_deduplication_same_finding_across_multiple_phases(self):
        """When an issue appears across Phase 3A, 4A, and 5A, generates exactly ONE merged recommendation tracking provenance."""
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["app.py"]}]
        plans = [{"finding_id": "RED-SQL-01", "remediation": "Use parameterized queries."}]
        retest = {
            "retest_results": [{
                "finding_id": "RED-SQL-01",
                "final_status": "REMEDIATED",
                "result": "Parameterized queries active."
            }]
        }
        agent = RecommendationEngineAgent(
            phase3a_findings=findings,
            phase4a_remediations=plans,
            phase5a_retest=retest
        )
        res = agent.generate_recommendations()

        sql_recs = [r for r in res["recommendations"] if "SQL" in r["problem"]]
        self.assertEqual(len(sql_recs), 1, "Duplicate finding across phases MUST be deduplicated into a single recommendation")

        rec = sql_recs[0]
        self.assertIn("phase_sources", rec)
        self.assertIn("Phase 3A", rec["phase_sources"])
        self.assertIn("Phase 4A", rec["phase_sources"])
        self.assertIn("Phase 5A", rec["phase_sources"])

    def test_duplicate_input_records_do_not_duplicate_recommendations(self):
        """Supplying identical finding records multiple times does not produce duplicate recommendations."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["app.py"]},
            {"finding_id": "RED-SQL-01", "affected_files": ["app.py"]},
            {"finding_id": "RED-SQL-01", "affected_files": ["app.py"]}
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        sql_recs = [r for r in res["recommendations"] if "SQL" in r["problem"]]
        self.assertEqual(len(sql_recs), 1)

    # =========================================================================
    # Group 9: Downstream Phase 9 Report Compatibility
    # =========================================================================

    def test_downstream_phase9_compatibility(self):
        """Verifies that Phase 9 report generator successfully consumes Phase 8 output."""
        agent8 = RecommendationEngineAgent(
            phase3a_findings=[{"finding_id": "RED-SQL-01"}],
            phase5a_retest={"retest_results": [{"finding_id": "RED-SQL-01", "final_status": "REMEDIATED"}]},
            phase6_smells=[{"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "evidence": "except: pass"}],
            phase7_relationships=[{"relationship_id": "REL-ARCH-SEC-01", "evidence": "Zero dependency"}]
        )
        p8_output = agent8.generate_recommendations()

        agent9 = FinalReportGeneratorAgent(phase8_recommendations=p8_output)
        report_data = agent9.generate_report_data()
        self.assertIn("findings_count", report_data)
        self.assertEqual(report_data["findings_count"]["recommendations_count"], p8_output["total_recommendations"])

        markdown = agent9.generate_markdown_report()
        self.assertIn("11. PRIORITIZED RECOMMENDATIONS", markdown)
        self.assertIn("REC-01", markdown)


    # =========================================================================
    # Group 10: Proportionate Language, Evidence Traceability & Technical Depth
    # =========================================================================

    def test_no_uncalibrated_absolute_security_claims(self):
        """Verifies that generated recommendations do not contain absolute, uncalibrated claims."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "evidence": "f'SELECT * FROM u WHERE id={id}'"},
            {"finding_id": "RED-SECRET-01", "affected_files": ["config.py"], "evidence": "SECRET_KEY = 'hardcoded'"},
            {"finding_id": "RED-DOS-01", "affected_files": ["extract.py"], "evidence": "zip.extractall()"},
            {"finding_id": "RED-DEBUG-01", "affected_files": ["app.py"], "evidence": "app.run(debug=True)"},
            {"finding_id": "RED-CMD-01", "affected_files": ["cli.py"], "evidence": "subprocess.run(cmd, shell=True)"},
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"], "evidence": "joblib.load(f)"},
            {"finding_id": "RED-CORS-01", "affected_files": ["app.py"], "evidence": "CORS(app, origins='*')"},
            {"finding_id": "RED-INJ-01", "affected_files": ["git.py"], "evidence": "git clone uri"},
            {"finding_id": "RED-CRYPTO-01", "affected_files": ["hash.py"], "evidence": "hashlib.md5()"},
        ]
        smells = [{"smell_id": "SMELL-SILENT", "category": "Poor Exception Handling", "evidence": "except Exception: pass"}]
        rels = [
            {"relationship_id": "REL-ARCH-SEC-01", "evidence": "Zero dependency"},
            {"relationship_id": "REL-ARCH-MAINT-01", "evidence": "Untyped dicts"},
            {"relationship_id": "REL-SEC-MAINT-01", "evidence": "Duplicated CLI sanitization"}
        ]
        agent = RecommendationEngineAgent(
            phase3a_findings=findings,
            phase6_smells=smells,
            phase7_relationships=rels
        )
        res = agent.generate_recommendations()

        forbidden_phrases = [
            "completely eliminates",
            "renders impossible",
            "structurally impossible",
            "guarantees safe",
            "guarantees reproducible",
            "eliminates arbitrary",
            "proves that",
            "eliminates collision",
            "eliminates shell",
        ]

        for rec in res["recommendations"]:
            for field in ("problem", "technical_reasoning", "security_impact", "recommended_change", "maintainability_impact"):
                val = rec.get(field, "").lower()
                for phrase in forbidden_phrases:
                    self.assertNotIn(
                        phrase,
                        val,
                        f"Absolute claim '{phrase}' found in rec '{rec['recommendation_id']}' field '{field}': {val}"
                    )

    def test_security_impact_states_risk_reduction_and_residual_risks(self):
        """Verifies that security recommendations explicitly explain risk reduction and state assumptions/residual risks."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"]},
            {"finding_id": "RED-SECRET-01", "affected_files": ["config.py"]},
            {"finding_id": "RED-DOS-01", "affected_files": ["extract.py"]},
            {"finding_id": "RED-DEBUG-01", "affected_files": ["app.py"]},
            {"finding_id": "RED-CMD-01", "affected_files": ["cli.py"]},
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"]},
            {"finding_id": "RED-CORS-01", "affected_files": ["app.py"]},
            {"finding_id": "RED-INJ-01", "affected_files": ["git.py"]},
            {"finding_id": "RED-CRYPTO-01", "affected_files": ["hash.py"]},
            {"finding_id": "RED-CUSTOM-99", "title": "Custom Flaw", "affected_files": ["mod.py"]},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        for rec in res["recommendations"]:
            sec_impact = rec.get("security_impact", "")
            self.assertIn("Risk reduction:", sec_impact, f"Rec '{rec['recommendation_id']}' missing 'Risk reduction:'")
            self.assertIn("Assumptions & Residual Risks:", sec_impact, f"Rec '{rec['recommendation_id']}' missing 'Assumptions & Residual Risks:'")

    def test_baseline_recommendations_do_not_fabricate_vulnerabilities(self):
        """Baseline recommendations generated when inputs are empty must be clearly labeled as proactive baselines."""
        agent = RecommendationEngineAgent()
        res = agent.generate_recommendations()

        for rec in res["recommendations"]:
            self.assertTrue(
                rec["finding_id"].startswith("BASE-"),
                f"Expected BASE finding ID, got {rec['finding_id']}"
            )
            self.assertIn("proactive", rec["problem"].lower())
            self.assertIn("proactive", rec["evidence"].lower())
            # Must not claim concrete vulnerability exists
            self.assertNotIn("vulnerability detected", rec["problem"].lower())
            self.assertNotIn("vulnerability detected", rec["evidence"].lower())

    def test_missing_evidence_handled_without_inventing_facts(self):
        """When findings lack evidence or affected files, does not hallucinate arbitrary file names or snippets."""
        findings = [{"finding_id": "RED-SQL-01"}]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        self.assertIn("unspecified in upstream findings", sql_rec["evidence"].lower())
        self.assertIn("without specific code snippet", sql_rec["evidence"].lower())

    def test_evidence_traceability_distinguishes_source_from_retest(self):
        """Evidence field clearly distinguishes observed source code facts from Phase 5A retest verification."""
        findings = [{
            "finding_id": "RED-SQL-01",
            "affected_files": ["src/db.py"],
            "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')"
        }]
        retest = {
            "retest_results": [{
                "finding_id": "RED-SQL-01",
                "final_status": "REMEDIATED",
                "result": "Parameterized query active: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
            }]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        sql_rec = next(r for r in res["recommendations"] if "SQL" in r["problem"])
        evidence = sql_rec["evidence"]
        self.assertIn("File(s) src/db.py", evidence)
        self.assertIn("cursor.execute(f'SELECT", evidence)
        self.assertIn("Retest verification (Phase 5A)", evidence)
        self.assertIn("REMEDIATED", evidence)

    def test_technically_appropriate_guidance_across_all_vulnerability_categories(self):
        """Checks that each specific vulnerability category has technically precise and appropriate guidance."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"]},
            {"finding_id": "RED-CMD-01", "affected_files": ["cli.py"]},
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"]},
            {"finding_id": "RED-DOS-01", "affected_files": ["extract.py"]},
            {"finding_id": "RED-SECRET-01", "affected_files": ["auth.py"]},
            {"finding_id": "RED-CORS-01", "affected_files": ["server.py"]},
            {"finding_id": "RED-DEBUG-01", "affected_files": ["server.py"]},
            {"finding_id": "RED-CRYPTO-01", "affected_files": ["crypto.py"]},
            {"finding_id": "RED-INJ-01", "affected_files": ["git.py"]},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        recs_by_fid = {r["finding_id"]: r for r in res["recommendations"]}

        # SQL
        self.assertIn("parameterized placeholders", recs_by_fid["RED-SQL-01"]["recommended_change"].lower())
        self.assertIn("second-order", recs_by_fid["RED-SQL-01"]["security_impact"].lower())

        # CMD
        self.assertIn("shell=false", recs_by_fid["RED-CMD-01"]["recommended_change"].lower())
        self.assertIn("argument/option injection", recs_by_fid["RED-CMD-01"]["security_impact"].lower())

        # DESER
        self.assertIn("hmac", recs_by_fid["RED-DESER-01"]["recommended_change"].lower())
        self.assertIn("safetensors", recs_by_fid["RED-DESER-01"]["security_impact"].lower())

        # DOS
        self.assertIn("byte ceilings", recs_by_fid["RED-DOS-01"]["security_impact"].lower())
        self.assertIn("timeouts", recs_by_fid["RED-DOS-01"]["security_impact"].lower())

        # SECRET
        self.assertIn("environment variables", recs_by_fid["RED-SECRET-01"]["recommended_change"].lower())
        self.assertIn("rotated immediately", recs_by_fid["RED-SECRET-01"]["security_impact"].lower())

        # CORS
        self.assertIn("whitelist", recs_by_fid["RED-CORS-01"]["recommended_change"].lower())
        self.assertIn("web browsers", recs_by_fid["RED-CORS-01"]["security_impact"].lower())

        # DEBUG
        self.assertIn("flask_debug", recs_by_fid["RED-DEBUG-01"]["recommended_change"].lower())
        self.assertIn("wsgi/asgi", recs_by_fid["RED-DEBUG-01"]["security_impact"].lower())

        # CRYPTO
        self.assertIn("sha-256", recs_by_fid["RED-CRYPTO-01"]["recommended_change"].lower())
        self.assertIn("argon2", recs_by_fid["RED-CRYPTO-01"]["security_impact"].lower())

        # INJ
        self.assertIn("--", recs_by_fid["RED-INJ-01"]["recommended_change"])
        self.assertIn("positional argument delimiter", recs_by_fid["RED-INJ-01"]["security_impact"].lower())


    # =========================================================================
    # Group 11: Baseline Guidance Disambiguation, Scoping & Configurable Inclusion
    # =========================================================================

    def test_zero_findings_with_baseline_default(self):
        """Zero findings with default configuration provides baseline guidance clearly tagged as general guidance."""
        agent = RecommendationEngineAgent()
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 3)
        self.assertEqual(res["summary"]["findings_driven"], 0)
        self.assertEqual(res["summary"]["baseline_guidance"], 3)
        self.assertEqual(res["summary"]["critical"], 0)
        self.assertEqual(res["summary"]["high"], 0)

        for rec in res["recommendations"]:
            self.assertEqual(rec["recommendation_type"], "baseline_guidance")
            self.assertIn("Baseline Guidance", rec["phase_sources"])
            self.assertEqual(rec["priority"], "LOW")
            self.assertIn("proactive", rec["problem"].lower())

    def test_zero_findings_with_baseline_disabled(self):
        """Zero findings with include_baseline_guidance=False produces zero recommendations without inflating counts."""
        agent = RecommendationEngineAgent(include_baseline_guidance=False)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 0)
        self.assertEqual(res["recommendations"], [])
        self.assertEqual(res["summary"]["findings_driven"], 0)
        self.assertEqual(res["summary"]["baseline_guidance"], 0)
        self.assertEqual(res["summary"]["critical"], 0)
        self.assertEqual(res["summary"]["high"], 0)

    def test_one_finding_does_not_pad_to_arbitrary_count(self):
        """When 1 finding exists, does not arbitrarily pad to 4 baseline recommendations."""
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "severity": "CRITICAL"}]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        # Must NOT pad to 4!
        self.assertEqual(res["total_recommendations"], 1)
        self.assertEqual(len(res["recommendations"]), 1)
        self.assertEqual(res["summary"]["findings_driven"], 1)
        self.assertEqual(res["summary"]["baseline_guidance"], 0)
        self.assertEqual(res["summary"]["critical"], 1)

        rec = res["recommendations"][0]
        self.assertEqual(rec["recommendation_type"], "finding_driven")
        self.assertEqual(rec["recommendation_id"], "REC-01")
        self.assertIn("RED-SQL-01", rec["finding_id"])

    def test_several_findings_without_baseline(self):
        """When several findings exist, generates exactly those finding-driven recommendations without padding."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "severity": "CRITICAL"},
            {"finding_id": "RED-CMD-01", "affected_files": ["cli.py"], "severity": "CRITICAL"},
            {"finding_id": "RED-DOS-01", "affected_files": ["extract.py"], "severity": "HIGH"},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 3)
        self.assertEqual(res["summary"]["findings_driven"], 3)
        self.assertEqual(res["summary"]["baseline_guidance"], 0)
        self.assertEqual(res["summary"]["critical"], 2)
        self.assertEqual(res["summary"]["high"], 1)
        for r in res["recommendations"]:
            self.assertEqual(r["recommendation_type"], "finding_driven")

    def test_one_finding_with_baseline_explicitly_enabled(self):
        """When baseline guidance is explicitly enabled, finding-driven recommendations appear first followed by baseline guidance."""
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "severity": "CRITICAL"}]
        agent = RecommendationEngineAgent(phase3a_findings=findings, include_baseline_guidance=True)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 4)
        self.assertEqual(res["summary"]["findings_driven"], 1)
        self.assertEqual(res["summary"]["baseline_guidance"], 3)
        # Critical summary is not inflated by baseline guidance
        self.assertEqual(res["summary"]["critical"], 1)
        self.assertEqual(res["summary"]["low"], 3)

        # First is the finding-driven recommendation
        first_rec = res["recommendations"][0]
        self.assertEqual(first_rec["recommendation_id"], "REC-01")
        self.assertEqual(first_rec["recommendation_type"], "finding_driven")
        self.assertEqual(first_rec["finding_id"], "RED-SQL-01")

        # Subsequent are baseline guidance
        for r in res["recommendations"][1:]:
            self.assertEqual(r["recommendation_type"], "baseline_guidance")
            self.assertTrue(r["finding_id"].startswith("BASE-"))

    def test_generate_recommendations_method_override_baseline_guidance(self):
        """generate_recommendations(include_baseline_guidance=...) can dynamically override agent configuration."""
        findings = [{"finding_id": "RED-SQL-01", "affected_files": ["db.py"]}]
        # Initialized with include_baseline_guidance=False
        agent = RecommendationEngineAgent(phase3a_findings=findings, include_baseline_guidance=False)

        res_disabled = agent.generate_recommendations()
        self.assertEqual(res_disabled["total_recommendations"], 1)
        self.assertEqual(res_disabled["summary"]["baseline_guidance"], 0)

        # Overridden to True
        res_enabled = agent.generate_recommendations(include_baseline_guidance=True)
        self.assertEqual(res_enabled["total_recommendations"], 4)
        self.assertEqual(res_enabled["summary"]["baseline_guidance"], 3)

    def test_baseline_guidance_explains_relevance_with_phase1_context(self):
        """Baseline guidance explains why recommendations are relevant using Phase 1 architectural context without inventing defects."""
        p1 = {
            "project_summary": {"application_type": {"type": "REST API Microservice"}},
            "frameworks": ["FastAPI"]
        }
        agent = RecommendationEngineAgent(phase1_reconstruction=p1, include_baseline_guidance=True)
        res = agent.generate_recommendations()

        base_recs = [r for r in res["recommendations"] if r["recommendation_type"] == "baseline_guidance"]
        self.assertGreaterEqual(len(base_recs), 3)

        config_rec = next(r for r in base_recs if r["finding_id"] == "BASE-CONFIG-01")
        self.assertIn("REST API Microservice", config_rec["evidence"])
        self.assertIn("FastAPI", config_rec["evidence"])
        self.assertIn("Twelve-Factor App", config_rec["technical_reasoning"])
        # Does not claim defect was found
        self.assertIn("No specific configuration defect was verified", config_rec["current_implementation"])

    # =========================================================================
    # Group 12: Explicit Finding Coverage, Unmapped Diagnostics & Stable Deduplication
    # =========================================================================

    def test_multiple_smells_of_same_category_all_processed(self):
        """Processes EVERY valid distinct smell of the same category, not just the first one."""
        smells = [
            {
                "smell_id": "SMELL-SILENT-01",
                "category": "Poor Exception Handling",
                "file": "src/services/auth.py",
                "function_or_class": "verify_token",
                "line": "42",
                "evidence": "except Exception: pass"
            },
            {
                "smell_id": "SMELL-SILENT-02",
                "category": "Poor Exception Handling",
                "file": "src/workers/queue.py",
                "function_or_class": "process_job",
                "line": "108",
                "evidence": "except Exception: pass"
            }
        ]
        agent = RecommendationEngineAgent(phase6_smells=smells)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 2)
        rec_ids = [r["recommendation_id"] for r in res["recommendations"]]
        self.assertEqual(rec_ids, ["REC-01", "REC-02"])

        # Both functions and files must be represented
        rec_texts = " ".join(r["problem"] + " " + r["evidence"] for r in res["recommendations"])
        self.assertIn("verify_token", rec_texts)
        self.assertIn("process_job", rec_texts)
        self.assertIn("src/services/auth.py", rec_texts)
        self.assertIn("src/workers/queue.py", rec_texts)

    def test_multiple_complexity_smells_distinct_functions_both_processed(self):
        """Processes distinct structural complexity / maintainability smells across multiple routines."""
        smells = [
            {
                "smell_id": "SMELL-NEST-01",
                "category": "Deep Nesting",
                "file": "src/parser.py",
                "function_or_class": "parse_ast_nodes",
                "evidence": "exhibits maximum block nesting depth of 5 levels"
            },
            {
                "smell_id": "SMELL-LONG-01",
                "category": "Long Method",
                "file": "src/exporter.py",
                "function_or_class": "export_large_dataset",
                "evidence": "function spans 120 lines of code"
            }
        ]
        agent = RecommendationEngineAgent(phase6_smells=smells)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 2)
        rec_ids = [r["recommendation_id"] for r in res["recommendations"]]
        self.assertEqual(rec_ids, ["REC-01", "REC-02"])

        rec_targets = [r["evidence"] for r in res["recommendations"]]
        self.assertTrue(any("parse_ast_nodes" in t for t in rec_targets))
        self.assertTrue(any("export_large_dataset" in t for t in rec_targets))

    def test_other_code_smells_processed_into_maintainability_recommendations(self):
        """Processes general clean-code smells (e.g. Dangerous Default Value, Dead Code) without dropping them."""
        smells = [
            {
                "smell_id": "SMELL-MUTABLE-DEFAULT-01",
                "category": "Dangerous Default Value",
                "file": "src/models.py",
                "function_or_class": "init_collection",
                "evidence": "def init_collection(items=[]):",
                "explanation": "Mutable default arguments retain mutated state across invocations.",
                "refactoring_strategy": "Use None sentinel with conditional initialization."
            }
        ]
        agent = RecommendationEngineAgent(phase6_smells=smells)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 1)
        rec = res["recommendations"][0]
        self.assertIn("Dangerous Default Value", rec["problem"])
        self.assertIn("init_collection", rec["evidence"])
        self.assertIn("None sentinel", rec["recommended_change"])
        self._assert_valid_recommendation_schema(rec)

    def test_distinct_findings_with_same_id_in_different_files(self):
        """Distinct security findings sharing the same finding_id across different files are NOT merged."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/users.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
            },
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/orders.py"],
                "evidence": "cursor.execute(f'SELECT * FROM orders WHERE status={st}')"
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 2)
        self.assertEqual(res["recommendations"][0]["recommendation_id"], "REC-01")
        self.assertEqual(res["recommendations"][1]["recommendation_id"], "REC-02")

        files_seen = [r["evidence"] for r in res["recommendations"]]
        self.assertTrue(any("src/users.py" in f for f in files_seen))
        self.assertTrue(any("src/orders.py" in f for f in files_seen))

    def test_duplicate_finding_ids_with_identical_evidence_deduplicated(self):
        """Identical finding entries with same ID and same evidence are cleanly deduplicated."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/users.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
            },
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/users.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 1)
        self.assertEqual(res["recommendations"][0]["recommendation_id"], "REC-01")

    def test_empty_finding_id_synthesizes_recommendation_and_diagnostic(self):
        """Findings with empty/missing finding_id but valid details synthesize an unmapped recommendation and diagnostic."""
        findings = [
            {
                "finding_id": "",
                "title": "Cleartext Administrative Password in Source",
                "affected_files": ["src/config.py"],
                "evidence": "ADMIN_PASSWORD = 'supersecretadmin'"
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 1)
        rec = res["recommendations"][0]
        self.assertTrue(rec["finding_id"].startswith("SEC-UNMAPPED-"))
        self.assertIn("Cleartext Administrative Password", rec["problem"])
        self.assertIn("manual security review", rec["recommended_change"].lower())

        # Preserved in unmapped_findings diagnostic report
        self.assertIn("unmapped_findings", res)
        self.assertEqual(len(res["unmapped_findings"]), 1)
        diagnostic = res["unmapped_findings"][0]
        self.assertEqual(diagnostic["status"], "EMPTY_ID")
        self.assertEqual(diagnostic["finding_id"], rec["finding_id"])

    def test_unknown_finding_id_does_not_invent_specific_remediation(self):
        """Unknown finding IDs without upstream remediation do not receive invented remediations and are recorded in diagnostics."""
        findings = [
            {
                "finding_id": "CUSTOM-VULN-999",
                "title": "Custom Protocol Parsing Vulnerability",
                "affected_files": ["src/network/parser.py"],
                "evidence": "parser.read_frame() allows uncontrolled buffer allocation",
                "severity": "HIGH"
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 1)
        rec = res["recommendations"][0]
        self.assertEqual(rec["finding_id"], "CUSTOM-VULN-999")
        # Must direct manual review instead of claiming invented automated fix
        self.assertIn("manual security review", rec["recommended_change"].lower())
        self.assertIn("no automated remediation plan was provided", rec["recommended_change"].lower())

        # Check unmapped diagnostic
        self.assertIn("unmapped_findings", res)
        diag = next(d for d in res["unmapped_findings"] if d.get("finding_id") == "CUSTOM-VULN-999")
        self.assertEqual(diag["status"], "UNMAPPED_FINDING_ID")
        self.assertFalse(diag["has_upstream_remediation"])
        self.assertEqual(res["summary"]["unmapped_findings"], 1)

    def test_malformed_records_captured_in_unmapped_diagnostics(self):
        """Malformed input items (None, raw strings, integers, empty dicts) do not crash and are recorded in unmapped diagnostics."""
        agent = RecommendationEngineAgent(
            phase3a_findings=[None, "raw_string_item", 12345, {}],  # type: ignore
            phase6_smells=[{}, "non_dict_smell"]  # type: ignore
        )
        res = agent.generate_recommendations()

        # Generates baseline guidance because 0 valid findings exist
        self.assertGreaterEqual(res["total_recommendations"], 3)
        self.assertIn("unmapped_findings", res)
        self.assertGreaterEqual(len(res["unmapped_findings"]), 6)

        statuses = [d["status"] for d in res["unmapped_findings"]]
        self.assertIn("MALFORMED_RECORD", statuses)
        self.assertIn("EMPTY_RECORD", statuses)

    def test_mixed_known_and_unknown_inputs_preserves_all_valid_findings(self):
        """Mixed known and unknown security findings and multiple code smells all preserved deterministically."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["src/db.py"], "evidence": "SELECT 1"},
            {"finding_id": "RED-XSS-99", "title": "DOM XSS", "affected_files": ["src/ui.py"], "evidence": "innerHTML = input"},
            "malformed_item"  # type: ignore
        ]
        smells = [
            {"smell_id": "SMELL-SILENT-1", "category": "Poor Exception Handling", "file": "a.py", "function_or_class": "f1", "evidence": "except: pass"},
            {"smell_id": "SMELL-SILENT-2", "category": "Poor Exception Handling", "file": "b.py", "function_or_class": "f2", "evidence": "except: pass"},
            {"smell_id": "SMELL-COMPLEX-1", "category": "Deep Nesting", "file": "c.py", "function_or_class": "f3", "evidence": "depth 4"}
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase6_smells=smells)
        res = agent.generate_recommendations()

        # 2 security recs + 3 smell recs = 5 total finding-driven recommendations
        self.assertEqual(res["total_recommendations"], 5)
        self.assertEqual(res["summary"]["findings_driven"], 5)
        self.assertEqual(res["summary"]["baseline_guidance"], 0)

        # Unique sequential IDs REC-01 to REC-05
        rec_ids = [r["recommendation_id"] for r in res["recommendations"]]
        self.assertEqual(rec_ids, ["REC-01", "REC-02", "REC-03", "REC-04", "REC-05"])

        # Malformed record and unknown finding recorded in diagnostics
        self.assertGreaterEqual(res["summary"]["unmapped_findings"], 2)
        self.assertTrue(any(d.get("finding_id") == "RED-XSS-99" for d in res["unmapped_findings"]))
        self.assertTrue(any(d.get("status") == "MALFORMED_RECORD" for d in res["unmapped_findings"]))

        for r in res["recommendations"]:
            self._assert_valid_recommendation_schema(r)


    # =========================================================================
    # Group 13: Deterministic Prioritization & Confidence Derivation Policies
    # =========================================================================

    def test_boundary_and_missing_data_conservative_fallback(self):
        """When findings lack explicit severity, files, and snippet evidence, falls back conservatively to MEDIUM priority and LOW confidence."""
        findings = [
            {
                "finding_id": "CUSTOM-VULN-UNKNOWN",
                "title": "Unspecified custom alert"
                # Missing severity, affected_files, evidence
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 1)
        rec = res["recommendations"][0]
        # Conservative fallback for unknown finding with no explicit severity is MEDIUM
        self.assertEqual(rec["priority"], "MEDIUM")
        # Missing both files and code snippet leads to conservative LOW confidence
        self.assertEqual(rec["confidence"], "LOW")
        self.assertEqual(res["summary"]["medium"], 1)
        self.assertEqual(res["summary"]["low"], 0)

    def test_conflicting_evidence_preserves_priority_and_lowers_confidence(self):
        """Conflicted remediation status preserves full base severity (never downgraded) and lowers confidence to LOW."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/db.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                "severity": "CRITICAL"
            }
        ]
        retest = {
            "retest_results": [
                {
                    "finding_id": "RED-SQL-01",
                    "final_status": "CONFLICTED",
                    "result": "Automated patch applied but payload execution still succeeds intermittently."
                }
            ]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        rec = res["recommendations"][0]
        # Priority must NOT be downgraded despite fix attempt
        self.assertEqual(rec["priority"], "CRITICAL")
        # Evidence inconsistency forces confidence to LOW
        self.assertEqual(rec["confidence"], "LOW")
        self.assertIn("CONFLICTED", rec["evidence"])

    def test_partial_remediation_precedence_and_risk_acknowledgment(self):
        """PARTIALLY_REMEDIATED adjusts CRITICAL to HIGH, leaves HIGH as HIGH, leaves MEDIUM as MEDIUM, while REMEDIATED shifts to LOW."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/db.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                "severity": "CRITICAL"
            },
            {
                "finding_id": "RED-SECRET-01",
                "affected_files": ["src/auth.py"],
                "evidence": "API_KEY = 'secret123'",
                "severity": "HIGH"
            },
            {
                "finding_id": "RED-CORS-01",
                "affected_files": ["src/server.py"],
                "evidence": "allow_origins=['*']",
                "severity": "MEDIUM"
            },
            {
                "finding_id": "RED-CMD-01",
                "affected_files": ["src/cli.py"],
                "evidence": "os.system(cmd)",
                "severity": "CRITICAL"
            }
        ]
        retest = {
            "retest_results": [
                {"finding_id": "RED-SQL-01", "final_status": "PARTIALLY_REMEDIATED"},
                {"finding_id": "RED-SECRET-01", "final_status": "PARTIALLY_REMEDIATED"},
                {"finding_id": "RED-CORS-01", "final_status": "PARTIALLY_REMEDIATED"},
                {"finding_id": "RED-CMD-01", "final_status": "REMEDIATED"}
            ]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        recs_by_fid = {r["finding_id"]: r for r in res["recommendations"]}

        # Base CRITICAL partially remediated drops to HIGH
        self.assertEqual(recs_by_fid["RED-SQL-01"]["priority"], "HIGH")
        # Base HIGH partially remediated remains HIGH
        self.assertEqual(recs_by_fid["RED-SECRET-01"]["priority"], "HIGH")
        # Base MEDIUM partially remediated remains MEDIUM
        self.assertEqual(recs_by_fid["RED-CORS-01"]["priority"], "MEDIUM")
        # Fully REMEDIATED finding drops to LOW (regression retention)
        self.assertEqual(recs_by_fid["RED-CMD-01"]["priority"], "LOW")

    def test_unverified_retest_preserves_priority_and_caps_confidence(self):
        """UNVERIFIED and NOT_TESTABLE retest results preserve base priority without downgrading and cap confidence at MEDIUM."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/db.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                "severity": "CRITICAL"
            }
        ]
        retest = {
            "retest_results": [
                {
                    "finding_id": "RED-SQL-01",
                    "final_status": "UNVERIFIED",
                    "result": "Target service was unreachable during verification."
                }
            ]
        }
        agent = RecommendationEngineAgent(phase3a_findings=findings, phase5a_retest=retest)
        res = agent.generate_recommendations()

        rec = res["recommendations"][0]
        # Must retain CRITICAL priority
        self.assertEqual(rec["priority"], "CRITICAL")
        # Unverified verification caps confidence at MEDIUM
        self.assertEqual(rec["confidence"], "MEDIUM")

    def test_cross_domain_relationship_priority_amplification(self):
        """Phase 7 cross-domain relationships elevate smell and architectural priorities based on documented rules."""
        smells = [
            {
                "smell_id": "SMELL-SILENT-01",
                "category": "Poor Exception Handling",
                "file": "src/auth.py",
                "function_or_class": "check_token",
                "evidence": "except Exception: pass"
            },
            {
                "smell_id": "SMELL-NEST-01",
                "category": "Deep Nesting",
                "file": "src/ingest.py",
                "function_or_class": "process_tree",
                "evidence": "5 nested loop levels"
            }
        ]
        p7 = {
            "relationships": [
                {
                    "relationship_id": "REL-SMELL-SEC-01",
                    "domains": ["code_smell", "security"],
                    "description": "Silent exceptions mask authentication failure logging."
                },
                {
                    "relationship_id": "REL-SMELL-SCALE-01",
                    "domains": ["code_smell", "scalability"],
                    "description": "Deep nesting in ingestion path causes catastrophic CPU latency."
                }
            ]
        }
        agent = RecommendationEngineAgent(phase6_smells=smells, phase7_relationships=p7)
        res = agent.generate_recommendations()

        recs = res["recommendations"]
        self.assertEqual(len(recs), 2)
        # Both smells elevated to HIGH due to Phase 7 cross-domain relationships
        for r in recs:
            self.assertEqual(r["priority"], "HIGH")

    def test_confidence_derived_separately_from_priority(self):
        """Confidence reflects evidence quality and consistency independently of priority level."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/db.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                "severity": "CRITICAL",
                "validation_status": "CONFIRMED"
            },
            {
                "finding_id": "RED-CMD-01",
                "affected_files": [],
                "evidence": "",
                "severity": "CRITICAL",
                "validation_status": "POSSIBLE"
            },
            {
                "finding_id": "RED-DOS-01",
                "affected_files": ["src/server.py"],
                "evidence": "while True: pass",
                "severity": "LOW",
                "validation_status": "CONFIRMED"
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        recs_by_fid = {r["finding_id"]: r for r in res["recommendations"]}

        # SQL is CRITICAL priority with HIGH confidence (file + snippet + confirmed)
        self.assertEqual(recs_by_fid["RED-SQL-01"]["priority"], "CRITICAL")
        self.assertEqual(recs_by_fid["RED-SQL-01"]["confidence"], "HIGH")

        # CMD is CRITICAL priority but LOW confidence (no files, no snippet, validation_status=POSSIBLE)
        self.assertEqual(recs_by_fid["RED-CMD-01"]["priority"], "CRITICAL")
        self.assertEqual(recs_by_fid["RED-CMD-01"]["confidence"], "LOW")

        # DOS is LOW priority with HIGH confidence (file + snippet + confirmed)
        self.assertEqual(recs_by_fid["RED-DOS-01"]["priority"], "LOW")
        self.assertEqual(recs_by_fid["RED-DOS-01"]["confidence"], "HIGH")

    def test_upstream_confidence_capping_honored(self):
        """If upstream finding explicitly specifies confidence=LOW or confidence=MEDIUM, it caps the derived confidence."""
        findings = [
            {
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/db.py"],
                "evidence": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
                "severity": "CRITICAL",
                "confidence": "LOW"
            }
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        rec = res["recommendations"][0]
        self.assertEqual(rec["priority"], "CRITICAL")
        self.assertEqual(rec["confidence"], "LOW")

    def test_stable_deterministic_ordering_for_equal_priority_recommendations(self):
        """Recommendations with identical priority preserve stable deterministic ordering across executions and input shuffles."""
        findings_order_a = [
            {"finding_id": "RED-SQL-01", "affected_files": ["b.py"], "evidence": "SELECT b", "severity": "HIGH"},
            {"finding_id": "RED-CMD-01", "affected_files": ["a.py"], "evidence": "exec a", "severity": "HIGH"},
            {"finding_id": "RED-DOS-01", "affected_files": ["c.py"], "evidence": "loop c", "severity": "HIGH"},
        ]
        findings_order_b = [
            {"finding_id": "RED-DOS-01", "affected_files": ["c.py"], "evidence": "loop c", "severity": "HIGH"},
            {"finding_id": "RED-SQL-01", "affected_files": ["b.py"], "evidence": "SELECT b", "severity": "HIGH"},
            {"finding_id": "RED-CMD-01", "affected_files": ["a.py"], "evidence": "exec a", "severity": "HIGH"},
        ]

        res_a = RecommendationEngineAgent(phase3a_findings=findings_order_a).generate_recommendations()
        res_b = RecommendationEngineAgent(phase3a_findings=findings_order_b).generate_recommendations()

        fids_a = [r["finding_id"] for r in res_a["recommendations"]]
        fids_b = [r["finding_id"] for r in res_b["recommendations"]]

        # Deterministic sorting ensures identical order regardless of input permutation
        self.assertEqual(fids_a, fids_b)
        self.assertEqual(fids_a, ["RED-CMD-01", "RED-DOS-01", "RED-SQL-01"])

    def test_summary_counts_match_recommendations_exactly(self):
        """Summary counts match the final recommendation list across all priority tiers and types."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["a.py"], "evidence": "SELECT 1", "severity": "CRITICAL"},
            {"finding_id": "RED-SECRET-01", "affected_files": ["b.py"], "evidence": "KEY = 'x'", "severity": "HIGH"},
            {"finding_id": "RED-CORS-01", "affected_files": ["c.py"], "evidence": "origin = '*'", "severity": "MEDIUM"},
            {"finding_id": "CUSTOM-INFO-01", "title": "Info note", "affected_files": ["d.py"], "evidence": "log info", "severity": "INFORMATIONAL"},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings, include_baseline_guidance=True)
        res = agent.generate_recommendations()

        recs = res["recommendations"]
        summary = res["summary"]

        self.assertEqual(res["total_recommendations"], len(recs))
        self.assertEqual(summary["critical"], sum(1 for r in recs if r["priority"] == "CRITICAL"))
        self.assertEqual(summary["high"], sum(1 for r in recs if r["priority"] == "HIGH"))
        self.assertEqual(summary["medium"], sum(1 for r in recs if r["priority"] == "MEDIUM"))
        self.assertEqual(summary["low"], sum(1 for r in recs if r["priority"] == "LOW"))
        self.assertEqual(summary["informational"], sum(1 for r in recs if r["priority"] == "INFORMATIONAL"))
        self.assertEqual(summary["findings_driven"], sum(1 for r in recs if r["recommendation_type"] == "finding_driven"))
        self.assertEqual(summary["baseline_guidance"], sum(1 for r in recs if r["recommendation_type"] == "baseline_guidance"))

        total_by_priorities = (
            summary["critical"] + summary["high"] + summary["medium"] +
            summary["low"] + summary["informational"]
        )
    def test_regression_multiple_identical_findings_consolidated_into_single_rec(self):
        """Several identical recommendation/finding records produce one canonical recommendation with combined evidence."""
        findings = [
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"], "line": "12", "evidence": "joblib.load(f1)"},
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"], "line": "45", "evidence": "joblib.load(f2)"},
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"], "line": "89", "evidence": "joblib.load(f3)"},
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"], "line": "120", "evidence": "joblib.load(f4)"},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        # Must produce exactly 1 canonical recommendation, not 4 duplicates
        self.assertEqual(res["total_recommendations"], 1)
        rec = res["recommendations"][0]
        self.assertEqual(rec["recommendation_id"], "REC-01")
        self.assertEqual(rec["finding_id"], "RED-DESER-01")
        self.assertEqual(rec["priority"], "HIGH")
        # Evidence from occurrences should be preserved
        self.assertIn("joblib.load(f1)", rec["evidence"])
        self.assertIn("joblib.load(f2)", rec["evidence"])
        self.assertEqual(rec["affected_files"], ["model.py"])

    def test_regression_conflicting_severity_preserves_higher_severity(self):
        """Duplicate records with conflicting severities preserve the higher severity without downgrade."""
        findings = [
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "severity": "MEDIUM", "evidence": "exec(q)"},
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "severity": "CRITICAL", "evidence": "exec(q)"},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res = agent.generate_recommendations()

        self.assertEqual(res["total_recommendations"], 1)
        rec = res["recommendations"][0]
        self.assertEqual(rec["priority"], "CRITICAL")

    def test_regression_repeated_pipeline_runs_deterministic(self):
        """Running the recommendation generator twice produces identical results without new duplicates."""
        findings = [
            {"finding_id": "RED-DESER-01", "affected_files": ["model.py"], "evidence": "joblib.load(f)"},
            {"finding_id": "RED-SQL-01", "affected_files": ["db.py"], "evidence": "cursor.execute(sql)"},
        ]
        agent = RecommendationEngineAgent(phase3a_findings=findings)
        res1 = agent.generate_recommendations()
        res2 = agent.generate_recommendations()

        self.assertEqual(res1["total_recommendations"], 2)
        self.assertEqual(res2["total_recommendations"], 2)
        self.assertEqual(
            [r["recommendation_id"] for r in res1["recommendations"]],
            [r["recommendation_id"] for r in res2["recommendations"]]
        )


if __name__ == "__main__":
    unittest.main()



