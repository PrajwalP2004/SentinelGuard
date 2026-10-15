"""
Unit tests for Phase 9: Final Software Architecture and Security Report Generator Agent.

Verifies:
- Missing phase5a_retest input reports status as unavailable/unknown, never claiming checks passed.
- Missing retest_results key reports status as unavailable/unknown, never claiming checks passed.
- Empty retest_results reports status as unconfirmed/unavailable, never claiming checks passed.
- Actual supplied retest results with non-remediated items correctly reports actionable status.
- Explicitly verified successful execution reports passed checks only when supported by actual data.
"""

import unittest
from src.phase9.report import FinalReportGeneratorAgent


class TestPhase9ReportGeneratorAgent(unittest.TestCase):
    """Test suite for Phase 9 FinalReportGeneratorAgent retest reporting integrity."""

    def test_missing_phase5a_retest_input_not_reported_as_passed(self):
        """When phase5a_retest is None or omitted, must report retest data as not supplied, never claiming checks passed."""
        agent_default = FinalReportGeneratorAgent()
        md_default = agent_default.generate_markdown_report()

        self.assertIn("6. SECURITY RETEST RESULTS", md_default)
        self.assertIn("No security retest data was supplied", md_default)
        self.assertIn("[UNKNOWN]", md_default)
        self.assertNotIn("passed without active remediation blockers", md_default)
        self.assertNotIn("All baseline security verification checks passed", md_default)

        agent_none = FinalReportGeneratorAgent(phase5a_retest=None)
        md_none = agent_none.generate_markdown_report()
        self.assertIn("No security retest data was supplied", md_none)
        self.assertNotIn("All baseline security verification checks passed", md_none)

    def test_missing_retest_results_key_not_reported_as_passed(self):
        """When phase5a_retest dictionary lacks the retest_results key, must report as unavailable, never claiming checks passed."""
        agent_empty_dict = FinalReportGeneratorAgent(phase5a_retest={})
        md_empty_dict = agent_empty_dict.generate_markdown_report()
        self.assertIn("No security retest data was supplied", md_empty_dict)
        self.assertNotIn("All baseline security verification checks passed", md_empty_dict)

        agent_other_keys = FinalReportGeneratorAgent(
            phase5a_retest={"status": "INITIALIZED", "timestamp": "2026-10-14T00:00:00Z"}
        )
        md_other_keys = agent_other_keys.generate_markdown_report()
        self.assertIn("retest_results` key missing", md_other_keys)
        self.assertIn("[UNKNOWN]", md_other_keys)
        self.assertNotIn("passed without active remediation blockers", md_other_keys)
        self.assertNotIn("All baseline security verification checks passed", md_other_keys)

    def test_empty_retest_results_not_reported_as_passed(self):
        """When retest_results is empty list, must report that no checks were executed, never claiming checks passed."""
        agent = FinalReportGeneratorAgent(phase5a_retest={"retest_results": []})
        md = agent.generate_markdown_report()

        self.assertIn("6. SECURITY RETEST RESULTS", md)
        self.assertIn("retest_results` is empty", md)
        self.assertIn("No security verification checks were executed", md)
        self.assertIn("[UNKNOWN]", md)
        self.assertNotIn("passed without active remediation blockers", md)
        self.assertNotIn("All baseline security verification checks passed", md)

    def test_empty_retest_results_with_zero_summary_not_reported_as_passed(self):
        """Empty retest_results with summary showing 0 total retested must not claim tests passed."""
        agent = FinalReportGeneratorAgent(
            phase5a_retest={
                "retest_results": [],
                "summary": {"total_retested": 0, "remediated": 0, "not_remediated": 0}
            }
        )
        md = agent.generate_markdown_report()

        self.assertIn("No security verification checks were executed", md)
        self.assertNotIn("All baseline security verification checks passed", md)

    def test_actual_supplied_retest_results_rendered_with_action_status(self):
        """When actual retest results are supplied with un-remediated items, renders actionable findings accurately."""
        retests = [
            {
                "finding_id": "RED-SQL-01",
                "final_status": "NOT_REMEDIATED",
                "original_issue": "Raw SQL concatenation in user query",
                "remediation_tested": "Parameterized query implementation",
                "result": "Payload ' OR 1=1 -- still executes successfully against database",
                "remaining_risk": "Remote database exfiltration and command execution",
                "evidence": "db.execute(f'SELECT * FROM users WHERE id={user_id}')"
            },
            {
                "finding_id": "RED-SECRET-01",
                "final_status": "PARTIALLY_REMEDIATED",
                "original_issue": "Hardcoded API key in config",
                "remediation_tested": "Environment variable lookup",
                "result": "Default fallback still contains live key",
                "remaining_risk": "Credential leakage in unconfigured environments",
                "evidence": "os.environ.get('API_KEY', 'sk_live_12345')"
            }
        ]
        agent = FinalReportGeneratorAgent(phase5a_retest={"retest_results": retests})
        md = agent.generate_markdown_report()

        self.assertIn("### Retest Result for `RED-SQL-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)", md)
        self.assertIn("### Retest Result for `RED-SECRET-01`: **PARTIALLY_REMEDIATED** (🟡 PARTIALLY ADDRESSED)", md)
        self.assertIn("db.execute(f'SELECT", md)
        self.assertNotIn("All baseline security verification checks passed", md)

    def test_explicitly_verified_successful_execution_with_remediated_records(self):
        """When retesting ran and all findings were verified as REMEDIATED, reports successful verification supported by actual data."""
        retests = [
            {
                "finding_id": "RED-SQL-01",
                "final_status": "REMEDIATED",
                "original_issue": "Raw SQL concatenation",
                "remediation_tested": "Parameterized queries with placeholder binding",
                "result": "Database cursor uses parameterized tuple binding; exploit payload fails",
                "remaining_risk": "None identified for this query path",
                "evidence": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
            }
        ]
        agent = FinalReportGeneratorAgent(
            phase5a_retest={
                "retest_results": retests,
                "summary": {"total_retested": 1, "remediated": 1, "not_remediated": 0, "partially_remediated": 0}
            }
        )
        md = agent.generate_markdown_report()

        self.assertIn("All 1 baseline security verification check(s) passed", md)
        self.assertIn("All evaluated vulnerabilities were confirmed remediated in the active codebase", md)
        self.assertIn("### Retest Result for `RED-SQL-01`: **REMEDIATED** (🟢 VERIFIED REMEDIATION)", md)

    def test_explicitly_verified_successful_execution_from_summary_metadata(self):
        """When execution metadata explicitly confirms all checks passed with total_retested > 0, reports successful verification."""
        p5a = {
            "execution_status": "PASSED",
            "summary": {
                "total_retested": 3,
                "remediated": 3,
                "not_remediated": 0,
                "partially_remediated": 0,
                "not_testable": 0,
                "false_positive": 0
            }
        }
        agent = FinalReportGeneratorAgent(phase5a_retest=p5a)
        md = agent.generate_markdown_report()

        self.assertIn("All 3 baseline security verification check(s) passed", md)
        self.assertIn("Retest execution metadata confirmed all evaluated security controls were successfully remediated", md)

    def test_generate_report_data_handles_missing_phase5a_safely(self):
        """generate_report_data reflects 0 retested findings when phase5a_retest is omitted or empty."""
        agent_none = FinalReportGeneratorAgent()
        data_none = agent_none.generate_report_data()
        self.assertEqual(data_none["findings_count"]["retested_findings"], 0)

        agent_empty = FinalReportGeneratorAgent(phase5a_retest={"retest_results": []})
        data_empty = agent_empty.generate_report_data()
        self.assertEqual(data_empty["findings_count"]["retested_findings"], 0)

    # =========================================================================
    # Error 2 Tests: Explicit Retest Badge Mapping & Unrecognized Status Safety
    # =========================================================================

    def test_all_recognized_retest_statuses_receive_explicit_badges(self):
        """Tests that every recognized Phase 5A retest status receives its corresponding explicit badge."""
        retests = [
            {"finding_id": "FIND-01", "final_status": "REMEDIATED"},
            {"finding_id": "FIND-02", "final_status": "PARTIALLY_REMEDIATED"},
            {"finding_id": "FIND-03", "final_status": "NOT_REMEDIATED"},
            {"finding_id": "FIND-04", "final_status": "NOT_TESTABLE"},
            {"finding_id": "FIND-05", "final_status": "FALSE_POSITIVE"},
            {"finding_id": "FIND-06", "final_status": "CONFLICTED"},
        ]
        agent = FinalReportGeneratorAgent(phase5a_retest={"retest_results": retests})
        md = agent.generate_markdown_report()

        # Recognized mappings
        self.assertIn("### Retest Result for `FIND-01`: **REMEDIATED** (🟢 VERIFIED REMEDIATION)", md)
        self.assertIn("### Retest Result for `FIND-02`: **PARTIALLY_REMEDIATED** (🟡 PARTIALLY ADDRESSED)", md)
        self.assertIn("### Retest Result for `FIND-03`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)", md)
        self.assertIn("### Retest Result for `FIND-04`: **NOT_TESTABLE** (⚪ UNABLE TO VERIFY)", md)
        self.assertIn("### Retest Result for `FIND-05`: **FALSE_POSITIVE** (🔵 FALSE POSITIVE)", md)
        self.assertIn("### Retest Result for `FIND-06`: **CONFLICTED** (🟠 CONFLICTED EVIDENCE)", md)

        # Untestable status must NEVER be labeled VERIFIED SAFE
        self.assertNotIn("`FIND-04`: **NOT_TESTABLE** (🟢 VERIFIED SAFE)", md)
        self.assertNotIn("VERIFIED SAFE", md)

    def test_unrecognized_statuses_never_labeled_verified_safe(self):
        """Unrecognized custom status strings must receive STATUS UNKNOWN and never VERIFIED SAFE."""
        retests = [
            {"finding_id": "FIND-CUSTOM-1", "final_status": "IN_PROGRESS"},
            {"finding_id": "FIND-CUSTOM-2", "final_status": "PENDING_VERIFICATION"},
            {"finding_id": "FIND-CUSTOM-3", "final_status": "BOGUS_STATUS"},
        ]
        agent = FinalReportGeneratorAgent(phase5a_retest={"retest_results": retests})
        md = agent.generate_markdown_report()

        self.assertIn("### Retest Result for `FIND-CUSTOM-1`: **IN_PROGRESS** (⚠️ STATUS UNKNOWN)", md)
        self.assertIn("### Retest Result for `FIND-CUSTOM-2`: **PENDING_VERIFICATION** (⚠️ STATUS UNKNOWN)", md)
        self.assertIn("### Retest Result for `FIND-CUSTOM-3`: **BOGUS_STATUS** (⚠️ STATUS UNKNOWN)", md)

        # Must never describe unrecognized finding as VERIFIED SAFE
        self.assertNotIn("VERIFIED SAFE", md)
        self.assertNotIn("VERIFIED REMEDIATION", md)

    def test_missing_and_empty_status_fields_safely_default_to_unknown(self):
        """Missing final_status key, None value, and whitespace/empty strings default to UNKNOWN with STATUS UNKNOWN badge."""
        retests = [
            {"finding_id": "FIND-EMPTY-1"},  # missing key
            {"finding_id": "FIND-EMPTY-2", "final_status": None},  # None value
            {"finding_id": "FIND-EMPTY-3", "final_status": ""},  # empty string
            {"finding_id": "FIND-EMPTY-4", "final_status": "   "},  # whitespace only
            {"finding_id": "FIND-EMPTY-5", "final_status": "UNKNOWN"},  # explicit UNKNOWN
        ]
        agent = FinalReportGeneratorAgent(phase5a_retest={"retest_results": retests})
        md = agent.generate_markdown_report()

        for fid in ["FIND-EMPTY-1", "FIND-EMPTY-2", "FIND-EMPTY-3", "FIND-EMPTY-4", "FIND-EMPTY-5"]:
            self.assertIn(f"### Retest Result for `{fid}`: **UNKNOWN** (⚠️ STATUS UNKNOWN)", md)

        # Must never be labeled VERIFIED SAFE
        self.assertNotIn("VERIFIED SAFE", md)
        self.assertNotIn("VERIFIED REMEDIATION", md)

    def test_get_retest_badge_classmethod_helper(self):
        """Directly verifies get_retest_badge helper method mapping across all edge cases."""
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("REMEDIATED"), "🟢 VERIFIED REMEDIATION")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("remediated"), "🟢 VERIFIED REMEDIATION")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("PARTIALLY_REMEDIATED"), "🟡 PARTIALLY ADDRESSED")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("NOT_REMEDIATED"), "🔴 ACTION REQUIRED")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("NOT_TESTABLE"), "⚪ UNABLE TO VERIFY")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("FALSE_POSITIVE"), "🔵 FALSE POSITIVE")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("CONFLICTED"), "🟠 CONFLICTED EVIDENCE")

        # Missing / invalid / unknown
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("UNKNOWN"), "⚠️ STATUS UNKNOWN")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge(""), "⚠️ STATUS UNKNOWN")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge(None), "⚠️ STATUS UNKNOWN")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge(12345), "⚠️ STATUS UNKNOWN")
        self.assertEqual(FinalReportGeneratorAgent.get_retest_badge("SOME_UNKNOWN_STATUS"), "⚠️ STATUS UNKNOWN")


    # =========================================================================
    # Error 3 Tests: Phase 7 Cross-Domain Completion vs Missing Analysis
    # =========================================================================

    def test_missing_phase7_cross_domain_input_reports_unknown(self):
        """When phase7_cross_domain is None or omitted or empty dict, reports analysis as not supplied and unknown."""
        agent_default = FinalReportGeneratorAgent()
        md_default = agent_default.generate_markdown_report()
        self.assertIn("9. CROSS-DOMAIN FINDINGS", md_default)
        self.assertIn("No cross-domain analysis data was supplied", md_default)
        self.assertIn("[UNKNOWN]", md_default)
        self.assertNotIn("No adverse cross-domain interactions detected", md_default)

        agent_none = FinalReportGeneratorAgent(phase7_cross_domain=None)
        md_none = agent_none.generate_markdown_report()
        self.assertIn("No cross-domain analysis data was supplied", md_none)
        self.assertNotIn("No adverse cross-domain interactions detected", md_none)

        agent_empty = FinalReportGeneratorAgent(phase7_cross_domain={})
        md_empty = agent_empty.generate_markdown_report()
        self.assertIn("No cross-domain analysis data was supplied", md_empty)
        self.assertNotIn("No adverse cross-domain interactions detected", md_empty)

    def test_empty_relationships_without_execution_proof_reports_unknown(self):
        """When cross_domain_relationships is an empty list without execution metadata, does not assume success."""
        agent = FinalReportGeneratorAgent(phase7_cross_domain={"cross_domain_relationships": []})
        md = agent.generate_markdown_report()

        self.assertIn("Cross-domain analysis completion could not be established", md)
        self.assertIn("[UNKNOWN]", md)
        self.assertNotIn("No adverse cross-domain interactions detected", md)

    def test_completed_analysis_with_no_relationships_supported_by_schema(self):
        """When Phase 7 schema confirms completion via domain_interactions and total_relationships=0, reports no adverse interactions."""
        p7_output = {
            "cross_domain_relationships": [],
            "total_relationships": 0,
            "domain_interactions": {
                "code_smell_security": 0,
                "security_performance": 0,
                "architecture_security": 0,
                "code_smell_scalability": 0,
                "architecture_maintainability": 0,
                "security_maintainability": 0,
            }
        }
        agent = FinalReportGeneratorAgent(phase7_cross_domain=p7_output)
        md = agent.generate_markdown_report()

        self.assertIn("Cross-domain engineering analysis completed", md)
        self.assertIn("[FACT] No adverse cross-domain interactions or conflicting architectural constraints were detected", md)

    def test_completed_analysis_with_explicit_status_no_relationships(self):
        """When Phase 7 payload contains explicit status=COMPLETED and empty relationships, reports verified completion."""
        p7_output = {
            "cross_domain_relationships": [],
            "status": "COMPLETED"
        }
        agent = FinalReportGeneratorAgent(phase7_cross_domain=p7_output)
        md = agent.generate_markdown_report()

        self.assertIn("Cross-domain engineering analysis completed", md)
        self.assertIn("[FACT] No adverse cross-domain interactions", md)

    def test_non_empty_relationships_rendered_accurately(self):
        """When Phase 7 returns valid relationships, renders full details and does not claim zero interactions."""
        relationships = [
            {
                "relationship_id": "REL-SEC-PERF-01",
                "domain_a": "Security",
                "domain_b": "Performance",
                "relationship": "DoS Mitigation Latency Overhead",
                "evidence": "src/extract.py (safe_extract): byte limits",
                "consequence": "Chunked hashing creates 5ms latency overhead under high load",
                "recommended_action": "Tune buffer ceiling based on benchmark metrics."
            }
        ]
        agent = FinalReportGeneratorAgent(
            phase7_cross_domain={
                "cross_domain_relationships": relationships,
                "total_relationships": 1,
                "domain_interactions": {"security_performance": 1}
            }
        )
        md = agent.generate_markdown_report()

        self.assertIn("### `REL-SEC-PERF-01`: Security ↔ Performance", md)
        self.assertIn("DoS Mitigation Latency Overhead", md)
        self.assertIn("Chunked hashing creates 5ms latency overhead", md)
        self.assertIn("Tune buffer ceiling based on benchmark metrics", md)
        self.assertNotIn("No adverse cross-domain interactions detected", md)


    # =========================================================================
    # Error 4 Tests: Phase 2 Requirements Authenticity & Epistemological Safety
    # =========================================================================

    def test_missing_phase2_requirements_disclosed_without_fabrication(self):
        """When phase2_requirements is omitted or None, discloses that no requirements were supplied without fabricating IDs."""
        agent_default = FinalReportGeneratorAgent()
        md_default = agent_default.generate_markdown_report()

        self.assertIn("3. REQUIREMENTS", md_default)
        self.assertIn("No functional requirements were supplied or documented", md_default)
        self.assertIn("No security requirements were supplied or documented", md_default)
        self.assertIn("[UNKNOWN]", md_default)

        # Must NOT fabricate explicit requirements or fake IDs
        self.assertNotIn("REQ-FUN-01", md_default)
        self.assertNotIn("REQ-SEC-01", md_default)
        self.assertNotIn("Execute core application routines and business logic", md_default)

        # Section 10 table must NOT fabricate REQ-01 SATISFIED
        self.assertIn("10. REQUIREMENT ↔ IMPLEMENTATION MATRIX", md_default)
        self.assertIn("| *None* | No Phase 2 requirements were supplied | **UNAVAILABLE** | None |", md_default)
        self.assertNotIn("| **REQ-01** (Core Logic) |", md_default)

    def test_empty_requirements_list_disclosed_without_fabrication(self):
        """When phase2_requirements is an empty list, clearly discloses missing requirements without fabricating rows."""
        agent = FinalReportGeneratorAgent(phase2_requirements=[])
        md = agent.generate_markdown_report()

        self.assertIn("No functional requirements were supplied", md)
        self.assertIn("No security requirements were supplied", md)
        self.assertNotIn("REQ-FUN-01", md)
        self.assertNotIn("REQ-SEC-01", md)
        self.assertNotIn("| **REQ-01** (Core Logic) |", md)
        self.assertIn("| *None* | No Phase 2 requirements were supplied | **UNAVAILABLE** | None |", md)

    def test_real_functional_and_security_requirements_reported_accurately(self):
        """When real Phase 2 requirements are supplied, reports actual IDs, tags, descriptions, and implementation evidence."""
        reqs = [
            {
                "requirement_id": "REQ-USER-AUTH-01",
                "category": "functional",
                "description": "Authenticate user via JWT bearer token",
                "status": "explicit",
                "source_file": "src/auth/jwt.py"
            },
            {
                "requirement_id": "REQ-DATA-ENCRYPT-01",
                "category": "security",
                "description": "Encrypt sensitive customer data at rest with AES-256",
                "status": "code_supported",
                "source_file": "src/storage/crypto.py"
            }
        ]
        agent = FinalReportGeneratorAgent(phase2_requirements=reqs)
        md = agent.generate_markdown_report()

        # Section 3: Genuine IDs and accurate evidentiary tags
        self.assertIn("- `REQ-USER-AUTH-01` [FACT - Explicit]: Authenticate user via JWT bearer token", md)
        self.assertIn("- `REQ-DATA-ENCRYPT-01` [FACT - Code Supported]: Encrypt sensitive customer data at rest with AES-256", md)

        # Section 10: Matrix table accurately renders supplied items and evidence
        self.assertIn("| **REQ-USER-AUTH-01**", md)
        self.assertIn("Implemented in src/auth/jwt.py", md)
        self.assertIn("| **REQ-DATA-ENCRYPT-01**", md)
        self.assertIn("Implemented in src/storage/crypto.py", md)
        self.assertNotIn("| *None* | No Phase 2 requirements were supplied", md)
        self.assertNotIn("| **REQ-01** (Core Logic)", md)

    def test_unknown_or_missing_requirement_status_handled_truthfully(self):
        """When requirement status is unknown or missing, labels it unverified/unknown and never marks it SATISFIED or EXPLICIT."""
        reqs = [
            {
                "requirement_id": "REQ-SEC-UNKNOWN-01",
                "category": "security",
                "description": "Sanitize shell inputs",
                "status": "unknown"
                # source_file omitted
            },
            {
                "requirement_id": "REQ-FUNC-NO-STATUS-01",
                "category": "functional",
                "description": "Process background invoice queue"
                # status key missing
            }
        ]
        agent = FinalReportGeneratorAgent(phase2_requirements=reqs)
        md = agent.generate_markdown_report()

        # Must label as UNKNOWN / Unverified, never [FACT - Explicit]
        self.assertIn("- `REQ-SEC-UNKNOWN-01` [UNKNOWN - Unverified]: Sanitize shell inputs", md)
        self.assertIn("- `REQ-FUNC-NO-STATUS-01` [UNKNOWN - Unverified]: Process background invoice queue", md)
        self.assertNotIn("`REQ-SEC-UNKNOWN-01` [FACT - Explicit]", md)
        self.assertNotIn("`REQ-FUNC-NO-STATUS-01` [FACT - Explicit]", md)

        # Section 10 must mark UNKNOWN, never SATISFIED
        self.assertIn("| **REQ-SEC-UNKNOWN-01**", md)
        self.assertIn("**UNKNOWN**", md)
        self.assertIn("No implementation evidence supplied", md)
        self.assertNotIn("REQ-SEC-UNKNOWN-01 (Sanitize shell inputs) | Implemented in unspecified file | **SATISFIED**", md)

    def test_correct_separation_of_actual_requirements_from_inferred_guidance(self):
        """Inferred baseline suggestions for maintainability must be explicitly labeled as baseline suggestions without fake IDs."""
        agent = FinalReportGeneratorAgent(phase2_requirements=[])
        md = agent.generate_markdown_report()

        # Inferred baseline guidance must NOT have fabricated requirement IDs like REQ-NFR-01
        self.assertNotIn("`REQ-NFR-01`", md)
        self.assertNotIn("`REQ-NFR-02`", md)
        self.assertIn("- [INFERRED - Baseline Suggestion] **Code Maintainability**:", md)
        self.assertIn("- [INFERRED - Baseline Suggestion] **Error Observability**:", md)

    # -------------------------------------------------------------------------
    # Error 5 Tests: Evidence-Driven Audit Scope & Coverage Claims
    # -------------------------------------------------------------------------
    def test_missing_metadata_avoids_hardcoded_audit_and_coverage_claims(self):
        """When metadata is missing, report must never claim comprehensive audit across domains or all Python files parsed."""
        agent = FinalReportGeneratorAgent()
        md = agent.generate_markdown_report()
        data = agent.generate_report_data()

        # Must NOT claim comprehensive audit across 6 domains or AST parsing across all files
        self.assertNotIn("performed a comprehensive audit across 6 primary engineering and security domains", md)
        self.assertNotIn("We audited all Python source files", md)
        self.assertNotIn("Every source file was parsed using Abstract Syntax Tree", md)
        self.assertNotIn("Files Analyzed", md)
        self.assertNotIn("Our automated analysis scanned", data["executive_summary"]["system_description"])

        # Must truthfully disclose unconfirmed/unknown coverage
        self.assertIn("Files Discovered**: Unconfirmed [UNKNOWN]", md)
        self.assertIn("configured to evaluate repositories across 6 primary engineering and security domains", md)
        self.assertIn("- **Static File Inspection Coverage**: [UNKNOWN]", md)
        self.assertIn("⚠️ **No Red Team security audit results were supplied for this report [UNKNOWN].**", md)
        self.assertNotIn("No critical vulnerabilities identified in the scanned source files", md)
        self.assertIn("[UNKNOWN] Phase 6 maintainability analysis results were not supplied; AST analysis coverage across Python source files could not be confirmed.", md)
        self.assertIn("- **Maintainability Status**: [UNKNOWN]", md)

    def test_partial_metadata_distinguishes_discovered_from_analyzed_files(self):
        """Discovered files from Phase 0 must not be reported as analyzed files when scanner metadata is absent."""
        p0 = {
            "total_files_discovered": 50,
            "source_files": [{"path": f"src/mod_{i}.py"} for i in range(50)],
            "languages": ["Python"]
        }
        agent = FinalReportGeneratorAgent(phase0_inventory=p0)
        md = agent.generate_markdown_report()
        data = agent.generate_report_data()

        # Discovered files accurately stated
        self.assertIn("Files Discovered**: 50", md)
        self.assertNotIn("Files Analyzed**: 50", md)
        self.assertIn("Repository inventory identified 50 project file(s)", data["executive_summary"]["system_description"])
        self.assertNotIn("Our automated analysis scanned 50 project files", data["executive_summary"]["system_description"])

        # File inspection coverage explicitly marked UNKNOWN because Phase 3A was not supplied
        self.assertIn("- **Static File Inspection Coverage**: [UNKNOWN]", md)
        self.assertNotIn("inspected **50 file(s)**", md)

    def test_fully_populated_metadata_reports_exact_inspected_counts_and_diagnostics(self):
        """When execution metadata is supplied, reports exact inspected file counts, skipped files, and parser diagnostics."""
        p0 = {
            "total_files_discovered": 30,
            "source_files": [{"path": f"src/file_{i}.py"} for i in range(30)],
            "configuration_files": [{"path": "config.yaml"}],
            "potentially_sensitive_files": [{"path": "secret.env"}],
            "frameworks": ["FastAPI"],
            "languages": ["Python"]
        }
        p1 = {
            "project_summary": {"name": "SampleApp"},
            "apis": [{"method": "GET", "path": "/health"}],
            "entry_points": [{"type": "cli_entry_point"}],
            "databases": [{"name": "PostgresDB"}]
        }
        p3a = {
            "inspected_files_count": 12,
            "skipped_files": [{"path": "huge.dat", "reason": "exceeds_size_limit"}],
            "findings": []
        }
        p6 = {
            "code_smells": [
                {
                    "smell_id": "SMELL-NEST-01",
                    "classification": "PROBLEMATIC",
                    "file": "src/file_1.py",
                    "function_or_class": "process",
                    "evidence": "4 nested if blocks",
                    "explanation": "high complexity",
                    "refactoring_strategy": "extract helper"
                }
            ],
            "scan_diagnostics": [
                {"file": "src/file_invalid.py", "status": "SYNTAX_ERROR", "message": "invalid syntax"}
            ]
        }
        p7 = {
            "status": "COMPLETED",
            "domain_interactions": {"security_performance": 1},
            "cross_domain_relationships": [
                {
                    "relationship_id": "REL-SEC-PERF-01",
                    "domain_a": "Security",
                    "domain_b": "Performance",
                    "relationship": "Sanitization overhead",
                    "evidence": "src/file_1.py",
                    "consequence": "minor latency",
                    "recommended_action": "cache compiled regex"
                }
            ],
            "total_relationships": 1
        }
        agent = FinalReportGeneratorAgent(
            phase0_inventory=p0,
            phase1_reconstruction=p1,
            phase3a_red_team=p3a,
            phase6_smells=p6,
            phase7_cross_domain=p7
        )
        md = agent.generate_markdown_report()

        # Section 1.3: Evidence-driven inspection coverage
        self.assertIn("- **Static File Inspection Coverage**: [FACT] Security scanners inspected **12 file(s)** (1 file(s) skipped based on size or path filters).", md)
        self.assertNotIn("We audited all Python source files", md)
        self.assertNotIn("Every source file was parsed using Abstract Syntax Tree", md)

        # Domain breakdown reflects actual scope
        self.assertIn("Evaluated 1 registered HTTP route(s) and 1 entry point candidate(s)", md)
        self.assertIn("Evaluated 1 detected persistence layer(s)", md)
        self.assertIn("candidate configuration files (1) and sensitive candidate files (1)", md)
        self.assertIn("detected framework(s): FastAPI", md)
        self.assertIn("1 scan diagnostic(s) recorded", md)
        self.assertIn("Evaluated 1 specific cross-domain interaction category pair(s)", md)

        # Section 4 reflects inspected files count, not all files
        self.assertIn("No critical vulnerabilities identified across the 12 inspected source file(s)", md)

        # Section 8 reflects diagnostics instead of sweeping AST claim
        self.assertIn("Abstract Syntax Tree (AST) analysis was executed against discovered Python source files (1 scan diagnostic(s) recorded during parsing).", md)

    def test_discovered_files_not_conflated_with_analyzed_files(self):
        """When 100 files are discovered but only 5 files were inspected, claims must not conflate the two."""
        p0 = {
            "repository": {"total_files": 100},
            "languages": ["Python"]
        }
        p3a = {
            "inspected_files_count": 5,
            "skipped_files": [],
            "findings": []
        }
        agent = FinalReportGeneratorAgent(
            phase0_inventory=p0,
            phase3a_red_team=p3a
        )
        md = agent.generate_markdown_report()

        # Header has Discovered files, not Analyzed
        self.assertIn("Files Discovered**: 100", md)
        self.assertNotIn("Files Analyzed**: 100", md)

        # Inspected coverage is strictly 5
        self.assertIn("Security scanners inspected **5 file(s)**", md)
        self.assertIn("across the 5 inspected source file(s)", md)
    def test_regression_duplicate_recommendations_consolidated_in_all_report_sections(self):
        """Duplicate recommendation records with different IDs produce one canonical row in Table 1.4, Section 7, and Section 11."""
        recs = [
            {
                "recommendation_id": "REC-01",
                "finding_id": "RED-DESER-01",
                "affected_files": ["model.py"],
                "problem": "Insecure object deserialization via unverified joblib/pickle machine learning model loading.",
                "recommended_change": "Enforce cryptographic SHA-256 HMAC signature verification prior to loading model files.",
                "security_impact": "Eliminates arbitrary code execution vectors targeting model ingestion.",
                "implementation_complexity": "MEDIUM",
                "priority": "HIGH",
                "evidence": "joblib.load(f1)"
            },
            {
                "recommendation_id": "REC-02",
                "finding_id": "RED-DESER-01",
                "affected_files": ["model.py"],
                "problem": "Insecure object deserialization via unverified joblib/pickle machine learning model loading.",
                "recommended_change": "Enforce cryptographic SHA-256 HMAC signature verification prior to loading model files.",
                "security_impact": "Eliminates arbitrary code execution vectors targeting model ingestion.",
                "implementation_complexity": "MEDIUM",
                "priority": "HIGH",
                "evidence": "joblib.load(f2)"
            },
            {
                "recommendation_id": "REC-03",
                "finding_id": "RED-DESER-01",
                "affected_files": ["model.py"],
                "problem": "Insecure object deserialization via unverified joblib/pickle machine learning model loading.",
                "recommended_change": "Enforce cryptographic SHA-256 HMAC signature verification prior to loading model files.",
                "security_impact": "Eliminates arbitrary code execution vectors targeting model ingestion.",
                "implementation_complexity": "MEDIUM",
                "priority": "HIGH",
                "evidence": "joblib.load(f3)"
            }
        ]
        agent = FinalReportGeneratorAgent(phase8_recommendations={"recommendations": recs})
        md = agent.generate_markdown_report()
        data = agent.generate_report_data()

        # Table 1.4 must contain exactly one REC-01 row for this issue, not REC-02 or REC-03
        self.assertIn("| **REC-01** | Security | Insecure object deserialization", md)
        self.assertNotIn("| **REC-02** |", md)
        self.assertNotIn("| **REC-03** |", md)

        # Section 11 must also have only REC-01
        self.assertIn("### `[HIGH]` REC-01: Insecure object deserialization", md)
        self.assertNotIn("### `[HIGH]` REC-02:", md)

        # Evidence must be combined
        self.assertIn("joblib.load(f1)", md)
        self.assertIn("joblib.load(f2)", md)

        # Structured report data must also be consolidated
        self.assertEqual(len(data["recommendations"]), 1)
        self.assertEqual(data["recommendations"][0]["recommendation_id"], "REC-01")

    def test_regression_distinct_recommendations_remain_separate(self):
        """Distinct recommendations with different finding IDs or different affected components remain separate."""
        recs = [
            {
                "recommendation_id": "REC-01",
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/users.py"],
                "problem": "Potential SQL Injection in users module.",
                "recommended_change": "Use parameterized queries.",
                "priority": "CRITICAL"
            },
            {
                "recommendation_id": "REC-02",
                "finding_id": "RED-SQL-01",
                "affected_files": ["src/orders.py"],
                "problem": "Potential SQL Injection in orders module.",
                "recommended_change": "Use parameterized queries.",
                "priority": "CRITICAL"
            }
        ]
        agent = FinalReportGeneratorAgent(phase8_recommendations={"recommendations": recs})
        md = agent.generate_markdown_report()

        self.assertIn("| **REC-01** | Security | Potential SQL Injection in users module.", md)
        self.assertIn("| **REC-02** | Security | Potential SQL Injection in orders module.", md)

    def test_regression_long_requirement_descriptions_not_truncated(self):
        """Requirement descriptions longer than 40 chars are rendered completely without ellipsis truncation."""
        long_desc = "The system must expose HTTP endpoint GET /api/run for client operations and workflow execution."
        reqs = [
            {
                "requirement_id": "REQ-FUNC-04",
                "category": "functional",
                "description": long_desc,
                "status": "explicit",
                "source_file": "src/api/routes.py"
            }
        ]
        agent = FinalReportGeneratorAgent(phase2_requirements=reqs)
        md = agent.generate_markdown_report()

        # Must NOT contain truncated version with ellipsis
        self.assertNotIn("The system must expose HTTP endpoint ...", md)
        # Must contain the entire description in Section 10 table
        self.assertIn(long_desc, md)
        self.assertIn(f"| **REQ-FUNC-04** ({long_desc}) | Implemented in src/api/routes.py | **SATISFIED** | `src/api/routes.py` | None; verified in code |", md)

    def test_regression_requirement_with_special_characters_and_pipes_safe(self):
        """Requirements containing quotes, angle brackets, ampersands, and table pipe characters render safely."""
        tricky_desc = 'Sanitize user input <script>alert("XSS")</script> & parameters | avoid pipe collision'
        reqs = [
            {
                "requirement_id": "REQ-SEC-09",
                "category": "security",
                "description": tricky_desc,
                "status": "code_supported",
                "source_file": "src/sanitize.py"
            }
        ]
        agent = FinalReportGeneratorAgent(phase2_requirements=reqs)
        md = agent.generate_markdown_report()

        # Table pipe | must be escaped as \|
        self.assertIn(r"avoid pipe collision", md)
        self.assertIn(r"\|", md)
        # Angle brackets and quotes preserved
        self.assertIn("<script>alert(\"XSS\")</script>", md)

    def test_regression_missing_or_empty_requirement_description_reported_truthfully(self):
        """Requirements with empty or None description are honestly labeled as incomplete rather than fabricated."""
        reqs = [
            {
                "requirement_id": "REQ-FUNC-99",
                "category": "functional",
                "description": "",
                "status": "explicit",
                "source_file": "src/unknown.py"
            }
        ]
        agent = FinalReportGeneratorAgent(phase2_requirements=reqs)
        md = agent.generate_markdown_report()

        self.assertIn("[Incomplete description in source data]", md)


if __name__ == "__main__":
    unittest.main()
