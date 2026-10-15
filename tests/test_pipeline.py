"""
Unit tests for Phase 1 (Project Reconstruction) and Phase 2 (Security Assessment).
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import io
from unittest.mock import patch

from src.phase0.ingestion import RepositoryIngestionAgent
from src.phase1.reconstruction import ProjectReconstructionAgent
from src.phase2.requirements import RequirementsEngineeringAgent
from src.phase2.assessment import SecurityAssessmentAgent
from src.phase3a.red_team import RedTeamSecurityAgent
from src.phase4a.blue_team import BlueTeamDefensiveAgent
from src.phase5a.retest import SecurityRetestAgent
from src.phase6.code_smells import CodeSmellAnalysisAgent
from src.phase7.cross_domain import CrossDomainAnalysisAgent
from src.phase8.recommendations import RecommendationEngineAgent
from src.phase9.report import FinalReportGeneratorAgent
from pipeline import (
    run_pipeline,
    build_parser,
    main,
    PipelineExecutionError,
    PhaseOutputValidationError,
    validate_phase_output,
    cleanup_temp_dir,
)


class TestMultiPhasePipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_pipeline_")
        self._setup_mock_project(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _setup_mock_project(self, base_dir: str):
        # Source & FastAPI Route
        src_dir = os.path.join(base_dir, "app")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/users')\n"
                "def get_users():\n"
                "    return [{'id': 1}]\n"
                "if __name__ == '__main__':\n"
                "    import uvicorn\n"
                "    uvicorn.run(app)\n"
            )

        # Manifest
        with open(os.path.join(base_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("fastapi==0.100.0\nuvicorn==0.23.0\nredis==5.0.0\n")

        # Documentation
        with open(os.path.join(base_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# User Management Microservice\nHandles user profile queries.\n")

    def test_phase1_reconstruction_schema(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        # Check all required Phase 1 top-level keys
        required_keys = [
            "project_summary", "users", "use_cases", "components", "architecture",
            "data_flows", "trust_boundaries", "entry_points", "apis", "databases",
            "external_services", "dependencies", "authentication_components",
            "deployment_model", "documented_behavior", "code_supported_behavior",
            "inferences", "unknowns"
        ]
        for key in required_keys:
            self.assertIn(key, p1, f"Missing required Phase 1 key: '{key}'")

        # Check HTTP API route detection
        routes = [a["path"] for a in p1["apis"]]
        self.assertIn("/api/users", routes)

        # Check component file paths
        for comp in p1["components"]:
            self.assertIn("supporting_file_paths", comp)
            self.assertTrue(len(comp["supporting_file_paths"]) > 0)

        # Check evidence classifications
        self.assertIn(p1["project_summary"]["problem_being_solved"]["classification"], ["DOCUMENTED", "CODE_SUPPORTED", "INFERRED", "UNKNOWN"])

    def test_phase2_security_assessment(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        agent2 = SecurityAssessmentAgent(phase1_reconstruction=p1)
        p2 = agent2.assess()

        # Check Phase 2 structure
        self.assertIn("assessment_summary", p2)
        self.assertIn("findings", p2)
        self.assertIn("architecture_resilience", p2)
        self.assertIn("remediation_roadmap", p2)

        summary = p2["assessment_summary"]
        self.assertIsInstance(summary["security_health_score"], int)
        self.assertGreaterEqual(summary["security_health_score"], 0)
        self.assertLessEqual(summary["security_health_score"], 100)

        # Findings should be prioritized
        findings = p2["findings"]
        self.assertTrue(len(findings) > 0)
        self.assertIn("severity", findings[0])
        self.assertIn("remediation", findings[0])

    def test_phase2_requirements_extraction(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        agent2_req = RequirementsEngineeringAgent(root_path=self.test_dir, phase0_inventory=p0, phase1_reconstruction=p1)
        reqs = agent2_req.extract_requirements()

        self.assertIsInstance(reqs, list)
        self.assertTrue(len(reqs) > 0)

        # Verify each requirement has the exact schema keys
        required_req_keys = [
            "requirement_id", "category", "description", "source",
            "source_file", "evidence", "status", "importance", "architectural_implications"
        ]
        for r in reqs:
            for k in required_req_keys:
                self.assertIn(k, r, f"Requirement missing key: '{k}'")
            self.assertIn(r["category"], ["functional", "security", "non_functional", "business_constraint"])
            self.assertIn(r["status"], ["explicit", "code_supported", "inferred", "unknown"])
            self.assertIn(r["importance"], ["critical", "high", "medium", "low"])
            self.assertIsInstance(r["architectural_implications"], list)

    def test_pipeline_e2e(self):
        result = run_pipeline(source=self.test_dir, source_type="dir", phase="all")
        self.assertIn("phase0_inventory", result)
        self.assertIn("phase1_reconstruction", result)
        self.assertIn("phase2_requirements", result)
        self.assertIn("phase2_security_assessment", result)

    def test_phase1_project_name_precedence(self):
        # Verify Windows backslash path and repo URLs are parsed without operator precedence bug
        mock_p0 = {
            "repository": {"source": r"C:\repos\alpha-service"},
            "source_files": [],
            "documentation_files": []
        }
        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=mock_p0)
        p1 = agent1.reconstruct()
        self.assertEqual(p1["project_summary"]["name"], "alpha-service")

        # GitHub URL
        mock_p0_git = {
            "repository": {"source": "https://github.com/org/payment-gateway.git"},
            "source_files": [],
            "documentation_files": []
        }
        agent1_git = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=mock_p0_git)
        p1_git = agent1_git.reconstruct()
        self.assertEqual(p1_git["project_summary"]["name"], "payment-gateway")

    def test_phase1_api_without_database_data_flow(self):
        # When an API has routes but no database files or DB references
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})
        # Ensure database_files is empty
        p0["database_files"] = []

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        http_flows = [f for f in p1["data_flows"] if f["flow_name"] == "HTTP Request/Response Flow"]
        self.assertTrue(len(http_flows) > 0)
        trace = http_flows[0]["trace"]
        self.assertNotIn("Database Persistence", trace, "API routes must not assume database storage when no database exists.")
        self.assertEqual(http_flows[0]["classification"], "INFERRED", "Data flows must be classified as INFERRED.")

    def test_phase1_auth_keywords_not_code_supported(self):
        # Create a source file with auth keyword
        auth_file = os.path.join(self.test_dir, "app", "auth_check.py")
        with open(auth_file, "w", encoding="utf-8") as f:
            f.write("# Simple comment referencing jwt and authenticate\npass\n")

        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        # Auth components must be labeled INFERRED, never CODE_SUPPORTED proof of protection
        for auth_comp in p1["authentication_components"]:
            self.assertEqual(auth_comp["classification"], "INFERRED")

        # Unknowns should report that enforcement policies could not be confirmed
        unknown_items = [u["item"] for u in p1["unknowns"]]
        self.assertTrue(any("Authentication" in item for item in unknown_items))

    def test_phase1_input_type_validation(self):
        # Reject invalid types with clear exceptions
        with self.assertRaises(TypeError):
            ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory="invalid_str")

        with self.assertRaises(ValueError):
            ProjectReconstructionAgent(root_path="", phase0_inventory={})

        with self.assertRaises(ValueError):
            ProjectReconstructionAgent(root_path=None, phase0_inventory={})

        # Resilient to None values in optional inventory keys
        agent = ProjectReconstructionAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": None, "documentation_files": None, "repository": {}}
        )
        p1 = agent.reconstruct()
        self.assertIsInstance(p1, dict)
        self.assertIn("project_summary", p1)

    def test_phase1_evidence_line_numbers(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        # Ingested app/main.py has route decorators; verify line numbers are attached
        routes = p1["apis"]
        self.assertTrue(len(routes) > 0)
        for r in routes:
            self.assertIn("line_number", r)
            self.assertIsInstance(r["line_number"], int)
            self.assertGreater(r["line_number"], 0)

    def test_phase1_partial_scan_propagation(self):
        mock_p0 = {
            "repository": {"source": "local"},
            "source_files": [{"path": "app/main.py", "language": "Python"}],
            "file_inventory": ["app/main.py"],
            "ingestion_status": "PARTIAL",
            "warnings": ["File count limit reached"]
        }
        agent = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=mock_p0)
        p1 = agent.reconstruct()
        self.assertEqual(p1["reconstruction_status"], "PARTIAL")
        self.assertTrue(any("Incomplete Repository Scan" in u["item"] for u in p1["unknowns"]))

    def test_system_design_phase_removed_and_not_required(self):
        # Verify SecurityAssessmentAgent generates no SYSDES findings
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})
        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        agent2 = SecurityAssessmentAgent(phase1_reconstruction=p1)
        p2 = agent2.assess()

        # Verify no SYSDES- prefixed findings exist
        sysdes_findings = [f for f in p2["findings"] if f["finding_id"].startswith("SYSDES")]
        self.assertEqual(sysdes_findings, [], "System Design findings must not be generated.")

        # Verify end-to-end pipeline executes without requiring System Design phase
        result = run_pipeline(source=self.test_dir, source_type="dir", phase="all")
        self.assertNotIn("phase_system_design", result)

    def test_phase0_stops_after_ingestion(self):
        """Selecting Phase 0 must stop immediately after Phase 0 ingestion and not run Phase 1."""
        with patch.object(ProjectReconstructionAgent, "reconstruct") as mock_reconstruct:
            result = run_pipeline(source=self.test_dir, source_type="dir", phase="0")
            self.assertIsInstance(result, dict)
            self.assertIn("file_inventory", result)
            self.assertIn("repository", result)
            mock_reconstruct.assert_not_called()

    def test_phase8_runs_prerequisites_in_order(self):
        """Selecting Phase 8 must execute all prerequisite phases (0-7) in exact dependency order."""
        execution_order = []

        orig_p0_inv = RepositoryIngestionAgent.inventory
        orig_p1_rec = ProjectReconstructionAgent.reconstruct
        orig_p2_req = RequirementsEngineeringAgent.extract_requirements
        orig_p2_sec = SecurityAssessmentAgent.assess
        orig_p3a_an = RedTeamSecurityAgent.analyze
        orig_p4a_an = BlueTeamDefensiveAgent.analyze
        orig_p5a_re = SecurityRetestAgent.retest
        orig_p6_an = CodeSmellAnalysisAgent.analyze
        orig_p7_an = CrossDomainAnalysisAgent.analyze
        orig_p8_rec = RecommendationEngineAgent.generate_recommendations

        def wrap_p0(agent_self, *args, **kwargs):
            execution_order.append("phase0_inventory")
            return orig_p0_inv(agent_self, *args, **kwargs)

        def wrap_p1(agent_self, *args, **kwargs):
            execution_order.append("phase1_reconstruct")
            return orig_p1_rec(agent_self, *args, **kwargs)

        def wrap_p2_req(agent_self, *args, **kwargs):
            execution_order.append("phase2_requirements")
            return orig_p2_req(agent_self, *args, **kwargs)

        def wrap_p2_sec(agent_self, *args, **kwargs):
            execution_order.append("phase2_assessment")
            return orig_p2_sec(agent_self, *args, **kwargs)

        def wrap_p3a(agent_self, *args, **kwargs):
            execution_order.append("phase3a_red_team")
            return orig_p3a_an(agent_self, *args, **kwargs)

        def wrap_p4a(agent_self, *args, **kwargs):
            execution_order.append("phase4a_blue_team")
            return orig_p4a_an(agent_self, *args, **kwargs)

        def wrap_p5a(agent_self, *args, **kwargs):
            execution_order.append("phase5a_retest")
            return orig_p5a_re(agent_self, *args, **kwargs)

        def wrap_p6(agent_self, *args, **kwargs):
            execution_order.append("phase6_code_smells")
            return orig_p6_an(agent_self, *args, **kwargs)

        def wrap_p7(agent_self, *args, **kwargs):
            execution_order.append("phase7_cross_domain")
            return orig_p7_an(agent_self, *args, **kwargs)

        def wrap_p8(agent_self, *args, **kwargs):
            execution_order.append("phase8_recommendations")
            return orig_p8_rec(agent_self, *args, **kwargs)

        with patch.object(RepositoryIngestionAgent, "inventory", side_effect=wrap_p0, autospec=True), \
             patch.object(ProjectReconstructionAgent, "reconstruct", side_effect=wrap_p1, autospec=True), \
             patch.object(RequirementsEngineeringAgent, "extract_requirements", side_effect=wrap_p2_req, autospec=True), \
             patch.object(SecurityAssessmentAgent, "assess", side_effect=wrap_p2_sec, autospec=True), \
             patch.object(RedTeamSecurityAgent, "analyze", side_effect=wrap_p3a, autospec=True), \
             patch.object(BlueTeamDefensiveAgent, "analyze", side_effect=wrap_p4a, autospec=True), \
             patch.object(SecurityRetestAgent, "retest", side_effect=wrap_p5a, autospec=True), \
             patch.object(CodeSmellAnalysisAgent, "analyze", side_effect=wrap_p6, autospec=True), \
             patch.object(CrossDomainAnalysisAgent, "analyze", side_effect=wrap_p7, autospec=True), \
             patch.object(RecommendationEngineAgent, "generate_recommendations", side_effect=wrap_p8, autospec=True), \
             patch.object(FinalReportGeneratorAgent, "generate_markdown_report") as mock_report:

            result = run_pipeline(source=self.test_dir, source_type="dir", phase="8")

            expected_order = [
                "phase0_inventory",
                "phase1_reconstruct",
                "phase2_requirements",
                "phase2_assessment",
                "phase3a_red_team",
                "phase4a_blue_team",
                "phase5a_retest",
                "phase6_code_smells",
                "phase7_cross_domain",
                "phase8_recommendations",
            ]
            self.assertEqual(execution_order, expected_order, "Phase 8 must execute prerequisite phases 0-7 in order.")
            mock_report.assert_not_called()
            self.assertIsInstance(result, dict)
            self.assertIn("recommendations", result)

    def test_phase9_runs_prerequisites_and_generates_final_report(self):
        """Selecting Phase 9 must run all prerequisite phases and generate the final report."""
        result_9 = run_pipeline(source=self.test_dir, source_type="dir", phase="9")
        self.assertIsInstance(result_9, dict)
        self.assertIn("report_data", result_9)
        self.assertIn("markdown_report", result_9)
        self.assertIn("# PHASE 9 — FINAL SOFTWARE ARCHITECTURE AND SECURITY REPORT", result_9["markdown_report"])
        self.assertIn("executive_summary", result_9["report_data"])

        # 'report' alias must yield the identical structure
        result_report = run_pipeline(source=self.test_dir, source_type="dir", phase="report")
        self.assertIsInstance(result_report, dict)
        self.assertIn("report_data", result_report)
        self.assertIn("markdown_report", result_report)

    def test_existing_phase_aliases_continue_to_work(self):
        """Verifies that all phase aliases ('3', '3a', '4', '4a', '5', '5a', '7', '7a', 'report') continue to function."""
        # Phase 3 & 3a
        res_3 = run_pipeline(source=self.test_dir, source_type="dir", phase="3")
        res_3a = run_pipeline(source=self.test_dir, source_type="dir", phase="3a")
        self.assertIn("findings", res_3)
        self.assertIn("findings", res_3a)

        # Phase 4 & 4a
        res_4 = run_pipeline(source=self.test_dir, source_type="dir", phase="4")
        res_4a = run_pipeline(source=self.test_dir, source_type="dir", phase="4a")
        self.assertIn("remediation_plans", res_4)
        self.assertIn("remediation_plans", res_4a)

        # Phase 5 & 5a
        res_5 = run_pipeline(source=self.test_dir, source_type="dir", phase="5")
        res_5a = run_pipeline(source=self.test_dir, source_type="dir", phase="5a")
        self.assertIn("retest_results", res_5)
        self.assertIn("retest_results", res_5a)

        # Phase 7 & 7a
        res_7 = run_pipeline(source=self.test_dir, source_type="dir", phase="7")
        res_7a = run_pipeline(source=self.test_dir, source_type="dir", phase="7a")
        self.assertIn("cross_domain_relationships", res_7)
        self.assertIn("cross_domain_relationships", res_7a)

        # Phase report
        res_report = run_pipeline(source=self.test_dir, source_type="dir", phase="report")
        self.assertIn("report_data", res_report)
        self.assertIn("markdown_report", res_report)

    def test_cli_help_accurately_describes_prerequisite_execution(self):
        """CLI parser help text must explicitly explain sequential prerequisite execution, all, and report options."""
        parser = build_parser()
        help_text = parser.format_help()

        self.assertIn("prerequisite", help_text.lower())
        self.assertIn("sequential", help_text.lower())
        self.assertIn("all", help_text)
        self.assertIn("report", help_text)
        self.assertIn("phase 8", help_text.lower())
        self.assertIn("phase 0", help_text.lower())

    # -------------------------------------------------------------------------
    # Failure Diagnostics & Debug Mode Tests
    # -------------------------------------------------------------------------
    def test_failure_during_repository_ingestion(self):
        """Failure during Phase 0 inventory must raise PipelineExecutionError with phase '0' and original cause."""
        simulated_err = ValueError("Corrupted repository inventory stream")
        with patch.object(RepositoryIngestionAgent, "inventory", side_effect=simulated_err):
            with self.assertRaises(PipelineExecutionError) as cm:
                run_pipeline(source=self.test_dir, source_type="dir", phase="all")

            err = cm.exception
            self.assertEqual(err.phase, "0")
            self.assertEqual(err.operation, "generating repository inventory")
            self.assertIs(err.original_error, simulated_err)
            self.assertIs(err.__cause__, simulated_err)
            self.assertIn("Phase 0 failed during 'generating repository inventory': Corrupted repository inventory stream", str(err))

    def test_failure_during_middle_phase(self):
        """Failure during a middle phase (e.g. Phase 4A) must identify the exact phase, operation, and chain the exception."""
        simulated_err = KeyError("missing_vulnerability_context")
        with patch.object(BlueTeamDefensiveAgent, "analyze", side_effect=simulated_err):
            with self.assertRaises(PipelineExecutionError) as cm:
                run_pipeline(source=self.test_dir, source_type="dir", phase="all")

            err = cm.exception
            self.assertEqual(err.phase, "4a")
            self.assertEqual(err.operation, "blue team defensive analysis")
            self.assertIs(err.original_error, simulated_err)
            self.assertIs(err.__cause__, simulated_err)
            self.assertIn("Phase 4a failed during 'blue team defensive analysis'", str(err))

    def test_failure_during_phase9_report_generation(self):
        """Failure during Phase 9 final report generation must identify Phase 9 and the report generation operation."""
        simulated_err = RuntimeError("Markdown rendering engine error")
        with patch.object(FinalReportGeneratorAgent, "generate_markdown_report", side_effect=simulated_err):
            with self.assertRaises(PipelineExecutionError) as cm:
                run_pipeline(source=self.test_dir, source_type="dir", phase="9")

            err = cm.exception
            self.assertEqual(err.phase, "9")
            self.assertEqual(err.operation, "generating final markdown report")
            self.assertIs(err.original_error, simulated_err)
            self.assertIs(err.__cause__, simulated_err)
            self.assertIn("Phase 9 failed during 'generating final markdown report'", str(err))

    def test_normal_mode_displays_concise_diagnostic_information(self):
        """In normal mode, CLI must print a concise diagnostic message to stderr, omit traceback, and leave stdout clean."""
        simulated_err = SyntaxError("AST syntax validation error")
        with patch.object(CodeSmellAnalysisAgent, "analyze", side_effect=simulated_err), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

            with self.assertRaises(SystemExit) as cm:
                main(argv=["--source", self.test_dir, "--source-type", "dir", "--phase", "all"])

            self.assertEqual(cm.exception.code, 1)
            err_output = mock_stderr.getvalue()
            std_output = mock_stdout.getvalue()

            self.assertIn("Pipeline error in Phase 6 during 'code smell and maintainability analysis': AST syntax validation error", err_output)
            self.assertNotIn("Traceback (most recent call last):", err_output)
            self.assertEqual(std_output, "", "stdout must remain clean on error for piping and script automation.")

    def test_debug_mode_includes_traceback_information(self):
        """In debug mode (--debug), CLI must print concise message and full traceback to stderr, keeping stdout clean."""
        simulated_err = SyntaxError("AST syntax validation error")
        with patch.object(CodeSmellAnalysisAgent, "analyze", side_effect=simulated_err), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

            with self.assertRaises(SystemExit) as cm:
                main(argv=["--source", self.test_dir, "--source-type", "dir", "--phase", "all", "--debug"])

            self.assertEqual(cm.exception.code, 1)
            err_output = mock_stderr.getvalue()
            std_output = mock_stdout.getvalue()

            self.assertIn("Pipeline error in Phase 6 during 'code smell and maintainability analysis': AST syntax validation error", err_output)
            self.assertIn("Traceback (most recent call last):", err_output)
            self.assertEqual(std_output, "", "stdout must remain clean on error for piping and script automation.")

    def test_nonzero_exit_status_after_failure(self):
        """CLI execution must return a nonzero exit status (exit code 1) on any failure."""
        with patch("sys.stderr", new_callable=io.StringIO), \
             patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as cm:
                main(argv=["--source", os.path.join(self.test_dir, "nonexistent_subfolder"), "--source-type", "dir"])
            self.assertEqual(cm.exception.code, 1)

    def test_temporary_resources_cleaned_up_after_failure(self):
        """When an ingestion or downstream phase fails, temporary cloned/extracted directories must still be cleaned up."""
        fake_temp = tempfile.mkdtemp(prefix="test_failure_cleanup_")
        self.assertTrue(os.path.exists(fake_temp))

        simulated_err = RuntimeError("Unexpected inventory scanning abort")
        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch.object(RepositoryIngestionAgent, "inventory", side_effect=simulated_err):

            with self.assertRaises(PipelineExecutionError):
                run_pipeline(source="https://github.com/mock/repo.git", source_type="github", phase="all")

            # Temporary directory must be removed by finally block despite the exception
            self.assertFalse(os.path.exists(fake_temp), "Temporary directory must be deleted on failure in finally block.")

    def test_temporary_repository_cleanup_after_successful_run(self):
        """Temporary repository directory must be cleaned up after a successful pipeline run."""
        fake_temp = tempfile.mkdtemp(prefix="test_success_cleanup_")
        self._setup_mock_project(fake_temp)
        self.assertTrue(os.path.exists(fake_temp))

        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)):
            result = run_pipeline(source="https://github.com/mock/repo.git", source_type="github", phase="0")
            self.assertIn("file_inventory", result)

        self.assertFalse(os.path.exists(fake_temp), "Temporary repository must be deleted after successful run.")

    def test_user_provided_local_directories_remain_intact(self):
        """User-provided local directories must never be deleted, during success or failure."""
        readme_path = os.path.join(self.test_dir, "README.md")
        self.assertTrue(os.path.exists(readme_path))

        # 1. On successful run
        res = run_pipeline(source=self.test_dir, source_type="dir", phase="1")
        self.assertIn("components", res)
        self.assertTrue(os.path.exists(self.test_dir), "User local directory must remain intact after success.")
        self.assertTrue(os.path.exists(readme_path), "User files must remain intact after success.")

        # 2. On failure
        simulated_err = ValueError("Failure in Phase 1")
        with patch.object(ProjectReconstructionAgent, "reconstruct", side_effect=simulated_err):
            with self.assertRaises(PipelineExecutionError):
                run_pipeline(source=self.test_dir, source_type="dir", phase="1")

        self.assertTrue(os.path.exists(self.test_dir), "User local directory must remain intact after phase failure.")
        self.assertTrue(os.path.exists(readme_path), "User files must remain intact after phase failure.")

    def test_user_provided_zip_files_remain_intact(self):
        """User-provided ZIP archives must remain intact after extraction and pipeline execution."""
        import zipfile
        temp_dir = tempfile.mkdtemp(prefix="test_zip_source_")
        try:
            zip_path = os.path.join(temp_dir, "sample_repo.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("app/server.py", "print('hello')\n")
                zf.writestr("README.md", "# Test Zip Project\n")

            self.assertTrue(os.path.exists(zip_path))

            # Run pipeline on zip
            result = run_pipeline(source=zip_path, source_type="zip", phase="0")
            self.assertIn("file_inventory", result)

            # ZIP archive itself must still exist
            self.assertTrue(os.path.exists(zip_path), "User ZIP archive must never be deleted by cleanup.")

            # Also test when a phase fails on zip
            simulated_err = RuntimeError("Phase 1 failure on zip")
            with patch.object(ProjectReconstructionAgent, "reconstruct", side_effect=simulated_err):
                with self.assertRaises(PipelineExecutionError):
                    run_pipeline(source=zip_path, source_type="zip", phase="1")

            self.assertTrue(os.path.exists(zip_path), "User ZIP archive must remain intact even if a phase fails.")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_no_cleanup_occurs_when_repository_not_temporary(self):
        """No cleanup attempts or rmtree calls should occur when the repository is not temporary."""
        with patch("pipeline.cleanup_temp_dir") as mock_cleanup:
            run_pipeline(source=self.test_dir, source_type="dir", phase="0")
            mock_cleanup.assert_called_once_with(None, source=self.test_dir)

    def test_cleanup_failure_does_not_hide_original_pipeline_error(self):
        """Cleanup failure (e.g. PermissionError) must not mask or replace the original phase error."""
        fake_temp = tempfile.mkdtemp(prefix="test_cleanup_fail_")
        self._setup_mock_project(fake_temp)

        simulated_phase_err = RuntimeError("Critical vulnerability scanner aborted")
        cleanup_err = PermissionError("Access denied deleting locked file")

        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch.object(ProjectReconstructionAgent, "reconstruct", side_effect=simulated_phase_err), \
             patch("shutil.rmtree", side_effect=cleanup_err), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:

            with self.assertRaises(PipelineExecutionError) as cm:
                run_pipeline(source="https://github.com/mock/repo.git", source_type="github", phase="1")

            # The raised exception must be the pipeline error, chaining simulated_phase_err
            self.assertEqual(cm.exception.phase, "1")
            self.assertIs(cm.exception.original_error, simulated_phase_err)
            self.assertIs(cm.exception.__cause__, simulated_phase_err)

            # Diagnostic warning for cleanup failure must be printed to stderr
            err_output = mock_stderr.getvalue()
            self.assertIn("Warning: Failed to clean up temporary directory", err_output)
            self.assertIn("Access denied deleting locked file", err_output)

        shutil.rmtree(fake_temp, ignore_errors=True)

    def test_cleanup_failure_on_successful_run_prints_diagnostic_to_stderr(self):
        """When cleanup fails after a successful pipeline run, a diagnostic is printed to stderr without raising."""
        fake_temp = tempfile.mkdtemp(prefix="test_cleanup_fail_success_")
        self._setup_mock_project(fake_temp)

        cleanup_err = OSError("Device or resource busy")
        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch("shutil.rmtree", side_effect=cleanup_err), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:

            result = run_pipeline(source="https://github.com/mock/repo.git", source_type="github", phase="0")
            self.assertIn("file_inventory", result)

            err_output = mock_stderr.getvalue()
            self.assertIn("Warning: Failed to clean up temporary directory", err_output)
            self.assertIn("Device or resource busy", err_output)

        shutil.rmtree(fake_temp, ignore_errors=True)

    def test_cleanup_temp_dir_guards_against_invalid_or_source_paths(self):
        """cleanup_temp_dir must guard against source paths, non-directories, and root paths."""
        with patch("shutil.rmtree") as mock_rmtree:
            # None or empty
            cleanup_temp_dir(None)
            cleanup_temp_dir("")
            mock_rmtree.assert_not_called()

            # Same as source
            cleanup_temp_dir(self.test_dir, source=self.test_dir)
            mock_rmtree.assert_not_called()

            # Root paths
            cleanup_temp_dir("C:\\")
            cleanup_temp_dir("/")
            mock_rmtree.assert_not_called()

    def test_contract_validation_valid_output_with_non_empty_collections(self):
        """Valid output with non-empty collections must pass contract validation."""
        valid_out = {"findings": [{"finding_id": "FIND-01", "severity": "HIGH"}]}
        result = validate_phase_output(
            phase="3a",
            operation="red team security analysis",
            output=valid_out,
            expected_type=dict,
            required_fields={"findings": list}
        )
        self.assertIs(result, valid_out)

    def test_contract_validation_valid_output_with_empty_collections(self):
        """Valid output with legitimate empty collections must be preserved and accepted without error."""
        # Empty findings
        p3a_empty = {"findings": []}
        res3a = validate_phase_output(
            phase="3a",
            operation="red team security analysis",
            output=p3a_empty,
            expected_type=dict,
            required_fields={"findings": list}
        )
        self.assertEqual(res3a["findings"], [])

        # Empty cross-domain relationships
        p7_empty = {"cross_domain_relationships": []}
        res7 = validate_phase_output(
            phase="7",
            operation="cross-domain engineering analysis",
            output=p7_empty,
            expected_type=dict,
            required_fields={"cross_domain_relationships": list}
        )
        self.assertEqual(res7["cross_domain_relationships"], [])

        # Empty Phase 2 requirements list
        res2 = validate_phase_output(
            phase="2",
            operation="extracting requirements",
            output=[],
            expected_type=list
        )
        self.assertEqual(res2, [])

    def test_contract_validation_missing_required_key(self):
        """Missing required key must immediately raise PhaseOutputValidationError identifying phase and field."""
        malformed_p3a = {"attack_surface": {}}  # missing 'findings'
        with self.assertRaises(PhaseOutputValidationError) as cm:
            validate_phase_output(
                phase="3a",
                operation="red team security analysis",
                output=malformed_p3a,
                expected_type=dict,
                required_fields={"findings": list}
            )

        err = cm.exception
        self.assertEqual(err.phase, "3a")
        self.assertEqual(err.operation, "red team security analysis")
        self.assertEqual(err.field, "findings")
        self.assertEqual(err.expected, "list")
        self.assertEqual(err.actual, "missing")
        self.assertIn("findings", str(err))
        self.assertIn("missing", str(err))

    def test_contract_validation_wrong_top_level_type(self):
        """Top-level output with unexpected type must raise PhaseOutputValidationError."""
        with self.assertRaises(PhaseOutputValidationError) as cm:
            validate_phase_output(
                phase="1",
                operation="reconstructing project architecture",
                output=["not", "a", "dict"],
                expected_type=dict
            )

        err = cm.exception
        self.assertEqual(err.phase, "1")
        self.assertEqual(err.expected, "dict")
        self.assertEqual(err.actual, "list")
        self.assertIn("Top-level output must be a dict, got list", str(err))

    def test_contract_validation_wrong_collection_type(self):
        """Required collection supplied with unexpected type must raise PhaseOutputValidationError."""
        malformed_p4a = {"remediation_plans": "none_available"}  # str instead of list
        with self.assertRaises(PhaseOutputValidationError) as cm:
            validate_phase_output(
                phase="4a",
                operation="blue team defensive analysis",
                output=malformed_p4a,
                expected_type=dict,
                required_fields={"remediation_plans": list}
            )

        err = cm.exception
        self.assertEqual(err.phase, "4a")
        self.assertEqual(err.field, "remediation_plans")
        self.assertEqual(err.expected, "list")
        self.assertEqual(err.actual, "str")
        self.assertIn("Field 'remediation_plans' must be a list, got str", str(err))

    def test_malformed_output_detected_before_downstream_agent_called(self):
        """Malformed output in Phase 3A must fail immediately and prevent Phase 4A agent from running."""
        malformed_p3a = {"summary": "no findings key"}
        with patch.object(RedTeamSecurityAgent, "analyze", return_value=malformed_p3a), \
             patch.object(BlueTeamDefensiveAgent, "analyze") as mock_blue_analyze:

            with self.assertRaises(PhaseOutputValidationError) as cm:
                run_pipeline(source=self.test_dir, source_type="dir", phase="all")

            # Phase 4A must NEVER have executed
            mock_blue_analyze.assert_not_called()

            # Exception must clearly identify Phase 3A
            err = cm.exception
            self.assertEqual(err.phase, "3a")
            self.assertEqual(err.field, "findings")
            self.assertIn("Phase 3a failed during 'red team security analysis'", str(err))

    def test_phase8_output_validation_before_phase9(self):
        """Malformed Phase 8 output must be caught before invoking Phase 9 report generation."""
        malformed_p8 = {"total": 0}  # missing 'recommendations' list
        with patch.object(RecommendationEngineAgent, "generate_recommendations", return_value=malformed_p8), \
             patch.object(FinalReportGeneratorAgent, "generate_report_data") as mock_report_data:

            with self.assertRaises(PhaseOutputValidationError) as cm:
                run_pipeline(source=self.test_dir, source_type="dir", phase="all")

            # Phase 9 report generation must not run
            mock_report_data.assert_not_called()

            # Exception must clearly identify Phase 8
            err = cm.exception
            self.assertEqual(err.phase, "8")
            self.assertEqual(err.field, "recommendations")
            self.assertIn("Phase 8 failed during 'generating prioritized recommendations'", str(err))

    def test_successful_end_to_end_execution_when_outputs_satisfy_contracts(self):
        """When all phase outputs conform to contracts, full pipeline runs end-to-end successfully."""
        result = run_pipeline(source=self.test_dir, source_type="dir", phase="all")
        self.assertIsInstance(result, dict)
        expected_keys = [
            "phase0_inventory",
            "phase1_reconstruction",
            "phase2_requirements",
            "phase2_security_assessment",
            "phase3a_red_team",
            "phase4a_blue_team",
            "phase5a_security_retest",
            "phase6_code_smells",
            "phase7_cross_domain",
            "phase8_recommendations",
            "phase9_final_report",
            "phase9_markdown_report",
        ]
        for k in expected_keys:
            self.assertIn(k, result, f"End-to-end result must include key '{k}'")


if __name__ == "__main__":
    unittest.main()
