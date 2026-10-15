"""
Unit tests for Phase 3A (Red Team), Phase 4A (Blue Team), and Phase 5A (Security Retest).
"""

import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.phase0.ingestion import RepositoryIngestionAgent, SecurityError
from src.phase1.reconstruction import ProjectReconstructionAgent
from src.phase2.requirements import RequirementsEngineeringAgent
from src.phase2.assessment import SecurityAssessmentAgent
from src.phase3a.red_team import RedTeamSecurityAgent
from src.phase4a.blue_team import BlueTeamDefensiveAgent
from src.phase5a.retest import SecurityRetestAgent
from src.phase6.code_smells import CodeSmellAnalysisAgent
from src.phase7.cross_domain import CrossDomainAnalysisAgent
from src.phase8.recommendations import RecommendationEngineAgent
from pipeline import run_pipeline


class TestRedBlueRetestPipeline(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_phases_3_4_5_")
        self._setup_mock_project(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _setup_mock_project(self, base_dir: str):
        src_dir = os.path.join(base_dir, "app")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write(
                "import os\n"
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/api/health')\n"
                "def health():\n"
                "    return {'status': 'ok'}\n"
                "if __name__ == '__main__':\n"
                "    import uvicorn\n"
                "    uvicorn.run(app)\n"
            )

        with open(os.path.join(base_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("fastapi==0.100.0\nuvicorn==0.23.0\n")

        with open(os.path.join(base_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Health Microservice\nExposes application health endpoints.\n")

    def test_git_option_injection_rejected(self):
        agent0 = RepositoryIngestionAgent()
        with self.assertRaises(SecurityError):
            agent0.obtain_repository("github", "--upload-pack=evil")

        with self.assertRaises(SecurityError):
            agent0.obtain_repository("github", "-u evil.git")

    def test_phase3a_red_team_schema_and_execution(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        agent2_req = RequirementsEngineeringAgent(root_path=self.test_dir, phase0_inventory=p0, phase1_reconstruction=p1)
        p2_reqs = agent2_req.extract_requirements()

        agent3a = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory=p0,
            phase1_reconstruction=p1,
            phase2_requirements=p2_reqs
        )
        p3a = agent3a.analyze()

        self.assertIn("attack_surface_map", p3a)
        self.assertIn("findings", p3a)
        self.assertIn("summary", p3a)

        # Verify exact Red Team finding schema keys
        required_rt_keys = [
            "finding_id", "category", "title", "severity", "confidence",
            "affected_files", "affected_functions", "attack_surface",
            "attacker_controlled_input", "security_boundary", "evidence",
            "attack_path", "impact", "validation_status", "requirement_affected",
            "false_positive_reason_if_applicable"
        ]
        valid_statuses = {"CONFIRMED", "PROBABLE", "POSSIBLE", "FALSE_POSITIVE", "INSUFFICIENT_EVIDENCE"}

        for finding in p3a["findings"]:
            for k in required_rt_keys:
                self.assertIn(k, finding, f"Phase 3A finding missing key '{k}'")
            self.assertIn(finding["validation_status"], valid_statuses)

    def test_phase4a_blue_team_schema_and_execution(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        agent2_req = RequirementsEngineeringAgent(root_path=self.test_dir, phase0_inventory=p0, phase1_reconstruction=p1)
        p2_reqs = agent2_req.extract_requirements()

        agent3a = RedTeamSecurityAgent(root_path=self.test_dir, phase0_inventory=p0, phase1_reconstruction=p1, phase2_requirements=p2_reqs)
        p3a = agent3a.analyze()

        agent4a = BlueTeamDefensiveAgent(
            root_path=self.test_dir,
            phase1_reconstruction=p1,
            phase2_requirements=p2_reqs,
            phase3a_findings=p3a["findings"]
        )
        p4a = agent4a.analyze()

        self.assertIn("remediation_plans", p4a)
        self.assertIn("total_plans", p4a)

        required_bt_keys = [
            "finding_id", "root_cause", "remediation", "recommended_changes",
            "security_controls", "hardening_measures", "affected_files",
            "regression_risks", "testing_requirements", "expected_result_after_fix", "confidence"
        ]
        for plan in p4a["remediation_plans"]:
            for k in required_bt_keys:
                self.assertIn(k, plan, f"Phase 4A remediation plan missing key '{k}'")

    def test_phase5a_retest_schema_and_execution(self):
        agent0 = RepositoryIngestionAgent()
        p0 = agent0.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        agent1 = ProjectReconstructionAgent(root_path=self.test_dir, phase0_inventory=p0)
        p1 = agent1.reconstruct()

        agent2_req = RequirementsEngineeringAgent(root_path=self.test_dir, phase0_inventory=p0, phase1_reconstruction=p1)
        p2_reqs = agent2_req.extract_requirements()

        agent3a = RedTeamSecurityAgent(root_path=self.test_dir, phase0_inventory=p0, phase1_reconstruction=p1, phase2_requirements=p2_reqs)
        p3a = agent3a.analyze()

        agent4a = BlueTeamDefensiveAgent(root_path=self.test_dir, phase1_reconstruction=p1, phase2_requirements=p2_reqs, phase3a_findings=p3a["findings"])
        p4a = agent4a.analyze()

        agent5a = SecurityRetestAgent(
            root_path=self.test_dir,
            phase3a_findings=p3a["findings"],
            phase4a_remediations=p4a["remediation_plans"]
        )
        p5a = agent5a.retest()

        self.assertIn("retest_results", p5a)
        self.assertIn("summary", p5a)

        required_retest_keys = [
            "finding_id", "original_issue", "original_attack_path",
            "remediation_tested", "result", "remaining_risk",
            "regression_detected", "final_status", "evidence", "confidence"
        ]
        valid_retest_statuses = {"REMEDIATED", "PARTIALLY_REMEDIATED", "NOT_REMEDIATED", "NOT_TESTABLE", "FALSE_POSITIVE"}

        for r in p5a["retest_results"]:
            for k in required_retest_keys:
                self.assertIn(k, r, f"Phase 5A retest result missing key '{k}'")
            self.assertIn(r["final_status"], valid_retest_statuses)

    def test_phase6_code_smells_schema_and_execution(self):
        agent6 = CodeSmellAnalysisAgent(root_path=self.test_dir)
        p6 = agent6.analyze()

        self.assertIn("code_smells", p6)
        self.assertIn("summary", p6)

        required_smell_keys = [
            "smell_id", "category", "file", "function_or_class",
            "evidence", "explanation", "severity", "classification",
            "maintenance_impact", "refactoring_strategy", "expected_benefit"
        ]
        valid_classifications = {"JUSTIFIED", "POTENTIALLY_EXCESSIVE", "PROBLEMATIC", "UNKNOWN"}

        for s in p6["code_smells"]:
            for k in required_smell_keys:
                self.assertIn(k, s, f"Phase 6 code smell missing key '{k}'")
            self.assertIn(s["classification"], valid_classifications)

    def test_phase7_cross_domain_schema_and_execution(self):
        agent7 = CrossDomainAnalysisAgent(
            phase2_requirements=[{"requirement_id": "REQ-NFR-02", "description": "zero dependencies"}],
            phase6_smells=[
                {"smell_id": "SMELL-SILENT-EXCEPTION", "category": "Poor Exception Handling"},
                {"smell_id": "SMELL-LONG-METHOD-INVENTORY", "category": "Long Method"},
                {"smell_id": "SMELL-PRIMITIVE-OBSESSION-CONTRACTS", "category": "Inappropriate Abstractions"},
                {"smell_id": "SMELL-DUPLICATE-CLI-LOGIC", "category": "Duplicate Code"}
            ]
        )
        p7 = agent7.analyze()

        self.assertIn("cross_domain_relationships", p7)
        self.assertIn("total_relationships", p7)
        self.assertGreater(p7["total_relationships"], 0)

        required_rel_keys = [
            "relationship_id", "domain_a", "finding_a", "domain_b",
            "finding_b", "relationship", "evidence", "consequence",
            "priority", "recommended_action"
        ]
        for rel in p7["cross_domain_relationships"]:
            for k in required_rel_keys:
                self.assertIn(k, rel, f"Phase 7 relationship missing key '{k}'")

    def test_phase8_recommendations_schema_and_execution(self):
        agent8 = RecommendationEngineAgent()
        p8 = agent8.generate_recommendations()

        self.assertIn("recommendations", p8)
        self.assertIn("total_recommendations", p8)
        self.assertGreater(p8["total_recommendations"], 0)

        required_rec_keys = [
            "recommendation_id", "problem", "evidence", "requirement_affected",
            "current_implementation", "recommended_change", "technical_reasoning",
            "alternatives", "trade_offs", "implementation_complexity",
            "security_impact", "maintainability_impact", "cost_considerations",
            "dependencies", "priority", "confidence"
        ]
        valid_priorities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

        for r in p8["recommendations"]:
            for k in required_rec_keys:
                self.assertIn(k, r, f"Phase 8 recommendation missing key '{k}'")
            self.assertIn(r["priority"], valid_priorities)

    def test_pipeline_e2e_all_phases(self):
        result = run_pipeline(source=self.test_dir, source_type="dir", phase="all")
        self.assertIn("phase0_inventory", result)
        self.assertIn("phase1_reconstruction", result)
        self.assertIn("phase2_requirements", result)
        self.assertIn("phase2_security_assessment", result)
        self.assertIn("phase3a_red_team", result)
        self.assertIn("phase4a_blue_team", result)
        self.assertIn("phase5a_security_retest", result)
        self.assertIn("phase6_code_smells", result)
        self.assertIn("phase7_cross_domain", result)
        self.assertIn("phase8_recommendations", result)
        self.assertIn("phase9_final_report", result)
        self.assertIn("phase9_markdown_report", result)

    def test_pipeline_individual_phases(self):
        p3 = run_pipeline(source=self.test_dir, source_type="dir", phase="3a")
        self.assertIn("attack_surface_map", p3)
        self.assertIn("findings", p3)

        p4 = run_pipeline(source=self.test_dir, source_type="dir", phase="4a")
        self.assertIn("remediation_plans", p4)

        p5 = run_pipeline(source=self.test_dir, source_type="dir", phase="5a")
        self.assertIn("retest_results", p5)

        p6 = run_pipeline(source=self.test_dir, source_type="dir", phase="6")
        self.assertIn("code_smells", p6)

        p7 = run_pipeline(source=self.test_dir, source_type="dir", phase="7")
        self.assertIn("cross_domain_relationships", p7)

        p8 = run_pipeline(source=self.test_dir, source_type="dir", phase="8")
        self.assertIn("recommendations", p8)

        p9 = run_pipeline(source=self.test_dir, source_type="dir", phase="9")
        self.assertIn("report_data", p9)
        self.assertIn("markdown_report", p9)
        self.assertIn("# PHASE 9 — FINAL SOFTWARE ARCHITECTURE AND SECURITY REPORT", p9["markdown_report"])
        self.assertIn("## 10. REQUIREMENT ↔ IMPLEMENTATION MATRIX", p9["markdown_report"])


if __name__ == "__main__":
    unittest.main()

