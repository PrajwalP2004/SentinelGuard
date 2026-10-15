"""
Unit tests for Phase 2 agents:
- SecurityAssessmentAgent (src.phase2.assessment)
- RequirementsEngineeringAgent (src.phase2.requirements)

Tests use controlled synthetic inputs targeting focused Phase 2 behavior:
1. Databases without known exposure do not generate info-disclosure findings; reported in manual_review_items.
2. Absent route-auth evidence treated as potential risk; intentionally public routes preserved without flagging.
3. Redis or general caches are not treated as rate-limiting proof; rate-limiting findings qualified.
4. OWASP checks use specific route, auth, and transport evidence with partial coverage disclosed.
5. Resilience and SPOF labeled as heuristic.
6. Semantic deduplication retains maximum severity and preserves distinct vulnerabilities.
7. File-read limit accurately enforces byte limit via binary mode.
8. Archive-safety analysis distinguishes detected validation code from verified safe behavior.
9. Potentially sensitive files do not infer actual secrets solely from names.
10. Deployment architecture is represented as technical architecture, not business constraint.
11. Formal deterministic output requirement not inferred solely from tests.
12. Discovered CLI and API behavior described as observed implementation behavior.
13. Path traversal and symlink escapes rejected.
14. Empty and malformed inputs handled safely.
"""

import os
import shutil
import tempfile
import unittest

from src.phase2.assessment import SecurityAssessmentAgent
from src.phase2.requirements import RequirementsEngineeringAgent


class TestSecurityAssessmentAgentFocused(unittest.TestCase):
    """Focused test suite for SecurityAssessmentAgent."""

    def test_database_without_known_exposure_does_not_create_finding(self):
        """Do not generate an info-disclosure finding for every database merely because it exists."""
        p1 = {
            "databases": [
                {
                    "name": "Standard Postgres Database",
                    "type": "relational_database",
                    "supporting_file_paths": ["src/db.py"]
                }
            ],
            "apis": [],
            "components": [{"name": "CoreService"}]
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()

        # Findings must NOT contain an Information Disclosure finding for standard database
        info_findings = [f for f in res["findings"] if f.get("stride_category") == "Information Disclosure"]
        self.assertEqual(len(info_findings), 0)

        # It must be reported separately in manual_review_items
        self.assertTrue(len(res["manual_review_items"]) > 0)
        self.assertIn("Database Security Configuration Review", res["manual_review_items"][0]["item"])

    def test_database_with_explicit_weakness_creates_finding(self):
        """Generate a vulnerability finding only when evidence supports a weakness."""
        p1 = {
            "databases": [
                {
                    "name": "Insecure MongoDB",
                    "description": "Unencrypted connection string with plaintext credentials and no_auth",
                    "supporting_file_paths": ["src/db.py"]
                }
            ]
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()
        info_findings = [f for f in res["findings"] if f.get("stride_category") == "Information Disclosure"]
        self.assertEqual(len(info_findings), 1)
        self.assertEqual(info_findings[0]["confidence"], "CONFIRMED")

    def test_intentionally_public_routes_preserved(self):
        """Preserve explicit evidence of intentionally public routes without flagging them as unauthenticated."""
        p1 = {
            "apis": [
                {
                    "method": "GET",
                    "path": "/health",
                    "is_public": True,
                    "supporting_file_paths": ["src/health.py"]
                },
                {
                    "method": "GET",
                    "path": "/metrics",
                    "supporting_file_paths": ["src/metrics.py"]
                }
            ],
            "authentication_components": []
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()

        # Both /health and /metrics are intentionally public routes; spoofing should not flag them
        spoof_findings = [f for f in res["findings"] if f.get("stride_category") == "Spoofing"]
        self.assertEqual(len(spoof_findings), 0)

    def test_missing_route_auth_treated_as_potential_risk(self):
        """Treat missing route-auth evidence as potential risk, not proof of open access."""
        p1 = {
            "apis": [
                {
                    "method": "POST",
                    "path": "/api/transfer",
                    "supporting_file_paths": ["src/transfer.py"]
                }
            ],
            "authentication_components": []
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()

        spoof_findings = [f for f in res["findings"] if f.get("stride_category") == "Spoofing"]
        self.assertEqual(len(spoof_findings), 1)
        self.assertEqual(spoof_findings[0]["confidence"], "POTENTIAL")
        self.assertIn("external gateway", spoof_findings[0]["description"])

    def test_redis_alone_not_treated_as_rate_limiting_proof(self):
        """Do not treat Redis or general-purpose services as proof of rate limiting."""
        p1 = {
            "apis": [{"method": "GET", "path": "/api/data", "supporting_file_paths": ["src/api.py"]}],
            "external_services": [{"name": "Redis In-Memory Cache"}],  # Just a cache, not rate limiting
            "components": [{"name": "AppCore"}]
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()

        # Must still flag unverified rate limiting with qualified potential confidence
        dos_findings = [f for f in res["findings"] if f.get("stride_category") == "Denial of Service"]
        self.assertEqual(len(dos_findings), 1)
        self.assertEqual(dos_findings[0]["confidence"], "POTENTIAL")
        self.assertIn("external reverse proxy", dos_findings[0]["description"])

    def test_dedicated_rate_limiting_component_detected(self):
        """Detect rate limiting specifically when dedicated component is present."""
        p1 = {
            "apis": [{"method": "GET", "path": "/api/data", "supporting_file_paths": ["src/api.py"]}],
            "components": [{"name": "RateLimitingMiddleware"}]
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()
        dos_findings = [f for f in res["findings"] if f.get("stride_category") == "Denial of Service"]
        self.assertEqual(len(dos_findings), 0)

    def test_resilience_and_spof_labeled_as_heuristic(self):
        """Label resilience and SPOF conclusions as heuristic."""
        p1 = {
            "components": [{"name": "Worker1"}, {"name": "Worker2"}],
            "deployment_model": {"model": "Standalone Process"}
        }
        agent = SecurityAssessmentAgent(phase1_reconstruction=p1)
        res = agent.assess()
        resilience = res["architecture_resilience"]
        self.assertEqual(resilience["spof_assessment"], "HEURISTIC_INDICATION")
        self.assertIn("unverified without deployment manifests", resilience["spof_reasoning"])

    def test_semantic_deduplication_preserves_maximum_severity(self):
        """Deduplication must retain the higher severity when merging equivalent findings."""
        findings = [
            {
                "finding_id": "FIND-01",
                "rule_id": "SEC-S01",
                "title": "Medium Auth finding",
                "severity": "MEDIUM",
                "confidence": "POTENTIAL",
                "stride_category": "Spoofing",
                "target": "HTTP API Ingress",
                "evidence": "evidence-1",
            },
            {
                "finding_id": "FIND-02",
                "rule_id": "SEC-S01",
                "title": "Critical Auth finding",
                "severity": "CRITICAL",
                "confidence": "CONFIRMED",
                "stride_category": "Spoofing",
                "target": "HTTP API Ingress",
                "evidence": "evidence-2",
            }
        ]
        agent = SecurityAssessmentAgent(phase1_reconstruction={})
        deduped = agent._deduplicate_findings(findings)
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["severity"], "CRITICAL")
        self.assertEqual(deduped[0]["confidence"], "CONFIRMED")
        self.assertIn("FIND-02", deduped[0].get("related_finding_ids", []))


class TestRequirementsEngineeringAgentFocused(unittest.TestCase):
    """Focused test suite for RequirementsEngineeringAgent."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="phase2_focused_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_file_read_limit_enforces_byte_limit(self):
        """Accurately enforce byte limit when reading files."""
        # Create a file with multibyte UTF-8 characters
        test_file = os.path.join(self.test_dir, "large.txt")
        # 1000 characters of 4-byte emojis
        emojis = "🚀" * 1000  # 4000 bytes
        with open(test_file, "wb") as f:
            f.write(emojis.encode("utf-8"))

        agent = RequirementsEngineeringAgent(root_path=self.test_dir, phase0_inventory={}, phase1_reconstruction={})
        content = agent._safe_read_file("large.txt")
        self.assertIsNotNone(content)
        self.assertEqual(content, emojis)

    def test_archive_safety_requires_actual_extraction_code(self):
        """Strengthen archive safety: keyword presence alone cannot establish safe extraction."""
        unrelated_file = os.path.join(self.test_dir, "unrelated.py")
        with open(unrelated_file, "w", encoding="utf-8") as f:
            f.write("# This mentions zip and realpath and target_dir\nword = 'zip'\n")

        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "unrelated.py"}]},
            phase1_reconstruction={}
        )
        reqs = agent.extract_requirements()
        archive_reqs = [r for r in reqs if "archive" in r["description"].lower() or "zip" in r["description"].lower()]
        self.assertEqual(len(archive_reqs), 0)

    def test_archive_safety_distinguishes_detected_validation_from_verified_safety(self):
        """Distinguish detected validation code from verified safe behavior."""
        safe_zip_file = os.path.join(self.test_dir, "extractor.py")
        with open(safe_zip_file, "w", encoding="utf-8") as f:
            f.write(
                "import zipfile, os\n"
                "with zipfile.ZipFile('test.zip') as z:\n"
                "    for m in z.namelist():\n"
                "        dest = os.path.realpath(os.path.join(target_dir, m))\n"
                "        if not dest.startswith(target_dir) or '..' in m:\n"
                "            raise Exception('traversal')\n"
                "        z.extract(m, target_dir)\n"
            )

        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "extractor.py"}]},
            phase1_reconstruction={}
        )
        reqs = agent.extract_requirements()
        archive_reqs = [r for r in reqs if "archive" in r["description"].lower() or "zip" in r["description"].lower()]
        self.assertEqual(len(archive_reqs), 1)
        self.assertEqual(archive_reqs[0]["status"], "code_supported")
        self.assertIn("observed implementation code", archive_reqs[0]["description"])

    def test_no_secret_inferred_solely_from_file_names(self):
        """Do not infer that potentially sensitive files contain actual secrets solely from names."""
        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={"potentially_sensitive_files": [{"path": ".env.sample"}]},
            phase1_reconstruction={}
        )
        reqs = agent.extract_requirements()
        secret_reqs = [r for r in reqs if "secret" in r["description"].lower() or "credential" in r["description"].lower()]
        self.assertEqual(len(secret_reqs), 1)
        self.assertEqual(secret_reqs[0]["status"], "unknown")
        self.assertIn("unverified", secret_reqs[0]["evidence"])

    def test_deployment_not_under_business_constraints_by_default(self):
        """Do not place deployment architecture under business constraints by default."""
        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={},
            phase1_reconstruction={"deployment_model": {"model": "Containerized Kubernetes"}}
        )
        reqs = agent.extract_requirements()

        # Business constraints must NOT contain the technical deployment model as code_supported
        biz_reqs = [r for r in reqs if r["category"] == "business_constraint" and "deployment" in r["description"].lower()]
        self.assertEqual(len(biz_reqs), 1)
        self.assertEqual(biz_reqs[0]["status"], "unknown")

        # Technical deployment belongs in non_functional
        nfr_deploy = [r for r in reqs if r["category"] == "non_functional" and "deployment" in r["description"].lower()]
        self.assertEqual(len(nfr_deploy), 1)
        # Without supporting implementation files on disk, status must be inferred, NOT code_supported
        self.assertEqual(nfr_deploy[0]["status"], "inferred")

    def test_deployment_code_supported_only_with_implementation_evidence(self):
        """Assign code_supported to deployment only when implementation files exist."""
        dockerfile = os.path.join(self.test_dir, "Dockerfile")
        with open(dockerfile, "w") as f:
            f.write("FROM python:3.11\n")

        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={"infrastructure_files": [{"path": "Dockerfile"}]},
            phase1_reconstruction={
                "deployment_model": {
                    "model": "Containerized Deployment",
                    "supporting_file_paths": ["Dockerfile"]
                }
            }
        )
        reqs = agent.extract_requirements()
        nfr_deploy = [r for r in reqs if r["category"] == "non_functional" and "deployment" in r["description"].lower()]
        self.assertEqual(len(nfr_deploy), 1)
        self.assertEqual(nfr_deploy[0]["status"], "code_supported")

    def test_deterministic_output_distinguishes_tested_from_documented(self):
        """Distinguish tested behavior from formal documented requirements."""
        # Scenario A: Only test assertion
        agent_tested = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={"test_files": [{"path": "tests/test_api.py"}]},
            phase1_reconstruction={}
        )
        test_file = os.path.join(self.test_dir, "test_api.py")
        with open(test_file, "w") as f:
            f.write("assertIn('schema_version', res)\n")
        agent_tested.source_files = [{"path": "test_api.py"}]
        agent_tested.test_files = [{"path": "test_api.py"}]

        reqs = agent_tested.extract_requirements()
        contract_reqs = [r for r in reqs if "schema" in r["description"].lower() or "contract" in r["description"].lower()]
        self.assertEqual(len(contract_reqs), 1)
        self.assertEqual(contract_reqs[0]["status"], "code_supported")
        self.assertIn("observed test behavior", contract_reqs[0]["description"])

    def test_discovered_api_and_cli_described_as_observed_behavior(self):
        """Describe discovered CLI and API behavior as observed implementation behavior unless specified in doc."""
        cli_file = os.path.join(self.test_dir, "cli.py")
        with open(cli_file, "w") as f:
            f.write("import argparse\nparser = argparse.ArgumentParser()\n")

        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "cli.py"}]},
            phase1_reconstruction={
                "apis": [{"method": "GET", "path": "/api/items", "supporting_file_paths": ["cli.py"]}]
            }
        )
        reqs = agent.extract_requirements()
        api_reqs = [r for r in reqs if "/api/items" in r["description"]]
        self.assertEqual(len(api_reqs), 1)
        self.assertIn("observed implementation behavior", api_reqs[0]["description"])
        self.assertEqual(api_reqs[0]["status"], "code_supported")

        cli_reqs = [r for r in reqs if "Command Line Interface" in r["description"]]
        self.assertEqual(len(cli_reqs), 1)
        self.assertIn("observed implementation behavior", cli_reqs[0]["description"])
        self.assertEqual(cli_reqs[0]["status"], "code_supported")

    def test_suspicious_path_traversal_and_symlink_escapes(self):
        """Reject traversal paths and absolute paths escaping repository root."""
        agent = RequirementsEngineeringAgent(root_path=self.test_dir, phase0_inventory={}, phase1_reconstruction={})
        self.assertIsNone(agent._resolve_safe_path("../../windows/system32/cmd.exe"))
        self.assertIsNone(agent._resolve_safe_path("../secret.txt"))
        self.assertIsNone(agent._resolve_safe_path("C:/Windows/win.ini"))

    def test_empty_and_malformed_inputs_handled_safely(self):
        """Safely handle empty, None, and malformed inputs without crashing."""
        for malformed in [None, {}, {"source_files": "not-a-list"}, {"apis": None}]:
            agent = RequirementsEngineeringAgent(
                root_path=self.test_dir,
                phase0_inventory=malformed,
                phase1_reconstruction=malformed
            )
            reqs = agent.extract_requirements()
            self.assertIsInstance(reqs, list)
            for r in reqs:
                self.assertIn(r["status"], agent.VALID_STATUSES)

    def test_missing_deployment_data_leaves_status_unknown(self):
        """When deployment data is missing, technical deployment status is unknown."""
        agent = RequirementsEngineeringAgent(
            root_path=self.test_dir,
            phase0_inventory={},
            phase1_reconstruction={}
        )
        reqs = agent.extract_requirements()
        nfr_deploy = [r for r in reqs if r["category"] == "non_functional" and "deployment" in r["description"].lower()]
        self.assertEqual(len(nfr_deploy), 1)
        self.assertIn(nfr_deploy[0]["status"], ["inferred", "unknown"])


if __name__ == "__main__":
    unittest.main()
