"""
Unit tests for Phase 0: Repository Ingestion Agent.
"""

import os
import sys
import json
import shutil
import zipfile
import tempfile
import io
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.phase0.ingestion import RepositoryIngestionAgent, SecurityError
from ingest import (
    main as ingest_main,
    cleanup_temp_dir as ingest_cleanup_temp_dir,
    safe_write_output as ingest_safe_write_output,
    infer_source_type as ingest_infer_source_type,
    is_supported_github_url as ingest_is_supported_github_url,
)


class TestRepositoryIngestionAgent(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_repo_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_repo(self, base_dir: str):
        # 1. Source files & Entry point
        src_dir = os.path.join(base_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("if __name__ == '__main__':\n    print('Hello World')\n")
        with open(os.path.join(src_dir, "service.py"), "w", encoding="utf-8") as f:
            f.write("class UserService:\n    pass\n")

        # 2. Dependency manifest
        with open(os.path.join(base_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("fastapi==0.100.0\nuvicorn==0.23.0\nredis==5.0.0\n")

        # 3. Test files
        tests_dir = os.path.join(base_dir, "tests")
        os.makedirs(tests_dir, exist_ok=True)
        with open(os.path.join(tests_dir, "test_main.py"), "w", encoding="utf-8") as f:
            f.write("def test_dummy():\n    assert True\n")

        # 4. Documentation
        with open(os.path.join(base_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Sample Project\nDocumentation here.\n")

        # 5. Database file
        db_dir = os.path.join(base_dir, "db")
        os.makedirs(db_dir, exist_ok=True)
        with open(os.path.join(db_dir, "schema.sql"), "w", encoding="utf-8") as f:
            f.write("CREATE TABLE users (id SERIAL PRIMARY KEY, name VARCHAR(255));\n")

        # 6. Infrastructure file
        with open(os.path.join(base_dir, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write("FROM python:3.11-slim\nCMD ['python', 'src/main.py']\n")

        # 7. CI/CD file
        ci_dir = os.path.join(base_dir, ".github", "workflows")
        os.makedirs(ci_dir, exist_ok=True)
        with open(os.path.join(ci_dir, "ci.yml"), "w", encoding="utf-8") as f:
            f.write("name: CI\non: [push]\n")

        # 8. Potentially sensitive file
        with open(os.path.join(base_dir, ".env.example"), "w", encoding="utf-8") as f:
            f.write("DATABASE_URL=postgres://localhost:5432/db\n")

        # 9. Excluded vendor / cache content
        cache_dir = os.path.join(base_dir, "__pycache__")
        os.makedirs(cache_dir, exist_ok=True)
        with open(os.path.join(cache_dir, "temp.pyc"), "w", encoding="utf-8") as f:
            f.write("fake pyc content")

    def test_local_directory_ingestion(self):
        self._create_mock_repo(self.test_dir)
        agent = RepositoryIngestionAgent()
        result = agent.inventory(self.test_dir, metadata={"source_type": "dir", "source": self.test_dir})

        # Required Top-Level Fields Verification
        required_fields = [
            "repository", "languages", "frameworks", "file_inventory",
            "source_files", "configuration_files", "dependency_files",
            "database_files", "infrastructure_files", "test_files",
            "documentation_files", "ci_cd_files", "generated_files",
            "potentially_sensitive_files", "entry_point_candidates",
            "external_services", "unknowns"
        ]
        for field in required_fields:
            self.assertIn(field, result, f"Field '{field}' must be present in output.")

        # Languages & Frameworks
        self.assertIn("Python", result["languages"])
        self.assertIn("FastAPI", result["frameworks"])

        # Dependencies
        dep_paths = [d["path"] for d in result["dependency_files"]]
        self.assertIn("requirements.txt", dep_paths)

        # External services detected in requirements.txt
        services = [s["name"] for s in result["external_services"]]
        self.assertTrue(any("Redis" in s for s in services))

        # Entry point candidate
        entry_paths = [e["path"] for e in result["entry_point_candidates"]]
        self.assertIn("src/main.py", entry_paths)

        # Database schema
        db_paths = [d["path"] for d in result["database_files"]]
        self.assertIn("db/schema.sql", db_paths)

        # Infrastructure
        infra_paths = [i["path"] for i in result["infrastructure_files"]]
        self.assertIn("Dockerfile", infra_paths)

        # Excluded directory in generated_files
        self.assertTrue(any("__pycache__" in g for g in result["generated_files"]))

        # CI/CD Files (verifying .github/workflows inclusion)
        ci_paths = [c["path"] for c in result["ci_cd_files"]]
        self.assertTrue(any(".github/workflows" in c for c in ci_paths), "CI/CD workflows in .github/workflows must be inventoried.")

        # Structure of important files
        for src in result["source_files"]:
            self.assertIn("path", src)
            self.assertIn("type", src)
            self.assertIn("language", src)
            self.assertIn("purpose", src)
            self.assertTrue(src["is_application_code"])
            self.assertIn(src["importance"], ["high", "medium", "low"])

    def test_zip_archive_ingestion(self):
        # Create mock repo and zip it
        mock_source = tempfile.mkdtemp(prefix="mock_src_")
        self._create_mock_repo(mock_source)

        zip_path = os.path.join(self.test_dir, "project.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(mock_source):
                for file in files:
                    full = os.path.join(root, file)
                    rel = os.path.relpath(full, mock_source)
                    z.write(full, rel)
        shutil.rmtree(mock_source, ignore_errors=True)

        agent = RepositoryIngestionAgent()
        extracted_path, is_temp = agent.obtain_repository("zip", zip_path)
        self.assertTrue(is_temp)
        self.assertTrue(os.path.exists(extracted_path))

        result = agent.inventory(extracted_path, metadata={"source_type": "zip", "source": zip_path})
        self.assertIn("src/main.py", result["file_inventory"])
        self.assertIn("FastAPI", result["frameworks"])

        shutil.rmtree(extracted_path, ignore_errors=True)

    def test_zip_slip_prevention(self):
        zip_path = os.path.join(self.test_dir, "malicious.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("../evil.txt", "malicious content")

        agent = RepositoryIngestionAgent()
        with self.assertRaises(SecurityError):
            agent.obtain_repository("zip", zip_path)

    def test_zip_absolute_path_and_drive_escape_prevention(self):
        agent = RepositoryIngestionAgent()

        # Leading slash absolute path
        abs_zip = os.path.join(self.test_dir, "malicious_abs.zip")
        with zipfile.ZipFile(abs_zip, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("/etc/passwd", "root:x:0:0")
        with self.assertRaises(SecurityError):
            agent.obtain_repository("zip", abs_zip)

        # Windows drive letter escape
        drive_zip = os.path.join(self.test_dir, "malicious_drive.zip")
        with zipfile.ZipFile(drive_zip, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("C:/Windows/system.ini", "[fonts]")
        with self.assertRaises(SecurityError):
            agent.obtain_repository("zip", drive_zip)

    def test_technology_detection_no_false_positives(self):
        # Python requirements with comments or substrings like 'next' or 'reaction'
        repo_dir = os.path.join(self.test_dir, "clean_py_repo")
        os.makedirs(repo_dir, exist_ok=True)
        with open(os.path.join(repo_dir, "requirements.txt"), "w", encoding="utf-8") as f:
            f.write("# what to do next\nrequests==2.31.0\npytest==7.4.0\n")

        agent = RepositoryIngestionAgent()
        result = agent.inventory(repo_dir, metadata={"source_type": "dir", "source": repo_dir})
        self.assertNotIn("Next.js", result["frameworks"], "Python requirements must not falsely trigger Next.js framework.")
        self.assertNotIn("React", result["frameworks"])

    def test_invalid_inputs_and_nonexistent_paths(self):
        agent = RepositoryIngestionAgent()
        with self.assertRaises(ValueError):
            agent.obtain_repository("dir", "")

        with self.assertRaises(FileNotFoundError):
            agent.obtain_repository("dir", os.path.join(self.test_dir, "nonexistent_dir_12345"))

        with self.assertRaises(FileNotFoundError):
            agent.inventory(os.path.join(self.test_dir, "nonexistent_dir_12345"))

    def test_github_url_validation_and_rejection(self):
        agent = RepositoryIngestionAgent()

        # Deceptive hostnames (subdomain spoofing)
        with self.assertRaises(ValueError):
            agent._validate_and_normalize_github_url("https://github.com.evil.com/owner/repo")

        # Unsupported scheme
        with self.assertRaises(ValueError):
            agent._validate_and_normalize_github_url("http://github.com/owner/repo")

        # Embedded credentials
        with self.assertRaises(SecurityError):
            agent._validate_and_normalize_github_url("https://user:pass@github.com/owner/repo")

        # Profile-only URLs (must not silently select a repo)
        with self.assertRaises(ValueError):
            agent._validate_and_normalize_github_url("https://github.com/PrajwalP2004")

        # Bare usernames
        with self.assertRaises(ValueError):
            agent._validate_and_normalize_github_url("PrajwalP2004")

        # Valid formats
        self.assertEqual(
            agent._validate_and_normalize_github_url("https://github.com/org/service.git"),
            "https://github.com/org/service"
        )
        self.assertEqual(
            agent._validate_and_normalize_github_url("git@github.com:org/service.git"),
            "https://github.com/org/service"
        )
        self.assertEqual(
            agent._validate_and_normalize_github_url("org/service"),
            "https://github.com/org/service"
        )

    def test_zip_malformed_and_unc_paths(self):
        agent = RepositoryIngestionAgent()

        # Malformed archive
        bad_zip = os.path.join(self.test_dir, "corrupt.zip")
        with open(bad_zip, "w") as f:
            f.write("not a real zip file header")
        with self.assertRaises(RuntimeError):
            agent.obtain_repository("zip", bad_zip)

        # UNC Path attempt
        unc_zip = os.path.join(self.test_dir, "unc.zip")
        with zipfile.ZipFile(unc_zip, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("//server/share/file.txt", "data")
        with self.assertRaises(SecurityError):
            agent.obtain_repository("zip", unc_zip)

        # Duplicate member paths extracted safely
        dup_zip = os.path.join(self.test_dir, "dup.zip")
        with zipfile.ZipFile(dup_zip, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("module/utils.py", "# first version")
            z.writestr("module/utils.py", "# second version")
        target_path, is_temp = agent.obtain_repository("zip", dup_zip)
        self.assertTrue(os.path.exists(os.path.join(target_path, "module", "utils.py")))
        shutil.rmtree(target_path, ignore_errors=True)

    def test_language_reconciliation_kotlin_swift_scala(self):
        poly_dir = os.path.join(self.test_dir, "polyglot_repo")
        os.makedirs(poly_dir, exist_ok=True)

        with open(os.path.join(poly_dir, "Main.kt"), "w", encoding="utf-8") as f:
            f.write("fun main(args: Array<String>) { println(\"Kotlin\") }\n")
        with open(os.path.join(poly_dir, "main.swift"), "w", encoding="utf-8") as f:
            f.write("@main struct App { static func main() {} }\n")
        with open(os.path.join(poly_dir, "Main.scala"), "w", encoding="utf-8") as f:
            f.write("object Main { def main(args: Array[String]): Unit = {} }\n")
        with open(os.path.join(poly_dir, "data.unknownext"), "w", encoding="utf-8") as f:
            f.write("opaque binary data\n")

        agent = RepositoryIngestionAgent()
        result = agent.inventory(poly_dir, metadata={"source_type": "dir", "source": poly_dir})

        # All languages must be detected and reconciled into source_files
        self.assertIn("Kotlin", result["languages"])
        self.assertIn("Swift", result["languages"])
        self.assertIn("Scala", result["languages"])

        src_langs = [s["language"] for s in result["source_files"]]
        self.assertIn("Kotlin", src_langs)
        self.assertIn("Swift", src_langs)
        self.assertIn("Scala", src_langs)

        # Entry points detected for polyglot files
        entry_paths = [e["path"] for e in result["entry_point_candidates"]]
        self.assertIn("Main.kt", entry_paths)
        self.assertIn("main.swift", entry_paths)
        self.assertIn("Main.scala", entry_paths)

        # Unknown extension classified into unknowns and unsupported_files
        unknown_paths = [u["path"] for u in result["unknowns"]]
        self.assertIn("data.unknownext", unknown_paths)
        unsupported_paths = [u["path"] for u in result["unsupported_files"]]
        self.assertIn("data.unknownext", unsupported_paths)

        # Output schema fields
        self.assertEqual(result["schema_version"], "1.0.0")
        self.assertEqual(result["ingestion_status"], "COMPLETE")
        self.assertIn("supported_languages", result)
        self.assertIn("Kotlin", result["supported_languages"])


class TestIngestCliCleanup(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_ingest_cleanup_")
        # Populate dummy project files
        src_dir = os.path.join(self.test_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("print('hello')\n")
        with open(os.path.join(self.test_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Ingest Cleanup Test\n")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cleanup_after_success(self):
        """Temporary repository must be deleted after successful ingestion run."""
        fake_temp = tempfile.mkdtemp(prefix="fake_temp_ingest_")
        shutil.copytree(self.test_dir, fake_temp, dirs_exist_ok=True)
        self.assertTrue(os.path.exists(fake_temp))

        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch("sys.stdout", new_callable=io.StringIO):
            ingest_main(["--source", "https://github.com/mock/repo.git", "--source-type", "github"])

        self.assertFalse(os.path.exists(fake_temp), "Temporary repository must be deleted after success.")

    def test_cleanup_after_inventory_failure(self):
        """Temporary repository must be deleted when agent.inventory raises an exception."""
        fake_temp = tempfile.mkdtemp(prefix="fake_temp_fail_")
        self.assertTrue(os.path.exists(fake_temp))

        simulated_err = RuntimeError("Disk read error during inventory")
        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch.object(RepositoryIngestionAgent, "inventory", side_effect=simulated_err), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:

            with self.assertRaises(SystemExit) as cm:
                ingest_main(["--source", "https://github.com/mock/repo.git", "--source-type", "github"])

            self.assertEqual(cm.exception.code, 1)
            err_output = mock_stderr.getvalue()
            self.assertIn("Ingestion error: Disk read error during inventory", err_output)

        self.assertFalse(os.path.exists(fake_temp), "Temporary repository must be deleted even if inventory fails.")

    def test_user_owned_local_directories_preserved(self):
        """User-provided local directories must never be deleted, even in temp-looking paths or on failure."""
        readme = os.path.join(self.test_dir, "README.md")
        self.assertTrue(os.path.exists(readme))

        # 1. On success
        with patch("sys.stdout", new_callable=io.StringIO):
            ingest_main(["--source", self.test_dir, "--source-type", "dir"])

        self.assertTrue(os.path.exists(self.test_dir), "User directory must remain intact after success.")
        self.assertTrue(os.path.exists(readme))

        # 2. On inventory failure
        with patch.object(RepositoryIngestionAgent, "inventory", side_effect=RuntimeError("Inventory failure")), \
             patch("sys.stderr", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as cm:
                ingest_main(["--source", self.test_dir, "--source-type", "dir"])
            self.assertEqual(cm.exception.code, 1)

        self.assertTrue(os.path.exists(self.test_dir), "User directory must remain intact after failure.")
        self.assertTrue(os.path.exists(readme))

    def test_user_owned_zip_files_preserved(self):
        """User-provided ZIP file must remain intact while its extracted temporary folder is removed."""
        zip_path = os.path.join(self.test_dir, "archive.zip")
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("src/main.py", "print('zip project')\n")
            zf.writestr("README.md", "# Zip Project\n")

        self.assertTrue(os.path.exists(zip_path))

        with patch("sys.stdout", new_callable=io.StringIO):
            ingest_main(["--source", zip_path, "--source-type", "zip"])

        # The ZIP file must still exist
        self.assertTrue(os.path.exists(zip_path), "User ZIP file must never be deleted by cleanup.")

    def test_cleanup_failure_does_not_mask_ingestion_error(self):
        """Cleanup failure must be reported to stderr without hiding the original ingestion error."""
        fake_temp = tempfile.mkdtemp(prefix="fake_temp_cleanup_err_")
        simulated_inv_err = ValueError("Invalid AST syntax encountered")
        simulated_cleanup_err = PermissionError("Locked file cannot be deleted")

        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch.object(RepositoryIngestionAgent, "inventory", side_effect=simulated_inv_err), \
             patch("shutil.rmtree", side_effect=simulated_cleanup_err), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:

            with self.assertRaises(SystemExit) as cm:
                ingest_main(["--source", "https://github.com/mock/repo.git", "--source-type", "github"])

            self.assertEqual(cm.exception.code, 1)
            err_output = mock_stderr.getvalue()
            # Original error must be reported
            self.assertIn("Ingestion error: Invalid AST syntax encountered", err_output)
            # Cleanup warning must be reported
            self.assertIn("Warning: Failed to clean up temporary directory", err_output)
            self.assertIn("Locked file cannot be deleted", err_output)

        shutil.rmtree(fake_temp, ignore_errors=True)

    def test_cleanup_failure_on_success_reports_warning(self):
        """When cleanup fails after a successful ingestion, a warning is printed to stderr and output is emitted."""
        fake_temp = tempfile.mkdtemp(prefix="fake_temp_cleanup_warn_")
        shutil.copytree(self.test_dir, fake_temp, dirs_exist_ok=True)
        simulated_cleanup_err = OSError("Disk device busy")

        with patch.object(RepositoryIngestionAgent, "obtain_repository", return_value=(fake_temp, True)), \
             patch("shutil.rmtree", side_effect=simulated_cleanup_err), \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout, \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:

            ingest_main(["--source", "https://github.com/mock/repo.git", "--source-type", "github"])

            err_output = mock_stderr.getvalue()
            std_output = mock_stdout.getvalue()

            self.assertIn("Warning: Failed to clean up temporary directory", err_output)
            self.assertIn("Disk device busy", err_output)
            # Stdout still contains the valid JSON inventory
            self.assertIn('"file_inventory"', std_output)

        shutil.rmtree(fake_temp, ignore_errors=True)

    def test_cleanup_temp_dir_defensive_guards(self):
        """cleanup_temp_dir must guard against None, source matching, and root drives."""
        with patch("shutil.rmtree") as mock_rmtree:
            ingest_cleanup_temp_dir(None)
            ingest_cleanup_temp_dir("")
            mock_rmtree.assert_not_called()

            # Same as source
            ingest_cleanup_temp_dir(self.test_dir, source=self.test_dir)
            mock_rmtree.assert_not_called()

            # Root paths
            ingest_cleanup_temp_dir("C:\\")
            ingest_cleanup_temp_dir("/")
            mock_rmtree.assert_not_called()


class TestSafeWriteOutput(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_safe_write_")
        # Populate dummy project files for CLI tests
        src_dir = os.path.join(self.test_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("print('hello')\n")
        with open(os.path.join(self.test_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Safe Write Project\n")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_successful_write(self):
        """Content must be written accurately with UTF-8 encoding and leave no temp files."""
        dest_path = os.path.join(self.test_dir, "output.json")
        payload = json.dumps({"status": "SUCCESS", "message": "Phase 0 Verified: üñîçødé"}, indent=2)

        ingest_safe_write_output(dest_path, payload)

        self.assertTrue(os.path.exists(dest_path))
        with open(dest_path, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        self.assertEqual(loaded["status"], "SUCCESS")
        self.assertEqual(loaded["message"], "Phase 0 Verified: üñîçødé")

        # Verify no temporary files remain in directory
        temp_files = [f for f in os.listdir(self.test_dir) if f.startswith(".tmp_output_")]
        self.assertEqual(temp_files, [], "No temporary output files should remain after success.")

    def test_missing_parent_directories_created(self):
        """Missing parent directories must be created automatically when writing."""
        nested_dest = os.path.join(self.test_dir, "deeply", "nested", "reports", "phase0.json")
        payload = json.dumps({"schema_version": "1.0.0"})

        ingest_safe_write_output(nested_dest, payload)

        self.assertTrue(os.path.exists(nested_dest))
        with open(nested_dest, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["schema_version"], "1.0.0")

    def test_atomic_replacement_of_existing_file(self):
        """An existing destination file must be atomically replaced with new content."""
        dest_path = os.path.join(self.test_dir, "existing.json")
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write("OLD_INITIAL_CONTENT")

        new_payload = json.dumps({"updated": True, "count": 42}, indent=2)
        ingest_safe_write_output(dest_path, new_payload)

        with open(dest_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertTrue(data["updated"])
        self.assertEqual(data["count"], 42)

    def test_write_failure_preserves_original_file_and_cleans_temp_file(self):
        """A failure during write must not truncate the destination file and must remove the temp file."""
        dest_path = os.path.join(self.test_dir, "critical_original.json")
        original_content = "ORIGINAL_UNTOUCHED_CONTENT"
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(original_content)

        # Force a failure during write
        with patch("os.replace", side_effect=OSError("Atomic replacement failure")):
            with self.assertRaises(OSError) as cm:
                ingest_safe_write_output(dest_path, "NEW_CORRUPTING_PAYLOAD")

            self.assertIn("Failed to write output to", str(cm.exception))

        # Original file must remain completely intact
        with open(dest_path, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), original_content)

        # Temporary files must have been cleaned up
        temp_files = [f for f in os.listdir(self.test_dir) if f.startswith(".tmp_output_")]
        self.assertEqual(temp_files, [], "Temporary file must be deleted upon failure.")

    def test_cli_output_write_failure_reports_to_stderr_and_exits_nonzero(self):
        """When --output write fails in CLI, it reports to stderr and exits with code 1, keeping stdout clean."""
        with patch("ingest.safe_write_output", side_effect=OSError("Disk write error")), \
             patch("sys.stderr", new_callable=io.StringIO) as mock_stderr, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

            with self.assertRaises(SystemExit) as cm:
                ingest_main([
                    "--source", self.test_dir,
                    "--source-type", "dir",
                    "--output", os.path.join(self.test_dir, "out.json")
                ])

            self.assertEqual(cm.exception.code, 1)
            err_output = mock_stderr.getvalue()
            std_output = mock_stdout.getvalue()

            self.assertIn("Ingestion error: Disk write error", err_output)
            self.assertEqual(std_output, "", "stdout must remain clean when error occurs.")

    def test_cli_output_success_reserves_stdout(self):
        """When --output succeeds in CLI, file is written, status is printed to stderr, and stdout remains clean."""
        out_path = os.path.join(self.test_dir, "cli_success.json")
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr, \
             patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:

            ingest_main([
                "--source", self.test_dir,
                "--source-type", "dir",
                "--output", out_path
            ])

            err_output = mock_stderr.getvalue()
            std_output = mock_stdout.getvalue()

            self.assertIn("Phase 0 Inventory written to", err_output)
            self.assertEqual(std_output, "", "stdout must not have status messages when --output is used.")
            self.assertTrue(os.path.exists(out_path))
            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("file_inventory", data)


class TestSourceTypeInferenceAndValidation(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_inference_")
        src_dir = os.path.join(self.test_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        with open(os.path.join(src_dir, "main.py"), "w", encoding="utf-8") as f:
            f.write("print('inference test')\n")
        with open(os.path.join(self.test_dir, "README.md"), "w", encoding="utf-8") as f:
            f.write("# Inference Test\n")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_valid_directory_paths_inference(self):
        """Existing local directory paths must be inferred as 'dir'."""
        inferred = ingest_infer_source_type(self.test_dir)
        self.assertEqual(inferred, "dir")

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ingest_main(["--source", self.test_dir])
            self.assertIn('"file_inventory"', mock_stdout.getvalue())

    def test_zip_paths_case_insensitive_uppercase(self):
        """ZIP files with uppercase extensions (.ZIP, .Zip) must be inferred as 'zip'."""
        zip_path_upper = os.path.join(self.test_dir, "repo_archive.ZIP")
        with zipfile.ZipFile(zip_path_upper, "w") as zf:
            zf.writestr("src/main.py", "print('hello zip')\n")
            zf.writestr("README.md", "# Zip Upper\n")

        inferred = ingest_infer_source_type(zip_path_upper)
        self.assertEqual(inferred, "zip")

        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ingest_main(["--source", zip_path_upper])
            self.assertIn('"file_inventory"', mock_stdout.getvalue())

        # Also test mixed case .Zip
        zip_path_mixed = os.path.join(self.test_dir, "mixed_archive.Zip")
        shutil.copyfile(zip_path_upper, zip_path_mixed)
        self.assertEqual(ingest_infer_source_type(zip_path_mixed), "zip")

    def test_valid_supported_repository_urls(self):
        """Supported GitHub HTTPS and Git SSH URLs must be inferred as 'github'."""
        valid_urls = [
            "https://github.com/owner/repo",
            "https://github.com/owner/repo.git",
            "https://www.github.com/owner/repo",
            "https://www.github.com/owner/repo.git",
            "git@github.com:owner/repo.git",
            "git@github.com:owner/repo",
        ]
        for url in valid_urls:
            self.assertTrue(ingest_is_supported_github_url(url), f"Should match supported GitHub URL: {url}")
            self.assertEqual(ingest_infer_source_type(url), "github", f"Should infer 'github' for: {url}")

    def test_arbitrary_urls_rejected(self):
        """Arbitrary URLs (e.g. GitLab, Bitbucket, HTTP) must not be treated as supported GitHub URLs."""
        unsupported_urls = [
            "https://gitlab.com/owner/repo.git",
            "https://bitbucket.org/owner/repo.git",
            "http://github.com/owner/repo",
            "http://example.com/repo.git",
            "https://evil.github.com.attacker.com/owner/repo",
        ]
        for url in unsupported_urls:
            self.assertFalse(ingest_is_supported_github_url(url), f"Should not match supported GitHub URL: {url}")
            with self.assertRaises(ValueError) as cm:
                ingest_infer_source_type(url)
            self.assertIn("Unable to infer source type", str(cm.exception))

    def test_nonexistent_paths(self):
        """Nonexistent local paths must fail with clear, actionable diagnostics."""
        missing_zip = os.path.join(self.test_dir, "missing_archive.ZIP")
        with self.assertRaises(ValueError) as cm:
            ingest_infer_source_type(missing_zip)
        self.assertIn("ZIP file not found at", str(cm.exception))

        missing_dir = os.path.join(self.test_dir, "missing_folder", "sub")
        with self.assertRaises(ValueError) as cm:
            ingest_infer_source_type(missing_dir)
        self.assertIn("Directory not found", str(cm.exception))

        # CLI execution on missing zip
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source", missing_zip])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("ZIP file not found at", mock_stderr.getvalue())

        # CLI execution on missing dir
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source", missing_dir])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("Directory not found", mock_stderr.getvalue())

    def test_ambiguous_sources(self):
        """Ambiguous sources or non-ZIP existing files must prompt the user to specify --source-type."""
        ambiguous_token = "some_random_unresolvable_token"
        with self.assertRaises(ValueError) as cm:
            ingest_infer_source_type(ambiguous_token)
        self.assertIn("Unable to infer source type for 'some_random_unresolvable_token'", str(cm.exception))
        self.assertIn("Specify --source-type explicitly", str(cm.exception))

        # Existing file that is not a ZIP
        txt_file = os.path.join(self.test_dir, "notes.txt")
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write("text data\n")
        with self.assertRaises(ValueError) as cm:
            ingest_infer_source_type(txt_file)
        self.assertIn("not a supported ZIP archive", str(cm.exception))

        # CLI on ambiguous token
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source", ambiguous_token])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("Specify --source-type explicitly", mock_stderr.getvalue())

    def test_explicit_source_type_validation(self):
        """Explicit --source-type must be validated and executed or rejected appropriately."""
        # 1. Valid dir explicit
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ingest_main(["--source-type", "dir", "--source", self.test_dir])
            self.assertIn('"file_inventory"', mock_stdout.getvalue())

        # 2. Nonexistent path with explicit dir
        missing_dir = os.path.join(self.test_dir, "does_not_exist")
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source-type", "dir", "--source", missing_dir])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("Directory not found", mock_stderr.getvalue())

        # 3. Non-directory path with explicit dir
        txt_file = os.path.join(self.test_dir, "file.txt")
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write("content")
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source-type", "dir", "--source", txt_file])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("Specified path is not a directory", mock_stderr.getvalue())

        # 4. Nonexistent path with explicit zip
        missing_zip = os.path.join(self.test_dir, "does_not_exist.zip")
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source-type", "zip", "--source", missing_zip])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("ZIP file not found", mock_stderr.getvalue())

        # 5. Non-zip file with explicit zip
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            with self.assertRaises(SystemExit) as exit_cm:
                ingest_main(["--source-type", "zip", "--source", txt_file])
            self.assertEqual(exit_cm.exception.code, 1)
            self.assertIn("Specified path is not a valid ZIP file", mock_stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
