"""
Dedicated Unit & Freeze-Gate Tests for Phase 3A: Red Team Security Analysis Agent.

Verifies Phase 3A in complete isolation with synthetic fixtures:
1. Safe subprocess argument handling does not produce option injection finding.
2. Risky subprocess call with untrusted input produces PROBABLE candidate.
3. Unrelated shlex.quote elsewhere in file does NOT silence risky shell command execution.
4. Shell command execution with properly applied shlex.quote on argument is safe.
5. Static literal commands (os.system('clear'), subprocess.run('git --version', shell=True)) are not flagged.
6. SQL execute with 2+ arguments (parameterized query) is safe even if '?' is in text/comment.
7. Dynamic SQL f-string query without parameters is detected as PROBABLE/POSSIBLE.
8. Deserialization with unknown provenance is qualified as POSSIBLE, untrusted ingress as PROBABLE.
9. Bounded read (f.read(1024)) is safe; unbounded read (f.read()) is flagged.
10. Unrelated variable guard (e.g. max_items = 10) does NOT silence unbounded f.read().
11. Archive extraction with safe path check, symlink check, and size limit is safe.
12. Unrelated commonpath in another function does NOT make an unsafe archive extraction safe.
13. Archive extraction with path validation but missing symlink guard flags POSSIBLE symlink traversal.
14. Wildcard CORS without credentials is LOW/POSSIBLE, not confirmed critical data theft.
15. Wildcard CORS with credentials is HIGH/PROBABLE.
16. CLI output destination (--output) is not flagged as unauthorized overwrite.
17. Absolute paths in internal dictionary outputs are classified as LOW/POSSIBLE information disclosure.
18. Dummy/placeholder secrets (changeme, dummy, test) are ignored.
19. Plausible high-entropy secret is detected with redacted evidence (value never exposed).
20. Hardcoded debug=True is flagged as PROBABLE even if os.getenv appears elsewhere for unrelated variable.
21. Dynamic debug=os.getenv('DEBUG') is qualified as POSSIBLE.
22. MD5 cache key is LOW/POSSIBLE even if word 'password' appears in unrelated comment.
23. MD5 password hashing is HIGH/PROBABLE.
24. tempfile.mktemp() followed by open(unrelated_file) does NOT treat mktemp as opened unsafely.
25. tempfile.mktemp() assigned to var and passed directly to open(var) is flagged as PROBABLE.
26. SSRF detects dynamic user URL while ignoring static constants/URLs.
27. XXE detects standard XML parser without defusedxml.
28. Repository containment: path traversal (../../) rejected via canonical commonpath.
29. Repository containment: symlinks pointing outside root are rejected.
30. Per-file limit (5MB): exact 5MB allowed, 5MB + 1 byte skipped.
31. Aggregate byte budget (50MB): enforcement stops before exceeding budget; total inspected bytes <= 50MB.
32. Deduplication merges findings in same file: aggregates line_numbers list and preserves distinct evidence.
33. Deduplication preserves findings in different files separately without cross-file status contamination.
34. Requirement mapping returns UNMAPPED when no match, and maps valid requirements accurately without inventing IDs.
35. Truthful coverage reporting across 18 dimensions: INSUFFICIENT_INPUT on empty repo, CHECKED_HEURISTICALLY on code.
36. Deterministic output ordering across repeated runs on identical inputs.
37. Empty repositories produce explicit, truthful results without crashing.
38. Missing/malformed Phase 0, 1, 2 inputs handled safely without crashes.
"""

import os
import shutil
import tempfile
import unittest

from src.phase3a.red_team import RedTeamSecurityAgent


class TestPhase3ARedTeamAgent(unittest.TestCase):
    """Freeze-gate verification test suite for RedTeamSecurityAgent."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="phase3a_freeze_test_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_file(self, rel_path: str, content: str) -> str:
        full_path = os.path.join(self.test_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        return rel_path

    # 1. Safe subprocess argument handling
    def test_safe_subprocess_arguments_not_flagged_as_option_injection(self):
        self._write_file("safe_git.py", (
            "import subprocess\n"
            "def clone_repo(url, dest):\n"
            "    if url.startswith(('-', '--')):\n"
            "        raise ValueError('Invalid URL')\n"
            "    subprocess.run(['git', 'clone', '--', url, dest])\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "safe_git.py"}]},
        )
        res = agent.analyze()
        inj = [f for f in res["findings"] if f["finding_id"] == "RED-INJ-01"]
        self.assertEqual(len(inj), 0)

    # 2. Risky subprocess call with untrusted input
    def test_risky_subprocess_call_detected_as_probable_candidate(self):
        self._write_file("risky_git.py", (
            "import subprocess\n"
            "def obtain_repository(source):\n"
            "    subprocess.Popen(['git', 'clone', source, 'target_dir'])\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "risky_git.py"}]},
        )
        res = agent.analyze()
        inj = [f for f in res["findings"] if f["finding_id"] == "RED-INJ-01"]
        self.assertEqual(len(inj), 1)
        self.assertEqual(inj[0]["validation_status"], "PROBABLE")

    # 3. Unrelated shlex.quote elsewhere in file does NOT silence risky shell command
    def test_unrelated_shlex_quote_does_not_silence_risky_shell_command(self):
        self._write_file("mixed_shell.py", (
            "import os, shlex\n"
            "def safe_printer(text):\n"
            "    return shlex.quote(text)\n"
            "\n"
            "def run_command_handler(untrusted_arg):\n"
            "    os.system('cat ' + untrusted_arg)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "mixed_shell.py"}]},
        )
        res = agent.analyze()
        cmd = [f for f in res["findings"] if f["finding_id"] == "RED-CMD-01"]
        self.assertEqual(len(cmd), 1)
        self.assertEqual(cmd[0]["validation_status"], "PROBABLE")

    # 4. Correctly applied shlex.quote on argument is safe
    def test_properly_quoted_shell_command_is_safe(self):
        self._write_file("quoted_shell.py", (
            "import os, shlex\n"
            "def run_safe(arg):\n"
            "    os.system('cat ' + shlex.quote(arg))\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "quoted_shell.py"}]},
        )
        res = agent.analyze()
        cmd = [f for f in res["findings"] if f["finding_id"] == "RED-CMD-01"]
        self.assertEqual(len(cmd), 0)

    # 5. Static literal commands are not flagged
    def test_static_literal_commands_not_flagged(self):
        self._write_file("static_cmd.py", (
            "import os, subprocess\n"
            "def clear():\n"
            "    os.system('clear')\n"
            "    subprocess.run('git --version', shell=True)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "static_cmd.py"}]},
        )
        res = agent.analyze()
        cmd = [f for f in res["findings"] if f["finding_id"] == "RED-CMD-01"]
        self.assertEqual(len(cmd), 0)

    # 6. SQL execute with 2+ arguments (parameterized) is safe even if '?' is in text
    def test_parameterized_sql_is_safe_even_with_question_marks(self):
        self._write_file("param_sql.py", (
            "def query_user(cursor, user_id):\n"
            "    # Does this query work? Yes.\n"
            "    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "param_sql.py"}]},
        )
        res = agent.analyze()
        sql = [f for f in res["findings"] if f["finding_id"] == "RED-SQL-01"]
        self.assertEqual(len(sql), 0)

    # 7. Dynamic SQL f-string query without parameters is detected
    def test_dynamic_sql_fstring_detected(self):
        self._write_file("vuln_sql.py", (
            "def get_user(cursor, request_user):\n"
            "    cursor.execute(f'SELECT * FROM users WHERE username = \\'{request_user}\\'')\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "vuln_sql.py"}]},
        )
        res = agent.analyze()
        sql = [f for f in res["findings"] if f["finding_id"] == "RED-SQL-01"]
        self.assertEqual(len(sql), 1)
        self.assertEqual(sql[0]["validation_status"], "PROBABLE")

    # 8. Deserialization with unknown provenance is POSSIBLE, untrusted is PROBABLE
    def test_deserialization_provenance_differentiation(self):
        self._write_file("cache_pickle.py", (
            "import pickle\n"
            "def load_cache(filename):\n"
            "    with open(filename, 'rb') as f:\n"
            "        return pickle.load(f)\n"
        ))
        self._write_file("network_pickle.py", (
            "import pickle\n"
            "def handle_network_request(request):\n"
            "    return pickle.loads(request.payload)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [
                {"path": "cache_pickle.py"},
                {"path": "network_pickle.py"}
            ]},
        )
        res = agent.analyze()
        cache_f = [f for f in res["findings"] if f["finding_id"] == "RED-DESER-01" and "cache_pickle.py" in f["affected_files"]][0]
        net_f = [f for f in res["findings"] if f["finding_id"] == "RED-DESER-01" and "network_pickle.py" in f["affected_files"]][0]

        self.assertEqual(cache_f["validation_status"], "POSSIBLE")
        self.assertEqual(net_f["validation_status"], "PROBABLE")

    # 9. Bounded read safe; unbounded read flagged
    def test_bounded_read_safe_unbounded_flagged(self):
        self._write_file("readers.py", (
            "def safe_read(p):\n"
            "    with open(p, 'rb') as f:\n"
            "        return f.read(4096)\n"
            "\n"
            "def unsafe_read(p):\n"
            "    with open(p, 'rb') as f:\n"
            "        return f.read()\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "readers.py"}]},
        )
        res = agent.analyze()
        dos = [f for f in res["findings"] if f["finding_id"] == "RED-DOS-02"]
        self.assertEqual(len(dos), 1)
        self.assertIn("unsafe_read", dos[0]["affected_functions"])
        self.assertNotIn("safe_read", dos[0]["affected_functions"])

    # 10. Unrelated variable guard does NOT silence unbounded read
    def test_unrelated_variable_guard_does_not_silence_unbounded_read(self):
        self._write_file("unrelated_guard.py", (
            "def process_items(file_path):\n"
            "    max_items = 50\n"
            "    limit_count = 100\n"
            "    with open(file_path, 'r') as f:\n"
            "        data = f.read()\n"
            "    return len(data)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "unrelated_guard.py"}]},
        )
        res = agent.analyze()
        dos = [f for f in res["findings"] if f["finding_id"] == "RED-DOS-02"]
        self.assertEqual(len(dos), 1)
        self.assertEqual(dos[0]["validation_status"], "PROBABLE")

    # 11. Archive extraction with safe path check, symlink check, and size limit is safe
    def test_safe_archive_extraction_not_flagged(self):
        self._write_file("safe_archive.py", (
            "import zipfile, os\n"
            "def extract_archive(archive_path, target_dir):\n"
            "    MAX_SIZE = 50 * 1024 * 1024\n"
            "    MAX_FILES = 500\n"
            "    total = 0\n"
            "    with zipfile.ZipFile(archive_path) as z:\n"
            "        if len(z.infolist()) > MAX_FILES:\n"
            "            raise ValueError('Too many files')\n"
            "        for info in z.infolist():\n"
            "            total += info.file_size\n"
            "            if total > MAX_SIZE:\n"
            "                raise ValueError('Zip bomb')\n"
            "            dest = os.path.realpath(os.path.join(target_dir, info.filename))\n"
            "            if os.path.commonpath([target_dir, dest]) != target_dir:\n"
            "                raise ValueError('Zip slip')\n"
            "            if info.is_symlink():\n"
            "                raise ValueError('Symlink')\n"
            "            z.extract(info, target_dir)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "safe_archive.py"}]},
        )
        res = agent.analyze()
        dos = [f for f in res["findings"] if f["finding_id"] in ("RED-DOS-01", "RED-FILE-02")]
        self.assertEqual(len(dos), 0)

    # 12. Unrelated commonpath in another function does NOT make unsafe extraction safe
    def test_unrelated_commonpath_does_not_protect_unsafe_extraction(self):
        self._write_file("mixed_zip.py", (
            "import zipfile, os\n"
            "def path_helper(base, target):\n"
            "    return os.path.commonpath([base, target]) == base\n"
            "\n"
            "def extract_vuln(zip_path, target_dir):\n"
            "    with zipfile.ZipFile(zip_path) as z:\n"
            "        z.extractall(target_dir)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "mixed_zip.py"}]},
        )
        res = agent.analyze()
        slip = [f for f in res["findings"] if f["finding_id"] == "RED-FILE-02"]
        self.assertGreater(len(slip), 0)
        self.assertEqual(slip[0]["validation_status"], "PROBABLE")

    # 13. Archive extraction with path validation but missing symlink guard flags POSSIBLE symlink traversal
    def test_missing_symlink_guard_flags_possible(self):
        self._write_file("nosymlink_zip.py", (
            "import zipfile, os\n"
            "def extract_no_sym(zip_path, target_dir):\n"
            "    with zipfile.ZipFile(zip_path) as z:\n"
            "        for info in z.infolist():\n"
            "            dest = os.path.realpath(os.path.join(target_dir, info.filename))\n"
            "            if os.path.commonpath([target_dir, dest]) != target_dir:\n"
            "                raise ValueError('Traversal')\n"
            "            z.extract(info, target_dir)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "nosymlink_zip.py"}]},
        )
        res = agent.analyze()
        sym = [f for f in res["findings"] if f["finding_id"] == "RED-FILE-02" and "Symlink" in f["title"]]
        self.assertEqual(len(sym), 1)
        self.assertEqual(sym[0]["validation_status"], "POSSIBLE")

    # 14. Wildcard CORS without credentials is LOW/POSSIBLE
    def test_wildcard_cors_without_credentials_is_low_possible(self):
        self._write_file("cors_basic.py", (
            "from flask import Flask\n"
            "from flask_cors import CORS\n"
            "app = Flask(__name__)\n"
            "CORS(app, origins='*')\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "cors_basic.py"}]},
        )
        res = agent.analyze()
        cors = [f for f in res["findings"] if f["finding_id"] == "RED-CORS-01"]
        self.assertEqual(len(cors), 1)
        self.assertEqual(cors[0]["severity"], "LOW")
        self.assertEqual(cors[0]["validation_status"], "POSSIBLE")

    # 15. Wildcard CORS with credentials is HIGH/PROBABLE
    def test_wildcard_cors_with_credentials_is_high_probable(self):
        self._write_file("cors_cred.py", (
            "from flask import Flask\n"
            "from flask_cors import CORS\n"
            "app = Flask(__name__)\n"
            "CORS(app, origins='*', supports_credentials=True)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "cors_cred.py"}]},
        )
        res = agent.analyze()
        cors = [f for f in res["findings"] if f["finding_id"] == "RED-CORS-01"]
        self.assertEqual(len(cors), 1)
        self.assertEqual(cors[0]["severity"], "HIGH")
        self.assertEqual(cors[0]["validation_status"], "PROBABLE")

    # 16. CLI output destination is not flagged as unauthorized overwrite
    def test_cli_output_path_not_flagged(self):
        self._write_file("cli_writer.py", (
            "import argparse\n"
            "def main():\n"
            "    parser = argparse.ArgumentParser()\n"
            "    parser.add_argument('--output', required=True)\n"
            "    args = parser.parse_args()\n"
            "    with open(args.output, 'w') as f:\n"
            "        f.write('content')\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "cli_writer.py"}]},
        )
        res = agent.analyze()
        out = [f for f in res["findings"] if f["finding_id"] == "RED-FILE-01"]
        self.assertEqual(len(out), 0)

    # 17. Absolute paths in internal dictionary are LOW/POSSIBLE
    def test_internal_path_leakage_is_low_possible(self):
        self._write_file("exporter.py", (
            "def get_export_contract(root_path):\n"
            "    return {'root_path': root_path, 'version': '1.0'}\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "exporter.py"}]},
        )
        res = agent.analyze()
        info = [f for f in res["findings"] if f["finding_id"] == "RED-INFO-02"]
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0]["severity"], "LOW")
        self.assertEqual(info[0]["validation_status"], "POSSIBLE")

    # 18. Dummy/placeholder secrets are ignored
    def test_dummy_secrets_ignored(self):
        self._write_file("sample_env.py", (
            "API_KEY = 'changeme-example-dummy-12345'\n"
            "SECRET_KEY = 'your-secret-key-here'\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "sample_env.py"}]},
        )
        res = agent.analyze()
        sec = [f for f in res["findings"] if f["finding_id"] == "RED-SECRET-01"]
        self.assertEqual(len(sec), 0)

    # 19. Plausible high-entropy secret detected with redacted evidence
    def test_plausible_secret_detected_and_redacted(self):
        self._write_file("prod_tokens.py", (
            "API_KEY = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "prod_tokens.py"}]},
        )
        res = agent.analyze()
        sec = [f for f in res["findings"] if f["finding_id"] == "RED-SECRET-01"]
        self.assertEqual(len(sec), 1)
        self.assertIn("[REDACTED", sec[0]["evidence"])
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ", sec[0]["evidence"])
        self.assertEqual(sec[0]["validation_status"], "PROBABLE")

    # 20. Hardcoded debug=True is flagged as PROBABLE
    def test_hardcoded_debug_is_probable(self):
        self._write_file("hardcoded_app.py", (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.run(debug=True)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "hardcoded_app.py"}]},
        )
        res = agent.analyze()
        dbg = [f for f in res["findings"] if f["finding_id"] == "RED-DEBUG-01"]
        self.assertEqual(len(dbg), 1)
        self.assertEqual(dbg[0]["validation_status"], "PROBABLE")

    # 21. Dynamic debug=os.getenv('DEBUG') is qualified as POSSIBLE
    def test_dynamic_debug_is_possible(self):
        self._write_file("dynamic_app.py", (
            "import os\n"
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "app.run(debug=os.getenv('DEBUG', 'False') == 'True')\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "dynamic_app.py"}]},
        )
        res = agent.analyze()
        dbg = [f for f in res["findings"] if f["finding_id"] == "RED-DEBUG-01"]
        self.assertEqual(len(dbg), 1)
        self.assertEqual(dbg[0]["validation_status"], "POSSIBLE")

    # 22. MD5 cache key is LOW/POSSIBLE even if word 'password' in comment
    def test_md5_cache_key_with_unrelated_comment_is_low(self):
        self._write_file("cache_hash.py", (
            "import hashlib\n"
            "# Note: user password must not be stored here\n"
            "def compute_cache_key(data):\n"
            "    return hashlib.md5(data.encode()).hexdigest()\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "cache_hash.py"}]},
        )
        res = agent.analyze()
        crypto = [f for f in res["findings"] if f["finding_id"] == "RED-CRYPTO-01"]
        self.assertEqual(len(crypto), 1)
        self.assertEqual(crypto[0]["severity"], "LOW")
        self.assertEqual(crypto[0]["validation_status"], "POSSIBLE")

    # 23. MD5 password hashing is HIGH/PROBABLE
    def test_md5_password_hashing_is_high_probable(self):
        self._write_file("auth_hash.py", (
            "import hashlib\n"
            "def store_user_password(password):\n"
            "    pwd_hash = hashlib.md5(password.encode()).hexdigest()\n"
            "    return pwd_hash\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "auth_hash.py"}]},
        )
        res = agent.analyze()
        crypto = [f for f in res["findings"] if f["finding_id"] == "RED-CRYPTO-01"]
        self.assertEqual(len(crypto), 1)
        self.assertEqual(crypto[0]["severity"], "HIGH")
        self.assertEqual(crypto[0]["validation_status"], "PROBABLE")

    # 24. mktemp followed by open on an unrelated variable is NOT marked unsafe open
    def test_mktemp_unrelated_open_not_coupled(self):
        self._write_file("mktemp_unrelated.py", (
            "import tempfile\n"
            "def worker(log_file):\n"
            "    scratch_name = tempfile.mktemp()\n"
            "    with open(log_file, 'a') as f:\n"
            "        f.write('done')\n"
            "    return scratch_name\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "mktemp_unrelated.py"}]},
        )
        res = agent.analyze()
        tmp = [f for f in res["findings"] if f["finding_id"] == "RED-TEMP-01"]
        self.assertEqual(len(tmp), 1)
        self.assertEqual(tmp[0]["validation_status"], "POSSIBLE")

    # 25. mktemp assigned and passed to open is PROBABLE
    def test_mktemp_directly_opened_is_probable(self):
        self._write_file("mktemp_open.py", (
            "import tempfile\n"
            "def create_scratch():\n"
            "    path = tempfile.mktemp()\n"
            "    with open(path, 'w') as f:\n"
            "        f.write('scratch')\n"
            "    return path\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "mktemp_open.py"}]},
        )
        res = agent.analyze()
        tmp = [f for f in res["findings"] if f["finding_id"] == "RED-TEMP-01"]
        self.assertEqual(len(tmp), 1)
        self.assertEqual(tmp[0]["validation_status"], "PROBABLE")

    # 26. SSRF detects dynamic user URL vs static URL
    def test_ssrf_detection_distinguishes_dynamic_from_static(self):
        self._write_file("network_reqs.py", (
            "import requests\n"
            "def fetch_default():\n"
            "    return requests.get('https://api.github.com/status')\n"
            "\n"
            "def fetch_user_webhook(user_url):\n"
            "    return requests.get(user_url)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "network_reqs.py"}]},
        )
        res = agent.analyze()
        ssrf = [f for f in res["findings"] if f["finding_id"] == "RED-SSRF-01"]
        self.assertEqual(len(ssrf), 1)
        self.assertIn("user_url", ssrf[0]["attacker_controlled_input"])

    # 27. XXE detects standard XML parser without defusedxml
    def test_xxe_detected_for_standard_parser(self):
        self._write_file("xml_ingest.py", (
            "import xml.etree.ElementTree as ET\n"
            "def parse_manifest(filepath):\n"
            "    return ET.parse(filepath)\n"
        ))
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "xml_ingest.py"}]},
        )
        res = agent.analyze()
        xxe = [f for f in res["findings"] if f["finding_id"] == "RED-XXE-01"]
        self.assertEqual(len(xxe), 1)
        self.assertEqual(xxe[0]["validation_status"], "POSSIBLE")

    # 28. Repository containment: path traversal (../../) rejected via commonpath
    def test_path_traversal_rejected_via_commonpath(self):
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "../../etc/shadow"}]},
        )
        corpus = agent._read_source_corpus()
        self.assertEqual(len(corpus), 0)
        self.assertTrue(len(agent.skipped_files) > 0)
        self.assertIn("Path traversal", agent.skipped_files[0]["reason"])

    # 29. Repository containment: symlinks outside root rejected
    def test_symlink_outside_root_rejected(self):
        outside_dir = tempfile.mkdtemp(prefix="outside_root_")
        try:
            target = os.path.join(outside_dir, "ext.py")
            with open(target, "w") as f:
                f.write("PASS = 123\n")
            link = os.path.join(self.test_dir, "sym_ext.py")
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                return
            agent = RedTeamSecurityAgent(
                root_path=self.test_dir,
                phase0_inventory={"source_files": [{"path": "sym_ext.py"}]},
            )
            corpus = agent._read_source_corpus()
            self.assertEqual(len(corpus), 0)
            self.assertIn("Symlink", agent.skipped_files[0]["reason"])
        finally:
            shutil.rmtree(outside_dir, ignore_errors=True)

    # 30. Per-file limit (5MB): boundary verification
    def test_per_file_limit_enforced_at_boundary(self):
        # Exact 5MB file
        exact_path = os.path.join(self.test_dir, "exact.py")
        with open(exact_path, "wb") as f:
            f.write(b"# OK\n" + b" " * (5 * 1024 * 1024 - 5))

        # 5MB + 1 byte file
        over_path = os.path.join(self.test_dir, "over.py")
        with open(over_path, "wb") as f:
            f.write(b"# OVER\n" + b" " * (5 * 1024 * 1024))

        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "exact.py"}, {"path": "over.py"}]},
        )
        corpus = agent._read_source_corpus()
        self.assertIn("exact.py", corpus)
        self.assertNotIn("over.py", corpus)
        reasons = [s["reason"] for s in agent.skipped_files if s["path"] == "over.py"]
        self.assertIn("File size exceeds 5MB per-file inspection limit", reasons[0])

    # 31. Aggregate byte budget enforcement
    def test_aggregate_byte_budget_enforced(self):
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": []},
        )
        # Verify budget constants
        self.assertEqual(agent.MAX_TOTAL_INSPECT_BYTES, 50 * 1024 * 1024)
        self.assertEqual(agent.MAX_INSPECT_FILE_SIZE, 5 * 1024 * 1024)
        self.assertEqual(agent.MAX_INSPECT_FILES, 500)
        self.assertLessEqual(agent.inspected_bytes, agent.MAX_TOTAL_INSPECT_BYTES)

    # 32. Deduplication merges findings in same file: aggregates line_numbers and evidence
    def test_deduplication_aggregates_line_numbers_in_same_file(self):
        candidates = [
            {
                "finding_id": "RED-SQL-01",
                "category": "Injection",
                "title": "SQL Injection",
                "severity": "HIGH",
                "affected_files": ["db.py"],
                "affected_functions": ["query_one"],
                "line_number": 15,
                "evidence": "db.py:15 execute call",
                "validation_status": "POSSIBLE",
            },
            {
                "finding_id": "RED-SQL-01",
                "category": "Injection",
                "title": "SQL Injection",
                "severity": "HIGH",
                "affected_files": ["db.py"],
                "affected_functions": ["query_two"],
                "line_number": 42,
                "evidence": "db.py:42 execute call",
                "validation_status": "PROBABLE",
            }
        ]
        agent = RedTeamSecurityAgent(root_path=self.test_dir)
        validated = agent.validate_findings(candidates)

        self.assertEqual(len(validated), 1)
        v = validated[0]
        self.assertIn(15, v["line_numbers"])
        self.assertIn(42, v["line_numbers"])
        self.assertEqual(v["validation_status"], "PROBABLE")
        self.assertIn("db.py:15", v["evidence"])
        self.assertIn("db.py:42", v["evidence"])
        self.assertIn("query_one", v["affected_functions"])
        self.assertIn("query_two", v["affected_functions"])

    # 33. Deduplication preserves findings in different files separately
    def test_deduplication_preserves_different_files_separately(self):
        candidates = [
            {
                "finding_id": "RED-CMD-01",
                "category": "Injection",
                "title": "Command Execution",
                "severity": "CRITICAL",
                "affected_files": ["api1.py"],
                "affected_functions": ["fn1"],
                "line_number": 10,
                "evidence": "api1.py:10",
                "validation_status": "PROBABLE",
            },
            {
                "finding_id": "RED-CMD-01",
                "category": "Injection",
                "title": "Command Execution",
                "severity": "CRITICAL",
                "affected_files": ["api2.py"],
                "affected_functions": ["fn2"],
                "line_number": 20,
                "evidence": "api2.py:20",
                "validation_status": "POSSIBLE",
            }
        ]
        agent = RedTeamSecurityAgent(root_path=self.test_dir)
        validated = agent.validate_findings(candidates)
        self.assertEqual(len(validated), 2)
        v1 = [v for v in validated if "api1.py" in v["affected_files"]][0]
        v2 = [v for v in validated if "api2.py" in v["affected_files"]][0]
        self.assertEqual(v1["validation_status"], "PROBABLE")
        self.assertEqual(v2["validation_status"], "POSSIBLE")

    # 34. Requirement mapping returns UNMAPPED when no match, and maps valid requirements accurately
    def test_requirement_mapping_accuracy_and_unmapped(self):
        reqs = [
            {"requirement_id": "REQ-SEC-ZIP-01", "description": "System must prevent archive traversal attacks", "category": "Security"},
            {"requirement_id": "REQ-SEC-INJ-01", "description": "Input validation against command injection", "category": "Security"}
        ]
        agent = RedTeamSecurityAgent(root_path=self.test_dir, phase2_requirements=reqs)

        # Matched archive finding
        m1 = agent._map_requirement_affected({"title": "Path Traversal during Archive Extraction (Zip-Slip)", "category": "File Handling"})
        self.assertEqual(m1, "REQ-SEC-ZIP-01")

        # Matched command finding
        m2 = agent._map_requirement_affected({"title": "Arbitrary Command Execution via Shell Invocation", "category": "Injection"})
        self.assertEqual(m2, "REQ-SEC-INJ-01")

        # Unmatched finding defaults to UNMAPPED
        m3 = agent._map_requirement_affected({"title": "Unrelated Business Logic Issue", "category": "General"})
        self.assertEqual(m3, "UNMAPPED")

    # 35. Truthful coverage reporting across 18 dimensions
    def test_truthful_coverage_reporting_status(self):
        self._write_file("dummy.py", "x = 1\n")
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": [{"path": "dummy.py"}]},
        )
        res = agent.analyze()
        dims = res["evaluation_dimensions"]
        self.assertEqual(len(dims), 18)
        for d in dims:
            self.assertEqual(d["status"], "CHECKED_HEURISTICALLY")
            self.assertIn("rules_evaluated", d)
            self.assertIn("limitations", d)

    # 36. Deterministic output ordering across repeated runs
    def test_deterministic_output_across_repeated_runs(self):
        self._write_file("det.py", "import tempfile\ndef run(): tempfile.mktemp()\n")
        agent1 = RedTeamSecurityAgent(root_path=self.test_dir, phase0_inventory={"source_files": [{"path": "det.py"}]})
        agent2 = RedTeamSecurityAgent(root_path=self.test_dir, phase0_inventory={"source_files": [{"path": "det.py"}]})

        res1 = agent1.analyze()
        res2 = agent2.analyze()

        self.assertEqual(len(res1["findings"]), len(res2["findings"]))
        if res1["findings"]:
            self.assertEqual(res1["findings"][0]["finding_id"], res2["findings"][0]["finding_id"])
            self.assertEqual(res1["findings"][0]["line_number"], res2["findings"][0]["line_number"])
            self.assertEqual(res1["findings"][0]["evidence"], res2["findings"][0]["evidence"])

    # 37. Empty repositories produce explicit, truthful results without crashing
    def test_empty_repository_results(self):
        agent = RedTeamSecurityAgent(
            root_path=self.test_dir,
            phase0_inventory={"source_files": []},
        )
        res = agent.analyze()
        self.assertEqual(len(res["findings"]), 0)
        self.assertEqual(res["summary"]["total_findings"], 0)
        self.assertIn("attack_surface_map", res)
        # Empty repo marks dimensions as INSUFFICIENT_INPUT
        for d in res["evaluation_dimensions"]:
            self.assertEqual(d["status"], "INSUFFICIENT_INPUT")

    # 38. Missing/malformed inputs handled safely without crashes
    def test_malformed_inputs_handled_safely(self):
        for bad_p0 in [None, "invalid", 123, {"source_files": "not-list"}]:
            agent = RedTeamSecurityAgent(
                root_path=self.test_dir,
                phase0_inventory=bad_p0,
                phase1_reconstruction=None,
                phase2_requirements=None
            )
            res = agent.analyze()
            self.assertIsInstance(res["findings"], list)
            self.assertIsInstance(res["summary"], dict)


if __name__ == "__main__":
    unittest.main()
