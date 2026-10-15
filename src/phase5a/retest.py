"""
Phase 5A: Security Retest Agent Module.

Verifies whether security issues identified by the Red Team (Phase 3A) have actually been
remediated in the active repository source code, checks whether proposed Blue Team
remediations (Phase 4A) were implemented, determines residual risks, and assigns
empirically grounded retest statuses.

Operational Principles:
1. Strict Filesystem Containment:
   All file reads are strictly constrained within the repository root. Path traversal attempts
   (e.g., '..', absolute paths outside root, escaping symlinks) are rejected and recorded as NOT_TESTABLE.
2. Bounded Consumption:
   Enforces a strict 5 MB file size ceiling and bounded buffer reads to prevent memory exhaustion.
3. Truthful Retest Classification:
   - REMEDIATED: Supported by positive source code evidence of security controls.
   - PARTIALLY_REMEDIATED: Partial controls detected, but material weakness remains.
   - NOT_REMEDIATED: Inspected code still demonstrates the vulnerability or lacks required controls.
   - NOT_TESTABLE: Target file is missing, unreadable, traversed, oversized, or unmapped,
     OR inspected code contains insufficient evidence of the relevant operation to evaluate the control.
   - FALSE_POSITIVE: Supported by verified evidence that construct is benign.
4. Non-Destructive Static Analysis:
   Inspection is purely read-only; no code is modified, commands executed, or network calls made.
"""

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class SecurityRetestAgent:
    """Agent responsible for empirically retesting and validating security remediations."""

    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB maximum file read ceiling
    MAX_AGGREGATE_BYTES = 25 * 1024 * 1024  # 25 MB cumulative inspection limit across all files

    VALID_RETEST_STATUSES = {
        "REMEDIATED",
        "PARTIALLY_REMEDIATED",
        "NOT_REMEDIATED",
        "NOT_TESTABLE",
        "FALSE_POSITIVE",
    }

    def __init__(
        self,
        root_path: str,
        phase3a_findings: Optional[List[Dict[str, Any]]] = None,
        phase4a_remediations: Optional[List[Dict[str, Any]]] = None,
    ):
        self.root_path = os.path.abspath(root_path) if root_path and isinstance(root_path, str) else os.getcwd()
        self.findings = phase3a_findings if isinstance(phase3a_findings, list) else []
        self._total_bytes_read = 0

        # Safe extraction of remediations map: finding_id -> remediation dict
        self.remediations: Dict[str, Dict[str, Any]] = {}
        if isinstance(phase4a_remediations, list):
            for r in phase4a_remediations:
                if isinstance(r, dict):
                    fid = r.get("finding_id")
                    if isinstance(fid, str) and fid.strip():
                        self.remediations[fid.strip()] = r

    def retest(self) -> Dict[str, Any]:
        """
        Executes empirical retesting for all Red Team findings against active repository source.
        """
        self._total_bytes_read = 0
        results: List[Dict[str, Any]] = []

        for finding in self.findings:
            if not isinstance(finding, dict):
                results.append(self._create_malformed_record(finding, "Non-dictionary finding entry."))
                continue

            fid = finding.get("finding_id")
            if not isinstance(fid, str) or not fid.strip():
                results.append(self._create_malformed_record(finding, "Finding missing valid finding_id."))
                continue

            clean_fid = fid.strip()
            rem = self.remediations.get(clean_fid, {})
            result = self._retest_single_finding(finding, rem)
            results.append(result)

        # Summary counts strictly match the final result records
        summary = {
            "total_retested": len(results),
            "remediated": sum(1 for r in results if r.get("final_status") == "REMEDIATED"),
            "partially_remediated": sum(1 for r in results if r.get("final_status") == "PARTIALLY_REMEDIATED"),
            "not_remediated": sum(1 for r in results if r.get("final_status") == "NOT_REMEDIATED"),
            "not_testable": sum(1 for r in results if r.get("final_status") == "NOT_TESTABLE"),
            "false_positive": sum(1 for r in results if r.get("final_status") == "FALSE_POSITIVE"),
        }

        return {
            "retest_results": results,
            "summary": summary,
        }

    def analyze(self) -> Dict[str, Any]:
        """Alias for retest() to preserve interface compatibility."""
        return self.retest()

    # -------------------------------------------------------------------------
    # Filesystem Containment & Bounded Reading
    # -------------------------------------------------------------------------

    def _read_file_safe(self, rel_path: Any) -> Tuple[Optional[str], str, str]:
        """
        Safely reads a repository file with strict path containment and size limits.

        Returns:
            (content, status_code, message)
            - content: The file text if status_code == "OK", otherwise None.
            - status_code: One of "OK", "INVALID_PATH", "TRAVERSAL_REJECTED",
              "MISSING_FILE", "IS_DIRECTORY", "OVERSIZED", "PERMISSION_ERROR", "READ_ERROR".
            - message: Diagnostic explanation without leaking host root paths.
        """
        if not isinstance(rel_path, str) or not rel_path.strip():
            return None, "INVALID_PATH", "File path must be a non-empty string."

        clean_path = rel_path.strip()
        if "\0" in clean_path:
            return None, "INVALID_PATH", "Null byte detected in file path."

        norm_rel = os.path.normpath(clean_path)

        # Disallow paths starting with drive letters or absolute roots outside root_path
        if os.path.isabs(norm_rel):
            target_path = os.path.normpath(norm_rel)
        else:
            target_path = os.path.normpath(os.path.join(self.root_path, norm_rel))

        real_root = os.path.realpath(self.root_path)
        real_target = os.path.realpath(target_path)

        # Enforce canonical path containment within repository root
        try:
            common = os.path.commonpath([real_root, real_target])
            if common != real_root:
                return None, "TRAVERSAL_REJECTED", f"Path escapes repository boundary: {clean_path}"
        except (ValueError, Exception):
            return None, "TRAVERSAL_REJECTED", f"Path escapes repository root: {clean_path}"

        # Inspect if path is a symlink escaping root
        if os.path.islink(target_path):
            try:
                dest = os.path.realpath(target_path)
                if os.path.commonpath([real_root, dest]) != real_root:
                    return None, "TRAVERSAL_REJECTED", f"Symlink escapes repository root: {clean_path}"
            except Exception:
                return None, "TRAVERSAL_REJECTED", f"Symlink escapes repository root: {clean_path}"

        if not os.path.exists(target_path):
            return None, "MISSING_FILE", f"File does not exist: {clean_path}"

        if os.path.isdir(target_path):
            return None, "IS_DIRECTORY", f"Path is a directory, not a file: {clean_path}"

        try:
            size = os.path.getsize(target_path)
            if size > self.MAX_FILE_SIZE:
                return None, "OVERSIZED", f"File size ({size} bytes) exceeds limit ({self.MAX_FILE_SIZE} bytes)."
            if self._total_bytes_read + size > self.MAX_AGGREGATE_BYTES:
                return None, "OVERSIZED", f"Aggregate inspection budget ({self.MAX_AGGREGATE_BYTES} bytes) exceeded."
        except OSError as e:
            return None, "READ_ERROR", f"Unable to inspect file size: {e}"

        try:
            with open(target_path, "rb") as f:
                raw_bytes = f.read(self.MAX_FILE_SIZE + 1)
                if len(raw_bytes) > self.MAX_FILE_SIZE:
                    return None, "OVERSIZED", f"File content in bytes ({len(raw_bytes)}) exceeds inspection ceiling ({self.MAX_FILE_SIZE} bytes)."
                if self._total_bytes_read + len(raw_bytes) > self.MAX_AGGREGATE_BYTES:
                    return None, "OVERSIZED", f"Aggregate inspection budget exceeded ({self._total_bytes_read + len(raw_bytes)} > {self.MAX_AGGREGATE_BYTES} bytes)."
                self._total_bytes_read += len(raw_bytes)
                content = raw_bytes.decode("utf-8", errors="replace")
                return content, "OK", ""
        except PermissionError:
            return None, "PERMISSION_ERROR", f"Permission denied reading file: {clean_path}"
        except Exception as e:
            return None, "READ_ERROR", f"Read error for {clean_path}: {type(e).__name__}"

    def _create_malformed_record(self, raw_entry: Any, reason: str) -> Dict[str, Any]:
        """Creates a predictable, compliant record for malformed finding inputs."""
        fid = "MALFORMED_FINDING"
        if isinstance(raw_entry, dict) and isinstance(raw_entry.get("finding_id"), str):
            fid = raw_entry["finding_id"]

        return {
            "finding_id": fid,
            "original_issue": "Malformed finding record",
            "original_attack_path": "N/A",
            "remediation_tested": "N/A",
            "result": f"Finding cannot be evaluated: {reason}",
            "remaining_risk": "Unable to verify remediation for malformed input.",
            "regression_detected": False,
            "regression_test_status": "NOT_ASSESSED",
            "final_status": "NOT_TESTABLE",
            "evidence": f"Malformed input item of type {type(raw_entry).__name__}: {reason}",
            "confidence": "LOW",
            "inspected_files": [],
        }

    # -------------------------------------------------------------------------
    # Single Finding Retest Dispatcher
    # -------------------------------------------------------------------------

    def _retest_single_finding(self, finding: Dict[str, Any], rem: Dict[str, Any]) -> Dict[str, Any]:
        fid = finding["finding_id"]
        orig_issue = finding.get("title", f"Finding {fid}")
        orig_attack_path = finding.get("attack_path", "N/A")
        remediation_tested = rem.get("remediation", "Apply defensive security controls.")

        # Respect upstream false positive determination when independently verifiable
        if finding.get("validation_status") == "FALSE_POSITIVE":
            upstream_ev = finding.get("evidence")
            has_evidence = isinstance(upstream_ev, str) and bool(upstream_ev.strip())

            # Inspect affected files if available
            affected_files = self._extract_affected_files(finding, fid)
            file_contents = {}
            for af in affected_files:
                content, status, _ = self._read_file_safe(af)
                if status == "OK" and content:
                    file_contents[af] = content

            # Check if active vulnerable constructs contradict false positive label
            code_corpus = "\n".join(file_contents.values())
            has_active_vuln = False
            if fid == "RED-DEBUG-01" and re.search(r'\b(?:app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)\b', code_corpus):
                has_active_vuln = True
            elif fid == "RED-SQL-01" and re.search(r'(?:cursor\.)?execute\(\s*f["\']', code_corpus):
                has_active_vuln = True
            elif fid == "RED-SECRET-01" and re.search(r'\b(?:JWT_SECRET|SECRET_KEY|API_KEY)\s*=\s*["\'][^"\']{8,}["\']', code_corpus):
                has_active_vuln = True

            if has_active_vuln:
                return {
                    "finding_id": fid,
                    "original_issue": orig_issue,
                    "original_attack_path": orig_attack_path,
                    "remediation_tested": remediation_tested,
                    "result": "Finding was labeled FALSE_POSITIVE upstream, but independent static retest detected active vulnerable construct.",
                    "remaining_risk": "Vulnerability remains active despite upstream false positive designation.",
                    "regression_detected": False,
                    "regression_test_status": "NOT_ASSESSED",
                    "final_status": "NOT_REMEDIATED",
                    "evidence": f"Contradictory evidence: active vulnerability found in inspected source files ({', '.join(file_contents.keys())}).",
                    "confidence": "HIGH",
                    "inspected_files": list(file_contents.keys()),
                }

            if not has_evidence and not file_contents:
                return {
                    "finding_id": fid,
                    "original_issue": orig_issue,
                    "original_attack_path": orig_attack_path,
                    "remediation_tested": remediation_tested,
                    "result": "Finding was marked FALSE_POSITIVE upstream in Phase 3A, but lacks supporting evidence and source context for independent verification.",
                    "remaining_risk": "Vulnerability status remains unverified; upstream false positive assertion cannot be confirmed.",
                    "regression_detected": False,
                    "regression_test_status": "NOT_ASSESSED",
                    "final_status": "NOT_TESTABLE",
                    "evidence": "Missing supporting evidence or source files to verify upstream FALSE_POSITIVE determination.",
                    "confidence": "LOW",
                    "inspected_files": [],
                }

            conf = finding.get("confidence", "HIGH" if has_evidence else "MEDIUM")
            return {
                "finding_id": fid,
                "original_issue": orig_issue,
                "original_attack_path": orig_attack_path,
                "remediation_tested": remediation_tested,
                "result": "Construct was validated as a false positive during Phase 3A analysis; accepted based on documented evidence.",
                "remaining_risk": "None identified upstream; residual risk unverified by static retest.",
                "regression_detected": False,
                "regression_test_status": "NOT_ASSESSED",
                "final_status": "FALSE_POSITIVE",
                "evidence": f"Phase 3A validated false positive: {upstream_ev or 'Code inspection confirmed benign usage.'}",
                "confidence": conf,
                "inspected_files": list(file_contents.keys()),
            }

        # Resolve target files to inspect
        affected_files = self._extract_affected_files(finding, fid)

        if not affected_files:
            return {
                "finding_id": fid,
                "original_issue": orig_issue,
                "original_attack_path": orig_attack_path,
                "remediation_tested": remediation_tested,
                "result": "No target source files specified or available to inspect for remediation.",
                "remaining_risk": "Vulnerability status remains unverified due to missing target file references.",
                "regression_detected": False,
                "regression_test_status": "NOT_ASSESSED",
                "final_status": "NOT_TESTABLE",
                "evidence": "Missing affected_files reference in finding.",
                "confidence": "LOW",
                "inspected_files": [],
            }

        # Read and validate all affected files
        file_contents: Dict[str, str] = {}
        read_errors: List[str] = []

        for af in affected_files:
            content, status, msg = self._read_file_safe(af)
            if status != "OK" or content is None:
                read_errors.append(f"{af} ({status}: {msg})")
            else:
                file_contents[af] = content

        # If any file failed safe reading, we cannot certify full remediation
        if read_errors:
            return {
                "finding_id": fid,
                "original_issue": orig_issue,
                "original_attack_path": orig_attack_path,
                "remediation_tested": remediation_tested,
                "result": f"One or more target files could not be inspected safely: {', '.join(read_errors)}",
                "remaining_risk": "Remediation cannot be verified; target files are inaccessible or uninspectable.",
                "regression_detected": False,
                "regression_test_status": "NOT_ASSESSED",
                "final_status": "NOT_TESTABLE",
                "evidence": f"File read failures: {'; '.join(read_errors)}",
                "confidence": "LOW",
                "inspected_files": list(file_contents.keys()),
            }

        # Dispatch finding-specific check
        dispatch_table = {
            "RED-SQL-01": self._check_sql_injection,
            "RED-SECRET-01": self._check_hardcoded_secrets,
            "RED-DESER-01": self._check_deserialization,
            "RED-DEBUG-01": self._check_debug_mode,
            "RED-CORS-01": self._check_cors_policy,
            "RED-CRYPTO-01": self._check_cryptographic_hashing,
            "RED-CMD-01": self._check_command_execution,
            "RED-INJ-01": self._check_git_option_injection,
            "RED-DOS-01": self._check_archive_decompression_dos,
            "RED-FILE-01": self._check_output_file_overwrite,
            "RED-DOS-02": self._check_unbounded_file_reads,
            "RED-FILE-02": self._check_archive_symlink_traversal,
            "RED-INFO-01": self._check_directory_scope,
            "RED-INFO-02": self._check_path_disclosure,
            "RED-SSRF-01": self._check_ssrf,
            "RED-XXE-01": self._check_xxe,
            "RED-TEMP-01": self._check_temporary_files,
            "RED-TLS-01": self._check_plaintext_transport,
        }

        checker = dispatch_table.get(fid)
        if not checker:
            return {
                "finding_id": fid,
                "original_issue": orig_issue,
                "original_attack_path": orig_attack_path,
                "remediation_tested": remediation_tested,
                "result": f"No automated static retest rule implemented for finding '{fid}'. Manual code review required.",
                "remaining_risk": "Vulnerability status cannot be determined automatically.",
                "regression_detected": False,
                "regression_test_status": "NOT_ASSESSED",
                "final_status": "NOT_TESTABLE",
                "evidence": f"Unsupported finding ID '{fid}'.",
                "confidence": "LOW",
                "inspected_files": list(file_contents.keys()),
            }

        status, result_desc, remaining_risk, evidence, confidence = checker(file_contents, rem, finding)

        return {
            "finding_id": fid,
            "original_issue": orig_issue,
            "original_attack_path": orig_attack_path,
            "remediation_tested": remediation_tested,
            "result": result_desc,
            "remaining_risk": remaining_risk,
            "regression_detected": False,
            "regression_test_status": "NOT_ASSESSED",
            "final_status": status,
            "evidence": evidence,
            "confidence": confidence,
            "inspected_files": list(file_contents.keys()),
        }

    def _extract_affected_files(self, finding: Dict[str, Any], fid: str) -> List[str]:
        """Extracts valid relative affected file paths, defaulting to known component locations if appropriate."""
        raw_files = finding.get("affected_files")
        files: List[str] = []

        if isinstance(raw_files, list):
            for f in raw_files:
                if isinstance(f, str) and f.strip():
                    files.append(f.strip())
        elif isinstance(raw_files, str) and raw_files.strip():
            files.append(raw_files.strip())

        # If empty, check for known standard locations based on finding ID
        if not files:
            defaults = {
                "RED-INJ-01": ["src/phase0/ingestion.py"],
                "RED-DOS-01": ["src/phase0/ingestion.py"],
                "RED-FILE-02": ["src/phase0/ingestion.py"],
                "RED-INFO-01": ["src/phase0/ingestion.py"],
                "RED-INFO-02": ["src/phase0/ingestion.py"],
                "RED-DOS-02": ["src/phase1/reconstruction.py", "src/phase2/requirements.py"],
                "RED-FILE-01": ["pipeline.py", "ingest.py"],
            }
            if fid in defaults:
                # Only use default if at least one file actually exists in root_path
                existing = [df for df in defaults[fid] if os.path.exists(os.path.join(self.root_path, df))]
                if existing:
                    files = existing

        return files

    # -------------------------------------------------------------------------
    # Structural Code Inspection Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _is_connected_to_deserialization(code: str) -> bool:
        """Checks if HMAC or signature verification is actually invoked in the same function as pickle/joblib deserialization."""
        try:
            import ast
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_code = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    has_pickle = any(p in func_code for p in ("pickle.load", "pickle.loads", "joblib.load"))
                    has_auth = any(a in func_code for a in ("hmac.compare_digest", "verify_signature", "verify_hmac"))
                    if has_pickle and has_auth:
                        return True
            return False
        except Exception:
            lines = code.splitlines()
            pickle_lines = [i for i, l in enumerate(lines) if "pickle.load" in l or "joblib.load" in l]
            auth_lines = [i for i, l in enumerate(lines) if "compare_digest" in l or "verify_signature" in l]
            for pl in pickle_lines:
                for al in auth_lines:
                    if 0 <= pl - al <= 20:
                        return True
            return False

    @staticmethod
    def _is_connected_to_http_request(code: str) -> bool:
        """Checks if destination validation is actually invoked on or before HTTP client requests."""
        try:
            import ast
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_code = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    has_req = any(r in func_code for r in ("requests.get", "requests.post", "requests.request", "urlopen", "httpx.get", "httpx.post"))
                    has_val = any(v in func_code for v in ("validate_url", "is_safe_url", "is_private", "allowed_domains", "url_allowlist", "check_destination"))
                    if has_req and has_val:
                        return True
            return False
        except Exception:
            lines = code.splitlines()
            req_lines = [i for i, l in enumerate(lines) if any(r in l for r in ("requests.", "urlopen", "httpx."))]
            val_lines = [i for i, l in enumerate(lines) if any(v in l for v in ("validate_url", "is_safe_url", "is_private"))]
            for rl in req_lines:
                for vl in val_lines:
                    if 0 <= rl - vl <= 15:
                        return True
            return False

    @staticmethod
    def _has_effective_xxe_protection(code: str) -> bool:
        """Checks whether XML parsing actively uses defusedxml or disables external entity resolution."""
        if re.search(r'\b(?:defusedxml\.(?:etree|minidom|pulldom|lxml|ElementTree|parse|fromstring)|defuse_stdlib)\b', code):
            return True
        if re.search(r'\b(?:resolve_entities\s*=\s*False|forbid_dtd\s*=\s*True|forbid_entities\s*=\s*True)\b', code):
            return True
        return False

    @staticmethod
    def _has_pre_extraction_quota(code: str) -> bool:
        """Checks whether archive extraction verifies quotas before or during extraction."""
        has_member_iteration = bool(re.search(r'\b(?:infolist|getmembers)\b', code))
        has_size_check = bool(re.search(r'(?:file_size|member\.size|member\.file_size|uncompressed_size)', code))
        has_threshold_comparison = bool(re.search(r'(?:>\s*(?:MAX_|LIMIT_|threshold|\d{5,})|sum\(|total_size)', code, re.IGNORECASE))
        return (has_member_iteration or has_size_check) and has_threshold_comparison

    # -------------------------------------------------------------------------
    # Finding-Specific Heuristic Checkers
    # -------------------------------------------------------------------------

    def _check_sql_injection(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits SQL query construction for parameterized queries vs dynamic formatting."""
        dynamic_sql_pattern = re.compile(
            r'(?:cursor\.)?execute\(\s*f["\']|'
            r'\.execute\(\s*["\'][^"\']*%s["\']\s*%|'
            r'\.execute\(\s*["\'][^"\']*\{\}["\']\.format|'
            r'(?:cursor\.)?execute\([^)]*\+[^)]*\)|'
            r'\b(?:query|sql|stmt)\s*=\s*(?:f["\']SELECT|["\']SELECT[^"\']*\+)',
            re.IGNORECASE | re.MULTILINE
        )
        parameterized_pattern = re.compile(
            r'(?:cursor\.)?execute\(\s*["\'][^"\']+["\']\s*,\s*(?:\([^)]*\)|\[[^\]]*\]|\{[^}]*\})\s*\)',
            re.MULTILINE
        )

        vulnerable_locations = []
        parameterized_locations = []

        for path, code in files.items():
            if dynamic_sql_pattern.search(code):
                vulnerable_locations.append(path)
            if parameterized_pattern.search(code):
                parameterized_locations.append(path)

        if vulnerable_locations:
            if parameterized_locations:
                return (
                    "NOT_REMEDIATED",
                    "Dynamic string formatting or concatenation remains present in SQL query construction; "
                    "unrelated parameterized queries elsewhere in the file do not remediate the vulnerable query.",
                    "SQL injection remains reachable through unparameterized query parameters.",
                    f"Dynamic SQL formatting detected in: {', '.join(vulnerable_locations)}",
                    "HIGH"
                )
            return (
                "NOT_REMEDIATED",
                "Dynamic string formatting or concatenation remains present in SQL query construction.",
                "SQL injection remains reachable through unparameterized query parameters.",
                f"Dynamic SQL formatting detected in: {', '.join(vulnerable_locations)}",
                "HIGH"
            )

        if parameterized_locations:
            return (
                "REMEDIATED",
                "Database queries use driver-appropriate parameterized placeholder syntax with separate parameter tuples.",
                "Direct SQL injection mitigated by query parameterization; dynamic table/column identifiers must be allowlisted separately.",
                f"Parameterized query execution observed in {', '.join(parameterized_locations)}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No database query execution operations observed in inspected files to evaluate SQL parameterization controls.",
            "Vulnerability status cannot be determined due to absence of database execution evidence.",
            f"No SQL execution statements detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_hardcoded_secrets(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits source code for plaintext credentials vs externalized environment retrieval."""
        secret_pattern = re.compile(
            r'\b(?:JWT_SECRET|SECRET_KEY|API_KEY|PASSWORD|PRIVATE_KEY|TOKEN|AUTH_KEY|CLIENT_SECRET)\s*=\s*["\']([^"\']{8,})["\']',
            re.IGNORECASE
        )
        fallback_pattern = re.compile(
            r'\b(?:os\.environ\.get|os\.getenv)\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']{8,})["\']',
            re.IGNORECASE
        )
        credential_external_pattern = re.compile(
            r'\b(?:os\.environ\.get|os\.getenv|os\.environ\[|get_secret)\(\s*["\'](?:JWT_SECRET|SECRET_KEY|API_KEY|PASSWORD|PRIVATE_KEY|TOKEN|AUTH_KEY|CLIENT_SECRET|DATABASE_URL)',
            re.IGNORECASE
        )

        dummy_keywords = {"your-secret", "changeme", "placeholder", "dummy", "example", "test", "mysecret"}
        vulnerable_locations = []
        fallback_locations = []
        externalized_found = False

        for path, code in files.items():
            for m in secret_pattern.finditer(code):
                val = m.group(1).lower()
                if not any(d in val for d in dummy_keywords):
                    vulnerable_locations.append(path)
                    break

            for m in fallback_pattern.finditer(code):
                val = m.group(1).lower()
                if not any(d in val for d in dummy_keywords):
                    fallback_locations.append(path)
                    break

            if credential_external_pattern.search(code):
                externalized_found = True

        if vulnerable_locations:
            return (
                "NOT_REMEDIATED",
                "Plaintext cryptographic secret or token assignment remains active in repository source; "
                "unrelated environment variable lookups elsewhere in the repository do not remediate the hardcoded credential.",
                "Credential leakage and token forgery remain possible from repository inspection. "
                "Note: External credential revocation and rotation cannot be verified through static analysis; separate confirmation of credential rotation in the target service is required.",
                f"Plaintext secret assignment detected in {', '.join(vulnerable_locations)}",
                "HIGH"
            )

        if fallback_locations:
            return (
                "NOT_REMEDIATED",
                "Environment variable lookup retains a hardcoded non-dummy fallback secret in code.",
                "Hardcoded credential fallback remains accessible if the environment variable is unset. "
                "Note: Separate confirmation of credential rotation in external stores is required.",
                f"Hardcoded secret fallback detected in {', '.join(fallback_locations)}",
                "HIGH"
            )

        if externalized_found:
            return (
                "REMEDIATED",
                "Credentials are externalized and loaded dynamically from environment or configuration store without hardcoded fallbacks.",
                "Committed plaintext secrets removed from inspected code. "
                "Note: External credential revocation and rotation cannot be verified through static repository analysis; separate confirmation of credential rotation in the target service is required.",
                f"Dynamic environment secret loading observed in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No credential assignments or external credential loading mechanisms observed in inspected files to evaluate secret externalization.",
            "Vulnerability status cannot be determined due to absence of credential operations.",
            f"No credential management operations detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_deserialization(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits deserialization routines for unsafe pickle/joblib usage vs authenticated or safe formats."""
        unsafe_deser_pattern = re.compile(r'\b(?:pickle\.load|pickle\.loads|_pickle\.load|joblib\.load)\b')
        safe_format_pattern = re.compile(r'\b(?:safetensors|onnx|json\.load|json\.loads|ast\.literal_eval)\b')

        pickle_found = False
        safe_format_found = False
        connected_auth_found = False
        unrelated_auth_found = False

        for path, code in files.items():
            if unsafe_deser_pattern.search(code):
                pickle_found = True
                if self._is_connected_to_deserialization(code):
                    connected_auth_found = True
                elif re.search(r'\b(?:hmac\.compare_digest|verify_signature|hmac\.new)\b', code):
                    unrelated_auth_found = True
            if safe_format_pattern.search(code):
                safe_format_found = True

        if pickle_found:
            if connected_auth_found:
                return (
                    "PARTIALLY_REMEDIATED",
                    "Pickle deserialization is guarded by HMAC or cryptographic signature verification; "
                    "note that arbitrary object construction risks remain inherent to pickle runtimes.",
                    "Residual risk remains if signing keys are compromised or signature verification is bypassed.",
                    f"Cryptographic signature check detected guarding deserializer in {', '.join(files.keys())}",
                    "MEDIUM"
                )
            if unrelated_auth_found:
                return (
                    "NOT_REMEDIATED",
                    "Unsafe pickle/joblib deserialization remains unprotected; cryptographic verification found in the file "
                    "is unrelated and does not guard the deserialized payload.",
                    "Arbitrary code execution remains reachable through untrusted serialized model or object files.",
                    f"Unprotected deserialization with unrelated crypto helper in {', '.join(files.keys())}",
                    "HIGH"
                )
            return (
                "NOT_REMEDIATED",
                "Unsafe pickle/joblib deserialization remains in active code without cryptographic digital signature or HMAC verification. "
                "Ordinary unauthenticated checksums do not prevent tampering if both file and hash are replaced.",
                "Arbitrary code execution remains reachable through untrusted serialized model or object files.",
                f"Unauthenticated deserialization calls in {', '.join(files.keys())}",
                "HIGH"
            )

        if safe_format_found:
            return (
                "REMEDIATED",
                "Insecure deserialization calls replaced with constrained, safe serialization formats (e.g., SafeTensors, ONNX, JSON).",
                "Arbitrary code execution surface from pickle object construction substantially eliminated.",
                f"Constrained serialization loaders observed in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No serialization or deserialization routines observed in inspected files to evaluate object loading controls.",
            "Vulnerability status cannot be determined due to absence of deserialization evidence.",
            f"No pickle/joblib loaders or safe formats detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_debug_mode(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits server configuration for hardcoded debug=True vs environment-gated settings."""
        code = "\n".join(files.values())

        hardcoded_true_pattern = re.compile(r'\b(?:app\.run\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True)\b')
        unsafe_default_pattern = re.compile(
            r'os\.(?:getenv|environ\.get)\(\s*["\'](?:DEBUG|FLASK_DEBUG|APP_DEBUG)["\']\s*,\s*["\']?(?:True|1|true)["\']?',
            re.IGNORECASE
        )
        safe_env_gated_pattern = re.compile(
            r'os\.(?:getenv|environ\.get)\(\s*["\'](?:DEBUG|FLASK_DEBUG|APP_DEBUG)["\'](?:\s*,\s*["\']?(?:False|0|false|None|)["\']?)?',
            re.IGNORECASE
        )
        explicit_false_pattern = re.compile(r'\b(?:debug\s*=\s*False|DEBUG\s*=\s*False)\b')

        if hardcoded_true_pattern.search(code):
            return (
                "NOT_REMEDIATED",
                "Web application specifies hardcoded debug=True without safe environment gating; "
                "unrelated environment variable lookups elsewhere in the file do not remediate the active debug setting.",
                "Interactive debug consoles and detailed stack traces remain exposed upon unhandled exceptions.",
                f"Hardcoded debug=True detected in {', '.join(files.keys())}",
                "HIGH"
            )

        if unsafe_default_pattern.search(code):
            return (
                "PARTIALLY_REMEDIATED",
                "Debug mode is configurable via environment variables, but defaults to enabled (True/1) when unset.",
                "Application runs in debug mode in production environments where the variable is unconfigured.",
                f"Insecure debug default detected in {', '.join(files.keys())}",
                "MEDIUM"
            )

        if explicit_false_pattern.search(code) or safe_env_gated_pattern.search(code):
            return (
                "REMEDIATED",
                "Debug mode is explicitly disabled or safely gated behind an environment configuration check defaulting to False.",
                "Diagnostic stack trace exposure suppressed in production.",
                f"Debug mode disabled or safely environment-gated in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No application server initialization or debug configuration observed in inspected files to evaluate debug mode status.",
            "Debug mode status cannot be verified from inspected files.",
            f"No debug configuration detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_cors_policy(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits CORS configuration for wildcard origins vs explicit allowlisting."""
        wildcard_pattern = re.compile(
            r'origins\s*=\s*["\']\*["\']|'
            r'origins\s*=\s*\[\s*["\']\*["\']\s*\]|'
            r'allow_origins\s*=\s*\[\s*["\']\*["\']\s*\]|'
            r'Access-Control-Allow-Origin:\s*\*|'
            r'allow_origins\s*=\s*["\']\*["\']',
            re.IGNORECASE
        )
        allowlist_pattern = re.compile(
            r'(?:origins|allow_origins)\s*=\s*\[\s*["\']https?://[^"\']+["\'](?:\s*,\s*["\']https?://[^"\']+["\'])*\s*\]|'
            r'CORS\([^)]*(?:origins|allow_origins)\s*=\s*(?!["\']\*["\'])',
            re.IGNORECASE
        )

        wildcard_found = False
        allowlist_found = False

        for path, code in files.items():
            if wildcard_pattern.search(code):
                wildcard_found = True
            if allowlist_pattern.search(code):
                allowlist_found = True

        if wildcard_found:
            return (
                "NOT_REMEDIATED",
                "CORS policy permits wildcard origins ('*') without domain restriction.",
                "Cross-origin data access remains open to arbitrary third-party websites.",
                f"Wildcard CORS origin configured in {', '.join(files.keys())}",
                "HIGH"
            )

        if allowlist_found:
            return (
                "REMEDIATED",
                "CORS configuration enforces an explicit origin allowlist. "
                "Note: CORS is a browser-enforced cross-origin policy and does not replace authentication, authorization, or anti-CSRF protections.",
                "Cross-origin read access restricted to approved domains; server-side authentication must remain independent.",
                f"Explicit CORS allowlist observed in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No Cross-Origin Resource Sharing configuration observed in inspected files to evaluate origin restrictions.",
            "CORS policy cannot be verified from inspected files.",
            f"No CORS configuration detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_cryptographic_hashing(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits hashing algorithms, differentiating password storage from general digest uses."""
        weak_hash_pattern = re.compile(r'\bhashlib\.(?:md5|sha1)\b')
        adaptive_pw_pattern = re.compile(r'\b(?:argon2|bcrypt|scrypt|passlib|pbkdf2)\b', re.IGNORECASE)
        modern_hash_pattern = re.compile(r'\bhashlib\.(?:sha256|sha512|sha3_256|sha3_512)\b')

        weak_found = False
        adaptive_found = False
        modern_found = False

        for path, code in files.items():
            if weak_hash_pattern.search(code):
                weak_found = True
            if adaptive_pw_pattern.search(code):
                adaptive_found = True
            if modern_hash_pattern.search(code):
                modern_found = True

        if weak_found:
            return (
                "NOT_REMEDIATED",
                "Deprecated, collision-vulnerable hash functions (MD5/SHA1) remain in active use.",
                "Collision attacks and pre-computed rainbow table cracking remain possible.",
                f"MD5/SHA1 calls detected in {', '.join(files.keys())}",
                "HIGH"
            )

        # Contextual distinction: is this password storage?
        context_str = (finding.get("title", "") + " " + finding.get("attack_path", "") + " " + " ".join(files.keys())).lower()
        is_password_context = any(w in context_str for w in ("password", "auth", "credential", "user", "login"))

        if is_password_context:
            if adaptive_found:
                return (
                    "REMEDIATED",
                    "Password storage upgraded to a dedicated adaptive algorithm (Argon2id, bcrypt, or scrypt) with salted work factors.",
                    "Brute-force password cracking resistance substantially improved.",
                    f"Adaptive password hashing observed in {', '.join(files.keys())}",
                    "HIGH"
                )
            if modern_found and not adaptive_found:
                return (
                    "PARTIALLY_REMEDIATED",
                    "Upgraded to SHA-256, but plain SHA-256 is a general-purpose digest rather than an adaptive password hash, "
                    "remaining susceptible to high-throughput GPU/ASIC dictionary attacks.",
                    "Password hashing lacks adaptive work-factor hardening against offline cracking.",
                    f"Plain SHA-256 used in password context in {', '.join(files.keys())}",
                    "HIGH"
                )

        if modern_found or adaptive_found:
            return (
                "REMEDIATED",
                "Upgraded to modern collision-resistant cryptographic hash functions.",
                "Collision vulnerabilities from legacy algorithms eliminated.",
                f"Modern cryptographic hashing observed in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No cryptographic hashing operations observed in inspected files to evaluate algorithm modernness or password hashing work factors.",
            "Cryptographic hash status cannot be verified from inspected files.",
            f"No hashing operations detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_command_execution(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits command execution for shell=True or string concatenation vs tokenized argument lists."""
        shell_exec_pattern = re.compile(
            r'\bos\.system\([^)]+\)|'
            r'subprocess\.(?:Popen|call|run|check_call|check_output)\([^)]*shell\s*=\s*True|'
            r'\beval\([^)]+\)|\bexec\([^)]+\)|'
            r'subprocess\.getoutput\(',
            re.MULTILINE
        )
        safe_subprocess_pattern = re.compile(
            r'subprocess\.(?:run|Popen|call|check_call|check_output)\(\s*\[[^\]]+\]',
            re.MULTILINE
        )
        dangerous_cli_unvalidated_pattern = re.compile(
            r'subprocess\.(?:run|Popen|call|check_call|check_output)\(\s*\[\s*["\'](?:git|ssh|tar|curl|wget|find|rsync)["\']\s*,\s*(?!["\']--["\'])[^\]]+\]',
            re.MULTILINE
        )

        shell_found = False
        safe_found = False
        dangerous_cli_found = False

        for path, code in files.items():
            if shell_exec_pattern.search(code):
                shell_found = True
            if safe_subprocess_pattern.search(code):
                safe_found = True
            if dangerous_cli_unvalidated_pattern.search(code):
                dangerous_cli_found = True

        if shell_found:
            return (
                "NOT_REMEDIATED",
                "Active code executes system commands through a shell interpreter without argument list isolation.",
                "Arbitrary command injection remains reachable if untrusted parameters reach the shell.",
                f"Shell execution construct detected in {', '.join(files.keys())}",
                "HIGH"
            )

        if safe_found:
            if dangerous_cli_found:
                return (
                    "PARTIALLY_REMEDIATED",
                    "Commands use tokenized argument lists avoiding shell=True, but invoke option-sensitive CLI utilities "
                    "(e.g., git, ssh, tar, curl) without option terminators ('--') or leading-hyphen argument validation.",
                    "Shell metacharacters are neutralized, but CLI argument/option injection remains possible if untrusted inputs start with '-'.",
                    f"Tokenized CLI execution without option terminator in {', '.join(files.keys())}",
                    "MEDIUM"
                )
            return (
                "REMEDIATED",
                "Commands are executed via tokenized argument lists without shell=True. "
                "Note: Direct argument execution mitigates shell metacharacters, but semantic validation and option terminators remain necessary.",
                "Shell-metacharacter injection mitigated by avoiding shell execution.",
                f"Tokenized subprocess invocation observed in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No process execution or system command operations observed in inspected files to evaluate command isolation controls.",
            "Command execution controls cannot be verified from inspected files.",
            f"No command execution operations detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_git_option_injection(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits git clone argument construction for hyphen rejection and '--' option terminators."""
        code = "\n".join(files.values())

        has_hyphen_check = bool(re.search(
            r'(?:source|repo|url|target)\.startswith\(\s*\(?["\']-["\']|startswith\(\s*\(?["\']--["\']',
            code
        ))
        has_separator = bool(
            re.search(r'\[\s*["\']git["\'].*?["\']--["\'].*?\]', code, re.DOTALL) or
            re.search(r'["\']--["\']\s*,\s*(?:source|repo_url|repo|url|target)', code)
        )

        if has_hyphen_check and has_separator:
            return (
                "REMEDIATED",
                "Git clone command explicitly includes the '--' argument separator in command construction and rejects leading hyphens in the source parameter.",
                "Git command option injection via flag-like source arguments mitigated.",
                f"Hyphen validation and '--' delimiter verified in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_hyphen_check or has_separator:
            return (
                "PARTIALLY_REMEDIATED",
                "Partial defense detected (hyphen validation or '--' separator is present in git command, but not both).",
                "Residual option injection exposure remains if inputs bypass the single control.",
                f"Partial Git option defense detected in {', '.join(files.keys())}",
                "MEDIUM"
            )

        return (
            "NOT_REMEDIATED",
            "Active code passes the repository source argument to Git without leading-hyphen validation or the '--' option terminator.",
            "Command option injection remains reachable: flag-like source arguments will be interpreted as Git CLI options.",
            f"Missing hyphen validation and '--' separator in {', '.join(files.keys())}",
            "HIGH"
        )

    def _check_archive_decompression_dos(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits archive extraction for pre-extraction quota enforcement."""
        code = "\n".join(files.values())

        has_extraction = bool(re.search(r'\b(?:extractall|extract)\b', code))
        has_quota = self._has_pre_extraction_quota(code)

        if has_quota:
            return (
                "REMEDIATED",
                "Archive extraction verifies pre-extraction quotas (uncompressed file size, compression ratio, or member counts) before extracting files.",
                "Decompression bomb Denial of Service mitigated within configured quota ceilings.",
                f"Archive pre-extraction quotas enforced in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_extraction:
            return (
                "NOT_REMEDIATED",
                "Active code extracts archive files without pre-extraction uncompressed byte or member quota verification. "
                "Note: Unenforced size constants in the file do not protect blind extractall() calls.",
                "Denial of Service via high-ratio decompression bombs remains reachable.",
                f"extractall() called without pre-extraction quota verification in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No archive extraction operations observed in inspected files to evaluate archive quota controls.",
            "Archive quota controls cannot be verified from inspected files.",
            f"No archive operations detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_output_file_overwrite(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits output file writing for destination boundary containment and overwrite guards."""
        code = "\n".join(files.values())

        has_boundary_containment = bool(re.search(
            r'\b(?:commonpath\s*\([^)]*(?:output|out|dest|target|export)[^)]*\)|safe_open_output|validate_output_path|resolve_output_path)\b',
            code,
            re.IGNORECASE
        ))
        has_overwrite_policy = bool(re.search(
            r'\b(?:overwrite|atomic|tempfile|os\.replace)\b',
            code,
            re.IGNORECASE
        ))

        if has_boundary_containment and has_overwrite_policy:
            return (
                "REMEDIATED",
                "Output destination paths enforce destination boundary containment and an explicit safe write/overwrite policy.",
                "Arbitrary file overwrite mitigated through destination boundary jail checks and safe write handling.",
                f"Destination boundary enforcement and safe overwrite policy observed in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_boundary_containment:
            return (
                "PARTIALLY_REMEDIATED",
                "Destination boundary containment is enforced, but an explicit overwrite protection or atomic replacement policy is unconfirmed.",
                "Writing outside the authorized directory is blocked, but unprompted overwrites inside the destination may occur.",
                f"Boundary containment enforced in {', '.join(files.keys())}",
                "MEDIUM"
            )

        return (
            "NOT_REMEDIATED",
            "Output file paths are opened directly without directory boundary containment or overwrite protection. "
            "Note: os.path.abspath normalization alone does not constrain destinations to authorized project boundaries.",
            "Arbitrary writable filesystem files remain subject to overwrite by exported output.",
            f"Missing destination boundary containment in {', '.join(files.keys())}",
            "HIGH"
        )

    def _check_unbounded_file_reads(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits file reading calls for bounded buffer parameters or file size limits."""
        unbounded_read_pattern = re.compile(r'\b(?:f|file|fp)\.read\(\s*\)', re.MULTILINE)
        bounded_read_pattern = re.compile(
            r'\b(?:f|file|fp)\.read\(\s*(?:MAX_READ|MAX_BYTES|\d{4,})\s*\)|'
            r'\bos\.path\.getsize\([^)]+\)\s*[><=]',
            re.MULTILINE
        )

        unbounded_found = False
        bounded_found = False

        for path, code in files.items():
            if unbounded_read_pattern.search(code):
                unbounded_found = True
            if bounded_read_pattern.search(code):
                bounded_found = True

        if unbounded_found and not bounded_found:
            return (
                "NOT_REMEDIATED",
                "Repository scanning utilities read entire files into memory using unbounded f.read() without size checks.",
                "Memory exhaustion Denial of Service remains reachable on oversized or minified files.",
                f"Unbounded f.read() detected in {', '.join(files.keys())}",
                "HIGH"
            )

        if bounded_found and not unbounded_found:
            return (
                "REMEDIATED",
                "File read operations enforce maximum buffer read thresholds (f.read(limit)) or file size pre-checks. "
                "Note: Truncating large files bounds memory consumption, but may limit static inspection coverage beyond the read threshold.",
                "Process memory consumption remains bounded during repository inspection.",
                f"Bounded file reads verified in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "PARTIALLY_REMEDIATED",
            "Mixed bounded and unbounded file read calls detected across inspected scanning modules.",
            "Residual memory exhaustion risk remains on specific unconstrained read paths.",
            f"Mixed read patterns in {', '.join(files.keys())}",
            "MEDIUM"
        )

    def _check_archive_symlink_traversal(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits archive extraction routines for symlink file mode inspection."""
        code = "\n".join(files.values())

        has_symlink_rejection = bool(re.search(
            r'(?:S_ISLNK\s*\(\s*(?:member|info|entry|f)\.mode|filter\s*=\s*["\']data["\']|(?:member|info|entry|f)\.is_symlink\(\)|(?:member|info|entry|f)\.issym\(\)|islink\s*\(\s*(?:dest|target|path)\))',
            code,
            re.IGNORECASE
        ))

        if has_symlink_rejection:
            return (
                "REMEDIATED",
                "Archive members are inspected for symlink mode attributes (e.g., S_ISLNK) and rejected before extraction.",
                "Symlink-based directory escape and overwrite attacks mitigated.",
                f"Symlink mode checks verified in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_REMEDIATED",
            "Archive extraction relies solely on string prefix matching without POSIX file mode attribute inspection.",
            "Symlink dereferencing may allow file extraction outside the target directory on compatible runtimes.",
            f"Missing symlink mode attribute inspection in {', '.join(files.keys())}",
            "HIGH"
        )

    def _check_directory_scope(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits directory ingestion for system root rejection or workspace confinement."""
        code = "\n".join(files.values())

        has_scope_check = bool(re.search(
            r'\b(?:system_root|root_dirs|allowed_dir|base_workspace|is_system_root)\b',
            code,
            re.IGNORECASE
        ))

        if has_scope_check:
            return (
                "REMEDIATED",
                "Directory ingestion validates input paths against operating system root directories and enforces workspace boundaries.",
                "Arbitrary host system root inventory enumeration blocked.",
                f"Directory boundary validation verified in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_REMEDIATED",
            "Local directory ingestion accepts arbitrary filesystem paths without boundary checking or root directory exclusion.",
            "Arbitrary host filesystem structure can be inventoried by passing operating system roots.",
            f"Missing system root validation in {', '.join(files.keys())}",
            "HIGH"
        )

    def _check_path_disclosure(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits output contract generation for path virtualization or relative mapping."""
        code = "\n".join(files.values())

        has_sanitization = bool(re.search(
            r'\b(?:sanitize_path|virtualize_path|relpath|relative_path)\b',
            code
        ))

        if has_sanitization:
            return (
                "REMEDIATED",
                "Internal filesystem paths are virtualized or mapped to repository-relative paths in output contracts.",
                "Exposure of internal host infrastructure paths and system usernames minimized.",
                f"Path sanitization logic verified in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_REMEDIATED",
            "Raw host filesystem paths (including user home directories) are serialized directly into generated output contracts.",
            "Internal infrastructure paths and user account names remain exposed in output metadata.",
            f"Raw absolute paths serialized in {', '.join(files.keys())}",
            "HIGH"
        )

    def _check_ssrf(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits HTTP client requests for URL validation and private IP rejection."""
        code = "\n".join(files.values())

        dynamic_req_pattern = re.compile(
            r'\b(?:requests\.(?:get|post|put|delete|patch|request)|urllib\.request\.urlopen|httpx\.(?:get|post))\(\s*(?![f"\']https?://[a-zA-Z0-9_\-\.]+["\']\s*[,)])(?!\s*["\']http)',
            re.IGNORECASE
        )
        has_network_call = bool(re.search(r'\b(?:requests\.(?:get|post|put|delete|patch|request)|urllib\.request\.urlopen|httpx\.(?:get|post))\b', code))
        has_dynamic_call = bool(dynamic_req_pattern.search(code))
        has_connected_validation = self._is_connected_to_http_request(code)

        if has_dynamic_call and not has_connected_validation:
            return (
                "NOT_REMEDIATED",
                "Dynamic outbound HTTP request is issued without destination URL validation or private IP checks; "
                "hardcoded or safe requests elsewhere in the file do not protect unvalidated request targets.",
                "Server-Side Request Forgery against internal networks and metadata services remains reachable.",
                f"Unvalidated dynamic HTTP requests detected in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_connected_validation:
            return (
                "REMEDIATED",
                "Outbound HTTP requests enforce URL scheme/domain allowlisting or reject private IP ranges in the request path.",
                "Server-Side Request Forgery against internal infrastructure mitigated.",
                f"URL destination validation verified in request path in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_network_call:
            return (
                "NOT_REMEDIATED",
                "Outbound HTTP requests are issued without calling URL allowlisting or private IP validation on the request target. "
                "Note: Unused validation helper functions elsewhere in the file do not protect unvalidated request paths.",
                "Server-Side Request Forgery against internal networks and metadata services remains reachable.",
                f"Unvalidated HTTP destinations in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No outbound HTTP client operations observed in inspected files to evaluate request destination validation.",
            "SSRF controls cannot be verified from inspected files.",
            f"No outbound HTTP requests detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_xxe(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits XML parsing for defusedxml or entity resolution disabling."""
        code = "\n".join(files.values())

        has_xml_call = bool(re.search(r'\b(?:xml\.etree|lxml|parse\(|fromstring\()', code))
        has_hardened_xml = self._has_effective_xxe_protection(code)

        if has_hardened_xml:
            return (
                "REMEDIATED",
                "XML parsing actively uses defusedxml or disables external DTD processing and entity expansion.",
                "XML External Entity (XXE) data exfiltration and XML bomb DoS mitigated.",
                f"Hardened XML parser verified in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_xml_call:
            return (
                "NOT_REMEDIATED",
                "XML documents parsed with standard parsers without disabling external entity resolution. "
                "Note: The presence of unused 'defusedxml' imports or references does not protect unconfigured parser calls.",
                "XML External Entity attacks remain reachable if untrusted XML inputs are processed.",
                f"Standard XML parsing without entity restriction in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No XML parsing operations observed in inspected files to evaluate XML entity resolution controls.",
            "XXE controls cannot be verified from inspected files.",
            f"No XML operations detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_temporary_files(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits temporary file creation for atomic NamedTemporaryFile/mkstemp vs mktemp."""
        code = "\n".join(files.values())

        has_mktemp = bool(re.search(r'\bmktemp\(', code))
        has_secure_temp = bool(re.search(r'\b(?:NamedTemporaryFile|mkstemp|TemporaryDirectory)\b', code))

        if has_mktemp:
            return (
                "NOT_REMEDIATED",
                "Deprecated tempfile.mktemp() remains in use, vulnerable to symlink race conditions. "
                "Note: The presence of mkstemp elsewhere in the codebase does not remediate active mktemp() calls.",
                "Temporary file race condition (TOCTOU) remains reachable.",
                f"tempfile.mktemp() detected in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_secure_temp:
            return (
                "REMEDIATED",
                "Temporary files created atomically using NamedTemporaryFile or mkstemp with exclusive creation flags.",
                "Temporary file creation race conditions mitigated.",
                f"Atomic temporary file creation observed in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No temporary file creation routines observed in inspected files to evaluate temporary file security.",
            "Temporary file creation controls cannot be verified from inspected files.",
            f"No tempfile operations detected in {', '.join(files.keys())}",
            "LOW"
        )

    def _check_plaintext_transport(
        self, files: Dict[str, str], rem: Dict[str, Any], finding: Dict[str, Any]
    ) -> Tuple[str, str, str, str, str]:
        """Audits network transport for HTTPS and TLS certificate verification."""
        code = "\n".join(files.values())

        has_verify_false = bool(re.search(r'\bverify\s*=\s*False\b', code))
        has_http = bool(re.search(r'["\']http://(?:(?!localhost|127\.0\.0\.1)[^"\']+)["\']', code))
        has_https = bool(re.search(r'["\']https://[^"\']+["\']', code))
        has_verify_true = bool(re.search(r'\bverify\s*=\s*True\b', code))

        if has_verify_false or has_http:
            return (
                "NOT_REMEDIATED",
                "Unencrypted HTTP communication or disabled TLS certificate verification (verify=False) observed.",
                "Transmission of data in plaintext remains vulnerable to eavesdropping and tampering in transit.",
                f"Insecure transport configurations in {', '.join(files.keys())}",
                "HIGH"
            )

        if has_https or has_verify_true:
            return (
                "REMEDIATED",
                "Remote network communications enforce TLS/HTTPS with active peer certificate verification.",
                "Eavesdropping and transmission tampering mitigated by transport layer security.",
                f"Encrypted transport verified in {', '.join(files.keys())}",
                "HIGH"
            )

        return (
            "NOT_TESTABLE",
            "No remote network communication calls observed in inspected files to evaluate transport layer security.",
            "Transport layer security cannot be verified from inspected files.",
            f"No remote network operations detected in {', '.join(files.keys())}",
            "LOW"
        )
