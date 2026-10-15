"""
Phase 4A: Blue Team White-Hat Defensive Security Agent.

Analyzes validated Red Team findings, identifies root causes, formulates minimal
effective remediations, identifies hardening measures, and performs regression risk assessments.
"""

import os
from typing import Any, Dict, List, Optional, Set, Tuple


class BlueTeamDefensiveAgent:
    """
    Agent that performs defensive analysis, root-cause identification, and remediation planning.

    Adheres to defensible security engineering principles:
    - Input validation: gracefully handles missing, malformed, or untyped findings.
    - Deterministic deduplication: merges findings with matching IDs, aggregating evidence
      and locations without inflating severity counts.
    - Accurate remediation guidance: provides technically nuanced, context-appropriate advice
      without unwarranted claims of absolute vulnerability elimination.
    - Non-destructive operation: proposes remediation plans without modifying project source files,
      executing system commands, or making external network requests.
    """

    SEVERITY_HIERARCHY = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }

    def __init__(
        self,
        root_path: str,
        phase1_reconstruction: Optional[Dict[str, Any]] = None,
        phase2_requirements: Optional[List[Dict[str, Any]]] = None,
        phase3a_findings: Optional[List[Dict[str, Any]]] = None,
    ):
        self.root_path = os.path.abspath(root_path) if root_path and isinstance(root_path, str) else os.getcwd()
        self.p1 = phase1_reconstruction if isinstance(phase1_reconstruction, dict) else {}
        self.p2_reqs = phase2_requirements if isinstance(phase2_requirements, list) else []
        self.raw_findings = phase3a_findings if isinstance(phase3a_findings, list) else []

    def analyze(self) -> Dict[str, Any]:
        """
        Executes defensive analysis, validates input findings, deduplicates by finding ID,
        and generates actionable remediation records.
        """
        validated_findings, invalid_count = self._validate_and_sanitize_findings(self.raw_findings)
        deduped_findings, duplicate_count = self._deduplicate_findings(validated_findings)

        remediation_plans: List[Dict[str, Any]] = []
        for finding in deduped_findings:
            plan = self._remediate_finding(finding)
            if plan:
                # Optionally attach Phase 1 / Phase 2 context if defensible
                context_info = self._resolve_context(finding)
                if context_info:
                    plan["context"] = context_info
                remediation_plans.append(plan)

        # Calculate severity summary strictly from unique, valid remediation plans
        summary_counts = {
            "critical": sum(1 for p in remediation_plans if p.get("severity") == "CRITICAL"),
            "high": sum(1 for p in remediation_plans if p.get("severity") == "HIGH"),
            "medium": sum(1 for p in remediation_plans if p.get("severity") == "MEDIUM"),
            "low": sum(1 for p in remediation_plans if p.get("severity") == "LOW"),
            "info": sum(1 for p in remediation_plans if p.get("severity") == "INFO"),
            "unknown": sum(1 for p in remediation_plans if p.get("severity") == "UNKNOWN"),
            "total_unique_plans": len(remediation_plans),
            "raw_findings_count": len(self.raw_findings),
            "duplicate_findings_count": duplicate_count,
            "invalid_findings_count": invalid_count,
        }

        return {
            "remediation_plans": remediation_plans,
            "total_plans": len(remediation_plans),
            "summary": summary_counts,
        }

    # -------------------------------------------------------------------------
    # Input Validation & Normalization
    # -------------------------------------------------------------------------

    def _validate_and_sanitize_findings(
        self, raw_list: List[Any]
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Validates raw findings, discarding non-dict or unidentifiable items deterministically.
        Returns a tuple of (valid_findings, invalid_count).
        """
        valid_findings: List[Dict[str, Any]] = []
        invalid_count = 0

        for item in raw_list:
            if not isinstance(item, dict):
                invalid_count += 1
                continue

            raw_fid = item.get("finding_id")
            if not isinstance(raw_fid, str) or not raw_fid.strip():
                invalid_count += 1
                continue

            fid = raw_fid.strip()

            # Sanitize affected_files
            raw_files = item.get("affected_files")
            affected_files: List[str] = []
            if isinstance(raw_files, list):
                for f in raw_files:
                    if isinstance(f, str) and f.strip():
                        affected_files.append(f.strip())
            elif isinstance(raw_files, str) and raw_files.strip():
                affected_files.append(raw_files.strip())

            # Normalize severity
            raw_sev = item.get("severity")
            if isinstance(raw_sev, str) and raw_sev.strip().upper() in self.SEVERITY_HIERARCHY:
                severity = raw_sev.strip().upper()
            else:
                severity = "UNKNOWN"

            # Normalize confidence
            raw_conf = item.get("confidence")
            if isinstance(raw_conf, str) and raw_conf.strip().upper() in {"HIGH", "MEDIUM", "LOW"}:
                confidence = raw_conf.strip().upper()
            else:
                confidence = "MEDIUM"

            # Sanitize evidence
            raw_ev = item.get("evidence")
            evidence_list: List[str] = []
            if isinstance(raw_ev, list):
                for e in raw_ev:
                    if isinstance(e, str) and e.strip():
                        evidence_list.append(e.strip())
            elif isinstance(raw_ev, str) and raw_ev.strip():
                evidence_list.append(raw_ev.strip())

            # Sanitize line numbers
            raw_lines = item.get("line_numbers") or item.get("line_number")
            line_numbers: List[int] = []
            if isinstance(raw_lines, list):
                for l in raw_lines:
                    if isinstance(l, int):
                        line_numbers.append(l)
            elif isinstance(raw_lines, int):
                line_numbers.append(raw_lines)

            # Preserve other optional string fields safely
            title = item.get("title") if isinstance(item.get("title"), str) else ""
            val_status = item.get("validation_status") if isinstance(item.get("validation_status"), str) else "UNVERIFIED"
            req_affected = item.get("requirement_affected") if isinstance(item.get("requirement_affected"), str) else "UNMAPPED"

            valid_findings.append({
                "finding_id": fid,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "affected_files": affected_files,
                "evidence": evidence_list,
                "line_numbers": sorted(list(set(line_numbers))),
                "validation_status": val_status,
                "requirement_affected": req_affected,
            })

        return valid_findings, invalid_count

    # -------------------------------------------------------------------------
    # Deduplication
    # -------------------------------------------------------------------------

    def _deduplicate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Deduplicates findings by finding_id, aggregating affected files, evidence, and line numbers.
        When conflicting severities occur, the highest severity in SEVERITY_HIERARCHY is retained.
        """
        deduped: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        duplicate_count = 0

        for f in findings:
            fid = f["finding_id"]
            if fid not in deduped:
                deduped[fid] = {
                    "finding_id": fid,
                    "title": f["title"],
                    "severity": f["severity"],
                    "confidence": f["confidence"],
                    "affected_files": list(f["affected_files"]),
                    "evidence": list(f["evidence"]),
                    "line_numbers": list(f["line_numbers"]),
                    "validation_status": f["validation_status"],
                    "requirement_affected": f["requirement_affected"],
                }
                order.append(fid)
            else:
                duplicate_count += 1
                curr = deduped[fid]

                # Update severity to the highest observed severity
                curr_rank = self.SEVERITY_HIERARCHY.get(curr["severity"], 99)
                new_rank = self.SEVERITY_HIERARCHY.get(f["severity"], 99)
                if new_rank < curr_rank:
                    curr["severity"] = f["severity"]

                # Aggregate affected files (preserving order, uniqueness)
                for path in f["affected_files"]:
                    if path not in curr["affected_files"]:
                        curr["affected_files"].append(path)

                # Aggregate evidence
                for ev in f["evidence"]:
                    if ev not in curr["evidence"]:
                        curr["evidence"].append(ev)

                # Aggregate line numbers
                combined_lines = set(curr["line_numbers"]).union(f["line_numbers"])
                curr["line_numbers"] = sorted(list(combined_lines))

                # If current title is empty and new title is present, preserve it
                if not curr["title"] and f["title"]:
                    curr["title"] = f["title"]

        return [deduped[fid] for fid in order], duplicate_count

    # -------------------------------------------------------------------------
    # Context Enrichment (Phase 1 & Phase 2)
    # -------------------------------------------------------------------------

    def _resolve_context(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Consults Phase 1 architecture and Phase 2 requirements only when an explicit,
        defensible relationship can be established. Never fabricates links.
        """
        context: Dict[str, Any] = {}
        affected = set(finding.get("affected_files", []))

        # Check Phase 1 entry points and APIs
        matching_eps = []
        raw_eps = self.p1.get("entry_points")
        if isinstance(raw_eps, list):
            for ep in raw_eps:
                if isinstance(ep, dict):
                    ep_path = ep.get("path") or ep.get("file")
                    if isinstance(ep_path, str) and ep_path in affected:
                        matching_eps.append(ep)
                elif isinstance(ep, str) and ep in affected:
                    matching_eps.append({"path": ep})

        matching_apis = []
        raw_apis = self.p1.get("apis")
        if isinstance(raw_apis, list):
            for api in raw_apis:
                if isinstance(api, dict):
                    api_file = api.get("file") or api.get("path")
                    if isinstance(api_file, str) and api_file in affected:
                        matching_apis.append(api)

        if matching_eps:
            context["exposed_entry_points"] = matching_eps
        if matching_apis:
            context["exposed_apis"] = matching_apis

        # Check Phase 2 requirements traceability
        req_id = finding.get("requirement_affected")
        if req_id and req_id != "UNMAPPED":
            for req in self.p2_reqs:
                if isinstance(req, dict) and req.get("id") == req_id:
                    context["associated_requirement"] = req
                    break

        return context if context else None

    # -------------------------------------------------------------------------
    # Remediation Plan Formulation
    # -------------------------------------------------------------------------

    def _remediate_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Formulates a defensible remediation plan for the given finding, providing
        accurate security advice, explicit security controls, and measurable testing criteria.
        """
        fid = finding["finding_id"]
        affected_files = finding.get("affected_files", [])
        severity = finding.get("severity", "UNKNOWN")
        confidence = finding.get("confidence", "HIGH")
        evidence = finding.get("evidence", [])
        line_numbers = finding.get("line_numbers", [])
        validation_status = finding.get("validation_status", "UNVERIFIED")

        # ---------------------------------------------------------------------
        # A. SQL Injection: RED-SQL-01
        # ---------------------------------------------------------------------
        if fid == "RED-SQL-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "SQL Injection via Dynamic Query Construction",
                "severity": severity,
                "root_cause": (
                    "Dynamic string formatting, interpolation, or concatenation in SQL query "
                    "construction mixes untrusted data with SQL command structure."
                ),
                "remediation": (
                    "Use parameterized queries or prepared statements separating SQL syntax from user values. "
                    "Note that placeholder syntax varies by database driver (? for SQLite, %s for PostgreSQL/MySQL, "
                    ":param for SQLAlchemy/named parameters). Furthermore, dynamic SQL identifiers (such as table "
                    "or column names) cannot be safely parameterized with ordinary value placeholders and require strict "
                    "server-side allowlist validation."
                ),
                "recommended_changes": [
                    "Replace dynamic string concatenation with driver-specific parameter placeholders: "
                    "e.g., cursor.execute('SELECT ... WHERE id = ?', (user_id,)) separating code from data.",
                    "For dynamic table or column identifiers, validate inputs against an explicit server-side allowlist "
                    "before constructing SQL queries.",
                ],
                "security_controls": [
                    "Parameterized SQL Queries",
                    "Prepared Statements",
                    "Identifier Allowlisting",
                ],
                "hardening_measures": [
                    "Adopt an Object-Relational Mapper (ORM) with schema-level validation.",
                    "Enforce database access credentials with the principle of least privilege, disabling administrative privileges.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Driver placeholder syntax variations must match the active database engine (? vs %s vs :name).",
                    "Allowlist validation may reject newly added valid database columns if schemas evolve without allowlist updates.",
                ],
                "testing_requirements": [
                    "Unit test passing SQL metacharacters (', --, OR 1=1) asserts parameters are treated strictly as literal data.",
                    "Unit test verifying unapproved table or column names are rejected by the identifier allowlist.",
                ],
                "expected_result_after_fix": (
                    "Parameterized queries separate query logic from data values; identifier allowlisting constrains "
                    "structural query changes, reducing SQL injection exposure upon comprehensive implementation."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # B. Hardcoded Secrets: RED-SECRET-01
        # ---------------------------------------------------------------------
        elif fid == "RED-SECRET-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Hardcoded Cryptographic Secret or Credential",
                "severity": severity,
                "root_cause": (
                    "Cryptographic signing keys, tokens, or database credentials committed directly to repository source code."
                ),
                "remediation": (
                    "Revoke and rotate the exposed credentials immediately across all environments. Externalize secrets into "
                    "a dedicated secrets management service (e.g., AWS Secrets Manager, HashiCorp Vault) or restricted environment variables. "
                    "Ensure secrets are excluded from version control (.gitignore) and prevent them from being logged. Note that moving a "
                    "secret to an environment variable alone does not provide complete protection against host compromise or process inspection."
                ),
                "recommended_changes": [
                    "Immediately revoke, invalidate, and rotate all exposed credentials.",
                    "Load secrets at application startup from an external secrets store or environment configuration with presence validation.",
                    "Add credential files, local configuration files (.env), and certificates to .gitignore.",
                ],
                "security_controls": [
                    "External Secret Management",
                    "Credential Revocation and Rotation",
                    "Log Redaction and Version-Control Exclusion",
                ],
                "hardening_measures": [
                    "Integrate automated secret-detection scanners (e.g., detect-secrets, git-secrets) into pre-commit hooks and CI pipelines.",
                    "Implement centralized secret rotation policies and use short-lived credentials where supported.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Deployment environments and local developer setups must configure the required credentials prior to startup.",
                ],
                "testing_requirements": [
                    "Verify the application fails to start safely in production when mandatory secret configuration is missing.",
                    "Confirm credential values are not exposed in application logs or exception stack traces.",
                ],
                "expected_result_after_fix": (
                    "Exposed credentials are invalidated, new secrets are externalized from source code, and version-control exclusion "
                    "prevents future credential leakage."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # C. Insecure Deserialization: RED-DESER-01
        # ---------------------------------------------------------------------
        elif fid == "RED-DESER-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Insecure Deserialization via pickle or joblib",
                "severity": severity,
                "root_cause": (
                    "Direct deserialization of pickle or joblib data from untrusted or unauthenticated sources permits arbitrary object construction."
                ),
                "remediation": (
                    "Never deserialize untrusted pickle or joblib data. For structured data or tensor weights, migrate to safer, constrained "
                    "serialization formats appropriate to the data type (e.g., JSON, Protocol Buffers, SafeTensors for model weights, or ONNX for "
                    "computational graphs). Where serialized artifacts must be loaded, establish authenticity before deserialization using a trusted "
                    "digital signature (asymmetric cryptography) or securely managed HMAC key; an ordinary unauthenticated SHA-256 checksum does not "
                    "establish trust, as an attacker with write access can replace both the artifact and checksum."
                ),
                "recommended_changes": [
                    "Migrate model artifacts to constrained, format-specific standards (e.g. SafeTensors for neural network weights) where applicable.",
                    "If pickle-based deserialization is strictly required, verify digital signatures or HMAC with protected keys prior to calling pickle/joblib.",
                    "Enforce strict filesystem write permissions on model storage directories.",
                ],
                "security_controls": [
                    "Constrained Serialization Formats",
                    "Cryptographic Authenticity Verification (Digital Signatures / HMAC)",
                    "Filesystem Write Access Control",
                ],
                "hardening_measures": [
                    "Run artifact loading and model inference in an isolated process sandbox with dropped privileges.",
                    "Audit model dependencies and enforce supply-chain artifact provenance.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Migrating serialization formats may require model re-export scripts and updates to downstream loaders.",
                    "Cryptographic signature verification requires key distribution and management infrastructure.",
                ],
                "testing_requirements": [
                    "Unit test verifying tampered or unsigned model artifacts fail authenticity verification and are not loaded.",
                    "Unit test verifying validly signed artifacts load correctly under the target runtime.",
                ],
                "expected_result_after_fix": (
                    "Untrusted serialized data is rejected prior to deserialization; adoption of constrained formats substantially reduces "
                    "remote code execution exposure."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # D. Password & Cryptographic Hashing: RED-CRYPTO-01
        # ---------------------------------------------------------------------
        elif fid == "RED-CRYPTO-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Weak Cryptographic Hashing Algorithm",
                "severity": severity,
                "root_cause": (
                    "Use of collision-vulnerable hash functions (MD5, SHA-1) for security-sensitive operations or password storage."
                ),
                "remediation": (
                    "Clearly distinguish password storage from general-purpose hashing. For password hashing, use a dedicated, adaptive "
                    "password-hashing algorithm such as Argon2id, bcrypt, or scrypt with appropriate salt generation and cost parameters; "
                    "plain SHA-256 is not an acceptable password hash. For non-password integrity verification, upgrade to modern collision-resistant "
                    "algorithms such as SHA-256 or SHA-512. For message authentication, use HMAC-SHA256 with a protected secret key."
                ),
                "recommended_changes": [
                    "For user passwords, migrate to Argon2id (via argon2-cffi) or bcrypt with per-password salts and calibrated work factors.",
                    "For non-password data integrity, replace hashlib.md5/sha1 with hashlib.sha256() or HMAC-SHA256.",
                ],
                "security_controls": [
                    "Adaptive Password Hashing (Argon2id/bcrypt)",
                    "Modern Collision-Resistant Hashes (SHA-256/SHA-512)",
                    "HMAC Authentication",
                ],
                "hardening_measures": [
                    "Implement an automatic password re-hashing workflow on user login to upgrade legacy hashes smoothly.",
                    "Periodically review and adjust work factor parameters to keep pace with hardware advancements.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Existing legacy password hashes must be verified and migrated upon subsequent user authentication.",
                ],
                "testing_requirements": [
                    "Unit test verifying new password hashes use the dedicated adaptive algorithm with valid salt and cost factors.",
                    "Unit test verifying legacy hash verification and upgrade workflows operate without regressions.",
                ],
                "expected_result_after_fix": (
                    "Password storage uses slow, salted adaptive functions resilient against brute-force attacks; non-password digests use "
                    "collision-resistant algorithms."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # E. Debug Mode Enabled: RED-DEBUG-01
        # ---------------------------------------------------------------------
        elif fid == "RED-DEBUG-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Debug Mode Enabled in Production Configuration",
                "severity": severity,
                "root_cause": (
                    "Web framework development server executed with debug=True, exposing interactive debug consoles and internal stack traces."
                ),
                "remediation": (
                    "Disable public debug consoles and detailed exception disclosure in production. Keep development and production "
                    "configurations strictly separate using environment-gated settings (e.g. debug=os.environ.get('APP_DEBUG', '').lower() == 'true') "
                    "defaulting to False. Deploy behind a production WSGI/ASGI server with sanitized generic error pages; note that a production "
                    "WSGI server alone does not eliminate underlying application security weaknesses."
                ),
                "recommended_changes": [
                    "Configure application debug mode to default to False unless explicitly enabled in trusted local development environments.",
                    "Implement global error handlers that return sanitized generic error responses to clients while logging details internally.",
                    "Deploy using a dedicated production WSGI/ASGI application server (e.g., Gunicorn, Uvicorn, Waitress).",
                ],
                "security_controls": [
                    "Environment Configuration Separation",
                    "Sanitized Error Handling",
                    "Production Application Server Deployment",
                ],
                "hardening_measures": [
                    "Disable interactive debugging consoles and profilers from network interfaces.",
                    "Centralize internal error logging with appropriate access controls and PII redaction.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Developers must explicitly set development environment flags during local troubleshooting sessions.",
                ],
                "testing_requirements": [
                    "Verify the application starts with debug mode disabled when configuration environment variables are unset.",
                    "Test simulated 500 server error response to confirm no sensitive stack trace or source code is returned to the client.",
                ],
                "expected_result_after_fix": (
                    "Detailed stack traces and interactive debug consoles are suppressed in production, mitigating diagnostic information leakage."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # F. Permissive CORS: RED-CORS-01
        # ---------------------------------------------------------------------
        elif fid == "RED-CORS-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Overly Permissive Cross-Origin Resource Sharing (CORS)",
                "severity": severity,
                "root_cause": (
                    "CORS configuration permits wildcard origins ('*') or unvalidated reflection, allowing unauthorized cross-origin requests."
                ),
                "remediation": (
                    "Define an explicit allowlist of trusted origins tailored to the application. Understand that CORS is a browser-enforced "
                    "cross-origin policy, not a replacement for authentication, authorization, or CSRF protections. Do not rely on the Referer header "
                    "as a security control, and avoid blindly trusting arbitrary environment-provided origin values without format validation."
                ),
                "recommended_changes": [
                    "Replace wildcard CORS origins with an explicit allowlist of authorized domain origins.",
                    "Validate request Origin headers against the allowlist before emitting Access-Control-Allow-Origin.",
                    "Ensure endpoints handling sensitive data enforce independent authentication, authorization, and anti-CSRF controls.",
                ],
                "security_controls": [
                    "Explicit Origin Allowlisting",
                    "Browser Cross-Origin Access Restriction",
                    "Independent Authentication & CSRF Controls",
                ],
                "hardening_measures": [
                    "Disallow 'Access-Control-Allow-Credentials: true' when wildcard or untrusted origins are configured.",
                    "Restrict allowed HTTP methods and request headers to the minimum necessary set.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Legitimate cross-origin frontend clients must be registered in the origin allowlist prior to communicating with API endpoints.",
                ],
                "testing_requirements": [
                    "Unit test asserting requests from allowlisted origins receive matching CORS headers.",
                    "Unit test asserting requests from untrusted origins do not receive permissive Access-Control-Allow-Origin headers.",
                ],
                "expected_result_after_fix": (
                    "Browser-based cross-origin read access is restricted to verified origins; server-side authentication and authorization "
                    "remain independently enforced."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # G. Command Execution: RED-CMD-01
        # ---------------------------------------------------------------------
        elif fid == "RED-CMD-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Arbitrary Command Execution via Shell Invocation",
                "severity": severity,
                "root_cause": (
                    "Executing system commands with shell=True or unvalidated parameters passed to command interpreters."
                ),
                "remediation": (
                    "Avoid shell execution by passing command arguments as an explicit token list with shell=False. Validate all arguments "
                    "according to their semantic role (e.g., path validation, integer ranges, token formats) rather than requiring every parameter "
                    "to be strictly alphanumeric. Note that avoiding a shell mitigates shell-metacharacter injection, but does not eliminate "
                    "argument/option injection, executable path manipulation, or logic flaws. Where commands support it, insert the '--' option "
                    "separator before positional arguments."
                ),
                "recommended_changes": [
                    "Use subprocess.run() with a list of arguments and shell=False, ensuring no shell interpreter parses dynamic strings.",
                    "Validate arguments against semantic rules appropriate to their data type.",
                    "Use '--' before positional user-provided arguments where the target utility supports option termination.",
                ],
                "security_controls": [
                    "Direct Executable Invocation (shell=False)",
                    "Semantic Argument Validation",
                    "Option Terminator ('--') Usage",
                ],
                "hardening_measures": [
                    "Specify absolute, trusted paths to invoked executables to prevent PATH manipulation.",
                    "Execute subprocesses with minimal privileges under a dedicated non-root service account.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Shell features (pipes, file redirection, globbing) are not available with shell=False and must be implemented via Python streams.",
                ],
                "testing_requirements": [
                    "Unit test passing shell metacharacters (; | & ` $ >) asserts they are treated as literal text and do not execute secondary commands.",
                    "Test validation logic to verify arguments with legitimate non-alphanumeric characters (such as dots or slashes) pass while injection payloads fail.",
                ],
                "expected_result_after_fix": (
                    "Direct subprocess invocation mitigates shell-metacharacter injection; semantic validation and option terminators constrain argument interpretation."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # H. Repository-Source Argument Injection: RED-INJ-01
        # ---------------------------------------------------------------------
        elif fid == "RED-INJ-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Command Option Injection via Repository Source Parameter",
                "severity": severity,
                "root_cause": (
                    "Git clone invocation passes user-controlled source parameter directly to subprocess.run without leading-hyphen "
                    "validation or positional argument disambiguation ('--' separator). Git interprets leading dashes as CLI flags."
                ),
                "remediation": (
                    "Validate that the repository source string does not begin with '-' or '--'. In the git clone command array, "
                    "place the standard '--' option separator immediately before the repository source argument to force Git to interpret "
                    "it as a positional argument. Validate URL schemes to permit only approved protocols (such as https://, ssh://, or http://), "
                    "and set GIT_TERMINAL_PROMPT=0 to prevent interactive hangs."
                ),
                "recommended_changes": [
                    "Validate repository source at function entry: reject strings beginning with '-' or '--' before invoking Git.",
                    "Format git clone arguments using the option separator: ['git', 'clone', '--depth', '1', '--', source_url, target_dir].",
                    "Set environment variable GIT_TERMINAL_PROMPT=0 and enforce allowed protocol schemes (e.g., https://, git@).",
                ],
                "security_controls": [
                    "Leading-Hyphen Input Rejection",
                    "Git Option Terminator ('--')",
                    "Protocol Scheme Allowlisting",
                ],
                "hardening_measures": [
                    "Execute git processes with non-interactive timeouts and bounded execution time.",
                    "Confine git clone operations to isolated scratch directories.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Valid repository URLs starting with standard protocols remain unaffected; only flag-like strings are blocked.",
                ],
                "testing_requirements": [
                    "Unit test verifying inputs starting with '--' or '-' raise immediate validation errors.",
                    "Unit test confirming standard HTTPS and SSH repository URLs clone successfully with the '--' separator in place.",
                ],
                "expected_result_after_fix": (
                    "Option-injection attempts via flag-style inputs are rejected before invocation; valid repository URLs are processed with positional separation."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # I. Archive Decompression Bomb: RED-DOS-01
        # ---------------------------------------------------------------------
        elif fid == "RED-DOS-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Archive Decompression Bomb (Zip Bomb) Vulnerability",
                "severity": severity,
                "root_cause": (
                    "Archive extraction blindly invokes extractall() without inspecting cumulative uncompressed file size, "
                    "compression ratio, or total entry counts across the archive infolist."
                ),
                "remediation": (
                    "Implement pre-extraction resource quotas: inspect archive metadata before extraction to enforce limits on total "
                    "uncompressed byte size, individual member uncompressed size, total member count, and maximum compression ratio. "
                    "Enforce path traversal checks to reject members with relative escapes (../) or absolute paths. Clean up partial extractions "
                    "and temporary directories within try...finally blocks."
                ),
                "recommended_changes": [
                    "Inspect archive member metadata before extracting: enforce limits such as MAX_TOTAL_SIZE, MAX_MEMBER_SIZE, MAX_ENTRIES, and MAX_RATIO.",
                    "Validate member paths to reject directory traversal and absolute path targets before writing any files.",
                    "Use try...finally constructs to ensure temporary extraction folders are cleaned up upon failure or cancellation.",
                ],
                "security_controls": [
                    "Archive Pre-Extraction Quota Checks",
                    "Member Path Traversal Rejection",
                    "Guaranteed Temporary Directory Cleanup",
                ],
                "hardening_measures": [
                    "Pass filter='data' where available on Python 3.12+ extraction APIs to benefit from standard-library security filters.",
                    "Stream extraction with running byte counters to guard against spoofed member metadata.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Legitimate archives that exceed configured size or member-count ceilings will be rejected unless thresholds are configurable.",
                ],
                "testing_requirements": [
                    "Unit test verifying archives exceeding member count or uncompressed byte ceilings trigger rejection before writing files.",
                    "Unit test confirming legitimate archives within quota limits extract successfully.",
                ],
                "expected_result_after_fix": (
                    "Pre-extraction resource quotas and path checks mitigate archive-based denial of service and extraction-time disk exhaustion."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # J. Unsafe Output Paths: RED-FILE-01
        # ---------------------------------------------------------------------
        elif fid == "RED-FILE-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Unrestricted Output File Overwrite",
                "severity": severity,
                "root_cause": (
                    "User-specified output path is opened directly without directory boundary validation or explicit overwrite protection, "
                    "allowing writes to arbitrary filesystem locations."
                ),
                "remediation": (
                    "Canonicalize the target path and enforce destination boundary containment (verifying the resolved path resides within an "
                    "authorized workspace or directory). Implement an explicit overwrite policy (requiring user confirmation or an overwrite flag). "
                    "Use safe file-writing practices, such as writing to a temporary file in the destination folder and atomically renaming, and set "
                    "appropriate file permissions. Account for symlink and TOCTOU risks during validation."
                ),
                "recommended_changes": [
                    "Canonicalize target paths using os.path.realpath() and verify containment within the authorized base directory using os.path.commonpath().",
                    "Require an explicit overwrite parameter or prompt before replacing existing files.",
                    "Write output atomically via a temporary file in the target directory followed by os.replace().",
                ],
                "security_controls": [
                    "Filesystem Destination Boundary Containment",
                    "Explicit Overwrite Policy",
                    "Atomic File Write & Replace",
                ],
                "hardening_measures": [
                    "Apply restrictive file permission modes (e.g., 0o600 or 0o644) on newly created output files.",
                    "Reject paths that resolve through symlinks pointing outside the authorized workspace.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Writing to paths outside the authorized workspace will be blocked unless explicitly permitted by configuration.",
                ],
                "testing_requirements": [
                    "Unit test verifying directory traversal attempts (e.g., ../../../etc/passwd) in output paths are rejected.",
                    "Unit test verifying safe output writing within an authorized directory succeeds.",
                ],
                "expected_result_after_fix": (
                    "Output operations are confined to authorized directory boundaries with atomic write handling, mitigating arbitrary overwrite risks."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # K. Unbounded File Reads: RED-DOS-02
        # ---------------------------------------------------------------------
        elif fid == "RED-DOS-02":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Unbounded File Read Leading to Memory Exhaustion",
                "severity": severity,
                "root_cause": (
                    "Static scanning utilities call f.read() on entire file contents without checking file size, allowing oversized or minified files "
                    "to cause excessive memory allocation."
                ),
                "remediation": (
                    "Implement bounded reads or streaming chunking, checking file size prior to reading. Establish sensible size ceilings (e.g., 1MB–5MB) "
                    "and exclude binary, minified, or auto-generated files from full static scanning. Acknowledge and communicate the operational "
                    "limitation that truncating large files may result in later patterns or vulnerabilities being missed."
                ),
                "recommended_changes": [
                    "Check os.path.getsize() prior to reading, skipping or applying bounded reads (f.read(MAX_READ_BYTES)) for textual analysis.",
                    "Stream files line-by-line where static analysis patterns allow.",
                    "Document and report any analysis coverage limitations when files are truncated or skipped.",
                ],
                "security_controls": [
                    "Bounded File Reads & Streaming",
                    "File Size Pre-Inspection",
                    "Analysis Coverage Limitation Reporting",
                ],
                "hardening_measures": [
                    "Detect and skip minified or single-line generated files with excessive line lengths.",
                    "Track aggregate byte budgets across scanning sessions to cap total memory and I/O consumption.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Files larger than the bounded threshold will only be partially inspected; static analysis may miss vulnerabilities located past the truncation boundary.",
                ],
                "testing_requirements": [
                    "Unit test asserting oversized files are read up to the configured byte limit without unbounded memory growth.",
                    "Verify coverage reporting records truncated files accurately.",
                ],
                "expected_result_after_fix": (
                    "Memory consumption remains bounded during static scanning; coverage limitations on truncated files are transparently recorded."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # L. Archive Symlinks: RED-FILE-02
        # ---------------------------------------------------------------------
        elif fid == "RED-FILE-02":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Archive Path Traversal via Symlink Manipulation",
                "severity": severity,
                "root_cause": (
                    "Archive member inspection checks filename path prefixes using string methods but does not inspect POSIX file mode "
                    "attributes in member.external_attr to detect symbolic link headers."
                ),
                "remediation": (
                    "Inspect archive member attributes before extraction (e.g. stat.S_ISLNK(member.external_attr >> 16) in ZIP files) "
                    "and reject any member containing symlink attributes or pointing outside the extraction boundary. On Python 3.12+, "
                    "utilize filter='data' for archive extraction APIs."
                ),
                "recommended_changes": [
                    "Inspect member.external_attr and reject members flagged as symbolic links with stat.S_ISLNK().",
                    "Post-extraction, verify extracted files do not resolve outside the extraction target directory.",
                ],
                "security_controls": [
                    "Archive Symlink Mode Rejection",
                    "Post-Extraction Boundary Verification",
                ],
                "hardening_measures": [
                    "Adopt Python 3.12+ extraction filters ('data' filter) where available.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Archives legitimately requiring internal symbolic links will be rejected; source archives typically do not require symlinks.",
                ],
                "testing_requirements": [
                    "Unit test verifying ZIP archives with symlink member attributes are rejected prior to extraction.",
                ],
                "expected_result_after_fix": (
                    "Archive symlink entries are identified and rejected, mitigating symlink-based directory escape and overwrite attacks."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # L2. Local Directory Traversal & Scope: RED-INFO-01
        # ---------------------------------------------------------------------
        elif fid == "RED-INFO-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Local Directory Traversal & Boundary Bypasses",
                "severity": severity,
                "root_cause": (
                    "Local directory ingestion accepts arbitrary filesystem paths without boundary checking, allowing analysis of sensitive system roots."
                ),
                "remediation": (
                    "Distinguish between intentional local CLI directory selection and unauthenticated service-level path ingestion. For CLI tools, "
                    "validate that the path exists, is a directory, and reject root or system-critical directories ('/' or 'C:\\'). For network-facing "
                    "services, confine directory ingestion to a configurable authorized workspace root."
                ),
                "recommended_changes": [
                    "Resolve input directory paths with os.path.realpath() and disallow operating system root directories.",
                    "For service environments, enforce that ingested directory paths reside strictly within an authorized base workspace.",
                ],
                "security_controls": [
                    "Filesystem Boundary Validation",
                    "System Root Exclusion",
                    "Configurable Workspace Confinement",
                ],
                "hardening_measures": [
                    "Provide an explicit workspace configuration option (--allowed-dir) for multi-tenant or server deployments.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Normal project directories remain accessible while system root paths are blocked.",
                ],
                "testing_requirements": [
                    "Unit test verifying legitimate workspace directories pass validation while system root paths are rejected.",
                ],
                "expected_result_after_fix": (
                    "Filesystem access is restricted from critical system roots and confined to intended project workspaces."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # L3. Path Disclosure: RED-INFO-02
        # ---------------------------------------------------------------------
        elif fid == "RED-INFO-02":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Information Disclosure via Internal Path Leaks",
                "severity": severity,
                "root_cause": (
                    "Emitting raw internal filesystem paths (including user home directories and system usernames) in generated output contracts "
                    "exposes internal infrastructure details."
                ),
                "remediation": (
                    "Minimize unnecessary host path disclosure by converting absolute filesystem paths to repository-relative or virtualized paths "
                    "in output reports, while preserving path information required by downstream pipeline consumers. Sanitize temporary directory paths "
                    "and usernames in public-facing outputs."
                ),
                "recommended_changes": [
                    "Convert host absolute paths to repository-relative paths where external output contracts do not require absolute filesystem references.",
                    "Sanitize username and temporary directory prefixes from generated report summaries.",
                ],
                "security_controls": [
                    "Path Virtualization and Relative Mapping",
                    "Internal Infrastructure Information Disclosure Minimization",
                ],
                "hardening_measures": [
                    "Provide consistent relative path mappings across all pipeline phase output contracts.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Downstream consumers requiring exact local filesystem paths must be accommodated or provided a clear mapping.",
                ],
                "testing_requirements": [
                    "Unit test verifying external contract summaries use relative or sanitized paths without raw username paths.",
                ],
                "expected_result_after_fix": (
                    "Diagnostic and report contracts minimize exposure of internal host paths and usernames."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # M1. SSRF Indicators: RED-SSRF-01
        # ---------------------------------------------------------------------
        elif fid == "RED-SSRF-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Server-Side Request Forgery (SSRF) Indicator",
                "severity": severity,
                "root_cause": (
                    "Performing HTTP requests to user-supplied URLs without destination validation permits Server-Side Request Forgery against internal infrastructure."
                ),
                "remediation": (
                    "Implement strict URL destination validation: parse target URLs, enforce an explicit allowlist of approved schemes (https://) "
                    "and hostnames/domains, and resolve hostnames to IP addresses before connecting. Reject private, loopback, and link-local IP addresses "
                    "(RFC 1918, RFC 3927, 127.0.0.0/8, ::1). Disable automatic HTTP redirect following or re-validate redirect destinations against the allowlist."
                ),
                "recommended_changes": [
                    "Validate URLs against an explicit domain allowlist before issuing network requests.",
                    "Resolve hostnames and reject requests targeting internal/private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16).",
                    "Disable automatic redirects or re-evaluate redirect locations against validation filters.",
                ],
                "security_controls": [
                    "URL Scheme & Domain Allowlisting",
                    "Private IP Range Rejection",
                    "Redirect Re-Validation",
                ],
                "hardening_measures": [
                    "Run outbound network services in an isolated network egress zone with restricted access to cloud metadata services.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Outbound requests to unlisted external domains or internal development services will be blocked.",
                ],
                "testing_requirements": [
                    "Unit test verifying URLs targeting loopback (127.0.0.1) or cloud metadata endpoints are rejected.",
                    "Unit test confirming requests to allowlisted domains succeed.",
                ],
                "expected_result_after_fix": (
                    "Outbound HTTP requests are restricted to approved external domains, mitigating internal service probing and metadata theft."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # M2. XXE Parsing: RED-XXE-01
        # ---------------------------------------------------------------------
        elif fid == "RED-XXE-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "XML External Entity (XXE) Parsing",
                "severity": severity,
                "root_cause": (
                    "Parsing XML documents with entity resolution or external DTD processing enabled permits XML External Entity (XXE) attacks."
                ),
                "remediation": (
                    "Disable external entity resolution, DTD processing, and entity expansion in all XML parsers. Alternatively, replace vulnerable "
                    "standard XML parsers with hardened libraries such as defusedxml (defusedxml.ElementTree, defusedxml.minidom)."
                ),
                "recommended_changes": [
                    "Replace standard xml.etree or lxml parsers with defusedxml equivalents.",
                    "If using lxml, explicitly configure XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False).",
                ],
                "security_controls": [
                    "Defused XML Parsing (defusedxml)",
                    "Disabling XML DTD and Entity Resolution",
                ],
                "hardening_measures": [
                    "Restrict parser memory and entity expansion depth to mitigate denial-of-service XML bomb attacks.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "XML documents legitimately relying on custom external DTDs or external entities must be restructured or parsed in isolated environments.",
                ],
                "testing_requirements": [
                    "Unit test asserting XML payloads with DOCTYPE ENTITY declarations are rejected or parsed without resolving external entities.",
                ],
                "expected_result_after_fix": (
                    "External entity resolution and entity expansion are disabled, mitigating XXE data exfiltration and denial of service."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # M3. Insecure Temporary Files: RED-TEMP-01
        # ---------------------------------------------------------------------
        elif fid == "RED-TEMP-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Insecure Temporary File Creation",
                "severity": severity,
                "root_cause": (
                    "Insecure temporary file creation (such as using tempfile.mktemp() or predictable file paths in world-writable directories) "
                    "creates race-condition vulnerabilities (symlink following, TOCTOU)."
                ),
                "remediation": (
                    "Use atomic and secure temporary file creation functions from the standard library, such as tempfile.NamedTemporaryFile() or "
                    "tempfile.mkstemp(), which open the file exclusively with restricted permissions (0o600). Never use deprecated tempfile.mktemp(). "
                    "Ensure temporary files are securely deleted using try...finally."
                ),
                "recommended_changes": [
                    "Replace tempfile.mktemp() with tempfile.NamedTemporaryFile(delete=True) or tempfile.mkstemp().",
                    "Wrap temporary file handling in context managers or try...finally blocks to ensure cleanup.",
                ],
                "security_controls": [
                    "Atomic Temporary File Creation",
                    "Exclusive File Creation Flags (O_CREAT | O_EXCL)",
                    "Restrictive File Permissions",
                ],
                "hardening_measures": [
                    "Use secure per-user temporary directories rather than shared system-wide directories where available.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Minimal risk; code using NamedTemporaryFile gains automatic creation and permission management.",
                ],
                "testing_requirements": [
                    "Unit test verifying temporary files are created with exclusive flags and restricted permissions without predictable name generation.",
                ],
                "expected_result_after_fix": (
                    "Temporary files are created atomically with restrictive permissions, mitigating symlink and race-condition vulnerabilities."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # M4. Plaintext Transport: RED-TLS-01
        # ---------------------------------------------------------------------
        elif fid == "RED-TLS-01":
            return {
                "finding_id": fid,
                "title": finding.get("title") or "Plaintext Transport Security Indicator",
                "severity": severity,
                "root_cause": (
                    "Transmission of sensitive data or credentials over unencrypted plaintext HTTP or disabling TLS certificate validation."
                ),
                "remediation": (
                    "Enforce TLS/HTTPS for all remote network communications. Configure HTTP client libraries (e.g., requests, urllib, httpx) "
                    "with certificate verification enabled (verify=True). Reject plaintext HTTP endpoints for external or credentialed communication."
                ),
                "recommended_changes": [
                    "Update remote endpoint URLs from http:// to https://.",
                    "Ensure verify=True (or valid CA bundle path) is configured for all HTTP client requests.",
                ],
                "security_controls": [
                    "Transport Layer Security (TLS/HTTPS)",
                    "Mandatory Certificate Verification",
                ],
                "hardening_measures": [
                    "Enforce modern TLS versions (TLS 1.2+ or TLS 1.3) and strong cipher suites.",
                    "Implement HTTP Strict Transport Security (HSTS) headers on web services.",
                ],
                "affected_files": affected_files,
                "regression_risks": [
                    "Legacy internal endpoints lacking valid TLS certificates will need certificates provisioned or designated CA roots.",
                ],
                "testing_requirements": [
                    "Unit test verifying outgoing requests enforce HTTPS and do not disable SSL/TLS certificate verification.",
                ],
                "expected_result_after_fix": (
                    "Network communications are encrypted in transit with verified peer certificates, protecting against eavesdropping and tampering."
                ),
                "confidence": confidence,
                "evidence": evidence,
                "line_numbers": line_numbers,
                "original_validation_status": validation_status,
            }

        # ---------------------------------------------------------------------
        # M5. Generic Fallback (for unmapped or unknown finding IDs)
        # ---------------------------------------------------------------------
        title_str = finding.get("title") if finding.get("title") else f"Uncategorized Security Finding ({fid})"
        return {
            "finding_id": fid,
            "title": title_str,
            "severity": severity,
            "root_cause": (
                f"Underlying security concern flagged in {title_str}. Requires manual source-level code review "
                "to confirm reachability and untrusted dataflow."
            ),
            "remediation": (
                "Review the flagged code construct against the reported evidence. Apply targeted input validation, "
                "boundary checking, and defensive error handling appropriate to the component architecture."
            ),
            "recommended_changes": [
                "Review the code location and evidence to confirm whether untrusted input reaches the affected operation.",
                "Implement defensive validation and principle-of-least-privilege controls tailored to the specific component.",
            ],
            "security_controls": [
                "Targeted Defensive Validation",
                "Manual Security Code Review",
            ],
            "hardening_measures": [
                "Document assumptions regarding data provenance and execution context.",
                "Implement automated regression tests covering expected and malformed inputs.",
            ],
            "affected_files": affected_files,
            "regression_risks": [
                "Low risk when guarded by automated test assertions and targeted code review.",
            ],
            "testing_requirements": [
                "Unit test covering legitimate operations and error-handling behavior for invalid inputs.",
            ],
            "expected_result_after_fix": (
                "The flagged construct is verified and guarded against unintended inputs, subject to source-level code review and empirical testing."
            ),
            "confidence": "LOW" if confidence == "LOW" else "MEDIUM",
            "evidence": evidence,
            "line_numbers": line_numbers,
            "original_validation_status": validation_status,
        }
