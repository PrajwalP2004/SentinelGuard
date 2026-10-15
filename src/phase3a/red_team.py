"""
Phase 3A: Red Team White-Hat Security Analysis Agent.

Performs authorized, repository-local static security assessment, attack-surface
reconnaissance, weakness auditing across 18 evaluation dimensions, and evidence-based
reachability validation.

Strict Operational Principles:
1. Repository-Local & Non-Destructive:
   Static analysis only. Does not execute malicious payloads, exploit external systems,
   or perform dynamic network testing.
2. Defensible Validation Model:
   Distinguishes suspicious patterns, plausible security concerns, and supported weaknesses.
   Never assigns 'CONFIRMED' solely based on regex matches, keyword presence, absence of defensive
   terms, or reconstructed metadata. Static analysis alone cannot certify runtime exploitability.
3. Filesystem Containment & Bounded Consumption:
   Enforces canonical path resolution, commonpath containment against directory traversal, and
   symlink escape rejection. Bounded binary reads strictly enforce per-file limit (5 MB) and
   aggregate repository byte budget (50 MB) before every read operation.
4. Context-Aware Detection:
   Audits call sites, argument construction, data provenance, and enclosing functions rather than
   relying on generic keyword presence.
5. Evidence-Preserving Deduplication:
   Merges duplicate findings targeting the same underlying weakness while retaining all affected
   locations, lines, and distinct evidence snippets without promoting confidence unsafely.
6. Defensible Requirement Mapping:
   Maps to Phase 2 requirements only when semantic alignment is supported by supplied records,
   defaulting to 'UNMAPPED'. Never fabricates requirement IDs.
7. Truthful Coverage Reporting:
   Accurately reports all 18 dimensions as CHECKED_HEURISTICALLY, PARTIALLY_ASSESSED, or
   INSUFFICIENT_INPUT, explicitly detailing executed checks and heuristic limitations.
"""

import ast
import os
import re
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple


class RedTeamSecurityAgent:
    """
    White-hat Red Team Security Analysis Agent.

    Performs attack surface reconnaissance, 18-dimension static weakness detection,
    defensible validation, and requirement traceability mapping.

    Validation Status Criteria:
    - CONFIRMED:
        Weakness, attacker-controlled source, reachability to dangerous sink, and lack of
        effective defense are all supported by concrete, location-specific code evidence.
        (Reserved for cases where static analysis establishes all necessary preconditions).
    - PROBABLE:
        Dangerous pattern or missing control observed with plausibly untrusted input, but full
        runtime reachability, environment configuration, or execution prerequisites cannot be
        proven statically.
    - POSSIBLE:
        Suspicious construct or risky API observed, but provenance of data, execution context,
        or deployment environment is unknown or ambiguous. Manual review required.
    - INSUFFICIENT_EVIDENCE:
        Potential security concern flagged, but code is truncated, missing, or lacks sufficient
        context to assess risk.
    - FALSE_POSITIVE:
        Analyzed construct determined to be benign (e.g. static literal, test fixture, intentional
        CLI operator feature, or non-security cache digest).

    Confidence Levels:
    - HIGH: Direct code evidence at call site with identified arguments and enclosing context.
    - MEDIUM: Pattern detected with heuristic context; exact dataflow cannot be verified statically.
    - LOW: Inferred or generic surface indicator without direct call-site evidence.

    Severity Levels:
    - CRITICAL: Arbitrary command execution, remote code execution, or unrestricted system file overwrite.
    - HIGH: SQL injection, credential leakage, or high-volume denial of service.
    - MEDIUM: Resource exhaustion, XXE, SSRF indicator, or race-condition temporary file creation.
    - LOW: Permissive CORS without credentials, internal path leakage in metadata, or non-security weak hashing.
    - INFO: Informational findings or hardening observations.
    """

    MAX_INSPECT_FILE_SIZE = 5 * 1024 * 1024       # 5 MB per-file inspection limit
    MAX_TOTAL_INSPECT_BYTES = 50 * 1024 * 1024   # 50 MB aggregate byte budget
    MAX_INSPECT_FILES = 500                      # Maximum repository files to inspect

    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    VALIDATION_STATUS_ORDER = {
        "CONFIRMED": 0,
        "PROBABLE": 1,
        "POSSIBLE": 2,
        "INSUFFICIENT_EVIDENCE": 3,
        "FALSE_POSITIVE": 4,
    }

    # Declarative definition of all 18 security evaluation dimensions
    DIMENSION_DEFINITIONS = [
        {"dimension_id": 1, "name": "Command & Subprocess Option Injection", "category": "Injection", "rules": ["Git clone '--' delimiter", "Subprocess argument sanitization"]},
        {"dimension_id": 2, "name": "SQL Injection & Dynamic Query Formatting", "category": "Injection", "rules": ["Parameterized query verification", "Dynamic SQL concatenation check"]},
        {"dimension_id": 3, "name": "Arbitrary Shell Command Execution", "category": "Injection", "rules": ["os.system dynamic arguments", "subprocess shell=True quoting"]},
        {"dimension_id": 4, "name": "Insecure Object Deserialization", "category": "Remote Code Execution", "rules": ["pickle.load provenance", "joblib.load unpickling"]},
        {"dimension_id": 5, "name": "Archive Decompression Bomb (Zip Bomb)", "category": "File Handling", "rules": ["ZipFile uncompressed size check", "Member count limits"]},
        {"dimension_id": 6, "name": "Archive Path Traversal & Symlink Attacks", "category": "File Handling", "rules": ["Extraction destination commonpath", "Symlink mode rejection"]},
        {"dimension_id": 7, "name": "Unrestricted Output File Overwrite", "category": "Access Control", "rules": ["Service destination jail check", "CLI output distinction"]},
        {"dimension_id": 8, "name": "Overly Permissive CORS Configuration", "category": "Access Control", "rules": ["Wildcard origin audit", "Credentialed CORS verification"]},
        {"dimension_id": 9, "name": "Unbounded Resource Consumption & DoS", "category": "Denial of Service", "rules": ["Call-site bounded read check", "File size validation"]},
        {"dimension_id": 10, "name": "Hardcoded Secrets & Cryptographic Keys", "category": "Information Disclosure", "rules": ["High-entropy credential audit", "Token redaction"]},
        {"dimension_id": 11, "name": "Information Disclosure via Path Leaks", "category": "Information Disclosure", "rules": ["Host root path leakage", "Output contract containment"]},
        {"dimension_id": 12, "name": "Local Directory Traversal & Boundary Bypasses", "category": "Access Control", "rules": ["Directory jail enforcement", "Local directory selection"]},
        {"dimension_id": 13, "name": "Debug Mode Enabled in Production", "category": "Configuration", "rules": ["app.run debug parameter check", "Environment guard verification"]},
        {"dimension_id": 14, "name": "Weak Cryptographic Hashing Algorithms", "category": "Cryptography", "rules": ["MD5/SHA-1 password use", "Cache key distinction"]},
        {"dimension_id": 15, "name": "Server-Side Request Forgery (SSRF) Indicators", "category": "Network Security", "rules": ["Dynamic HTTP destination check", "URL allowlist audit"]},
        {"dimension_id": 16, "name": "XML External Entity (XXE) Parsing", "category": "XML Parsing", "rules": ["XML parser entity resolution", "defusedxml verification"]},
        {"dimension_id": 17, "name": "Insecure Temporary File Creation", "category": "File Handling", "rules": ["tempfile.mktemp usage", "Non-atomic open check"]},
        {"dimension_id": 18, "name": "Plaintext Transport Security Indicators", "category": "Transport Security", "rules": ["Plaintext HTTP URL check", "Localhost exclusion"]},
    ]

    def __init__(
        self,
        root_path: str,
        phase0_inventory: Optional[Dict[str, Any]] = None,
        phase1_reconstruction: Optional[Dict[str, Any]] = None,
        phase2_requirements: Optional[List[Dict[str, Any]]] = None,
    ):
        self.root_path = os.path.abspath(root_path) if root_path else os.getcwd()
        self.p0 = phase0_inventory if isinstance(phase0_inventory, dict) else {}
        self.p1 = phase1_reconstruction if isinstance(phase1_reconstruction, dict) else {}
        self.p2_reqs = phase2_requirements if isinstance(phase2_requirements, list) else []

        # Safe extraction of Phase 0 inventory collections
        self.source_files = self._extract_path_list(self.p0.get("source_files"))
        self.doc_files = self._extract_path_list(self.p0.get("documentation_files"))
        self.dep_files = self._extract_path_list(self.p0.get("dependency_files"))
        self.config_files = self._extract_path_list(self.p0.get("configuration_files"))
        self.infra_files = self._extract_path_list(self.p0.get("infrastructure_files"))
        self.entry_point_candidates = self._extract_path_list(self.p0.get("entry_point_candidates"))

        # Safe extraction of Phase 1 reconstruction collections
        self.entry_points = self.p1.get("entry_points") if isinstance(self.p1.get("entry_points"), list) else []
        self.apis = self.p1.get("apis") if isinstance(self.p1.get("apis"), list) else []
        self.trust_boundaries = self.p1.get("trust_boundaries") if isinstance(self.p1.get("trust_boundaries"), list) else []
        self.data_flows = self.p1.get("data_flows") if isinstance(self.p1.get("data_flows"), list) else []
        self.auth_components = self.p1.get("authentication_components") if isinstance(self.p1.get("authentication_components"), list) else []

        self.skipped_files: List[Dict[str, str]] = []
        self.inspected_bytes = 0
        self.inspected_files_count = 0

    @staticmethod
    def _extract_path_list(raw_list: Any) -> List[Dict[str, Any]]:
        """Normalizes inventory items into a uniform list of dicts with a 'path' key."""
        items: List[Dict[str, Any]] = []
        if not isinstance(raw_list, list):
            return items
        for entry in raw_list:
            if isinstance(entry, str) and entry.strip():
                items.append({"path": entry.strip()})
            elif isinstance(entry, dict):
                p = entry.get("path") or entry.get("file") or entry.get("name") or ""
                if isinstance(p, str) and p.strip():
                    items.append(dict(entry, path=p.strip()))
        return items

    def analyze(self) -> Dict[str, Any]:
        """
        Executes Phase 3A: Reconnaissance, Security Analysis, Validation, and Coverage Evaluation.
        """
        attack_surface = self.reconnaissance()
        findings = self.security_analysis()
        validated_findings = self.validate_findings(findings)

        # Build honest evaluation dimension coverage report
        evaluation_dimensions = self._build_dimension_coverage(validated_findings)

        # Summary counts must match exactly the final validated findings
        summary_counts = {
            "total_findings": len(validated_findings),
            "confirmed": sum(1 for f in validated_findings if f.get("validation_status") == "CONFIRMED"),
            "probable": sum(1 for f in validated_findings if f.get("validation_status") == "PROBABLE"),
            "possible": sum(1 for f in validated_findings if f.get("validation_status") == "POSSIBLE"),
            "false_positive": sum(1 for f in validated_findings if f.get("validation_status") == "FALSE_POSITIVE"),
            "insufficient_evidence": sum(1 for f in validated_findings if f.get("validation_status") == "INSUFFICIENT_EVIDENCE"),
        }

        return {
            "attack_surface_map": attack_surface,
            "findings": validated_findings,
            "evaluation_dimensions": evaluation_dimensions,
            "skipped_files": list(self.skipped_files),
            "inspected_files_count": self.inspected_files_count,
            "inspected_bytes": self.inspected_bytes,
            "summary": summary_counts,
            "disclaimer": (
                "Static-analysis results are heuristic and do not constitute a formal penetration test or security certification. "
                "A clean scan indicates no findings were detected by implemented checks; it does not guarantee absence of vulnerabilities. "
                "Missing evidence is not proof of security."
            )
        }

    # -------------------------------------------------------------------------
    # PHASE A: Reconnaissance & Attack Surface Mapping
    # -------------------------------------------------------------------------
    def reconnaissance(self) -> Dict[str, Any]:
        """Discovers and maps the application attack surface from validated Phase 0/1 evidence."""
        entry_point_list = []
        for ep in self.entry_points:
            if isinstance(ep, dict):
                entry_point_list.append({
                    "type": ep.get("type", "entry_point"),
                    "description": ep.get("description", ""),
                    "files": [p for p in ep.get("supporting_file_paths", []) if isinstance(p, str)]
                })

        user_inputs = [
            {"parameter": "CLI flags (--source, --source-type, --phase, --output)", "channel": "Process Command Line"},
            {"parameter": "Repository contents (source files, manifests)", "channel": "Filesystem / Ingestion"}
        ]
        if self.apis:
            user_inputs.append({"parameter": "HTTP request body, headers, query parameters", "channel": "REST Ingress"})

        boundaries = [b.get("boundary", "General Boundary") for b in self.trust_boundaries if isinstance(b, dict)]

        return {
            "application_entry_points": entry_point_list,
            "api_endpoints": self.apis,
            "authentication_endpoints": [a.get("mechanism") for a in self.auth_components if isinstance(a, dict) and a.get("mechanism")],
            "authorization_boundaries": boundaries,
            "user_controlled_inputs": user_inputs,
            "file_handling_surfaces": ["Archive extraction", "Filesystem recursive walk", "Output file write"],
            "database_interactions": [db.get("type", "Database") for db in self.p1.get("databases", []) if isinstance(db, dict)],
            "external_services": [s.get("name", "External Service") for s in self.p1.get("external_services", []) if isinstance(s, dict)],
            "secrets_handling": [s.get("path") for s in self.p0.get("potentially_sensitive_files", []) if isinstance(s, dict) and s.get("path")],
            "network_facing_components": [r.get("path") for r in self.apis if isinstance(r, dict) and r.get("path")],
            "administrative_functionality": ["CLI execution dispatcher"]
        }

    # -------------------------------------------------------------------------
    # Corpus Loader: Filesystem Containment & Bounded Aggregate Budget
    # -------------------------------------------------------------------------
    def _read_source_corpus(self) -> Dict[str, str]:
        """
        Loads repository source files with strict containment and bounded resource limits.

        Enforces:
        - Canonical path resolution and commonpath check against repository root.
        - Rejection of symlinks that point outside the repository.
        - Per-file inspection limit (5 MB).
        - Maximum file count limit (500 files).
        - Aggregate byte budget (50 MB) calculated BEFORE every read to prevent budget overflow.
        - Controlled decoding without unbounded memory expansion.
        """
        corpus: Dict[str, str] = {}
        seen_paths: Set[str] = set()
        self.inspected_bytes = 0
        self.inspected_files_count = 0

        all_candidates = self.source_files + self.entry_point_candidates
        real_root = os.path.realpath(self.root_path)

        for s in all_candidates:
            rel = s.get("path")
            if not rel or not isinstance(rel, str):
                continue

            cleaned_rel = rel.replace("\\", "/").strip()
            if cleaned_rel in seen_paths:
                continue
            seen_paths.add(cleaned_rel)

            # Avoid analyzing the security agent's own implementation files if run in self-repo
            if any(cleaned_rel.startswith(p) for p in ("src/phase3a/", "src/phase4a/", "src/phase5a/")):
                continue

            # Resolve canonical path and verify containment within root_path
            try:
                if os.path.isabs(cleaned_rel):
                    candidate_path = os.path.abspath(cleaned_rel)
                else:
                    candidate_path = os.path.abspath(os.path.join(self.root_path, cleaned_rel))

                real_candidate = os.path.realpath(candidate_path)

                # Robust containment check via commonpath (catches ../ traversal and absolute path escapes)
                if os.path.commonpath([real_root, real_candidate]) != real_root:
                    self.skipped_files.append({"path": cleaned_rel, "reason": "Path traversal or outside repository root"})
                    continue
            except (ValueError, Exception):
                self.skipped_files.append({"path": cleaned_rel, "reason": "Cross-drive or malformed path outside repository root"})
                continue

            # Check symlink containment explicitly
            if os.path.islink(candidate_path):
                try:
                    symlink_target = os.path.realpath(candidate_path)
                    if os.path.commonpath([real_root, symlink_target]) != real_root:
                        self.skipped_files.append({"path": cleaned_rel, "reason": "Symlink points outside repository root"})
                        continue
                except (ValueError, Exception):
                    self.skipped_files.append({"path": cleaned_rel, "reason": "Symlink resolves outside root"})
                    continue

            # Ensure candidate is an existing regular file
            if not os.path.isfile(real_candidate):
                continue

            # Enforce aggregate file count budget
            if self.inspected_files_count >= self.MAX_INSPECT_FILES:
                self.skipped_files.append({"path": cleaned_rel, "reason": "Aggregate file count budget exceeded (max 500 files)"})
                break

            # Calculate remaining aggregate byte budget BEFORE read
            remaining_aggregate = self.MAX_TOTAL_INSPECT_BYTES - self.inspected_bytes
            if remaining_aggregate <= 0:
                self.skipped_files.append({"path": cleaned_rel, "reason": "Aggregate byte budget exceeded (max 50 MB)"})
                break

            # Calculate the maximum allowed bytes for this file
            max_allowed_for_file = min(self.MAX_INSPECT_FILE_SIZE, remaining_aggregate)

            # Read max_allowed_for_file + 1 bytes to detect truncation / limit violations
            try:
                with open(real_candidate, "rb") as f:
                    raw_bytes = f.read(max_allowed_for_file + 1)

                # If read exceeds per-file limit (5 MB), skip file
                if len(raw_bytes) > self.MAX_INSPECT_FILE_SIZE:
                    self.skipped_files.append({"path": cleaned_rel, "reason": "File size exceeds 5MB per-file inspection limit"})
                    continue

                # If read exceeds remaining aggregate budget, record skip and stop
                if len(raw_bytes) > remaining_aggregate:
                    self.skipped_files.append({"path": cleaned_rel, "reason": f"Reading file would exceed aggregate byte budget ({remaining_aggregate} bytes remaining)"})
                    break

                # File accepted
                decoded_content = raw_bytes.decode("utf-8", errors="ignore")
                corpus[cleaned_rel] = decoded_content
                self.inspected_bytes += len(raw_bytes)
                self.inspected_files_count += 1

            except (PermissionError, OSError):
                self.skipped_files.append({"path": cleaned_rel, "reason": "Permission denied or OS read failure"})
                continue
            except Exception:
                self.skipped_files.append({"path": cleaned_rel, "reason": "Unexpected read failure"})
                continue

        return corpus

    # -------------------------------------------------------------------------
    # Context Helpers: Call-Site Inspection & Safe Redaction
    # -------------------------------------------------------------------------
    @staticmethod
    def _find_match_context(content: str, match_pos: int) -> Tuple[int, str, str]:
        """Returns (line_number, enclosing_function, code_snippet) for a given character index."""
        line_no = content[:match_pos].count("\n") + 1
        lines = content.splitlines()
        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""

        func_name = "module_level"
        for i in range(min(line_no - 1, len(lines) - 1), -1, -1):
            m = re.match(r'^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', lines[i])
            if m:
                func_name = m.group(1)
                break
            m_cls = re.match(r'^\s*class\s+([a-zA-Z_][a-zA-Z0-9_]*)\b', lines[i])
            if m_cls and func_name == "module_level":
                func_name = f"{m_cls.group(1)}.class_scope"

        return line_no, func_name, snippet

    @staticmethod
    def _redact_secret(val: str) -> str:
        """Safely redacts a sensitive token without revealing its full value."""
        if len(val) <= 6:
            return "[REDACTED]"
        return f"{val[:2]}...[REDACTED:{len(val)} chars]...{val[-2:]}"

    # -------------------------------------------------------------------------
    # PHASE B: 18-Dimension Security Analysis
    # -------------------------------------------------------------------------
    def security_analysis(self) -> List[Dict[str, Any]]:
        """Evaluates code across 18 security dimensions and identifies candidates."""
        candidates: List[Dict[str, Any]] = []
        code_corpus = self._read_source_corpus()

        # Dimension 1-4: Injection & Subprocess / Deserialization
        candidates.extend(self._audit_injection_risks(code_corpus))

        # Dimension 5-6: Archive Handling (Decompression bombs, symlink traversal)
        candidates.extend(self._audit_file_handling(code_corpus))

        # Dimension 7-8: Access Control & Overwrite / CORS
        candidates.extend(self._audit_access_control(code_corpus))

        # Dimension 9: Input Validation & Memory / DoS Risks
        candidates.extend(self._audit_input_validation_and_dos(code_corpus))

        # Dimension 10-11: Secrets & Information Disclosure
        candidates.extend(self._audit_information_disclosure(code_corpus))

        # Dimension 12-13: Authentication / Local Directories & Debug Mode
        candidates.extend(self._audit_auth_and_boundaries(code_corpus))

        # Dimension 14: Cryptography & Logging
        candidates.extend(self._audit_logging_and_errors(code_corpus))

        # Dimension 15-18: Extended Security Dimensions
        candidates.extend(self._audit_extended_dimensions(code_corpus))

        return candidates

    # --- Dimension 1 to 4: Injection & Deserialization ---
    def _audit_injection_risks(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            is_test_file = any(k in file_path.lower() for k in ("test_", "tests/"))

            # 1. Git Subprocess Option Injection (Dimension 1)
            # Evaluates subprocess invocation with git clone, argument structure, and option delimiters
            if "git" in content and "clone" in content and any(k in content for k in ("subprocess", "Popen", "run", "call", "check_call")):
                clone_match = re.search(r'subprocess\.(?:Popen|run|call|check_call)\(\s*(\[[^\]]+\]|[^,\)]+)', content)
                if clone_match:
                    args_text = clone_match.group(1)
                    has_double_dash = '"--"' in args_text or "'--'" in args_text or '["--"]' in content or "['--']" in content
                    has_hyphen_guard = 'startswith("-")' in content or "startswith('-')" in content or 'startswith(("-", "--"))' in content

                    # Safe if arguments explicitly terminate options with '--' or sanitize leading hyphens
                    if not (has_double_dash or has_hyphen_guard):
                        line_no, func_name, snippet = self._find_match_context(content, clone_match.start())
                        findings.append({
                            "finding_id": "RED-INJ-01",
                            "category": "Injection",
                            "title": "Subprocess Option Injection via Unsanitized Git Clone Parameter",
                            "severity": "CRITICAL",
                            "confidence": "HIGH" if not is_test_file else "MEDIUM",
                            "affected_files": [file_path],
                            "affected_functions": [func_name],
                            "line_number": line_no,
                            "attack_surface": "CLI --source argument or Git Clone Ingestion",
                            "attacker_controlled_input": "source parameter passed to git clone command",
                            "security_boundary": "Application Process -> External Git Subprocess",
                            "evidence": f"Git clone invocation '{snippet}' passes arguments without '--' option terminator or leading-hyphen validation at line {line_no}.",
                            "attack_path": "An attacker supplies a source URL starting with options (e.g., --upload-pack, -u, --config), triggering option injection or command execution.",
                            "impact": "Arbitrary command execution or Git configuration manipulation in the process context.",
                            "validation_status": "PROBABLE" if not is_test_file else "POSSIBLE"
                        })

            # 2. SQL Injection (Dimension 2)
            # Evaluates dynamic string interpolation in SQL query execution vs parameterized query placeholders
            # A '?' character in text or comments does NOT prove parameterization if only 1 argument is passed to execute()
            try:
                tree = ast.parse(content, filename=file_path)
            except SyntaxError:
                tree = None

            if tree is not None:
                class SQLVisitor(ast.NodeVisitor):
                    def __init__(self, outer):
                        self.outer = outer
                        self.sql_findings = []

                    def visit_Call(self, node: ast.Call):
                        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
                            if len(node.args) >= 1:
                                first_arg = node.args[0]
                                is_dynamic = False
                                var_name = ""

                                if isinstance(first_arg, ast.JoinedStr):  # f-string
                                    is_dynamic = True
                                    for val in first_arg.values:
                                        if isinstance(val, ast.FormattedValue) and isinstance(val.value, ast.Name):
                                            var_name = val.value.id
                                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):  # % formatting
                                    is_dynamic = True
                                elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == "format":
                                    is_dynamic = True
                                elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):  # + concatenation
                                    is_dynamic = True

                                if is_dynamic:
                                    # Check if execute has parameter arguments (len(node.args) >= 2)
                                    is_parameterized = (len(node.args) >= 2)
                                    if not is_parameterized:
                                        raw_source = ast.unparse(first_arg).upper() if hasattr(ast, "unparse") else ""
                                        if any(kw in raw_source for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE")):
                                            line_no = node.lineno
                                            has_untrusted_var = any(k in var_name.lower() for k in ("request", "user", "input", "param", "arg", "data", "payload", "body"))
                                            val_status = "PROBABLE" if has_untrusted_var else "POSSIBLE"
                                            sev = "HIGH" if val_status == "PROBABLE" else "MEDIUM"
                                            lines = content.splitlines()
                                            snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else "cursor.execute(...)"
                                            self.sql_findings.append({
                                                "line_no": line_no,
                                                "snippet": snippet,
                                                "var_name": var_name,
                                                "val_status": val_status,
                                                "sev": sev
                                            })
                        self.generic_visit(node)

                sv = SQLVisitor(self)
                sv.visit(tree)
                for sf in sv.sql_findings:
                    findings.append({
                        "finding_id": "RED-SQL-01",
                        "category": "Injection",
                        "title": "SQL Injection via Dynamic String Formatting in Database Query",
                        "severity": sf["sev"],
                        "confidence": "HIGH" if sf["val_status"] == "PROBABLE" else "MEDIUM",
                        "affected_files": [file_path],
                        "affected_functions": [self._find_match_context(content, content.find(sf["snippet"]))[1]],
                        "line_number": sf["line_no"],
                        "attack_surface": "Database Persistence Layer / SQL Ingress",
                        "attacker_controlled_input": f"Dynamic parameter '{sf['var_name']}' formatted into SQL query string" if sf["var_name"] else "Unsanitized formatted SQL query",
                        "security_boundary": "Application Runtime -> Relational Database Engine",
                        "evidence": f"Dynamic query construction '{sf['snippet']}' identified at line {sf['line_no']}.",
                        "attack_path": "An attacker injects SQL meta-characters into query parameters to alter query syntax and execution.",
                        "impact": "Unauthorized database read, modification, or data exfiltration.",
                        "validation_status": sf["val_status"]
                    })
            else:
                # Regex fallback
                sql_match = re.search(
                    r'(?:cursor\.)?execute\s*\(\s*(?:f[\'"].*?\{[a-zA-Z0-9_]+.*?\}|[\'"].*?(?:%s|\{\}).*?[\'"]\s*[%]|[\'"].*?[\'"]\.format|\([^)]*\+\s*[\'"].*?(?:SELECT|INSERT|UPDATE|DELETE))',
                    content,
                    re.IGNORECASE | re.DOTALL
                )
                if sql_match and any(kw in sql_match.group(0).upper() for kw in ("SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE")):
                    line_no, func_name, snippet = self._find_match_context(content, sql_match.start())
                    matched_text = sql_match.group(0)
                    var_match = re.search(r'\{([a-zA-Z0-9_]+)\}', matched_text)
                    var_name = var_match.group(1).lower() if var_match else ""
                    has_untrusted_var = any(k in var_name for k in ("request", "user", "input", "param", "arg", "data", "payload", "body"))

                    val_status = "PROBABLE" if has_untrusted_var else "POSSIBLE"
                    sev = "HIGH" if val_status == "PROBABLE" else "MEDIUM"

                    findings.append({
                        "finding_id": "RED-SQL-01",
                        "category": "Injection",
                        "title": "SQL Injection via Dynamic String Formatting in Database Query",
                        "severity": sev,
                        "confidence": "HIGH" if val_status == "PROBABLE" else "MEDIUM",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "Database Persistence Layer / SQL Ingress",
                        "attacker_controlled_input": f"Dynamic parameter '{var_name}' formatted into SQL query string" if var_name else "Unsanitized formatted SQL query",
                        "security_boundary": "Application Runtime -> Relational Database Engine",
                        "evidence": f"Dynamic query construction '{snippet}' identified at line {line_no}.",
                        "attack_path": "An attacker injects SQL meta-characters into query parameters to alter query syntax and execution.",
                        "impact": "Unauthorized database read, modification, or data exfiltration.",
                        "validation_status": val_status
                    })

            # 3. Arbitrary Shell Command Execution (Dimension 3)
            # Evaluates shell=True or os.system with dynamic arguments (skips static literals and quoted commands)
            cmd_match = re.search(r'\b(?:os\.system\(([^)]+)\)|subprocess\.(?:Popen|call|run)\(([^)]*shell\s*=\s*True[^)]*)\)|eval\(([^)]+)\)|exec\(([^)]+)\))', content)
            if cmd_match and not is_test_file:
                matched_arg = cmd_match.group(1) or cmd_match.group(2) or cmd_match.group(3) or cmd_match.group(4) or ""
                # Static string literals without variables are safe (e.g. os.system('clear'), subprocess.run('git --version', shell=True))
                is_static_literal = bool(re.match(r'^\s*["\'][a-zA-Z0-9_\-\.\s\/]+["\']\s*$', matched_arg))

                # Check if shlex.quote is applied specifically to the argument of this command
                has_arg_quoted = "shlex.quote" in matched_arg

                if not is_static_literal and not has_arg_quoted:
                    line_no, func_name, snippet = self._find_match_context(content, cmd_match.start())
                    findings.append({
                        "finding_id": "RED-CMD-01",
                        "category": "Injection",
                        "title": "Arbitrary Command Execution via Shell Invocation",
                        "severity": "CRITICAL",
                        "confidence": "HIGH",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "Operating System Subprocess Ingress",
                        "attacker_controlled_input": "Dynamic variables interpolated into shell command",
                        "security_boundary": "Application Process -> Operating System Shell",
                        "evidence": f"Unsanitized command execution '{snippet}' identified at line {line_no}.",
                        "attack_path": "An attacker supplies shell metacharacters (; & | `) in parameters executed by the shell.",
                        "impact": "Host system command execution in the context of the running application.",
                        "validation_status": "PROBABLE"
                    })

            # 4. Insecure Object Deserialization (Dimension 4)
            # Assesses pickle/joblib deserialization; checks data provenance
            deser_match = re.search(r'\b(?:pickle\.load|pickle\.loads|joblib\.load)\b', content)
            if deser_match:
                line_no, func_name, snippet = self._find_match_context(content, deser_match.start())
                has_untrusted_source = any(k in content.lower() for k in ("request", "upload", "download", "socket", "network", "client", "payload"))
                val_status = "PROBABLE" if has_untrusted_source else "POSSIBLE"

                findings.append({
                    "finding_id": "RED-DESER-01",
                    "category": "Remote Code Execution",
                    "title": "Insecure Object Deserialization via Python Pickle / Joblib",
                    "severity": "HIGH" if val_status == "PROBABLE" else "MEDIUM",
                    "confidence": "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Object Deserialization Pipeline",
                    "attacker_controlled_input": "Serialized pickle/joblib payload stream",
                    "security_boundary": "External Storage / Network Ingress -> Python Runtime",
                    "evidence": f"Deserialization routine '{snippet}' identified at line {line_no}. Data provenance: {'untrusted ingress stream' if has_untrusted_source else 'local or unspecified file source'}.",
                    "attack_path": "An attacker provides a crafted pickled object with __reduce__ hooks to execute arbitrary Python bytecode.",
                    "impact": "Remote code execution in the context of the server process.",
                    "validation_status": val_status
                })

        return findings

    # --- Dimension 5 & 6: File Handling (Archive Safety) ---
    def _audit_file_handling(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            if "zipfile.ZipFile" in content or "tarfile.open" in content:
                # Inspect by function scope to avoid file-wide keyword false positives
                lines = content.splitlines()
                func_blocks: List[Tuple[str, int, int, str]] = []  # (func_name, start_line, end_line, body)
                current_func = "module"
                start = 0

                for idx, line in enumerate(lines):
                    m = re.match(r'^\s*def\s+([a-zA-Z0-9_]+)\(', line)
                    if m:
                        if func_blocks or start < idx:
                            func_blocks.append((current_func, start + 1, idx, "\n".join(lines[start:idx])))
                        current_func = m.group(1)
                        start = idx
                func_blocks.append((current_func, start + 1, len(lines), "\n".join(lines[start:])))

                for f_name, f_start, f_end, f_body in func_blocks:
                    if "extractall" not in f_body and "extract(" not in f_body:
                        continue

                    # 5. Decompression Bomb (Zip Bomb) (Dimension 5)
                    # Checks uncompressed size limits AND member count limits within this function
                    has_size_check = any(k in f_body for k in ("file_size", "uncompressed", "MAX_SIZE", "MAX_BYTES", "MAX_ZIP", "limit_bytes"))
                    has_member_check = any(k in f_body for k in ("infolist", "namelist", "MAX_FILES", "member_count"))

                    if "extractall(" in f_body and not (has_size_check and has_member_check):
                        line_offset = 0
                        for i, l in enumerate(f_body.splitlines()):
                            if "extractall(" in l:
                                line_offset = i
                                break
                        line_no = f_start + line_offset
                        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else "extractall()"

                        findings.append({
                            "finding_id": "RED-DOS-01",
                            "category": "File Handling",
                            "title": "Uncontrolled Resource Consumption via Archive Decompression (Zip Bomb)",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "affected_files": [file_path],
                            "affected_functions": [f_name],
                            "line_number": line_no,
                            "attack_surface": "Archive Ingestion Subsystem",
                            "attacker_controlled_input": "Compressed archive file or stream",
                            "security_boundary": "External Archive -> Host Filesystem Storage",
                            "evidence": f"Extraction call '{snippet}' at line {line_no} lacks cumulative uncompressed size and member-count limits in function '{f_name}'.",
                            "attack_path": "An attacker uploads a highly compressed archive that expands into gigabytes of data.",
                            "impact": "Disk space exhaustion or denial of service crash.",
                            "validation_status": "PROBABLE"
                        })

                    # 6. Archive Path Traversal & Symlinks (Dimension 6)
                    # Inspects path normalization, canonical containment, and symlink rejection within this function
                    has_path_validation = any(k in f_body for k in ("commonpath", "os.path.commonpath", "startswith", "os.path.abspath"))
                    has_symlink_guard = any(k in f_body for k in ("islink", "S_ISLNK", "is_symlink", "issym", "symlink"))

                    if "extract" in f_body:
                        line_offset = 0
                        for i, l in enumerate(f_body.splitlines()):
                            if "extract" in l:
                                line_offset = i
                                break
                        line_no = f_start + line_offset
                        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else "extract()"

                        if not has_path_validation:
                            findings.append({
                                "finding_id": "RED-FILE-02",
                                "category": "File Handling",
                                "title": "Path Traversal during Archive Extraction (Zip-Slip)",
                                "severity": "CRITICAL",
                                "confidence": "HIGH",
                                "affected_files": [file_path],
                                "affected_functions": [f_name],
                                "line_number": line_no,
                                "attack_surface": "Archive Member Extraction Subsystem",
                                "attacker_controlled_input": "Archive members with '../' relative path components",
                                "security_boundary": "Extraction Sandbox -> Host Filesystem",
                                "evidence": f"Extraction call '{snippet}' at line {line_no} extracts member paths without canonical boundary checks in function '{f_name}'.",
                                "attack_path": "An attacker crafts an archive with '../' paths to overwrite files outside extraction directory.",
                                "impact": "Arbitrary file overwrite or code execution.",
                                "validation_status": "PROBABLE"
                            })
                        elif not has_symlink_guard:
                            findings.append({
                                "finding_id": "RED-FILE-02",
                                "category": "File Handling",
                                "title": "Potential Symlink Traversal during Archive Extraction",
                                "severity": "HIGH",
                                "confidence": "MEDIUM",
                                "affected_files": [file_path],
                                "affected_functions": [f_name],
                                "line_number": line_no,
                                "attack_surface": "Archive Member Mode Inspection",
                                "attacker_controlled_input": "Archive members containing symbolic links",
                                "security_boundary": "Extraction Sandbox -> Target Filesystem",
                                "evidence": f"Member extraction '{snippet}' at line {line_no} checks paths but does not explicitly reject symlink modes in function '{f_name}'.",
                                "attack_path": "An archive with a symbolic link target pointing outside sandbox permits writing outside target directory.",
                                "impact": "Arbitrary file modification outside extraction sandbox.",
                                "validation_status": "POSSIBLE"
                            })

        return findings

    # --- Dimension 7 & 8: Access Control & CORS ---
    def _audit_access_control(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            # 7. Unrestricted Output File Overwrite (Dimension 7)
            # Distinguishes normal CLI operator destination selection from service-level arbitrary write
            out_match = re.search(r'open\(\s*(?:args\.output|output_path|dest_path)\s*,\s*["\']w[b]?["\']', content)
            if out_match:
                line_no, func_name, snippet = self._find_match_context(content, out_match.start())
                has_jail = "commonpath" in content or ("realpath" in content and "startswith" in content)
                is_cli = "argparse" in content or "sys.argv" in content or "click" in content

                # Normal CLI argument destination is intended operator behavior, not a vulnerability
                if not has_jail and not is_cli:
                    findings.append({
                        "finding_id": "RED-FILE-01",
                        "category": "Access Control",
                        "title": "Unrestricted Output File Overwrite in Service Layer",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "Service Output File Persistence",
                        "attacker_controlled_input": "Output destination path parameter",
                        "security_boundary": "Untrusted Request -> Host Filesystem",
                        "evidence": f"Output file write '{snippet}' at line {line_no} does not enforce directory jail.",
                        "attack_path": "A caller supplies an absolute or traversal output path targeting sensitive host files.",
                        "impact": "Unauthorized file overwrite or data corruption.",
                        "validation_status": "PROBABLE"
                    })

            # 8. Overly Permissive CORS (Dimension 8)
            # Evaluates wildcard origin in context; distinguishes credentialed vs public endpoints
            cors_match = re.search(r'(?:CORS\([^)]*origins\s*=\s*["\']\*["\']|Access-Control-Allow-Origin:\s*\*|origins\s*=\s*\[["\']\*["\']\])', content, re.IGNORECASE)
            if cors_match:
                line_no, func_name, snippet = self._find_match_context(content, cors_match.start())
                has_credentials = any(k in content for k in ("supports_credentials=True", "allow_credentials=True", "Access-Control-Allow-Credentials: true"))

                if has_credentials:
                    sev = "HIGH"
                    status = "PROBABLE"
                    desc = "CORS configuration permits wildcard origin ('*') combined with credentialed access."
                else:
                    sev = "LOW"
                    status = "POSSIBLE"
                    desc = "CORS policy permits wildcard origin ('*') without credentials (safe for public read-only APIs, review if private endpoints exist)."

                findings.append({
                    "finding_id": "RED-CORS-01",
                    "category": "Access Control",
                    "title": "Permissive Cross-Origin Resource Sharing (CORS) Policy",
                    "severity": sev,
                    "confidence": "HIGH" if has_credentials else "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Browser Cross-Origin Ingress",
                    "attacker_controlled_input": "HTTP Origin Request Header",
                    "security_boundary": "Web Browser Same-Origin Policy -> Backend API",
                    "evidence": f"CORS definition '{snippet}' at line {line_no}: {desc}",
                    "attack_path": "An external website triggers cross-origin browser requests to read API responses.",
                    "impact": "Unauthorized cross-origin access to API response data." if has_credentials else "Information exposure on unintentionally public endpoints.",
                    "validation_status": status
                })

        return findings

    # --- Dimension 9: Input Validation & DoS (Unbounded Reads) ---
    def _audit_input_validation_and_dos(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Detects unbounded file and stream reads while distinguishing bounded reads and pre-checks.

        Checks:
        - Call site arguments: distinguishes read() (unbounded) from read(MAX_BYTES) (bounded).
        - Guards in the enclosing function scope (e.g. os.path.getsize(path) checks).
        - Unrelated size checks in other functions do NOT guard this call site.
        - Classifies as PROBABLE or POSSIBLE, avoiding unsupported CONFIRMED claims.
        """
        findings = []
        for file_path, content in corpus.items():
            is_test_file = any(k in file_path.lower() for k in ("test_", "tests/"))
            if is_test_file:
                continue

            try:
                tree = ast.parse(content, filename=file_path)
            except SyntaxError:
                tree = None

            if tree is not None:
                class ReadCallVisitor(ast.NodeVisitor):
                    def __init__(self):
                        self.unbounded_calls: List[Tuple[int, str, bool]] = []

                    def visit_FunctionDef(self, node: ast.FunctionDef):
                        # Inspect statements within this function for size guards on the file
                        func_source = ast.unparse(node) if hasattr(ast, "unparse") else ""
                        has_file_guard = any(k in func_source for k in ("getsize", "file_size", "MAX_SIZE", "MAX_BYTES", "MAX_READ"))

                        for child in ast.walk(node):
                            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                                if child.func.attr == "read":
                                    # If read() has no arguments, it is unbounded
                                    is_unbounded = (len(child.args) == 0)
                                    if is_unbounded:
                                        self.unbounded_calls.append((child.lineno, node.name, has_file_guard))
                        self.generic_visit(node)

                visitor = ReadCallVisitor()
                visitor.visit(tree)

                for line_no, func_name, has_guard in visitor.unbounded_calls:
                    if not has_guard:
                        lines = content.splitlines()
                        snippet = lines[line_no - 1].strip() if line_no - 1 < len(lines) else "f.read()"
                        findings.append({
                            "finding_id": "RED-DOS-02",
                            "category": "Denial of Service",
                            "title": "Unbounded File Read in Application Ingestion Routine",
                            "severity": "MEDIUM",
                            "confidence": "HIGH",
                            "affected_files": [file_path],
                            "affected_functions": [func_name],
                            "line_number": line_no,
                            "attack_surface": "Filesystem / Ingestion File Reading",
                            "attacker_controlled_input": "Arbitrarily large file inside scanned repository",
                            "security_boundary": "Untrusted Filesystem Input -> Process Heap Memory",
                            "evidence": f"Unbounded read operation '{snippet}' at line {line_no} lacks prior size validation or byte limit.",
                            "attack_path": "An attacker supplies a multi-gigabyte file, causing memory exhaustion during read.",
                            "impact": "Process memory exhaustion (OOM crash) and denial of service.",
                            "validation_status": "PROBABLE"
                        })
                        break  # One finding per file is sufficient
            else:
                read_matches = list(re.finditer(r'(?:f|file|stream|fp)\.read\(\s*\)', content))
                for rm in read_matches:
                    line_no, func_name, snippet = self._find_match_context(content, rm.start())
                    surrounding = content[max(0, rm.start() - 300):rm.start()]
                    has_size_check = any(k in surrounding for k in ("getsize", "file_size", "MAX_READ", "MAX_BYTES"))
                    if not has_size_check:
                        findings.append({
                            "finding_id": "RED-DOS-02",
                            "category": "Denial of Service",
                            "title": "Unbounded File Read in Application Ingestion Routine",
                            "severity": "MEDIUM",
                            "confidence": "MEDIUM",
                            "affected_files": [file_path],
                            "affected_functions": [func_name],
                            "line_number": line_no,
                            "attack_surface": "Filesystem / Ingestion File Reading",
                            "attacker_controlled_input": "Arbitrarily large file inside scanned repository",
                            "security_boundary": "Untrusted Filesystem Input -> Process Heap Memory",
                            "evidence": f"Unbounded read operation '{snippet}' at line {line_no} lacks prior size validation or byte limit.",
                            "attack_path": "An attacker supplies an oversized file, causing memory exhaustion during read.",
                            "impact": "Process memory exhaustion (OOM crash) and denial of service.",
                            "validation_status": "PROBABLE"
                        })
                        break

        return findings

    # --- Dimension 10 & 11: Secrets & Information Disclosure ---
    def _audit_information_disclosure(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            is_test_file = any(k in file_path.lower() for k in ("test_", "tests/"))

            # 10. Hardcoded Secrets (Dimension 10)
            secret_pattern = re.compile(
                r'\b(?:JWT_SECRET|SECRET_KEY|API_KEY|PRIVATE_KEY|DATABASE_PASSWORD|ACCESS_TOKEN|AUTH_TOKEN)\s*=\s*["\']([a-zA-Z0-9_\-\.\$\!\#]{10,})["\']',
                re.IGNORECASE
            )
            for sm in secret_pattern.finditer(content):
                raw_val = sm.group(1)
                lower_val = raw_val.lower()

                # Filter out obvious dummy, placeholder, or documentation credentials
                is_placeholder = any(p in lower_val for p in (
                    "your-secret", "changeme", "placeholder", "dummy", "example",
                    "fake", "sample"
                )) or lower_val in ("password", "secret", "admin", "12345", "123456", "12345678", "1234567890") or lower_val.startswith("test")

                if not is_placeholder and not is_test_file:
                    line_no, func_name, _ = self._find_match_context(content, sm.start())
                    redacted = self._redact_secret(raw_val)
                    findings.append({
                        "finding_id": "RED-SECRET-01",
                        "category": "Information Disclosure",
                        "title": "Hardcoded Secret Token or Cryptographic Key in Application Source",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "Source Code Secrets Management",
                        "attacker_controlled_input": "None (Static credential exposure)",
                        "security_boundary": "Source Repository -> Unauthorized Consumers",
                        "evidence": f"Hardcoded credential assignment identified at line {line_no} with value: {redacted}",
                        "attack_path": "An auditor or unauthorized party with repository access extracts credentials to access protected services.",
                        "impact": "Authentication bypass or unauthorized access to external service resources.",
                        "validation_status": "PROBABLE"
                    })
                    break

            # 11. Internal Path Leakage in Exported Outputs (Dimension 11)
            path_leak_match = re.search(r'["\']root_path["\']\s*:\s*root_path', content)
            if path_leak_match and not is_test_file:
                line_no, func_name, snippet = self._find_match_context(content, path_leak_match.start())
                findings.append({
                    "finding_id": "RED-INFO-02",
                    "category": "Information Disclosure",
                    "title": "Internal Host Filesystem Path Embedded in Contract Output",
                    "severity": "LOW",
                    "confidence": "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Exported JSON Output Contract",
                    "attacker_controlled_input": "None",
                    "security_boundary": "Host Filesystem Paths -> Exported Document",
                    "evidence": f"Root filesystem path embedded in output schema '{snippet}' at line {line_no}.",
                    "attack_path": "An external consumer reviews exported JSON output to discover internal directory structure and usernames.",
                    "impact": "Low-impact internal environment enumeration.",
                    "validation_status": "POSSIBLE"
                })

        return findings

    # --- Dimension 12 & 13: Local Directory & Debug Mode ---
    def _audit_auth_and_boundaries(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            is_test_file = any(k in file_path.lower() for k in ("test_", "tests/"))

            # 12. Local Directory Traversal vs Intended CLI Selection (Dimension 12)
            if 'source_type in ("dir", "local", "filesystem")' in content and not is_test_file:
                has_dir_jail = "allowed_dirs" in content or "base_dir" in content
                if not has_dir_jail:
                    line_no, func_name, snippet = self._find_match_context(content, content.find('source_type in ("dir"'))
                    findings.append({
                        "finding_id": "RED-INFO-01",
                        "category": "Access Control",
                        "title": "Unrestricted Local Directory Ingestion in CLI Interface",
                        "severity": "LOW",
                        "confidence": "LOW",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "CLI --source parameter with local directory type",
                        "attacker_controlled_input": "source directory path parameter",
                        "security_boundary": "CLI Operator Execution Context -> Host Filesystem",
                        "evidence": f"Directory ingestion '{snippet}' at line {line_no} allows operator to scan arbitrary local folders.",
                        "attack_path": "An operator specifies an arbitrary directory to inventory files.",
                        "impact": "Normal CLI file enumeration (intended tool behavior; verify if workspace restriction is required).",
                        "validation_status": "POSSIBLE"
                    })

            # 13. Debug Mode Enabled in Production (Dimension 13)
            # Evaluates whether debug=True is hardcoded or guarded by environment variable
            debug_match = re.search(r'\b(?:app\.run\([^)]*debug\s*=\s*([^,\)]+)|DEBUG\s*=\s*([^,\s\n]+))', content)
            if debug_match and not is_test_file:
                matched_val = (debug_match.group(1) or debug_match.group(2) or "").strip()
                line_no, func_name, snippet = self._find_match_context(content, debug_match.start())
                has_env_guard = "os.getenv" in matched_val or "os.environ" in matched_val or "is_debug" in matched_val

                val_status = "POSSIBLE" if has_env_guard else "PROBABLE"

                findings.append({
                    "finding_id": "RED-DEBUG-01",
                    "category": "Configuration",
                    "title": "Interactive Debug Mode Enabled in Web Application Server",
                    "severity": "HIGH",
                    "confidence": "HIGH" if val_status == "PROBABLE" else "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Web Application Server Ingress",
                    "attacker_controlled_input": "HTTP requests triggering unhandled exceptions",
                    "security_boundary": "Public Ingress -> Interactive Debugger Console",
                    "evidence": f"Server invocation with debug mode: '{snippet}' at line {line_no}.",
                    "attack_path": "An attacker triggers an application error to access an interactive debugging console or stack trace.",
                    "impact": "Information disclosure of server environment or interactive code execution via debug console.",
                    "validation_status": val_status
                })

        return findings

    # --- Dimension 14: Cryptographic Hashing ---
    def _audit_logging_and_errors(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            is_test_file = any(k in file_path.lower() for k in ("test_", "tests/"))

            # 14. Weak Cryptography (Dimension 14)
            hash_match = re.search(r'\bhashlib\.(?:md5|sha1)\b', content)
            if hash_match:
                line_no, func_name, snippet = self._find_match_context(content, hash_match.start())

                # Contextual evaluation: distinguishes password/auth from cache keys / checksums
                lines = content.splitlines()
                stmt = lines[line_no - 1].lower() if line_no - 1 < len(lines) else ""
                is_password_or_auth = any(k in stmt or k in func_name.lower() for k in ("password", "passwd", "auth_token", "api_token", "signature", "credential"))
                is_cache_or_checksum = any(k in stmt or k in func_name.lower() for k in ("cache_key", "etag", "checksum", "file_hash", "digest", "guid", "uuid"))

                if is_password_or_auth:
                    sev = "HIGH"
                    status = "PROBABLE"
                    desc = "Cryptographically broken hash function (MD5/SHA-1) used in security-sensitive authentication or signature context."
                elif is_cache_or_checksum:
                    sev = "LOW"
                    status = "POSSIBLE"
                    desc = "MD5/SHA-1 hash algorithm used for non-security purpose (checksum or cache key); not used for passwords or signatures."
                else:
                    sev = "LOW"
                    status = "POSSIBLE"
                    desc = "MD5/SHA-1 algorithm detected with ambiguous context; verify whether hash collisions affect security boundaries."

                findings.append({
                    "finding_id": "RED-CRYPTO-01",
                    "category": "Cryptography",
                    "title": "Use of Cryptographically Weak Hash Algorithm (MD5/SHA-1)",
                    "severity": sev,
                    "confidence": "HIGH" if is_password_or_auth else "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Cryptographic Hashing Subsystem",
                    "attacker_controlled_input": "Data passed to hash function",
                    "security_boundary": "Application Cryptographic Verification -> Collision Domain",
                    "evidence": f"Hash invocation '{snippet}' at line {line_no}: {desc}",
                    "attack_path": "An attacker generates hash collisions to bypass signature checks." if is_password_or_auth else "Non-adversarial hash collision in cache key.",
                    "impact": "Integrity bypass or credential vulnerability." if is_password_or_auth else "Low-impact non-security hash collision.",
                    "validation_status": status
                })

        return findings

    # --- Dimension 15 to 18: Extended Security Dimensions ---
    def _audit_extended_dimensions(self, corpus: Dict[str, str]) -> List[Dict[str, Any]]:
        findings = []
        for file_path, content in corpus.items():
            is_test_file = any(k in file_path.lower() for k in ("test_", "tests/"))

            # 15. Server-Side Request Forgery (SSRF) (Dimension 15)
            # Evaluates dynamic request destinations vs static URLs or verified allowlists
            ssrf_match = re.search(r'\b(?:requests\.get|requests\.post|urllib\.request\.urlopen)\(\s*([a-zA-Z0-9_]+)\b', content)
            if ssrf_match and not is_test_file:
                var_name = ssrf_match.group(1)
                if var_name not in ("url", "DEFAULT_URL", "BASE_URL", "API_BASE"):
                    line_no, func_name, snippet = self._find_match_context(content, ssrf_match.start())
                    findings.append({
                        "finding_id": "RED-SSRF-01",
                        "category": "Network Security",
                        "title": "Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request",
                        "severity": "HIGH",
                        "confidence": "MEDIUM",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "Outbound HTTP Client Integration",
                        "attacker_controlled_input": f"Dynamic URL parameter '{var_name}'",
                        "security_boundary": "Internal Application -> External / Cloud Metadata Endpoints",
                        "evidence": f"Outbound HTTP call '{snippet}' at line {line_no} takes variable without verified destination allowlist.",
                        "attack_path": "An attacker supplies internal loopback (127.0.0.1) or cloud metadata (169.254.169.254) addresses.",
                        "impact": "Cloud credential theft or internal service network scanning.",
                        "validation_status": "POSSIBLE"
                    })

            # 16. XML External Entity (XXE) Parsing (Dimension 16)
            has_xml_import = any(k in content for k in ("xml.etree", "xml.dom", "lxml"))
            xxe_match = re.search(r'\b(?:xml\.etree\.ElementTree|xml\.dom\.minidom|lxml\.etree|ET|ElementTree|minidom|etree)\.parse\(', content)
            if has_xml_import and xxe_match and not is_test_file:
                has_defused = "defusedxml" in content
                if not has_defused:
                    line_no, func_name, snippet = self._find_match_context(content, xxe_match.start())
                    findings.append({
                        "finding_id": "RED-XXE-01",
                        "category": "XML Parsing",
                        "title": "XML External Entity (XXE) Processing via Standard XML Parser",
                        "severity": "MEDIUM",
                        "confidence": "MEDIUM",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "XML File & Payload Parsing Subsystem",
                        "attacker_controlled_input": "XML payload with DOCTYPE external entity declaration",
                        "security_boundary": "External XML Stream -> Local Filesystem Parser",
                        "evidence": f"XML parsing routine '{snippet}' at line {line_no} without defusedxml protection.",
                        "attack_path": "An attacker submits XML containing SYSTEM entity references to read local files.",
                        "impact": "Arbitrary local file disclosure or denial of service.",
                        "validation_status": "POSSIBLE"
                    })

            # 17. Insecure Temporary File Creation (Dimension 17)
            # Evaluates tempfile.mktemp() and subsequent open usage
            temp_match = re.search(r'([a-zA-Z0-9_]+)\s*=\s*tempfile\.mktemp\(', content)
            if temp_match and not is_test_file:
                var_name = temp_match.group(1)
                line_no, func_name, snippet = self._find_match_context(content, temp_match.start())
                surrounding = content[temp_match.start():min(len(content), temp_match.end() + 300)]
                is_subsequently_opened = f"open({var_name}" in surrounding

                val_status = "PROBABLE" if is_subsequently_opened else "POSSIBLE"

                findings.append({
                    "finding_id": "RED-TEMP-01",
                    "category": "File Handling",
                    "title": "Insecure Temporary File Creation using Deprecated mktemp()",
                    "severity": "MEDIUM",
                    "confidence": "HIGH" if is_subsequently_opened else "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Temporary Filesystem Management",
                    "attacker_controlled_input": "Symlink creation in temporary directory",
                    "security_boundary": "Shared Temp Folder -> Application State",
                    "evidence": f"Deprecated mktemp routine '{snippet}' at line {line_no} creates race-prone temporary path{' followed by non-atomic open()' if is_subsequently_opened else ''}.",
                    "attack_path": "A local unprivileged process creates a symlink at the predicted mktemp path before file creation.",
                    "impact": "Arbitrary file overwrite or race condition privilege escalation.",
                    "validation_status": val_status
                })
            elif "tempfile.mktemp" in content and not is_test_file:
                line_no, func_name, snippet = self._find_match_context(content, content.find("tempfile.mktemp"))
                findings.append({
                    "finding_id": "RED-TEMP-01",
                    "category": "File Handling",
                    "title": "Insecure Temporary File Creation using Deprecated mktemp()",
                    "severity": "MEDIUM",
                    "confidence": "MEDIUM",
                    "affected_files": [file_path],
                    "affected_functions": [func_name],
                    "line_number": line_no,
                    "attack_surface": "Temporary Filesystem Management",
                    "attacker_controlled_input": "Symlink creation in temporary directory",
                    "security_boundary": "Shared Temp Folder -> Application State",
                    "evidence": f"Deprecated mktemp routine '{snippet}' at line {line_no} creates race-prone temporary path.",
                    "attack_path": "A local process creates a symlink at the predicted mktemp path before file creation.",
                    "impact": "Arbitrary file overwrite or race condition privilege escalation.",
                    "validation_status": "POSSIBLE"
                })

            # 18. Plaintext Transport Security (Dimension 18)
            # Excludes localhost, 127.0.0.1, documentation, and schema references
            plaintext_match = re.search(r'["\']http://[a-zA-Z0-9_\-\.]+["\']', content)
            if plaintext_match and not is_test_file:
                matched_url = plaintext_match.group(0).lower()
                is_benign = any(b in matched_url for b in (
                    "localhost", "127.0.0.1", "0.0.0.0", "w3.org", "schemas.", "example.com"
                ))
                if not is_benign:
                    line_no, func_name, snippet = self._find_match_context(content, plaintext_match.start())
                    findings.append({
                        "finding_id": "RED-TLS-01",
                        "category": "Transport Security",
                        "title": "Unencrypted Plaintext HTTP Communication URL Detected",
                        "severity": "LOW",
                        "confidence": "MEDIUM",
                        "affected_files": [file_path],
                        "affected_functions": [func_name],
                        "line_number": line_no,
                        "attack_surface": "External Network Communications",
                        "attacker_controlled_input": "None",
                        "security_boundary": "Application Process -> External Network",
                        "evidence": f"Plaintext HTTP reference '{snippet}' at line {line_no}.",
                        "attack_path": "Network eavesdropper intercepts plaintext HTTP data transit.",
                        "impact": "Data sniffing or in-transit traffic tampering.",
                        "validation_status": "POSSIBLE"
                    })

        return findings

    # -------------------------------------------------------------------------
    # Coverage Reporting: Truthful 18-Dimension Assessment
    # -------------------------------------------------------------------------
    def _build_dimension_coverage(self, validated_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Builds honest, transparent coverage evaluation across all 18 dimensions.
        Distinguishes heuristic static checks from comprehensive taint analysis.
        """
        findings_by_dim: Dict[int, int] = defaultdict(int)
        dim_map = {
            "RED-INJ-01": 1, "RED-SQL-01": 2, "RED-CMD-01": 3, "RED-DESER-01": 4,
            "RED-DOS-01": 5, "RED-FILE-02": 6, "RED-FILE-01": 7, "RED-CORS-01": 8,
            "RED-DOS-02": 9, "RED-SECRET-01": 10, "RED-INFO-02": 11, "RED-INFO-01": 12,
            "RED-DEBUG-01": 13, "RED-CRYPTO-01": 14, "RED-SSRF-01": 15, "RED-XXE-01": 16,
            "RED-TEMP-01": 17, "RED-TLS-01": 18
        }
        for f in validated_findings:
            d_id = dim_map.get(f.get("finding_id", ""), 0)
            if d_id:
                findings_by_dim[d_id] += 1

        dimension_reports = []
        is_empty_corpus = (self.inspected_files_count == 0)

        for d in self.DIMENSION_DEFINITIONS:
            d_id = d["dimension_id"]
            cnt = findings_by_dim[d_id]

            if is_empty_corpus:
                status = "INSUFFICIENT_INPUT"
            else:
                status = "CHECKED_HEURISTICALLY"

            dimension_reports.append({
                "dimension_id": d_id,
                "name": d["name"],
                "category": d["category"],
                "status": status,
                "analysis_depth": "HEURISTIC_STATIC_ANALYSIS",
                "rules_evaluated": d["rules"],
                "surface_detected": (cnt > 0),
                "findings_count": cnt,
                "skipped_files_count": len(self.skipped_files),
                "limitations": "Heuristic AST/regex pattern matching lacks interprocedural taint flow; reachability requires manual verification."
            })

        return dimension_reports

    # -------------------------------------------------------------------------
    # PHASE C: Validation, Evidence-Preserving Deduplication, Requirement Mapping
    # -------------------------------------------------------------------------
    def validate_findings(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validates findings with evidence-preserving deduplication and requirement mapping.

        Deduplication rules:
        - Weakness identity: groups findings by (category, finding_id, primary_affected_file).
        - Distinct files remain distinct findings so evidence is never erased across repositories.
        - Multiple occurrences in the same file are merged into a single finding for that file,
          retaining all affected functions, line numbers, and evidence records in 'evidence'.
        - Does not promote confidence or status blindly.
        """
        deduped_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        for c in candidates:
            fid = c.get("finding_id", "RED-UNKNOWN")
            category = c.get("category", "General")
            files = [f for f in c.get("affected_files", []) if isinstance(f, str)]
            primary_file = files[0] if files else "unknown"

            # Stable deduplication key: category + finding ID + primary file target
            dedup_key = (category, fid, primary_file)

            line_no = c.get("line_number")

            if dedup_key in deduped_map:
                existing = deduped_map[dedup_key]

                # Merge affected files without duplication
                for f in files:
                    if f not in existing["affected_files"]:
                        existing["affected_files"].append(f)

                # Merge affected functions
                for fn in c.get("affected_functions", []):
                    if isinstance(fn, str) and fn not in existing["affected_functions"]:
                        existing["affected_functions"].append(fn)

                # Maintain sorted line_numbers collection
                if line_no is not None and line_no not in existing["line_numbers"]:
                    existing["line_numbers"].append(line_no)
                    existing["line_numbers"].sort()

                # Retain higher severity
                curr_sev_rank = self.SEVERITY_ORDER.get(existing.get("severity", "INFO"), 5)
                new_sev_rank = self.SEVERITY_ORDER.get(c.get("severity", "INFO"), 5)
                if new_sev_rank < curr_sev_rank:
                    existing["severity"] = c.get("severity", existing["severity"])

                # Retain highest validation status rank for this specific file without blind upgrade
                curr_status_rank = self.VALIDATION_STATUS_ORDER.get(existing.get("validation_status", "POSSIBLE"), 5)
                new_status_rank = self.VALIDATION_STATUS_ORDER.get(c.get("validation_status", "POSSIBLE"), 5)
                if new_status_rank < curr_status_rank:
                    existing["validation_status"] = c.get("validation_status", existing["validation_status"])

                # Append distinct evidence
                new_evidence = c.get("evidence", "")
                if new_evidence and new_evidence not in existing.get("evidence", ""):
                    existing["evidence"] = f"{existing.get('evidence', '')}; {new_evidence}".strip("; ")

                continue

            # Map to Phase 2 requirements defensively without fabricating IDs
            req_id = self._map_requirement_affected(c)

            line_numbers = [line_no] if line_no is not None else []

            item = {
                "finding_id": fid,
                "category": category,
                "title": c.get("title", "Security Finding"),
                "severity": c.get("severity", "MEDIUM"),
                "confidence": c.get("confidence", "HIGH"),
                "affected_files": list(files),
                "affected_functions": list(c.get("affected_functions", [])),
                "attack_surface": c.get("attack_surface", "Application Attack Surface"),
                "attacker_controlled_input": c.get("attacker_controlled_input", "Untrusted Input"),
                "security_boundary": c.get("security_boundary", "Trust Boundary"),
                "evidence": c.get("evidence", "Identified by static analysis."),
                "attack_path": c.get("attack_path", "Execution path requires verification."),
                "impact": c.get("impact", "Potential security impact."),
                "validation_status": c.get("validation_status", "POSSIBLE"),
                "requirement_affected": req_id,
                "false_positive_reason_if_applicable": c.get("false_positive_reason_if_applicable", "")
            }
            if line_no is not None:
                item["line_number"] = line_no
            item["line_numbers"] = line_numbers

            deduped_map[dedup_key] = item

        validated = list(deduped_map.values())

        # Sort deterministically: by severity rank, then finding_id, then primary file
        validated.sort(key=lambda x: (
            self.SEVERITY_ORDER.get(x.get("severity", "INFO"), 5),
            x.get("finding_id", ""),
            x.get("affected_files", [""])[0] if x.get("affected_files") else "",
            x.get("line_number", 0)
        ))

        return validated

    def _map_requirement_affected(self, finding: Dict[str, Any]) -> str:
        """
        Maps a security finding to a Phase 2 requirement using defensive semantic matching.
        Returns 'UNMAPPED' if no defensible match exists in Phase 2 requirements.
        Never fabricates requirement IDs.
        """
        if not self.p2_reqs:
            return "UNMAPPED"

        finding_title = str(finding.get("title", "")).lower()
        finding_cat = str(finding.get("category", "")).lower()

        for r in self.p2_reqs:
            if not isinstance(r, dict):
                continue
            r_desc = str(r.get("description", "")).lower()
            r_cat = str(r.get("category", "")).lower()
            r_id = r.get("requirement_id", "")
            if not r_id:
                continue

            # Match Archive / ZIP requirements
            if any(k in finding_title for k in ("zip", "archive", "decompression", "symlink")):
                if any(k in r_desc for k in ("zip", "archive", "traversal")):
                    return r_id

            # Match Authentication & Access Control requirements
            if any(k in finding_title for k in ("auth", "cors", "rbac", "access control")):
                if any(k in r_desc for k in ("auth", "identity", "access", "permission")):
                    return r_id

            # Match Secrets & Information Disclosure requirements
            if any(k in finding_title for k in ("secret", "token", "credential", "leakage")):
                if any(k in r_desc for k in ("secret", "credential", "token")):
                    return r_id

            # Match Transport Security / TLS requirements
            if any(k in finding_title for k in ("tls", "plaintext", "http")):
                if any(k in r_desc for k in ("tls", "https", "transport", "encryption")):
                    return r_id

            # Match Input Validation & Injection requirements
            if any(k in finding_title for k in ("injection", "sql", "command", "read", "dos")):
                if any(k in r_desc for k in ("input", "validation", "injection", "dos")):
                    return r_id

        return "UNMAPPED"
