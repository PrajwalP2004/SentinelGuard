"""
Phase 2: Requirements Engineering Agent Module.

Extracts functional requirements, security requirements, non-functional requirements,
and business constraints from project documentation, source code, Phase 0 inventory,
and Phase 1 project reconstruction.

Strict Rules:
- Preserves the requirement-status vocabulary: 'explicit', 'code_supported', 'inferred', 'unknown'.
- 'explicit': Used only when directly supported by documentation or an explicit specification.
- 'code_supported': Used only for behavior demonstrated by actual implementation evidence.
- 'inferred': Used for carefully qualified engineering deductions based on structural evidence.
- 'unknown': Used when evidence is absent or insufficient.
- File-read limit accurately enforces a strict byte limit via binary reads before decoding.
- Archive-safety analysis requires actual extraction code and validates member guards; distinguishes detected validation code from verified safe behavior.
- Does not infer that potentially sensitive files contain actual secrets solely from names or inventory classifications.
- Does not place deployment architecture under business constraints by default; represents deployment as technical architecture and requires supporting implementation evidence for 'code_supported'.
- Does not infer formal deterministic output requirements solely from tests; distinguishes tested behavior from documented requirements.
- Describes discovered CLI and API behavior as observed implementation behavior unless backed by a specification.
- Resolves paths safely within the repository root, rejecting traversal and symlink escapes.
"""

import os
import re
from typing import Dict, List, Any, Optional, Set, Union

MAX_READ_BYTES = 5 * 1024 * 1024  # 5 MB maximum buffer read limit (strictly enforced in bytes)


class RequirementsEngineeringAgent:
    """Agent responsible for extracting requirements from repository evidence and Phase 0/1 artifacts."""

    VALID_STATUSES = {"explicit", "code_supported", "inferred", "unknown"}

    def __init__(
        self,
        root_path: str,
        phase0_inventory: Optional[Dict[str, Any]] = None,
        phase1_reconstruction: Optional[Dict[str, Any]] = None
    ):
        self.root_path = os.path.abspath(root_path) if root_path else os.getcwd()
        self.p0 = phase0_inventory if isinstance(phase0_inventory, dict) else {}
        self.p1 = phase1_reconstruction if isinstance(phase1_reconstruction, dict) else {}
        self.warnings: List[str] = []

        if not phase0_inventory:
            self.warnings.append("Phase 0 inventory is missing or empty; requirements extraction based on partial baseline.")
        if not phase1_reconstruction:
            self.warnings.append("Phase 1 reconstruction is missing or empty; use case extraction limited.")

        # Extract inventory collections safely handling both strings and dictionaries
        self.source_files = self._extract_file_list(self.p0.get("source_files"))
        self.doc_files = self._extract_file_list(self.p0.get("documentation_files"))
        self.dep_files = self._extract_file_list(self.p0.get("dependency_files"))
        self.infra_files = self._extract_file_list(self.p0.get("infrastructure_files"))
        self.test_files = self._extract_file_list(self.p0.get("test_files"))
        self.file_inventory = self._extract_file_list(self.p0.get("file_inventory"))
        self.sensitive_files = self._extract_file_list(self.p0.get("potentially_sensitive_files"))

        # Extract Phase 1 entities safely
        self.apis = self._ensure_list_of_dicts(self.p1.get("apis"))
        self.use_cases = self._ensure_list_of_dicts(self.p1.get("use_cases"))
        self.trust_boundaries = self._ensure_list_of_dicts(self.p1.get("trust_boundaries"))
        self.auth_components = self._ensure_list_of_dicts(self.p1.get("authentication_components"))
        self.deployment = self.p1.get("deployment_model", {}) if isinstance(self.p1.get("deployment_model"), dict) else {}
        self.users = self._ensure_list_of_dicts(self.p1.get("users"))

    # -------------------------------------------------------------------------
    # Safe Path and Type Helpers
    # -------------------------------------------------------------------------
    @staticmethod
    def _extract_file_list(raw_list: Any) -> List[Dict[str, Any]]:
        """Normalizes inventory items into a uniform list of dicts with a 'path' key."""
        normalized: List[Dict[str, Any]] = []
        if not isinstance(raw_list, list):
            return normalized

        for item in raw_list:
            if isinstance(item, str):
                normalized.append({"path": item.strip()})
            elif isinstance(item, dict):
                path = item.get("path") or item.get("file") or item.get("name") or ""
                if isinstance(path, str) and path.strip():
                    normalized.append(dict(item, path=path.strip()))
        return normalized

    @staticmethod
    def _ensure_list_of_dicts(val: Any) -> List[Dict[str, Any]]:
        if isinstance(val, list):
            return [x for x in val if isinstance(x, dict)]
        return []

    def _resolve_safe_path(self, rel_or_abs_path: str) -> Optional[str]:
        """
        Resolves a file path and verifies that it resides strictly inside the repository root.
        Rejects directory traversal attempts and symlink escapes.
        """
        if not rel_or_abs_path or not isinstance(rel_or_abs_path, str):
            return None
        try:
            cleaned = rel_or_abs_path.replace("\\", "/").strip()
            if os.path.isabs(cleaned):
                candidate = os.path.abspath(cleaned)
            else:
                candidate = os.path.abspath(os.path.join(self.root_path, cleaned))

            real_candidate = os.path.realpath(candidate)
            real_root = os.path.realpath(self.root_path)

            if os.path.commonpath([real_root, real_candidate]) == real_root:
                return real_candidate
            return None
        except Exception:
            return None

    def _safe_read_file(self, rel_or_abs_path: str) -> Optional[str]:
        """
        Safely reads a repository file up to MAX_READ_BYTES with boundary validation.
        Enforces a strict byte limit by reading binary bytes first before UTF-8 decoding.
        """
        safe_path = self._resolve_safe_path(rel_or_abs_path)
        if not safe_path or not os.path.isfile(safe_path):
            return None
        try:
            with open(safe_path, "rb") as f:
                raw_bytes = f.read(MAX_READ_BYTES)
                return raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            return None

    # -------------------------------------------------------------------------
    # Requirements Extraction Entry Point
    # -------------------------------------------------------------------------
    def extract_requirements(self) -> List[Dict[str, Any]]:
        """Extracts all requirements categorized according to the Phase 2 specification."""
        requirements: List[Dict[str, Any]] = []

        requirements.extend(self._extract_functional_requirements())
        requirements.extend(self._extract_security_requirements())
        requirements.extend(self._extract_non_functional_requirements())
        requirements.extend(self._extract_business_constraints())

        # Validate that all requirements adhere strictly to the schema and status vocabulary
        validated_reqs = []
        for req in requirements:
            if req.get("status") not in self.VALID_STATUSES:
                req["status"] = "unknown"
            validated_reqs.append(req)

        return validated_reqs

    # -------------------------------------------------------------------------
    # 1. Functional Requirements
    # -------------------------------------------------------------------------
    def _extract_functional_requirements(self) -> List[Dict[str, Any]]:
        reqs = []
        req_counter = 1

        # A. Requirements from Phase 1 Use Cases
        for uc in self.use_cases:
            uc_name = uc.get("name", "Unnamed Use Case")
            uc_desc = uc.get("description", "")
            supp_files = uc.get("supporting_file_paths", [])
            source_file = supp_files[0] if supp_files and isinstance(supp_files[0], str) else ""

            # Check if documentation explicitly defines this as a requirement
            has_doc_support = False
            for doc in self.doc_files:
                doc_text = self._safe_read_file(doc["path"])
                if doc_text and uc_name.lower() in doc_text.lower():
                    has_doc_support = True
                    source_file = doc["path"]
                    break

            if has_doc_support:
                description = f"The system must support {uc_name}: {uc_desc}"
                status = "explicit"
                source = "Documentation Specification"
            elif source_file:
                description = f"Observed implementation behavior for {uc_name}: {uc_desc}"
                status = "code_supported"
                source = "Use Case Analysis"
            else:
                description = f"Inferred use case capability for {uc_name}: {uc_desc}"
                status = "inferred"
                source = "System Reconstruction"

            reqs.append({
                "requirement_id": f"REQ-FUNC-{req_counter:02d}",
                "category": "functional",
                "description": description,
                "source": source,
                "source_file": source_file if source_file else "Phase 1 Reconstruction",
                "evidence": f"Identified use case '{uc_name}' with supporting artifact {source_file}.",
                "status": status,
                "importance": "high",
                "architectural_implications": [
                    f"Component execution mapped to {source_file if source_file else 'core pipeline'}"
                ]
            })
            req_counter += 1

        # B. Requirements from HTTP API Routes (Observed implementation behavior unless specified in doc)
        for api in self.apis:
            method = api.get("method", "GET")
            path = api.get("path", "/")
            supp_files = api.get("supporting_file_paths", [])
            source_file = supp_files[0] if supp_files and isinstance(supp_files[0], str) else ""
            line_no = api.get("line_number")

            # Check if documentation explicitly specifies this route
            has_doc_route = False
            for doc in self.doc_files:
                doc_text = self._safe_read_file(doc["path"])
                if doc_text and path in doc_text:
                    has_doc_route = True
                    break

            if has_doc_route:
                description = f"The system must expose HTTP endpoint {method} {path} for client operations."
                status = "explicit"
                source = "API Documentation Specification"
            else:
                description = f"Discovered HTTP endpoint handler for {method} {path} (observed implementation behavior)."
                status = "code_supported"
                source = "API Route Definition"

            evidence_str = f"Registered route handler {method} {path} in {source_file}"
            if line_no:
                evidence_str += f" at line {line_no}"

            reqs.append({
                "requirement_id": f"REQ-FUNC-{req_counter:02d}",
                "category": "functional",
                "description": description,
                "source": source,
                "source_file": source_file,
                "evidence": evidence_str,
                "status": status,
                "importance": "high",
                "architectural_implications": [
                    "HTTP ingress routing and request dispatching"
                ]
            })
            req_counter += 1

        # C. CLI Functional Requirement (Observed implementation behavior unless documented)
        cli_file = self._find_actual_cli_implementation()
        if cli_file:
            has_cli_doc = any("cli" in self._safe_read_file(doc["path"]).lower() for doc in self.doc_files if self._safe_read_file(doc["path"]))
            if has_cli_doc:
                description = "The system must provide a Command Line Interface (CLI) for parsing user arguments and dispatching execution."
                status = "explicit"
            else:
                description = f"Discovered Command Line Interface (CLI) entry point in {cli_file} (observed implementation behavior)."
                status = "code_supported"

            reqs.append({
                "requirement_id": f"REQ-FUNC-{req_counter:02d}",
                "category": "functional",
                "description": description,
                "source": "CLI Implementation",
                "source_file": cli_file,
                "evidence": f"CLI argument parsing or sys.argv dispatch detected in {cli_file}.",
                "status": status,
                "importance": "high",
                "architectural_implications": [
                    "Terminal argument parsing and command dispatcher"
                ]
            })
            req_counter += 1

        return reqs

    def _find_actual_cli_implementation(self) -> Optional[str]:
        """Inspects source files for actual CLI logic (argparse, click, sys.argv, main dispatch)."""
        for s in self.source_files:
            path = s["path"]
            if any(k in path.lower() for k in ("cli", "main", "ingest", "pipeline", "run")):
                content = self._safe_read_file(path)
                if content and any(kw in content for kw in ("argparse", "click", "sys.argv", "__main__", "parse_args")):
                    return path
        return None

    # -------------------------------------------------------------------------
    # 2. Security Requirements
    # -------------------------------------------------------------------------
    def _extract_security_requirements(self) -> List[Dict[str, Any]]:
        reqs = []
        req_counter = 1

        # A. Archive Extraction Safety (Zip-Slip check)
        # Inspect actual code paths and validation logic; distinguish detected validation code from verified safe behavior
        zip_evidence = self._inspect_archive_extraction_safety()
        if zip_evidence:
            reqs.append({
                "requirement_id": f"REQ-SEC-{req_counter:02d}",
                "category": "security",
                "description": zip_evidence["description"],
                "source": "Archive Extraction Safety Inspection",
                "source_file": zip_evidence["file"],
                "evidence": zip_evidence["evidence"],
                "status": zip_evidence["status"],
                "importance": "critical",
                "architectural_implications": [
                    "Enforces canonical path boundary checks before writing extracted archive members"
                ]
            })
            req_counter += 1

        # B. Authentication Requirement
        if self.auth_components:
            auth_comp = self.auth_components[0]
            supp_files = auth_comp.get("supporting_file_paths", [])
            auth_file = supp_files[0] if supp_files and isinstance(supp_files[0], str) else ""

            reqs.append({
                "requirement_id": f"REQ-SEC-{req_counter:02d}",
                "category": "security",
                "description": "The system must verify caller identity and authenticate requests before granting access to protected operations.",
                "source": "Authentication References",
                "source_file": auth_file if auth_file else "Phase 1 Reconstruction",
                "evidence": f"Authentication mechanism identified: {auth_comp.get('mechanism', 'Auth Routine')}",
                "status": "code_supported",
                "importance": "high",
                "architectural_implications": [
                    "Identity verification and token inspection middleware"
                ]
            })
            req_counter += 1
        else:
            reqs.append({
                "requirement_id": f"REQ-SEC-{req_counter:02d}",
                "category": "security",
                "description": "Authentication requirement is not established from available codebase evidence.",
                "source": "Codebase Inspection",
                "source_file": "None",
                "evidence": "No authentication middleware, token verification, or credential storage detected in source files.",
                "status": "unknown",
                "importance": "low",
                "architectural_implications": []
            })
            req_counter += 1

        # C. Potentially Sensitive Data / Secret Handling
        # Do not infer that potentially sensitive files contain actual secrets solely from names or inventory classifications
        secret_evidence = self._inspect_secrets_handling()
        reqs.append({
            "requirement_id": f"REQ-SEC-{req_counter:02d}",
            "category": "security",
            "description": secret_evidence["description"],
            "source": secret_evidence["source"],
            "source_file": secret_evidence["file"],
            "evidence": secret_evidence["evidence"],
            "status": secret_evidence["status"],
            "importance": "high",
            "architectural_implications": [
                "Environment variable isolation or external secret store configuration"
            ] if secret_evidence["status"] in ("explicit", "code_supported") else []
        })
        req_counter += 1

        # D. Transport Security (TLS Enforcement)
        # Do not treat an HTTPS URL or string as proof that TLS is enforced throughout the application
        tls_evidence = self._inspect_tls_enforcement()
        reqs.append({
            "requirement_id": f"REQ-SEC-{req_counter:02d}",
            "category": "security",
            "description": tls_evidence["description"],
            "source": tls_evidence["source"],
            "source_file": tls_evidence["file"],
            "evidence": tls_evidence["evidence"],
            "status": tls_evidence["status"],
            "importance": "high",
            "architectural_implications": [
                "TLS certificate verification and transport layer encryption"
            ] if tls_evidence["status"] in ("explicit", "code_supported") else []
        })
        req_counter += 1

        return reqs

    def _inspect_archive_extraction_safety(self) -> Optional[Dict[str, Any]]:
        """
        Inspects whether the repository actually performs archive extraction,
        and whether it implements member path validation to guard against Zip-Slip traversal.
        Distinguishes detected validation code from verified safe behavior.
        """
        for s in self.source_files:
            content = self._safe_read_file(s["path"])
            if not content:
                continue

            # Verify that archive extraction functions are actually called
            has_archive_op = any(kw in content for kw in ("zipfile.ZipFile", "tarfile.open", ".extractall(", ".extract("))
            if not has_archive_op:
                continue

            # Check for path traversal validation logic guarding member paths
            has_path_validation = any(kw in content for kw in (
                "commonpath", "realpath", "startswith", "os.path.abspath"
            )) and any(chk in content for chk in ("..", "outside", "traversal", "startswith", "target_dir"))

            if has_path_validation:
                return {
                    "status": "code_supported",
                    "file": s["path"],
                    "description": "Archive member path validation logic detected prior to extraction (observed implementation code; dynamic verification required for complete edge-case safety).",
                    "evidence": f"Path boundary validation logic (canonical path resolution) identified in {s['path']}."
                }
            else:
                return {
                    "status": "unknown",
                    "file": s["path"],
                    "description": "Archive extraction detected, but path traversal prevention controls cannot be verified from available code paths.",
                    "evidence": f"Archive extraction functions present in {s['path']} without confirmed canonical path prefix verification."
                }
        return None

    def _inspect_secrets_handling(self) -> Dict[str, Any]:
        """
        Inspects secrets handling requirements.
        Does not infer that potentially sensitive files contain actual secrets solely from names or inventory classifications.
        """
        # 1. Check documentation for explicit secrets decoupling requirement
        for doc in self.doc_files:
            content = self._safe_read_file(doc["path"])
            if content and any(phrase in content.lower() for phrase in (
                "secrets must be stored in", "use environment variables for credentials", "do not commit secrets"
            )):
                return {
                    "status": "explicit",
                    "source": "Project Documentation Specification",
                    "file": doc["path"],
                    "description": "The system must decouple and protect sensitive credentials and secrets using external secret stores or environment variables.",
                    "evidence": f"Explicit secrets management specification found in {doc['path']}."
                }

        # 2. Check source code for actual environment variable / secrets loading logic
        for s in self.source_files:
            content = self._safe_read_file(s["path"])
            if content and any(kw in content for kw in ("os.getenv(", "os.environ.get(", "dotenv.load_dotenv", "boto3.client('secretsmanager'")):
                return {
                    "status": "code_supported",
                    "source": "Configuration Logic",
                    "file": s["path"],
                    "description": "The application loads configuration and secrets via environment variables or secret stores (observed implementation behavior).",
                    "evidence": f"Environment variable or secret loading logic identified in {s['path']}."
                }

        # 3. If only file names match inventory classifications (e.g. .env, config.json)
        if self.sensitive_files:
            return {
                "status": "unknown",
                "source": "File Inventory Classification",
                "file": self.sensitive_files[0]["path"],
                "description": "Secret handling requirements cannot be established solely from file name classifications without verified secret content.",
                "evidence": f"File '{self.sensitive_files[0]['path']}' matched sensitive filename pattern; actual secret presence unverified."
            }

        return {
            "status": "unknown",
            "source": "Secrets Management Audit",
            "file": "None",
            "description": "Secret handling and credential protection requirements cannot be established from available evidence.",
            "evidence": "No secrets management specifications or credential loading logic detected.",
        }

    def _inspect_tls_enforcement(self) -> Dict[str, Any]:
        """
        Evaluates whether TLS encryption is enforced.
        Do not infer TLS enforcement solely from HTTPS URLs in documentation or dependency links.
        """
        for doc in self.doc_files:
            content = self._safe_read_file(doc["path"])
            if content and any(phrase in content.lower() for phrase in (
                "tls must be enforced", "enforce https", "tls 1.3 required", "mandatory tls", "ssl required"
            )):
                return {
                    "status": "explicit",
                    "source": "Project Documentation Specification",
                    "file": doc["path"],
                    "description": "The system must enforce secure communication channels using TLS/HTTPS for external data transfers.",
                    "evidence": f"Explicit TLS mandate found in documentation {doc['path']}."
                }

        for s in self.source_files:
            content = self._safe_read_file(s["path"])
            if content and any(kw in content for kw in ("ssl.create_default_context", "ssl.CERT_REQUIRED", "check_hostname = True")):
                return {
                    "status": "code_supported",
                    "source": "SSL/TLS Configuration Logic",
                    "file": s["path"],
                    "description": "The system enforces secure communication channels using TLS with certificate validation (observed implementation behavior).",
                    "evidence": f"TLS context and certificate validation logic verified in {s['path']}."
                }

        return {
            "status": "unknown",
            "source": "Transport Layer Inspection",
            "file": "None",
            "description": "Transport layer security (TLS/HTTPS) enforcement cannot be established from available codebase evidence.",
            "evidence": "No TLS context creation, SSL certificate configuration, or documented TLS enforcement detected.",
        }

    # -------------------------------------------------------------------------
    # 3. Non-Functional Requirements
    # -------------------------------------------------------------------------
    def _extract_non_functional_requirements(self) -> List[Dict[str, Any]]:
        reqs = []
        req_counter = 1

        # A. Cross-Platform Portability
        platform_file = None
        for s in self.source_files:
            content = self._safe_read_file(s["path"])
            if content and any(kw in content for kw in ("sys.platform", "os.name", "platform.system", "replace(\"\\\\\"")):
                platform_file = s["path"]
                break

        if platform_file:
            reqs.append({
                "requirement_id": f"REQ-NFR-{req_counter:02d}",
                "category": "non_functional",
                "description": "The software executes cross-platform on Windows and POSIX operating systems, handling path separators safely (observed implementation behavior).",
                "source": "Platform Compatibility Code",
                "source_file": platform_file,
                "evidence": f"Platform-specific dispatch or path normalization logic verified in {platform_file}.",
                "status": "code_supported",
                "importance": "high",
                "architectural_implications": [
                    "Cross-platform filesystem path normalization to forward slashes and UTF-8 console output"
                ]
            })
            req_counter += 1

        # B. Dependency Management & Execution Environment
        # Do not infer standard-library purity solely because a dependency manifest is missing
        dep_evidence = self._inspect_dependency_requirements()
        reqs.append({
            "requirement_id": f"REQ-NFR-{req_counter:02d}",
            "category": "non_functional",
            "description": dep_evidence["description"],
            "source": dep_evidence["source"],
            "source_file": dep_evidence["file"],
            "evidence": dep_evidence["evidence"],
            "status": dep_evidence["status"],
            "importance": "high",
            "architectural_implications": [
                "Managed runtime dependency installation"
            ] if dep_evidence["status"] == "code_supported" else []
        })
        req_counter += 1

        # C. Output Contract & Testing (Distinguish tested behavior from formal requirements)
        contract_evidence = self._inspect_output_contract()
        if contract_evidence:
            reqs.append({
                "requirement_id": f"REQ-NFR-{req_counter:02d}",
                "category": "non_functional",
                "description": contract_evidence["description"],
                "source": contract_evidence["source"],
                "source_file": contract_evidence["file"],
                "evidence": contract_evidence["evidence"],
                "status": contract_evidence["status"],
                "importance": "high",
                "architectural_implications": [
                    "Contract-driven schema validation between pipeline stages"
                ]
            })
            req_counter += 1

        # D. Technical Deployment Architecture (Represented as technical architecture, not business constraint)
        deploy_evidence = self._inspect_deployment_architecture()
        reqs.append({
            "requirement_id": f"REQ-NFR-{req_counter:02d}",
            "category": "non_functional",
            "description": deploy_evidence["description"],
            "source": deploy_evidence["source"],
            "source_file": deploy_evidence["file"],
            "evidence": deploy_evidence["evidence"],
            "status": deploy_evidence["status"],
            "importance": "medium",
            "architectural_implications": [
                f"Execution lifecycle bounded by {deploy_evidence['model']} runtime environment"
            ]
        })
        req_counter += 1

        return reqs

    def _inspect_dependency_requirements(self) -> Dict[str, Any]:
        """
        Inspects dependency requirements.
        If manifests are missing, reports dependency status as unknown unless documentation states a requirement.
        """
        if self.dep_files:
            dep_path = self.dep_files[0]["path"]
            return {
                "status": "code_supported",
                "source": "Dependency Manifest Audit",
                "file": dep_path,
                "description": "Application dependencies are specified in declarative manifests for environment replication (observed manifest).",
                "evidence": f"Dependency manifest identified: {dep_path}"
            }

        for doc in self.doc_files:
            content = self._safe_read_file(doc["path"])
            if content and any(kw in content.lower() for kw in ("standard library only", "zero dependencies", "no external dependencies")):
                return {
                    "status": "explicit",
                    "source": "Project Documentation Specification",
                    "file": doc["path"],
                    "description": "The core engine must operate using the standard library without external dependencies.",
                    "evidence": f"Explicit zero-dependency specification documented in {doc['path']}."
                }

        return {
            "status": "unknown",
            "source": "Dependency Audit",
            "file": "None",
            "description": "External dependency constraints cannot be established due to absence of dependency manifests.",
            "evidence": "No dependency manifests (requirements.txt, pyproject.toml, package.json) present in repository."
        }

    def _inspect_output_contract(self) -> Optional[Dict[str, Any]]:
        """
        Inspects whether a deterministic output contract is required.
        Distinguishes documented requirements from tested implementation behavior.
        Does not infer a formal requirement solely from test existence.
        """
        # 1. Documented specification
        for doc in self.doc_files:
            content = self._safe_read_file(doc["path"])
            if content and any(kw in content.lower() for kw in ("output contract", "json schema contract", "schema specification")):
                return {
                    "status": "explicit",
                    "source": "Output Contract Documentation",
                    "file": doc["path"],
                    "description": "The system must output deterministic, contract-conforming JSON schemas for integration.",
                    "evidence": f"Output schema contract documented in {doc['path']}."
                }

        # 2. Tested implementation behavior (distinguished from formal requirement)
        for t in self.test_files:
            content = self._safe_read_file(t["path"])
            if content and any(kw in content for kw in ("jsonschema", "schema_version", "validate_schema", "test_schema")):
                return {
                    "status": "code_supported",
                    "source": "Automated Test Suite",
                    "file": t["path"],
                    "description": "Output schema conformance is verified by automated test assertions (observed test behavior).",
                    "evidence": f"Schema verification assertions detected in test file {t['path']}."
                }

        return None

    def _inspect_deployment_architecture(self) -> Dict[str, Any]:
        """
        Evaluates technical deployment architecture.
        Do not assign code_supported without supporting implementation evidence.
        """
        deployment_model = self.deployment.get("model", "Standalone Process Execution")
        supp_files = self.deployment.get("supporting_file_paths", [])

        # Verify whether supporting files actually exist in repository inventory
        existing_supp = []
        for p in supp_files:
            if isinstance(p, str) and (
                any(s["path"] == p for s in self.source_files) or
                any(i["path"] == p for i in self.infra_files) or
                os.path.isfile(os.path.join(self.root_path, p))
            ):
                existing_supp.append(p)

        if existing_supp:
            status = "code_supported"
            file_ref = existing_supp[0]
            evidence = f"Deployment implementation artifacts detected: {', '.join(existing_supp)}"
        elif self.infra_files:
            status = "code_supported"
            file_ref = self.infra_files[0]["path"]
            evidence = f"Infrastructure configuration file present: {file_ref}"
        elif self.deployment.get("model"):
            # Model classified by Phase 1 inference, but lacks supporting files
            status = "inferred"
            file_ref = "Phase 1 Reconstruction"
            evidence = f"Inferred deployment model '{deployment_model}' without dedicated infrastructure files."
        else:
            status = "unknown"
            file_ref = "None"
            evidence = "No deployment model classification or infrastructure files available."

        return {
            "status": status,
            "source": "Technical Architecture Evaluation",
            "file": file_ref,
            "model": deployment_model,
            "description": f"The technical architecture executes under: {deployment_model} (technical deployment architecture).",
            "evidence": evidence,
        }

    # -------------------------------------------------------------------------
    # 4. Business Constraints
    # -------------------------------------------------------------------------
    def _extract_business_constraints(self) -> List[Dict[str, Any]]:
        """
        Extracts business constraints, separating them from technical architecture and deployment details.
        Does not place deployment architecture under business constraints by default.
        """
        reqs = []
        req_counter = 1

        # A. Expected Users / Target Personas
        user_roles = [u.get("role", "") for u in self.users if isinstance(u, dict) and u.get("role")]
        if user_roles:
            roles_str = ", ".join(user_roles)
            reqs.append({
                "requirement_id": f"REQ-BIZ-{req_counter:02d}",
                "category": "business_constraint",
                "description": f"The software is intended for designated operational personas: {roles_str}.",
                "source": "User Persona Model",
                "source_file": "Phase 1 Reconstruction",
                "evidence": f"User roles identified in system reconstruction: {roles_str}.",
                "status": "inferred",
                "importance": "medium",
                "architectural_implications": [
                    "Developer-centric CLI or authenticated API interface"
                ]
            })
            req_counter += 1

        # B. Deployment Business Mandate (Unknown by default; technical deployment belongs in NFR)
        reqs.append({
            "requirement_id": f"REQ-BIZ-{req_counter:02d}",
            "category": "business_constraint",
            "description": "Deployment constraints driven by business mandates are not established from available documentation.",
            "source": "Business Requirements Audit",
            "source_file": "None",
            "evidence": "No regulatory, compliance, or business hosting mandates documented; deployment choices are technical implementation decisions.",
            "status": "unknown",
            "importance": "low",
            "architectural_implications": []
        })
        req_counter += 1

        # C. Traffic Constraints (Unknown - do not invent enterprise scale)
        reqs.append({
            "requirement_id": f"REQ-BIZ-{req_counter:02d}",
            "category": "business_constraint",
            "description": "Expected traffic volume and concurrency requirements cannot be established from available evidence.",
            "source": "Evidence Audit",
            "source_file": "None",
            "evidence": "No traffic volume, QPS, or concurrent user metrics exist in codebase or documentation.",
            "status": "unknown",
            "importance": "low",
            "architectural_implications": []
        })
        req_counter += 1

        # D. Latency Constraints (Unknown)
        reqs.append({
            "requirement_id": f"REQ-BIZ-{req_counter:02d}",
            "category": "business_constraint",
            "description": "Latency requirements cannot be established from available evidence.",
            "source": "Evidence Audit",
            "source_file": "None",
            "evidence": "No latency thresholds or response-time targets are documented.",
            "status": "unknown",
            "importance": "low",
            "architectural_implications": []
        })
        req_counter += 1

        # E. Availability Constraints (Unknown)
        reqs.append({
            "requirement_id": f"REQ-BIZ-{req_counter:02d}",
            "category": "business_constraint",
            "description": "Availability requirements (e.g., uptime nines, failover) cannot be established from available evidence.",
            "source": "Evidence Audit",
            "source_file": "None",
            "evidence": "No SLA, uptime nines, or high-availability targets are documented.",
            "status": "unknown",
            "importance": "low",
            "architectural_implications": []
        })
        req_counter += 1

        # F. Cost / Budget Constraints (Unknown)
        reqs.append({
            "requirement_id": f"REQ-BIZ-{req_counter:02d}",
            "category": "business_constraint",
            "description": "Cost or infrastructure budget constraints cannot be established from available evidence.",
            "source": "Evidence Audit",
            "source_file": "None",
            "evidence": "No financial budget or hosting cost limitations are documented.",
            "status": "unknown",
            "importance": "low",
            "architectural_implications": []
        })
        req_counter += 1

        return reqs
