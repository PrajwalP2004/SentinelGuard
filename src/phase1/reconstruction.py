"""
Phase 1: Project Reconstruction Agent Module.

Reconstructs the intended and implemented behavior of the supplied software project
using the Phase 0 structural inventory and repository source files.

Distinguishes:
- DOCUMENTED: Facts supported directly by documentation.
- CODE_SUPPORTED: Facts verified by source code and manifests.
- INFERRED: Reasonable engineering deductions based on evidence.
- UNKNOWN: Information that cannot be determined from available artifacts.
"""

import os
import re
import json
from typing import Dict, List, Any, Optional, Set

MAX_READ_BYTES = 5 * 1024 * 1024  # 5 MB maximum buffer read limit


class ProjectReconstructionAgent:
    """Agent that reconstructs software behavior, architecture, data flows, and trust boundaries."""

    def __init__(self, root_path: str, phase0_inventory: Dict[str, Any]):
        if not isinstance(phase0_inventory, dict):
            raise TypeError(f"phase0_inventory must be a dict, got {type(phase0_inventory).__name__}")
        if not root_path or not isinstance(root_path, str) or not root_path.strip():
            raise ValueError("root_path must be a non-empty string directory path")

        # Validate that phase0_inventory contains inventory data
        if "repository" not in phase0_inventory and "source_files" not in phase0_inventory and "file_inventory" not in phase0_inventory:
            raise ValueError("phase0_inventory must contain valid repository inventory data")

        self.root_path = os.path.abspath(root_path)
        self.p0 = phase0_inventory
        self.source_files = self.p0.get("source_files") if isinstance(self.p0.get("source_files"), list) else []
        self.doc_files = self.p0.get("documentation_files") if isinstance(self.p0.get("documentation_files"), list) else []
        self.config_files = self.p0.get("configuration_files") if isinstance(self.p0.get("configuration_files"), list) else []
        self.dep_files = self.p0.get("dependency_files") if isinstance(self.p0.get("dependency_files"), list) else []
        self.infra_files = self.p0.get("infrastructure_files") if isinstance(self.p0.get("infrastructure_files"), list) else []
        self.test_files = self.p0.get("test_files") if isinstance(self.p0.get("test_files"), list) else []
        self.warnings = list(self.p0.get("warnings", []))

    def reconstruct(self) -> Dict[str, Any]:
        """Executes full project reconstruction and outputs the Phase 1 schema."""
        docs_text = self._read_documentation()
        code_findings = self._scan_source_code()

        users = self._determine_users(docs_text, code_findings)
        use_cases = self._determine_use_cases(docs_text, code_findings)
        summary = self._determine_project_summary(docs_text, code_findings, use_cases=use_cases)
        components = self._determine_components(code_findings)
        architecture = self._determine_architecture(code_findings)
        data_flows = self._determine_data_flows(code_findings)
        trust_boundaries = self._determine_trust_boundaries(code_findings)
        entry_points = self._determine_entry_points(code_findings)
        apis = self._determine_apis(code_findings)
        databases = self._determine_databases(code_findings)
        external_services = self._determine_external_services(code_findings)
        dependencies = self._determine_dependencies()
        auth_components = self._determine_auth_components(code_findings)
        deployment_model = self._determine_deployment_model()

        documented_behavior = self._extract_documented_behavior(docs_text)
        code_supported_behavior = self._extract_code_supported_behavior(code_findings)
        inferences = self._extract_inferences(summary, users, architecture)
        unknowns = self._identify_unknowns(databases, deployment_model, auth_components)

        reconstruction_status = "PARTIAL" if self.p0.get("ingestion_status") == "PARTIAL" else "COMPLETE"
        if reconstruction_status == "PARTIAL":
            unknowns.append({
                "item": "Incomplete Repository Scan",
                "classification": "UNKNOWN",
                "description": f"Phase 0 ingestion was partial. Some files or directories were skipped due to resource limits: {self.warnings}"
            })

        return {
            "schema_version": "1.0.0",
            "reconstruction_status": reconstruction_status,
            "warnings": self.warnings,
            "project_summary": summary,
            "users": users,
            "use_cases": use_cases,
            "components": components,
            "architecture": architecture,
            "data_flows": data_flows,
            "trust_boundaries": trust_boundaries,
            "entry_points": entry_points,
            "apis": apis,
            "databases": databases,
            "external_services": external_services,
            "dependencies": dependencies,
            "authentication_components": auth_components,
            "deployment_model": deployment_model,
            "documented_behavior": documented_behavior,
            "code_supported_behavior": code_supported_behavior,
            "inferences": inferences,
            "unknowns": unknowns,
        }

    def _read_documentation(self) -> Dict[str, str]:
        """Reads documentation files for textual evidence with path safety."""
        docs = {}
        for d in self.doc_files:
            rel = d.get("path", "")
            if not rel:
                continue
            full = os.path.abspath(os.path.join(self.root_path, rel))
            if not (full == self.root_path or full.startswith(self.root_path + os.sep)):
                continue
            try:
                if os.path.isfile(full):
                    with open(full, "r", encoding="utf-8", errors="ignore") as f:
                        docs[rel] = f.read(MAX_READ_BYTES)
            except (OSError, UnicodeDecodeError, PermissionError):
                pass
        return docs

    def _scan_source_code(self) -> Dict[str, Any]:
        """Scans source code for patterns (routes, auth, models, entry points) with path bounds checking."""
        findings: Dict[str, Any] = {
            "routes": [],
            "models": [],
            "auth_references": [],
            "db_references": [],
            "entry_files": [],
            "external_clients": [],
            "has_cli": False,
            "has_web_api": False,
            "has_frontend": False,
        }

        # Check entry points from Phase 0
        for ep in self.p0.get("entry_point_candidates", []):
            findings["entry_files"].append(ep["path"])
            if ep["path"].endswith(".py") and "cli" in ep["path"].lower():
                findings["has_cli"] = True

        for s in self.source_files:
            rel = s.get("path", "")
            if not rel:
                continue
            full = os.path.abspath(os.path.join(self.root_path, rel))
            # Verify file access remains strictly within intended repository root
            if not (full == self.root_path or full.startswith(self.root_path + os.sep)):
                continue
            if not os.path.isfile(full):
                continue

            is_test_file = (
                any(t in rel.lower() for t in ("/tests/", "/test/", "test_"))
                or rel.lower().endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts"))
            )

            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(MAX_READ_BYTES)

                # 1. HTTP Route Detection (exclude test mocks from production API routes)
                if not is_test_file:
                    # Python FastAPI / Starlette
                    for match in re.finditer(
                        r'@\w+\.(get|post|put|delete|patch)\([\'"]([/][^\'"]*)[\'"]',
                        content,
                        re.IGNORECASE
                    ):
                        method, path = match.group(1), match.group(2)
                        line_number = content[:match.start()].count("\n") + 1
                        entry = {"method": method.upper(), "path": path, "file": rel, "line_number": line_number}
                        if not any(r["method"] == entry["method"] and r["path"] == entry["path"] and r["file"] == entry["file"] for r in findings["routes"]):
                            findings["routes"].append(entry)
                            findings["has_web_api"] = True

                    # Flask @app.route / @bp.route
                    for match in re.finditer(
                        r'@\w+\.route\([\'"]([/][^\'"]*)[\'"](?:\s*,\s*methods\s*=\s*[\[\(]([^\]\)]+)[\]\)])?',
                        content
                    ):
                        path, methods_str = match.group(1), match.group(2)
                        line_number = content[:match.start()].count("\n") + 1
                        if methods_str:
                            methods = [m.strip(" '\"").upper() for m in methods_str.split(",") if m.strip(" '\"")]
                        else:
                            methods = ["GET"]
                        for m in methods:
                            entry = {"method": m, "path": path, "file": rel, "line_number": line_number}
                            if not any(r["method"] == entry["method"] and r["path"] == entry["path"] and r["file"] == entry["file"] for r in findings["routes"]):
                                findings["routes"].append(entry)
                        findings["has_web_api"] = True

                    # Node/Express routes - strictly requiring leading slash to avoid false positives like map.get('key')
                    for match in re.finditer(
                        r'(?:app|router)\.(get|post|put|delete|patch)\([\'"]([/][^\'"]*)[\'"]',
                        content,
                        re.IGNORECASE
                    ):
                        method, path = match.group(1), match.group(2)
                        line_number = content[:match.start()].count("\n") + 1
                        entry = {"method": method.upper(), "path": path, "file": rel, "line_number": line_number}
                        if not any(r["method"] == entry["method"] and r["path"] == entry["path"] and r["file"] == entry["file"] for r in findings["routes"]):
                            findings["routes"].append(entry)
                            findings["has_web_api"] = True

                # 2. CLI patterns
                if "argparse.ArgumentParser" in content or "click.command" in content or "sys.argv" in content:
                    findings["has_cli"] = True

                # 3. Frontend patterns: Require actual UI directory or UI DOM/component code
                in_ui_dir = any(ui_kw in rel.lower() for ui_kw in ("web/", "ui/", "frontend/", "client/", "public/", "static/"))
                if s.get("language") in ("HTML", "CSS") and in_ui_dir:
                    findings["has_frontend"] = True
                elif s.get("language") in ("JavaScript", "TypeScript"):
                    if (
                        "document.getElementById" in content
                        or "document.querySelector" in content
                        or "ReactDOM." in content
                        or "from 'react'" in content
                        or 'from "react"' in content
                        or "from 'vue'" in content
                        or 'from "vue"' in content
                    ):
                        findings["has_frontend"] = True

                # 4. Authentication patterns: require specific security/auth tokens, avoid generic word "token"
                auth_regexes = [
                    r'\b(jwt|oauth2?|bearer|password_hash|bcrypt|argon2|login_required|authenticate|authorization)\b',
                    r'\b(access_token|refresh_token|auth_token)\b'
                ]
                for pat in auth_regexes:
                    match = re.search(pat, content, re.IGNORECASE)
                    if match:
                        line_number = content[:match.start()].count("\n") + 1
                        findings["auth_references"].append({
                            "keyword": match.group(1),
                            "file": rel,
                            "line_number": line_number
                        })
                        break

                # 5. Database patterns: actual library imports or cursor execution
                db_regexes = [
                    r'\b(sqlite3|sqlalchemy|prisma|mongoose|sequelize|psycopg2?|asyncpg|pymongo|mysqlclient|pymysql)\b',
                    r'\bcursor\.execute\b'
                ]
                for pat in db_regexes:
                    match = re.search(pat, content, re.IGNORECASE)
                    if match:
                        line_number = content[:match.start()].count("\n") + 1
                        findings["db_references"].append({
                            "keyword": match.group(1) if match.lastindex else "cursor.execute",
                            "file": rel,
                            "line_number": line_number
                        })
                        break

                # 6. External client calls
                client_patterns = [
                    (r'\brequests\.(?:get|post|put|delete)\b', "HTTP Client (requests)"),
                    (r'\bhttpx\.(?:get|post|put|delete)\b', "HTTP Client (httpx)"),
                    (r'\baxios\.(?:get|post|put|delete)\b', "HTTP Client (axios)"),
                    (r'\bfetch\(', "Fetch API Client")
                ]
                for pat, client_name in client_patterns:
                    match = re.search(pat, content)
                    if match:
                        line_number = content[:match.start()].count("\n") + 1
                        if not any(c.get("name") == client_name for c in findings["external_clients"]):
                            findings["external_clients"].append({
                                "name": client_name,
                                "detected_in": rel,
                                "line_number": line_number,
                                "reference_type": "source_code_http_client"
                            })

            except (OSError, UnicodeDecodeError, PermissionError):
                pass

        return findings

    def _determine_project_summary(
        self,
        docs: Dict[str, str],
        findings: Dict[str, Any],
        use_cases: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        app_type = "Library / CLI Tool"
        if findings["has_web_api"] and findings["has_frontend"]:
            app_type = "Full-Stack Web Application"
        elif findings["has_web_api"]:
            app_type = "Web API / Backend Service"
        elif findings["has_frontend"]:
            app_type = "Client-Side Frontend Application"
        elif findings["has_cli"]:
            app_type = "Command-Line Interface (CLI) Application"

        doc_paths = [p for p in docs.keys() if "readme" in p.lower()]
        summary_doc = docs.get(doc_paths[0], "") if doc_paths else ""

        # Extract first meaningful non-header, non-badge, non-HTML paragraph
        lines = []
        for line in summary_doc.split("\n"):
            stripped = line.strip()
            if not stripped:
                continue
            # Skip markdown headings, badges, image syntax, raw HTML tags, URLs
            if stripped.startswith(("#", "[!", "<", "---", "http://", "https://", "!")):
                continue
            # Skip lines that are mostly punctuation/badges or contain HTML
            if "<img" in stripped or "<div" in stripped or "<a " in stripped or "align=" in stripped:
                continue
            # Skip very short lines (likely labels or stray text)
            if len(stripped) < 20:
                continue
            lines.append(stripped)
        problem_statement = lines[0] if lines else "General-purpose software application."

        # Fix operator precedence bug in project name detection
        repo_info = self.p0.get("repository", {}) or self.p0.get("metadata", {})
        source = repo_info.get("source", "")
        project_name = ""
        if source and not source.startswith("repo_ingest_") and ("/" in source or "\\" in source or "github" in source):
            clean = source.rstrip("/").rstrip("\\").replace(".git", "")
            project_name = os.path.basename(clean.replace("\\", "/"))

        if not project_name or project_name.startswith("repo_ingest_") or project_name.startswith("test_"):
            header_lines = [l.strip("# ").strip() for l in summary_doc.split("\n") if l.strip().startswith("# ")]
            if header_lines and len(header_lines[0]) < 60:
                project_name = header_lines[0]
            elif not project_name:
                project_name = os.path.basename(self.root_path) or "Target Application"

        # Dynamically formulate use cases statement rather than hardcoding SentinelGuard text
        if use_cases:
            uc_names = [u["name"] for u in use_cases[:3]]
            use_case_statement = f"Application execution supporting operations: {', '.join(uc_names)}."
            use_case_classification = "CODE_SUPPORTED" if any(u.get("classification") == "CODE_SUPPORTED" for u in use_cases) else "INFERRED"
        else:
            use_case_statement = "General domain component execution and data processing."
            use_case_classification = "INFERRED"

        return {
            "name": project_name,
            "problem_being_solved": {
                "statement": problem_statement,
                "classification": "DOCUMENTED" if summary_doc else "INFERRED",
                "supporting_file_paths": doc_paths if doc_paths else [s["path"] for s in self.source_files[:2]]
            },
            "primary_users": {
                "statement": "Software developers, systems engineers, and technical auditors.",
                "classification": "INFERRED",
                "supporting_file_paths": doc_paths if doc_paths else []
            },
            "major_use_cases": {
                "statement": use_case_statement,
                "classification": use_case_classification,
                "supporting_file_paths": [s["path"] for s in self.source_files[:3]]
            },
            "application_type": {
                "type": app_type,
                "classification": "INFERRED",
                "supporting_file_paths": [s["path"] for s in self.source_files if "cli" in s["path"].lower() or "main" in s["path"].lower()] or [s["path"] for s in self.source_files[:1]]
            },
            "expected_operating_environment": {
                "environment": f"Runtimes: {', '.join(self.p0.get('languages', ['Python']))}; Standard operating system with process execution capability.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [d["path"] for d in self.dep_files] or [s["path"] for s in self.source_files[:1]]
            }
        }

    def _determine_users(self, docs: Dict[str, str], findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        users = []
        cli_paths = [s["path"] for s in self.source_files if any(k in s["path"].lower() for k in ("cli", "main", "ingest", "pipeline", "run"))]
        if not cli_paths and self.source_files:
            cli_paths = [self.source_files[0]["path"]]

        if findings["has_cli"]:
            users.append({
                "role": "CLI Operator / Developer",
                "description": "Executes command-line commands and reviews printed or exported analysis results.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": cli_paths
            })
        if findings["has_web_api"]:
            users.append({
                "role": "API Consumer / Client Application",
                "description": "Sends HTTP requests to published endpoint routes.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [r["file"] for r in findings["routes"][:2]]
            })
        if not users:
            users.append({
                "role": "Software Engineer / System Integrator",
                "description": "Imports module libraries or executes codebase components.",
                "classification": "INFERRED",
                "supporting_file_paths": [s["path"] for s in self.source_files[:1]]
            })
        return users

    def _determine_use_cases(self, docs: Dict[str, str], findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        use_cases = []
        idx = 1
        cli_paths = [s["path"] for s in self.source_files if any(k in s["path"].lower() for k in ("cli", "main", "ingest", "pipeline", "run"))]
        if not cli_paths and self.source_files:
            cli_paths = [self.source_files[0]["path"]]

        if findings["has_cli"]:
            use_cases.append({
                "id": f"UC-0{idx}",
                "name": "Command Line Execution",
                "description": "Invoke the application via terminal flags to perform project operations.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": cli_paths
            })
            idx += 1

        if findings["routes"]:
            for r in findings["routes"][:3]:
                use_cases.append({
                    "id": f"UC-0{idx}",
                    "name": f"HTTP {r['method']} {r['path']}",
                    "description": f"Process {r['method']} request against {r['path']}.",
                    "classification": "CODE_SUPPORTED",
                    "supporting_file_paths": [r["file"]]
                })
                idx += 1

        if not use_cases:
            use_cases.append({
                "id": "UC-01",
                "name": "Component Execution",
                "description": "Execute core domain routines and data processing.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [s["path"] for s in self.source_files[:1]]
            })

        return use_cases

    def _determine_components(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        components = []
        grouped: Dict[str, List[str]] = {}
        for s in self.source_files:
            parts = s["path"].replace("\\", "/").split("/")
            group_key = parts[0] if len(parts) > 1 else "root"
            grouped.setdefault(group_key, []).append(s["path"])

        for group, files in grouped.items():
            components.append({
                "name": group.capitalize() if group != "root" else "Root Application Module",
                "type": "application_module",
                "description": f"Contains application logic and source files for {group}.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": files
            })
        return components

    def _determine_architecture(self, findings: Dict[str, Any]) -> Dict[str, Any]:
        arch_type = "Modular Monolith / Script Pipeline"
        if findings["has_web_api"] and findings["has_frontend"]:
            arch_type = "Client-Server Architecture (Web Frontend + Backend API)"
        elif findings["has_web_api"]:
            arch_type = "Service-Oriented REST / Web Service"
        elif findings["has_cli"]:
            arch_type = "Command-Line Tool Architecture"

        return {
            "pattern": arch_type,
            "description": "Architectural structure organized into source modules and utility functions.",
            "classification": "INFERRED",
            "supporting_file_paths": [s["path"] for s in self.source_files[:3]]
        }

    def _determine_data_flows(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        flows = []
        cli_paths = [s["path"] for s in self.source_files if any(k in s["path"].lower() for k in ("cli", "main", "ingest", "pipeline", "run"))]
        if not cli_paths and self.source_files:
            cli_paths = [self.source_files[0]["path"]]

        if findings["has_cli"]:
            flows.append({
                "flow_name": "CLI Processing Flow",
                "trace": "Input (CLI Flags & Parameters) → Processing (Argument parsing & Domain Execution) → Output (Console stdout or File Export)",
                "classification": "INFERRED",
                "supporting_file_paths": cli_paths
            })
        if findings["routes"]:
            # Do not assume database storage unless database usage is actually verified in code
            has_db = bool(findings["db_references"] or self.p0.get("database_files"))
            if has_db:
                trace = "Input (HTTP Client Request) → Processing (Controller / Route handler) → Data Storage (Database Persistence) → Output (HTTP Response JSON)"
            else:
                trace = "Input (HTTP Client Request) → Processing (Controller / Route handler) → Output (HTTP Response JSON)"

            flows.append({
                "flow_name": "HTTP Request/Response Flow",
                "trace": trace,
                "classification": "INFERRED",
                "supporting_file_paths": [r["file"] for r in findings["routes"][:2]]
            })
        if not flows:
            flows.append({
                "flow_name": "Module Execution Flow",
                "trace": "Input (Function arguments) → Processing (Algorithm execution) → Output (Return values)",
                "classification": "INFERRED",
                "supporting_file_paths": [s["path"] for s in self.source_files[:1]]
            })
        return flows

    def _determine_trust_boundaries(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        boundaries = [
            {
                "boundary": "Operating System / User Process Boundary",
                "description": "Separates calling user/system inputs from internal runtime execution.",
                "classification": "INFERRED",
                "supporting_file_paths": [s["path"] for s in self.source_files[:1]]
            }
        ]
        if findings["routes"]:
            boundaries.append({
                "boundary": "Network Perimeter / HTTP Ingress Boundary",
                "description": "Separates untrusted network clients from backend web services.",
                "classification": "INFERRED",
                "supporting_file_paths": [r["file"] for r in findings["routes"][:1]]
            })
        if findings["db_references"] or self.p0.get("database_files"):
            supporting = [d["file"] for d in findings["db_references"][:1]] or [f["path"] for f in self.p0.get("database_files", [])[:1]]
            boundaries.append({
                "boundary": "Data Storage Boundary",
                "description": "Separates application service process from persistent database tier.",
                "classification": "INFERRED",
                "supporting_file_paths": supporting
            })
        return boundaries

    def _determine_entry_points(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        entry_points = []
        for path in findings["entry_files"]:
            entry_points.append({
                "type": "application_startup",
                "description": f"Startup file: {path}",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [path]
            })
        for r in findings["routes"]:
            ep = {
                "type": "http_endpoint",
                "description": f"{r['method']} {r['path']}",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [r["file"]]
            }
            if "line_number" in r:
                ep["line_number"] = r["line_number"]
            entry_points.append(ep)
        return entry_points

    def _determine_apis(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        apis = []
        for r in findings["routes"]:
            api = {
                "method": r["method"],
                "path": r["path"],
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [r["file"]]
            }
            if "line_number" in r:
                api["line_number"] = r["line_number"]
            apis.append(api)
        return apis

    def _determine_databases(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        dbs = []
        for db_file in self.p0.get("database_files", []):
            dbs.append({
                "name": "Database Schema / Script",
                "type": db_file.get("type", "database_schema"),
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [db_file["path"]]
            })
        for dbr in findings["db_references"]:
            item = {
                "name": f"ORM / Database Access ({dbr['keyword']})",
                "type": "data_access_layer",
                "classification": "INFERRED",
                "supporting_file_paths": [dbr["file"]]
            }
            if "line_number" in dbr:
                item["line_number"] = dbr["line_number"]
            dbs.append(item)
        return dbs

    def _determine_external_services(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        combined = list(self.p0.get("external_services", []))
        for client in findings.get("external_clients", []):
            if not any(e.get("name") == client["name"] for e in combined):
                combined.append(client)
        return combined

    def _determine_dependencies(self) -> List[Dict[str, Any]]:
        return self.p0.get("dependency_files", [])

    def _determine_auth_components(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        auths = []
        for a in findings["auth_references"]:
            item = {
                "mechanism": f"Potential authentication reference: '{a['keyword']}' (unverified enforcement)",
                "classification": "INFERRED",
                "supporting_file_paths": [a["file"]]
            }
            if "line_number" in a:
                item["line_number"] = a["line_number"]
            auths.append(item)
        return auths

    def _determine_deployment_model(self) -> Dict[str, Any]:
        dockerfiles = [i["path"] for i in self.infra_files if "docker" in i["path"].lower()]
        ci_files = [c["path"] for c in self.p0.get("ci_cd_files", [])]

        if dockerfiles:
            return {
                "model": "Containerized Deployment",
                "description": "Contains Dockerfile/compose infrastructure definitions.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": dockerfiles
            }
        elif ci_files:
            return {
                "model": "CI/CD Managed Pipeline",
                "description": "Contains CI/CD workflow automation.",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": ci_files
            }
        else:
            return {
                "model": "Standalone Process Execution",
                "description": "Runs natively in the host language runtime environment.",
                "classification": "INFERRED",
                "supporting_file_paths": [s["path"] for s in self.source_files[:1]]
            }

    def _extract_documented_behavior(self, docs: Dict[str, str]) -> List[Dict[str, Any]]:
        documented = []
        for path, content in docs.items():
            lines = [l.strip("- *# ") for l in content.split("\n") if l.strip().startswith(("-", "*", "##"))]
            for line in lines[:5]:
                if len(line) > 10:
                    documented.append({
                        "behavior": line,
                        "classification": "DOCUMENTED",
                        "supporting_file_paths": [path]
                    })
        return documented

    def _extract_code_supported_behavior(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        code_supported = []
        for s in self.source_files[:5]:
            code_supported.append({
                "behavior": f"Execution of logic in {s['path']} ({s['language']}).",
                "classification": "CODE_SUPPORTED",
                "supporting_file_paths": [s["path"]]
            })
        return code_supported

    def _extract_inferences(
        self,
        summary: Dict[str, Any],
        users: List[Dict[str, Any]],
        arch: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        inferences = [
            {
                "inference": f"Application architecture conforms to {arch['pattern']}.",
                "classification": "INFERRED",
                "supporting_file_paths": arch.get("supporting_file_paths", [])
            }
        ]
        for u in users:
            if u.get("classification") == "INFERRED":
                inferences.append({
                    "inference": f"User persona '{u['role']}' deduced from application interface exposure.",
                    "classification": "INFERRED",
                    "supporting_file_paths": u.get("supporting_file_paths", [])
                })
        if summary.get("problem_being_solved", {}).get("classification") == "INFERRED":
            inferences.append({
                "inference": "Project problem statement inferred from general repository structure in absence of README specifications.",
                "classification": "INFERRED",
                "supporting_file_paths": summary.get("problem_being_solved", {}).get("supporting_file_paths", [])
            })
        return inferences

    def _identify_unknowns(
        self,
        databases: List[Any],
        deployment: Dict[str, Any],
        auth: List[Any]
    ) -> List[Dict[str, Any]]:
        unknowns = []
        if not databases:
            unknowns.append({
                "item": "Database Persistence Schema",
                "classification": "UNKNOWN",
                "description": "No explicit SQL schema or ORM models detected in repository source files."
            })
        if not auth:
            unknowns.append({
                "item": "Authentication Mechanism",
                "classification": "UNKNOWN",
                "description": "No authentication middleware or token verification routines detected in code."
            })
        elif all(a.get("classification") == "INFERRED" for a in auth):
            unknowns.append({
                "item": "Authentication Enforcement & Authorization Policies",
                "classification": "UNKNOWN",
                "description": "Authentication keywords were referenced, but no active enforcement middleware or access control policies could be confirmed."
            })
        if not self.p0.get("external_services"):
            unknowns.append({
                "item": "External Third-Party Integrations",
                "classification": "UNKNOWN",
                "description": "No third-party SaaS, cloud, or external API client integrations detected in repository manifests."
            })
        if deployment.get("model") == "Standalone Process Execution":
            unknowns.append({
                "item": "Production Deployment Infrastructure",
                "classification": "UNKNOWN",
                "description": "No container definitions (Dockerfile), Kubernetes manifests, or infrastructure-as-code files found in repository."
            })
        if not self.test_files:
            unknowns.append({
                "item": "Automated Test Coverage",
                "classification": "UNKNOWN",
                "description": "No unit, integration, or end-to-end automated test suites detected in repository."
            })
        return unknowns
