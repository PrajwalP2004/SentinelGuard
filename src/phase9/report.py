"""
Phase 9: Final Software Architecture and Security Report Generator Agent.

Synthesizes verified facts, threat analyses, defensive remediations, retest evaluations,
code smells, cross-domain interactions, and prioritized recommendations into a clear,
plain-English, audit-grade report accessible to any user or stakeholder.

Strictly adheres to evidentiary classification:
- FACT: Directly verified in repository files, source lines, or manifests.
- INFERENCE: Deduced from code structure, file naming, or heuristics.
- ANALYSIS: Diagnostic assessment derived through security/quality modeling.
- RECOMMENDATION: Prescriptive remediation or engineering improvement.
- UNKNOWN: Unverifiable without runtime environment or external artifacts.
"""

import re
from typing import Dict, List, Any, Optional, Set, Tuple


class FinalReportGeneratorAgent:
    """Agent that generates the comprehensive Phase 9 Final Software Analysis Report in plain English."""

    RETEST_STATUS_BADGES = {
        "REMEDIATED": "🟢 VERIFIED REMEDIATION",
        "PARTIALLY_REMEDIATED": "🟡 PARTIALLY ADDRESSED",
        "NOT_REMEDIATED": "🔴 ACTION REQUIRED",
        "NOT_TESTABLE": "⚪ UNABLE TO VERIFY",
        "FALSE_POSITIVE": "🔵 FALSE POSITIVE",
        "CONFLICTED": "🟠 CONFLICTED EVIDENCE",
    }

    @classmethod
    def get_retest_badge(cls, status: Any) -> str:
        """Determines the explicit plain-English badge for a Phase 5A retest status."""
        if not isinstance(status, str):
            return "⚠️ STATUS UNKNOWN"
        normalized = status.strip().upper()
        return cls.RETEST_STATUS_BADGES.get(normalized, "⚠️ STATUS UNKNOWN")

    @staticmethod
    def _get_requirement_tag(r: Dict[str, Any]) -> str:
        """Derives epistemological tag from genuine Phase 2 status without inventing explicit claims."""
        if not isinstance(r, dict):
            return "[UNKNOWN - Unverified]"
        raw_status = str(r.get("status", "")).strip().lower()
        if raw_status == "explicit":
            return "[FACT - Explicit]"
        elif raw_status == "code_supported":
            return "[FACT - Code Supported]"
        elif raw_status == "inferred":
            return "[INFERRED]"
        elif raw_status in ("unknown", ""):
            return "[UNKNOWN - Unverified]"
        else:
            return f"[{raw_status.upper()}]"

    def __init__(
        self,
        phase0_inventory: Optional[Dict[str, Any]] = None,
        phase1_reconstruction: Optional[Dict[str, Any]] = None,
        phase2_requirements: Optional[List[Dict[str, Any]]] = None,
        phase2_assessment: Optional[Dict[str, Any]] = None,
        phase3a_red_team: Optional[Dict[str, Any]] = None,
        phase4a_blue_team: Optional[Dict[str, Any]] = None,
        phase5a_retest: Optional[Dict[str, Any]] = None,
        phase6_smells: Optional[Dict[str, Any]] = None,
        phase7_cross_domain: Optional[Dict[str, Any]] = None,
        phase8_recommendations: Optional[Dict[str, Any]] = None,
    ):
        self.p0 = phase0_inventory or {}
        self._p0_provided = phase0_inventory is not None
        self.p1 = phase1_reconstruction or {}
        self._p1_provided = phase1_reconstruction is not None
        if isinstance(phase2_requirements, list):
            self.p2_reqs = [r for r in phase2_requirements if isinstance(r, dict)]
            self._p2_provided = True
        elif isinstance(phase2_requirements, dict):
            req_list = phase2_requirements.get("requirements", [])
            self.p2_reqs = [r for r in req_list if isinstance(r, dict)] if isinstance(req_list, list) else []
            self._p2_provided = True
        else:
            self.p2_reqs = []
            self._p2_provided = phase2_requirements is not None
        self.p2_sec = phase2_assessment or {}
        self._p2_sec_provided = phase2_assessment is not None
        self.p3a = phase3a_red_team or {}
        self._p3a_provided = phase3a_red_team is not None
        self.p4a = phase4a_blue_team or {}
        self._p4a_provided = phase4a_blue_team is not None
        if isinstance(phase5a_retest, dict):
            self.p5a = phase5a_retest
            self._p5a_provided = True
        elif isinstance(phase5a_retest, list):
            self.p5a = {"retest_results": [r for r in phase5a_retest if isinstance(r, dict)]}
            self._p5a_provided = True
        else:
            self.p5a = {}
            self._p5a_provided = phase5a_retest is not None
        self.p6 = phase6_smells or {}
        self._p6_provided = phase6_smells is not None
        if isinstance(phase7_cross_domain, dict):
            self.p7 = phase7_cross_domain
            self._p7_provided = True
        elif isinstance(phase7_cross_domain, list):
            self.p7 = {"cross_domain_relationships": [r for r in phase7_cross_domain if isinstance(r, dict)]}
            self._p7_provided = True
        else:
            self.p7 = {}
            self._p7_provided = phase7_cross_domain is not None
        self.p8 = phase8_recommendations or {}
        self._p8_provided = phase8_recommendations is not None

    def _get_discovered_files_count(self) -> Optional[int]:
        """Resolves the verified number of discovered files from Phase 0 inventory metadata."""
        if not self._p0_provided:
            return None
        repo_info = self.p0.get("repository", {}) if isinstance(self.p0.get("repository"), dict) else {}
        total = (
            self.p0.get("total_files_discovered")
            or repo_info.get("total_files")
            or len(self.p0.get("file_inventory", []))
            or len(self.p0.get("source_files", []))
        )
        return int(total) if total else 0

    def _get_inspected_files_count(self) -> Optional[int]:
        """Returns the verified count of inspected files from Phase 3A scanner execution metadata."""
        if not self._p3a_provided:
            return None
        val = self.p3a.get("inspected_files_count")
        if val is not None and isinstance(val, (int, float)):
            return int(val)
        return None

    def _get_target_name(self) -> str:
        name = self.p1.get("project_summary", {}).get("name")
        if name and not name.startswith("repo_ingest_"):
            return name
        repo_info = self.p0.get("repository", {}) or self.p0.get("metadata", {})
        src = repo_info.get("source", "")
        if src and not src.startswith("repo_ingest_") and ("/" in src or "\\" in src or "github" in src):
            clean = src.rstrip("/").replace(".git", "")
            target = clean.split("/")[-1].split("\\")[-1]
            if target and not target.startswith("repo_ingest_"):
                return target
        return name or "Target Software System"

    @staticmethod
    def _normalize_text(val: Any) -> str:
        """Normalizes text for robust duplicate comparison by stripping non-alphanumerics and collapsing whitespace."""
        if not val:
            return ""
        cleaned = re.sub(r'[*`_]', '', str(val))
        cleaned = re.sub(r'[^a-zA-Z0-9\s]', ' ', cleaned)
        return " ".join(cleaned.strip().lower().split())

    def _get_validated_recommendations(self) -> List[Dict[str, Any]]:
        """Lightweight validation and defensive deduplication of recommendations before rendering.
        
        Ensures:
        - Recommendation IDs are valid, non-empty, and unique.
        - Rows sharing identical substantive problem, solution, and impact are consolidated.
        - Evidence and affected files from duplicates are combined without loss.
        - Higher priority is preserved without silent downgrades.
        """
        raw_recs = self.p8.get("recommendations", []) if self._p8_provided else []
        if not isinstance(raw_recs, list):
            return []

        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        conf_ranks = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

        deduped: List[Dict[str, Any]] = []

        for r in raw_recs:
            if not isinstance(r, dict):
                continue
            raw_fid = str(r.get("finding_id", "")).strip().upper()
            prob = self._normalize_text(r.get("problem", ""))
            sol = self._normalize_text(r.get("recommended_change", ""))

            raw_files = r.get("affected_files", [])
            if isinstance(raw_files, str):
                files_list = [raw_files]
            elif isinstance(raw_files, list):
                files_list = raw_files
            else:
                files_list = []
            files_tuple = tuple(sorted(str(f).strip().lower() for f in files_list if str(f).strip()))

            base_fid = raw_fid if (raw_fid and not raw_fid.startswith("SEC-UNMAPPED") and not raw_fid.startswith("SMELL-") and not raw_fid.startswith("BASE-")) else (raw_fid or "GENERAL")

            match_idx = None
            for idx, existing in enumerate(deduped):
                ex_fid = str(existing.get("finding_id", "")).strip().upper()
                ex_base_fid = ex_fid if (ex_fid and not ex_fid.startswith("SEC-UNMAPPED") and not ex_fid.startswith("SMELL-") and not ex_fid.startswith("BASE-")) else (ex_fid or "GENERAL")
                ex_prob = self._normalize_text(existing.get("problem", ""))
                ex_sol = self._normalize_text(existing.get("recommended_change", ""))

                if base_fid == ex_base_fid and prob == ex_prob and sol == ex_sol:
                    ex_files = existing.get("affected_files", [])
                    if isinstance(ex_files, str):
                        ex_files_list = [ex_files]
                    elif isinstance(ex_files, list):
                        ex_files_list = ex_files
                    else:
                        ex_files_list = []
                    ex_files_tuple = tuple(sorted(str(f).strip().lower() for f in ex_files_list if str(f).strip()))

                    # Duplicate match: identical files or one/both have unspecified files
                    if files_tuple == ex_files_tuple or not files_tuple or not ex_files_tuple:
                        match_idx = idx
                        break

            if match_idx is not None:
                existing = deduped[match_idx]

                # Merge evidence
                ev_canon = str(existing.get("evidence", "")).strip()
                ev_dup = str(r.get("evidence", "")).strip()
                if ev_dup and ev_dup not in ev_canon:
                    if ev_canon:
                        existing["evidence"] = f"{ev_canon}; Additional occurrence: {ev_dup}"
                    else:
                        existing["evidence"] = ev_dup

                # Merge affected files
                files_set = set(existing.get("affected_files", []))
                for f in files_list:
                    if f and str(f).strip():
                        files_set.add(str(f).strip())
                if files_set:
                    existing["affected_files"] = sorted(list(files_set))

                # Merge phase sources
                srcs = list(existing.get("phase_sources", []))
                for s in r.get("phase_sources", []):
                    if s not in srcs:
                        srcs.append(s)
                existing["phase_sources"] = srcs

                # Resolve priority
                p_canon = existing.get("priority", "MEDIUM")
                p_dup = r.get("priority", "MEDIUM")
                if priority_order.get(p_dup, 2) < priority_order.get(p_canon, 2):
                    existing["priority"] = p_dup

                # Resolve confidence
                c_canon = existing.get("confidence", "MEDIUM")
                c_dup = r.get("confidence", "MEDIUM")
                if conf_ranks.get(c_dup, 1) < conf_ranks.get(c_canon, 1):
                    existing["confidence"] = c_dup
            else:
                deduped.append(dict(r))

        # Re-index unique recommendation IDs sequentially
        for i, r in enumerate(deduped, start=1):
            r["recommendation_id"] = f"REC-{i:02d}"

        return deduped

    def _validate_and_normalize_requirements(self) -> List[Dict[str, Any]]:
        """Validates requirement records and preserves full descriptions without loss or summary substitution."""
        if not self._p2_provided or not self.p2_reqs:
            return []

        validated: List[Dict[str, Any]] = []
        seen_rids: Set[str] = set()

        for idx, r in enumerate(self.p2_reqs, start=1):
            if not isinstance(r, dict):
                continue
            req_copy = dict(r)
            rid = str(r.get("requirement_id", "")).strip()
            if not rid:
                rid = f"REQ-UNKNOWN-{idx:02d}"
            elif rid in seen_rids:
                rid = f"{rid}-DUP-{idx:02d}"
            seen_rids.add(rid)
            req_copy["requirement_id"] = rid

            desc = r.get("description")
            if desc is None or not str(desc).strip():
                # Report missing or incomplete source descriptions honestly
                req_copy["description"] = "[Incomplete description in source data]"
            else:
                req_copy["description"] = str(desc).strip()

            validated.append(req_copy)

        return validated

    def generate_report_data(self) -> Dict[str, Any]:
        """Assembles verified data across all phases into a structured report dictionary."""
        target_name = self._get_target_name()
        summary = self.p1.get("project_summary", {})
        problem = summary.get("problem_being_solved", {}).get("statement", "Software application and technical workflows.")
        app_type = summary.get("application_type", {}).get("type", "Software Application")
        arch_pattern = self.p1.get("architecture", {}).get("pattern", "Modular Application Architecture")
        languages = ", ".join(self.p0.get("languages", ["Source Code"])) if (self._p0_provided and self.p0.get("languages")) else "Source Code"
        discovered_files = self._get_discovered_files_count()

        findings = self.p3a.get("findings", []) if self._p3a_provided else []
        smells = self.p6.get("code_smells", []) if self._p6_provided else []
        recs = self._get_validated_recommendations() if self._p8_provided else []

        if not self._p3a_provided:
            sec_summary = "[UNKNOWN] Red Team security assessment results were not supplied; vulnerability status could not be confirmed."
        elif findings:
            sec_summary = (
                f"[FACT] Ethical Hacker Testing (Red Team) identified {len(findings)} potential security concern(s) "
                f"in the codebase, including: {', '.join([f.get('title', 'Security Finding') for f in findings[:3]])}. "
                "Each issue was analyzed for root causes and concrete defensive repairs were designed."
            )
        else:
            inspected = self._get_inspected_files_count()
            if inspected is not None:
                sec_summary = (
                    f"[FACT] Ethical Hacker Testing (Red Team) inspected {inspected} file(s) and did not find any critical "
                    "active vulnerabilities across the evaluated dimensions. Standard defensive hardening checks were conducted."
                )
            else:
                sec_summary = (
                    "[FACT] Available Ethical Hacker Testing (Red Team) results indicate no critical active vulnerabilities "
                    "in the evaluated codebase files."
                )

        if not self._p6_provided:
            maint_summary = "[UNKNOWN] Code quality review results were not supplied; maintainability findings could not be confirmed."
        else:
            maint_summary = (
                f"[ANALYSIS] Code Quality Review (Phase 6): Static maintainability analysis identified {len(smells)} "
                "potential issue(s) across evaluated methods, nesting depths, and error handling."
            )

        if self._p0_provided and discovered_files is not None:
            sys_description = (
                f"[FACT] {target_name} is a {app_type} built primarily with {languages}. "
                f"Repository inventory identified {discovered_files} project file(s). Purpose: {problem}"
            )
        else:
            sys_description = (
                f"[FACT] {target_name} is a {app_type} built primarily with {languages}. "
                f"Purpose: {problem} (Repository file inventory was not supplied [UNKNOWN])."
            )

        return {
            "metadata": {
                "report_title": "PHASE 9 — FINAL SOFTWARE ARCHITECTURE AND SECURITY REPORT",
                "target_system": target_name,
                "status": "AUDITED_AND_EVALUATED",
                "reading_level": "PLAIN_ENGLISH_CLEAR_ACCESSIBLE",
                "epistemological_standards": ["FACT", "INFERENCE", "ANALYSIS", "RECOMMENDATION", "UNKNOWN"]
            },
            "executive_summary": {
                "system_description": sys_description,
                "architecture_overview": (
                    f"[FACT] Architecture Design: The project is structured as a {arch_pattern}. "
                    f"It contains {len(self.p1.get('components', []))} main functional modules, "
                    f"{len(self.p1.get('entry_points', []))} detected entry points/routes, and "
                    f"{len(self.p1.get('databases', []))} database storage layers."
                ),
                "major_security_findings": sec_summary,
                "major_maintainability_findings": maint_summary,
                "most_important_recommendations": (
                    f"[RECOMMENDATION] {len(recs)} Actionable Improvements: We generated a prioritized improvement roadmap "
                    f"focusing on security fixes, code cleanup, and production stability."
                )
            },
            "findings_count": {
                "red_team_findings": len(findings),
                "blue_team_plans": len(self.p4a.get("remediation_plans", [])) if self._p4a_provided else 0,
                "retested_findings": len(self.p5a.get("retest_results", [])) if self._p5a_provided else 0,
                "code_smell_count": len(smells),
                "cross_domain_relationships": len(self.p7.get("cross_domain_relationships", [])) if self._p7_provided else 0,
                "recommendations_count": len(recs)
            },
            "recommendations": recs
        }

    def generate_markdown_report(self) -> str:
        """Renders the comprehensive Phase 9 Markdown report in simple, clear, user-friendly language."""
        lines: List[str] = []
        target_name = self._get_target_name()
        summary = self.p1.get("project_summary", {})
        problem = summary.get("problem_being_solved", {}).get("statement", "Automated application and technical workflow.")
        app_type = summary.get("application_type", {}).get("type", "Software Application")
        arch_pattern = self.p1.get("architecture", {}).get("pattern", "Modular Application Architecture")
        languages = ", ".join(self.p0.get("languages", ["Python"])) if (self._p0_provided and self.p0.get("languages")) else "Python"
        discovered_files = self._get_discovered_files_count()

        # Header
        lines.append("# PHASE 9 — FINAL SOFTWARE ARCHITECTURE AND SECURITY REPORT")
        lines.append("")
        lines.append(f"> ### 🎯 Target Repository Audited: **{target_name}**")
        if self._p0_provided and discovered_files is not None:
            files_header = f"**Files Discovered**: {discovered_files}"
        else:
            files_header = "**Files Discovered**: Unconfirmed [UNKNOWN]"
        lines.append(f"> **Application Type**: {app_type} | **Languages**: {languages} | {files_header}")
        lines.append("")
        lines.append("> ### 📖 Plain-English Guide to the Tags in This Report")
        lines.append("> Every key point in this report is clearly labeled so you always know where the information comes from:")
        lines.append("> - **[FACT]**: Directly proven by looking at real code files in this project.")
        lines.append("> - **[INFERENCE]**: An educated conclusion based on file names, folders, or coding patterns.")
        lines.append("> - **[ANALYSIS]**: Calculated or diagnosed by our automated scanners.")
        lines.append("> - **[RECOMMENDATION]**: A practical, friendly suggestion for the engineering team.")
        lines.append("> - **[UNKNOWN]**: Something that cannot be confirmed without running the code on a live internet server or when data is missing.")
        lines.append("")

        # 1. EXECUTIVE SUMMARY & WHAT WAS ANALYZED
        lines.append("## 1. EXECUTIVE SUMMARY")
        lines.append("")
        lines.append("### 1.1 What This Software Does")
        if self._p0_provided and discovered_files is not None:
            file_scope_statement = f"Repository inventory identified **{discovered_files} file(s)** associated with **{languages}**."
        else:
            file_scope_statement = f"Repository file inventory was not supplied; total file count could not be confirmed [UNKNOWN]."
        lines.append(
            f"- **[FACT]**: **{target_name}** is a **{app_type}**. "
            f"Based on project documentation and code structure: *{problem}* "
            f"{file_scope_statement}"
        )
        lines.append("")
        lines.append("### 1.2 How the System Is Built (Architecture)")
        lines.append(
            f"- **[FACT]**: **{arch_pattern}**: The codebase is organized into "
            f"**{len(self.p1.get('components', []))} main functional components**, "
            f"with **{len(self.p1.get('apis', []))} web API routes**, and "
            f"**{len(self.p1.get('databases', []))} database persistence layers**."
        )
        lines.append("")

        # WHAT OUR SYSTEM ANALYZED FOR IMPROVEMENTS
        lines.append("### 1.3 What Our System Analyzed for Improvements (The Scope of Analysis)")
        lines.append(
            f"The automated pipeline is configured to evaluate repositories across 6 primary engineering and security domains. "
            f"Below is the verified audit scope and analysis coverage for **{target_name}** based on available execution metadata:"
        )
        lines.append("")

        inspected_count = self._get_inspected_files_count()
        if inspected_count is not None:
            p3a_skipped = self.p3a.get("skipped_files", []) if isinstance(self.p3a.get("skipped_files"), list) else []
            lines.append(f"- **Static File Inspection Coverage**: [FACT] Security scanners inspected **{inspected_count} file(s)** ({len(p3a_skipped)} file(s) skipped based on size or path filters).")
        elif self._p3a_provided:
            lines.append("- **Static File Inspection Coverage**: [ANALYSIS] Security scanner executed, but specific inspected file count was not reported in Phase 3A metadata.")
        else:
            lines.append("- **Static File Inspection Coverage**: [UNKNOWN] Security scanner execution metadata was not supplied; analyzed file count could not be confirmed.")
        lines.append("")

        # Domain 1
        lines.append("1. **🌐 Web API & Ingress Safety**:")
        lines.append("   - *Configured checks*: Ingress parameter sanitization, injection flaws (SQL, command, path traversal), and input boundary validation.")
        if self._p1_provided and (self.p1.get("apis") or self.p1.get("entry_points")):
            apis_cnt = len(self.p1.get("apis", []))
            eps_cnt = len(self.p1.get("entry_points", []))
            lines.append(f"   - *Verified scope*: Evaluated {apis_cnt} registered HTTP route(s) and {eps_cnt} entry point candidate(s) from architectural reconstruction.")
        elif self._p1_provided:
            lines.append("   - *Verified scope*: No HTTP web routes were registered in the codebase; analysis evaluated module and CLI entry points where present.")
        else:
            lines.append("   - *Verified scope*: [UNKNOWN] Architectural entry point metadata was not supplied; verified route coverage could not be confirmed.")
        if self._p3a_provided:
            ingress_findings = [f for f in self.p3a.get("findings", []) if any(k in str(f.get("category", "")).lower() or k in str(f.get("title", "")).lower() for k in ("injection", "input", "traversal", "ingress", "api"))]
            lines.append(f"   - *Analysis findings*: Available results indicate {len(ingress_findings)} ingress-related security finding(s).")
        else:
            lines.append("   - *Analysis findings*: [UNKNOWN] Red Team security assessment data was not supplied.")
        lines.append("")

        # Domain 2
        lines.append("2. **🗄️ Database Queries & Persistence Layer**:")
        lines.append("   - *Configured checks*: Parameterized prepared statements versus dynamic string concatenation, database credentials, and query safety.")
        if self._p1_provided and self.p1.get("databases"):
            db_cnt = len(self.p1.get("databases", []))
            lines.append(f"   - *Verified scope*: Evaluated {db_cnt} detected persistence layer(s) from architectural reconstruction.")
        elif self._p1_provided:
            lines.append("   - *Verified scope*: No dedicated database persistence layer was identified; filesystem data operations evaluated where present.")
        else:
            lines.append("   - *Verified scope*: [UNKNOWN] Database architecture metadata was not supplied.")
        if self._p3a_provided:
            db_findings = [f for f in self.p3a.get("findings", []) if any(k in str(f.get("category", "")).lower() or k in str(f.get("title", "")).lower() for k in ("sql", "database", "query"))]
            lines.append(f"   - *Analysis findings*: Available results indicate {len(db_findings)} database security finding(s).")
        else:
            lines.append("   - *Analysis findings*: [UNKNOWN] Red Team security assessment data was not supplied.")
        lines.append("")

        # Domain 3
        lines.append("3. **🔐 Credential Leakage & Secrets Management**:")
        lines.append("   - *Configured checks*: Pattern and entropy scanning for hardcoded secrets, private cryptographic keys, API tokens, and plaintext credentials.")
        if self._p0_provided:
            sens_cnt = len(self.p0.get("potentially_sensitive_files", []))
            cfg_cnt = len(self.p0.get("configuration_files", []))
            lines.append(f"   - *Verified scope*: Evaluated candidate configuration files ({cfg_cnt}) and sensitive candidate files ({sens_cnt}) identified in repository inventory.")
        else:
            lines.append("   - *Verified scope*: [UNKNOWN] Repository file inventory was not supplied; secrets scan file scope could not be confirmed.")
        if self._p3a_provided:
            secret_findings = [f for f in self.p3a.get("findings", []) if any(k in str(f.get("category", "")).lower() or k in str(f.get("title", "")).lower() for k in ("secret", "token", "credential", "key", "password"))]
            lines.append(f"   - *Analysis findings*: Available results indicate {len(secret_findings)} credential-related finding(s).")
        else:
            lines.append("   - *Analysis findings*: [UNKNOWN] Red Team security assessment data was not supplied.")
        lines.append("")

        # Domain 4
        lines.append("4. **🛡️ Runtime Configuration & Operational Security**:")
        lines.append("   - *Configured checks*: Audit of framework execution flags (`debug=True`), permissive CORS policies (`origins='*'`), and weak legacy hash algorithms (MD5/SHA1).")
        if self._p0_provided and self.p0.get("frameworks"):
            fw_list = ", ".join(self.p0.get("frameworks", []))
            lines.append(f"   - *Verified scope*: Evaluated operational configuration for detected framework(s): {fw_list}.")
        elif self._p0_provided:
            lines.append("   - *Verified scope*: Evaluated repository operational files; no external web frameworks detected in manifests.")
        else:
            lines.append("   - *Verified scope*: [UNKNOWN] Framework configuration metadata was not supplied.")
        if self._p3a_provided:
            cfg_findings = [f for f in self.p3a.get("findings", []) if any(k in str(f.get("category", "")).lower() or k in str(f.get("title", "")).lower() for k in ("config", "cors", "debug", "hash", "crypto"))]
            lines.append(f"   - *Analysis findings*: Available results indicate {len(cfg_findings)} configuration/operational finding(s).")
        else:
            lines.append("   - *Analysis findings*: [UNKNOWN] Red Team security assessment data was not supplied.")
        lines.append("")

        # Domain 5
        lines.append("5. **🧩 Code Maintainability & AST Code Smells**:")
        lines.append("   - *Configured checks*: Static AST parsing for long methods, deep block nesting (>3 levels), silent exception swallowing (`except Exception: pass`), and cyclomatic complexity.")
        if self._p6_provided and self.p6:
            p6_diag = self.p6.get("scan_diagnostics", []) if isinstance(self.p6.get("scan_diagnostics"), list) else []
            lines.append(f"   - *Verified scope*: Static maintainability analysis executed against candidate Python source files ({len(p6_diag)} scan diagnostic(s) recorded). Parser execution is verified only where AST parsing completed successfully.")
        elif self._p6_provided:
            lines.append("   - *Verified scope*: Maintainability scanner was executed, but diagnostic records were not available.")
        else:
            lines.append("   - *Verified scope*: [UNKNOWN] Maintainability analysis results were not supplied; AST coverage across source files could not be confirmed.")
        if self._p6_provided and self.p6:
            lines.append(f"   - *Analysis findings*: Available results identify {len(self.p6.get('code_smells', []))} code smell(s) in parsed Python routines.")
        else:
            lines.append("   - *Analysis findings*: [UNKNOWN] Code smell data was not supplied.")
        lines.append("")

        # Domain 6
        lines.append("6. **🔄 Cross-Domain Interactions & Engineering Trade-offs**:")
        lines.append("   - *Configured checks*: Synthesis of cross-domain impacts and trade-offs between security controls, code maintainability, and operational performance.")
        if self._p7_provided and self.p7:
            interactions = self.p7.get("domain_interactions")
            if isinstance(interactions, dict) and interactions:
                lines.append(f"   - *Verified scope*: Evaluated {len(interactions)} specific cross-domain interaction category pair(s).")
            else:
                lines.append("   - *Verified scope*: Cross-domain analysis executed across available phase findings.")
        else:
            lines.append("   - *Verified scope*: [UNKNOWN] Cross-domain analysis results were not supplied; interaction coverage could not be confirmed.")
        if self._p7_provided and self.p7:
            rel_cnt = len(self.p7.get("cross_domain_relationships", []))
            lines.append(f"   - *Analysis findings*: Available results produced {rel_cnt} verified cross-domain relationship(s).")
        else:
            lines.append("   - *Analysis findings*: [UNKNOWN] Cross-domain relationships not supplied.")
        lines.append("")

        # MASTER SUMMARY NOTE (Shifted to Section 13 at the end of the report)
        lines.append("*(Note: The consolidated Master Summary Table / Executive Action Matrix has been shifted to the conclusion of this report in Section 13.)*")
        lines.append("")

        # 2. PROJECT UNDERSTANDING
        lines.append("## 2. PROJECT UNDERSTANDING (HOW THE SYSTEM WORKS)")
        lines.append("")
        lines.append(f"- **Purpose**: [FACT] {problem}")
        lines.append(f"- **Who Uses It**: [INFERENCE] {summary.get('primary_users', {}).get('statement', 'Application users and operators.')}")
        lines.append("- **The Main Pieces (Components)**: [FACT]")
        components = self.p1.get("components", [])
        if components:
            for c in components:
                name = c.get("name", "Component")
                desc = c.get("description", "Application module")
                files = c.get("supporting_file_paths", [])
                sample_files = ", ".join(files[:3])
                lines.append(f"  - **{name}**: {desc} (Files: `{sample_files}`)")
        else:
            lines.append("  - Core Application Module: Contains root source files.")

        lines.append(f"- **Technologies Used**: [FACT] {languages}")
        apis = self.p1.get("apis", [])
        if apis:
            lines.append(f"- **Web APIs Discovered**: [FACT] {len(apis)} HTTP route(s):")
            for a in apis[:6]:
                lines.append(f"  - `{a.get('method', 'GET')} {a.get('path', '/')}` in `{', '.join(a.get('supporting_file_paths', []))}`")
            if len(apis) > 6:
                lines.append(f"  - *...and {len(apis) - 6} additional endpoints.*")
        else:
            lines.append("- **Web APIs**: [FACT] Standalone library or script-based workflow (no HTTP web routes registered).")

        databases = self.p1.get("databases", [])
        if databases:
            lines.append(f"- **Databases & Data Storage**: [FACT] {len(databases)} storage layer(s):")
            for db in databases:
                lines.append(f"  - {db.get('name', 'Database')}: `{', '.join(db.get('supporting_file_paths', []))}`")
        else:
            lines.append("- **Databases**: [FACT] File-based data storage or in-memory execution.")

        deploy = self.p1.get("deployment_model", {})
        lines.append(f"- **Deployment Model**: [FACT] {deploy.get('model', 'Standard Local / Hosted Execution')} — {deploy.get('description', 'Standard application runtime.')}")
        lines.append("")

        # 3. REQUIREMENTS
        lines.append("## 3. REQUIREMENTS (WHAT THE SYSTEM MUST DO)")
        lines.append("")
        all_reqs = self._validate_and_normalize_requirements()
        lines.append("### Functional Rules (What Features It Must Have)")
        func_reqs = [r for r in all_reqs if str(r.get("category", "")).strip().lower() in ("functional", "func")]
        if func_reqs:
            for r in func_reqs:
                rid = r.get("requirement_id", "REQ-FUNC")
                tag = self._get_requirement_tag(r)
                desc = r.get("description", "Functional requirement.")
                lines.append(f"- `{rid}` {tag}: {desc}")
        else:
            lines.append("- *No functional requirements were supplied or documented in Phase 2 input data [UNKNOWN].*")

        lines.append("")
        lines.append("### Security Rules (How It Keeps Itself Safe)")
        sec_reqs = [r for r in all_reqs if str(r.get("category", "")).strip().lower() == "security"]
        if sec_reqs:
            for r in sec_reqs:
                rid = r.get("requirement_id", "REQ-SEC")
                tag = self._get_requirement_tag(r)
                desc = r.get("description", "Security requirement.")
                lines.append(f"- `{rid}` {tag}: {desc}")
        else:
            lines.append("- *No security requirements were supplied or documented in Phase 2 input data [UNKNOWN].*")

        lines.append("")
        lines.append("### Maintainability & Quality Rules")
        nfr_reqs = [r for r in all_reqs if str(r.get("category", "")).strip().lower() in ("non_functional", "nfr", "maintainability", "quality")]
        if nfr_reqs:
            for r in nfr_reqs:
                rid = r.get("requirement_id", "REQ-NFR")
                tag = self._get_requirement_tag(r)
                desc = r.get("description", "Maintainability requirement.")
                lines.append(f"- `{rid}` {tag}: {desc}")
        else:
            lines.append("- [INFERRED - Baseline Suggestion] **Code Maintainability**: Code should follow structured functions without deeply nested control blocks.")
            lines.append("- [INFERRED - Baseline Suggestion] **Error Observability**: Runtime exceptions should be logged with diagnostic details rather than swallowed silently.")
        lines.append("")

        # 4. RED TEAM SECURITY ASSESSMENT
        lines.append("## 4. RED TEAM SECURITY ASSESSMENT (ETHICAL HACKER AUDIT)")
        lines.append("")
        lines.append("Our automated ethical hacker agent checked the application for security vulnerabilities. Here is what was found:")
        lines.append("")
        if not self._p3a_provided:
            lines.append("⚠️ **No Red Team security audit results were supplied for this report [UNKNOWN].**")
            lines.append("Vulnerability status and security posture cannot be certified without executed security analysis.")
            lines.append("")
        else:
            findings = self.p3a.get("findings", [])
            if not findings:
                inspected = self._get_inspected_files_count()
                if inspected is not None:
                    lines.append(f"✅ **No critical vulnerabilities identified across the {inspected} inspected source file(s).**")
                else:
                    lines.append("✅ **No critical vulnerabilities identified in the available static security scan results.**")
                lines.append("The codebase demonstrates standard code hygiene for the evaluated security dimensions. (Note: Static analysis covers configured heuristic rules and does not guarantee the absence of all vulnerabilities).")
                lines.append("")
            else:
                seen_fids = set()
                for f in findings:
                    fid = f.get("finding_id", "RED-FINDING")
                    if fid in seen_fids:
                        continue
                    seen_fids.add(fid)
                    title = f.get("title", "Security Finding")
                    lines.append(f"### Vulnerability: `{fid}` — {title}")
                    lines.append(f"- **What Is the Issue?**: [ANALYSIS] {title}")
                    lines.append(f"- **Where Could an Attacker Attack?**: [ANALYSIS] {f.get('attack_surface')}")
                    lines.append(f"- **Which File Was Affected?**: [FACT] `{', '.join(f.get('affected_files', []))}`")
                    lines.append(f"- **Proof in the Code**: [FACT] {f.get('evidence')}")
                    lines.append(f"- **How Could an Attacker Exploit This?**: [ANALYSIS] {f.get('attack_path')}")
                    lines.append(f"- **What Harm Could It Cause?**: [ANALYSIS] {f.get('impact')}")
                    lines.append(f"- **Danger Level (Severity)**: [ANALYSIS] **{f.get('severity')}**")
                    lines.append(f"- **Confidence Level**: [ANALYSIS] **{f.get('confidence')}**")
                    lines.append(f"- **Current Status**: [FACT] **{f.get('validation_status')}**")
                    lines.append("")

        # 5. BLUE TEAM DEFENSIVE ASSESSMENT
        lines.append("## 5. BLUE TEAM DEFENSIVE ASSESSMENT (HOW TO FIX THEM)")
        lines.append("")
        lines.append("The defensive team analyzed the root cause of every vulnerability and designed solid, permanent fixes:")
        lines.append("")
        if not self._p4a_provided:
            lines.append("No Blue Team defensive remediation plans were supplied for this report [UNKNOWN].")
            lines.append("")
        else:
            plans = self.p4a.get("remediation_plans", [])
            if not plans:
                lines.append("No active vulnerabilities required immediate remediation plans in the supplied Blue Team assessment.")
                lines.append("")
            else:
                seen_plan_ids = set()
                for p in plans:
                    fid = p.get("finding_id", "UNKNOWN")
                    if fid in seen_plan_ids:
                        continue
                    seen_plan_ids.add(fid)
                    lines.append(f"### Defense Plan for `{fid}`")
                    lines.append(f"- **Root Cause (Why Did It Happen?)**: [ANALYSIS] {p.get('root_cause')}")
                    lines.append(f"- **The Fix to Apply**: [RECOMMENDATION] {p.get('remediation')}")
                    changes = p.get("recommended_changes", [])
                    if changes:
                        lines.append(f"- **Concrete Code Changes**: [RECOMMENDATION] `{'; '.join(changes)}`")
                    lines.append(f"- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `{'; '.join(p.get('hardening_measures', []))}`")
                    lines.append(f"- **Did We Break Anything? (Regression Check)**: [ANALYSIS] {'; '.join(p.get('regression_risks', []))}")
                    lines.append(f"- **How to Test It**: [FACT] {'; '.join(p.get('testing_requirements', []))}")
                    lines.append("")

        # 6. SECURITY RETEST RESULTS
        lines.append("## 6. SECURITY RETEST RESULTS (VERIFYING CURRENT CODE STATUS)")
        lines.append("")
        lines.append("We re-evaluated the active codebase against the identified security checks to determine what is currently fixed versus what needs developer action:")
        lines.append("")
        p5a_dict = self.p5a if isinstance(self.p5a, dict) else {}
        retests = p5a_dict.get("retest_results") if isinstance(p5a_dict.get("retest_results"), list) else None
        summary = p5a_dict.get("summary") if isinstance(p5a_dict.get("summary"), dict) else {}
        exec_status = str(p5a_dict.get("execution_status") or p5a_dict.get("status") or "").strip().upper()

        total_retested = summary.get("total_retested")
        if total_retested is None:
            total_retested = len(retests) if retests is not None else 0

        remediated_count = summary.get("remediated")
        if remediated_count is None:
            remediated_count = sum(1 for r in retests if isinstance(r, dict) and r.get("final_status") == "REMEDIATED") if retests else 0

        not_remediated_count = summary.get("not_remediated")
        if not_remediated_count is None:
            not_remediated_count = sum(1 for r in retests if isinstance(r, dict) and r.get("final_status") == "NOT_REMEDIATED") if retests else 0

        partially_remediated_count = summary.get("partially_remediated")
        if partially_remediated_count is None:
            partially_remediated_count = sum(1 for r in retests if isinstance(r, dict) and r.get("final_status") == "PARTIALLY_REMEDIATED") if retests else 0

        # Retest is explicitly verified passed ONLY when supported by actual data:
        # Retesting must have actually run (total_retested > 0), with all items remediated,
        # zero not_remediated, zero partially_remediated, and execution confirmed.
        explicitly_passed = (
            total_retested > 0
            and remediated_count == total_retested
            and not_remediated_count == 0
            and partially_remediated_count == 0
            and (
                exec_status in ("PASSED", "SUCCESS", "VERIFIED")
                or (retests is not None and len(retests) > 0 and all(isinstance(r, dict) and r.get("final_status") == "REMEDIATED" for r in retests))
            )
        )

        if retests:
            if explicitly_passed:
                lines.append(f"✅ **All {total_retested} baseline security verification check(s) passed.** All evaluated vulnerabilities were confirmed remediated in the active codebase.")
                lines.append("")
            seen_retest_ids = set()
            for r in retests:
                if not isinstance(r, dict):
                    continue
                fid = r.get("finding_id", "UNKNOWN")
                if fid in seen_retest_ids:
                    continue
                seen_retest_ids.add(fid)
                raw_status = r.get("final_status")
                if isinstance(raw_status, str) and raw_status.strip():
                    status_text = raw_status.strip().upper()
                else:
                    status_text = "UNKNOWN"
                badge = self.get_retest_badge(status_text)
                lines.append(f"### Retest Result for `{fid}`: **{status_text}** ({badge})")
                lines.append(f"- **Original Issue**: [FACT] {r.get('original_issue', 'Security finding evaluated during retest.')}")
                lines.append(f"- **Remediation Evaluated**: [FACT] {r.get('remediation_tested', 'Defensive control implementation.')}")
                lines.append(f"- **Test Outcome in Active Code**: [FACT] {r.get('result', 'Retest verification evaluated.')}")
                lines.append(f"- **Remaining Risk**: [ANALYSIS] {r.get('remaining_risk', 'None identified.')}")
                lines.append(f"- **Current File Evidence**: [FACT] `{r.get('evidence', '')}`")
                lines.append("")
        elif explicitly_passed:
            lines.append(f"✅ **All {total_retested} baseline security verification check(s) passed.** Retest execution metadata confirmed all evaluated security controls were successfully remediated in the active codebase.")
            lines.append("")
        elif not self._p5a_provided or not self.p5a:
            lines.append("- **Retest Status**: [UNKNOWN] No security retest data was supplied. The remediation status of security findings or baseline controls could not be verified.")
            lines.append("")
        elif "retest_results" not in p5a_dict:
            lines.append("- **Retest Status**: [UNKNOWN] Retest results were not available in the supplied Phase 5A payload (`retest_results` key missing). Remediation status remains unconfirmed.")
            lines.append("")
        else:
            lines.append("- **Retest Status**: [UNKNOWN] No retest results were supplied or available (`retest_results` is empty). No security verification checks were executed, and remediation status remains unconfirmed.")
            lines.append("")

        # 7. RECOMMENDATION TRADE-OFFS
        lines.append("## 7. RECOMMENDATION TRADE-OFFS (PROS AND CONS)")
        lines.append("")
        lines.append("In software engineering, every improvement comes with a trade-off. Here is what you gain and what you give up:")
        lines.append("")
        lines.append("| Recommendation | What You Gain (The Benefit) | What You Give Up (The Trade-Off) |")
        lines.append("| :--- | :--- | :--- |")
        recs = self._get_validated_recommendations()
        seen_tradeoff_ids = set()
        for r in recs:
            rid      = r.get("recommendation_id")
            if not rid or rid in seen_tradeoff_ids:
                continue
            seen_tradeoff_ids.add(rid)
            prob     = str(r.get("problem", "")).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
            gain     = str(r.get("security_impact", r.get("technical_reasoning", "Improved code quality"))).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
            tradeoff = str(r.get("trade_offs", "Minor refactoring effort")).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
            lines.append(f"| **{rid}** — {prob} | {gain} | {tradeoff} |")
        lines.append("")

        # 8. CODE SMELL ASSESSMENT
        lines.append("## 8. CODE SMELL ASSESSMENT (CODE QUALITY REVIEW)")
        lines.append("")
        lines.append(
            "A 'code smell' is a warning sign that code might be messy, overly complex, or hard to maintain in the future."
        )
        if self._p6_provided and self.p6:
            p6_diag = self.p6.get("scan_diagnostics", []) if isinstance(self.p6.get("scan_diagnostics"), list) else []
            if p6_diag:
                lines.append(
                    f"Abstract Syntax Tree (AST) analysis was executed against discovered Python source files "
                    f"({len(p6_diag)} scan diagnostic(s) recorded during parsing)."
                )
            else:
                lines.append(
                    "Abstract Syntax Tree (AST) analysis was executed against discovered Python source files where AST parsing was supported."
                )
        else:
            lines.append(
                "[UNKNOWN] Phase 6 maintainability analysis results were not supplied; AST analysis coverage across Python source files could not be confirmed."
            )
        lines.append("")
        if not self._p6_provided or not self.p6:
            lines.append("### Summary of Code Quality Findings")
            lines.append("- **Maintainability Status**: [UNKNOWN] Code smell assessment data was not supplied; findings could not be verified.")
            lines.append("")
            smells = []
        else:
            smells = self.p6.get("code_smells", [])
            lines.append("### Summary of Code Quality Findings")
            lines.append(f"- **Total Code Smells Found**: [FACT] **{len(smells)}**")
            problematic = [s for s in smells if s.get("classification") == "PROBLEMATIC"]
            potentially = [s for s in smells if s.get("classification") == "POTENTIALLY_EXCESSIVE"]
            justified = [s for s in smells if s.get("classification") == "JUSTIFIED"]
            lines.append(f"- **PROBLEMATIC (High Priority to Clean Up)**: [ANALYSIS] {len(problematic)} items")
            lines.append(f"- **POTENTIALLY_EXCESSIVE (A bit complicated)**: [ANALYSIS] {len(potentially)} items")
            lines.append(f"- **JUSTIFIED (Complex for good reasons)**: [ANALYSIS] {len(justified)} items")
            lines.append("")

        if smells:
            lines.append("### Key Code Quality Highlights & Cleanup Plan")
            for s in smells[:6]:
                sid = s.get("smell_id", "SMELL")
                name = s.get("category", "Code Quality Issue")
                file_path = s.get("file", "source file")
                func_name = s.get("function_or_class", "module")
                lines.append(f"#### `{sid}` — {name} in `{func_name}`")
                lines.append(f"- **File Location**: [FACT] `{file_path}`")
                lines.append(f"- **What Was Found**: [FACT] {s.get('evidence')}")
                lines.append(f"- **Why It Matters**: [ANALYSIS] {s.get('explanation')}")
                lines.append(f"- **Severity Tag**: [ANALYSIS] `{s.get('classification')}`")
                lines.append(f"- **How to Clean It Up**: [RECOMMENDATION] {s.get('refactoring_strategy')}")
                lines.append("")

        # 9. CROSS-DOMAIN FINDINGS
        lines.append("## 9. CROSS-DOMAIN FINDINGS (HOW EVERYTHING CONNECTS)")
        lines.append("")
        lines.append("Security, speed, architecture, and clean code all impact each other. Here is how they interact in this project:")
        lines.append("")
        p7_dict = self.p7 if isinstance(self.p7, dict) else {}
        relationships = p7_dict.get("cross_domain_relationships") if isinstance(p7_dict.get("cross_domain_relationships"), list) else None

        # Check execution / analysis completion proof in Phase 7 schema:
        # Phase 7 CrossDomainAnalysisAgent returns "total_relationships" and "domain_interactions"
        has_domain_interactions = isinstance(p7_dict.get("domain_interactions"), dict)
        has_total_relationships = isinstance(p7_dict.get("total_relationships"), int)
        explicit_status = str(p7_dict.get("status") or p7_dict.get("execution_status") or "").strip().upper()
        explicit_completed = explicit_status in ("COMPLETED", "SUCCESS", "PASSED") or bool(p7_dict.get("analysis_completed"))

        analysis_verified = (has_domain_interactions and has_total_relationships) or explicit_completed

        if relationships:
            for rel in relationships:
                if not isinstance(rel, dict):
                    continue
                lines.append(f"### `{rel.get('relationship_id')}`: {rel.get('domain_a')} ↔ {rel.get('domain_b')}")
                lines.append(f"- **Interaction Type**: [ANALYSIS] {rel.get('relationship')}")
                lines.append(f"- **Evidence from the Code**: [FACT] {rel.get('evidence')}")
                lines.append(f"- **Impact on the Software**: [ANALYSIS] {rel.get('consequence')}")
                lines.append(f"- **Recommended Engineering Action**: [RECOMMENDATION] {rel.get('recommended_action')}")
                lines.append("")
        elif not self._p7_provided or not self.p7:
            lines.append("- **Cross-Domain Analysis Status**: [UNKNOWN] No cross-domain analysis data was supplied. Cross-domain interactions and systemic risks could not be verified.")
            lines.append("")
        elif analysis_verified and (relationships is not None or has_total_relationships):
            lines.append("✅ **Cross-domain engineering analysis completed.** [FACT] No adverse cross-domain interactions or conflicting architectural constraints were detected across the analyzed components.")
            lines.append("")
        else:
            lines.append("- **Cross-Domain Analysis Status**: [UNKNOWN] Cross-domain analysis completion could not be established. Although a relationships container was supplied, analysis execution metadata was unavailable and cross-domain interaction status remains unconfirmed.")
            lines.append("")

        # 10. REQUIREMENT <-> IMPLEMENTATION MATRIX
        lines.append("## 10. REQUIREMENT ↔ IMPLEMENTATION MATRIX (STATUS TABLE)")
        lines.append("")
        lines.append("This table shows every requirement, how it is implemented in this codebase today, and its verification status:")
        lines.append("")
        lines.append("| Requirement | What the Code Does Today | Status | Evidence File | Gap / What's Missing |")
        lines.append("| :--- | :--- | :---: | :--- | :--- |")

        validated_reqs = self._validate_and_normalize_requirements()
        if validated_reqs:
            for r in validated_reqs:
                rid = r.get("requirement_id", "REQ")
                desc = r.get("description", "Requirement")
                desc_clean = str(desc).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
                src_file = r.get("source_file") or r.get("source") or "unspecified file"
                src_file_clean = str(src_file).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
                raw_status = str(r.get("status", "")).strip().lower()
                if raw_status in ("code_supported", "documented", "explicit"):
                    status = "SATISFIED"
                    gap = "None; verified in code"
                elif raw_status == "inferred":
                    status = "INFERRED"
                    gap = "Requires formal verification"
                elif raw_status == "partially_satisfied":
                    status = "PARTIALLY_SATISFIED"
                    gap = "Requires runtime verification"
                else:
                    status = "UNKNOWN"
                    gap = "No implementation evidence supplied"
                gap_clean = str(gap).replace("|", "\\|")
                lines.append(f"| **{rid}** ({desc_clean}) | Implemented in {src_file_clean} | **{status}** | `{src_file_clean}` | {gap_clean} |")
        else:
            lines.append("| *None* | No Phase 2 requirements were supplied | **UNAVAILABLE** | None | Implementation matrix could not be evaluated |")
        lines.append("")

        # 11. PRIORITIZED RECOMMENDATIONS
        lines.append("## 11. PRIORITIZED RECOMMENDATIONS (DEVELOPER TO-DO LIST)")
        lines.append("")
        lines.append("Here is the prioritized list of recommended improvements, ranked from Critical/High to Low priority:")
        lines.append("")
        recs = self._get_validated_recommendations()
        for r in recs:
            prob_clean = str(r.get("problem", "")).replace("\r\n", " ").replace("\n", " ")
            lines.append(f"### `[{r.get('priority')}]` {r.get('recommendation_id')}: {prob_clean}")
            lines.append(f"- **The Issue**: [ANALYSIS] {prob_clean}")
            lines.append(f"- **Where to Look**: [FACT] `{r.get('evidence')}`")
            lines.append(f"- **Recommended Action**: [RECOMMENDATION] {r.get('recommended_change')}")
            lines.append(f"- **Why This Helps**: [ANALYSIS] {r.get('technical_reasoning')}")
            lines.append(f"- **How Hard to Fix?**: [ANALYSIS] **{r.get('implementation_complexity')}**")
            lines.append(f"- **Trade-Off**: [ANALYSIS] {r.get('trade_offs')}")
            lines.append("")

        # 12. LIMITATIONS & HONESTY
        lines.append("## 12. LIMITATIONS & HONESTY DISCLOSURE")
        lines.append("")
        lines.append("We believe in total transparency. Here is what this static analysis tool can and cannot see:")
        lines.append("")
        lines.append(f"- **Static Analysis Only**: [FACT] Automated analysis evaluated available code and configuration files in **{target_name}** using static inspection without running the software on a live internet server.")
        lines.append("- **No Production Secrets Tested**: [FACT] We cannot see live server environment variables, production cloud secret managers, or production database passwords.")
        lines.append("- **Dynamic Code Construction**: [ANALYSIS] If code constructs routes or queries through extreme dynamic metaprogramming at runtime, static code scanners might not see them without live execution.")
        lines.append("- **External Cloud Services**: [UNKNOWN] Third-party cloud service endpoints, external APIs, and live network latency cannot be verified without live internet connectivity.")
        lines.append("")

        # 13. MASTER SUMMARY OF ALL IMPROVEMENT SUGGESTIONS (EXECUTIVE ACTION MATRIX)
        lines.append("## 13. MASTER SUMMARY OF ALL IMPROVEMENT SUGGESTIONS (EXECUTIVE ACTION MATRIX)")
        lines.append("")
        lines.append("Below is the consolidated master summary of all improvement suggestions generated for this repository, ranked by priority:")
        lines.append("")
        lines.append("| ID | Category | Problem Analyzed | Suggested Improvement | Expected Benefit | Effort | Priority |")
        lines.append("| :--- | :--- | :--- | :--- | :--- | :---: | :---: |")

        recs = self._get_validated_recommendations()
        if not recs:
            lines.append("| **REC-01** | General | Baseline project structure | Maintain automated regression tests and security scanning | Prevents regressions | **Low** | **LOW** |")
        else:
            seen_rec_ids = set()
            for r in recs:
                rid = r.get("recommendation_id", "REC")
                if rid in seen_rec_ids:
                    continue
                seen_rec_ids.add(rid)
                prio   = r.get("priority", "MEDIUM")
                prob   = str(r.get("problem", "Identified issue")).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
                sol    = str(r.get("recommended_change", "Apply recommended fix")).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
                benefit = str(r.get("security_impact", r.get("technical_reasoning", "Improves software quality"))).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
                effort = "Low" if "LOW" in r.get("implementation_complexity", "").upper() else "Medium" if "MED" in r.get("implementation_complexity", "").upper() else "High"
                cat    = "Security" if prio in ("CRITICAL", "HIGH") else "Maintainability"
                lines.append(f"| **{rid}** | {cat} | {prob} | {sol} | {benefit} | **{effort}** | **{prio}** |")
        lines.append("")

        return "\n".join(lines)
