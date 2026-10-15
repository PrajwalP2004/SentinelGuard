"""
Phase 8: Senior Software Engineering Recommendation Engine Agent.

Transforms verified findings from security, architecture, code quality, and
cross-domain analyses into prioritized, proportionate, and actionable engineering recommendations.
Integrates evidence and context across all upstream phases (1, 2, 3A, 4A, 5A, 6, 7).
"""

import os
import re
from typing import Dict, List, Any, Optional, Set, Tuple


class RecommendationEngineAgent:
    """Agent that synthesizes multi-phase findings into actionable technical recommendations.

    Prioritization and Confidence Policy:
    =====================================
    Recommendation priority and confidence levels are deterministically derived from upstream
    phase data (Phases 1-7), evidence quality, remediation status, and cross-domain relationships,
    rather than being hardcoded into individual templates.

    Priority Determination & Precedence Hierarchy:
    ----------------------------------------------
    Priorities are evaluated according to the following strict precedence rules:
    1. Baseline Guidance:
       - Condition: recommendation_type == "baseline_guidance"
       - Priority: LOW (proactive architectural hygiene advice; does not claim repository defects).
    2. Verified Remediation:
       - Condition: Phase 5A retest confirms remediation (retest_status == "REMEDIATED") without conflicting evidence.
       - Priority: LOW (the active vulnerability is mitigated; recommendation pivots to automated regression guards).
    3. Conflicting Remediation Evidence:
       - Condition: retest_status == "CONFLICTED" or retest/finding evidence indicates contradictory facts.
       - Priority: Preserves base severity without downgrade (e.g., CRITICAL remains CRITICAL, HIGH remains HIGH).
         Conservative rule: unverified or disputed fixes must never prematurely downgrade operational risk.
    4. Partial Remediation:
       - Condition: retest_status == "PARTIALLY_REMEDIATED"
       - Priority: Conservative risk adjustment.
         - Base CRITICAL -> adjusted to HIGH (partial reduction acknowledged, but residual attack paths remain open).
         - Base HIGH -> remains HIGH (active exposure remains unmitigated).
         - Base MEDIUM -> remains MEDIUM.
         - Base LOW / INFORMATIONAL -> remains base severity.
    5. Cross-Domain Amplification (Phase 7):
       - Silent exception suppression smell + REL-SMELL-SEC-01 -> elevates to HIGH (suppresses auditability/logging).
       - Traversal structural complexity smell + REL-SMELL-SCALE-01 -> elevates to HIGH (creates scaling bottleneck).
       - RED-DOS-01 + REL-SEC-PERF-01 -> preserved at HIGH or CRITICAL (DoS risk amplified by extraction latency).
       - Standalone architectural relationships (REL-ARCH-SEC-01, REL-ARCH-MAINT-01, REL-SEC-MAINT-01) -> HIGH.
    6. Active / Untested Finding (Base Severity Resolution):
       - Condition: Unresolved finding (retest_status in ("NOT_REMEDIATED", "UNTESTED", "NOT_TESTABLE", "UNVERIFIED")).
       - Priority: Resolved from upstream finding severity or Blue Team remediation plan severity.
         If exploitability is explicitly rated ACTIVE_EXPLOIT or CRITICAL, elevated to CRITICAL.
         If severity is missing from upstream finding:
         - Canonical taxonomy for recognized IDs (e.g., RED-SQL-01: CRITICAL, RED-SECRET-01: HIGH, RED-CORS-01: MEDIUM, RED-CRYPTO-01: LOW).
         - Unknown/arbitrary finding IDs: conservative fallback to MEDIUM (avoids false precision).
         - Code smells without cross-domain amplification: structural -> MEDIUM; general clean code -> LOW.
    7. Informational:
       - Condition: Upstream finding explicitly flagged with INFORMATIONAL severity (advisory only).
       - Priority: INFORMATIONAL.

    Confidence Derivation:
    ----------------------
    Confidence is evaluated independently of priority based on evidence quality and consistency:
    - LOW:
      - Conflicting or contradictory evidence (retest_status == "CONFLICTED" or conflict in evidence text).
      - Upstream validation status is POSSIBLE, INSUFFICIENT_EVIDENCE, or FALSE_POSITIVE.
      - Upstream explicitly assigned LOW confidence.
      - Missing data: finding lacks both concrete code snippets and specific target file paths.
    - MEDIUM:
      - Partial evidence: finding specifies target file(s) but lacks concrete code snippet, OR vice-versa.
      - Upstream validation status is PROBABLE.
      - Upstream explicitly capped confidence at MEDIUM or POTENTIAL.
      - Retest status is UNVERIFIED or NOT_TESTABLE.
    - HIGH:
      - Strong evidence: finding contains concrete, non-placeholder code snippet (>=10 chars) AND verified file path(s).
      - Upstream validation status is CONFIRMED or not degraded.
      - Verified Phase 7 relationships with concrete evidence.
      - Baseline guidance (high confidence in proactive software engineering best practices).
    """

    PRIORITY_ORDER = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFORMATIONAL": 4,
    }

    CANONICAL_TAXONOMY_SEVERITY = {
        "RED-SQL-01": "CRITICAL",
        "RED-CMD-01": "CRITICAL",
        "RED-DESER-01": "HIGH",
        "RED-DESERIAL-01": "HIGH",
        "RED-AUTH-01": "CRITICAL",
        "RED-SECRET-01": "HIGH",
        "RED-DOS-01": "HIGH",
        "RED-DEBUG-01": "HIGH",
        "RED-INJ-01": "HIGH",
        "RED-XXE-01": "HIGH",
        "RED-SSRF-01": "HIGH",
        "RED-PATH-01": "HIGH",
        "RED-CORS-01": "MEDIUM",
        "RED-CRYPTO-01": "LOW",
    }

    def __init__(
        self,
        phase1_reconstruction: Optional[Dict[str, Any]] = None,
        phase2_requirements: Optional[List[Dict[str, Any]]] = None,
        phase3a_findings: Optional[List[Dict[str, Any]]] = None,
        phase4a_remediations: Optional[List[Dict[str, Any]]] = None,
        phase5a_retest: Optional[Dict[str, Any]] = None,
        phase6_smells: Optional[List[Dict[str, Any]]] = None,
        phase7_relationships: Optional[List[Dict[str, Any]]] = None,
        include_baseline_guidance: Optional[bool] = None,
    ):
        self.p1 = phase1_reconstruction if isinstance(phase1_reconstruction, dict) else {}
        self.raw_p2 = phase2_requirements
        self.raw_p3a = phase3a_findings
        self.raw_p4a = phase4a_remediations
        self.raw_p5a = phase5a_retest
        self.raw_p6 = phase6_smells
        self.raw_p7 = phase7_relationships

        self.p2_reqs = self._extract_list(phase2_requirements, "requirements")
        self.p3a_findings = self._extract_list(phase3a_findings, "findings")
        self.p4a_remediations = self._extract_list(phase4a_remediations, "remediation_plans")
        self.p5a_retest = phase5a_retest if isinstance(phase5a_retest, dict) else (
            {"retest_results": phase5a_retest} if isinstance(phase5a_retest, list) else {}
        )
        self.p6_smells = self._extract_list(phase6_smells, "code_smells")
        self.p7_relationships = self._extract_list(phase7_relationships, "cross_domain_relationships")
        if not self.p7_relationships and isinstance(phase7_relationships, dict):
            self.p7_relationships = self._extract_list(phase7_relationships, "relationships")
        self.include_baseline_guidance = include_baseline_guidance

    @staticmethod
    def _extract_list(raw_input: Any, key_name: str) -> List[Dict[str, Any]]:
        """Safely normalizes input containers into a list of dicts."""
        if isinstance(raw_input, list):
            return [x for x in raw_input if isinstance(x, dict)]
        if isinstance(raw_input, dict):
            inner = raw_input.get(key_name, [])
            if isinstance(inner, list):
                return [x for x in inner if isinstance(x, dict)]
        return []

    # -------------------------------------------------------------------------
    # Upstream Context Resolution Helpers
    # -------------------------------------------------------------------------

    def _resolve_requirement(self, req_id: Optional[str] = None, category_hint: Optional[str] = None) -> str:
        """Connects recommendation to verified Phase 2 requirements when supported by input data."""
        if req_id and isinstance(req_id, str):
            clean_id = req_id.strip()
            for r in self.p2_reqs:
                if str(r.get("requirement_id", "")).strip().upper() == clean_id.upper():
                    title = r.get("title") or r.get("description", "")
                    return f"{clean_id}: {title}" if title else clean_id
            return clean_id

        if category_hint and isinstance(category_hint, str):
            hint_lower = category_hint.lower()
            for r in self.p2_reqs:
                cat = str(r.get("category", "")).lower()
                desc = str(r.get("description", "")).lower()
                title = str(r.get("title", "")).lower()
                r_id = str(r.get("requirement_id", "")).strip()
                if hint_lower in cat or hint_lower in desc or hint_lower in title:
                    r_title = r.get("title") or r.get("description", "")
                    return f"{r_id}: {r_title}" if r_title else r_id

        # Traceable defaults matching standard SecSys Architect taxonomy
        if category_hint in ("observability", "logging"):
            return "REQ-NFR-03: Diagnostic Observability & Logging"
        if category_hint in ("maintainability", "complexity"):
            return "REQ-NFR-01: Code Maintainability and Extensibility"
        if category_hint in ("dependency", "architecture"):
            return "REQ-NFR-02: Zero External Dependencies Policy"
        if category_hint in ("performance", "quota"):
            return "REQ-NFR-02: Defensive Archive Ingestion & Quotas"
        return "REQ-SEC-01: Application Security Controls"

    def _resolve_phase1_context(self) -> Dict[str, Any]:
        """Extracts relevant, traceable system facts from Phase 1 without inventing details."""
        summary = self.p1.get("project_summary", {})
        arch = self.p1.get("architecture", {})
        databases = self.p1.get("databases", [])
        frameworks = self.p1.get("frameworks", [])
        archive_ctrls = self.p1.get("archive_controls", {})

        db_names = [d.get("type") or d.get("name") for d in databases if isinstance(d, dict)]
        db_names = [d for d in db_names if d]

        fw_names = [f.get("name") if isinstance(f, dict) else str(f) for f in frameworks]
        fw_names = [f for f in fw_names if f]

        return {
            "project_name": summary.get("name"),
            "app_type": summary.get("application_type", {}).get("type") if isinstance(summary.get("application_type"), dict) else None,
            "arch_pattern": arch.get("pattern"),
            "databases": db_names,
            "frameworks": fw_names,
            "archive_enforced": archive_ctrls.get("enforced") if isinstance(archive_ctrls, dict) else None,
        }

    # -------------------------------------------------------------------------
    # Recommendation Deduplication & Evidence Consolidation Helpers
    # -------------------------------------------------------------------------

    @classmethod
    def _normalize_text(cls, val: Any) -> str:
        """Normalizes text for robust duplicate comparison by stripping non-alphanumerics and collapsing whitespace."""
        if not val:
            return ""
        cleaned = re.sub(r'[*`_]', '', str(val))
        cleaned = re.sub(r'[^a-zA-Z0-9\s]', ' ', cleaned)
        return " ".join(cleaned.strip().lower().split())

    @classmethod
    def _compute_rec_dedup_key(cls, r: Dict[str, Any]) -> Tuple[str, str, str, Tuple[str, ...]]:
        """Computes a stable deduplication key based on the underlying issue, solution, and affected component/files.
        
        Two recommendations are true duplicates if they share:
        1. A specific finding ID AND normalized problem statement AND normalized solution AND the same affected files/component.
        2. Or, for non-standard IDs, the same normalized problem, recommended change, technical reasoning, and affected files.
        Distinct findings in materially different files or components are preserved as separate recommendations.
        """
        raw_fid = str(r.get("finding_id", "")).strip().upper()
        prob = cls._normalize_text(r.get("problem", ""))
        sol = cls._normalize_text(r.get("recommended_change", ""))
        
        raw_files = r.get("affected_files", [])
        if isinstance(raw_files, str):
            files_list = [raw_files]
        elif isinstance(raw_files, list):
            files_list = raw_files
        else:
            files_list = []
        files_tuple = tuple(sorted(str(f).strip().lower() for f in files_list if str(f).strip()))
        
        # If finding_id is a known specific security finding ID
        if raw_fid and not raw_fid.startswith("SEC-UNMAPPED") and not raw_fid.startswith("SMELL-") and not raw_fid.startswith("BASE-"):
            return (raw_fid, prob, sol, files_tuple)
            
        reasoning = cls._normalize_text(r.get("technical_reasoning", r.get("security_impact", "")))
        return (raw_fid or "GENERAL", prob, sol, files_tuple)

    @classmethod
    def _merge_duplicate_recs(cls, existing: Dict[str, Any], duplicate: Dict[str, Any]) -> Dict[str, Any]:
        """Consolidates duplicate recommendation records into a canonical recommendation.
        
        Preserves:
        - Non-conflicting evidence from both records
        - Union of affected files / components
        - Phase provenance sources
        - Higher priority (never silently downgrading severity)
        - Higher confidence
        """
        merged = dict(existing)
        
        # 1. Merge affected files
        files_set = set()
        for rec in (existing, duplicate):
            raw_files = rec.get("affected_files", [])
            if isinstance(raw_files, list):
                for f in raw_files:
                    if f and str(f).strip():
                        files_set.add(str(f).strip())
            elif isinstance(raw_files, str) and raw_files.strip():
                files_set.add(raw_files.strip())
        if files_set:
            merged["affected_files"] = sorted(list(files_set))
            
        # 2. Merge evidence
        ev_existing = str(existing.get("evidence", "")).strip()
        ev_dup = str(duplicate.get("evidence", "")).strip()
        if ev_dup and ev_dup not in ev_existing:
            if ev_existing:
                merged["evidence"] = f"{ev_existing}; Additional occurrence: {ev_dup}"
            else:
                merged["evidence"] = ev_dup
                
        # 3. Merge phase sources
        srcs = list(existing.get("phase_sources", []))
        for s in duplicate.get("phase_sources", []):
            if s not in srcs:
                srcs.append(s)
        merged["phase_sources"] = srcs
        
        # 4. Resolve priority: take the higher priority (lower rank value in PRIORITY_ORDER)
        p_exist = existing.get("priority", "MEDIUM")
        p_dup = duplicate.get("priority", "MEDIUM")
        order_exist = cls.PRIORITY_ORDER.get(p_exist, 2)
        order_dup = cls.PRIORITY_ORDER.get(p_dup, 2)
        if order_dup < order_exist:
            merged["priority"] = p_dup
            
        # 5. Resolve confidence: take higher confidence
        conf_ranks = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        c_exist = existing.get("confidence", "MEDIUM")
        c_dup = duplicate.get("confidence", "MEDIUM")
        if conf_ranks.get(c_dup, 1) < conf_ranks.get(c_exist, 1):
            merged["confidence"] = c_dup
            
        return merged

    def _consolidate_recommendations(self, recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicates and merges recommendations representing the same underlying issue."""
        deduped: List[Dict[str, Any]] = []
        key_to_index: Dict[Tuple[str, str, str], int] = {}
        
        for r in recs:
            key = self._compute_rec_dedup_key(r)
            if key in key_to_index:
                # Merge duplicate into existing canonical record
                idx = key_to_index[key]
                deduped[idx] = self._merge_duplicate_recs(deduped[idx], r)
            else:
                key_to_index[key] = len(deduped)
                deduped.append(dict(r))
                
        return deduped

    # -------------------------------------------------------------------------
    # Prioritization & Confidence Policy Helpers
    # -------------------------------------------------------------------------

    def _derive_security_priority(
        self,
        fid: str,
        finding: Dict[str, Any],
        p4a_plan: Dict[str, Any],
        p5a_res: Dict[str, Any],
        retest_status: str,
        is_conflicted: bool,
        p7_by_rel_id: Dict[str, Dict[str, Any]],
    ) -> str:
        """Deterministically derives security recommendation priority based on documented precedence rules."""
        # 1. Base severity from upstream finding or plan
        base_sev = None
        if finding.get("severity"):
            s = str(finding.get("severity")).strip().upper()
            if s in self.PRIORITY_ORDER:
                base_sev = s
        if base_sev is None and p4a_plan.get("severity"):
            s = str(p4a_plan.get("severity")).strip().upper()
            if s in self.PRIORITY_ORDER:
                base_sev = s
        if base_sev is None:
            base_sev = self.CANONICAL_TAXONOMY_SEVERITY.get(fid, "MEDIUM")

        # Exploitability signal
        exploitability = str(finding.get("exploitability", "")).strip().upper()
        if exploitability in ("CRITICAL", "ACTIVE_EXPLOIT") and base_sev == "HIGH":
            base_sev = "CRITICAL"

        # Precedence 1: Verified remediation
        if retest_status == "REMEDIATED" and not is_conflicted:
            return "LOW"

        # Precedence 2: Conflicting evidence (conservative: do not downgrade)
        if is_conflicted:
            return base_sev

        # Precedence 3: Partial remediation (conservative: critical -> high, others retain base severity)
        if retest_status == "PARTIALLY_REMEDIATED":
            if base_sev == "CRITICAL":
                return "HIGH"
            return base_sev

        # Precedence 4: Cross-domain amplification
        if fid == "RED-DOS-01" and p7_by_rel_id.get("REL-SEC-PERF-01"):
            if self.PRIORITY_ORDER.get(base_sev, 2) > self.PRIORITY_ORDER["HIGH"]:
                return "HIGH"
            return base_sev

        # Precedence 5: Active, untested, or unresolved finding
        return base_sev

    def _derive_confidence(
        self,
        finding: Dict[str, Any],
        p4a_plan: Dict[str, Any],
        p5a_res: Dict[str, Any],
        raw_evidence: str,
        files_list: List[str],
        retest_status: str,
        is_conflicted: bool,
    ) -> str:
        """Derives recommendation confidence from evidence quality and consistency separately from priority."""
        # Factor 1: Conflicting or contradictory evidence
        if is_conflicted:
            return "LOW"

        # Factor 2: Upstream validation status
        v_status = str(finding.get("validation_status", "")).strip().upper()
        if v_status in ("POSSIBLE", "INSUFFICIENT_EVIDENCE", "FALSE_POSITIVE"):
            return "LOW"

        # Factor 3: Upstream explicit confidence cap
        raw_conf = str(
            finding.get("confidence")
            or p5a_res.get("confidence")
            or p4a_plan.get("confidence")
            or ""
        ).strip().upper()

        cap = "HIGH"
        if raw_conf == "LOW":
            return "LOW"
        elif raw_conf in ("MEDIUM", "POTENTIAL") or v_status == "PROBABLE":
            cap = "MEDIUM"
        elif raw_conf in ("HIGH", "CONFIRMED") or v_status == "CONFIRMED":
            cap = "HIGH"

        # Factor 4: Retest unverified or not testable caps confidence
        if retest_status in ("UNVERIFIED", "NOT_TESTABLE"):
            if cap == "HIGH":
                cap = "MEDIUM"

        # Factor 5: Evidence quality (concrete code snippet and files)
        evidence_str = str(raw_evidence).strip()
        has_snippet = (
            bool(evidence_str)
            and len(evidence_str) >= 10
            and not any(p in evidence_str.lower() for p in (
                "without specific code snippet",
                "upstream finding logged without",
                "unspecified",
                "none",
                "placeholder"
            ))
        )
        has_files = (
            bool(files_list)
            and any(f and f.strip() and not any(p in f.lower() for p in ("unspecified", "target component")) for f in files_list)
        )

        if has_snippet and has_files:
            return cap
        elif has_snippet or has_files:
            return "MEDIUM" if cap == "HIGH" else cap
        else:
            # Conservative fallback: insufficient upstream data
            return "LOW"

    def _derive_smell_priority(
        self,
        smell: Dict[str, Any],
        is_silent: bool,
        is_structural: bool,
        rel_sec: Optional[Dict[str, Any]],
        rel_scale: Optional[Dict[str, Any]],
        is_scale_candidate: bool,
    ) -> str:
        """Derives code smell priority respecting severity and Phase 7 cross-domain amplification."""
        raw_sev = str(smell.get("severity", "")).strip().upper()
        upstream_sev = raw_sev if raw_sev in self.PRIORITY_ORDER else None

        if is_silent:
            if rel_sec:
                return "HIGH"
            return upstream_sev or "HIGH"
        elif is_structural:
            if rel_scale and is_scale_candidate:
                return "HIGH"
            return upstream_sev or "MEDIUM"
        else:
            return upstream_sev or "LOW"

    def _derive_smell_confidence(self, smell: Dict[str, Any]) -> str:
        """Derives code smell confidence from smell evidence, file context, and validation status."""
        v_status = str(smell.get("validation_status", "")).strip().upper()
        if v_status in ("POSSIBLE", "INSUFFICIENT_EVIDENCE", "FALSE_POSITIVE"):
            return "LOW"

        raw_conf = str(smell.get("confidence", "")).strip().upper()
        cap = "HIGH"
        if raw_conf == "LOW":
            return "LOW"
        elif raw_conf in ("MEDIUM", "POTENTIAL") or v_status == "PROBABLE":
            cap = "MEDIUM"

        evidence = str(smell.get("evidence", "")).strip()
        file_path = str(smell.get("file", "")).strip()

        has_snippet = len(evidence) >= 8 and not any(p in evidence.lower() for p in ("unspecified", "none", "placeholder"))
        has_file = len(file_path) > 0 and file_path != "source" and "unspecified" not in file_path.lower()

        if has_snippet and has_file:
            return cap
        elif has_snippet or has_file:
            return "MEDIUM" if cap == "HIGH" else cap
        else:
            return "LOW"

    def _derive_rel_confidence(self, rel: Optional[Dict[str, Any]]) -> str:
        """Derives confidence for Phase 7 cross-domain architectural relationships."""
        if not rel or not isinstance(rel, dict):
            return "LOW"
        is_verified = rel.get("verified", True)
        v_status = str(rel.get("verification_status", "")).strip().upper()
        if v_status in ("UNVERIFIED", "INSUFFICIENT_EVIDENCE") or not is_verified:
            return "LOW"
        evidence = str(rel.get("evidence", "")).strip()
        if not evidence or "unspecified" in evidence.lower():
            return "MEDIUM"
        return "HIGH"

    # -------------------------------------------------------------------------
    # Recommendation Generation
    # -------------------------------------------------------------------------

    def generate_recommendations(self, include_baseline_guidance: Optional[bool] = None) -> Dict[str, Any]:
        """Generates evidence-backed technical recommendations conforming to Phase 8 specifications.

        Backward-compatible schema extension:
        - Added 'unmapped_findings': List of findings, smells, or relationships that are unsupported,
          unmapped to automated templates, empty, or malformed, preserving full audit traceability.
        - Added 'summary.unmapped_findings': count of unmapped diagnostic entries.
        """
        recs: List[Dict[str, Any]] = []
        seen_fids: Set[str] = set()
        seen_finding_identities: Set[Tuple[str, Tuple[str, ...], str, str]] = set()
        unmapped_findings: List[Dict[str, Any]] = []
        p1_ctx = self._resolve_phase1_context()

        # Capture malformed non-dictionary elements from raw inputs
        def collect_malformed(raw_input: Any, key_name: str, phase_name: str):
            if raw_input is None:
                return
            items = []
            if isinstance(raw_input, list):
                items = raw_input
            elif isinstance(raw_input, dict):
                inner = raw_input.get(key_name)
                if isinstance(inner, list):
                    items = inner
                elif inner is not None:
                    unmapped_findings.append({
                        "source_phase": phase_name,
                        "status": "MALFORMED_CONTAINER",
                        "reason": f"Expected list for '{key_name}', got {type(inner).__name__}.",
                        "raw_record": inner
                    })
            for item in items:
                if not isinstance(item, dict):
                    unmapped_findings.append({
                        "source_phase": phase_name,
                        "status": "MALFORMED_RECORD",
                        "reason": f"Non-dictionary record of type '{type(item).__name__}' found in {phase_name} input.",
                        "raw_record": item
                    })

        collect_malformed(self.raw_p3a, "findings", "Phase 3A")
        collect_malformed(self.raw_p6, "code_smells", "Phase 6")
        collect_malformed(self.raw_p7, "cross_domain_relationships", "Phase 7")

        # Build index maps for upstream phases
        p4a_by_fid: Dict[str, Dict[str, Any]] = {}
        for p in self.p4a_remediations:
            fid = str(p.get("finding_id", "")).strip().upper()
            if fid:
                p4a_by_fid[fid] = p

        p5a_by_fid: Dict[str, Dict[str, Any]] = {}
        retest_results = self.p5a_retest.get("retest_results", [])
        if isinstance(retest_results, list):
            for r in retest_results:
                if isinstance(r, dict):
                    fid = str(r.get("finding_id", "")).strip().upper()
                    if fid:
                        p5a_by_fid[fid] = r

        p7_by_rel_id: Dict[str, Dict[str, Any]] = {}
        for rel in self.p7_relationships:
            rid = str(rel.get("relationship_id", "")).strip().upper()
            if rid:
                p7_by_rel_id[rid] = rel

        # ---------------------------------------------------------------------
        # 1. Security Findings: Synthesize across Phase 3A, 4A, 5A, and 7
        # ---------------------------------------------------------------------
        all_finding_entries: List[Dict[str, Any]] = []
        unmapped_sec_counter = 0

        for f in self.p3a_findings:
            if not isinstance(f, dict):
                continue
            raw_fid = str(f.get("finding_id", "")).strip().upper()
            title = str(f.get("title", "")).strip()
            evidence = str(f.get("evidence", "")).strip()
            files = f.get("affected_files", [])

            # Empty record check: completely empty dictionary
            if not raw_fid and not title and not evidence and not files:
                unmapped_findings.append({
                    "source_phase": "Phase 3A",
                    "status": "EMPTY_RECORD",
                    "reason": "Finding dictionary has no finding_id, title, evidence, or affected_files.",
                    "record": f
                })
                continue

            # Empty ID check: finding has details but empty finding_id
            if not raw_fid:
                unmapped_sec_counter += 1
                fid = f"SEC-UNMAPPED-{unmapped_sec_counter:02d}"
                finding_copy = dict(f)
                finding_copy["finding_id"] = fid
                finding_copy["is_empty_id"] = True
                all_finding_entries.append(finding_copy)
                unmapped_findings.append({
                    "source_phase": "Phase 3A",
                    "finding_id": fid,
                    "status": "EMPTY_ID",
                    "reason": "Finding provided with empty or missing finding_id; assigned sequential unmapped ID for tracking.",
                    "affected_files": files,
                    "evidence": evidence,
                    "title": title
                })
            else:
                all_finding_entries.append(f)

        # Supplement with Phase 4A plans not yet in all_finding_entries
        existing_fids = {str(x.get("finding_id", "")).strip().upper() for x in all_finding_entries}
        for fid, plan in p4a_by_fid.items():
            if fid not in existing_fids:
                all_finding_entries.append({
                    "finding_id": fid,
                    "title": plan.get("title", f"Security Finding {fid}"),
                    "affected_files": plan.get("affected_files", []),
                    "severity": plan.get("severity"),
                    "confidence": plan.get("confidence"),
                    "evidence": plan.get("evidence", ""),
                    "requirement_affected": plan.get("requirement_affected", "REQ-SEC-01"),
                })
                existing_fids.add(fid)

        # Supplement with Phase 5A retests not yet in all_finding_entries
        for fid, r_item in p5a_by_fid.items():
            if fid not in existing_fids:
                all_finding_entries.append({
                    "finding_id": fid,
                    "title": r_item.get("original_issue", f"Security Finding {fid}"),
                    "affected_files": r_item.get("inspected_files", []),
                    "severity": r_item.get("severity"),
                    "confidence": r_item.get("confidence"),
                    "evidence": r_item.get("evidence", ""),
                    "requirement_affected": "REQ-SEC-01",
                })
                existing_fids.add(fid)

        consolidated_findings: List[Dict[str, Any]] = []
        finding_id_to_idx: Dict[Tuple[str, Tuple[str, ...], str, str], int] = {}
        for finding in all_finding_entries:
            fid = str(finding.get("finding_id", "")).strip().upper()
            if not fid:
                continue

            raw_files = finding.get("affected_files", [])
            if isinstance(raw_files, str):
                files_list = [raw_files]
            elif isinstance(raw_files, list):
                files_list = raw_files
            else:
                files_list = []
            files_tuple = tuple(sorted(str(x).strip() for x in files_list if str(x).strip()))
            evidence = str(finding.get("evidence", "")).strip()
            line = str(finding.get("line", "")).strip()

            finding_identity = (fid, files_tuple, evidence, line)
            if finding_identity in finding_id_to_idx:
                existing_f = consolidated_findings[finding_id_to_idx[finding_identity]]
                # Resolve conflicting severity: take higher severity (lower rank in PRIORITY_ORDER)
                s_exist = str(existing_f.get("severity", "")).strip().upper()
                s_new = str(finding.get("severity", "")).strip().upper()
                rank_exist = self.PRIORITY_ORDER.get(s_exist, 99)
                rank_new = self.PRIORITY_ORDER.get(s_new, 99)
                if rank_new < rank_exist:
                    existing_f["severity"] = s_new
                # Resolve confidence: take higher confidence
                c_ranks = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
                c_exist = str(existing_f.get("confidence", "")).strip().upper()
                c_new = str(finding.get("confidence", "")).strip().upper()
                if c_ranks.get(c_new, 99) < c_ranks.get(c_exist, 99):
                    existing_f["confidence"] = c_new
            else:
                finding_id_to_idx[finding_identity] = len(consolidated_findings)
                consolidated_findings.append(dict(finding))

        for finding in consolidated_findings:
            fid = str(finding.get("finding_id", "")).strip().upper()
            if not fid:
                continue

            raw_files = finding.get("affected_files", [])
            if isinstance(raw_files, str):
                files_list = [raw_files]
            elif isinstance(raw_files, list):
                files_list = raw_files
            else:
                files_list = []
            files_tuple = tuple(sorted(str(x).strip() for x in files_list if str(x).strip()))
            evidence = str(finding.get("evidence", "")).strip()
            line = str(finding.get("line", "")).strip()
            seen_fids.add(fid)

            p4a_plan = p4a_by_fid.get(fid, {})
            p5a_res = p5a_by_fid.get(fid, {})

            # Determine Retest Status & Provenance
            retest_status = str(p5a_res.get("final_status", "")).strip().upper() if p5a_res else "UNTESTED"
            retest_result_msg = str(p5a_res.get("result", "")).strip() if p5a_res else ""
            remaining_risk = str(p5a_res.get("remaining_risk", "")).strip() if p5a_res else ""
            p5a_evidence = str(p5a_res.get("evidence", "")).strip() if p5a_res else ""

            phase_sources = ["Phase 3A"]
            if p4a_plan:
                phase_sources.append("Phase 4A")
            if p5a_res:
                phase_sources.append("Phase 5A")

            # Resolve affected files
            files = files_list or p4a_plan.get("affected_files", []) or p5a_res.get("inspected_files", [])
            if isinstance(files, str):
                files = [files]
            files_str = ", ".join(files) if files else ""

            # Requirement linking
            req_id = self._resolve_requirement(
                finding.get("requirement_affected") or p4a_plan.get("requirement_affected"),
                category_hint="security"
            )

            # Build Security Recommendation tailored by status and domain facts
            rec = self._build_security_rec(
                fid=fid,
                finding=finding,
                p4a_plan=p4a_plan,
                p5a_res=p5a_res,
                retest_status=retest_status,
                retest_result_msg=retest_result_msg,
                remaining_risk=remaining_risk,
                p5a_evidence=p5a_evidence,
                files_str=files_str,
                req_id=req_id,
                p1_ctx=p1_ctx,
                p7_by_rel_id=p7_by_rel_id,
                phase_sources=phase_sources,
                unmapped_findings=unmapped_findings,
            )
            if rec:
                if files_list:
                    rec["affected_files"] = list(files_list)
                recs.append(rec)

        # ---------------------------------------------------------------------
        # 2. Code Smells & Maintainability: Synthesize across Phase 6 and 7
        # ---------------------------------------------------------------------
        smell_recs = self._build_smell_recommendations(p7_by_rel_id, unmapped_findings)
        recs.extend(smell_recs)

        # ---------------------------------------------------------------------
        # 3. Cross-Domain Architectural Insights (Phase 7 standalone relationships)
        # ---------------------------------------------------------------------
        arch_recs = self._build_cross_domain_recommendations(p7_by_rel_id, seen_fids, unmapped_findings)
        recs.extend(arch_recs)

        # Mark all upstream finding-derived recommendations explicitly
        for r in recs:
            r["recommendation_type"] = "finding_driven"

        # ---------------------------------------------------------------------
        # 4. Baseline Technical Recommendations (Configurable Proactive Guidance)
        # ---------------------------------------------------------------------
        # Do not arbitrarily pad findings to reach 4.
        # Include baseline guidance only if explicitly requested, or if zero findings exist by default.
        if include_baseline_guidance is not None:
            should_include_baseline = bool(include_baseline_guidance)
        elif self.include_baseline_guidance is not None:
            should_include_baseline = bool(self.include_baseline_guidance)
        else:
            should_include_baseline = (len(recs) == 0)

        if should_include_baseline:
            baseline_recs = self._build_baseline_recommendations(p1_ctx=p1_ctx)
            for br in baseline_recs:
                br["recommendation_type"] = "baseline_guidance"
            recs.extend(baseline_recs)

        # ---------------------------------------------------------------------
        # 5. Prioritize, Deduplicate, and Format Output IDs
        # ---------------------------------------------------------------------
        # Consolidate duplicate recommendations representing the same underlying issue,
        # preserving combined evidence, affected files, and highest priority.
        recs = self._consolidate_recommendations(recs)

        # Finding-driven recommendations appear first, sorted by priority and finding_id.
        # Baseline suggestions appear after, sorted by finding_id, ensuring deterministic order.
        # Multi-attribute deterministic stable ordering
        recs.sort(key=lambda r: (
            0 if r.get("recommendation_type") == "finding_driven" else 1,
            self.PRIORITY_ORDER.get(r.get("priority", "MEDIUM"), 5),
            str(r.get("finding_id", "")).strip().upper(),
            str(r.get("evidence", "")).strip(),
            str(r.get("problem", "")).strip(),
            str(r.get("requirement_affected", "")).strip(),
        ))

        for i, r in enumerate(recs, start=1):
            r["recommendation_id"] = f"REC-{i:02d}"

        return {
            "recommendations": recs,
            "total_recommendations": len(recs),
            "unmapped_findings": unmapped_findings,
            "summary": {
                "critical": sum(1 for r in recs if r.get("priority") == "CRITICAL"),
                "high": sum(1 for r in recs if r.get("priority") == "HIGH"),
                "medium": sum(1 for r in recs if r.get("priority") == "MEDIUM"),
                "low": sum(1 for r in recs if r.get("priority") == "LOW"),
                "informational": sum(1 for r in recs if r.get("priority") == "INFORMATIONAL"),
                "findings_driven": sum(1 for r in recs if r.get("recommendation_type") == "finding_driven"),
                "baseline_guidance": sum(1 for r in recs if r.get("recommendation_type") == "baseline_guidance"),
                "unmapped_findings": len(unmapped_findings),
            }
        }

    # -------------------------------------------------------------------------
    # Security Recommendation Builder (Status-Aware)
    # -------------------------------------------------------------------------

    def _build_security_rec(
        self,
        fid: str,
        finding: Dict[str, Any],
        p4a_plan: Dict[str, Any],
        p5a_res: Dict[str, Any],
        retest_status: str,
        retest_result_msg: str,
        remaining_risk: str,
        p5a_evidence: str,
        files_str: str,
        req_id: str,
        p1_ctx: Dict[str, Any],
        p7_by_rel_id: Dict[str, Dict[str, Any]],
        phase_sources: List[str],
        unmapped_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Constructs a nuanced, status-aware, and proportionate recommendation for a security finding."""
        title = finding.get("title") or p4a_plan.get("title") or f"Security Finding {fid}"
        raw_evidence = finding.get("evidence") or p4a_plan.get("evidence") or p5a_evidence
        root_cause = p4a_plan.get("root_cause")
        plan_remediation = p4a_plan.get("remediation")
        plan_changes = p4a_plan.get("recommended_changes", [])
        reg_risks = p4a_plan.get("regression_risks", [])

        is_remediated = retest_status == "REMEDIATED"
        is_partial = retest_status == "PARTIALLY_REMEDIATED"
        is_conflicted = retest_status == "CONFLICTED" or "conflict" in p5a_evidence.lower() or "conflict" in str(raw_evidence).lower()

        priority = self._derive_security_priority(
            fid=fid,
            finding=finding,
            p4a_plan=p4a_plan,
            p5a_res=p5a_res,
            retest_status=retest_status,
            is_conflicted=is_conflicted,
            p7_by_rel_id=p7_by_rel_id,
        )

        files_list = [f.strip() for f in files_str.split(",") if f.strip()] if files_str else []
        confidence = self._derive_confidence(
            finding=finding,
            p4a_plan=p4a_plan,
            p5a_res=p5a_res,
            raw_evidence=raw_evidence,
            files_list=files_list,
            retest_status=retest_status,
            is_conflicted=is_conflicted,
        )

        # Phase 1 traceable database context without invention
        db_context = f" Database detected in Phase 1: {', '.join(p1_ctx['databases'])}." if p1_ctx.get("databases") else ""

        # Distinguish observed component facts from missing evidence
        files_label = f"File(s) {files_str}" if files_str else "Target component (unspecified in upstream findings)"
        if raw_evidence:
            evidence_summary = f"{files_label}: {raw_evidence}.{db_context}"
        else:
            evidence_summary = f"{files_label}: Upstream finding logged without specific code snippet.{db_context}"

        if p5a_res and retest_result_msg:
            evidence_summary += f" Retest verification (Phase 5A): status={retest_status}, details={retest_result_msg}."

        # ---------------------------------------------------------------------
        # 1. SQL Injection (RED-SQL-01)
        # ---------------------------------------------------------------------
        if fid == "RED-SQL-01":
            if is_remediated:
                problem = "Maintain and continuously verify parameterized query guards to prevent regression of resolved SQL injection (RED-SQL-01)."
                cur_impl = f"Phase 5A retest confirmed remediation (REMEDIATED): {retest_result_msg or 'Parameterized queries verified'}."
                rec_change = "Retain parameterized query placeholders and embed automated regression tests in CI/CD asserting parameters are treated strictly as literal data."
            elif is_partial:
                problem = f"Complete SQL parameterization across remaining query paths; partial controls leave injection exposure (RED-SQL-01). Residual risk: {remaining_risk}."
                cur_impl = f"Partial parameterization verified in Phase 5A retest ({retest_result_msg}). Unaddressed paths: {remaining_risk}."
                rec_change = plan_remediation or "Refactor remaining dynamic SQL statements to use parameterized placeholders with argument tuples."
            else:
                problem = "Potential SQL Injection vulnerability due to dynamic query string formatting (RED-SQL-01)."
                cur_impl = "SQL queries are assembled dynamically via string formatting or f-strings."
                rec_change = plan_remediation or "Refactor all database queries to use parameterized placeholders (? for SQLite, %s for PostgreSQL/MySQL) with parameter tuples."

            trade_offs = "Requires driver-specific placeholder syntax (? vs %s). Allowlist updates needed if dynamic table/column identifiers are required."
            if reg_risks:
                trade_offs += f" Regression consideration: {'; '.join(reg_risks[:2])}."

            return {
                "problem": problem,
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": cur_impl,
                "recommended_change": rec_change,
                "technical_reasoning": root_cause or (
                    "Prepared statements instruct the database driver to compile SQL query structure separately from parameters, "
                    "ensuring user inputs are treated strictly as data literals rather than executable SQL syntax."
                ),
                "alternatives": "Deploy an external Web Application Firewall (WAF) or ORM abstraction. Trade-off: WAFs inspect inputs heuristically but do not resolve underlying code vulnerabilities and risk false-positive rejections.",
                "trade_offs": trade_offs,
                "implementation_complexity": "LOW (updating SQL call sites to pass query tuples).",
                "security_impact": (
                    "Risk reduction: Substantially mitigates SQL injection vulnerabilities across refactored database queries by ensuring user inputs cannot alter query logic. "
                    "Assumptions & Residual Risks: Assumes dynamic query construction uses parameter placeholders throughout; dynamic SQL identifiers (table or column names) cannot be parameterized and require strict allowlisting. "
                    "Persisted values must not be concatenated into dynamic queries downstream (second-order injection)."
                ),
                "maintainability_impact": "Significantly clarifies query parameters and enables database query plan caching.",
                "cost_considerations": "Zero financial or infrastructure cost; purely standard database library usage.",
                "dependencies": "Standard library or existing DB driver (sqlite3, psycopg2, sqlalchemy).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 2. Hardcoded Secrets (RED-SECRET-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-SECRET-01":
            if is_remediated:
                problem = "Maintain externalized environment configuration and credential rotation procedures (RED-SECRET-01)."
                cur_impl = f"Phase 5A retest confirmed sensitive credentials have been removed from source files ({retest_result_msg})."
                rec_change = "Retain environment variable loading (os.environ) and ensure automated repository pre-commit hooks block future secret commits."
            elif is_partial:
                problem = f"Complete credential externalization; partial credential isolation detected (RED-SECRET-01). Residual risk: {remaining_risk}."
                cur_impl = f"Partial credential extraction verified in Phase 5A ({retest_result_msg})."
                rec_change = "Extract remaining hardcoded keys into environment variables and immediately rotate historically committed credentials."
            else:
                problem = "Hardcoded cryptographic secret key, API token, or password committed to version control (RED-SECRET-01)."
                cur_impl = "Cryptographic secrets are hardcoded directly into application source files."
                rec_change = plan_remediation or "Externalize all credentials into environment variables (os.environ or python-dotenv) and rotate exposed keys immediately."

            return {
                "problem": problem,
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": cur_impl,
                "recommended_change": rec_change,
                "technical_reasoning": root_cause or (
                    "Secrets stored directly in source code risk exposure through version control history, developer workstations, and code review platforms, "
                    "potentially allowing unauthorized actors to forge tokens or access protected services."
                ),
                "alternatives": "Store credentials in encrypted vault files with KMS keys. Trade-off: increases operational complexity compared to standard environment variables.",
                "trade_offs": "Requires operators and developers to configure local environment files before launching.",
                "implementation_complexity": "LOW (extracting strings to os.environ.get('SECRET_KEY')).",
                "security_impact": (
                    "Risk reduction: Prevents plaintext credential exposure within version-controlled source files. "
                    "Assumptions & Residual Risks: Historically committed credentials must be invalidated and rotated immediately, as git history preserves past commits. "
                    "Deployment host environment variables must be protected with appropriate system access permissions."
                ),
                "maintainability_impact": "Enables seamless environment configuration across local development, staging, and production.",
                "cost_considerations": "Zero cost; relies on built-in os.environ or standard dotenv tooling.",
                "dependencies": "Standard library (os.environ) or python-dotenv.",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 3. Archive Decompression Bombs / DoS (RED-DOS-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-DOS-01":
            rel_perf = p7_by_rel_id.get("REL-SEC-PERF-01")
            perf_tradeoff_note = ""
            if rel_perf:
                phase_sources.append("Phase 7")
                perf_tradeoff_note = " Cross-Domain Trade-off (REL-SEC-PERF-01): Pre-scan loops across archive entries introduce computational processing latency; calibrate entry size thresholds (e.g. 200MB) to balance denial-of-service defense against ingestion throughput."

            if is_remediated:
                problem = "Maintain verified pre-extraction quota enforcement to guard against archive decompression bombs (RED-DOS-01)."
                cur_impl = f"Phase 5A retest verified pre-extraction quotas: {retest_result_msg}."
                rec_change = "Retain pre-extraction inspection checks (cumulative uncompressed size and member count limits) as an essential defensive gate."
            elif is_partial:
                problem = f"Complete pre-extraction archive quota controls; partial inspection leaves unverified ceilings (RED-DOS-01). Residual risk: {remaining_risk}."
                cur_impl = f"Phase 5A retest indicated partial quota enforcement ({retest_result_msg})."
                rec_change = "Enforce both cumulative uncompressed byte ceilings (e.g., 200MB) and member count caps (e.g., 5000) prior to archive extraction."
            elif is_conflicted:
                problem = "Resolve conflicting evidence regarding archive decompression quota enforcement (RED-DOS-01)."
                cur_impl = "Phase 5A retest reported REMEDIATED, but repository source code inspection detected unshielded extraction calls."
                rec_change = "Conduct immediate manual code verification and implement strict pre-extraction quota loops in extraction routines."
            else:
                problem = "Uncontrolled resource consumption via archive decompression bombs (Zip Bombs) (RED-DOS-01)."
                cur_impl = "Archive is extracted without pre-scanning member sizes."
                rec_change = plan_remediation or "Pre-scan archive members before extraction: enforce cumulative uncompressed size limits (e.g. 200MB) and compression ratio checks (100:1)."

            return {
                "problem": problem,
                "evidence": evidence_summary,
                "requirement_affected": self._resolve_requirement(req_id, "quota"),
                "current_implementation": cur_impl,
                "recommended_change": rec_change,
                "technical_reasoning": root_cause or (
                    "Decompression bombs (Zip Bombs) expand small archives into hundreds of gigabytes, "
                    "potentially exhausting host disk space, memory, or filesystem inodes during extraction."
                ),
                "alternatives": "Use isolated ramdisks or ephemeral sandboxes for extraction. Trade-off: complex operational setup.",
                "trade_offs": f"Extremely large legitimate archives will require administrator quota configuration.{perf_tradeoff_note}",
                "implementation_complexity": "LOW (iterating zip infolist before extractall).",
                "security_impact": (
                    "Risk reduction: Protects host storage and filesystem inode capacity by enforcing pre-extraction thresholds on cumulative uncompressed byte volume and byte ceilings. "
                    "Assumptions & Residual Risks: Configured quota thresholds (e.g., 200MB, 5000 entries) must accommodate legitimate archives. "
                    "Ingestion still incurs CPU processing overhead during archive directory traversal, which should be bounded with execution timeouts."
                ),
                "maintainability_impact": "Adds robust validation to ingestion pipeline.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Standard library (zipfile).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 4. Debug Configuration (RED-DEBUG-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-DEBUG-01":
            return {
                "problem": "Debug mode enabled in server runtime configuration exposing interactive debugger console (RED-DEBUG-01)." if not is_remediated else "Maintain production runtime configuration with debug mode disabled (RED-DEBUG-01).",
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Application startup explicitly specifies debug=True.",
                "recommended_change": "Gate debug mode behind an environment variable (debug=os.environ.get('FLASK_DEBUG') == '1') and run behind a production WSGI server (Gunicorn or Waitress).",
                "technical_reasoning": root_cause or (
                    "Debug consoles and verbose error handlers expose internal stack traces and interactive execution terminals (e.g. Werkzeug PIN consoles) on network interfaces, "
                    "enabling runtime inspection and potential arbitrary code execution."
                ),
                "alternatives": "Rely on reverse-proxy IP restrictions. Trade-off: fragile defense if reverse proxy rules misconfigure.",
                "trade_offs": "Developers must explicitly set FLASK_DEBUG=1 when developing locally.",
                "implementation_complexity": "LOW (single configuration flag update).",
                "security_impact": (
                    "Risk reduction: Disables interactive web debugger consoles and reduces verbose stack trace exposure to external clients. "
                    "Assumptions & Residual Risks: Application error handlers must still ensure unhandled exceptions do not leak internal diagnostic details in JSON error responses. "
                    "Production WSGI/ASGI servers (e.g., Gunicorn or Waitress) should manage worker processes."
                ),
                "maintainability_impact": "Establishes clean separation between development and production configurations.",
                "cost_considerations": "Zero cost.",
                "dependencies": "None.",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 5. Command Injection (RED-CMD-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-CMD-01":
            return {
                "problem": "Arbitrary command execution risk via shell invocation with user-supplied arguments (RED-CMD-01)." if not is_remediated else "Maintain safe tokenized subprocess execution without shell interpretation (RED-CMD-01).",
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Subprocess execution passes commands through the system shell interpreter.",
                "recommended_change": plan_remediation or "Pass arguments as tokenized argument lists (subprocess.run(['cmd', arg1], shell=False)) and validate all input parameters.",
                "technical_reasoning": root_cause or (
                    "Executing subprocesses through a shell interpreter (shell=True) causes the shell to evaluate metacharacters (; | & `), "
                    "enabling arbitrary chained commands. Passing arguments as a discrete tokenized list directly to the executable bypasses shell command interpretation."
                ),
                "alternatives": "Escape shell parameters with shlex.quote(). Trade-off: direct list execution without a shell is safer and immune to parser quirks.",
                "trade_offs": "Shell pipeline syntax must be rewritten using standard library pipes.",
                "implementation_complexity": "LOW (converting command strings to string arrays).",
                "security_impact": (
                    "Risk reduction: Prevents shell metacharacter command chaining by executing binaries directly without shell invocation (shell=False). "
                    "Assumptions & Residual Risks: Assumes the invoked executable does not itself parse arguments as internal subcommands or shell scripts; "
                    "user inputs must still be validated to prevent argument/option injection (e.g., inputs starting with hyphens modifying CLI behavior)."
                ),
                "maintainability_impact": "Simplifies debugging and avoids platform-specific shell interpreter variations.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Standard library (subprocess).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 6. Insecure Deserialization (RED-DESER-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-DESER-01":
            return {
                "problem": "Insecure object deserialization via unverified joblib/pickle machine learning model loading (RED-DESER-01)." if not is_remediated else "Maintain cryptographic integrity verification for serialized model loading (RED-DESER-01).",
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Model files are deserialized directly from disk using joblib.load() without integrity verification.",
                "recommended_change": plan_remediation or "Enforce cryptographic SHA-256 HMAC signature verification prior to loading model files, restrict model directory write permissions, or migrate to safe serialization formats (ONNX/Safetensors).",
                "technical_reasoning": root_cause or (
                    "Standard Python serialization protocols (pickle/joblib) execute arbitrary object constructors and reducers (__reduce__) during deserialization, "
                    "creating arbitrary code execution risks if model files are modified or supplied by untrusted parties."
                ),
                "alternatives": "Host model execution inside an isolated worker container. Trade-off: introduces container orchestration overhead.",
                "trade_offs": "Model checksums or signatures must be recorded and updated whenever models are retrained.",
                "implementation_complexity": "MEDIUM (computing and verifying SHA-256 HMAC signature prior to loading).",
                "security_impact": (
                    "Risk reduction: Verifying cryptographic HMAC signatures prior to deserialization detects tampering and prevents loading unverified model files. "
                    "Assumptions & Residual Risks: Assumes HMAC secret keys and signing certificates are kept confidential; if model files originate from untrusted external sources, "
                    "migrating to non-executable serialization formats (e.g., Safetensors, ONNX) is strongly recommended as pickle cannot be safely sandboxed."
                ),
                "maintainability_impact": "Promotes reproducible and integrity-verified model deployment pipelines.",
                "cost_considerations": "Zero cost; relies on standard library hashlib.",
                "dependencies": "Standard library (hashlib, hmac).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 7. Permissive CORS (RED-CORS-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-CORS-01":
            return {
                "problem": "Overly permissive CORS policy allows arbitrary wildcard origins ('*') (RED-CORS-01)." if not is_remediated else "Maintain explicit frontend origin whitelisting in CORS policies (RED-CORS-01).",
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "CORS configuration specifies origins='*' without domain restriction.",
                "recommended_change": plan_remediation or "Replace wildcard origin with an explicit whitelist of approved frontend client URLs configured via environment variables.",
                "technical_reasoning": root_cause or (
                    "Wildcard CORS configurations ('*') allow any third-party web origin loaded in a user's browser to send requests and read API responses across origins, "
                    "bypassing browser same-origin policy isolation."
                ),
                "alternatives": "Serve frontend and backend from identical domains using reverse proxies. Trade-off: avoids CORS entirely but requires combined routing setup.",
                "trade_offs": "New client domains must be explicitly added to configuration before accessing APIs.",
                "implementation_complexity": "LOW (updating CORS origins argument).",
                "security_impact": (
                    "Risk reduction: Restricts browser-mediated cross-origin API read access to designated, trusted frontend client domains. "
                    "Assumptions & Residual Risks: CORS is enforced solely by web browsers; it does not prevent direct HTTP requests from non-browser clients (such as curl or automated scripts), "
                    "which must be authenticated independently via tokens or session credentials."
                ),
                "maintainability_impact": "Provides centralized visibility into approved API consumers.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Existing CORS library (flask-cors).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 8. Git Option/Command Injection (RED-INJ-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-INJ-01":
            return {
                "problem": "Potential command or option injection during Git repository cloning via user-controlled URIs (RED-INJ-01)." if not is_remediated else "Maintain strict URI protocol parsing and positional argument delimiters for Git execution (RED-INJ-01).",
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Source parameter is passed without option boundary delimiter.",
                "recommended_change": plan_remediation or "Enforce strict protocol scheme parsing: validate permitted URI schemes ('https://', 'http://', 'git@') and insert the '--' positional separator.",
                "technical_reasoning": root_cause or (
                    "User-supplied repository URIs starting with hyphens or non-standard protocol schemes can be interpreted by git clone as command-line flags (e.g. --upload-pack) "
                    "or invoke external protocol helpers, enabling argument injection or unexpected program execution."
                ),
                "alternatives": "Execute git clone inside ephemeral sandboxes. Trade-off: introduces external container runtime requirements.",
                "trade_offs": "Blocks non-standard file:// URLs unless explicitly allowed.",
                "implementation_complexity": "LOW (adding input validation and delimiter in git clone command).",
                "security_impact": (
                    "Risk reduction: Restricting URI schemes to approved protocols (https://, git@) and inserting the positional argument delimiter (--) prevents user inputs from being interpreted as CLI option flags. "
                    "Assumptions & Residual Risks: Repository operations must enforce network timeouts and disk storage quotas to prevent denial-of-service during large or slow repository clones."
                ),
                "maintainability_impact": "Consolidates URI parsing into a predictable routine.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Standard library (urllib.parse).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 9. Cryptographic Weaknesses (RED-CRYPTO-01)
        # ---------------------------------------------------------------------
        elif fid == "RED-CRYPTO-01":
            return {
                "problem": "Use of deprecated MD5/SHA1 cryptographic hash algorithm vulnerable to collisions (RED-CRYPTO-01)." if not is_remediated else "Maintain modern SHA-256 cryptographic hashing standards (RED-CRYPTO-01).",
                "evidence": evidence_summary,
                "requirement_affected": req_id,
                "current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Legacy hash functions are invoked for data hashing.",
                "recommended_change": plan_remediation or "Upgrade to SHA-256 (hashlib.sha256) for data integrity or salted bcrypt/Argon2 for password hashing.",
                "technical_reasoning": root_cause or (
                    "Legacy hash functions such as MD5 and SHA-1 have known theoretical and practical collision vulnerabilities, "
                    "making them unsuitable for integrity verification, digital signatures, or security tokens."
                ),
                "alternatives": "Retain MD5 solely for non-cryptographic cache key generation. Trade-off: risks confusion with security hashes.",
                "trade_offs": "SHA-256 produces longer digest strings (64 hex characters vs 32 for MD5).",
                "implementation_complexity": "LOW (replacing hashlib.md5 with hashlib.sha256).",
                "security_impact": (
                    "Risk reduction: Migrating to SHA-256 provides strong collision resistance for cryptographic checksums, data integrity validation, and message authentication. "
                    "Assumptions & Residual Risks: For user password storage or secret derivation, salted memory-hard key-derivation functions (e.g., Argon2id or bcrypt) must be used "
                    "rather than general-purpose fast cryptographic hashes like SHA-256."
                ),
                "maintainability_impact": "Brings cryptographic implementations into compliance with modern standards.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Standard library (hashlib).",
                "priority": priority,
                "confidence": confidence,
                "finding_id": fid,
                "remediation_status": retest_status,
                "phase_sources": phase_sources,
            }

        # ---------------------------------------------------------------------
        # 10. Dynamic Fallback for Arbitrary / Custom Security Findings
        # ---------------------------------------------------------------------
        is_empty_id = finding.get("is_empty_id", False)
        if unmapped_findings is not None and not is_empty_id:
            unmapped_findings.append({
                "source_phase": "Phase 3A",
                "finding_id": fid,
                "title": title,
                "status": "UNMAPPED_FINDING_ID",
                "reason": "Finding ID is not in the recognized security taxonomy; preserved without automated template invention.",
                "has_upstream_remediation": bool(plan_remediation),
                "affected_files": files_str.split(", ") if files_str else [],
                "evidence": raw_evidence,
            })

        if plan_remediation:
            rec_change = plan_remediation
            if plan_changes:
                rec_change = f"{rec_change} Details: {'; '.join(plan_changes)}."
            tech_reasoning = root_cause or finding.get("impact") or "Targeted defensive controls from upstream Blue Team remediation plan address the identified component flaw."
            alternatives = "Implement perimeter network controls or manual review gates."
        else:
            rec_change = (
                f"Conduct manual security review and dynamic verification for {fid} ({title}) to determine targeted architectural remediation, "
                f"as no automated remediation plan was provided by upstream phases."
            )
            tech_reasoning = root_cause or finding.get("impact") or (
                f"Finding '{fid}' ({title}) does not match standard automated remediation patterns and lacks an upstream Blue Team remediation plan. "
                f"Defensive implementation requires manual code inspection."
            )
            alternatives = "Apply defense-in-depth architectural safeguards or isolate the affected component."

        sec_impact_base = finding.get("impact") or "Reduces attack surface across identified components."
        return {
            "problem": f"{title} ({fid})" if not is_remediated else f"Maintain verified remediation for {title} ({fid}).",
            "evidence": evidence_summary,
            "requirement_affected": req_id,
            "current_implementation": f"Phase 5A retest status: {retest_status} ({retest_result_msg})" if p5a_res else "Current code constructs match security finding criteria.",
            "recommended_change": rec_change,
            "technical_reasoning": tech_reasoning,
            "alternatives": alternatives,
            "trade_offs": "; ".join(reg_risks) if reg_risks else "Requires code testing across affected components.",
            "implementation_complexity": "MEDIUM",
            "security_impact": (
                f"Risk reduction: {sec_impact_base} "
                "Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; "
                "verification via automated tests is required to confirm fix efficacy."
            ),
            "maintainability_impact": "Aligns implementation with security baseline standards.",
            "cost_considerations": "Zero financial cost; engineering refactoring effort.",
            "dependencies": "Standard library.",
            "priority": priority,
            "confidence": confidence,
            "finding_id": fid,
            "remediation_status": retest_status,
            "phase_sources": phase_sources,
        }

    # -------------------------------------------------------------------------
    # Code Smell Recommendation Builder (Phase 6 + Phase 7)
    # -------------------------------------------------------------------------

    def _build_smell_recommendations(
        self,
        p7_by_rel_id: Dict[str, Dict[str, Any]],
        unmapped_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Synthesizes recommendations from Phase 6 code smells enriched by Phase 7 cross-domain facts.

        Processes every valid distinct smell rather than only the first match per category.
        Deduplicates using stable issue identity and evidence: (smell_id, file, function_or_class, line, evidence).
        """
        recs: List[Dict[str, Any]] = []
        seen_smell_identities: Set[Tuple[str, str, str, str, str]] = set()

        for smell in self.p6_smells:
            if not isinstance(smell, dict):
                continue

            smell_id = str(smell.get("smell_id", "")).strip().upper()
            file_path = str(smell.get("file", "")).strip()
            func_or_class = str(smell.get("function_or_class", "")).strip()
            line = str(smell.get("line", "")).strip()
            evidence = str(smell.get("evidence", "")).strip()
            category = str(smell.get("category", "")).strip()
            explanation = str(smell.get("explanation", "")).strip()

            # Empty record check
            if not smell_id and not file_path and not func_or_class and not evidence and not category:
                if unmapped_findings is not None:
                    unmapped_findings.append({
                        "source_phase": "Phase 6",
                        "status": "EMPTY_RECORD",
                        "reason": "Code smell dictionary has no smell_id, file, function, evidence, or category.",
                        "record": smell
                    })
                continue

            # Deduplication key based on stable issue identity and evidence
            smell_key = (smell_id, file_path, func_or_class, line, evidence)
            if smell_key in seen_smell_identities:
                continue
            seen_smell_identities.add(smell_key)

            is_silent = (
                "SILENT" in smell_id
                or category.lower() in ("poor exception handling", "poor exception handling / silent exceptions", "broad exception clause")
                or "silent" in explanation.lower()
                or ("pass" in evidence.lower() and "except" in evidence.lower())
            )

            is_structural = (
                category in ("Deep Nesting", "Long Method", "God Class / Large Class", "God Class", "High Cyclomatic Complexity")
                or smell.get("classification") == "PROBLEMATIC"
                or "COMPLEX" in smell_id
                or "NEST" in smell_id
                or "LONG-METHOD" in smell_id
            )

            target_name = func_or_class or file_path or ("function" if is_structural else "routine")
            is_traversal = any(w in target_name.lower() for w in ("traversal", "walk", "search", "discover", "scan")) if is_structural else False
            scale_rel_not_yet_used = not any("REL-SMELL-SCALE-01" in r.get("problem", "") for r in recs)
            is_scale_candidate = is_traversal or scale_rel_not_yet_used

            priority = self._derive_smell_priority(
                smell=smell,
                is_silent=is_silent,
                is_structural=is_structural,
                rel_sec=p7_by_rel_id.get("REL-SMELL-SEC-01"),
                rel_scale=p7_by_rel_id.get("REL-SMELL-SCALE-01"),
                is_scale_candidate=is_scale_candidate,
            )
            confidence = self._derive_smell_confidence(smell)

            if is_silent:
                rel_sec = p7_by_rel_id.get("REL-SMELL-SEC-01")
                sec_impact = (
                    "Risk reduction: Restores diagnostic observability and audit logging for abnormal runtime conditions. "
                    "Assumptions & Residual Risks: Logged messages must be sanitized to ensure sensitive data (passwords, tokens, PII) is not written to application logs."
                )
                tech_reasoning = (
                    "Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures "
                    "(such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage."
                )
                phase_sources = ["Phase 6"]

                if rel_sec:
                    phase_sources.append("Phase 7")
                    sec_impact = (
                        "Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly "
                        "impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. "
                        "Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens."
                    )
                    tech_reasoning = f"{tech_reasoning} Cross-domain consequence: {rel_sec.get('consequence', '')}"

                problem_msg = (
                    f"Silent exception suppression in '{func_or_class}' masks runtime failures and impedes diagnostic visibility."
                    if func_or_class
                    else "Silent exception suppression (except Exception: pass) masks runtime failures and impedes diagnostic visibility."
                )
                evidence_msg = (
                    f"File {file_path or 'source'} in '{func_or_class or 'method'}': {evidence or 'except Exception: pass'}"
                )

                recs.append({
                    "problem": problem_msg,
                    "evidence": evidence_msg,
                    "requirement_affected": self._resolve_requirement(category_hint="observability"),
                    "current_implementation": "Broad except clauses catch all exceptions and execute 'pass' without recording error details.",
                    "recommended_change": smell.get("refactoring_strategy") or "Replace silent 'pass' blocks with specific exception types (e.g., (OSError, ValueError)) and log diagnostic messages using standard logging (logger.debug / logger.warning).",
                    "technical_reasoning": tech_reasoning,
                    "alternatives": "Let exceptions crash the process immediately. Trade-off: halts application on recoverable errors.",
                    "trade_offs": "Negligible I/O overhead when debug logging is enabled.",
                    "implementation_complexity": "LOW (updating exception clauses to log diagnostics).",
                    "security_impact": sec_impact,
                    "maintainability_impact": "Dramatically shortens developer troubleshooting time.",
                    "cost_considerations": "Zero cost; relies on built-in logging module.",
                    "dependencies": "Standard library (logging).",
                    "priority": priority,
                    "confidence": confidence,
                    "finding_id": smell_id or f"SMELL-SILENT-{len(recs)+1:02d}",
                    "affected_files": [file_path] if file_path else [],
                    "phase_sources": phase_sources,
                })

            elif is_structural:
                rel_scale = p7_by_rel_id.get("REL-SMELL-SCALE-01")
                problem = f"High structural complexity and maintainability hazards in '{target_name}'."
                trade_offs = "Requires creating small helper functions; zero impact on public API behavior."
                phase_sources = ["Phase 6"]

                if rel_scale and is_scale_candidate:
                    phase_sources.append("Phase 7")
                    problem = (
                        f"High structural complexity in repository traversal '{target_name}' "
                        "poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01)."
                    )
                    trade_offs = (
                        "Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core "
                        "parallelism, while requiring modular extraction of filtering logic."
                    )
                else:
                    problem = f"High cyclomatic complexity and deep nesting in '{target_name}' hinders code maintainability."

                recs.append({
                    "problem": problem,
                    "evidence": f"File {file_path or 'source'} in '{target_name}': {evidence or 'high cyclomatic complexity'}",
                    "requirement_affected": self._resolve_requirement(category_hint="maintainability"),
                    "current_implementation": explanation or "Large monolithic routine with multi-level nested conditionals and loops.",
                    "recommended_change": smell.get("refactoring_strategy") or "Decompose large routines using Extract Method and early guard clauses to flatten nesting to a linear flow.",
                    "technical_reasoning": explanation or "Deeply nested control structures and monolithic functions increase cyclomatic complexity, making unit testing difficult and introducing edge-case bugs.",
                    "alternatives": "Keep code monolithic with extensive comments. Trade-off: comments quickly become outdated while cognitive debt remains.",
                    "trade_offs": trade_offs,
                    "implementation_complexity": "MEDIUM (extracting logic into 2-3 focused helper functions).",
                    "security_impact": (
                        "Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow."
                    ),
                    "maintainability_impact": smell.get("maintenance_impact") or "Significantly simplifies unit test coverage and code readability.",
                    "cost_considerations": "Zero cost.",
                    "dependencies": "None.",
                    "priority": priority,
                    "confidence": confidence,
                    "finding_id": smell_id or f"SMELL-COMPLEX-{len(recs)+1:02d}",
                    "affected_files": [file_path] if file_path else [],
                    "phase_sources": phase_sources,
                })

            else:
                # Other valid clean code smells (e.g. Dangerous Default Value, Dead Code, Global State Mutation, Long Parameter List, etc.)
                recs.append({
                    "problem": f"Code smell ({category or 'Quality Defect'}) detected in '{target_name}'.",
                    "evidence": f"File {file_path or 'source'} in '{target_name}': {evidence or 'code smell construct'}",
                    "requirement_affected": self._resolve_requirement(category_hint="maintainability"),
                    "current_implementation": explanation or f"Implementation exhibits {category or 'code maintainability smell'}.",
                    "recommended_change": smell.get("refactoring_strategy") or f"Refactor '{target_name}' to address {category or 'maintainability smell'}.",
                    "technical_reasoning": explanation or "Eliminating code smells prevents technical debt accumulation, reduces bug density, and enhances long-term maintainability.",
                    "alternatives": "Document current implementation quirks in code comments. Trade-off: does not eliminate technical debt.",
                    "trade_offs": "Requires testing across affected routines to confirm zero functional regressions.",
                    "implementation_complexity": "LOW (targeted refactoring).",
                    "security_impact": (
                        "Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability."
                    ),
                    "maintainability_impact": smell.get("maintenance_impact") or smell.get("expected_benefit") or "Improves readability, modularity, and testability.",
                    "cost_considerations": "Zero cost.",
                    "dependencies": "None.",
                    "priority": priority,
                    "confidence": confidence,
                    "finding_id": smell_id or f"SMELL-{len(recs)+1:02d}",
                    "affected_files": [file_path] if file_path else [],
                    "phase_sources": ["Phase 6"],
                })

        return recs

    # -------------------------------------------------------------------------
    # Cross-Domain Architectural Recommendations (Phase 7 Standalone Relationships)
    # -------------------------------------------------------------------------

    def _build_cross_domain_recommendations(
        self,
        p7_by_rel_id: Dict[str, Dict[str, Any]],
        seen_fids: Set[str],
        unmapped_findings: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Constructs dedicated architectural recommendations for distinct Phase 7 cross-domain findings."""
        recs: List[Dict[str, Any]] = []

        recognized_rel_ids = {
            "REL-ARCH-SEC-01", "REL-ARCH-MAINT-01", "REL-SEC-MAINT-01",
            "REL-SMELL-SEC-01", "REL-SEC-PERF-01", "REL-SMELL-SCALE-01"
        }
        if unmapped_findings is not None:
            for rel in self.p7_relationships:
                rid = str(rel.get("relationship_id", "")).strip().upper()
                if not rid:
                    unmapped_findings.append({
                        "source_phase": "Phase 7",
                        "status": "EMPTY_RELATIONSHIP_ID",
                        "reason": "Relationship record missing relationship_id.",
                        "record": rel
                    })
                elif rid not in recognized_rel_ids:
                    unmapped_findings.append({
                        "source_phase": "Phase 7",
                        "relationship_id": rid,
                        "status": "UNMAPPED_RELATIONSHIP_ID",
                        "reason": f"Relationship ID '{rid}' is not in the recognized Phase 7 cross-domain taxonomy.",
                        "record": rel
                    })

        # REL-ARCH-SEC-01: Zero External Dependencies vs In-House Security Parsers
        rel_arch_sec = p7_by_rel_id.get("REL-ARCH-SEC-01")
        if rel_arch_sec and "REL-ARCH-SEC-01" not in seen_fids:
            seen_fids.add("REL-ARCH-SEC-01")
            recs.append({
                "problem": "Zero-dependency architecture avoids third-party package vulnerabilities but shifts security parsing and boundary validation responsibilities entirely to internal code (REL-ARCH-SEC-01).",
                "evidence": rel_arch_sec.get("evidence", "Requirement mandates standard library only without external packages."),
                "requirement_affected": self._resolve_requirement(category_hint="dependency"),
                "current_implementation": "All URI parsing, archive handling, and cryptographic routines rely strictly on standard library modules.",
                "recommended_change": rel_arch_sec.get("recommended_action") or "Maintain zero-dependency constraint backed by rigorous automated unit test harnesses and static analysis for custom parsing logic.",
                "technical_reasoning": rel_arch_sec.get("consequence") or "Relying strictly on the standard library avoids third-party supply-chain package risks but requires internal code to defend against edge cases.",
                "alternatives": "Adopt established third-party parsing libraries (e.g., urllib3, defusedxml). Trade-off: violates zero-dependency policy.",
                "trade_offs": "Requires dedicated in-house unit testing for boundary condition parsing.",
                "implementation_complexity": "LOW (authoring unit test suites for existing custom parsers).",
                "security_impact": (
                    "Risk reduction: Avoids third-party dependency supply-chain attack vectors. "
                    "Assumptions & Residual Risks: Internal parsing logic (URI validation, archive extraction) must be supported by comprehensive unit test harnesses "
                    "and edge-case testing to match the robustness of mature external libraries."
                ),
                "maintainability_impact": "Zero external dependency management overhead; stable runtime across all platforms.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Python standard library.",
                "priority": "HIGH",
                "confidence": self._derive_rel_confidence(rel_arch_sec),
                "finding_id": "REL-ARCH-SEC-01",
                "phase_sources": ["Phase 7", "Phase 2"],
            })

        # REL-ARCH-MAINT-01: Untyped Dictionary Contracts across Phase Boundaries
        rel_arch_maint = p7_by_rel_id.get("REL-ARCH-MAINT-01")
        if rel_arch_maint and "REL-ARCH-MAINT-01" not in seen_fids:
            seen_fids.add("REL-ARCH-MAINT-01")
            recs.append({
                "problem": "Untyped dictionary contracts across pipeline phase boundaries increase interface coupling and runtime schema drift risks (REL-ARCH-MAINT-01).",
                "evidence": rel_arch_maint.get("evidence", "Phase contract boundaries pass unstructured dictionaries."),
                "requirement_affected": self._resolve_requirement(category_hint="maintainability"),
                "current_implementation": "Inter-phase component data exchange utilizes raw Python dictionaries without static type enforcement.",
                "recommended_change": rel_arch_maint.get("recommended_action") or "Formalize inter-phase data exchange contracts using TypedDict or dataclass schemas to enforce static type safety across pipeline interfaces.",
                "technical_reasoning": rel_arch_maint.get("consequence") or "Raw untyped dictionaries lack static schema validation, increasing maintenance friction and unhandled KeyError risks during schema evolution.",
                "alternatives": "Rely on runtime assertion checks. Trade-off: catches errors only during execution rather than static type check time.",
                "trade_offs": "Requires authoring TypedDict definitions for core phase exchange data structures.",
                "implementation_complexity": "MEDIUM (defining TypedDict schemas in a common contract module).",
                "security_impact": (
                    "Risk reduction: Reduces data corruption and unhandled schema drift across pipeline phase boundaries by introducing typed data structures (TypedDict or dataclasses). "
                    "Assumptions & Residual Risks: Runtime validation remains necessary when parsing external or untrusted JSON inputs."
                ),
                "maintainability_impact": "Enables IDE autocomplete, static type checking (mypy), and clear architectural boundaries.",
                "cost_considerations": "Zero cost.",
                "dependencies": "Standard library (typing.TypedDict).",
                "priority": "HIGH",
                "confidence": self._derive_rel_confidence(rel_arch_maint),
                "finding_id": "REL-ARCH-MAINT-01",
                "phase_sources": ["Phase 7", "Phase 6"],
            })

        # REL-SEC-MAINT-01: Duplicate CLI Output Sanitization
        rel_sec_maint = p7_by_rel_id.get("REL-SEC-MAINT-01")
        if rel_sec_maint and "REL-SEC-MAINT-01" not in seen_fids:
            seen_fids.add("REL-SEC-MAINT-01")
            recs.append({
                "problem": "Duplicated CLI output sanitization and stream reconfiguration risks divergent security posture across entry points (REL-SEC-MAINT-01).",
                "evidence": rel_sec_maint.get("evidence", "CLI output sanitization logic duplicated across multiple entry points."),
                "requirement_affected": self._resolve_requirement(category_hint="security"),
                "current_implementation": "Output stream encoding and path sanitization helpers are copy-pasted across CLI entry points.",
                "recommended_change": rel_sec_maint.get("recommended_action") or "Consolidate duplicated CLI output sanitization and stream reconfiguration into a shared utility module.",
                "technical_reasoning": rel_sec_maint.get("consequence") or "Duplicated sanitization logic risks divergent updates where security checks applied in one entry point may be overlooked in another.",
                "alternatives": "Keep individual CLI entry points self-contained. Trade-off: increases risk of security drift.",
                "trade_offs": "Requires creating a shared cli_utils module.",
                "implementation_complexity": "LOW (extracting helper function to shared utility).",
                "security_impact": (
                    "Risk reduction: Promotes uniform output sanitization and reduces divergence in terminal escape sequence filtering across CLI entry points by centralizing utility routines. "
                    "Assumptions & Residual Risks: All current and future CLI entry points must consistently import and route output through the shared utility."
                ),
                "maintainability_impact": "Reduces duplicate code and centralizes stream reconfiguration logic.",
                "cost_considerations": "Zero cost.",
                "dependencies": "None.",
                "priority": "HIGH",
                "confidence": self._derive_rel_confidence(rel_sec_maint),
                "finding_id": "REL-SEC-MAINT-01",
                "phase_sources": ["Phase 7", "Phase 6"],
            })

        return recs

    # -------------------------------------------------------------------------
    # Baseline Fallback Recommendations (Proactive, Proportionate Guidance)
    # -------------------------------------------------------------------------

    def _build_baseline_recommendations(self, p1_ctx: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Provides defensible, proactive baseline architectural guidance without claiming repository defects."""
        p1 = p1_ctx or {}
        app_type = p1.get("app_type") or "application"
        frameworks = p1.get("frameworks") or []
        fw_desc = f" ({', '.join(frameworks)})" if frameworks else ""

        baselines: List[Dict[str, Any]] = [
            {
                "problem": "Proactive general guidance: Centralize application configuration and operational parameters across environments (BASE-CONFIG-01).",
                "evidence": f"Proactive architectural baseline relevant to {app_type}{fw_desc}; general engineering guidance independent of confirmed repository defects.",
                "requirement_affected": self._resolve_requirement(category_hint="maintainability"),
                "current_implementation": "General architecture guidance: No specific configuration defect was verified in scanned repository files. Verify runtime parameters use centralized environment variables.",
                "recommended_change": "Consolidate configurable runtime options and operational flags into a central settings module reading from environment variables with safe defaults.",
                "technical_reasoning": (
                    f"Centralized configuration management adheres to Twelve-Factor App principles and is relevant to {app_type} architectures, "
                    "ensuring operational parameters and service credentials remain decoupled from application source code."
                ),
                "alternatives": "Use command-line flags exclusively. Trade-off: cumbersome in containerized or serverless environments.",
                "trade_offs": "Requires defining a central config dictionary or dataclass.",
                "implementation_complexity": "LOW (moving constants to a config.py module).",
                "security_impact": (
                    "Risk reduction: Proactively reduces the likelihood of accidental credential leakage in version control and simplifies multi-environment deployment. "
                    "Assumptions & Residual Risks: Operational environment variables must be secured on hosting systems."
                ),
                "maintainability_impact": "Single source of truth for all configurable thresholds.",
                "cost_considerations": "Zero cost; standard library os.environ.",
                "dependencies": "Standard library (os.environ).",
                "priority": "LOW",
                "confidence": "HIGH",
                "finding_id": "BASE-CONFIG-01",
                "phase_sources": ["Baseline Guidance"],
            },
            {
                "problem": "Proactive general guidance: Maintain automated test harnesses to prevent functional and security regressions (BASE-TESTING-01).",
                "evidence": f"Proactive software quality baseline relevant to {app_type}; automated regression guards support ongoing refactoring independently of specific defects.",
                "requirement_affected": self._resolve_requirement(category_hint="maintainability"),
                "current_implementation": "General quality guidance: No specific test regression was verified in scanned repository files. Automated assertion coverage should guard core workflows.",
                "recommended_change": "Implement standard automated unit and integration tests using Python's standard unittest or pytest framework.",
                "technical_reasoning": (
                    f"Automated regression test suites ensure ongoing refactoring and security hardening measures in {app_type} codebases "
                    "do not introduce regressions or break component contract interfaces."
                ),
                "alternatives": "Manual QA testing. Trade-off: slow, error-prone, and unsustainable for continuous deployment.",
                "trade_offs": "Initial time investment to author test cases.",
                "implementation_complexity": "MEDIUM (writing unit test assertions for core endpoints and functions).",
                "security_impact": (
                    "Risk reduction: Proactively guards security boundaries, input validation logic, and schema parsers against regressions before deployment. "
                    "Assumptions & Residual Risks: Unit tests validate tested execution paths; integration tests and ongoing test maintenance remain necessary."
                ),
                "maintainability_impact": "Enables confident refactoring and rapid feature iteration.",
                "cost_considerations": "Zero cost; standard library unittest.",
                "dependencies": "Standard library (unittest).",
                "priority": "LOW",
                "confidence": "HIGH",
                "finding_id": "BASE-TESTING-01",
                "phase_sources": ["Baseline Guidance"],
            },
            {
                "problem": "Proactive general guidance: Configure defensive HTTP response headers on public API endpoints (BASE-HEADERS-01).",
                "evidence": (
                    f"Proactive web security baseline relevant to web-facing interfaces{fw_desc}; "
                    "defense-in-depth standard for HTTP endpoints independent of confirmed repository findings."
                ),
                "requirement_affected": self._resolve_requirement(category_hint="security"),
                "current_implementation": "General security guidance: No specific header vulnerability was verified by upstream scanners. Web response pipelines should be verified to include standard browser defenses.",
                "recommended_change": "Inject standard HTTP defensive headers (X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy) into API responses.",
                "technical_reasoning": (
                    "Security headers provide defense-in-depth against client-side browser attacks including clickjacking, "
                    "MIME-type sniffing, and cross-site framing."
                ),
                "alternatives": "Configure headers at the reverse proxy (Nginx / Cloudflare). Trade-off: requires external proxy setup.",
                "trade_offs": "Strict Content-Security-Policy must accommodate all approved frontend asset origins.",
                "implementation_complexity": "LOW (adding an after_request middleware hook).",
                "security_impact": (
                    "Risk reduction: Provides defense-in-depth against MIME-type sniffing (nosniff) and frame embedding (clickjacking). "
                    "Assumptions & Residual Risks: Browser headers do not protect non-browser API clients and must be tailored so Content-Security-Policy does not block legitimate frontend origins."
                ),
                "maintainability_impact": "Centralizes response header policies in a single middleware location.",
                "cost_considerations": "Zero cost.",
                "dependencies": "None.",
                "priority": "LOW",
                "confidence": "HIGH",
                "finding_id": "BASE-HEADERS-01",
                "phase_sources": ["Baseline Guidance"],
            }
        ]

        return baselines


