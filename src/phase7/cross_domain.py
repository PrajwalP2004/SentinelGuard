"""
Phase 7: Cross-Domain Software Engineering Analysis Agent.

Synthesizes evidence-based relationships and trade-offs across:
- Security
- Code Quality
- Scalability
- Performance
- Architecture
- Maintainability
- Requirements
"""

import ast
import os
import re
from typing import Dict, List, Any, Optional, Set, Tuple


def _safe_str(val: Any) -> str:
    """Safely extracts a stripped string from any object, returning '' if not a string."""
    if isinstance(val, str):
        return val.strip()
    return ""


def _collect_scoped_nodes(root: ast.AST, target_types: Any) -> List[Any]:
    """Collects AST nodes of given types strictly within current scope, without descending into nested functions/classes."""
    results: List[Any] = []
    for child in ast.iter_child_nodes(root):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(child, target_types):
            results.append(child)
        results.extend(_collect_scoped_nodes(child, target_types))
    return results


def _has_enforcement(if_node: ast.If) -> bool:
    """Verifies that an If block enforces its condition via raise, return, break, or exit call."""
    for sub in ast.walk(if_node):
        if isinstance(sub, (ast.Raise, ast.Return, ast.Break)):
            return True
        if isinstance(sub, ast.Call):
            fname = ""
            if isinstance(sub.func, ast.Name):
                fname = sub.func.id
            elif isinstance(sub.func, ast.Attribute):
                fname = sub.func.attr
            if fname in ("exit", "abort"):
                return True
    return False


class CrossDomainAnalysisAgent:
    """Agent that performs multi-dimensional cross-domain relationship analysis."""

    def __init__(
        self,
        root_path: Optional[str] = None,
        phase1_reconstruction: Optional[Dict[str, Any]] = None,
        phase2_requirements: Optional[List[Dict[str, Any]]] = None,
        phase3a_findings: Optional[List[Dict[str, Any]]] = None,
        phase4a_remediations: Optional[List[Dict[str, Any]]] = None,
        phase5a_retest: Optional[Dict[str, Any]] = None,
        phase6_smells: Optional[List[Dict[str, Any]]] = None,
        **kwargs: Any
    ):
        # Backward-compatibility: support positional invocation if phase1_reconstruction was passed first
        if isinstance(root_path, dict) and phase1_reconstruction is None:
            phase1_reconstruction = root_path
            root_path = None

        self.root_path: Optional[str] = root_path if isinstance(root_path, str) and root_path.strip() else None

        # Defensively sanitize input arguments without in-place mutation
        self.p1: Dict[str, Any] = phase1_reconstruction if isinstance(phase1_reconstruction, dict) else {}
        self.p2_reqs: List[Dict[str, Any]] = [
            r for r in phase2_requirements if isinstance(r, dict)
        ] if isinstance(phase2_requirements, list) else []
        self.p3a_findings: List[Dict[str, Any]] = [
            f for f in phase3a_findings if isinstance(f, dict)
        ] if isinstance(phase3a_findings, list) else []
        self.p4a_remediations: List[Dict[str, Any]] = [
            rem for rem in phase4a_remediations if isinstance(rem, dict)
        ] if isinstance(phase4a_remediations, list) else []
        self.p5a_retest: Dict[str, Any] = phase5a_retest if isinstance(phase5a_retest, dict) else {}
        self.p6_smells: List[Dict[str, Any]] = [
            s for s in phase6_smells if isinstance(s, dict)
        ] if isinstance(phase6_smells, list) else []

    def _inspect_source_details(self) -> Tuple[bool, str, str, Dict[str, Any]]:
        """
        Conservative, bounded, read-only AST inspection of repository extraction code.
        Returns: (found, state, evidence_msg, details_dict)
        """
        if not self.root_path or not os.path.isdir(self.root_path):
            return False, "NOT_FOUND", "", {}
        canonical_root = os.path.realpath(self.root_path)

        candidate_rel_paths = [
            os.path.join("src", "phase0", "ingestion.py"),
            os.path.join("src", "utils", "archive.py"),
            "ingest.py",
        ]

        has_extraction_code = False

        for rel in candidate_rel_paths:
            full_path = os.path.realpath(os.path.join(canonical_root, rel))
            try:
                if os.path.commonpath([canonical_root, full_path]) != canonical_root:
                    continue
            except (ValueError, OSError):
                continue

            if os.path.isfile(full_path):
                try:
                    if os.path.getsize(full_path) > 1024 * 1024:
                        continue
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        source_text = f.read()

                    try:
                        tree = ast.parse(source_text, filename=rel)
                    except SyntaxError:
                        continue

                    for node in ast.walk(tree):
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            scoped_calls = _collect_scoped_nodes(node, ast.Call)
                            extract_calls = []
                            for call in scoped_calls:
                                func_name = ""
                                if isinstance(call.func, ast.Attribute):
                                    func_name = call.func.attr
                                elif isinstance(call.func, ast.Name):
                                    func_name = call.func.id
                                if func_name in ("extractall", "extract"):
                                    extract_calls.append(call)

                            if not extract_calls:
                                continue

                            has_extraction_code = True
                            first_extract_line = min(c.lineno for c in extract_calls)

                            scoped_ifs = _collect_scoped_nodes(node, ast.If)
                            pre_extraction_ifs = [
                                if_stmt for if_stmt in scoped_ifs
                                if if_stmt.lineno < first_extract_line and _has_enforcement(if_stmt)
                            ]

                            has_cumulative = False
                            has_member_size = False
                            has_members = False
                            has_ratio = False
                            has_path = False

                            for if_stmt in pre_extraction_ifs:
                                test_dump = ast.dump(if_stmt.test).lower()
                                if any(k in test_dump for k in ("uncompressed", "limit_bytes", "max_bytes", "max_size", "total_size", "accumulated", "cumulative")):
                                    has_cumulative = True
                                if any(k in test_dump for k in ("file_size", "member_size", "member.size", "entry.size")):
                                    has_member_size = True
                                if any(k in test_dump for k in ("max_files", "member_count", "file_count", "max_members")) or ("len(" in test_dump or "len" in test_dump):
                                    has_members = True
                                if any(k in test_dump for k in ("ratio", "compress_size", "compression_ratio")):
                                    has_ratio = True
                                if any(k in test_dump for k in ("commonpath", "realpath", "abspath", "startswith", "filename")):
                                    has_path = True

                            detected_controls = []
                            unverified_controls = []

                            if has_cumulative:
                                detected_controls.append("cumulative uncompressed size limits")
                            elif has_member_size:
                                detected_controls.append("per-member uncompressed size limits")
                                unverified_controls.append("cumulative uncompressed size limit across entries")
                            else:
                                unverified_controls.append("uncompressed size limits")

                            if has_members:
                                detected_controls.append("member count caps")
                            else:
                                unverified_controls.append("member count caps")

                            if has_ratio:
                                detected_controls.append("compression ratio checks")
                            else:
                                unverified_controls.append("compression ratio checks")

                            if has_path:
                                detected_controls.append("path traversal validation")
                            else:
                                unverified_controls.append("path traversal validation")

                            if detected_controls:
                                # Full verification requires cumulative size OR (per-member size + member count)
                                is_full = has_cumulative or (has_member_size and has_members)
                                state = "VERIFIED_PRESENT" if is_full else "PARTIALLY_VERIFIED"
                                controls_str = ", ".join(detected_controls)
                                unverified_str = f" (unverified: {', '.join(unverified_controls)})" if unverified_controls else ""
                                evidence_msg = (
                                    f"Verified pre-extraction quota enforcement in {rel} ({node.name}() enforces {controls_str} before extraction){unverified_str}."
                                )
                                details = {
                                    "has_cumulative_size": has_cumulative,
                                    "has_member_size": has_member_size,
                                    "has_member_count": has_members,
                                    "has_ratio": has_ratio,
                                    "has_path": has_path,
                                    "detected_controls": detected_controls,
                                    "unverified_controls": unverified_controls,
                                    "pre_extraction": True,
                                    "file": rel,
                                    "function": node.name
                                }
                                return True, state, evidence_msg, details
                except (PermissionError, OSError):
                    continue

        return False, "NOT_FOUND" if not has_extraction_code else "RISK_IDENTIFIED", "", {"has_extraction_code": has_extraction_code}

    def _inspect_source_for_archive_quota(self) -> Tuple[bool, str]:
        """
        Conservative, bounded, read-only AST inspection of repository extraction code.
        Compatibility wrapper returning (bool, str).
        """
        found, _, evidence, _ = self._inspect_source_details()
        return found, evidence

    def evaluate_archive_quota_state(self) -> Dict[str, Any]:
        """
        Classifies archive decompression quota status into one of distinct states:
        - VERIFIED_PRESENT: Concrete evidence demonstrates required security controls are implemented and tested
                            via Phase 5A retest (REMEDIATED with concrete, tested quota evidence)
                            or validated source AST inspection of pre-extraction guards.
                            (verified=True, full_verification=True, partial_verification=False)
        - PARTIALLY_VERIFIED: Partial control evidence exists (e.g. PARTIALLY_REMEDIATED,
                              source per-member check without cumulative limit, member-count cap without total size).
                              (verified=False, full_verification=False, partial_verification=True)
        - UNVERIFIED: Missing, generic, or insufficient evidence (e.g. REMEDIATED with generic/empty evidence,
                      or keywords present without verification proof).
                      (verified=False, full_verification=False, partial_verification=False)
        - CONFLICTING_EVIDENCE: Retest and source evidence contradict each other.
                                (verified=False, full_verification=False, partial_verification=False)
        - PLANNED_ONLY: Proposed in Phase 4A remediation plan, but implementation is not verified.
                        (verified=False, full_verification=False, partial_verification=False)
        - RISK_IDENTIFIED: Identified in Phase 3A vulnerability finding without remediation,
                           or confirmed NOT_REMEDIATED in Phase 5A.
                           (verified=False, full_verification=False, partial_verification=False)
        - NOT_ASSESSED: Retest status NOT_TESTABLE, NOT_ASSESSED, FALSE_POSITIVE, or unknown/malformed status.
                        (verified=False, full_verification=False, partial_verification=False)
        - NOT_FOUND: No archive quota findings, plans, or controls present.
                     (verified=False, full_verification=False, partial_verification=False)
        """
        # 1. Check Phase 5A retest results (highest verification authority)
        retest_results = self.p5a_retest.get("retest_results", [])
        if isinstance(retest_results, list):
            for res in retest_results:
                if isinstance(res, dict):
                    f_id = _safe_str(res.get("finding_id")).upper()
                    desc = f"{_safe_str(res.get('result'))} {_safe_str(res.get('original_issue'))}".lower()
                    if f_id == "RED-DOS-01" or "decompression" in desc or "zip bomb" in desc:
                        status = _safe_str(res.get("final_status")).upper()
                        raw_evidence = _safe_str(res.get("evidence"))
                        result_msg = _safe_str(res.get("result"))
                        detail = raw_evidence or result_msg

                        if status == "REMEDIATED":
                            # Check for source conflict if repository source files are present
                            src_found, src_state, src_evidence, src_details = self._inspect_source_details()
                            if self.root_path and src_details.get("has_extraction_code") and not src_found:
                                return {
                                    "state": "CONFLICTING_EVIDENCE",
                                    "verified": False,
                                    "full_verification": False,
                                    "partial_verification": False,
                                    "evidence": (
                                        "Phase 5A retest reported RED-DOS-01 as REMEDIATED, but static source inspection "
                                        "detected unverified or missing pre-extraction guards in repository extraction "
                                        "routines; control is classified as CONFLICTING_EVIDENCE due to conflicting evidence."
                                    ),
                                    "finding_id": f_id,
                                    "status": "CONFLICTED"
                                }

                            if not detail or not detail.strip():
                                return {
                                    "state": "UNVERIFIED",
                                    "verified": False,
                                    "full_verification": False,
                                    "partial_verification": False,
                                    "evidence": f"Phase 5A retest reported RED-DOS-01 as REMEDIATED without verification evidence; control remains unverified.",
                                    "finding_id": f_id,
                                    "status": status
                                }

                            detail_lower = detail.lower()

                            # Check for partial remediation indicators within the evidence text
                            partial_indicators = ("partial", "partially", "pending", "incomplete", "unverified check")
                            is_partial_detail = any(p in detail_lower for p in partial_indicators)

                            if is_partial_detail:
                                return {
                                    "state": "PARTIALLY_VERIFIED",
                                    "verified": False,
                                    "full_verification": False,
                                    "partial_verification": True,
                                    "evidence": f"Phase 5A retest indicated partial quota verification for RED-DOS-01: {detail}.",
                                    "finding_id": f_id,
                                    "status": status
                                }

                            # Distinguish concrete verification of controls from generic evidence or isolated keywords
                            has_test_verb = bool(re.search(
                                r'\b(?:verifi\w*|tested|test\s+passed|validated|validat\w*|enforc\w*|inspection\s+checks?|checks?\s+passed|blocks?)\b',
                                detail_lower
                            ))
                            has_size_control = bool(re.search(
                                r'\b(?:uncompressed|size\s+limit|max_bytes|limit_bytes|max_size|total_size|file_size|max_uncompressed_bytes)\b',
                                detail_lower
                            ))
                            has_member_control = bool(re.search(
                                r'\b(?:member\s+count|max_files|file\s+count|max_members)\b',
                                detail_lower
                            ))
                            has_pre_extraction = bool(re.search(
                                r'\b(?:pre-extraction|pre-scan|decompression\s+quota)\b',
                                detail_lower
                            ))
                            has_metrics = bool(re.search(r'\d+\s*(?:mb|gb|kb|bytes|b|:1)?\b|\(\s*\d+', detail_lower))
                            has_validated_ingest = bool(re.search(
                                r'\b(?:pre-extraction\s+quotas?\s+validated|decompression\s+quota\s+verified)\b',
                                detail_lower
                            ))

                            has_concrete_evidence = has_test_verb and (
                                (has_size_control and (has_member_control or has_metrics)) or
                                (has_pre_extraction and (has_metrics or has_validated_ingest or has_size_control))
                            )

                            if has_concrete_evidence and len(detail) >= 15:
                                evidence_msg = (
                                    f"Phase 5A retest verified archive pre-extraction quota enforcement for RED-DOS-01 (REMEDIATED): {detail}."
                                )
                                return {
                                    "state": "VERIFIED_PRESENT",
                                    "verified": True,
                                    "full_verification": True,
                                    "partial_verification": False,
                                    "evidence": evidence_msg,
                                    "finding_id": f_id,
                                    "status": status
                                }
                            else:
                                evidence_msg = (
                                    f"Phase 5A retest reported RED-DOS-01 as REMEDIATED without concrete quota verification metrics: {detail}."
                                )
                                return {
                                    "state": "UNVERIFIED",
                                    "verified": False,
                                    "full_verification": False,
                                    "partial_verification": False,
                                    "evidence": evidence_msg,
                                    "finding_id": f_id,
                                    "status": status
                                }
                        elif status == "PARTIALLY_REMEDIATED":
                            evidence_msg = (
                                f"Phase 5A retest indicated partial remediation for RED-DOS-01 (PARTIALLY_REMEDIATED): {detail or 'partial quota controls present'}."
                            )
                            return {
                                "state": "PARTIALLY_VERIFIED",
                                "verified": False,
                                "full_verification": False,
                                "partial_verification": True,
                                "evidence": evidence_msg,
                                "finding_id": f_id,
                                "status": status
                            }
                        elif status == "NOT_REMEDIATED":
                            return {
                                "state": "RISK_IDENTIFIED",
                                "verified": False,
                                "full_verification": False,
                                "partial_verification": False,
                                "evidence": f"Phase 5A retest confirmed RED-DOS-01 is NOT_REMEDIATED; decompression bomb risk remains reachable.",
                                "finding_id": f_id,
                                "status": status
                            }
                        elif status == "FALSE_POSITIVE":
                            return {
                                "state": "NOT_ASSESSED",
                                "verified": False,
                                "full_verification": False,
                                "partial_verification": False,
                                "evidence": f"Phase 5A retest marked RED-DOS-01 as FALSE_POSITIVE; no quota defense needed or tested.",
                                "finding_id": f_id,
                                "status": status
                            }
                        else:
                            # NOT_TESTABLE, NOT_ASSESSED, missing, or unexpected statuses
                            status_label = status if status else "UNKNOWN"
                            return {
                                "state": "NOT_ASSESSED",
                                "verified": False,
                                "full_verification": False,
                                "partial_verification": False,
                                "evidence": f"Phase 5A retest marked RED-DOS-01 as {status_label}; automated verification unavailable.",
                                "finding_id": f_id,
                                "status": status_label
                            }

        # 2. Check source code under root_path if provided (bounded, read-only AST inspection)
        if self.root_path and os.path.isdir(self.root_path):
            src_found, src_state, src_evidence, src_details = self._inspect_source_details()
            if src_found:
                is_full = src_state == "VERIFIED_PRESENT"
                return {
                    "state": src_state,
                    "verified": is_full,
                    "full_verification": is_full,
                    "partial_verification": not is_full,
                    "evidence": src_evidence,
                    "finding_id": "RED-DOS-01",
                    "status": "SOURCE_VERIFIED"
                }

        # 3. Check Phase 1 reconstruction metadata (treated as reported evidence, not independent source verification)
        if isinstance(self.p1, dict):
            archive_ctrls = self.p1.get("archive_controls")
            if isinstance(archive_ctrls, dict) and archive_ctrls.get("enforced") is True:
                desc = _safe_str(archive_ctrls.get("description"))
                if desc:
                    return {
                        "state": "PARTIALLY_VERIFIED",
                        "verified": False,
                        "full_verification": False,
                        "partial_verification": True,
                        "evidence": f"Phase 1 reconstruction reported archive quota controls: {desc} (unverified by source inspection).",
                        "finding_id": "RED-DOS-01",
                        "status": "RECONSTRUCTION_REPORTED"
                    }

        # 4. Check Phase 4A remediation plans (planned only - NOT verified implementation)
        for rem in self.p4a_remediations:
            if isinstance(rem, dict):
                f_id = _safe_str(rem.get("finding_id")).upper()
                r_id = _safe_str(rem.get("remediation_id")).upper()
                desc = f"{_safe_str(rem.get('title'))} {_safe_str(rem.get('description'))}".lower()
                if f_id == "RED-DOS-01" or r_id == "REM-DOS-01" or "decompression" in desc:
                    return {
                        "state": "PLANNED_ONLY",
                        "verified": False,
                        "full_verification": False,
                        "partial_verification": False,
                        "evidence": f"Phase 4A remediation plan {r_id or 'REM-DOS-01'} proposes pre-extraction quota checks, but implementation has not been verified.",
                        "finding_id": f_id or "RED-DOS-01",
                        "status": "PLANNED"
                    }

        # 5. Check Phase 3A findings (vulnerability risk identified - NOT verified implementation)
        for f in self.p3a_findings:
            if isinstance(f, dict):
                f_id = _safe_str(f.get("finding_id")).upper()
                f_type = _safe_str(f.get("finding_type")).lower()
                desc = f"{_safe_str(f.get('title'))} {_safe_str(f.get('description'))}".lower()
                if f_id == "RED-DOS-01" or "decompression" in f_type or "zip bomb" in desc:
                    return {
                        "state": "RISK_IDENTIFIED",
                        "verified": False,
                        "full_verification": False,
                        "partial_verification": False,
                        "evidence": f"Phase 3A security finding {f_id or 'RED-DOS-01'} identifies decompression bomb vulnerability; no quota enforcement verified.",
                        "finding_id": f_id or "RED-DOS-01",
                        "status": "UNREMEDIATED"
                    }

        return {
            "state": "NOT_FOUND",
            "verified": False,
            "full_verification": False,
            "partial_verification": False,
            "evidence": "",
            "finding_id": "",
            "status": "NONE"
        }

    def _evaluate_archive_quota_controls(self) -> Tuple[bool, str]:
        """
        Determines whether archive decompression quota defenses meet verification criteria.
        Returns True only for VERIFIED_PRESENT or PARTIALLY_VERIFIED states.
        """
        state_info = self.evaluate_archive_quota_state()
        has_active = state_info.get("state") in ("VERIFIED_PRESENT", "PARTIALLY_VERIFIED")
        return has_active, state_info.get("evidence", "")

    def analyze(self) -> Dict[str, Any]:
        """Synthesizes cross-domain interactions supported by empirical evidence."""
        relationships: List[Dict[str, Any]] = []
        seen_ids: Set[str] = set()

        def _add_relationship(rel_dict: Dict[str, Any]) -> None:
            rel_id = rel_dict["relationship_id"]
            if rel_id not in seen_ids:
                seen_ids.add(rel_id)
                # Additive backward-compatible convenience fields for UI and reports
                rel_dict["domains"] = f"{rel_dict['domain_a']} <-> {rel_dict['domain_b']}"
                rel_dict["interaction"] = rel_dict["relationship"]
                rel_dict["trade_off"] = rel_dict["consequence"]
                rel_dict["impact"] = rel_dict["consequence"]
                relationships.append(rel_dict)

        # ---------------------------------------------------------------------
        # 1. Code Smells <-> Security: Silent Exception Handling weakens Security Observability
        # ---------------------------------------------------------------------
        silent_smells = []
        for s in self.p6_smells:
            if not isinstance(s, dict):
                continue
            cat = _safe_str(s.get("category"))
            evidence = _safe_str(s.get("evidence"))
            explanation = _safe_str(s.get("explanation"))
            file_path = _safe_str(s.get("file"))
            smell_id = _safe_str(s.get("smell_id")).upper()

            # Must have non-empty file and non-empty evidence
            if not file_path or not evidence:
                continue

            # Check for active logging or re-raise that disproves silence
            has_logging = bool(re.search(r'\b(?:logger?\.(?:info|error|warning|exception|debug)|logging\.(?:info|error|warning|exception|debug))\b', evidence, re.IGNORECASE))
            has_reraise = bool(re.search(r'\braise\b', evidence, re.IGNORECASE))

            if has_logging or has_reraise:
                continue

            # Must demonstrate actual exception suppression in evidence or structured smell_id
            has_suppression = (
                bool(re.search(r'\b(?:pass|swallow(?:ed)?|silent(?:ly)?\s+suppress\w*)\b|\.\.\.', evidence, re.IGNORECASE)) or
                "SILENT" in smell_id
            )

            if has_suppression:
                silent_smells.append(s)

        if silent_smells:
            locations = []
            for s in silent_smells:
                f_path = _safe_str(s.get("file"))
                f_target = _safe_str(s.get("function_or_class"))
                loc = f"{f_path}:{f_target}" if f_target else f_path
                if loc and loc not in locations:
                    locations.append(loc)

            sample_evidence = _safe_str(silent_smells[0].get("evidence"))
            _add_relationship({
                "relationship_id": "REL-SMELL-SEC-01",
                "domain_a": "Code Quality",
                "finding_a": "Poor Exception Handling (Silent except: pass)",
                "domain_b": "Security",
                "finding_b": "Audit Logging & Incident Detection (STRIDE-REP-01 / OWASP-A09)",
                "relationship": "Code Smell Undermines Security Observability",
                "evidence": f"Silent exception suppression detected in {', '.join(locations[:3])}: {sample_evidence}",
                "consequence": "Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.",
                "priority": "HIGH",
                "recommended_action": "Replace silent pass handlers with targeted exception types and route caught exceptions to structured diagnostic audit logs."
            })

        # ---------------------------------------------------------------------
        # 2. Security <-> Performance: Pre-scan Decompression Quotas add Ingestion Latency
        # ---------------------------------------------------------------------
        has_zip_quota, quota_evidence = self._evaluate_archive_quota_controls()
        if has_zip_quota:
            state_info = self.evaluate_archive_quota_state()
            is_partial = state_info["state"] == "PARTIALLY_VERIFIED"
            consequence_text = (
                "Pre-scan validation loops across archive entries introduce potential computational processing overhead, "
                "trading execution time for mitigated risk of disk-exhaustion denial of service."
                if not is_partial else
                "Partial pre-scan validation introduces potential processing overhead while leaving unverified quota ceilings subject to resource exhaustion."
            )
            _add_relationship({
                "relationship_id": "REL-SEC-PERF-01",
                "domain_a": "Security",
                "finding_a": "Decompression Bomb Protection Quota Checks (RED-DOS-01)",
                "domain_b": "Performance",
                "finding_b": "Archive Extraction Latency Overhead",
                "relationship": "Defensive Security Quota Pre-Scan Adds Potential Computational Overhead",
                "evidence": quota_evidence,
                "consequence": consequence_text,
                "priority": "MEDIUM",
                "recommended_action": "Retain pre-scan validation checks; potential computational overhead of entry inspection is an appropriate defensive trade-off against host filesystem exhaustion."
            })

        # ---------------------------------------------------------------------
        # 3. Architecture <-> Security: Zero Third-Party Dependencies vs. In-House Security Parsers
        # ---------------------------------------------------------------------
        zero_dep_req = None
        for r in self.p2_reqs:
            if not isinstance(r, dict):
                continue
            desc = _safe_str(r.get("description"))
            title = _safe_str(r.get("title"))
            evidence = _safe_str(r.get("evidence"))
            combined = f"{desc} {title} {evidence}".lower()

            if not desc and not evidence:
                continue

            # Verify that requirement actually mandates zero/no external dependencies or standard library only
            is_zero_dep = (
                bool(re.search(r'\b(?:zero|no|without)\s+(?:external\s+|third[- ]party\s+|runtime\s+)?depend', combined)) or
                bool(re.search(r'\bstandard\s+library\s+only\b', combined)) or
                bool(re.search(r'\bstandard\s+library\b[^\.\n]*\bwithout\s+(?:external|third[- ]party)\b', combined))
            )

            if is_zero_dep:
                zero_dep_req = r
                break

        if zero_dep_req:
            req_id = _safe_str(zero_dep_req.get("requirement_id"))
            req_desc = _safe_str(zero_dep_req.get("description"))
            finding_a_label = f"Zero External Dependencies Requirement ({req_id})" if req_id else "Zero External Dependencies Requirement"
            evidence_str = f"Requirement {req_id} specifies: '{req_desc}'." if req_id else f"Requirement specifies: '{req_desc}'."
            _add_relationship({
                "relationship_id": "REL-ARCH-SEC-01",
                "domain_a": "Architecture / Requirements",
                "finding_a": finding_a_label,
                "domain_b": "Security",
                "finding_b": "Supply Chain Attack Surface Reduction vs. In-House Security Maintenance",
                "relationship": "Zero-Dependency Policy Reduces Third-Party Dependency Exposure but Increases In-House Validation Responsibility",
                "evidence": evidence_str,
                "consequence": "Relying on standard-library implementations reduces exposure to third-party package vulnerabilities, but places ongoing maintenance, security patching, and validation responsibilities on custom internal routines.",
                "priority": "HIGH",
                "recommended_action": "Maintain zero-dependency constraint if minimal deployment footprint is required, backed by rigorous unit testing and security static analysis of custom parsing logic."
            })

        # ---------------------------------------------------------------------
        # 4. Code Smells <-> Scalability: Monolithic Ingestion Loop prevents Multi-Core Parallelism
        # ---------------------------------------------------------------------
        inventory_smell = None
        for s in self.p6_smells:
            if not isinstance(s, dict):
                continue
            cat = _safe_str(s.get("category"))
            target_func = _safe_str(s.get("function_or_class"))
            f_path = _safe_str(s.get("file"))
            evidence = _safe_str(s.get("evidence"))
            explanation = _safe_str(s.get("explanation"))
            combined = f"{target_func} {f_path} {evidence} {explanation}".lower()

            if not f_path or not evidence:
                continue

            # Must actually be connected to inventory, repository ingestion, directory traversal, or file discovery
            is_inventory = (
                bool(re.search(r'\binventory\b', combined)) or
                bool(re.search(r'\b(?:file\s+discovery|directory\s+traversal|walk(?:ing)?|ingest(?:ion)?)\b', combined))
            )

            if is_inventory and cat in ("Long Method", "Deep Nesting", "High Cyclomatic Complexity"):
                inventory_smell = s
                break

        if inventory_smell:
            target_file = _safe_str(inventory_smell.get("file"))
            target_func = _safe_str(inventory_smell.get("function_or_class"))
            smell_evidence = _safe_str(inventory_smell.get("evidence"))
            func_desc = f"in {target_func}" if target_func else ""
            _add_relationship({
                "relationship_id": "REL-SMELL-SCALE-01",
                "domain_a": "Code Quality",
                "finding_a": f"High Structural Complexity {func_desc}".strip(),
                "domain_b": "Scalability",
                "finding_b": "Filesystem Traversal and Ingestion Bottleneck Risk",
                "relationship": "Monolithic Traversal Logic Poses Potential Scalability Constraint",
                "evidence": f"{target_file}{' (' + target_func + ')' if target_func else ''}: {smell_evidence}",
                "consequence": "High cyclomatic complexity and deep nesting in repository traversal routines increase maintenance overhead and represent a plausible scaling bottleneck under large file counts.",
                "priority": "MEDIUM",
                "recommended_action": "Refactor traversal routines into smaller modular functions to separate file discovery from filtering and categorization logic."
            })

        # ---------------------------------------------------------------------
        # 5. Architecture <-> Maintainability: Untyped Dictionary Contracts increase Inter-Phase Coupling
        # ---------------------------------------------------------------------
        primitive_smell = None
        for s in self.p6_smells:
            if not isinstance(s, dict):
                continue
            cat = _safe_str(s.get("category"))
            evidence = _safe_str(s.get("evidence"))
            explanation = _safe_str(s.get("explanation"))
            target_func = _safe_str(s.get("function_or_class"))
            f_path = _safe_str(s.get("file"))
            combined = f"{evidence} {explanation} {target_func} {f_path}".lower()

            if not f_path or not evidence:
                continue

            is_primitive = (
                "primitive" in cat.lower() or
                "primitive-obsession" in _safe_str(s.get("smell_id")).lower()
            )

            is_contract_boundary = bool(re.search(r'\b(?:phase|contract|boundary|interface|pipeline|data\s+exchange)\b', combined))

            if is_primitive and is_contract_boundary:
                primitive_smell = s
                break

        if primitive_smell:
            aff_file = _safe_str(primitive_smell.get("file"))
            aff_evidence = _safe_str(primitive_smell.get("evidence"))
            target_func = _safe_str(primitive_smell.get("function_or_class"))
            _add_relationship({
                "relationship_id": "REL-ARCH-MAINT-01",
                "domain_a": "Architecture",
                "finding_a": "Pipeline Component Data Exchange Contracts",
                "domain_b": "Maintainability",
                "finding_b": "Primitive Obsession across Contract Boundaries",
                "relationship": "Untyped Data Exchange Increases Maintenance Friction across Interfaces",
                "evidence": f"Component data exchange in {aff_file}{' (' + target_func + ')' if target_func else ''}: {aff_evidence}",
                "consequence": "Relying on raw untyped dictionaries across phase boundaries lacks static schema validation, increasing maintenance overhead and the risk of unhandled key errors during schema evolution.",
                "priority": "HIGH",
                "recommended_action": "Formalize inter-phase data exchange using typed dataclasses or TypedDict schemas to document and validate contracts between pipeline components."
            })

        # ---------------------------------------------------------------------
        # 6. Security <-> Maintainability: Duplicate CLI Sanitization risks Security Drift
        # ---------------------------------------------------------------------
        dup_cli_smell = None
        for s in self.p6_smells:
            if not isinstance(s, dict):
                continue
            cat = _safe_str(s.get("category"))
            target_func = _safe_str(s.get("function_or_class"))
            evidence = _safe_str(s.get("evidence"))
            explanation = _safe_str(s.get("explanation"))
            f_path = _safe_str(s.get("file"))
            combined = f"{target_func} {evidence} {explanation}".lower()

            if not f_path or not evidence:
                continue

            is_dup = "duplicate" in cat.lower() or "duplicate" in _safe_str(s.get("smell_id")).lower()
            if not is_dup:
                continue

            # Must establish CLI output with sanitization / stream safety
            has_cli_token = bool(re.search(r'\b(?:cli|stdout|stream|entry_point)\b', combined))
            has_sanitization = bool(re.search(r'\b(?:sanitiz\w*|safe_write\w*|boundary\s+check|reconfigure|path_traversal)\b', combined))

            if has_cli_token and has_sanitization:
                dup_cli_smell = s
                break

        if dup_cli_smell:
            aff_file = _safe_str(dup_cli_smell.get("file"))
            aff_evidence = _safe_str(dup_cli_smell.get("evidence"))
            target_func = _safe_str(dup_cli_smell.get("function_or_class"))
            _add_relationship({
                "relationship_id": "REL-SEC-MAINT-01",
                "domain_a": "Security",
                "finding_a": "CLI Output Sanitization and Stream Boundary Safety",
                "domain_b": "Maintainability",
                "finding_b": "Duplicated CLI Output and Sanitization Logic",
                "relationship": "Duplicated Output Logic Risks Inconsistent Security Posture",
                "evidence": f"Duplication in {aff_file}{' (' + target_func + ')' if target_func else ''}: {aff_evidence}",
                "consequence": "Duplicated output handling and sanitization logic risks divergent updates over time, where security checks or path boundaries applied in one entry point may be missed in another.",
                "priority": "HIGH",
                "recommended_action": "Consolidate duplicated CLI output sanitization and stream reconfiguration logic into a shared common utility module."
            })

        # Calculate exact domain interaction counts matching relationship occurrences
        return {
            "cross_domain_relationships": relationships,
            "total_relationships": len(relationships),
            "domain_interactions": {
                "code_smell_security": sum(1 for r in relationships if r.get("relationship_id") == "REL-SMELL-SEC-01"),
                "security_performance": sum(1 for r in relationships if r.get("relationship_id") == "REL-SEC-PERF-01"),
                "architecture_security": sum(1 for r in relationships if r.get("relationship_id") == "REL-ARCH-SEC-01"),
                "code_smell_scalability": sum(1 for r in relationships if r.get("relationship_id") == "REL-SMELL-SCALE-01"),
                "architecture_maintainability": sum(1 for r in relationships if r.get("relationship_id") == "REL-ARCH-MAINT-01"),
                "security_maintainability": sum(1 for r in relationships if r.get("relationship_id") == "REL-SEC-MAINT-01"),
            }
        }
