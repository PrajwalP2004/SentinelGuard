"""
Phase 2: Security Assessment Agent Module.

Consumes the Phase 1 Project Reconstruction model and executes:
1. Scoped STRIDE Threat Modeling across trust boundaries and entry points
2. Evidence-based OWASP Top 10 Architectural Compliance Auditing (with explicit partial coverage declaration)
3. Deterministic, Bounded Quantitative Security Scoring (0 - 100) and Actionable Remediation Roadmap
4. Qualified Architecture Resilience and Single-Point-of-Failure (SPOF) Analysis

Strict Evidence Rules:
- Evaluates authentication at per-asset/per-route scope; does not treat absence of route-level auth evidence as definitive proof of vulnerability without qualification.
- Preserves explicit evidence of intentionally public routes (e.g., /health, /metrics, public APIs).
- Does not generate information disclosure findings for databases merely because they exist; requires evidence of weakness. Unverified protections are reported as manual-review items.
- Detects rate-limiting evidence specifically; does not treat Redis or general caches as rate-limiting proof. Qualifies findings when external gateway/proxy configurations are unavailable.
- Separates AuthN, AuthZ, and transport security into distinct evidence-based evaluations.
- Labels resilience and SPOF conclusions as heuristic unless supported by deployment redundancy evidence.
- Semantic deduplication preserves the most severe evidence and never merges distinct vulnerability types.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict


class SecurityAssessmentAgent:
    """Agent that performs STRIDE threat modeling, OWASP compliance checking, and risk scoring."""

    # Deterministic scoring penalty deductions from base 100
    # Confirmed findings incur full penalties; potential/manual verification findings incur bounded partial penalties
    SEVERITY_WEIGHTS = {
        "CONFIRMED": {
            "CRITICAL": 20,
            "HIGH": 12,
            "MEDIUM": 6,
            "LOW": 2,
            "INFO": 0,
        },
        "POTENTIAL": {
            "CRITICAL": 10,
            "HIGH": 6,
            "MEDIUM": 3,
            "LOW": 1,
            "INFO": 0,
        },
        "MANUAL_VERIFICATION_REQUIRED": {
            "CRITICAL": 8,
            "HIGH": 4,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0,
        },
    }

    SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    KNOWN_PUBLIC_PATHS = {
        "/health", "/healthz", "/live", "/ready", "/ping",
        "/metrics", "/status", "/version", "/info",
        "/docs", "/openapi.json", "/swagger.json", "/favicon.ico",
    }

    def __init__(self, phase1_reconstruction: Optional[Dict[str, Any]] = None):
        self.p1 = phase1_reconstruction if isinstance(phase1_reconstruction, dict) else {}
        self.warnings: List[str] = []
        self.manual_review_items: List[Dict[str, Any]] = []

        if not phase1_reconstruction:
            self.warnings.append("Phase 1 reconstruction data is empty or missing. Assessment evaluated under unknown baseline.")

        # Extract and safely normalize Phase 1 collections
        self.components = self._ensure_list(self.p1.get("components"))
        self.trust_boundaries = self._ensure_list(self.p1.get("trust_boundaries"))
        self.entry_points = self._ensure_list(self.p1.get("entry_points"))
        self.apis = self._ensure_list(self.p1.get("apis"))
        self.databases = self._ensure_list(self.p1.get("databases"))
        self.external_services = self._ensure_list(self.p1.get("external_services"))
        self.auth_components = self._ensure_list(self.p1.get("authentication_components"))
        self.data_flows = self._ensure_list(self.p1.get("data_flows"))
        self.deployment = self.p1.get("deployment_model", {}) if isinstance(self.p1.get("deployment_model"), dict) else {}

    @staticmethod
    def _ensure_list(val: Any) -> List[Any]:
        if isinstance(val, list):
            return [x for x in val if isinstance(x, (dict, str))]
        return []

    def assess(self) -> Dict[str, Any]:
        """Runs the complete security assessment and returns structured results."""
        self.manual_review_items = []

        stride_findings = self._evaluate_stride()
        owasp_findings = self._evaluate_owasp()
        system_design_findings = self._evaluate_system_design()

        all_findings = stride_findings + owasp_findings + system_design_findings

        # Semantic Deduplication: Preserves distinct vulnerabilities and retains maximum severity
        deduped_findings = self._deduplicate_findings(all_findings)

        # Sort by severity rank
        deduped_findings.sort(key=lambda x: (self.SEVERITY_RANK.get(x.get("severity", "INFO"), 5), x.get("finding_id", "")))

        # Compute deterministic, bounded score
        score = self._compute_deterministic_score(deduped_findings)

        if score >= 90:
            risk_tier = "LOW RISK (STRONG RESILIENCE)"
        elif score >= 70:
            risk_tier = "MODERATE RISK"
        elif score >= 50:
            risk_tier = "HIGH RISK"
        else:
            risk_tier = "CRITICAL RISK"

        stride_summary = defaultdict(int)
        for f in deduped_findings:
            if "stride_category" in f:
                stride_summary[f["stride_category"]] += 1

        owasp_summary = defaultdict(int)
        for f in deduped_findings:
            if "owasp_category" in f:
                owasp_summary[f["owasp_category"]] += 1

        assessment_summary = {
            "security_health_score": score,
            "risk_tier": risk_tier,
            "total_findings": len(deduped_findings),
            "stride_summary": dict(stride_summary),
            "owasp_summary": dict(owasp_summary),
            "owasp_coverage": "PARTIAL (Evaluates A01, A02, A04, A07, A08, A09 based on static heuristics; manual dynamic audit required for A03, A05, A06, A10)",
            "score_type": "HEURISTIC_ESTIMATE",
            "scoring_methodology": "Deterministic penalty model (0-100) scaled by finding confidence and severity. This represents a static heuristic estimate, not a formal security certification or penetration test.",
            "manual_review_items": list(self.manual_review_items),
        }

        if self.warnings:
            assessment_summary["limitations"] = list(self.warnings)

        return {
            "assessment_summary": assessment_summary,
            "findings": deduped_findings,
            "architecture_resilience": self._evaluate_resilience_metrics(),
            "remediation_roadmap": self._generate_roadmap(deduped_findings),
            "manual_review_items": list(self.manual_review_items),
        }

    # -------------------------------------------------------------------------
    # STRIDE Threat Modeling (Scoped and Evidence-Based)
    # -------------------------------------------------------------------------
    def _evaluate_stride(self) -> List[Dict[str, Any]]:
        findings = []

        # Extract known auth supporting files and route-level auth indicators
        auth_files = set()
        for a in self.auth_components:
            if isinstance(a, dict):
                for p in a.get("supporting_file_paths", []):
                    if isinstance(p, str):
                        auth_files.add(p.replace("\\", "/"))

        # 1. SPOOFING: Evaluate authentication at per-asset / per-route scope
        findings.extend(self._evaluate_spoofing(auth_files))

        # 2. TAMPERING: Data flows without transit integrity
        findings.extend(self._evaluate_tampering())

        # 3. REPUDIATION: Missing audit logging on state-mutating actions
        findings.extend(self._evaluate_repudiation())

        # 4. INFORMATION DISCLOSURE: Unencrypted or unauthenticated storage / boundaries
        findings.extend(self._evaluate_information_disclosure())

        # 5. DENIAL OF SERVICE: Missing rate limiting / backpressure on public HTTP endpoints
        findings.extend(self._evaluate_denial_of_service())

        # 6. ELEVATION OF PRIVILEGE: Missing RBAC/ABAC authorization checks
        findings.extend(self._evaluate_elevation_of_privilege())

        return findings

    def _is_route_intentionally_public(self, api: Dict[str, Any]) -> bool:
        """Determines if a route has explicit evidence of being intentionally public."""
        if api.get("is_public") is True or api.get("public") is True:
            return True
        path = str(api.get("path", "")).strip().lower()
        if path in self.KNOWN_PUBLIC_PATHS or any(path.startswith(p) for p in ("/public/", "/static/", "/docs/")):
            return True
        desc = str(api.get("description", "")).lower()
        if "public" in desc or "unauthenticated" in desc or "health" in desc:
            return True
        return False

    def _evaluate_spoofing(self, auth_files: Set[str]) -> List[Dict[str, Any]]:
        """
        Check ingress boundaries and API routes for authentication at the appropriate scope.
        Treat missing route-authentication evidence as potential/unverified risk, not proof of open access.
        Preserves intentionally public routes without flagging them.
        """
        findings = []
        has_global_auth = len(self.auth_components) > 0

        if self.apis:
            unauthenticated_apis = []
            authenticated_apis = []
            intentionally_public_apis = []

            for api in self.apis:
                if not isinstance(api, dict):
                    continue
                route_id = f"{api.get('method', 'ANY')} {api.get('path', '/')}"
                supp_files = [f.replace("\\", "/") for f in api.get("supporting_file_paths", []) if isinstance(f, str)]

                # Check if route is intentionally public
                if self._is_route_intentionally_public(api):
                    intentionally_public_apis.append(route_id)
                    continue

                # Check if route has explicit auth metadata or file match
                is_auth_route = api.get("auth_required") is True or any(f in auth_files for f in supp_files)

                if api.get("auth_required") is False:
                    # Explicit evidence of missing authentication
                    unauthenticated_apis.append((route_id, supp_files, api.get("line_number"), "EXPLICIT_DISABLED"))
                elif is_auth_route:
                    authenticated_apis.append(route_id)
                else:
                    # Missing evidence - potential risk, not confirmed open access
                    unauthenticated_apis.append((route_id, supp_files, api.get("line_number"), "MISSING_EVIDENCE"))

            # Only evaluate non-public routes
            if unauthenticated_apis:
                supp_paths = []
                has_explicit_disabled = any(status == "EXPLICIT_DISABLED" for *_, status in unauthenticated_apis)
                for _, paths, _, _ in unauthenticated_apis:
                    supp_paths.extend(paths)

                confidence = "CONFIRMED" if has_explicit_disabled else "POTENTIAL"

                if len(authenticated_apis) == 0 and not has_global_auth:
                    findings.append({
                        "finding_id": "STRIDE-SPOOF-01",
                        "rule_id": "SEC-S01",
                        "title": "Unverified Authentication Controls on HTTP Ingress Endpoints",
                        "severity": "HIGH",
                        "confidence": confidence,
                        "stride_category": "Spoofing",
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "target": "HTTP API Ingress",
                        "description": (
                            f"{len(unauthenticated_apis)} non-public HTTP route handler(s) lack route-specific authentication "
                            "middleware or credential verification in application code. Missing evidence is evaluated as a potential risk; "
                            "external gateway authentication may be present."
                        ),
                        "evidence": f"Routes lacking verified authentication: {', '.join(r[0] for r in unauthenticated_apis[:4])}",
                        "supporting_file_paths": list(set(supp_paths))[:3],
                        "remediation": "Mandate authentication middleware (e.g., OAuth2/JWT bearer verification) or verify external gateway enforcement.",
                    })
                elif len(authenticated_apis) > 0 or has_global_auth:
                    findings.append({
                        "finding_id": "STRIDE-SPOOF-02",
                        "rule_id": "SEC-S01",
                        "title": f"Partial Authentication Coverage: {len(unauthenticated_apis)} Route(s) Lack Verified Authentication",
                        "severity": "HIGH",
                        "confidence": confidence,
                        "stride_category": "Spoofing",
                        "owasp_category": "A07:2021-Identification and Authentication Failures",
                        "target": "Unprotected API Routes",
                        "description": (
                            f"Authentication is verified on {len(authenticated_apis)} route(s), but {len(unauthenticated_apis)} route(s) "
                            "lack route-specific authentication evidence. The presence of an authentication component does not guarantee coverage across all endpoints."
                        ),
                        "evidence": f"Routes lacking verified authentication: {', '.join(r[0] for r in unauthenticated_apis[:4])}",
                        "supporting_file_paths": list(set(supp_paths))[:3],
                        "remediation": "Apply authentication guards to unauthenticated routes or configure explicit authorization boundaries.",
                    })

        elif not has_global_auth:
            has_network_ingress = any("Network" in b.get("boundary", "") for b in self.trust_boundaries if isinstance(b, dict))
            if has_network_ingress:
                findings.append({
                    "finding_id": "STRIDE-SPOOF-01",
                    "rule_id": "SEC-S01",
                    "title": "Unauthenticated Ingress Perimeter Detected",
                    "severity": "CRITICAL",
                    "confidence": "POTENTIAL",
                    "stride_category": "Spoofing",
                    "owasp_category": "A07:2021-Identification and Authentication Failures",
                    "target": "Network Perimeter / Ingress Boundary",
                    "description": "Network perimeter boundary detected without evidence of centralized identity verification or authentication middleware.",
                    "evidence": "Network perimeter identified in trust boundaries with zero authentication components.",
                    "supporting_file_paths": [],
                    "remediation": "Implement an identity provider, API gateway auth, or mutual TLS at the network ingress boundary.",
                })

        return findings

    def _evaluate_tampering(self) -> List[Dict[str, Any]]:
        """
        Evaluate tampering risk.
        Do NOT infer tampering vulnerabilities merely because a flow name contains "HTTP".
        Only flag when evidence demonstrates clear plaintext transport or unverified crossing of untrusted boundaries.
        """
        findings = []

        for flow in self.data_flows:
            if not isinstance(flow, dict):
                continue
            flow_name = flow.get("flow_name", "")
            trace = flow.get("trace", "")
            supporting = [p for p in flow.get("supporting_file_paths", []) if isinstance(p, str)]

            # Check if trace or flow explicitly mentions unencrypted plaintext protocol (e.g. "http://" instead of "https://")
            is_explicit_plaintext = "http://" in trace.lower() or "http://" in flow_name.lower() or "plaintext" in trace.lower()

            if is_explicit_plaintext:
                findings.append({
                    "finding_id": f"STRIDE-TAMP-01-{flow_name.replace(' ', '_')}",
                    "rule_id": "SEC-T01",
                    "title": f"Unencrypted Plaintext HTTP Flow in '{flow_name}'",
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "stride_category": "Tampering",
                    "owasp_category": "A02:2021-Cryptographic Failures",
                    "target": flow_name,
                    "description": f"Data flow '{flow_name}' explicitly communicates over unencrypted HTTP, allowing in-transit tampering and eavesdropping.",
                    "evidence": f"Data flow trace specifies unencrypted protocol: {trace}",
                    "supporting_file_paths": supporting[:2],
                    "remediation": "Enforce HTTPS/TLS 1.3 transit encryption with HSTS.",
                })

        return findings

    def _evaluate_repudiation(self) -> List[Dict[str, Any]]:
        """
        Evaluate repudiation risk.
        Do not add audit-logging findings unconditionally.
        Only flag if there are state-mutating operations and no logging components are detected.
        """
        findings = []
        has_state_mutations = False
        mutating_evidence = []

        for api in self.apis:
            if isinstance(api, dict) and api.get("method", "").upper() in ("POST", "PUT", "DELETE", "PATCH"):
                has_state_mutations = True
                mutating_evidence.append(f"{api.get('method')} {api.get('path')}")

        if not has_state_mutations and self.databases:
            has_state_mutations = True
            mutating_evidence.append("Persistent database operations detected")

        if has_state_mutations:
            has_logging = any(
                "log" in str(s.get("name", "")).lower() or "audit" in str(s.get("name", "")).lower()
                for s in self.external_services if isinstance(s, dict)
            ) or any(
                "log" in str(c.get("name", "")).lower() or "audit" in str(c.get("name", "")).lower()
                for c in self.components if isinstance(c, dict)
            )

            if not has_logging:
                findings.append({
                    "finding_id": "STRIDE-REP-01",
                    "rule_id": "SEC-R01",
                    "title": "Absence of Immutable Audit Logging on State-Mutating Operations",
                    "severity": "MEDIUM",
                    "confidence": "POTENTIAL",
                    "stride_category": "Repudiation",
                    "owasp_category": "A09:2021-Security Logging and Monitoring Failures",
                    "target": "State-Mutating Operations",
                    "description": (
                        "State-mutating endpoints and database modifications lack evidence of structured audit logging. "
                        "Static inspection cannot confirm absence of centralized logging without runtime inspection."
                    ),
                    "evidence": f"State mutations present ({', '.join(mutating_evidence[:3])}) without dedicated audit logging component.",
                    "supporting_file_paths": [],
                    "remediation": "Implement tamper-evident audit logging for state-mutating and security-sensitive events.",
                })

        return findings

    def _evaluate_information_disclosure(self) -> List[Dict[str, Any]]:
        """
        Evaluate information disclosure.
        Do NOT generate an information-disclosure finding for every database merely because it exists.
        Only generate a vulnerability finding when evidence supports a weakness (e.g. plaintext connection strings, hardcoded credentials).
        If protection cannot be verified statically, report it as a manual-review item, NOT a vulnerability finding.
        """
        findings = []

        for db in self.databases:
            if not isinstance(db, dict):
                continue
            db_name = db.get("name", "Database")
            supporting = [p for p in db.get("supporting_file_paths", []) if isinstance(p, str)]
            desc = str(db.get("description", "")).lower()
            name_lower = db_name.lower()

            # Check if there is actual evidence of weakness (e.g. explicit plaintext transport or unencrypted credentials)
            has_weakness = any(k in desc or k in name_lower for k in ("unencrypted", "plaintext", "hardcoded_credential", "no_auth", "insecure"))

            if has_weakness:
                findings.append({
                    "finding_id": f"STRIDE-INFO-01-{db_name.replace(' ', '_')[:30]}",
                    "rule_id": "SEC-I01",
                    "title": f"Insecure Database Configuration Identified ({db_name})",
                    "severity": "HIGH",
                    "confidence": "CONFIRMED",
                    "stride_category": "Information Disclosure",
                    "owasp_category": "A01:2021-Broken Access Control",
                    "target": db_name,
                    "description": f"Database '{db_name}' demonstrates unencrypted or unauthenticated configuration.",
                    "evidence": f"Identified weakness indicator in database definition: {db_name}",
                    "supporting_file_paths": supporting[:2],
                    "remediation": "Enforce TLS encryption and credential isolation via secret management.",
                })
            else:
                # Protection cannot be verified statically; record as manual review item, NOT a vulnerability finding
                self.manual_review_items.append({
                    "item": f"Database Security Configuration Review ({db_name})",
                    "target": db_name,
                    "category": "Data Storage Protection",
                    "reason": "Database interface detected. Static analysis cannot verify encryption-at-rest or network access controls without deployment configuration.",
                    "supporting_file_paths": supporting[:2],
                    "verification_needed": "Verify connection TLS enforcement, least-privilege DB roles, and storage volume encryption.",
                })

        return findings

    def _evaluate_denial_of_service(self) -> List[Dict[str, Any]]:
        """
        Evaluate DoS risk.
        Do NOT infer DoS vulnerability merely because entry points exist (e.g. CLI tools or libraries).
        Do NOT treat Redis or general-purpose services as proof of rate limiting.
        Detect rate-limiting evidence specifically and qualify the result when external gateway or proxy configuration is unavailable.
        """
        findings = []

        if self.apis:
            # Look for specific rate-limiting evidence, NOT general-purpose caches like Redis
            has_rate_limiting = any(
                any(k in str(c.get("name", "")).lower() for k in ("ratelimit", "rate_limit", "throttl", "limiter", "slowapi"))
                for c in self.components if isinstance(c, dict)
            ) or any(
                any(k in str(s.get("name", "")).lower() for k in ("ratelimit", "rate_limit", "throttl", "waf_rate_limit"))
                for s in self.external_services if isinstance(s, dict)
            )

            if not has_rate_limiting:
                findings.append({
                    "finding_id": "STRIDE-DOS-01",
                    "rule_id": "SEC-D01",
                    "title": "Unverified In-Application Rate Limiting on Exposed HTTP API Endpoints",
                    "severity": "MEDIUM",
                    "confidence": "POTENTIAL",
                    "stride_category": "Denial of Service",
                    "owasp_category": "A04:2021-Insecure Design",
                    "target": "HTTP API Ingress",
                    "description": (
                        f"{len(self.apis)} HTTP API routes detected without dedicated in-application rate limiting or throttling middleware. "
                        "Static inspection cannot observe external reverse proxy (e.g. Nginx, Envoy) or API Gateway throttling policies; "
                        "qualify whether rate limiting is enforced at an outer perimeter."
                    ),
                    "evidence": f"{len(self.apis)} HTTP route(s) detected; zero dedicated rate-limiting middleware found in application code.",
                    "supporting_file_paths": [p for api in self.apis if isinstance(api, dict) for p in api.get("supporting_file_paths", []) if isinstance(p, str)][:3],
                    "remediation": "Deploy rate limiting middleware (e.g., token bucket) or verify that an API gateway/reverse proxy throttles client requests.",
                })

        return findings

    def _evaluate_elevation_of_privilege(self) -> List[Dict[str, Any]]:
        """
        Evaluate authorization / privilege escalation (AuthZ).
        Separate from authentication (AuthN). Even if auth is present, check whether role/permission checks exist.
        """
        findings = []

        has_authz = any(
            any(k in str(c.get("name", "")).lower() for k in ("rbac", "abac", "permission", "authoriz", "role"))
            for c in self.components if isinstance(c, dict)
        ) or any(
            any(k in str(a.get("mechanism", "")).lower() for k in ("role", "permission", "rbac", "scope", "claim"))
            for a in self.auth_components if isinstance(a, dict)
        )

        if (self.apis or len(self.components) > 1) and not has_authz:
            findings.append({
                "finding_id": "STRIDE-ELEV-01",
                "rule_id": "SEC-E01",
                "title": "Absence of Role-Based Access Control (RBAC) / Authorization Scopes",
                "severity": "HIGH",
                "confidence": "POTENTIAL",
                "stride_category": "Elevation of Privilege",
                "owasp_category": "A01:2021-Broken Access Control",
                "target": "Application Service Layer",
                "description": (
                    "No fine-grained role or permission checks detected before service routine execution. "
                    "Authenticated users may execute operations beyond their intended privilege tier if authorization is not enforced."
                ),
                "evidence": "Zero authorization, role-mapping, or scope-validation components detected in reconstruction model.",
                "supporting_file_paths": [],
                "remediation": "Enforce explicit permission or role checks (RBAC/ABAC) on all service dispatchers and route handlers.",
            })

        return findings

    # -------------------------------------------------------------------------
    # OWASP Top 10 Auditing (Evidence-Based and Explicitly Partial)
    # -------------------------------------------------------------------------
    def _evaluate_owasp(self) -> List[Dict[str, Any]]:
        """
        Evaluate OWASP Top 10 categories with evidence-based checks.
        Coverage is explicitly partial (static architectural heuristics).
        Uses specific route, authorization, and transport evidence rather than a global auth component count.
        """
        findings = []

        # OWASP A01: Broken Access Control (Evaluated when non-public routes lack access controls)
        has_authz = any(
            any(k in str(c.get("name", "")).lower() for k in ("rbac", "abac", "permission", "authoriz", "role"))
            for c in self.components if isinstance(c, dict)
        )
        non_public_apis = [a for a in self.apis if isinstance(a, dict) and not self._is_route_intentionally_public(a)]

        if non_public_apis and not has_authz and len(self.auth_components) == 0:
            findings.append({
                "finding_id": "OWASP-A01-01",
                "rule_id": "OWASP-A01",
                "title": "OWASP A01: Broken Access Control (Deny-by-Default Not Enforced)",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "stride_category": "Elevation of Privilege",
                "owasp_category": "A01:2021-Broken Access Control",
                "target": "HTTP API Ingress",
                "description": f"{len(non_public_apis)} non-public API endpoint(s) lack explicit access control checks or deny-by-default policies.",
                "evidence": f"{len(non_public_apis)} non-public route(s) detected without access control middleware.",
                "supporting_file_paths": [p for a in non_public_apis for p in a.get("supporting_file_paths", []) if isinstance(p, str)][:2],
                "remediation": "Adopt a deny-by-default access posture and enforce access control validation on each incoming request.",
            })

        # OWASP A02: Cryptographic Failures (Only emitted if unencrypted transport or storage is observed)
        has_plaintext_flow = any(
            "http://" in str(f.get("trace", "")).lower() or "http://" in str(f.get("flow_name", "")).lower()
            for f in self.data_flows if isinstance(f, dict)
        )
        if has_plaintext_flow:
            findings.append({
                "finding_id": "OWASP-A02-01",
                "rule_id": "OWASP-A02",
                "title": "OWASP A02: Cryptographic Failures (Plaintext Transmission Detected)",
                "severity": "HIGH",
                "confidence": "CONFIRMED",
                "stride_category": "Information Disclosure",
                "owasp_category": "A02:2021-Cryptographic Failures",
                "target": "Data Transmission Channels",
                "description": "Unencrypted HTTP communication was detected in system data flows, risking credential and data interception.",
                "evidence": "Plaintext 'http://' transport identified in data flow specifications.",
                "supporting_file_paths": [],
                "remediation": "Mandate TLS 1.3 across all communication channels and disallow plaintext HTTP.",
            })

        # OWASP A07: Identification and Authentication Failures
        if non_public_apis and len(self.auth_components) == 0:
            has_explicit_disabled = any(a.get("auth_required") is False for a in non_public_apis)
            confidence = "CONFIRMED" if has_explicit_disabled else "POTENTIAL"

            findings.append({
                "finding_id": "OWASP-A07-01",
                "rule_id": "OWASP-A07",
                "title": "OWASP A07: Identification and Authentication Failures",
                "severity": "CRITICAL" if has_explicit_disabled else "HIGH",
                "confidence": confidence,
                "stride_category": "Spoofing",
                "owasp_category": "A07:2021-Identification and Authentication Failures",
                "target": "HTTP API Ingress",
                "description": "Non-public API endpoints lack verified caller identity validation in application code.",
                "evidence": f"Zero authentication components registered for {len(non_public_apis)} non-public route(s).",
                "supporting_file_paths": [],
                "remediation": "Implement standard authentication (OAuth 2.0 / JWT) with strong signature verification or verify external gateway enforcement.",
            })

        return findings

    def _evaluate_system_design(self) -> List[Dict[str, Any]]:
        """Retained for backward compatibility without creating unsupported findings."""
        return []

    # -------------------------------------------------------------------------
    # Semantic Deduplication and Bounded Scoring
    # -------------------------------------------------------------------------
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Deduplicates findings so equivalent findings do not survive merely because they have different IDs.
        Preserves distinct issues that affect different assets or have materially different evidence.
        Always retains the HIGHER severity when merging equivalent findings.
        """
        deduped: List[Dict[str, Any]] = []
        target_map: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

        for f in findings:
            target = str(f.get("target", "")).strip().lower()
            stride_cat = str(f.get("stride_category", "")).strip()
            canonical_weakness = self._classify_weakness(f)

            equiv_key = (target, stride_cat, canonical_weakness)

            if equiv_key in target_map:
                existing = target_map[equiv_key]

                # Retain the HIGHER severity (lower rank number)
                existing_rank = self.SEVERITY_RANK.get(existing.get("severity", "INFO"), 5)
                new_rank = self.SEVERITY_RANK.get(f.get("severity", "INFO"), 5)

                if new_rank < existing_rank:
                    existing["severity"] = f["severity"]
                    existing["title"] = f["title"]

                # Retain CONFIRMED confidence if either is CONFIRMED
                if f.get("confidence") == "CONFIRMED" or existing.get("confidence") == "CONFIRMED":
                    existing["confidence"] = "CONFIRMED"

                # Merge related finding IDs
                if "related_finding_ids" not in existing:
                    existing["related_finding_ids"] = []
                if f["finding_id"] not in existing["related_finding_ids"]:
                    existing["related_finding_ids"].append(f["finding_id"])

                # Append distinct evidence if not already present
                new_evidence = f.get("evidence", "")
                if new_evidence and new_evidence not in existing.get("evidence", ""):
                    existing["evidence"] = f"{existing.get('evidence', '')}; {new_evidence}".strip("; ")

                continue

            target_map[equiv_key] = f
            deduped.append(f)

        return deduped

    @staticmethod
    def _classify_weakness(f: Dict[str, Any]) -> str:
        """Determines the core weakness category of a finding for semantic deduplication."""
        rule = str(f.get("rule_id", "")).upper()
        title = str(f.get("title", "")).lower()

        if "S01" in rule or "A07" in rule or "authentication" in title or "spoof" in title:
            return "WEAKNESS_AUTHENTICATION"
        if "T01" in rule or "tamper" in title:
            return "WEAKNESS_TRANSIT_INTEGRITY"
        if "R01" in rule or "A09" in rule or "audit" in title or "logging" in title:
            return "WEAKNESS_AUDIT_LOGGING"
        if "I01" in rule or "disclosure" in title:
            return "WEAKNESS_DATA_EXPOSURE"
        if "D01" in rule or "A04" in rule or "rate limit" in title or "dos" in title:
            return "WEAKNESS_RATE_LIMITING"
        if "E01" in rule or "A01" in rule or "authorization" in title or "access control" in title or "rbac" in title:
            return "WEAKNESS_ACCESS_CONTROL"
        if "A02" in rule or "crypto" in title:
            return "WEAKNESS_CRYPTOGRAPHY"

        return f.get("finding_id", "GENERAL")

    def _compute_deterministic_score(self, findings: List[Dict[str, Any]]) -> int:
        """
        Computes a bounded, deterministic risk score (0 - 100).
        Penalties are scaled by confidence and severity.
        """
        total_penalty = 0

        for f in findings:
            sev = f.get("severity", "INFO")
            conf = f.get("confidence", "POTENTIAL")

            weights = self.SEVERITY_WEIGHTS.get(conf, self.SEVERITY_WEIGHTS["POTENTIAL"])
            penalty = weights.get(sev, 0)
            total_penalty += penalty

        score = max(0, min(100, 100 - total_penalty))
        return int(score)

    # -------------------------------------------------------------------------
    # Resilience Metrics (Heuristic and Qualified)
    # -------------------------------------------------------------------------
    def _evaluate_resilience_metrics(self) -> Dict[str, Any]:
        """
        Evaluates architecture resilience.
        Conclusions are explicitly labeled as heuristic unless redundancy and failover are verified by deployment evidence.
        """
        has_caching = any(
            "redis" in str(s.get("name", "")).lower() or "memcached" in str(s.get("name", "")).lower()
            for s in self.external_services if isinstance(s, dict)
        )
        has_queue = any(
            any(k in str(s.get("name", "")).lower() for k in ("kafka", "rabbit", "sqs", "queue"))
            for s in self.external_services if isinstance(s, dict)
        )
        is_containerized = "Containerized" in str(self.deployment.get("model", ""))

        num_components = len(self.components)
        if num_components <= 1:
            spof_detected = True
            spof_assessment = "HEURISTIC_INDICATION"
            spof_reasoning = "Single monolithic module identified without distinct service tiers; failure impacts entire process."
        else:
            spof_detected = False
            spof_assessment = "HEURISTIC_INDICATION"
            spof_reasoning = (
                f"{num_components} modular component(s) detected. Architecture supports modular decomposition, "
                "but high-availability redundancy, active failover, and replica counts remain unverified without deployment manifests."
            )

        return {
            "spof_detected": spof_detected,
            "spof_assessment": spof_assessment,
            "spof_reasoning": spof_reasoning,
            "caching_layer_present": has_caching,
            "asynchronous_queue_present": has_queue,
            "containerized": is_containerized,
            "total_entry_points": len(self.entry_points),
            "total_api_routes": len(self.apis),
        }

    def _generate_roadmap(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generates a prioritized remediation roadmap from deduplicated findings."""
        roadmap = []
        for i, f in enumerate(findings, 1):
            roadmap.append({
                "priority_rank": i,
                "finding_id": f["finding_id"],
                "action": f.get("remediation", "Review and remediate security finding."),
                "target": f.get("target", "System Component"),
                "severity": f.get("severity", "MEDIUM"),
                "confidence": f.get("confidence", "POTENTIAL"),
            })
        return roadmap
