# Multi-Phase System Design & Security Pipeline

An automated multi-phase software engineering and defensive security pipeline.

---

## 🧭 Pipeline Architecture

```plaintext
                   ┌────────────────────────────────────────┐
                   │   Input: GitHub URL / ZIP / Directory  │
                   └───────────────────┬────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 0: Repository Ingestion Agent (src/phase0/ingestion.py)               │
│ • Safe ZIP extraction (zip-slip & bomb prevention) & Git shallow cloning    │
│ • Vendor & cache exclusion filtering (node_modules, .git, __pycache__)     │
│ • Language, framework & dependency manifest categorization                  │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 0 Inventory JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 1: Project Reconstruction Agent (src/phase1/reconstruction.py)        │
│ • Component boundaries & architectural pattern classification               │
│ • Entry point & HTTP API route discovery                                    │
│ • Data flow tracing & Trust boundary modeling                               │
│ • Evidence classification (DOCUMENTED, CODE_SUPPORTED, INFERRED, UNKNOWN)   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 1 Reconstruction JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 2: Requirements & Threat Modeling (src/phase2/requirements.py,        │
│                                          src/phase2/assessment.py)          │
│ • Functional, Security, Non-Functional, and Business Constraints            │
│ • STRIDE Threat Modeling & OWASP Top 10 compliance evaluation              │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 2 Specifications JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 3A: Red Team Security Analysis Agent (src/phase3a/red_team.py)        │
│ • Attack-surface mapping across entry points, inputs, and boundaries        │
│ • In-depth vulnerability audit across 18 security dimensions               │
│ • Empirical reachability tracing & strict status validation                 │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 3A Validated Findings JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 4A: Blue Team Defensive Analysis Agent (src/phase4a/blue_team.py)     │
│ • Root-cause analysis on all validated Red Team findings                    │
│ • Defense-in-depth remediation plans & minimal blast radius fixes           │
│ • Hardening controls & automated regression risk assessments                │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 4A Defensive Remediation JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 5A: Security Retest Agent (src/phase5a/retest.py)                     │
│ • Empirical verification of active code against original attack paths       │
│ • Definitive status assignment (REMEDIATED, PARTIALLY_REMEDIATED, etc.)     │
│ • Remaining risk identification and regression validation                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 5A Retest Results JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 6: Code Smell & Maintainability Agent (src/phase6/code_smells.py)     │
│ • Static quality analysis across 18 maintainability and smell dimensions    │
│ • Cognitive & cyclomatic complexity auditing with justification rules       │
│ • Targeted refactoring strategies and maintenance impact evaluation         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 6 Code Smells JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 7: Cross-Domain Analysis Agent (src/phase7/cross_domain.py)           │
│ • Multi-dimensional synthesis between Security, Code Quality, and Scale     │
│ • Performance vs. security trade-off modeling (e.g. pre-scan overhead)      │
│ • Architecture vs. maintainability coupling & dependency analysis           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 7 Cross-Domain JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 8: Recommendation Engine Agent (src/phase8/recommendations.py)        │
│ • Evidence-backed, prioritized engineering recommendations (REC-01..REC-06) │
│ • Explicit trade-offs, complexity scoring, and non-breaking mitigations     │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ Phase 8 Recommendations JSON
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ PHASE 9: Final Report Generator Agent (src/phase9/report.py)                │
│ • Audit-grade Markdown and JSON final software analysis report              │
│ • Epistemological rigor (FACT, INFERENCE, ANALYSIS, RECOMMENDATION, UNKNOWN)│
│ • Requirement ↔ Implementation Matrix and full trace validation             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Execution Commands

```bash
# Run full pipeline end-to-end (Phase 0 -> Phase 1 -> ... -> Phase 9)
python pipeline.py --source . --phase all

# Run Phase 0 only: Repository structural inventory
python pipeline.py --source . --phase 0

# Run Phase 1 only: Project reconstruction
python pipeline.py --source . --phase 1

# Run Phase 2 only: Requirements extraction
python pipeline.py --source . --phase 2

# Run Phase 3A only: Red Team attack surface & vulnerability discovery
python pipeline.py --source . --phase 3a

# Run Phase 4A only: Blue Team root-cause analysis & remediation planning
python pipeline.py --source . --phase 4a

# Run Phase 5A only: Security retest verification
python pipeline.py --source . --phase 5a

# Run Phase 6 only: Code smell & maintainability quality analysis
python pipeline.py --source . --phase 6

# Run Phase 7 only: Cross-domain interaction analysis
python pipeline.py --source . --phase 7

# Run Phase 8 only: Senior recommendation engine
python pipeline.py --source . --phase 8

# Run Phase 9 only: Final report generator (Markdown format)
python pipeline.py --source . --phase 9 --format markdown

# Output results directly to a JSON or Markdown file
python pipeline.py --source . --phase 9 --format markdown --output final_report.md
python pipeline.py --source . --phase all --output full_pipeline_results.json
```

---

## 🧪 Testing

```bash
python -m unittest discover tests
```
