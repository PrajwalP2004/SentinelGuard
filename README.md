# 🛡️ SentinelGuard — Multi-Phase System Design & Security Pipeline

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-brightgreen)
![Architecture](https://img.shields.io/badge/Pipeline-10--Phase%20Agentic-orange)
![Tests](https://img.shields.io/badge/Unit%20Tests-378%20Tests-success)

**SentinelGuard** is an automated repository security and code quality analysis tool that uses a deterministic **10-phase agent-based architecture**—built strictly on the Python 3 standard library with **zero external dependencies**—to analyze software projects, detect vulnerabilities, identify code smells, statically verify security fixes, and generate prioritized recommendations with comprehensive audit reports in **JSON** and **Markdown**.

---

## ✨ Key Highlights

* **Zero External Dependencies:** Implemented 100% with Python's built-in standard library (`ast`, `re`, `zipfile`, `http.server`, `subprocess`, `json`)—no `pip install`, external databases, or cloud LLM APIs required, ensuring full source-code privacy and zero supply-chain risk.
* **Hardened Repository Ingestion:** Protects the host system against **Zip-Slip** path traversal, **decompression bombs** (size, compression ratio, and file count limits), and **Git CLI option injection**.
* **Closed-Loop Security Auditing:** Pairs offensive vulnerability discovery (**Red Team**) with root-cause remediation plans (**Blue Team**) and automated static verification (**Security Retest**).
* **Cross-Domain Risk Correlation:** Connects maintainability defects (such as silent exception handling or deep nesting) to security blind spots and scalability bottlenecks.
* **Epistemic Rigor:** Every statement in the final audit report is explicitly classified (`FACT`, `INFERENCE`, `ANALYSIS`, `RECOMMENDATION`, `UNKNOWN`) to distinguish verified code facts from heuristic inferences.

---

## 🧭 Pipeline Architecture

```text
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

## ⚙️ Prerequisites & Setup

* **Python:** Python 3.10 or higher (Python 3.12 recommended)
* **Git CLI:** Required only when scanning remote GitHub repository URLs
* **Third-Party Packages:** None (`0` external dependencies)

```bash
git clone <your-repository-url>
cd SentinelGuard
```

---

## 🖥️ Web Dashboard

Launch the local interactive dashboard to run scans, track phase-by-phase progress, inspect KPI cards, and view rendered audit reports in your browser:

```bash
python gui.py --port 8080
```

Then open `http://localhost:8080` in your browser.

---

## 🚀 CLI Execution Commands

### Full Pipeline & Report Export
```bash
# Run full pipeline end-to-end (Phase 0 -> Phase 1 -> ... -> Phase 9)
python pipeline.py --source . --phase all

# Output full pipeline results directly to JSON
python pipeline.py --source . --phase all --output full_pipeline_results.json

# Generate final audit report in Markdown and save to file
python pipeline.py --source . --phase 9 --format markdown --output final_report.md
```

### Individual Phase Execution
```bash
# Run Phase 0 only: Repository structural inventory
python pipeline.py --source . --phase 0

# Run Phase 1 only: Project reconstruction
python pipeline.py --source . --phase 1

# Run Phase 2 only: Requirements extraction & threat modeling
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
```

---

## 📂 Repository Structure

```text
SentinelGuard/
├── pipeline.py                  # CLI entry point & deterministic DAG orchestrator
├── gui.py                       # Local HTTP server & REST API (/api/run, /api/health)
├── frontend/                    # Zero-dependency Web UI (HTML5, CSS3, Vanilla JS)
├── src/
│   ├── phase0/ingestion.py      # Safe ZIP/Git/directory ingestion & inventory
│   ├── phase1/reconstruction.py # Route, entry-point & trust boundary modeling
│   ├── phase2/                  # Requirements extraction & STRIDE assessment
│   ├── phase3a/red_team.py      # 18 AST & regex security vulnerability checkers
│   ├── phase4a/blue_team.py     # Root-cause diagnosis & remediation blueprints
│   ├── phase5a/retest.py        # Static verification of defensive controls
│   ├── phase6/code_smells.py    # 18 Python AST maintainability & complexity rules
│   ├── phase7/cross_domain.py   # Security ↔ Maintainability ↔ Performance correlation
│   ├── phase8/recommendations.py  # Severity- and confidence-weighted prioritization
│   └── phase9/report.py         # Epistemic Markdown & JSON report compiler
└── tests/                       # Automated unittest suite (378 unit tests)
```

---

## 🧪 Testing

Run the full automated test suite using Python's built-in `unittest` runner:

```bash
python -m unittest discover tests
```

---

## 📌 Scope & Current Boundaries

* **Static Analysis Only:** SentinelGuard analyzes source code via AST parsing and lexical rules without executing target applications or running live exploit payloads.
* **Language Coverage:** Repository ingestion supports multi-language projects, while deep AST code-smell analysis (Phase 6) currently targets Python (`.py`) files.
* **Local Web Server:** `gui.py` runs on Python's single-threaded `http.server` and is designed for local workstation or CI/CD usage rather than multi-tenant public hosting.
