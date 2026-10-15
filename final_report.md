# PHASE 9 — FINAL SOFTWARE ARCHITECTURE AND SECURITY REPORT

> ### 🎯 Target Repository Audited: **Multi-Phase System Design & Security Pipeline**
> **Application Type**: Client-Side Frontend Application | **Languages**: CSS, HTML, JavaScript, Markdown, Python | **Files Discovered**: 41

> ### 📖 Plain-English Guide to the Tags in This Report
> Every key point in this report is clearly labeled so you always know where the information comes from:
> - **[FACT]**: Directly proven by looking at real code files in this project.
> - **[INFERENCE]**: An educated conclusion based on file names, folders, or coding patterns.
> - **[ANALYSIS]**: Calculated or diagnosed by our automated scanners.
> - **[RECOMMENDATION]**: A practical, friendly suggestion for the engineering team.
> - **[UNKNOWN]**: Something that cannot be confirmed without running the code on a live internet server or when data is missing.

## 1. EXECUTIVE SUMMARY

### 1.1 What This Software Does
- **[FACT]**: **Multi-Phase System Design & Security Pipeline** is a **Client-Side Frontend Application**. Based on project documentation and code structure: *An automated multi-phase software engineering and defensive security pipeline.* Repository inventory identified **41 file(s)** associated with **CSS, HTML, JavaScript, Markdown, Python**.

### 1.2 How the System Is Built (Architecture)
- **[FACT]**: **Command-Line Tool Architecture**: The codebase is organized into **3 main functional components**, with **0 web API routes**, and **5 database persistence layers**.

### 1.3 What Our System Analyzed for Improvements (The Scope of Analysis)
The automated pipeline is configured to evaluate repositories across 6 primary engineering and security domains. Below is the verified audit scope and analysis coverage for **Multi-Phase System Design & Security Pipeline** based on available execution metadata:

- **Static File Inspection Coverage**: [FACT] Security scanners inspected **21 file(s)** (0 file(s) skipped based on size or path filters).

1. **🌐 Web API & Ingress Safety**:
   - *Configured checks*: Ingress parameter sanitization, injection flaws (SQL, command, path traversal), and input boundary validation.
   - *Verified scope*: Evaluated 0 registered HTTP route(s) and 5 entry point candidate(s) from architectural reconstruction.
   - *Analysis findings*: Available results indicate 2 ingress-related security finding(s).

2. **🗄️ Database Queries & Persistence Layer**:
   - *Configured checks*: Parameterized prepared statements versus dynamic string concatenation, database credentials, and query safety.
   - *Verified scope*: Evaluated 5 detected persistence layer(s) from architectural reconstruction.
   - *Analysis findings*: Available results indicate 0 database security finding(s).

3. **🔐 Credential Leakage & Secrets Management**:
   - *Configured checks*: Pattern and entropy scanning for hardcoded secrets, private cryptographic keys, API tokens, and plaintext credentials.
   - *Verified scope*: Evaluated candidate configuration files (0) and sensitive candidate files (0) identified in repository inventory.
   - *Analysis findings*: Available results indicate 0 credential-related finding(s).

4. **🛡️ Runtime Configuration & Operational Security**:
   - *Configured checks*: Audit of framework execution flags (`debug=True`), permissive CORS policies (`origins='*'`), and weak legacy hash algorithms (MD5/SHA1).
   - *Verified scope*: Evaluated repository operational files; no external web frameworks detected in manifests.
   - *Analysis findings*: Available results indicate 1 configuration/operational finding(s).

5. **🧩 Code Maintainability & AST Code Smells**:
   - *Configured checks*: Static AST parsing for long methods, deep block nesting (>3 levels), silent exception swallowing (`except Exception: pass`), and cyclomatic complexity.
   - *Verified scope*: Static maintainability analysis executed against candidate Python source files (0 scan diagnostic(s) recorded). Parser execution is verified only where AST parsing completed successfully.
   - *Analysis findings*: Available results identify 211 code smell(s) in parsed Python routines.

6. **🔄 Cross-Domain Interactions & Engineering Trade-offs**:
   - *Configured checks*: Synthesis of cross-domain impacts and trade-offs between security controls, code maintainability, and operational performance.
   - *Verified scope*: Evaluated 6 specific cross-domain interaction category pair(s).
   - *Analysis findings*: Available results produced 5 verified cross-domain relationship(s).

*(Note: The consolidated Master Summary Table / Executive Action Matrix has been shifted to the conclusion of this report in Section 13.)*

## 2. PROJECT UNDERSTANDING (HOW THE SYSTEM WORKS)

- **Purpose**: [FACT] An automated multi-phase software engineering and defensive security pipeline.
- **Who Uses It**: [INFERENCE] Software developers, systems engineers, and technical auditors.
- **The Main Pieces (Components)**: [FACT]
  - **Root Application Module**: Contains application logic and source files for root. (Files: `gui.py, ingest.py, pipeline.py`)
  - **Src**: Contains application logic and source files for src. (Files: `src/phase0/ingestion.py, src/phase0/__init__.py, src/phase1/reconstruction.py`)
  - **Web**: Contains application logic and source files for web. (Files: `web/app.js, web/index.html, web/style.css`)
- **Technologies Used**: [FACT] CSS, HTML, JavaScript, Markdown, Python
- **Web APIs**: [FACT] Standalone library or script-based workflow (no HTTP web routes registered).
- **Databases & Data Storage**: [FACT] 5 storage layer(s):
  - ORM / Database Access (prisma): `src/phase0/ingestion.py`
  - ORM / Database Access (sqlite3): `src/phase1/reconstruction.py`
  - ORM / Database Access (cursor.execute): `src/phase3a/red_team.py`
  - ORM / Database Access (SQLAlchemy): `src/phase4a/blue_team.py`
  - ORM / Database Access (sqlite3): `src/phase8/recommendations.py`
- **Deployment Model**: [FACT] Standalone Process Execution — Runs natively in the host language runtime environment.

## 3. REQUIREMENTS (WHAT THE SYSTEM MUST DO)

### Functional Rules (What Features It Must Have)
- `REQ-FUNC-01` [FACT - Explicit]: The system must support Command Line Execution: Invoke the application via terminal flags to perform project operations.
- `REQ-FUNC-02` [FACT - Explicit]: The system must provide a Command Line Interface (CLI) for parsing user arguments and dispatching execution.

### Security Rules (How It Keeps Itself Safe)
- `REQ-SEC-01` [FACT - Code Supported]: Archive member path validation logic detected prior to extraction (observed implementation code; dynamic verification required for complete edge-case safety).
- `REQ-SEC-02` [FACT - Code Supported]: The system must verify caller identity and authenticate requests before granting access to protected operations.
- `REQ-SEC-03` [FACT - Code Supported]: The application loads configuration and secrets via environment variables or secret stores (observed implementation behavior).
- `REQ-SEC-04` [FACT - Code Supported]: The system enforces secure communication channels using TLS with certificate validation (observed implementation behavior).

### Maintainability & Quality Rules
- `REQ-NFR-01` [FACT - Code Supported]: The software executes cross-platform on Windows and POSIX operating systems, handling path separators safely (observed implementation behavior).
- `REQ-NFR-02` [UNKNOWN - Unverified]: External dependency constraints cannot be established due to absence of dependency manifests.
- `REQ-NFR-03` [FACT - Explicit]: The system must output deterministic, contract-conforming JSON schemas for integration.
- `REQ-NFR-04` [FACT - Code Supported]: The technical architecture executes under: Standalone Process Execution (technical deployment architecture).

## 4. RED TEAM SECURITY ASSESSMENT (ETHICAL HACKER AUDIT)

Our automated ethical hacker agent checked the application for security vulnerabilities. Here is what was found:

### Vulnerability: `RED-INJ-01` — Subprocess Option Injection via Unsanitized Git Clone Parameter
- **What Is the Issue?**: [ANALYSIS] Subprocess Option Injection via Unsanitized Git Clone Parameter
- **Where Could an Attacker Attack?**: [ANALYSIS] CLI --source argument or Git Clone Ingestion
- **Which File Was Affected?**: [FACT] `src/phase8/recommendations.py`
- **Proof in the Code**: [FACT] Git clone invocation '"recommended_change": plan_remediation or "Pass arguments as tokenized argument lists (subprocess.run(['cmd', arg1], shell=False)) and validate all input parameters.",' passes arguments without '--' option terminator or leading-hyphen validation at line 1087.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An attacker supplies a source URL starting with options (e.g., --upload-pack, -u, --config), triggering option injection or command execution.
- **What Harm Could It Cause?**: [ANALYSIS] Arbitrary command execution or Git configuration manipulation in the process context.
- **Danger Level (Severity)**: [ANALYSIS] **CRITICAL**
- **Confidence Level**: [ANALYSIS] **HIGH**
- **Current Status**: [FACT] **PROBABLE**

### Vulnerability: `RED-DESER-01` — Insecure Object Deserialization via Python Pickle / Joblib
- **What Is the Issue?**: [ANALYSIS] Insecure Object Deserialization via Python Pickle / Joblib
- **Where Could an Attacker Attack?**: [ANALYSIS] Object Deserialization Pipeline
- **Which File Was Affected?**: [FACT] `src/phase8/recommendations.py`
- **Proof in the Code**: [FACT] Deserialization routine '"current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Model files are deserialized directly from disk using joblib.load() without integrity verification.",' identified at line 1118. Data provenance: untrusted ingress stream.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An attacker provides a crafted pickled object with __reduce__ hooks to execute arbitrary Python bytecode.
- **What Harm Could It Cause?**: [ANALYSIS] Remote code execution in the context of the server process.
- **Danger Level (Severity)**: [ANALYSIS] **HIGH**
- **Confidence Level**: [ANALYSIS] **MEDIUM**
- **Current Status**: [FACT] **PROBABLE**

### Vulnerability: `RED-DOS-01` — Uncontrolled Resource Consumption via Archive Decompression (Zip Bomb)
- **What Is the Issue?**: [ANALYSIS] Uncontrolled Resource Consumption via Archive Decompression (Zip Bomb)
- **Where Could an Attacker Attack?**: [ANALYSIS] Archive Ingestion Subsystem
- **Which File Was Affected?**: [FACT] `src/phase2/requirements.py`
- **Proof in the Code**: [FACT] Extraction call 'has_archive_op = any(kw in content for kw in ("zipfile.ZipFile", "tarfile.open", ".extractall(", ".extract("))' at line 395 lacks cumulative uncompressed size and member-count limits in function '_inspect_archive_extraction_safety'.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An attacker uploads a highly compressed archive that expands into gigabytes of data.
- **What Harm Could It Cause?**: [ANALYSIS] Disk space exhaustion or denial of service crash.
- **Danger Level (Severity)**: [ANALYSIS] **HIGH**
- **Confidence Level**: [ANALYSIS] **HIGH**
- **Current Status**: [FACT] **PROBABLE**

### Vulnerability: `RED-FILE-02` — Potential Symlink Traversal during Archive Extraction
- **What Is the Issue?**: [ANALYSIS] Potential Symlink Traversal during Archive Extraction
- **Where Could an Attacker Attack?**: [ANALYSIS] Archive Member Mode Inspection
- **Which File Was Affected?**: [FACT] `src/phase2/requirements.py`
- **Proof in the Code**: [FACT] Member extraction 'def _inspect_archive_extraction_safety(self) -> Optional[Dict[str, Any]]:' at line 383 checks paths but does not explicitly reject symlink modes in function '_inspect_archive_extraction_safety'.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An archive with a symbolic link target pointing outside sandbox permits writing outside target directory.
- **What Harm Could It Cause?**: [ANALYSIS] Arbitrary file modification outside extraction sandbox.
- **Danger Level (Severity)**: [ANALYSIS] **HIGH**
- **Confidence Level**: [ANALYSIS] **MEDIUM**
- **Current Status**: [FACT] **POSSIBLE**

### Vulnerability: `RED-SSRF-01` — Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request
- **What Is the Issue?**: [ANALYSIS] Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request
- **Where Could an Attacker Attack?**: [ANALYSIS] Outbound HTTP Client Integration
- **Which File Was Affected?**: [FACT] `src/phase0/ingestion.py`
- **Proof in the Code**: [FACT] Outbound HTTP call 'with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp:' at line 283 takes variable without verified destination allowlist.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An attacker supplies internal loopback (127.0.0.1) or cloud metadata (169.254.169.254) addresses.
- **What Harm Could It Cause?**: [ANALYSIS] Cloud credential theft or internal service network scanning.
- **Danger Level (Severity)**: [ANALYSIS] **HIGH**
- **Confidence Level**: [ANALYSIS] **MEDIUM**
- **Current Status**: [FACT] **POSSIBLE**

### Vulnerability: `RED-DOS-02` — Unbounded File Read in Application Ingestion Routine
- **What Is the Issue?**: [ANALYSIS] Unbounded File Read in Application Ingestion Routine
- **Where Could an Attacker Attack?**: [ANALYSIS] Filesystem / Ingestion File Reading
- **Which File Was Affected?**: [FACT] `gui.py`
- **Proof in the Code**: [FACT] Unbounded read operation 'content = f.read()' at line 67 lacks prior size validation or byte limit.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An attacker supplies a multi-gigabyte file, causing memory exhaustion during read.
- **What Harm Could It Cause?**: [ANALYSIS] Process memory exhaustion (OOM crash) and denial of service.
- **Danger Level (Severity)**: [ANALYSIS] **MEDIUM**
- **Confidence Level**: [ANALYSIS] **HIGH**
- **Current Status**: [FACT] **PROBABLE**

### Vulnerability: `RED-CRYPTO-01` — Use of Cryptographically Weak Hash Algorithm (MD5/SHA-1)
- **What Is the Issue?**: [ANALYSIS] Use of Cryptographically Weak Hash Algorithm (MD5/SHA-1)
- **Where Could an Attacker Attack?**: [ANALYSIS] Cryptographic Hashing Subsystem
- **Which File Was Affected?**: [FACT] `src/phase8/recommendations.py`
- **Proof in the Code**: [FACT] Hash invocation '"implementation_complexity": "LOW (replacing hashlib.md5 with hashlib.sha256).",' at line 1221: MD5/SHA-1 algorithm detected with ambiguous context; verify whether hash collisions affect security boundaries.
- **How Could an Attacker Exploit This?**: [ANALYSIS] Non-adversarial hash collision in cache key.
- **What Harm Could It Cause?**: [ANALYSIS] Low-impact non-security hash collision.
- **Danger Level (Severity)**: [ANALYSIS] **LOW**
- **Confidence Level**: [ANALYSIS] **MEDIUM**
- **Current Status**: [FACT] **POSSIBLE**

### Vulnerability: `RED-INFO-01` — Unrestricted Local Directory Ingestion in CLI Interface
- **What Is the Issue?**: [ANALYSIS] Unrestricted Local Directory Ingestion in CLI Interface
- **Where Could an Attacker Attack?**: [ANALYSIS] CLI --source parameter with local directory type
- **Which File Was Affected?**: [FACT] `src/phase0/ingestion.py`
- **Proof in the Code**: [FACT] Directory ingestion 'elif source_type in ("dir", "local", "filesystem"):' at line 454 allows operator to scan arbitrary local folders.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An operator specifies an arbitrary directory to inventory files.
- **What Harm Could It Cause?**: [ANALYSIS] Normal CLI file enumeration (intended tool behavior; verify if workspace restriction is required).
- **Danger Level (Severity)**: [ANALYSIS] **LOW**
- **Confidence Level**: [ANALYSIS] **LOW**
- **Current Status**: [FACT] **POSSIBLE**

### Vulnerability: `RED-INFO-02` — Internal Host Filesystem Path Embedded in Contract Output
- **What Is the Issue?**: [ANALYSIS] Internal Host Filesystem Path Embedded in Contract Output
- **Where Could an Attacker Attack?**: [ANALYSIS] Exported JSON Output Contract
- **Which File Was Affected?**: [FACT] `src/phase0/ingestion.py`
- **Proof in the Code**: [FACT] Root filesystem path embedded in output schema '"root_path": root_path,' at line 788.
- **How Could an Attacker Exploit This?**: [ANALYSIS] An external consumer reviews exported JSON output to discover internal directory structure and usernames.
- **What Harm Could It Cause?**: [ANALYSIS] Low-impact internal environment enumeration.
- **Danger Level (Severity)**: [ANALYSIS] **LOW**
- **Confidence Level**: [ANALYSIS] **MEDIUM**
- **Current Status**: [FACT] **POSSIBLE**

## 5. BLUE TEAM DEFENSIVE ASSESSMENT (HOW TO FIX THEM)

The defensive team analyzed the root cause of every vulnerability and designed solid, permanent fixes:

### Defense Plan for `RED-INJ-01`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Git clone invocation passes user-controlled source parameter directly to subprocess.run without leading-hyphen validation or positional argument disambiguation ('--' separator). Git interprets leading dashes as CLI flags.
- **The Fix to Apply**: [RECOMMENDATION] Validate that the repository source string does not begin with '-' or '--'. In the git clone command array, place the standard '--' option separator immediately before the repository source argument to force Git to interpret it as a positional argument. Validate URL schemes to permit only approved protocols (such as https://, ssh://, or http://), and set GIT_TERMINAL_PROMPT=0 to prevent interactive hangs.
- **Concrete Code Changes**: [RECOMMENDATION] `Validate repository source at function entry: reject strings beginning with '-' or '--' before invoking Git.; Format git clone arguments using the option separator: ['git', 'clone', '--depth', '1', '--', source_url, target_dir].; Set environment variable GIT_TERMINAL_PROMPT=0 and enforce allowed protocol schemes (e.g., https://, git@).`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Execute git processes with non-interactive timeouts and bounded execution time.; Confine git clone operations to isolated scratch directories.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Valid repository URLs starting with standard protocols remain unaffected; only flag-like strings are blocked.
- **How to Test It**: [FACT] Unit test verifying inputs starting with '--' or '-' raise immediate validation errors.; Unit test confirming standard HTTPS and SSH repository URLs clone successfully with the '--' separator in place.

### Defense Plan for `RED-DESER-01`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Direct deserialization of pickle or joblib data from untrusted or unauthenticated sources permits arbitrary object construction.
- **The Fix to Apply**: [RECOMMENDATION] Never deserialize untrusted pickle or joblib data. For structured data or tensor weights, migrate to safer, constrained serialization formats appropriate to the data type (e.g., JSON, Protocol Buffers, SafeTensors for model weights, or ONNX for computational graphs). Where serialized artifacts must be loaded, establish authenticity before deserialization using a trusted digital signature (asymmetric cryptography) or securely managed HMAC key; an ordinary unauthenticated SHA-256 checksum does not establish trust, as an attacker with write access can replace both the artifact and checksum.
- **Concrete Code Changes**: [RECOMMENDATION] `Migrate model artifacts to constrained, format-specific standards (e.g. SafeTensors for neural network weights) where applicable.; If pickle-based deserialization is strictly required, verify digital signatures or HMAC with protected keys prior to calling pickle/joblib.; Enforce strict filesystem write permissions on model storage directories.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Run artifact loading and model inference in an isolated process sandbox with dropped privileges.; Audit model dependencies and enforce supply-chain artifact provenance.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Migrating serialization formats may require model re-export scripts and updates to downstream loaders.; Cryptographic signature verification requires key distribution and management infrastructure.
- **How to Test It**: [FACT] Unit test verifying tampered or unsigned model artifacts fail authenticity verification and are not loaded.; Unit test verifying validly signed artifacts load correctly under the target runtime.

### Defense Plan for `RED-DOS-01`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Archive extraction blindly invokes extractall() without inspecting cumulative uncompressed file size, compression ratio, or total entry counts across the archive infolist.
- **The Fix to Apply**: [RECOMMENDATION] Implement pre-extraction resource quotas: inspect archive metadata before extraction to enforce limits on total uncompressed byte size, individual member uncompressed size, total member count, and maximum compression ratio. Enforce path traversal checks to reject members with relative escapes (../) or absolute paths. Clean up partial extractions and temporary directories within try...finally blocks.
- **Concrete Code Changes**: [RECOMMENDATION] `Inspect archive member metadata before extracting: enforce limits such as MAX_TOTAL_SIZE, MAX_MEMBER_SIZE, MAX_ENTRIES, and MAX_RATIO.; Validate member paths to reject directory traversal and absolute path targets before writing any files.; Use try...finally constructs to ensure temporary extraction folders are cleaned up upon failure or cancellation.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Pass filter='data' where available on Python 3.12+ extraction APIs to benefit from standard-library security filters.; Stream extraction with running byte counters to guard against spoofed member metadata.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Legitimate archives that exceed configured size or member-count ceilings will be rejected unless thresholds are configurable.
- **How to Test It**: [FACT] Unit test verifying archives exceeding member count or uncompressed byte ceilings trigger rejection before writing files.; Unit test confirming legitimate archives within quota limits extract successfully.

### Defense Plan for `RED-FILE-02`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Archive member inspection checks filename path prefixes using string methods but does not inspect POSIX file mode attributes in member.external_attr to detect symbolic link headers.
- **The Fix to Apply**: [RECOMMENDATION] Inspect archive member attributes before extraction (e.g. stat.S_ISLNK(member.external_attr >> 16) in ZIP files) and reject any member containing symlink attributes or pointing outside the extraction boundary. On Python 3.12+, utilize filter='data' for archive extraction APIs.
- **Concrete Code Changes**: [RECOMMENDATION] `Inspect member.external_attr and reject members flagged as symbolic links with stat.S_ISLNK().; Post-extraction, verify extracted files do not resolve outside the extraction target directory.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Adopt Python 3.12+ extraction filters ('data' filter) where available.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Archives legitimately requiring internal symbolic links will be rejected; source archives typically do not require symlinks.
- **How to Test It**: [FACT] Unit test verifying ZIP archives with symlink member attributes are rejected prior to extraction.

### Defense Plan for `RED-SSRF-01`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Performing HTTP requests to user-supplied URLs without destination validation permits Server-Side Request Forgery against internal infrastructure.
- **The Fix to Apply**: [RECOMMENDATION] Implement strict URL destination validation: parse target URLs, enforce an explicit allowlist of approved schemes (https://) and hostnames/domains, and resolve hostnames to IP addresses before connecting. Reject private, loopback, and link-local IP addresses (RFC 1918, RFC 3927, 127.0.0.0/8, ::1). Disable automatic HTTP redirect following or re-validate redirect destinations against the allowlist.
- **Concrete Code Changes**: [RECOMMENDATION] `Validate URLs against an explicit domain allowlist before issuing network requests.; Resolve hostnames and reject requests targeting internal/private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16).; Disable automatic redirects or re-evaluate redirect locations against validation filters.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Run outbound network services in an isolated network egress zone with restricted access to cloud metadata services.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Outbound requests to unlisted external domains or internal development services will be blocked.
- **How to Test It**: [FACT] Unit test verifying URLs targeting loopback (127.0.0.1) or cloud metadata endpoints are rejected.; Unit test confirming requests to allowlisted domains succeed.

### Defense Plan for `RED-DOS-02`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Static scanning utilities call f.read() on entire file contents without checking file size, allowing oversized or minified files to cause excessive memory allocation.
- **The Fix to Apply**: [RECOMMENDATION] Implement bounded reads or streaming chunking, checking file size prior to reading. Establish sensible size ceilings (e.g., 1MB–5MB) and exclude binary, minified, or auto-generated files from full static scanning. Acknowledge and communicate the operational limitation that truncating large files may result in later patterns or vulnerabilities being missed.
- **Concrete Code Changes**: [RECOMMENDATION] `Check os.path.getsize() prior to reading, skipping or applying bounded reads (f.read(MAX_READ_BYTES)) for textual analysis.; Stream files line-by-line where static analysis patterns allow.; Document and report any analysis coverage limitations when files are truncated or skipped.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Detect and skip minified or single-line generated files with excessive line lengths.; Track aggregate byte budgets across scanning sessions to cap total memory and I/O consumption.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Files larger than the bounded threshold will only be partially inspected; static analysis may miss vulnerabilities located past the truncation boundary.
- **How to Test It**: [FACT] Unit test asserting oversized files are read up to the configured byte limit without unbounded memory growth.; Verify coverage reporting records truncated files accurately.

### Defense Plan for `RED-CRYPTO-01`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Use of collision-vulnerable hash functions (MD5, SHA-1) for security-sensitive operations or password storage.
- **The Fix to Apply**: [RECOMMENDATION] Clearly distinguish password storage from general-purpose hashing. For password hashing, use a dedicated, adaptive password-hashing algorithm such as Argon2id, bcrypt, or scrypt with appropriate salt generation and cost parameters; plain SHA-256 is not an acceptable password hash. For non-password integrity verification, upgrade to modern collision-resistant algorithms such as SHA-256 or SHA-512. For message authentication, use HMAC-SHA256 with a protected secret key.
- **Concrete Code Changes**: [RECOMMENDATION] `For user passwords, migrate to Argon2id (via argon2-cffi) or bcrypt with per-password salts and calibrated work factors.; For non-password data integrity, replace hashlib.md5/sha1 with hashlib.sha256() or HMAC-SHA256.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Implement an automatic password re-hashing workflow on user login to upgrade legacy hashes smoothly.; Periodically review and adjust work factor parameters to keep pace with hardware advancements.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Existing legacy password hashes must be verified and migrated upon subsequent user authentication.
- **How to Test It**: [FACT] Unit test verifying new password hashes use the dedicated adaptive algorithm with valid salt and cost factors.; Unit test verifying legacy hash verification and upgrade workflows operate without regressions.

### Defense Plan for `RED-INFO-01`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Local directory ingestion accepts arbitrary filesystem paths without boundary checking, allowing analysis of sensitive system roots.
- **The Fix to Apply**: [RECOMMENDATION] Distinguish between intentional local CLI directory selection and unauthenticated service-level path ingestion. For CLI tools, validate that the path exists, is a directory, and reject root or system-critical directories ('/' or 'C:\'). For network-facing services, confine directory ingestion to a configurable authorized workspace root.
- **Concrete Code Changes**: [RECOMMENDATION] `Resolve input directory paths with os.path.realpath() and disallow operating system root directories.; For service environments, enforce that ingested directory paths reside strictly within an authorized base workspace.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Provide an explicit workspace configuration option (--allowed-dir) for multi-tenant or server deployments.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Normal project directories remain accessible while system root paths are blocked.
- **How to Test It**: [FACT] Unit test verifying legitimate workspace directories pass validation while system root paths are rejected.

### Defense Plan for `RED-INFO-02`
- **Root Cause (Why Did It Happen?)**: [ANALYSIS] Emitting raw internal filesystem paths (including user home directories and system usernames) in generated output contracts exposes internal infrastructure details.
- **The Fix to Apply**: [RECOMMENDATION] Minimize unnecessary host path disclosure by converting absolute filesystem paths to repository-relative or virtualized paths in output reports, while preserving path information required by downstream pipeline consumers. Sanitize temporary directory paths and usernames in public-facing outputs.
- **Concrete Code Changes**: [RECOMMENDATION] `Convert host absolute paths to repository-relative paths where external output contracts do not require absolute filesystem references.; Sanitize username and temporary directory prefixes from generated report summaries.`
- **Extra Safety Locks (Hardening)**: [RECOMMENDATION] `Provide consistent relative path mappings across all pipeline phase output contracts.`
- **Did We Break Anything? (Regression Check)**: [ANALYSIS] Downstream consumers requiring exact local filesystem paths must be accommodated or provided a clear mapping.
- **How to Test It**: [FACT] Unit test verifying external contract summaries use relative or sanitized paths without raw username paths.

## 6. SECURITY RETEST RESULTS (VERIFYING CURRENT CODE STATUS)

We re-evaluated the active codebase against the identified security checks to determine what is currently fixed versus what needs developer action:

### Retest Result for `RED-INJ-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Subprocess Option Injection via Unsanitized Git Clone Parameter
- **Remediation Evaluated**: [FACT] Validate that the repository source string does not begin with '-' or '--'. In the git clone command array, place the standard '--' option separator immediately before the repository source argument to force Git to interpret it as a positional argument. Validate URL schemes to permit only approved protocols (such as https://, ssh://, or http://), and set GIT_TERMINAL_PROMPT=0 to prevent interactive hangs.
- **Test Outcome in Active Code**: [FACT] Active code passes the repository source argument to Git without leading-hyphen validation or the '--' option terminator.
- **Remaining Risk**: [ANALYSIS] Command option injection remains reachable: flag-like source arguments will be interpreted as Git CLI options.
- **Current File Evidence**: [FACT] `Missing hyphen validation and '--' separator in src/phase8/recommendations.py`

### Retest Result for `RED-DESER-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Insecure Object Deserialization via Python Pickle / Joblib
- **Remediation Evaluated**: [FACT] Never deserialize untrusted pickle or joblib data. For structured data or tensor weights, migrate to safer, constrained serialization formats appropriate to the data type (e.g., JSON, Protocol Buffers, SafeTensors for model weights, or ONNX for computational graphs). Where serialized artifacts must be loaded, establish authenticity before deserialization using a trusted digital signature (asymmetric cryptography) or securely managed HMAC key; an ordinary unauthenticated SHA-256 checksum does not establish trust, as an attacker with write access can replace both the artifact and checksum.
- **Test Outcome in Active Code**: [FACT] Unsafe pickle/joblib deserialization remains in active code without cryptographic digital signature or HMAC verification. Ordinary unauthenticated checksums do not prevent tampering if both file and hash are replaced.
- **Remaining Risk**: [ANALYSIS] Arbitrary code execution remains reachable through untrusted serialized model or object files.
- **Current File Evidence**: [FACT] `Unauthenticated deserialization calls in src/phase8/recommendations.py`

### Retest Result for `RED-DOS-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Uncontrolled Resource Consumption via Archive Decompression (Zip Bomb)
- **Remediation Evaluated**: [FACT] Implement pre-extraction resource quotas: inspect archive metadata before extraction to enforce limits on total uncompressed byte size, individual member uncompressed size, total member count, and maximum compression ratio. Enforce path traversal checks to reject members with relative escapes (../) or absolute paths. Clean up partial extractions and temporary directories within try...finally blocks.
- **Test Outcome in Active Code**: [FACT] Active code extracts archive files without pre-extraction uncompressed byte or member quota verification. Note: Unenforced size constants in the file do not protect blind extractall() calls.
- **Remaining Risk**: [ANALYSIS] Denial of Service via high-ratio decompression bombs remains reachable.
- **Current File Evidence**: [FACT] `extractall() called without pre-extraction quota verification in src/phase2/requirements.py`

### Retest Result for `RED-FILE-02`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Potential Symlink Traversal during Archive Extraction
- **Remediation Evaluated**: [FACT] Inspect archive member attributes before extraction (e.g. stat.S_ISLNK(member.external_attr >> 16) in ZIP files) and reject any member containing symlink attributes or pointing outside the extraction boundary. On Python 3.12+, utilize filter='data' for archive extraction APIs.
- **Test Outcome in Active Code**: [FACT] Archive extraction relies solely on string prefix matching without POSIX file mode attribute inspection.
- **Remaining Risk**: [ANALYSIS] Symlink dereferencing may allow file extraction outside the target directory on compatible runtimes.
- **Current File Evidence**: [FACT] `Missing symlink mode attribute inspection in src/phase2/requirements.py`

### Retest Result for `RED-SSRF-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request
- **Remediation Evaluated**: [FACT] Implement strict URL destination validation: parse target URLs, enforce an explicit allowlist of approved schemes (https://) and hostnames/domains, and resolve hostnames to IP addresses before connecting. Reject private, loopback, and link-local IP addresses (RFC 1918, RFC 3927, 127.0.0.0/8, ::1). Disable automatic HTTP redirect following or re-validate redirect destinations against the allowlist.
- **Test Outcome in Active Code**: [FACT] Dynamic outbound HTTP request is issued without destination URL validation or private IP checks; hardcoded or safe requests elsewhere in the file do not protect unvalidated request targets.
- **Remaining Risk**: [ANALYSIS] Server-Side Request Forgery against internal networks and metadata services remains reachable.
- **Current File Evidence**: [FACT] `Unvalidated dynamic HTTP requests detected in src/phase0/ingestion.py`

### Retest Result for `RED-DOS-02`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Unbounded File Read in Application Ingestion Routine
- **Remediation Evaluated**: [FACT] Implement bounded reads or streaming chunking, checking file size prior to reading. Establish sensible size ceilings (e.g., 1MB–5MB) and exclude binary, minified, or auto-generated files from full static scanning. Acknowledge and communicate the operational limitation that truncating large files may result in later patterns or vulnerabilities being missed.
- **Test Outcome in Active Code**: [FACT] Repository scanning utilities read entire files into memory using unbounded f.read() without size checks.
- **Remaining Risk**: [ANALYSIS] Memory exhaustion Denial of Service remains reachable on oversized or minified files.
- **Current File Evidence**: [FACT] `Unbounded f.read() detected in gui.py`

### Retest Result for `RED-CRYPTO-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Use of Cryptographically Weak Hash Algorithm (MD5/SHA-1)
- **Remediation Evaluated**: [FACT] Clearly distinguish password storage from general-purpose hashing. For password hashing, use a dedicated, adaptive password-hashing algorithm such as Argon2id, bcrypt, or scrypt with appropriate salt generation and cost parameters; plain SHA-256 is not an acceptable password hash. For non-password integrity verification, upgrade to modern collision-resistant algorithms such as SHA-256 or SHA-512. For message authentication, use HMAC-SHA256 with a protected secret key.
- **Test Outcome in Active Code**: [FACT] Deprecated, collision-vulnerable hash functions (MD5/SHA1) remain in active use.
- **Remaining Risk**: [ANALYSIS] Collision attacks and pre-computed rainbow table cracking remain possible.
- **Current File Evidence**: [FACT] `MD5/SHA1 calls detected in src/phase8/recommendations.py`

### Retest Result for `RED-INFO-01`: **NOT_REMEDIATED** (🔴 ACTION REQUIRED)
- **Original Issue**: [FACT] Unrestricted Local Directory Ingestion in CLI Interface
- **Remediation Evaluated**: [FACT] Distinguish between intentional local CLI directory selection and unauthenticated service-level path ingestion. For CLI tools, validate that the path exists, is a directory, and reject root or system-critical directories ('/' or 'C:\'). For network-facing services, confine directory ingestion to a configurable authorized workspace root.
- **Test Outcome in Active Code**: [FACT] Local directory ingestion accepts arbitrary filesystem paths without boundary checking or root directory exclusion.
- **Remaining Risk**: [ANALYSIS] Arbitrary host filesystem structure can be inventoried by passing operating system roots.
- **Current File Evidence**: [FACT] `Missing system root validation in src/phase0/ingestion.py`

### Retest Result for `RED-INFO-02`: **REMEDIATED** (🟢 VERIFIED REMEDIATION)
- **Original Issue**: [FACT] Internal Host Filesystem Path Embedded in Contract Output
- **Remediation Evaluated**: [FACT] Minimize unnecessary host path disclosure by converting absolute filesystem paths to repository-relative or virtualized paths in output reports, while preserving path information required by downstream pipeline consumers. Sanitize temporary directory paths and usernames in public-facing outputs.
- **Test Outcome in Active Code**: [FACT] Internal filesystem paths are virtualized or mapped to repository-relative paths in output contracts.
- **Remaining Risk**: [ANALYSIS] Exposure of internal host infrastructure paths and system usernames minimized.
- **Current File Evidence**: [FACT] `Path sanitization logic verified in src/phase0/ingestion.py`

## 7. RECOMMENDATION TRADE-OFFS (PROS AND CONS)

In software engineering, every improvement comes with a trade-off. Here is what you gain and what you give up:

| Recommendation | What You Gain (The Benefit) | What You Give Up (The Trade-Off) |
| :--- | :--- | :--- |
| **REC-01** — Potential command or option injection during Git repository cloning via user-controlled URIs (RED-INJ-01). | Risk reduction: Restricting URI schemes to approved protocols (https://, git@) and inserting the positional argument delimiter (--) prevents user inputs from being interpreted as CLI option flags. Assumptions & Residual Risks: Repository operations must enforce network timeouts and disk storage quotas to prevent denial-of-service during large or slow repository clones. | Blocks non-standard file:// URLs unless explicitly allowed. |
| **REC-02** — Insecure object deserialization via unverified joblib/pickle machine learning model loading (RED-DESER-01). | Risk reduction: Verifying cryptographic HMAC signatures prior to deserialization detects tampering and prevents loading unverified model files. Assumptions & Residual Risks: Assumes HMAC secret keys and signing certificates are kept confidential; if model files originate from untrusted external sources, migrating to non-executable serialization formats (e.g., Safetensors, ONNX) is strongly recommended as pickle cannot be safely sandboxed. | Model checksums or signatures must be recorded and updated whenever models are retrained. |
| **REC-03** — Uncontrolled resource consumption via archive decompression bombs (Zip Bombs) (RED-DOS-01). | Risk reduction: Protects host storage and filesystem inode capacity by enforcing pre-extraction thresholds on cumulative uncompressed byte volume and byte ceilings. Assumptions & Residual Risks: Configured quota thresholds (e.g., 200MB, 5000 entries) must accommodate legitimate archives. Ingestion still incurs CPU processing overhead during archive directory traversal, which should be bounded with execution timeouts. | Extremely large legitimate archives will require administrator quota configuration. |
| **REC-04** — Potential Symlink Traversal during Archive Extraction (RED-FILE-02) | Risk reduction: Arbitrary file modification outside extraction sandbox. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | Archives legitimately requiring internal symbolic links will be rejected; source archives typically do not require symlinks. |
| **REC-05** — Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request (RED-SSRF-01) | Risk reduction: Cloud credential theft or internal service network scanning. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | Outbound requests to unlisted external domains or internal development services will be blocked. |
| **REC-06** — Untyped dictionary contracts across pipeline phase boundaries increase interface coupling and runtime schema drift risks (REL-ARCH-MAINT-01). | Risk reduction: Reduces data corruption and unhandled schema drift across pipeline phase boundaries by introducing typed data structures (TypedDict or dataclasses). Assumptions & Residual Risks: Runtime validation remains necessary when parsing external or untrusted JSON inputs. | Requires authoring TypedDict definitions for core phase exchange data structures. |
| **REC-07** — Zero-dependency architecture avoids third-party package vulnerabilities but shifts security parsing and boundary validation responsibilities entirely to internal code (REL-ARCH-SEC-01). | Risk reduction: Avoids third-party dependency supply-chain attack vectors. Assumptions & Residual Risks: Internal parsing logic (URI validation, archive extraction) must be supported by comprehensive unit test harnesses and edge-case testing to match the robustness of mature external libraries. | Requires dedicated in-house unit testing for boundary condition parsing. |
| **REC-08** — Duplicated CLI output sanitization and stream reconfiguration risks divergent security posture across entry points (REL-SEC-MAINT-01). | Risk reduction: Promotes uniform output sanitization and reduces divergence in terminal escape sequence filtering across CLI entry points by centralizing utility routines. Assumptions & Residual Risks: All current and future CLI entry points must consistently import and route output through the shared utility. | Requires creating a shared cli_utils module. |
| **REC-09** — High structural complexity in repository traversal 'do_GET' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic. |
| **REC-10** — High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-11** — High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-12** — High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-13** — High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-14** — High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-15** — High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-16** — High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-17** — High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic. |
| **REC-18** — High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-19** — High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-20** — High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-21** — High cyclomatic complexity and deep nesting in '_is_connected_to_deserialization' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-22** — High cyclomatic complexity and deep nesting in '_is_connected_to_http_request' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-23** — High cyclomatic complexity and deep nesting in '_collect_python_files' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-24** — High cyclomatic complexity and deep nesting in '_compute_cyclomatic_complexity' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-25** — High cyclomatic complexity and deep nesting in '_find_dead_code' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-26** — High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-27** — High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-28** — High cyclomatic complexity and deep nesting in '_inspect_patterns' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-29** — High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-30** — High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-31** — High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-32** — High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-33** — High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-34** — High cyclomatic complexity and deep nesting in 'RepositoryIngestionAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-35** — High cyclomatic complexity and deep nesting in 'ProjectReconstructionAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-36** — High cyclomatic complexity and deep nesting in 'SecurityAssessmentAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-37** — High cyclomatic complexity and deep nesting in 'RequirementsEngineeringAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-38** — High cyclomatic complexity and deep nesting in 'RedTeamSecurityAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-39** — High cyclomatic complexity and deep nesting in 'BlueTeamDefensiveAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-40** — High cyclomatic complexity and deep nesting in 'SecurityRetestAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-41** — High cyclomatic complexity and deep nesting in 'CodeSmellAnalysisAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-42** — High cyclomatic complexity and deep nesting in 'CrossDomainAnalysisAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-43** — High cyclomatic complexity and deep nesting in 'RecommendationEngineAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-44** — High cyclomatic complexity and deep nesting in 'FinalReportGeneratorAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-45** — High cyclomatic complexity and deep nesting in 'TestPhase3ARedTeamAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-46** — High cyclomatic complexity and deep nesting in 'TestPhase4ABlueTeamAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-47** — High cyclomatic complexity and deep nesting in 'TestPhase5ASecurityRetestAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-48** — High cyclomatic complexity and deep nesting in 'TestPhase6CodeSmellAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-49** — High cyclomatic complexity and deep nesting in 'TestPhase7CrossDomainAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-50** — High cyclomatic complexity and deep nesting in 'TestPhase8RecommendationEngine' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-51** — High cyclomatic complexity and deep nesting in 'TestPhase9ReportGeneratorAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-52** — High cyclomatic complexity and deep nesting in 'TestMultiPhasePipeline' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-53** — High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-54** — High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-55** — High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-56** — High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic. |
| **REC-57** — High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-58** — High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-59** — High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-60** — High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-61** — High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-62** — High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-63** — High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-64** — High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-65** — High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-66** — High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-67** — High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-68** — High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-69** — High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-70** — High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-71** — High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-72** — High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic. |
| **REC-73** — High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-74** — High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-75** — High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-76** — High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-77** — High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-78** — High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-79** — High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-80** — High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-81** — High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-82** — High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-83** — Silent exception suppression in 'Line 61' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-84** — Silent exception suppression in 'Line 186' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-85** — Silent exception suppression in 'Line 313' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-86** — Silent exception suppression in 'Line 361' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-87** — Silent exception suppression in 'Line 837' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-88** — Silent exception suppression in 'Line 920' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-89** — Silent exception suppression in 'Line 116' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-90** — Silent exception suppression in 'Line 276' masks runtime failures and impedes diagnostic visibility. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | Negligible I/O overhead when debug logging is enabled. |
| **REC-91** — Unbounded File Read in Application Ingestion Routine (RED-DOS-02) | Risk reduction: Process memory exhaustion (OOM crash) and denial of service. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | Files larger than the bounded threshold will only be partially inspected; static analysis may miss vulnerabilities located past the truncation boundary. |
| **REC-92** — High cyclomatic complexity and deep nesting in 'main' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-93** — High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-94** — High cyclomatic complexity and deep nesting in '_read_documentation' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-95** — High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-96** — High cyclomatic complexity and deep nesting in '_evaluate_stride' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-97** — High cyclomatic complexity and deep nesting in '_extract_file_list' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-98** — High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-99** — High cyclomatic complexity and deep nesting in 'visit_FunctionDef' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-100** — High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-101** — High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-102** — High cyclomatic complexity and deep nesting in '_audit_logging_and_errors' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-103** — High cyclomatic complexity and deep nesting in '_extract_path_list' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-104** — High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-105** — High cyclomatic complexity and deep nesting in '_deduplicate_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-106** — High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-107** — High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-108** — High cyclomatic complexity and deep nesting in '_check_deserialization' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-109** — High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-110** — High cyclomatic complexity and deep nesting in '__init__' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-111** — High cyclomatic complexity and deep nesting in '_format_exception_type' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-112** — High cyclomatic complexity and deep nesting in '_has_global_mutation' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-113** — High cyclomatic complexity and deep nesting in '_has_enforcement' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-114** — High cyclomatic complexity and deep nesting in 'collect_malformed' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-115** — High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-116** — High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-117** — High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-118** — High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-119** — High cyclomatic complexity and deep nesting in '_get_requirement_tag' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-120** — High cyclomatic complexity and deep nesting in 'safe_write_output / stream wrapper' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-121** — High cyclomatic complexity and deep nesting in 'do_GET' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-122** — High cyclomatic complexity and deep nesting in 'TestRepositoryIngestionAgent' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-123** — High cyclomatic complexity and deep nesting in 'TestRequirementsEngineeringAgentFocused' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-124** — High cyclomatic complexity and deep nesting in 'TestRedBlueRetestPipeline' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-125** — High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-126** — High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-127** — High cyclomatic complexity and deep nesting in '_is_entry_point_candidate' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-128** — High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-129** — High cyclomatic complexity and deep nesting in '_validate_and_normalize_github_url' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-130** — High cyclomatic complexity and deep nesting in '_classify_weakness' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-131** — High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-132** — High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-133** — High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-134** — High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-135** — High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-136** — High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-137** — High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-138** — High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-139** — High cyclomatic complexity and deep nesting in '_read_file_safe' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-140** — High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-141** — High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-142** — High cyclomatic complexity and deep nesting in '_derive_confidence' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-143** — High cyclomatic complexity and deep nesting in '_derive_security_priority' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-144** — High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-145** — High cyclomatic complexity and deep nesting in '_resolve_requirement' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-146** — Code smell (Repeated Conditionals) detected in 'Line 49'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-147** — Code smell (Repeated Conditionals) detected in 'Line 238'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-148** — Code smell (Repeated Conditionals) detected in 'Line 859'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-149** — Code smell (Repeated Conditionals) detected in 'Line 288'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-150** — Code smell (Repeated Conditionals) detected in 'Line 467'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-151** — Code smell (Repeated Conditionals) detected in 'Line 302'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-152** — Code smell (Repeated Conditionals) detected in 'Line 195'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-153** — Code smell (Repeated Conditionals) detected in 'Line 299'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-154** — Code smell (Repeated Conditionals) detected in 'Line 272'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-155** — Code smell (Repeated Conditionals) detected in 'Line 900'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-156** — Code smell (Repeated Conditionals) detected in 'Line 46'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-157** — Code smell (Repeated Conditionals) detected in 'Line 749'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-158** — High cyclomatic complexity and deep nesting in 'main' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-159** — High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-160** — High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-161** — High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-162** — High cyclomatic complexity and deep nesting in '_extract_business_constraints' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-163** — High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-164** — High cyclomatic complexity and deep nesting in '_extract_non_functional_requirements' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-165** — High cyclomatic complexity and deep nesting in '_extract_security_requirements' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-166** — High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-167** — High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-168** — High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-169** — High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-170** — High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-171** — High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-172** — High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-173** — High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-174** — High cyclomatic complexity and deep nesting in '_build_baseline_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-175** — High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-176** — High cyclomatic complexity and deep nesting in 'generate_report_data' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-177** — High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-178** — High cyclomatic complexity and deep nesting in 'test_phase8_runs_prerequisites_in_order' hinders code maintainability. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | Requires creating small helper functions; zero impact on public API behavior. |
| **REC-179** — Code smell (Long Parameter List) detected in '__init__'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-180** — Code smell (Long Parameter List) detected in '_build_security_rec'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-181** — Code smell (Long Parameter List) detected in '_derive_confidence'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-182** — Code smell (Long Parameter List) detected in '_derive_security_priority'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-183** — Code smell (Long Parameter List) detected in '__init__'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-184** — Code smell (Long Parameter List) detected in '__init__'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-185** — Code smell (Inappropriate Abstractions / Primitive Obsession) detected in 'Cross-Phase Data Exchange'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-186** — Use of deprecated MD5/SHA1 cryptographic hash algorithm vulnerable to collisions (RED-CRYPTO-01). | Risk reduction: Migrating to SHA-256 provides strong collision resistance for cryptographic checksums, data integrity validation, and message authentication. Assumptions & Residual Risks: For user password storage or secret derivation, salted memory-hard key-derivation functions (e.g., Argon2id or bcrypt) must be used rather than general-purpose fast cryptographic hashes like SHA-256. | SHA-256 produces longer digest strings (64 hex characters vs 32 for MD5). |
| **REC-187** — Unrestricted Local Directory Ingestion in CLI Interface (RED-INFO-01) | Risk reduction: Normal CLI file enumeration (intended tool behavior; verify if workspace restriction is required). Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | Normal project directories remain accessible while system root paths are blocked. |
| **REC-188** — Maintain verified remediation for Internal Host Filesystem Path Embedded in Contract Output (RED-INFO-02). | Risk reduction: Low-impact internal environment enumeration. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | Downstream consumers requiring exact local filesystem paths must be accommodated or provided a clear mapping. |
| **REC-189** — Code smell (Hard-coded Configuration) detected in 'CONFIG_FILENAMES'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-190** — Code smell (Hard-coded Configuration) detected in 'EXTENSION_LANGUAGE_MAP'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-191** — Code smell (Magic Numbers) detected in '_determine_project_summary'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-192** — Code smell (Magic Numbers) detected in 'assess'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-193** — Code smell (Magic Numbers) detected in 'assess'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-194** — Code smell (Magic Numbers) detected in 'assess'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-195** — Code smell (Magic Numbers) detected in '_is_connected_to_deserialization'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-196** — Code smell (Magic Numbers) detected in '_is_connected_to_http_request'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-197** — Code smell (Magic Numbers) detected in '_inspect_ast'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-198** — Code smell (Magic Numbers) detected in '_inspect_ast'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-199** — Code smell (Magic Numbers) detected in '_inspect_ast'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-200** — Code smell (Magic Numbers) detected in '_inspect_ast'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-201** — Code smell (Magic Numbers) detected in '_inspect_ast'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-202** — Code smell (Magic Numbers) detected in '_inspect_ast'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-203** — Code smell (Magic Numbers) detected in 'evaluate_archive_quota_state'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-204** — Code smell (Multiple Return Points) detected in 'is_supported_github_url'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-205** — Code smell (Multiple Return Points) detected in 'run_pipeline'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-206** — Code smell (Multiple Return Points) detected in '_is_entry_point_candidate'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-207** — Code smell (Multiple Return Points) detected in '_classify_weakness'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-208** — Code smell (Multiple Return Points) detected in '_map_requirement_affected'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-209** — Code smell (Multiple Return Points) detected in '_remediate_finding'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-210** — Code smell (Multiple Return Points) detected in '_check_cryptographic_hashing'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-211** — Code smell (Multiple Return Points) detected in '_check_deserialization'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-212** — Code smell (Multiple Return Points) detected in '_read_file_safe'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-213** — Code smell (Multiple Return Points) detected in '_retest_single_finding'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-214** — Code smell (Multiple Return Points) detected in '_format_exception_type'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-215** — Code smell (Multiple Return Points) detected in '_read_file_safe'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-216** — Code smell (Multiple Return Points) detected in 'evaluate_archive_quota_state'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-217** — Code smell (Multiple Return Points) detected in '_build_security_rec'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-218** — Code smell (Multiple Return Points) detected in '_derive_confidence'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-219** — Code smell (Multiple Return Points) detected in '_derive_security_priority'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-220** — Code smell (Multiple Return Points) detected in '_derive_smell_confidence'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-221** — Code smell (Multiple Return Points) detected in '_derive_smell_priority'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-222** — Code smell (Multiple Return Points) detected in '_resolve_requirement'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |
| **REC-223** — Code smell (Multiple Return Points) detected in '_get_requirement_tag'. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | Requires testing across affected routines to confirm zero functional regressions. |

## 8. CODE SMELL ASSESSMENT (CODE QUALITY REVIEW)

A 'code smell' is a warning sign that code might be messy, overly complex, or hard to maintain in the future.
Abstract Syntax Tree (AST) analysis was executed against discovered Python source files where AST parsing was supported.

### Summary of Code Quality Findings
- **Total Code Smells Found**: [FACT] **211**
- **PROBLEMATIC (High Priority to Clean Up)**: [ANALYSIS] 105 items
- **POTENTIALLY_EXCESSIVE (A bit complicated)**: [ANALYSIS] 104 items
- **JUSTIFIED (Complex for good reasons)**: [ANALYSIS] 2 items

### Key Code Quality Highlights & Cleanup Plan
#### `SMELL-DEEP-NEST-gui_py-DO_GET` — Deep Nesting in `do_GET`
- **File Location**: [FACT] `gui.py`
- **What Was Found**: [FACT] Function 'do_GET' exhibits maximum block nesting depth of 9 levels.
- **Why It Matters**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **Severity Tag**: [ANALYSIS] `PROBLEMATIC`
- **How to Clean It Up**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.

#### `SMELL-DEEP-NEST-ingest_py-SAFE_WRITE_OUTPUT` — Deep Nesting in `safe_write_output`
- **File Location**: [FACT] `ingest.py`
- **What Was Found**: [FACT] Function 'safe_write_output' exhibits maximum block nesting depth of 5 levels.
- **Why It Matters**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **Severity Tag**: [ANALYSIS] `PROBLEMATIC`
- **How to Clean It Up**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.

#### `SMELL-DEEP-NEST-pipeline_py-RUN_PIPELINE` — Deep Nesting in `run_pipeline`
- **File Location**: [FACT] `pipeline.py`
- **What Was Found**: [FACT] Function 'run_pipeline' exhibits maximum block nesting depth of 6 levels.
- **Why It Matters**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **Severity Tag**: [ANALYSIS] `PROBLEMATIC`
- **How to Clean It Up**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.

#### `SMELL-DEEP-NEST-pipeline_py-SAFE_WRITE_OUTPUT` — Deep Nesting in `safe_write_output`
- **File Location**: [FACT] `pipeline.py`
- **What Was Found**: [FACT] Function 'safe_write_output' exhibits maximum block nesting depth of 5 levels.
- **Why It Matters**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **Severity Tag**: [ANALYSIS] `PROBLEMATIC`
- **How to Clean It Up**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.

#### `SMELL-LONG-METHOD-pipeline_py-RUN_PIPELINE` — Long Method in `run_pipeline`
- **File Location**: [FACT] `pipeline.py`
- **What Was Found**: [FACT] Function 'run_pipeline' spans 280 lines of code (lines 227-506).
- **Why It Matters**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **Severity Tag**: [ANALYSIS] `PROBLEMATIC`
- **How to Clean It Up**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.

#### `SMELL-DEEP-NEST-src_phase0_ingestion_py-INVENTORY` — Deep Nesting in `inventory`
- **File Location**: [FACT] `src/phase0/ingestion.py`
- **What Was Found**: [FACT] Function 'inventory' exhibits maximum block nesting depth of 6 levels.
- **Why It Matters**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **Severity Tag**: [ANALYSIS] `PROBLEMATIC`
- **How to Clean It Up**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.

## 9. CROSS-DOMAIN FINDINGS (HOW EVERYTHING CONNECTS)

Security, speed, architecture, and clean code all impact each other. Here is how they interact in this project:

### `REL-SMELL-SEC-01`: Code Quality ↔ Security
- **Interaction Type**: [ANALYSIS] Code Smell Undermines Security Observability
- **Evidence from the Code**: [FACT] Silent exception suppression detected in src/phase0/ingestion.py:Line 837, src/phase0/ingestion.py:Line 920, ingest.py:Line 61: Except handler catches 'Exception' with a silent suppression statement (line 837).
- **Impact on the Software**: [ANALYSIS] Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **Recommended Engineering Action**: [RECOMMENDATION] Replace silent pass handlers with targeted exception types and route caught exceptions to structured diagnostic audit logs.

### `REL-ARCH-SEC-01`: Architecture / Requirements ↔ Security
- **Interaction Type**: [ANALYSIS] Zero-Dependency Policy Reduces Third-Party Dependency Exposure but Increases In-House Validation Responsibility
- **Evidence from the Code**: [FACT] Requirement REQ-NFR-02 specifies: 'External dependency constraints cannot be established due to absence of dependency manifests.'.
- **Impact on the Software**: [ANALYSIS] Relying on standard-library implementations reduces exposure to third-party package vulnerabilities, but places ongoing maintenance, security patching, and validation responsibilities on custom internal routines.
- **Recommended Engineering Action**: [RECOMMENDATION] Maintain zero-dependency constraint if minimal deployment footprint is required, backed by rigorous unit testing and security static analysis of custom parsing logic.

### `REL-SMELL-SCALE-01`: Code Quality ↔ Scalability
- **Interaction Type**: [ANALYSIS] Monolithic Traversal Logic Poses Potential Scalability Constraint
- **Evidence from the Code**: [FACT] ingest.py (safe_write_output): Function 'safe_write_output' exhibits maximum block nesting depth of 5 levels.
- **Impact on the Software**: [ANALYSIS] High cyclomatic complexity and deep nesting in repository traversal routines increase maintenance overhead and represent a plausible scaling bottleneck under large file counts.
- **Recommended Engineering Action**: [RECOMMENDATION] Refactor traversal routines into smaller modular functions to separate file discovery from filtering and categorization logic.

### `REL-ARCH-MAINT-01`: Architecture ↔ Maintainability
- **Interaction Type**: [ANALYSIS] Untyped Data Exchange Increases Maintenance Friction across Interfaces
- **Evidence from the Code**: [FACT] Component data exchange in src/phase1/reconstruction.py / src/phase2/requirements.py (Cross-Phase Data Exchange): Phases exchange raw Dict[str, Any] structures and index raw string keys ('apis', 'authentication_components', 'dependency_files', 'deployment_model') without typed schema models.
- **Impact on the Software**: [ANALYSIS] Relying on raw untyped dictionaries across phase boundaries lacks static schema validation, increasing maintenance overhead and the risk of unhandled key errors during schema evolution.
- **Recommended Engineering Action**: [RECOMMENDATION] Formalize inter-phase data exchange using typed dataclasses or TypedDict schemas to document and validate contracts between pipeline components.

### `REL-SEC-MAINT-01`: Security ↔ Maintainability
- **Interaction Type**: [ANALYSIS] Duplicated Output Logic Risks Inconsistent Security Posture
- **Evidence from the Code**: [FACT] Duplication in pipeline.py / ingest.py (safe_write_output / stream wrapper): Duplicate logic verified: identical 'safe_write_output' function (pipeline.py:L160, ingest.py:L35); identical stdout UTF-8 reconfiguration stream wrapper.
- **Impact on the Software**: [ANALYSIS] Duplicated output handling and sanitization logic risks divergent updates over time, where security checks or path boundaries applied in one entry point may be missed in another.
- **Recommended Engineering Action**: [RECOMMENDATION] Consolidate duplicated CLI output sanitization and stream reconfiguration logic into a shared common utility module.

## 10. REQUIREMENT ↔ IMPLEMENTATION MATRIX (STATUS TABLE)

This table shows every requirement, how it is implemented in this codebase today, and its verification status:

| Requirement | What the Code Does Today | Status | Evidence File | Gap / What's Missing |
| :--- | :--- | :---: | :--- | :--- |
| **REQ-FUNC-01** (The system must support Command Line Execution: Invoke the application via terminal flags to perform project operations.) | Implemented in final_report.md | **SATISFIED** | `final_report.md` | None; verified in code |
| **REQ-FUNC-02** (The system must provide a Command Line Interface (CLI) for parsing user arguments and dispatching execution.) | Implemented in ingest.py | **SATISFIED** | `ingest.py` | None; verified in code |
| **REQ-SEC-01** (Archive member path validation logic detected prior to extraction (observed implementation code; dynamic verification required for complete edge-case safety).) | Implemented in src/phase0/ingestion.py | **SATISFIED** | `src/phase0/ingestion.py` | None; verified in code |
| **REQ-SEC-02** (The system must verify caller identity and authenticate requests before granting access to protected operations.) | Implemented in src/phase1/reconstruction.py | **SATISFIED** | `src/phase1/reconstruction.py` | None; verified in code |
| **REQ-SEC-03** (The application loads configuration and secrets via environment variables or secret stores (observed implementation behavior).) | Implemented in src/phase2/requirements.py | **SATISFIED** | `src/phase2/requirements.py` | None; verified in code |
| **REQ-SEC-04** (The system enforces secure communication channels using TLS with certificate validation (observed implementation behavior).) | Implemented in src/phase2/requirements.py | **SATISFIED** | `src/phase2/requirements.py` | None; verified in code |
| **REQ-NFR-01** (The software executes cross-platform on Windows and POSIX operating systems, handling path separators safely (observed implementation behavior).) | Implemented in ingest.py | **SATISFIED** | `ingest.py` | None; verified in code |
| **REQ-NFR-02** (External dependency constraints cannot be established due to absence of dependency manifests.) | Implemented in None | **UNKNOWN** | `None` | No implementation evidence supplied |
| **REQ-NFR-03** (The system must output deterministic, contract-conforming JSON schemas for integration.) | Implemented in final_report.md | **SATISFIED** | `final_report.md` | None; verified in code |
| **REQ-NFR-04** (The technical architecture executes under: Standalone Process Execution (technical deployment architecture).) | Implemented in gui.py | **SATISFIED** | `gui.py` | None; verified in code |
| **REQ-BIZ-01** (The software is intended for designated operational personas: CLI Operator / Developer.) | Implemented in Phase 1 Reconstruction | **INFERRED** | `Phase 1 Reconstruction` | Requires formal verification |
| **REQ-BIZ-02** (Deployment constraints driven by business mandates are not established from available documentation.) | Implemented in None | **UNKNOWN** | `None` | No implementation evidence supplied |
| **REQ-BIZ-03** (Expected traffic volume and concurrency requirements cannot be established from available evidence.) | Implemented in None | **UNKNOWN** | `None` | No implementation evidence supplied |
| **REQ-BIZ-04** (Latency requirements cannot be established from available evidence.) | Implemented in None | **UNKNOWN** | `None` | No implementation evidence supplied |
| **REQ-BIZ-05** (Availability requirements (e.g., uptime nines, failover) cannot be established from available evidence.) | Implemented in None | **UNKNOWN** | `None` | No implementation evidence supplied |
| **REQ-BIZ-06** (Cost or infrastructure budget constraints cannot be established from available evidence.) | Implemented in None | **UNKNOWN** | `None` | No implementation evidence supplied |

## 11. PRIORITIZED RECOMMENDATIONS (DEVELOPER TO-DO LIST)

Here is the prioritized list of recommended improvements, ranked from Critical/High to Low priority:

### `[CRITICAL]` REC-01: Potential command or option injection during Git repository cloning via user-controlled URIs (RED-INJ-01).
- **The Issue**: [ANALYSIS] Potential command or option injection during Git repository cloning via user-controlled URIs (RED-INJ-01).
- **Where to Look**: [FACT] `File(s) src/phase8/recommendations.py: Git clone invocation '"recommended_change": plan_remediation or "Pass arguments as tokenized argument lists (subprocess.run(['cmd', arg1], shell=False)) and validate all input parameters.",' passes arguments without '--' option terminator or leading-hyphen validation at line 1087.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Active code passes the repository source argument to Git without leading-hyphen validation or the '--' option terminator..`
- **Recommended Action**: [RECOMMENDATION] Validate that the repository source string does not begin with '-' or '--'. In the git clone command array, place the standard '--' option separator immediately before the repository source argument to force Git to interpret it as a positional argument. Validate URL schemes to permit only approved protocols (such as https://, ssh://, or http://), and set GIT_TERMINAL_PROMPT=0 to prevent interactive hangs.
- **Why This Helps**: [ANALYSIS] Git clone invocation passes user-controlled source parameter directly to subprocess.run without leading-hyphen validation or positional argument disambiguation ('--' separator). Git interprets leading dashes as CLI flags.
- **How Hard to Fix?**: [ANALYSIS] **LOW (adding input validation and delimiter in git clone command).**
- **Trade-Off**: [ANALYSIS] Blocks non-standard file:// URLs unless explicitly allowed.

### `[HIGH]` REC-02: Insecure object deserialization via unverified joblib/pickle machine learning model loading (RED-DESER-01).
- **The Issue**: [ANALYSIS] Insecure object deserialization via unverified joblib/pickle machine learning model loading (RED-DESER-01).
- **Where to Look**: [FACT] `File(s) src/phase8/recommendations.py: Deserialization routine '"current_implementation": f"Phase 5A status: {retest_status} ({retest_result_msg})" if p5a_res else "Model files are deserialized directly from disk using joblib.load() without integrity verification.",' identified at line 1118. Data provenance: untrusted ingress stream.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Unsafe pickle/joblib deserialization remains in active code without cryptographic digital signature or HMAC verification. Ordinary unauthenticated checksums do not prevent tampering if both file and hash are replaced..`
- **Recommended Action**: [RECOMMENDATION] Never deserialize untrusted pickle or joblib data. For structured data or tensor weights, migrate to safer, constrained serialization formats appropriate to the data type (e.g., JSON, Protocol Buffers, SafeTensors for model weights, or ONNX for computational graphs). Where serialized artifacts must be loaded, establish authenticity before deserialization using a trusted digital signature (asymmetric cryptography) or securely managed HMAC key; an ordinary unauthenticated SHA-256 checksum does not establish trust, as an attacker with write access can replace both the artifact and checksum.
- **Why This Helps**: [ANALYSIS] Direct deserialization of pickle or joblib data from untrusted or unauthenticated sources permits arbitrary object construction.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (computing and verifying SHA-256 HMAC signature prior to loading).**
- **Trade-Off**: [ANALYSIS] Model checksums or signatures must be recorded and updated whenever models are retrained.

### `[HIGH]` REC-03: Uncontrolled resource consumption via archive decompression bombs (Zip Bombs) (RED-DOS-01).
- **The Issue**: [ANALYSIS] Uncontrolled resource consumption via archive decompression bombs (Zip Bombs) (RED-DOS-01).
- **Where to Look**: [FACT] `File(s) src/phase2/requirements.py: Extraction call 'has_archive_op = any(kw in content for kw in ("zipfile.ZipFile", "tarfile.open", ".extractall(", ".extract("))' at line 395 lacks cumulative uncompressed size and member-count limits in function '_inspect_archive_extraction_safety'.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Active code extracts archive files without pre-extraction uncompressed byte or member quota verification. Note: Unenforced size constants in the file do not protect blind extractall() calls..`
- **Recommended Action**: [RECOMMENDATION] Implement pre-extraction resource quotas: inspect archive metadata before extraction to enforce limits on total uncompressed byte size, individual member uncompressed size, total member count, and maximum compression ratio. Enforce path traversal checks to reject members with relative escapes (../) or absolute paths. Clean up partial extractions and temporary directories within try...finally blocks.
- **Why This Helps**: [ANALYSIS] Archive extraction blindly invokes extractall() without inspecting cumulative uncompressed file size, compression ratio, or total entry counts across the archive infolist.
- **How Hard to Fix?**: [ANALYSIS] **LOW (iterating zip infolist before extractall).**
- **Trade-Off**: [ANALYSIS] Extremely large legitimate archives will require administrator quota configuration.

### `[HIGH]` REC-04: Potential Symlink Traversal during Archive Extraction (RED-FILE-02)
- **The Issue**: [ANALYSIS] Potential Symlink Traversal during Archive Extraction (RED-FILE-02)
- **Where to Look**: [FACT] `File(s) src/phase2/requirements.py: Member extraction 'def _inspect_archive_extraction_safety(self) -> Optional[Dict[str, Any]]:' at line 383 checks paths but does not explicitly reject symlink modes in function '_inspect_archive_extraction_safety'.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Archive extraction relies solely on string prefix matching without POSIX file mode attribute inspection..`
- **Recommended Action**: [RECOMMENDATION] Inspect archive member attributes before extraction (e.g. stat.S_ISLNK(member.external_attr >> 16) in ZIP files) and reject any member containing symlink attributes or pointing outside the extraction boundary. On Python 3.12+, utilize filter='data' for archive extraction APIs. Details: Inspect member.external_attr and reject members flagged as symbolic links with stat.S_ISLNK().; Post-extraction, verify extracted files do not resolve outside the extraction target directory..
- **Why This Helps**: [ANALYSIS] Archive member inspection checks filename path prefixes using string methods but does not inspect POSIX file mode attributes in member.external_attr to detect symbolic link headers.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM**
- **Trade-Off**: [ANALYSIS] Archives legitimately requiring internal symbolic links will be rejected; source archives typically do not require symlinks.

### `[HIGH]` REC-05: Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request (RED-SSRF-01)
- **The Issue**: [ANALYSIS] Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request (RED-SSRF-01)
- **Where to Look**: [FACT] `File(s) src/phase0/ingestion.py: Outbound HTTP call 'with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp:' at line 283 takes variable without verified destination allowlist.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Dynamic outbound HTTP request is issued without destination URL validation or private IP checks; hardcoded or safe requests elsewhere in the file do not protect unvalidated request targets..`
- **Recommended Action**: [RECOMMENDATION] Implement strict URL destination validation: parse target URLs, enforce an explicit allowlist of approved schemes (https://) and hostnames/domains, and resolve hostnames to IP addresses before connecting. Reject private, loopback, and link-local IP addresses (RFC 1918, RFC 3927, 127.0.0.0/8, ::1). Disable automatic HTTP redirect following or re-validate redirect destinations against the allowlist. Details: Validate URLs against an explicit domain allowlist before issuing network requests.; Resolve hostnames and reject requests targeting internal/private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16).; Disable automatic redirects or re-evaluate redirect locations against validation filters..
- **Why This Helps**: [ANALYSIS] Performing HTTP requests to user-supplied URLs without destination validation permits Server-Side Request Forgery against internal infrastructure.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM**
- **Trade-Off**: [ANALYSIS] Outbound requests to unlisted external domains or internal development services will be blocked.

### `[HIGH]` REC-06: Untyped dictionary contracts across pipeline phase boundaries increase interface coupling and runtime schema drift risks (REL-ARCH-MAINT-01).
- **The Issue**: [ANALYSIS] Untyped dictionary contracts across pipeline phase boundaries increase interface coupling and runtime schema drift risks (REL-ARCH-MAINT-01).
- **Where to Look**: [FACT] `Component data exchange in src/phase1/reconstruction.py / src/phase2/requirements.py (Cross-Phase Data Exchange): Phases exchange raw Dict[str, Any] structures and index raw string keys ('apis', 'authentication_components', 'dependency_files', 'deployment_model') without typed schema models.`
- **Recommended Action**: [RECOMMENDATION] Formalize inter-phase data exchange using typed dataclasses or TypedDict schemas to document and validate contracts between pipeline components.
- **Why This Helps**: [ANALYSIS] Relying on raw untyped dictionaries across phase boundaries lacks static schema validation, increasing maintenance overhead and the risk of unhandled key errors during schema evolution.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (defining TypedDict schemas in a common contract module).**
- **Trade-Off**: [ANALYSIS] Requires authoring TypedDict definitions for core phase exchange data structures.

### `[HIGH]` REC-07: Zero-dependency architecture avoids third-party package vulnerabilities but shifts security parsing and boundary validation responsibilities entirely to internal code (REL-ARCH-SEC-01).
- **The Issue**: [ANALYSIS] Zero-dependency architecture avoids third-party package vulnerabilities but shifts security parsing and boundary validation responsibilities entirely to internal code (REL-ARCH-SEC-01).
- **Where to Look**: [FACT] `Requirement REQ-NFR-02 specifies: 'External dependency constraints cannot be established due to absence of dependency manifests.'.`
- **Recommended Action**: [RECOMMENDATION] Maintain zero-dependency constraint if minimal deployment footprint is required, backed by rigorous unit testing and security static analysis of custom parsing logic.
- **Why This Helps**: [ANALYSIS] Relying on standard-library implementations reduces exposure to third-party package vulnerabilities, but places ongoing maintenance, security patching, and validation responsibilities on custom internal routines.
- **How Hard to Fix?**: [ANALYSIS] **LOW (authoring unit test suites for existing custom parsers).**
- **Trade-Off**: [ANALYSIS] Requires dedicated in-house unit testing for boundary condition parsing.

### `[HIGH]` REC-08: Duplicated CLI output sanitization and stream reconfiguration risks divergent security posture across entry points (REL-SEC-MAINT-01).
- **The Issue**: [ANALYSIS] Duplicated CLI output sanitization and stream reconfiguration risks divergent security posture across entry points (REL-SEC-MAINT-01).
- **Where to Look**: [FACT] `Duplication in pipeline.py / ingest.py (safe_write_output / stream wrapper): Duplicate logic verified: identical 'safe_write_output' function (pipeline.py:L160, ingest.py:L35); identical stdout UTF-8 reconfiguration stream wrapper.`
- **Recommended Action**: [RECOMMENDATION] Consolidate duplicated CLI output sanitization and stream reconfiguration logic into a shared common utility module.
- **Why This Helps**: [ANALYSIS] Duplicated output handling and sanitization logic risks divergent updates over time, where security checks or path boundaries applied in one entry point may be missed in another.
- **How Hard to Fix?**: [ANALYSIS] **LOW (extracting helper function to shared utility).**
- **Trade-Off**: [ANALYSIS] Requires creating a shared cli_utils module.

### `[HIGH]` REC-09: High structural complexity in repository traversal 'do_GET' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **The Issue**: [ANALYSIS] High structural complexity in repository traversal 'do_GET' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **Where to Look**: [FACT] `File gui.py in 'do_GET': Function 'do_GET' exhibits maximum block nesting depth of 9 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic.

### `[HIGH]` REC-10: High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability.
- **Where to Look**: [FACT] `File ingest.py in 'safe_write_output': Function 'safe_write_output' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-11: High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability.
- **Where to Look**: [FACT] `File pipeline.py in 'run_pipeline': Function 'run_pipeline' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-12: High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability.
- **Where to Look**: [FACT] `File pipeline.py in 'safe_write_output': Function 'safe_write_output' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-13: High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'inventory': Function 'inventory' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-14: High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'obtain_repository': Function 'obtain_repository' exhibits maximum block nesting depth of 8 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-15: High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_extract_frameworks': Function '_extract_frameworks' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-16: High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_try_download_github_archive': Function '_try_download_github_archive' exhibits maximum block nesting depth of 8 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-17: High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **The Issue**: [ANALYSIS] High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_scan_source_code': Function '_scan_source_code' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic.

### `[HIGH]` REC-18: High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'visit_Call': Function 'visit_Call' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-19: High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_file_handling': Function '_audit_file_handling' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-20: High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_remediate_finding': Function '_remediate_finding' exhibits maximum block nesting depth of 18 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-21: High cyclomatic complexity and deep nesting in '_is_connected_to_deserialization' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_is_connected_to_deserialization' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_is_connected_to_deserialization': Function '_is_connected_to_deserialization' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-22: High cyclomatic complexity and deep nesting in '_is_connected_to_http_request' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_is_connected_to_http_request' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_is_connected_to_http_request': Function '_is_connected_to_http_request' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-23: High cyclomatic complexity and deep nesting in '_collect_python_files' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_collect_python_files' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_collect_python_files': Function '_collect_python_files' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-24: High cyclomatic complexity and deep nesting in '_compute_cyclomatic_complexity' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_compute_cyclomatic_complexity' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_compute_cyclomatic_complexity': Function '_compute_cyclomatic_complexity' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-25: High cyclomatic complexity and deep nesting in '_find_dead_code' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_find_dead_code' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_find_dead_code': Function '_find_dead_code' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-26: High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_architectural_smells': Function '_inspect_architectural_smells' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-27: High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Function '_inspect_ast' exhibits maximum block nesting depth of 9 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-28: High cyclomatic complexity and deep nesting in '_inspect_patterns' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_patterns' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_patterns': Function '_inspect_patterns' exhibits maximum block nesting depth of 6 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-29: High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'evaluate_archive_quota_state': Function 'evaluate_archive_quota_state' exhibits maximum block nesting depth of 8 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-30: High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in '_inspect_source_details': Function '_inspect_source_details' exhibits maximum block nesting depth of 8 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-31: High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_security_rec': Function '_build_security_rec' exhibits maximum block nesting depth of 9 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-32: High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'generate_markdown_report': Function 'generate_markdown_report' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-33: High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in '_get_validated_recommendations': Function '_get_validated_recommendations' exhibits maximum block nesting depth of 5 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-34: High cyclomatic complexity and deep nesting in 'RepositoryIngestionAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'RepositoryIngestionAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'RepositoryIngestionAgent': Class 'RepositoryIngestionAgent' contains 7 methods and spans 750 lines (lines 172-921).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-35: High cyclomatic complexity and deep nesting in 'ProjectReconstructionAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'ProjectReconstructionAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in 'ProjectReconstructionAgent': Class 'ProjectReconstructionAgent' contains 22 methods and spans 713 lines (lines 22-734).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-36: High cyclomatic complexity and deep nesting in 'SecurityAssessmentAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'SecurityAssessmentAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in 'SecurityAssessmentAgent': Class 'SecurityAssessmentAgent' contains 18 methods and spans 712 lines (lines 24-735).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-37: High cyclomatic complexity and deep nesting in 'RequirementsEngineeringAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'RequirementsEngineeringAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in 'RequirementsEngineeringAgent': Class 'RequirementsEngineeringAgent' contains 17 methods and spans 774 lines (lines 30-803).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-38: High cyclomatic complexity and deep nesting in 'RedTeamSecurityAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'RedTeamSecurityAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'RedTeamSecurityAgent': Class 'RedTeamSecurityAgent' contains 19 methods and spans 1354 lines (lines 41-1394).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-39: High cyclomatic complexity and deep nesting in 'BlueTeamDefensiveAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'BlueTeamDefensiveAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in 'BlueTeamDefensiveAgent': Class 'BlueTeamDefensiveAgent' contains 6 methods and spans 1179 lines (lines 12-1190).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-40: High cyclomatic complexity and deep nesting in 'SecurityRetestAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'SecurityRetestAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in 'SecurityRetestAgent': Class 'SecurityRetestAgent' contains 29 methods and spans 1325 lines (lines 31-1355).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-41: High cyclomatic complexity and deep nesting in 'CodeSmellAnalysisAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'CodeSmellAnalysisAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in 'CodeSmellAnalysisAgent': Class 'CodeSmellAnalysisAgent' contains 16 methods and spans 839 lines (lines 31-869).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-42: High cyclomatic complexity and deep nesting in 'CrossDomainAnalysisAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'CrossDomainAnalysisAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'CrossDomainAnalysisAgent': Class 'CrossDomainAnalysisAgent' contains 6 methods and spans 738 lines (lines 55-792).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-43: High cyclomatic complexity and deep nesting in 'RecommendationEngineAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'RecommendationEngineAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in 'RecommendationEngineAgent': Class 'RecommendationEngineAgent' contains 18 methods and spans 1691 lines (lines 14-1704).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-44: High cyclomatic complexity and deep nesting in 'FinalReportGeneratorAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'FinalReportGeneratorAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'FinalReportGeneratorAgent': Class 'FinalReportGeneratorAgent' contains 11 methods and spans 969 lines (lines 20-988).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-45: High cyclomatic complexity and deep nesting in 'TestPhase3ARedTeamAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase3ARedTeamAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase3a_agent.py in 'TestPhase3ARedTeamAgent': Class 'TestPhase3ARedTeamAgent' contains 41 methods and spans 726 lines (lines 53-778).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-46: High cyclomatic complexity and deep nesting in 'TestPhase4ABlueTeamAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase4ABlueTeamAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase4a_agent.py in 'TestPhase4ABlueTeamAgent': Class 'TestPhase4ABlueTeamAgent' contains 29 methods and spans 722 lines (lines 33-754).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-47: High cyclomatic complexity and deep nesting in 'TestPhase5ASecurityRetestAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase5ASecurityRetestAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase5a_agent.py in 'TestPhase5ASecurityRetestAgent': Class 'TestPhase5ASecurityRetestAgent' contains 44 methods and spans 949 lines (lines 32-980).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-48: High cyclomatic complexity and deep nesting in 'TestPhase6CodeSmellAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase6CodeSmellAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase6_agent.py in 'TestPhase6CodeSmellAgent': Class 'TestPhase6CodeSmellAgent' contains 35 methods and spans 657 lines (lines 19-675).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-49: High cyclomatic complexity and deep nesting in 'TestPhase7CrossDomainAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase7CrossDomainAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase7_agent.py in 'TestPhase7CrossDomainAgent': Class 'TestPhase7CrossDomainAgent' contains 61 methods and spans 1025 lines (lines 26-1050).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-50: High cyclomatic complexity and deep nesting in 'TestPhase8RecommendationEngine' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase8RecommendationEngine' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase8_agent.py in 'TestPhase8RecommendationEngine': Class 'TestPhase8RecommendationEngine' contains 56 methods and spans 1276 lines (lines 25-1300).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-51: High cyclomatic complexity and deep nesting in 'TestPhase9ReportGeneratorAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestPhase9ReportGeneratorAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase9_agent.py in 'TestPhase9ReportGeneratorAgent': Class 'TestPhase9ReportGeneratorAgent' contains 31 methods and spans 725 lines (lines 16-740).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-52: High cyclomatic complexity and deep nesting in 'TestMultiPhasePipeline' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestMultiPhasePipeline' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_pipeline.py in 'TestMultiPhasePipeline': Class 'TestMultiPhasePipeline' contains 41 methods and spans 791 lines (lines 38-828).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-53: High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'inventory': Function 'inventory' has a calculated cyclomatic complexity score of 65 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-54: High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'obtain_repository': Function 'obtain_repository' has a calculated cyclomatic complexity score of 53 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-55: High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_determine_project_summary': Function '_determine_project_summary' has a calculated cyclomatic complexity score of 37 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-56: High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **The Issue**: [ANALYSIS] High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_scan_source_code': Function '_scan_source_code' has a calculated cyclomatic complexity score of 47 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic.

### `[HIGH]` REC-57: High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_injection_risks': Function '_audit_injection_risks' has a calculated cyclomatic complexity score of 39 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-58: High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_remediate_finding': Function '_remediate_finding' has a calculated cyclomatic complexity score of 39 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-59: High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_validate_and_sanitize_findings': Function '_validate_and_sanitize_findings' has a calculated cyclomatic complexity score of 29 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-60: High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_architectural_smells': Function '_inspect_architectural_smells' has a calculated cyclomatic complexity score of 32 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-61: High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Function '_inspect_ast' has a calculated cyclomatic complexity score of 64 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-62: High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'analyze': Function 'analyze' has a calculated cyclomatic complexity score of 55 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-63: High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'evaluate_archive_quota_state': Function 'evaluate_archive_quota_state' has a calculated cyclomatic complexity score of 50 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-64: High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in '_inspect_source_details': Function '_inspect_source_details' has a calculated cyclomatic complexity score of 37 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-65: High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in 'generate_recommendations': Function 'generate_recommendations' has a calculated cyclomatic complexity score of 51 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-66: High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_security_rec': Function '_build_security_rec' has a calculated cyclomatic complexity score of 75 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-67: High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_smell_recommendations': Function '_build_smell_recommendations' has a calculated cyclomatic complexity score of 55 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-68: High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'generate_markdown_report': Function 'generate_markdown_report' has a calculated cyclomatic complexity score of 139 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-69: High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in '_get_validated_recommendations': Function '_get_validated_recommendations' has a calculated cyclomatic complexity score of 39 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-70: High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability.
- **Where to Look**: [FACT] `File pipeline.py in 'run_pipeline': Function 'run_pipeline' spans 280 lines of code (lines 227-506).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-71: High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'inventory': Function 'inventory' spans 342 lines of code (lines 468-809).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-72: High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **The Issue**: [ANALYSIS] High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01).
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_scan_source_code': Function '_scan_source_code' spans 160 lines of code (lines 120-279).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Refactoring into generator-based traversal routines enables streaming discovery and potential multi-core parallelism, while requiring modular extraction of filtering logic.

### `[HIGH]` REC-73: High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_injection_risks': Function '_audit_injection_risks' spans 202 lines of code (lines 411-612).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-74: High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_remediate_finding': Function '_remediate_finding' spans 905 lines of code (lines 286-1190).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-75: High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_retest_single_finding': Function '_retest_single_finding' spans 179 lines of code (lines 210-388).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-76: High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Function '_inspect_ast' spans 346 lines of code (lines 183-528).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-77: High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'analyze': Function 'analyze' spans 291 lines of code (lines 502-792).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-78: High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'evaluate_archive_quota_state': Function 'evaluate_archive_quota_state' spans 258 lines of code (lines 234-491).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-79: High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in 'generate_recommendations': Function 'generate_recommendations' spans 315 lines of code (lines 514-828).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-80: High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_security_rec': Function '_build_security_rec' spans 461 lines of code (lines 834-1294).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-81: High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_smell_recommendations': Function '_build_smell_recommendations' spans 191 lines of code (lines 1300-1490).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-82: High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'generate_markdown_report': Function 'generate_markdown_report' spans 608 lines of code (lines 381-988).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[HIGH]` REC-83: Silent exception suppression in 'Line 61' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 61' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File ingest.py in 'Line 61': Except handler catches 'OSError' with a silent suppression statement (line 61).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-84: Silent exception suppression in 'Line 186' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 186' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File pipeline.py in 'Line 186': Except handler catches 'OSError' with a silent suppression statement (line 186).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-85: Silent exception suppression in 'Line 313' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 313' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'Line 313': Except handler catches 'OSError' with a silent suppression statement (line 313).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-86: Silent exception suppression in 'Line 361' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 361' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'Line 361': Except handler catches 'OSError' with a silent suppression statement (line 361).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-87: Silent exception suppression in 'Line 837' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 837' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'Line 837': Except handler catches 'Exception' with a silent suppression statement (line 837).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-88: Silent exception suppression in 'Line 920' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 920' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'Line 920': Except handler catches 'Exception' with a silent suppression statement (line 920).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-89: Silent exception suppression in 'Line 116' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 116' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in 'Line 116': Except handler catches '(OSError, UnicodeDecodeError, PermissionError)' with a silent suppression statement (line 116).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[HIGH]` REC-90: Silent exception suppression in 'Line 276' masks runtime failures and impedes diagnostic visibility.
- **The Issue**: [ANALYSIS] Silent exception suppression in 'Line 276' masks runtime failures and impedes diagnostic visibility.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in 'Line 276': Except handler catches '(OSError, UnicodeDecodeError, PermissionError)' with a silent suppression statement (line 276).`
- **Recommended Action**: [RECOMMENDATION] Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.
- **Why This Helps**: [ANALYSIS] Catching broad exceptions without logging suppresses diagnostic errors, hiding underlying failures (such as permission denials, data corruption, or validation issues) and hindering troubleshooting and incident triage. Cross-domain consequence: Unhandled exceptions in component execution are discarded without diagnostic logging, impairing incident investigation and observability of operational anomalies.
- **How Hard to Fix?**: [ANALYSIS] **LOW (updating exception clauses to log diagnostics).**
- **Trade-Off**: [ANALYSIS] Negligible I/O overhead when debug logging is enabled.

### `[MEDIUM]` REC-91: Unbounded File Read in Application Ingestion Routine (RED-DOS-02)
- **The Issue**: [ANALYSIS] Unbounded File Read in Application Ingestion Routine (RED-DOS-02)
- **Where to Look**: [FACT] `File(s) gui.py: Unbounded read operation 'content = f.read()' at line 67 lacks prior size validation or byte limit.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Repository scanning utilities read entire files into memory using unbounded f.read() without size checks..`
- **Recommended Action**: [RECOMMENDATION] Implement bounded reads or streaming chunking, checking file size prior to reading. Establish sensible size ceilings (e.g., 1MB–5MB) and exclude binary, minified, or auto-generated files from full static scanning. Acknowledge and communicate the operational limitation that truncating large files may result in later patterns or vulnerabilities being missed. Details: Check os.path.getsize() prior to reading, skipping or applying bounded reads (f.read(MAX_READ_BYTES)) for textual analysis.; Stream files line-by-line where static analysis patterns allow.; Document and report any analysis coverage limitations when files are truncated or skipped..
- **Why This Helps**: [ANALYSIS] Static scanning utilities call f.read() on entire file contents without checking file size, allowing oversized or minified files to cause excessive memory allocation.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM**
- **Trade-Off**: [ANALYSIS] Files larger than the bounded threshold will only be partially inspected; static analysis may miss vulnerabilities located past the truncation boundary.

### `[MEDIUM]` REC-92: High cyclomatic complexity and deep nesting in 'main' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'main' hinders code maintainability.
- **Where to Look**: [FACT] `File ingest.py in 'main': Function 'main' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-93: High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_determine_project_summary': Function '_determine_project_summary' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-94: High cyclomatic complexity and deep nesting in '_read_documentation' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_read_documentation' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_read_documentation': Function '_read_documentation' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-95: High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in '_evaluate_spoofing': Function '_evaluate_spoofing' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-96: High cyclomatic complexity and deep nesting in '_evaluate_stride' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_evaluate_stride' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in '_evaluate_stride': Function '_evaluate_stride' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-97: High cyclomatic complexity and deep nesting in '_extract_file_list' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_file_list' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in '_extract_file_list': Function '_extract_file_list' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-98: High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'validate_findings': Function 'validate_findings' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-99: High cyclomatic complexity and deep nesting in 'visit_FunctionDef' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'visit_FunctionDef' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'visit_FunctionDef': Function 'visit_FunctionDef' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-100: High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_injection_risks': Function '_audit_injection_risks' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-101: High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_input_validation_and_dos': Function '_audit_input_validation_and_dos' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-102: High cyclomatic complexity and deep nesting in '_audit_logging_and_errors' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_logging_and_errors' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_logging_and_errors': Function '_audit_logging_and_errors' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-103: High cyclomatic complexity and deep nesting in '_extract_path_list' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_path_list' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_extract_path_list': Function '_extract_path_list' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-104: High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_read_source_corpus': Function '_read_source_corpus' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-105: High cyclomatic complexity and deep nesting in '_deduplicate_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_deduplicate_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_deduplicate_findings': Function '_deduplicate_findings' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-106: High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_resolve_context': Function '_resolve_context' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-107: High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_validate_and_sanitize_findings': Function '_validate_and_sanitize_findings' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-108: High cyclomatic complexity and deep nesting in '_check_deserialization' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_check_deserialization' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_check_deserialization': Function '_check_deserialization' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-109: High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_retest_single_finding': Function '_retest_single_finding' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-110: High cyclomatic complexity and deep nesting in '__init__' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '__init__' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '__init__': Function '__init__' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-111: High cyclomatic complexity and deep nesting in '_format_exception_type' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_format_exception_type' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_format_exception_type': Function '_format_exception_type' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-112: High cyclomatic complexity and deep nesting in '_has_global_mutation' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_has_global_mutation' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_has_global_mutation': Function '_has_global_mutation' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-113: High cyclomatic complexity and deep nesting in '_has_enforcement' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_has_enforcement' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in '_has_enforcement': Function '_has_enforcement' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-114: High cyclomatic complexity and deep nesting in 'collect_malformed' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'collect_malformed' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in 'collect_malformed': Function 'collect_malformed' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-115: High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in 'generate_recommendations': Function 'generate_recommendations' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-116: High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_cross_domain_recommendations': Function '_build_cross_domain_recommendations' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-117: High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_smell_recommendations': Function '_build_smell_recommendations' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-118: High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_merge_duplicate_recs': Function '_merge_duplicate_recs' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-119: High cyclomatic complexity and deep nesting in '_get_requirement_tag' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_get_requirement_tag' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in '_get_requirement_tag': Function '_get_requirement_tag' exhibits maximum block nesting depth of 4 levels.`
- **Recommended Action**: [RECOMMENDATION] Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.
- **Why This Helps**: [ANALYSIS] Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-120: High cyclomatic complexity and deep nesting in 'safe_write_output / stream wrapper' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'safe_write_output / stream wrapper' hinders code maintainability.
- **Where to Look**: [FACT] `File pipeline.py / ingest.py in 'safe_write_output / stream wrapper': Duplicate logic verified: identical 'safe_write_output' function (pipeline.py:L160, ingest.py:L35); identical stdout UTF-8 reconfiguration stream wrapper.`
- **Recommended Action**: [RECOMMENDATION] Extract shared CLI and file utilities into a shared module (e.g., src/common/cli.py).
- **Why This Helps**: [ANALYSIS] Duplicate utility implementations lead to maintenance drift if bug fixes are made in one file but omitted in the other.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-121: High cyclomatic complexity and deep nesting in 'do_GET' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'do_GET' hinders code maintainability.
- **Where to Look**: [FACT] `File gui.py in 'do_GET': Function 'do_GET' actively mutates module-level global variable(s) _CACHED_SAMPLE at line 75.`
- **Recommended Action**: [RECOMMENDATION] Encapsulate mutable state in an instantiated service class or pass state explicitly via parameters.
- **Why This Helps**: [ANALYSIS] Direct mutation of module-level globals creates invisible coupling between disjoint subsystems.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-122: High cyclomatic complexity and deep nesting in 'TestRepositoryIngestionAgent' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestRepositoryIngestionAgent' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_ingestion.py in 'TestRepositoryIngestionAgent': Class 'TestRepositoryIngestionAgent' contains 12 methods and spans 294 lines (lines 27-320).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-123: High cyclomatic complexity and deep nesting in 'TestRequirementsEngineeringAgentFocused' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestRequirementsEngineeringAgentFocused' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_phase2_agents.py in 'TestRequirementsEngineeringAgentFocused': Class 'TestRequirementsEngineeringAgentFocused' contains 13 methods and spans 192 lines (lines 192-383).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-124: High cyclomatic complexity and deep nesting in 'TestRedBlueRetestPipeline' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'TestRedBlueRetestPipeline' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_red_blue_retest.py in 'TestRedBlueRetestPipeline': Class 'TestRedBlueRetestPipeline' contains 12 methods and spans 253 lines (lines 26-278).`
- **Recommended Action**: [RECOMMENDATION] Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.
- **Why This Helps**: [ANALYSIS] The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-125: High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability.
- **Where to Look**: [FACT] `File pipeline.py in 'run_pipeline': Function 'run_pipeline' has a calculated cyclomatic complexity score of 23 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-126: High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_extract_frameworks': Function '_extract_frameworks' has a calculated cyclomatic complexity score of 18 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-127: High cyclomatic complexity and deep nesting in '_is_entry_point_candidate' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_is_entry_point_candidate' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_is_entry_point_candidate': Function '_is_entry_point_candidate' has a calculated cyclomatic complexity score of 18 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-128: High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_try_download_github_archive': Function '_try_download_github_archive' has a calculated cyclomatic complexity score of 18 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-129: High cyclomatic complexity and deep nesting in '_validate_and_normalize_github_url' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_validate_and_normalize_github_url' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_validate_and_normalize_github_url': Function '_validate_and_normalize_github_url' has a calculated cyclomatic complexity score of 24 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-130: High cyclomatic complexity and deep nesting in '_classify_weakness' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_classify_weakness' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in '_classify_weakness': Function '_classify_weakness' has a calculated cyclomatic complexity score of 24 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-131: High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in '_evaluate_spoofing': Function '_evaluate_spoofing' has a calculated cyclomatic complexity score of 17 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-132: High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in '_extract_functional_requirements': Function '_extract_functional_requirements' has a calculated cyclomatic complexity score of 21 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-133: High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'validate_findings': Function 'validate_findings' has a calculated cyclomatic complexity score of 18 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-134: High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'visit_Call': Function 'visit_Call' has a calculated cyclomatic complexity score of 22 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-135: High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_extended_dimensions': Function '_audit_extended_dimensions' has a calculated cyclomatic complexity score of 19 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-136: High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_file_handling': Function '_audit_file_handling' has a calculated cyclomatic complexity score of 23 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-137: High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_read_source_corpus': Function '_read_source_corpus' has a calculated cyclomatic complexity score of 19 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-138: High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_resolve_context': Function '_resolve_context' has a calculated cyclomatic complexity score of 23 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-139: High cyclomatic complexity and deep nesting in '_read_file_safe' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_read_file_safe' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_read_file_safe': Function '_read_file_safe' has a calculated cyclomatic complexity score of 19 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-140: High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_retest_single_finding': Function '_retest_single_finding' has a calculated cyclomatic complexity score of 23 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-141: High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_cross_domain_recommendations': Function '_build_cross_domain_recommendations' has a calculated cyclomatic complexity score of 17 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-142: High cyclomatic complexity and deep nesting in '_derive_confidence' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_derive_confidence' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_confidence': Function '_derive_confidence' has a calculated cyclomatic complexity score of 23 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-143: High cyclomatic complexity and deep nesting in '_derive_security_priority' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_derive_security_priority' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_security_priority': Function '_derive_security_priority' has a calculated cyclomatic complexity score of 17 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-144: High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_merge_duplicate_recs': Function '_merge_duplicate_recs' has a calculated cyclomatic complexity score of 16 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-145: High cyclomatic complexity and deep nesting in '_resolve_requirement' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_resolve_requirement' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_resolve_requirement': Function '_resolve_requirement' has a calculated cyclomatic complexity score of 19 (threshold: 15).`
- **Recommended Action**: [RECOMMENDATION] Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.
- **Why This Helps**: [ANALYSIS] High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-146: Code smell (Repeated Conditionals) detected in 'Line 49'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 49'.
- **Where to Look**: [FACT] `File gui.py in 'Line 49': Chained if/elif construct with 6 sequential branching conditions detected at line 49.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-147: Code smell (Repeated Conditionals) detected in 'Line 238'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 238'.
- **Where to Look**: [FACT] `File pipeline.py in 'Line 238': Chained if/elif construct with 4 sequential branching conditions detected at line 238.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-148: Code smell (Repeated Conditionals) detected in 'Line 859'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 859'.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'Line 859': Chained if/elif construct with 4 sequential branching conditions detected at line 859.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-149: Code smell (Repeated Conditionals) detected in 'Line 288'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 288'.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in 'Line 288': Chained if/elif construct with 4 sequential branching conditions detected at line 288.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-150: Code smell (Repeated Conditionals) detected in 'Line 467'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 467'.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'Line 467': Chained if/elif construct with 4 sequential branching conditions detected at line 467.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-151: Code smell (Repeated Conditionals) detected in 'Line 302'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 302'.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in 'Line 302': Chained if/elif construct with 18 sequential branching conditions detected at line 302.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-152: Code smell (Repeated Conditionals) detected in 'Line 195'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 195'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in 'Line 195': Chained if/elif construct with 4 sequential branching conditions detected at line 195.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-153: Code smell (Repeated Conditionals) detected in 'Line 299'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 299'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in 'Line 299': Chained if/elif construct with 4 sequential branching conditions detected at line 299.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-154: Code smell (Repeated Conditionals) detected in 'Line 272'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 272'.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'Line 272': Chained if/elif construct with 4 sequential branching conditions detected at line 272.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-155: Code smell (Repeated Conditionals) detected in 'Line 900'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 900'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in 'Line 900': Chained if/elif construct with 9 sequential branching conditions detected at line 900.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-156: Code smell (Repeated Conditionals) detected in 'Line 46'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 46'.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'Line 46': Chained if/elif construct with 4 sequential branching conditions detected at line 46.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-157: Code smell (Repeated Conditionals) detected in 'Line 749'.
- **The Issue**: [ANALYSIS] Code smell (Repeated Conditionals) detected in 'Line 749'.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'Line 749': Chained if/elif construct with 4 sequential branching conditions detected at line 749.`
- **Recommended Action**: [RECOMMENDATION] Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).
- **Why This Helps**: [ANALYSIS] Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-158: High cyclomatic complexity and deep nesting in 'main' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'main' hinders code maintainability.
- **Where to Look**: [FACT] `File ingest.py in 'main': Function 'main' spans 81 lines of code (lines 161-241).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-159: High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'obtain_repository': Function 'obtain_repository' spans 144 lines of code (lines 323-466).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-160: High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_determine_project_summary': Function '_determine_project_summary' spans 89 lines of code (lines 281-369).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-161: High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in '_evaluate_spoofing': Function '_evaluate_spoofing' spans 103 lines of code (lines 193-295).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-162: High cyclomatic complexity and deep nesting in '_extract_business_constraints' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_business_constraints' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in '_extract_business_constraints': Function '_extract_business_constraints' spans 98 lines of code (lines 706-803).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-163: High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in '_extract_functional_requirements': Function '_extract_functional_requirements' spans 119 lines of code (lines 155-273).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-164: High cyclomatic complexity and deep nesting in '_extract_non_functional_requirements' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_non_functional_requirements' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in '_extract_non_functional_requirements': Function '_extract_non_functional_requirements' spans 82 lines of code (lines 509-590).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-165: High cyclomatic complexity and deep nesting in '_extract_security_requirements' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_extract_security_requirements' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase2/requirements.py in '_extract_security_requirements': Function '_extract_security_requirements' spans 94 lines of code (lines 288-381).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-166: High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in 'validate_findings': Function 'validate_findings' spans 101 lines of code (lines 1246-1346).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-167: High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_extended_dimensions': Function '_audit_extended_dimensions' spans 132 lines of code (lines 1062-1193).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-168: High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_file_handling': Function '_audit_file_handling' spans 107 lines of code (lines 615-721).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-169: High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_audit_input_validation_and_dos': Function '_audit_input_validation_and_dos' spans 92 lines of code (lines 792-883).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-170: High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_read_source_corpus': Function '_read_source_corpus' spans 109 lines of code (lines 237-345).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-171: High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_validate_and_sanitize_findings': Function '_validate_and_sanitize_findings' spans 84 lines of code (lines 89-172).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-172: High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_architectural_smells': Function '_inspect_architectural_smells' spans 132 lines of code (lines 566-697).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-173: High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in '_inspect_source_details': Function '_inspect_source_details' spans 133 lines of code (lines 92-224).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-174: High cyclomatic complexity and deep nesting in '_build_baseline_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_baseline_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_baseline_recommendations': Function '_build_baseline_recommendations' spans 89 lines of code (lines 1616-1704).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-175: High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_cross_domain_recommendations': Function '_build_cross_domain_recommendations' spans 115 lines of code (lines 1496-1610).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-176: High cyclomatic complexity and deep nesting in 'generate_report_data' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'generate_report_data' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in 'generate_report_data': Function 'generate_report_data' spans 87 lines of code (lines 293-379).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-177: High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability.
- **Where to Look**: [FACT] `File src/phase9/report.py in '_get_validated_recommendations': Function '_get_validated_recommendations' spans 104 lines of code (lines 157-260).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-178: High cyclomatic complexity and deep nesting in 'test_phase8_runs_prerequisites_in_order' hinders code maintainability.
- **The Issue**: [ANALYSIS] High cyclomatic complexity and deep nesting in 'test_phase8_runs_prerequisites_in_order' hinders code maintainability.
- **Where to Look**: [FACT] `File tests/test_pipeline.py in 'test_phase8_runs_prerequisites_in_order': Function 'test_phase8_runs_prerequisites_in_order' spans 85 lines of code (lines 293-377).`
- **Recommended Action**: [RECOMMENDATION] Extract Method refactoring: decompose procedural blocks into focused helper routines.
- **Why This Helps**: [ANALYSIS] Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM (extracting logic into 2-3 focused helper functions).**
- **Trade-Off**: [ANALYSIS] Requires creating small helper functions; zero impact on public API behavior.

### `[MEDIUM]` REC-179: Code smell (Long Parameter List) detected in '__init__'.
- **The Issue**: [ANALYSIS] Code smell (Long Parameter List) detected in '__init__'.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in '__init__': Function '__init__' declares 8 parameters (root_path, phase1_reconstruction, phase2_requirements, phase3a_findings, phase4a_remediations...) at line 58.`
- **Recommended Action**: [RECOMMENDATION] Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.
- **Why This Helps**: [ANALYSIS] Long parameter lists couple functions tightly to caller context and suggest missing abstractions.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-180: Code smell (Long Parameter List) detected in '_build_security_rec'.
- **The Issue**: [ANALYSIS] Code smell (Long Parameter List) detected in '_build_security_rec'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_security_rec': Function '_build_security_rec' declares 14 parameters (fid, finding, p4a_plan, p5a_res, retest_status...) at line 834.`
- **Recommended Action**: [RECOMMENDATION] Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.
- **Why This Helps**: [ANALYSIS] Long parameter lists couple functions tightly to caller context and suggest missing abstractions.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-181: Code smell (Long Parameter List) detected in '_derive_confidence'.
- **The Issue**: [ANALYSIS] Code smell (Long Parameter List) detected in '_derive_confidence'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_confidence': Function '_derive_confidence' declares 7 parameters (finding, p4a_plan, p5a_res, raw_evidence, files_list...) at line 380.`
- **Recommended Action**: [RECOMMENDATION] Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.
- **Why This Helps**: [ANALYSIS] Long parameter lists couple functions tightly to caller context and suggest missing abstractions.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-182: Code smell (Long Parameter List) detected in '_derive_security_priority'.
- **The Issue**: [ANALYSIS] Code smell (Long Parameter List) detected in '_derive_security_priority'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_security_priority': Function '_derive_security_priority' declares 7 parameters (fid, finding, p4a_plan, p5a_res, retest_status...) at line 328.`
- **Recommended Action**: [RECOMMENDATION] Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.
- **Why This Helps**: [ANALYSIS] Long parameter lists couple functions tightly to caller context and suggest missing abstractions.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-183: Code smell (Long Parameter List) detected in '__init__'.
- **The Issue**: [ANALYSIS] Code smell (Long Parameter List) detected in '__init__'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '__init__': Function '__init__' declares 8 parameters (phase1_reconstruction, phase2_requirements, phase3a_findings, phase4a_remediations, phase5a_retest...) at line 105.`
- **Recommended Action**: [RECOMMENDATION] Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.
- **Why This Helps**: [ANALYSIS] Long parameter lists couple functions tightly to caller context and suggest missing abstractions.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-184: Code smell (Long Parameter List) detected in '__init__'.
- **The Issue**: [ANALYSIS] Code smell (Long Parameter List) detected in '__init__'.
- **Where to Look**: [FACT] `File src/phase9/report.py in '__init__': Function '__init__' declares 10 parameters (phase0_inventory, phase1_reconstruction, phase2_requirements, phase2_assessment, phase3a_red_team...) at line 57.`
- **Recommended Action**: [RECOMMENDATION] Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.
- **Why This Helps**: [ANALYSIS] Long parameter lists couple functions tightly to caller context and suggest missing abstractions.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[MEDIUM]` REC-185: Code smell (Inappropriate Abstractions / Primitive Obsession) detected in 'Cross-Phase Data Exchange'.
- **The Issue**: [ANALYSIS] Code smell (Inappropriate Abstractions / Primitive Obsession) detected in 'Cross-Phase Data Exchange'.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py / src/phase2/requirements.py in 'Cross-Phase Data Exchange': Phases exchange raw Dict[str, Any] structures and index raw string keys ('apis', 'authentication_components', 'dependency_files', 'deployment_model') without typed schema models.`
- **Recommended Action**: [RECOMMENDATION] Introduce typed dataclasses or Pydantic models for inter-phase contracts (Phase0Inventory, Phase1Model).
- **Why This Helps**: [ANALYSIS] Passing untyped dictionaries across phase boundaries lacks schema validation, autocomplete, and compile-time type safety.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-186: Use of deprecated MD5/SHA1 cryptographic hash algorithm vulnerable to collisions (RED-CRYPTO-01).
- **The Issue**: [ANALYSIS] Use of deprecated MD5/SHA1 cryptographic hash algorithm vulnerable to collisions (RED-CRYPTO-01).
- **Where to Look**: [FACT] `File(s) src/phase8/recommendations.py: Hash invocation '"implementation_complexity": "LOW (replacing hashlib.md5 with hashlib.sha256).",' at line 1221: MD5/SHA-1 algorithm detected with ambiguous context; verify whether hash collisions affect security boundaries.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Deprecated, collision-vulnerable hash functions (MD5/SHA1) remain in active use..`
- **Recommended Action**: [RECOMMENDATION] Clearly distinguish password storage from general-purpose hashing. For password hashing, use a dedicated, adaptive password-hashing algorithm such as Argon2id, bcrypt, or scrypt with appropriate salt generation and cost parameters; plain SHA-256 is not an acceptable password hash. For non-password integrity verification, upgrade to modern collision-resistant algorithms such as SHA-256 or SHA-512. For message authentication, use HMAC-SHA256 with a protected secret key.
- **Why This Helps**: [ANALYSIS] Use of collision-vulnerable hash functions (MD5, SHA-1) for security-sensitive operations or password storage.
- **How Hard to Fix?**: [ANALYSIS] **LOW (replacing hashlib.md5 with hashlib.sha256).**
- **Trade-Off**: [ANALYSIS] SHA-256 produces longer digest strings (64 hex characters vs 32 for MD5).

### `[LOW]` REC-187: Unrestricted Local Directory Ingestion in CLI Interface (RED-INFO-01)
- **The Issue**: [ANALYSIS] Unrestricted Local Directory Ingestion in CLI Interface (RED-INFO-01)
- **Where to Look**: [FACT] `File(s) src/phase0/ingestion.py: Directory ingestion 'elif source_type in ("dir", "local", "filesystem"):' at line 454 allows operator to scan arbitrary local folders.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=NOT_REMEDIATED, details=Local directory ingestion accepts arbitrary filesystem paths without boundary checking or root directory exclusion..`
- **Recommended Action**: [RECOMMENDATION] Distinguish between intentional local CLI directory selection and unauthenticated service-level path ingestion. For CLI tools, validate that the path exists, is a directory, and reject root or system-critical directories ('/' or 'C:\'). For network-facing services, confine directory ingestion to a configurable authorized workspace root. Details: Resolve input directory paths with os.path.realpath() and disallow operating system root directories.; For service environments, enforce that ingested directory paths reside strictly within an authorized base workspace..
- **Why This Helps**: [ANALYSIS] Local directory ingestion accepts arbitrary filesystem paths without boundary checking, allowing analysis of sensitive system roots.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM**
- **Trade-Off**: [ANALYSIS] Normal project directories remain accessible while system root paths are blocked.

### `[LOW]` REC-188: Maintain verified remediation for Internal Host Filesystem Path Embedded in Contract Output (RED-INFO-02).
- **The Issue**: [ANALYSIS] Maintain verified remediation for Internal Host Filesystem Path Embedded in Contract Output (RED-INFO-02).
- **Where to Look**: [FACT] `File(s) src/phase0/ingestion.py: Root filesystem path embedded in output schema '"root_path": root_path,' at line 788.. Database detected in Phase 1: data_access_layer, data_access_layer, data_access_layer, data_access_layer, data_access_layer. Retest verification (Phase 5A): status=REMEDIATED, details=Internal filesystem paths are virtualized or mapped to repository-relative paths in output contracts..`
- **Recommended Action**: [RECOMMENDATION] Minimize unnecessary host path disclosure by converting absolute filesystem paths to repository-relative or virtualized paths in output reports, while preserving path information required by downstream pipeline consumers. Sanitize temporary directory paths and usernames in public-facing outputs. Details: Convert host absolute paths to repository-relative paths where external output contracts do not require absolute filesystem references.; Sanitize username and temporary directory prefixes from generated report summaries..
- **Why This Helps**: [ANALYSIS] Emitting raw internal filesystem paths (including user home directories and system usernames) in generated output contracts exposes internal infrastructure details.
- **How Hard to Fix?**: [ANALYSIS] **MEDIUM**
- **Trade-Off**: [ANALYSIS] Downstream consumers requiring exact local filesystem paths must be accommodated or provided a clear mapping.

### `[LOW]` REC-189: Code smell (Hard-coded Configuration) detected in 'CONFIG_FILENAMES'.
- **The Issue**: [ANALYSIS] Code smell (Hard-coded Configuration) detected in 'CONFIG_FILENAMES'.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'CONFIG_FILENAMES': Module-level constant 'CONFIG_FILENAMES' embeds a hardcoded mapping table with 18 entries (line 142).`
- **Recommended Action**: [RECOMMENDATION] Externalize configuration mappings into structured JSON, YAML, or dataclass definitions.
- **Why This Helps**: [ANALYSIS] Static rule tables and scoring weights embedded in source files require code edits and redeployments to alter.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-190: Code smell (Hard-coded Configuration) detected in 'EXTENSION_LANGUAGE_MAP'.
- **The Issue**: [ANALYSIS] Code smell (Hard-coded Configuration) detected in 'EXTENSION_LANGUAGE_MAP'.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in 'EXTENSION_LANGUAGE_MAP': Module-level constant 'EXTENSION_LANGUAGE_MAP' embeds a hardcoded mapping table with 42 entries (line 68).`
- **Recommended Action**: [RECOMMENDATION] Externalize configuration mappings into structured JSON, YAML, or dataclass definitions.
- **Why This Helps**: [ANALYSIS] Static rule tables and scoring weights embedded in source files require code edits and redeployments to alter.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-191: Code smell (Magic Numbers) detected in '_determine_project_summary'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_determine_project_summary'.
- **Where to Look**: [FACT] `File src/phase1/reconstruction.py in '_determine_project_summary': Comparison expression uses unexplained numeric literal 20 at line 313.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-192: Code smell (Magic Numbers) detected in 'assess'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in 'assess'.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in 'assess': Comparison expression uses unexplained numeric literal 90 at line 105.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-193: Code smell (Magic Numbers) detected in 'assess'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in 'assess'.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in 'assess': Comparison expression uses unexplained numeric literal 70 at line 107.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-194: Code smell (Magic Numbers) detected in 'assess'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in 'assess'.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in 'assess': Comparison expression uses unexplained numeric literal 50 at line 109.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-195: Code smell (Magic Numbers) detected in '_is_connected_to_deserialization'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_is_connected_to_deserialization'.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_is_connected_to_deserialization': Comparison expression uses unexplained numeric literal 20 at line 445.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-196: Code smell (Magic Numbers) detected in '_is_connected_to_http_request'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_is_connected_to_http_request'.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_is_connected_to_http_request': Comparison expression uses unexplained numeric literal 15 at line 469.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-197: Code smell (Magic Numbers) detected in '_inspect_ast'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_inspect_ast'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Comparison expression uses unexplained numeric literal 80 at line 200.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-198: Code smell (Magic Numbers) detected in '_inspect_ast'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_inspect_ast'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Comparison expression uses unexplained numeric literal 150 at line 201.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-199: Code smell (Magic Numbers) detected in '_inspect_ast'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_inspect_ast'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Comparison expression uses unexplained numeric literal 15 at line 236.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-200: Code smell (Magic Numbers) detected in '_inspect_ast'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_inspect_ast'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Comparison expression uses unexplained numeric literal 25 at line 244.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-201: Code smell (Magic Numbers) detected in '_inspect_ast'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_inspect_ast'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Comparison expression uses unexplained numeric literal 250 at line 431.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-202: Code smell (Magic Numbers) detected in '_inspect_ast'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in '_inspect_ast'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_inspect_ast': Comparison expression uses unexplained numeric literal 350 at line 432.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-203: Code smell (Magic Numbers) detected in 'evaluate_archive_quota_state'.
- **The Issue**: [ANALYSIS] Code smell (Magic Numbers) detected in 'evaluate_archive_quota_state'.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'evaluate_archive_quota_state': Comparison expression uses unexplained numeric literal 15 at line 346.`
- **Recommended Action**: [RECOMMENDATION] Extract numeric literal to a named constant or configuration setting.
- **Why This Helps**: [ANALYSIS] Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-204: Code smell (Multiple Return Points) detected in 'is_supported_github_url'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in 'is_supported_github_url'.
- **Where to Look**: [FACT] `File ingest.py in 'is_supported_github_url': Function 'is_supported_github_url' contains 5 return statements (lines 119, 117, 113, 109, 106).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-205: Code smell (Multiple Return Points) detected in 'run_pipeline'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in 'run_pipeline'.
- **Where to Look**: [FACT] `File pipeline.py in 'run_pipeline': Function 'run_pipeline' contains 11 return statements (lines 486, 480, 445, 421, 398, 379).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-206: Code smell (Multiple Return Points) detected in '_is_entry_point_candidate'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_is_entry_point_candidate'.
- **Where to Look**: [FACT] `File src/phase0/ingestion.py in '_is_entry_point_candidate': Function '_is_entry_point_candidate' contains 7 return statements (lines 840, 836, 834, 832, 830, 828).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-207: Code smell (Multiple Return Points) detected in '_classify_weakness'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_classify_weakness'.
- **Where to Look**: [FACT] `File src/phase2/assessment.py in '_classify_weakness': Function '_classify_weakness' contains 8 return statements (lines 661, 659, 657, 655, 653, 651).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-208: Code smell (Multiple Return Points) detected in '_map_requirement_affected'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_map_requirement_affected'.
- **Where to Look**: [FACT] `File src/phase3a/red_team.py in '_map_requirement_affected': Function '_map_requirement_affected' contains 7 return statements (lines 1394, 1392, 1387, 1382, 1377, 1372).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-209: Code smell (Multiple Return Points) detected in '_remediate_finding'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_remediate_finding'.
- **Where to Look**: [FACT] `File src/phase4a/blue_team.py in '_remediate_finding': Function '_remediate_finding' contains 19 return statements (lines 1152, 1109, 1064, 1022, 976, 932).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-210: Code smell (Multiple Return Points) detected in '_check_cryptographic_hashing'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_check_cryptographic_hashing'.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_check_cryptographic_hashing': Function '_check_cryptographic_hashing' contains 5 return statements (lines 867, 859, 849, 841, 827).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-211: Code smell (Multiple Return Points) detected in '_check_deserialization'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_check_deserialization'.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_check_deserialization': Function '_check_deserialization' contains 5 return statements (lines 691, 683, 673, 665, 656).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-212: Code smell (Multiple Return Points) detected in '_read_file_safe'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_read_file_safe'.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_read_file_safe': Function '_read_file_safe' contains 16 return statements (lines 183, 181, 179, 176, 174, 168).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-213: Code smell (Multiple Return Points) detected in '_retest_single_finding'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_retest_single_finding'.
- **Where to Look**: [FACT] `File src/phase5a/retest.py in '_retest_single_finding': Function '_retest_single_finding' contains 7 return statements (lines 375, 358, 319, 291, 272, 256).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-214: Code smell (Multiple Return Points) detected in '_format_exception_type'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_format_exception_type'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_format_exception_type': Function '_format_exception_type' contains 5 return statements (lines 869, 868, 866, 863, 861).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-215: Code smell (Multiple Return Points) detected in '_read_file_safe'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_read_file_safe'.
- **Where to Look**: [FACT] `File src/phase6/code_smells.py in '_read_file_safe': Function '_read_file_safe' contains 5 return statements (lines 148, 140, 132, 130, 118).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-216: Code smell (Multiple Return Points) detected in 'evaluate_archive_quota_state'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in 'evaluate_archive_quota_state'.
- **Where to Look**: [FACT] `File src/phase7/cross_domain.py in 'evaluate_archive_quota_state': Function 'evaluate_archive_quota_state' contains 14 return statements (lines 483, 473, 456, 439, 423, 408).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-217: Code smell (Multiple Return Points) detected in '_build_security_rec'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_build_security_rec'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_build_security_rec': Function '_build_security_rec' contains 10 return statements (lines 1271, 1209, 1178, 1146, 1114, 1082).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-218: Code smell (Multiple Return Points) detected in '_derive_confidence'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_derive_confidence'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_confidence': Function '_derive_confidence' contains 6 return statements (lines 445, 442, 440, 410, 398, 393).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-219: Code smell (Multiple Return Points) detected in '_derive_security_priority'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_derive_security_priority'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_security_priority': Function '_derive_security_priority' contains 7 return statements (lines 378, 375, 374, 369, 368, 363).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-220: Code smell (Multiple Return Points) detected in '_derive_smell_confidence'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_derive_smell_confidence'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_smell_confidence': Function '_derive_smell_confidence' contains 5 return statements (lines 495, 493, 491, 480, 475).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-221: Code smell (Multiple Return Points) detected in '_derive_smell_priority'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_derive_smell_priority'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_derive_smell_priority': Function '_derive_smell_priority' contains 5 return statements (lines 469, 467, 466, 463, 462).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-222: Code smell (Multiple Return Points) detected in '_resolve_requirement'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_resolve_requirement'.
- **Where to Look**: [FACT] `File src/phase8/recommendations.py in '_resolve_requirement': Function '_resolve_requirement' contains 8 return statements (lines 181, 180, 178, 176, 174, 170).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

### `[LOW]` REC-223: Code smell (Multiple Return Points) detected in '_get_requirement_tag'.
- **The Issue**: [ANALYSIS] Code smell (Multiple Return Points) detected in '_get_requirement_tag'.
- **Where to Look**: [FACT] `File src/phase9/report.py in '_get_requirement_tag': Function '_get_requirement_tag' contains 6 return statements (lines 55, 53, 51, 49, 47, 44).`
- **Recommended Action**: [RECOMMENDATION] Consolidate return statements or decompose function into smaller single-exit routines.
- **Why This Helps**: [ANALYSIS] Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.
- **How Hard to Fix?**: [ANALYSIS] **LOW (targeted refactoring).**
- **Trade-Off**: [ANALYSIS] Requires testing across affected routines to confirm zero functional regressions.

## 12. LIMITATIONS & HONESTY DISCLOSURE

We believe in total transparency. Here is what this static analysis tool can and cannot see:

- **Static Analysis Only**: [FACT] Automated analysis evaluated available code and configuration files in **Multi-Phase System Design & Security Pipeline** using static inspection without running the software on a live internet server.
- **No Production Secrets Tested**: [FACT] We cannot see live server environment variables, production cloud secret managers, or production database passwords.
- **Dynamic Code Construction**: [ANALYSIS] If code constructs routes or queries through extreme dynamic metaprogramming at runtime, static code scanners might not see them without live execution.
- **External Cloud Services**: [UNKNOWN] Third-party cloud service endpoints, external APIs, and live network latency cannot be verified without live internet connectivity.

## 13. MASTER SUMMARY OF ALL IMPROVEMENT SUGGESTIONS (EXECUTIVE ACTION MATRIX)

Below is the consolidated master summary of all improvement suggestions generated for this repository, ranked by priority:

| ID | Category | Problem Analyzed | Suggested Improvement | Expected Benefit | Effort | Priority |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **REC-01** | Security | Potential command or option injection during Git repository cloning via user-controlled URIs (RED-INJ-01). | Validate that the repository source string does not begin with '-' or '--'. In the git clone command array, place the standard '--' option separator immediately before the repository source argument to force Git to interpret it as a positional argument. Validate URL schemes to permit only approved protocols (such as https://, ssh://, or http://), and set GIT_TERMINAL_PROMPT=0 to prevent interactive hangs. | Risk reduction: Restricting URI schemes to approved protocols (https://, git@) and inserting the positional argument delimiter (--) prevents user inputs from being interpreted as CLI option flags. Assumptions & Residual Risks: Repository operations must enforce network timeouts and disk storage quotas to prevent denial-of-service during large or slow repository clones. | **Low** | **CRITICAL** |
| **REC-02** | Security | Insecure object deserialization via unverified joblib/pickle machine learning model loading (RED-DESER-01). | Never deserialize untrusted pickle or joblib data. For structured data or tensor weights, migrate to safer, constrained serialization formats appropriate to the data type (e.g., JSON, Protocol Buffers, SafeTensors for model weights, or ONNX for computational graphs). Where serialized artifacts must be loaded, establish authenticity before deserialization using a trusted digital signature (asymmetric cryptography) or securely managed HMAC key; an ordinary unauthenticated SHA-256 checksum does not establish trust, as an attacker with write access can replace both the artifact and checksum. | Risk reduction: Verifying cryptographic HMAC signatures prior to deserialization detects tampering and prevents loading unverified model files. Assumptions & Residual Risks: Assumes HMAC secret keys and signing certificates are kept confidential; if model files originate from untrusted external sources, migrating to non-executable serialization formats (e.g., Safetensors, ONNX) is strongly recommended as pickle cannot be safely sandboxed. | **Medium** | **HIGH** |
| **REC-03** | Security | Uncontrolled resource consumption via archive decompression bombs (Zip Bombs) (RED-DOS-01). | Implement pre-extraction resource quotas: inspect archive metadata before extraction to enforce limits on total uncompressed byte size, individual member uncompressed size, total member count, and maximum compression ratio. Enforce path traversal checks to reject members with relative escapes (../) or absolute paths. Clean up partial extractions and temporary directories within try...finally blocks. | Risk reduction: Protects host storage and filesystem inode capacity by enforcing pre-extraction thresholds on cumulative uncompressed byte volume and byte ceilings. Assumptions & Residual Risks: Configured quota thresholds (e.g., 200MB, 5000 entries) must accommodate legitimate archives. Ingestion still incurs CPU processing overhead during archive directory traversal, which should be bounded with execution timeouts. | **Low** | **HIGH** |
| **REC-04** | Security | Potential Symlink Traversal during Archive Extraction (RED-FILE-02) | Inspect archive member attributes before extraction (e.g. stat.S_ISLNK(member.external_attr >> 16) in ZIP files) and reject any member containing symlink attributes or pointing outside the extraction boundary. On Python 3.12+, utilize filter='data' for archive extraction APIs. Details: Inspect member.external_attr and reject members flagged as symbolic links with stat.S_ISLNK().; Post-extraction, verify extracted files do not resolve outside the extraction target directory.. | Risk reduction: Arbitrary file modification outside extraction sandbox. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | **Medium** | **HIGH** |
| **REC-05** | Security | Potential Server-Side Request Forgery (SSRF) via Dynamic HTTP Request (RED-SSRF-01) | Implement strict URL destination validation: parse target URLs, enforce an explicit allowlist of approved schemes (https://) and hostnames/domains, and resolve hostnames to IP addresses before connecting. Reject private, loopback, and link-local IP addresses (RFC 1918, RFC 3927, 127.0.0.0/8, ::1). Disable automatic HTTP redirect following or re-validate redirect destinations against the allowlist. Details: Validate URLs against an explicit domain allowlist before issuing network requests.; Resolve hostnames and reject requests targeting internal/private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16).; Disable automatic redirects or re-evaluate redirect locations against validation filters.. | Risk reduction: Cloud credential theft or internal service network scanning. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | **Medium** | **HIGH** |
| **REC-06** | Security | Untyped dictionary contracts across pipeline phase boundaries increase interface coupling and runtime schema drift risks (REL-ARCH-MAINT-01). | Formalize inter-phase data exchange using typed dataclasses or TypedDict schemas to document and validate contracts between pipeline components. | Risk reduction: Reduces data corruption and unhandled schema drift across pipeline phase boundaries by introducing typed data structures (TypedDict or dataclasses). Assumptions & Residual Risks: Runtime validation remains necessary when parsing external or untrusted JSON inputs. | **Medium** | **HIGH** |
| **REC-07** | Security | Zero-dependency architecture avoids third-party package vulnerabilities but shifts security parsing and boundary validation responsibilities entirely to internal code (REL-ARCH-SEC-01). | Maintain zero-dependency constraint if minimal deployment footprint is required, backed by rigorous unit testing and security static analysis of custom parsing logic. | Risk reduction: Avoids third-party dependency supply-chain attack vectors. Assumptions & Residual Risks: Internal parsing logic (URI validation, archive extraction) must be supported by comprehensive unit test harnesses and edge-case testing to match the robustness of mature external libraries. | **Low** | **HIGH** |
| **REC-08** | Security | Duplicated CLI output sanitization and stream reconfiguration risks divergent security posture across entry points (REL-SEC-MAINT-01). | Consolidate duplicated CLI output sanitization and stream reconfiguration logic into a shared common utility module. | Risk reduction: Promotes uniform output sanitization and reduces divergence in terminal escape sequence filtering across CLI entry points by centralizing utility routines. Assumptions & Residual Risks: All current and future CLI entry points must consistently import and route output through the shared utility. | **Low** | **HIGH** |
| **REC-09** | Security | High structural complexity in repository traversal 'do_GET' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-10** | Security | High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-11** | Security | High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-12** | Security | High cyclomatic complexity and deep nesting in 'safe_write_output' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-13** | Security | High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-14** | Security | High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-15** | Security | High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-16** | Security | High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-17** | Security | High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-18** | Security | High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-19** | Security | High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-20** | Security | High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-21** | Security | High cyclomatic complexity and deep nesting in '_is_connected_to_deserialization' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-22** | Security | High cyclomatic complexity and deep nesting in '_is_connected_to_http_request' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-23** | Security | High cyclomatic complexity and deep nesting in '_collect_python_files' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-24** | Security | High cyclomatic complexity and deep nesting in '_compute_cyclomatic_complexity' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-25** | Security | High cyclomatic complexity and deep nesting in '_find_dead_code' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-26** | Security | High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-27** | Security | High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-28** | Security | High cyclomatic complexity and deep nesting in '_inspect_patterns' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-29** | Security | High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-30** | Security | High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-31** | Security | High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-32** | Security | High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-33** | Security | High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-34** | Security | High cyclomatic complexity and deep nesting in 'RepositoryIngestionAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-35** | Security | High cyclomatic complexity and deep nesting in 'ProjectReconstructionAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-36** | Security | High cyclomatic complexity and deep nesting in 'SecurityAssessmentAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-37** | Security | High cyclomatic complexity and deep nesting in 'RequirementsEngineeringAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-38** | Security | High cyclomatic complexity and deep nesting in 'RedTeamSecurityAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-39** | Security | High cyclomatic complexity and deep nesting in 'BlueTeamDefensiveAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-40** | Security | High cyclomatic complexity and deep nesting in 'SecurityRetestAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-41** | Security | High cyclomatic complexity and deep nesting in 'CodeSmellAnalysisAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-42** | Security | High cyclomatic complexity and deep nesting in 'CrossDomainAnalysisAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-43** | Security | High cyclomatic complexity and deep nesting in 'RecommendationEngineAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-44** | Security | High cyclomatic complexity and deep nesting in 'FinalReportGeneratorAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-45** | Security | High cyclomatic complexity and deep nesting in 'TestPhase3ARedTeamAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-46** | Security | High cyclomatic complexity and deep nesting in 'TestPhase4ABlueTeamAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-47** | Security | High cyclomatic complexity and deep nesting in 'TestPhase5ASecurityRetestAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-48** | Security | High cyclomatic complexity and deep nesting in 'TestPhase6CodeSmellAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-49** | Security | High cyclomatic complexity and deep nesting in 'TestPhase7CrossDomainAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-50** | Security | High cyclomatic complexity and deep nesting in 'TestPhase8RecommendationEngine' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-51** | Security | High cyclomatic complexity and deep nesting in 'TestPhase9ReportGeneratorAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-52** | Security | High cyclomatic complexity and deep nesting in 'TestMultiPhasePipeline' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-53** | Security | High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-54** | Security | High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-55** | Security | High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-56** | Security | High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-57** | Security | High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-58** | Security | High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-59** | Security | High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-60** | Security | High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-61** | Security | High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-62** | Security | High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-63** | Security | High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-64** | Security | High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-65** | Security | High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-66** | Security | High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-67** | Security | High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-68** | Security | High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-69** | Security | High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-70** | Security | High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-71** | Security | High cyclomatic complexity and deep nesting in 'inventory' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-72** | Security | High structural complexity in repository traversal '_scan_source_code' poses a scalability bottleneck during filesystem discovery (REL-SMELL-SCALE-01). | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-73** | Security | High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-74** | Security | High cyclomatic complexity and deep nesting in '_remediate_finding' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-75** | Security | High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-76** | Security | High cyclomatic complexity and deep nesting in '_inspect_ast' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-77** | Security | High cyclomatic complexity and deep nesting in 'analyze' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-78** | Security | High cyclomatic complexity and deep nesting in 'evaluate_archive_quota_state' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-79** | Security | High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-80** | Security | High cyclomatic complexity and deep nesting in '_build_security_rec' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-81** | Security | High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-82** | Security | High cyclomatic complexity and deep nesting in 'generate_markdown_report' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **HIGH** |
| **REC-83** | Security | Silent exception suppression in 'Line 61' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-84** | Security | Silent exception suppression in 'Line 186' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-85** | Security | Silent exception suppression in 'Line 313' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-86** | Security | Silent exception suppression in 'Line 361' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-87** | Security | Silent exception suppression in 'Line 837' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-88** | Security | Silent exception suppression in 'Line 920' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-89** | Security | Silent exception suppression in 'Line 116' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-90** | Security | Silent exception suppression in 'Line 276' masks runtime failures and impedes diagnostic visibility. | Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors. | Risk reduction: Phase 7 cross-domain analysis (REL-SMELL-SEC-01) indicates that broad exception suppression directly impairs audit logging & incident detection (STRIDE Repudiation / OWASP A09). Replacing silent handlers with typed exception logging restores visibility into system failures. Assumptions & Residual Risks: Log messages must omit sensitive credentials or tokens. | **Low** | **HIGH** |
| **REC-91** | Maintainability | Unbounded File Read in Application Ingestion Routine (RED-DOS-02) | Implement bounded reads or streaming chunking, checking file size prior to reading. Establish sensible size ceilings (e.g., 1MB–5MB) and exclude binary, minified, or auto-generated files from full static scanning. Acknowledge and communicate the operational limitation that truncating large files may result in later patterns or vulnerabilities being missed. Details: Check os.path.getsize() prior to reading, skipping or applying bounded reads (f.read(MAX_READ_BYTES)) for textual analysis.; Stream files line-by-line where static analysis patterns allow.; Document and report any analysis coverage limitations when files are truncated or skipped.. | Risk reduction: Process memory exhaustion (OOM crash) and denial of service. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | **Medium** | **MEDIUM** |
| **REC-92** | Maintainability | High cyclomatic complexity and deep nesting in 'main' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-93** | Maintainability | High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-94** | Maintainability | High cyclomatic complexity and deep nesting in '_read_documentation' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-95** | Maintainability | High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-96** | Maintainability | High cyclomatic complexity and deep nesting in '_evaluate_stride' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-97** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_file_list' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-98** | Maintainability | High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-99** | Maintainability | High cyclomatic complexity and deep nesting in 'visit_FunctionDef' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-100** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_injection_risks' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-101** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-102** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_logging_and_errors' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-103** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_path_list' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-104** | Maintainability | High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-105** | Maintainability | High cyclomatic complexity and deep nesting in '_deduplicate_findings' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-106** | Maintainability | High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-107** | Maintainability | High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-108** | Maintainability | High cyclomatic complexity and deep nesting in '_check_deserialization' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-109** | Maintainability | High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-110** | Maintainability | High cyclomatic complexity and deep nesting in '__init__' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-111** | Maintainability | High cyclomatic complexity and deep nesting in '_format_exception_type' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-112** | Maintainability | High cyclomatic complexity and deep nesting in '_has_global_mutation' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-113** | Maintainability | High cyclomatic complexity and deep nesting in '_has_enforcement' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-114** | Maintainability | High cyclomatic complexity and deep nesting in 'collect_malformed' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-115** | Maintainability | High cyclomatic complexity and deep nesting in 'generate_recommendations' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-116** | Maintainability | High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-117** | Maintainability | High cyclomatic complexity and deep nesting in '_build_smell_recommendations' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-118** | Maintainability | High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-119** | Maintainability | High cyclomatic complexity and deep nesting in '_get_requirement_tag' hinders code maintainability. | Invert conditionals using guard clauses and extract nested loop bodies into standalone functions. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-120** | Maintainability | High cyclomatic complexity and deep nesting in 'safe_write_output / stream wrapper' hinders code maintainability. | Extract shared CLI and file utilities into a shared module (e.g., src/common/cli.py). | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-121** | Maintainability | High cyclomatic complexity and deep nesting in 'do_GET' hinders code maintainability. | Encapsulate mutable state in an instantiated service class or pass state explicitly via parameters. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-122** | Maintainability | High cyclomatic complexity and deep nesting in 'TestRepositoryIngestionAgent' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-123** | Maintainability | High cyclomatic complexity and deep nesting in 'TestRequirementsEngineeringAgentFocused' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-124** | Maintainability | High cyclomatic complexity and deep nesting in 'TestRedBlueRetestPipeline' hinders code maintainability. | Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-125** | Maintainability | High cyclomatic complexity and deep nesting in 'run_pipeline' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-126** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_frameworks' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-127** | Maintainability | High cyclomatic complexity and deep nesting in '_is_entry_point_candidate' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-128** | Maintainability | High cyclomatic complexity and deep nesting in '_try_download_github_archive' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-129** | Maintainability | High cyclomatic complexity and deep nesting in '_validate_and_normalize_github_url' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-130** | Maintainability | High cyclomatic complexity and deep nesting in '_classify_weakness' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-131** | Maintainability | High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-132** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-133** | Maintainability | High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-134** | Maintainability | High cyclomatic complexity and deep nesting in 'visit_Call' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-135** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-136** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-137** | Maintainability | High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-138** | Maintainability | High cyclomatic complexity and deep nesting in '_resolve_context' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-139** | Maintainability | High cyclomatic complexity and deep nesting in '_read_file_safe' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-140** | Maintainability | High cyclomatic complexity and deep nesting in '_retest_single_finding' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-141** | Maintainability | High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-142** | Maintainability | High cyclomatic complexity and deep nesting in '_derive_confidence' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-143** | Maintainability | High cyclomatic complexity and deep nesting in '_derive_security_priority' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-144** | Maintainability | High cyclomatic complexity and deep nesting in '_merge_duplicate_recs' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-145** | Maintainability | High cyclomatic complexity and deep nesting in '_resolve_requirement' hinders code maintainability. | Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-146** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 49'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-147** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 238'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-148** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 859'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-149** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 288'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-150** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 467'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-151** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 302'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-152** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 195'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-153** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 299'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-154** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 272'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-155** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 900'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-156** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 46'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-157** | Maintainability | Code smell (Repeated Conditionals) detected in 'Line 749'. | Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-158** | Maintainability | High cyclomatic complexity and deep nesting in 'main' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-159** | Maintainability | High cyclomatic complexity and deep nesting in 'obtain_repository' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-160** | Maintainability | High cyclomatic complexity and deep nesting in '_determine_project_summary' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-161** | Maintainability | High cyclomatic complexity and deep nesting in '_evaluate_spoofing' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-162** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_business_constraints' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-163** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_functional_requirements' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-164** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_non_functional_requirements' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-165** | Maintainability | High cyclomatic complexity and deep nesting in '_extract_security_requirements' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-166** | Maintainability | High cyclomatic complexity and deep nesting in 'validate_findings' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-167** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_extended_dimensions' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-168** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_file_handling' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-169** | Maintainability | High cyclomatic complexity and deep nesting in '_audit_input_validation_and_dos' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-170** | Maintainability | High cyclomatic complexity and deep nesting in '_read_source_corpus' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-171** | Maintainability | High cyclomatic complexity and deep nesting in '_validate_and_sanitize_findings' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-172** | Maintainability | High cyclomatic complexity and deep nesting in '_inspect_architectural_smells' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-173** | Maintainability | High cyclomatic complexity and deep nesting in '_inspect_source_details' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-174** | Maintainability | High cyclomatic complexity and deep nesting in '_build_baseline_recommendations' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-175** | Maintainability | High cyclomatic complexity and deep nesting in '_build_cross_domain_recommendations' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-176** | Maintainability | High cyclomatic complexity and deep nesting in 'generate_report_data' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-177** | Maintainability | High cyclomatic complexity and deep nesting in '_get_validated_recommendations' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-178** | Maintainability | High cyclomatic complexity and deep nesting in 'test_phase8_runs_prerequisites_in_order' hinders code maintainability. | Extract Method refactoring: decompose procedural blocks into focused helper routines. | Risk reduction: Reduces the likelihood of logic oversights and unhandled edge cases in critical code paths by simplifying execution flow. | **Medium** | **MEDIUM** |
| **REC-179** | Maintainability | Code smell (Long Parameter List) detected in '__init__'. | Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-180** | Maintainability | Code smell (Long Parameter List) detected in '_build_security_rec'. | Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-181** | Maintainability | Code smell (Long Parameter List) detected in '_derive_confidence'. | Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-182** | Maintainability | Code smell (Long Parameter List) detected in '_derive_security_priority'. | Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-183** | Maintainability | Code smell (Long Parameter List) detected in '__init__'. | Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-184** | Maintainability | Code smell (Long Parameter List) detected in '__init__'. | Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-185** | Maintainability | Code smell (Inappropriate Abstractions / Primitive Obsession) detected in 'Cross-Phase Data Exchange'. | Introduce typed dataclasses or Pydantic models for inter-phase contracts (Phase0Inventory, Phase1Model). | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **MEDIUM** |
| **REC-186** | Maintainability | Use of deprecated MD5/SHA1 cryptographic hash algorithm vulnerable to collisions (RED-CRYPTO-01). | Clearly distinguish password storage from general-purpose hashing. For password hashing, use a dedicated, adaptive password-hashing algorithm such as Argon2id, bcrypt, or scrypt with appropriate salt generation and cost parameters; plain SHA-256 is not an acceptable password hash. For non-password integrity verification, upgrade to modern collision-resistant algorithms such as SHA-256 or SHA-512. For message authentication, use HMAC-SHA256 with a protected secret key. | Risk reduction: Migrating to SHA-256 provides strong collision resistance for cryptographic checksums, data integrity validation, and message authentication. Assumptions & Residual Risks: For user password storage or secret derivation, salted memory-hard key-derivation functions (e.g., Argon2id or bcrypt) must be used rather than general-purpose fast cryptographic hashes like SHA-256. | **Low** | **LOW** |
| **REC-187** | Maintainability | Unrestricted Local Directory Ingestion in CLI Interface (RED-INFO-01) | Distinguish between intentional local CLI directory selection and unauthenticated service-level path ingestion. For CLI tools, validate that the path exists, is a directory, and reject root or system-critical directories ('/' or 'C:\'). For network-facing services, confine directory ingestion to a configurable authorized workspace root. Details: Resolve input directory paths with os.path.realpath() and disallow operating system root directories.; For service environments, enforce that ingested directory paths reside strictly within an authorized base workspace.. | Risk reduction: Normal CLI file enumeration (intended tool behavior; verify if workspace restriction is required). Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | **Medium** | **LOW** |
| **REC-188** | Maintainability | Maintain verified remediation for Internal Host Filesystem Path Embedded in Contract Output (RED-INFO-02). | Minimize unnecessary host path disclosure by converting absolute filesystem paths to repository-relative or virtualized paths in output reports, while preserving path information required by downstream pipeline consumers. Sanitize temporary directory paths and usernames in public-facing outputs. Details: Convert host absolute paths to repository-relative paths where external output contracts do not require absolute filesystem references.; Sanitize username and temporary directory prefixes from generated report summaries.. | Risk reduction: Low-impact internal environment enumeration. Assumptions & Residual Risks: Assumes the remediation covers all user-controlled input paths and edge cases; verification via automated tests is required to confirm fix efficacy. | **Medium** | **LOW** |
| **REC-189** | Maintainability | Code smell (Hard-coded Configuration) detected in 'CONFIG_FILENAMES'. | Externalize configuration mappings into structured JSON, YAML, or dataclass definitions. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-190** | Maintainability | Code smell (Hard-coded Configuration) detected in 'EXTENSION_LANGUAGE_MAP'. | Externalize configuration mappings into structured JSON, YAML, or dataclass definitions. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-191** | Maintainability | Code smell (Magic Numbers) detected in '_determine_project_summary'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-192** | Maintainability | Code smell (Magic Numbers) detected in 'assess'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-193** | Maintainability | Code smell (Magic Numbers) detected in 'assess'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-194** | Maintainability | Code smell (Magic Numbers) detected in 'assess'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-195** | Maintainability | Code smell (Magic Numbers) detected in '_is_connected_to_deserialization'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-196** | Maintainability | Code smell (Magic Numbers) detected in '_is_connected_to_http_request'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-197** | Maintainability | Code smell (Magic Numbers) detected in '_inspect_ast'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-198** | Maintainability | Code smell (Magic Numbers) detected in '_inspect_ast'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-199** | Maintainability | Code smell (Magic Numbers) detected in '_inspect_ast'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-200** | Maintainability | Code smell (Magic Numbers) detected in '_inspect_ast'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-201** | Maintainability | Code smell (Magic Numbers) detected in '_inspect_ast'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-202** | Maintainability | Code smell (Magic Numbers) detected in '_inspect_ast'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-203** | Maintainability | Code smell (Magic Numbers) detected in 'evaluate_archive_quota_state'. | Extract numeric literal to a named constant or configuration setting. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-204** | Maintainability | Code smell (Multiple Return Points) detected in 'is_supported_github_url'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-205** | Maintainability | Code smell (Multiple Return Points) detected in 'run_pipeline'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-206** | Maintainability | Code smell (Multiple Return Points) detected in '_is_entry_point_candidate'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-207** | Maintainability | Code smell (Multiple Return Points) detected in '_classify_weakness'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-208** | Maintainability | Code smell (Multiple Return Points) detected in '_map_requirement_affected'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-209** | Maintainability | Code smell (Multiple Return Points) detected in '_remediate_finding'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-210** | Maintainability | Code smell (Multiple Return Points) detected in '_check_cryptographic_hashing'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-211** | Maintainability | Code smell (Multiple Return Points) detected in '_check_deserialization'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-212** | Maintainability | Code smell (Multiple Return Points) detected in '_read_file_safe'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-213** | Maintainability | Code smell (Multiple Return Points) detected in '_retest_single_finding'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-214** | Maintainability | Code smell (Multiple Return Points) detected in '_format_exception_type'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-215** | Maintainability | Code smell (Multiple Return Points) detected in '_read_file_safe'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-216** | Maintainability | Code smell (Multiple Return Points) detected in 'evaluate_archive_quota_state'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-217** | Maintainability | Code smell (Multiple Return Points) detected in '_build_security_rec'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-218** | Maintainability | Code smell (Multiple Return Points) detected in '_derive_confidence'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-219** | Maintainability | Code smell (Multiple Return Points) detected in '_derive_security_priority'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-220** | Maintainability | Code smell (Multiple Return Points) detected in '_derive_smell_confidence'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-221** | Maintainability | Code smell (Multiple Return Points) detected in '_derive_smell_priority'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-222** | Maintainability | Code smell (Multiple Return Points) detected in '_resolve_requirement'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
| **REC-223** | Maintainability | Code smell (Multiple Return Points) detected in '_get_requirement_tag'. | Consolidate return statements or decompose function into smaller single-exit routines. | Risk reduction: Eliminates unexpected side effects and brittle code constructs, supporting system stability. | **Low** | **LOW** |
