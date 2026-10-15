"""
Phase 0: Repository Ingestion Agent Module.

Obtains and structurally inventories software repositories from:
1. A GitHub repository URL (cloned via git)
2. A ZIP archive (extracted securely)
3. A local extracted directory

Outputs the exact Phase 0 structural JSON inventory.
"""

import os
import sys
import re
import stat
import json
import shutil
import zipfile
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple

# Defensive resource quotas and thresholds
MAX_ZIP_EXTRACTED_BYTES = 200 * 1024 * 1024  # 200 MB maximum uncompressed size
MAX_ZIP_ENTRIES = 10000                      # 10,000 maximum entries
MAX_ZIP_RATIO = 100.0                        # 100:1 maximum compression ratio
MAX_READ_BYTES = 5 * 1024 * 1024             # 5 MB maximum buffer read limit
MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024       # 100 MB max archive download
MAX_LOCAL_FILES = 15000                      # 15,000 max scanned local files
MAX_LOCAL_BYTES = 300 * 1024 * 1024          # 300 MB max scanned local bytes
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024     # 50 MB max single file size
DOWNLOAD_TIMEOUT_SECONDS = 30                # 30s request timeout

# Recognized primary application source code languages
SOURCE_CODE_LANGUAGES = {
    "Python", "JavaScript", "TypeScript", "Go", "Java", "Rust",
    "C", "C++", "C#", "PHP", "Ruby", "Swift", "Kotlin", "Scala"
}

# Standard directories to exclude from application source code analysis
EXCLUDED_DIRECTORIES = {
    "node_modules",
    ".git",
    "build",
    "dist",
    "target",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    ".idea",
    ".vscode",
    ".gradle",
    ".mvn",
    ".next",
    ".nuxt",
    "vendor",
    "coverage",
    ".tox",
    ".mypy_cache",
}

# Known file extensions mapped to languages
EXTENSION_LANGUAGE_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C",
    ".cpp": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".php": "PHP",
    ".rb": "Ruby",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".scala": "Scala",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sass": "SASS",
    ".less": "LESS",
    ".sql": "SQL",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
    ".xml": "XML",
    ".md": "Markdown",
    ".markdown": "Markdown",
    ".rst": "reStructuredText",
    ".txt": "Text",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".dockerfile": "Dockerfile",
}

# Dependency manifest filenames
DEPENDENCY_MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "composer.lock",
}

# Configuration filenames
CONFIG_FILENAMES = {
    "tsconfig.json",
    "jsconfig.json",
    "vite.config.js",
    "vite.config.ts",
    "next.config.js",
    "next.config.mjs",
    "webpack.config.js",
    "tailwind.config.js",
    "babel.config.json",
    ".eslintrc.json",
    ".eslintrc.js",
    ".prettierrc",
    "pytest.ini",
    "tox.ini",
    "setup.cfg",
    "application.properties",
    "application.yml",
    "application.yaml",
}

# Database file patterns
DATABASE_EXTENSIONS = {".sql", ".prisma"}


class SecurityError(Exception):
    """Raised when a security validation check fails (e.g., zip-slip attack)."""
    pass


class RepositoryIngestionAgent:
    """Agent responsible for obtaining and structurally inventorying a software repository."""

    def __init__(self, work_dir: Optional[str] = None):
        self.work_dir = work_dir or tempfile.gettempdir()

    def _validate_and_normalize_github_url(self, source: str) -> str:
        """
        Validates that source is a valid, supported GitHub repository URL.
        Rejects:
        - Leading hyphens (CLI option injection)
        - Embedded credentials (user:pass@...)
        - Unsupported schemes (must be HTTPS or git@)
        - Arbitrary / spoofed hostnames (must be strictly github.com or www.github.com)
        - Profile-only URLs (e.g. https://github.com/username) without repository
        - Bare usernames
        - Malformed paths or directory traversals
        Returns the normalized HTTPS clone URL (e.g. https://github.com/owner/repo).
        """
        clean = source.strip()
        if clean.startswith(("-", "--")):
            raise SecurityError(f"Invalid repository source: leading hyphens not permitted: {source}")

        # Check for Git SSH format: git@github.com:owner/repo(.git)
        ssh_match = re.match(r'^git@github\.com:([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$', clean)
        if ssh_match:
            owner, repo = ssh_match.group(1), ssh_match.group(2)
            if repo in (".", "..") or owner in (".", ".."):
                raise ValueError(f"Invalid repository path: '{owner}/{repo}'.")
            return f"https://github.com/{owner}/{repo}"

        # Otherwise parse as URL
        if not (clean.startswith("http://") or clean.startswith("https://")):
            # Check if it's in short form: owner/repo
            short_match = re.match(r'^([a-zA-Z0-9_.-]+)/([a-zA-Z0-9_.-]+?)(?:\.git)?/?$', clean)
            if short_match:
                owner, repo = short_match.group(1), short_match.group(2)
                if repo in (".", "..") or owner in (".", ".."):
                    raise ValueError(f"Invalid repository path: '{owner}/{repo}'.")
                return f"https://github.com/{owner}/{repo}"
            # Single token (profile or bare username candidate)
            if "/" not in clean and "\\" not in clean:
                raise ValueError(
                    f"GitHub username or profile '{clean}' supplied without a repository. "
                    "Please specify a specific repository in the format 'owner/repo' or 'https://github.com/owner/repo'."
                )
            clean = f"https://{clean}"

        parsed = urllib.parse.urlparse(clean)

        # Reject embedded credentials
        if parsed.username or parsed.password:
            raise SecurityError("Embedded credentials in repository URL are not permitted.")

        # Scheme must be https
        if parsed.scheme.lower() != "https":
            raise ValueError(f"Unsupported URL scheme '{parsed.scheme}'; only HTTPS is permitted for GitHub repositories.")

        # Hostname validation: strictly github.com or www.github.com
        hostname = (parsed.hostname or "").lower()
        if hostname not in ("github.com", "www.github.com"):
            raise ValueError(f"Invalid host '{hostname}'; only 'github.com' is supported.")

        # Path validation: must have exactly 2 parts (/owner/repo)
        path_parts = [p for p in parsed.path.strip("/").split("/") if p]
        if len(path_parts) == 1:
            raise ValueError(
                f"GitHub profile URL '{source}' supplied without a repository. "
                "Please specify a specific repository in the format 'https://github.com/owner/repo'."
            )
        elif len(path_parts) != 2:
            raise ValueError(f"Invalid GitHub repository URL path: '{parsed.path}'. Expected format: '/owner/repo'.")

        owner, repo = path_parts[0], path_parts[1]
        if repo.endswith(".git"):
            repo = repo[:-4]

        if not re.match(r'^[a-zA-Z0-9_.-]+$', owner) or not re.match(r'^[a-zA-Z0-9_.-]+$', repo) or repo in (".", "..") or owner in (".", ".."):
            raise ValueError(f"Invalid characters in repository path: '{owner}/{repo}'.")

        return f"https://github.com/{owner}/{repo}"

    def _try_download_github_archive(self, clean_source: str) -> Optional[str]:
        """
        Attempts to stream a repository ZIP archive directly from GitHub over HTTPS
        when git clone fails. Applies bounded streaming and size limits.
        """
        try:
            parsed = urllib.parse.urlparse(clean_source)
            path_parts = [p for p in parsed.path.strip("/").split("/") if p]
            if len(path_parts) < 2:
                return None
            owner, repo = path_parts[0], path_parts[1]
            if repo.endswith(".git"):
                repo = repo[:-4]

            candidate_urls = [
                f"https://github.com/{owner}/{repo}/archive/refs/heads/main.zip",
                f"https://github.com/{owner}/{repo}/archive/refs/heads/master.zip",
                f"https://api.github.com/repos/{owner}/{repo}/zipball"
            ]

            headers = {
                "User-Agent": "SentinelGuard/1.0",
                "Accept": "*/*"
            }

            for url in candidate_urls:
                temp_zip = None
                try:
                    req = urllib.request.Request(url, headers=headers)
                    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp:
                        if resp.status == 200:
                            temp_zip = tempfile.NamedTemporaryFile(suffix=".zip", delete=False, dir=self.work_dir)
                            total_downloaded = 0
                            chunk_size = 64 * 1024
                            while True:
                                chunk = resp.read(chunk_size)
                                if not chunk:
                                    break
                                total_downloaded += len(chunk)
                                if total_downloaded > MAX_DOWNLOAD_BYTES:
                                    temp_zip.close()
                                    if os.path.exists(temp_zip.name):
                                        os.remove(temp_zip.name)
                                    raise SecurityError(
                                        f"Remote download size exceeds maximum allowed threshold ({MAX_DOWNLOAD_BYTES // (1024*1024)} MB)."
                                    )
                                temp_zip.write(chunk)
                            temp_zip.close()
                            if total_downloaded > 0:
                                return temp_zip.name
                            else:
                                if os.path.exists(temp_zip.name):
                                    os.remove(temp_zip.name)
                except SecurityError:
                    raise
                except Exception:
                    if temp_zip and os.path.exists(temp_zip.name):
                        try:
                            os.remove(temp_zip.name)
                        except OSError:
                            pass
                    continue

            return None
        except SecurityError:
            raise
        except Exception:
            return None

    def obtain_repository(self, source_type: str, source: str) -> Tuple[str, bool]:
        """
        Obtains the repository files from GitHub, a ZIP file, or an existing directory.
        Returns (extracted_path, is_temporary).
        """
        source_type = source_type.lower().strip()

        if source_type in ("github", "profile"):
            clean_source = self._validate_and_normalize_github_url(source)
            target_dir = tempfile.mkdtemp(prefix="repo_ingest_", dir=self.work_dir)
            git_err = ""

            try:
                env = os.environ.copy()
                env["GIT_TERMINAL_PROMPT"] = "0"
                cmd = ["git", "clone", "--depth", "1", "--", clean_source, target_dir]
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, timeout=60)
                if result.returncode == 0:
                    return target_dir, True
                git_err = result.stderr.strip()
            except subprocess.TimeoutExpired:
                git_err = "Git clone connection timed out after 60 seconds."
            except Exception as e:
                git_err = str(e)
            finally:
                if git_err and os.path.exists(target_dir):
                    shutil.rmtree(target_dir, ignore_errors=True)

            # Automated fallback: direct GitHub archive download over HTTPS
            fallback_zip = self._try_download_github_archive(clean_source)
            if fallback_zip:
                try:
                    extracted_path, is_temp = self.obtain_repository(source_type="zip", source=fallback_zip)
                    return extracted_path, is_temp
                finally:
                    if os.path.exists(fallback_zip):
                        try:
                            os.remove(fallback_zip)
                        except OSError:
                            pass

            raise RuntimeError(
                f"Failed to access GitHub repository from {source}.\n"
                f"Git Error: {git_err}\n"
                "Automatic archive download fallback also failed. "
                "Please verify the repository URL is public, check your network/firewall connection, or download the repository ZIP manually and select 'zip' in the GUI."
            )

        elif source_type == "zip":
            if not source or not isinstance(source, str) or not source.strip():
                raise ValueError("Repository source path or URL must not be empty.")
            if not os.path.exists(source) or not os.path.isfile(source):
                raise FileNotFoundError(f"ZIP file not found at: {source}")

            target_dir = tempfile.mkdtemp(prefix="repo_zip_", dir=self.work_dir)
            target_abs = os.path.abspath(target_dir)
            try:
                with zipfile.ZipFile(source, "r") as z:
                    infolist = z.infolist()
                    if len(infolist) > MAX_ZIP_ENTRIES:
                        raise SecurityError(f"Decompression bomb detected: total entries ({len(infolist)}) exceeds maximum limit.")

                    total_uncompressed = 0
                    seen_members = set()

                    for member in infolist:
                        # Reject symlink members to prevent symlink traversal attacks
                        mode = member.external_attr >> 16
                        if stat.S_ISLNK(mode):
                            raise SecurityError(f"Symlink member detected in ZIP archive: extraction denied ({member.filename})")

                        if member.file_size < 0:
                            raise SecurityError(f"Negative file size detected in member: {member.filename}")

                        total_uncompressed += member.file_size
                        if total_uncompressed > MAX_ZIP_EXTRACTED_BYTES:
                            raise SecurityError("Decompression bomb detected: cumulative uncompressed size exceeds allowed threshold.")

                        if member.file_size > MAX_SINGLE_FILE_BYTES:
                            raise SecurityError(f"Individual file size ({member.file_size} bytes) exceeds maximum threshold in member: {member.filename}")

                        if member.compress_size == 0 and member.file_size > 5 * 1024 * 1024:
                            raise SecurityError(f"Decompression bomb detected: zero compressed size with large uncompressed file ({member.filename})")
                        elif member.compress_size > 0:
                            ratio = member.file_size / member.compress_size
                            if ratio > MAX_ZIP_RATIO and member.file_size > 10 * 1024 * 1024:
                                raise SecurityError(f"Decompression bomb detected: compression ratio ({ratio:.1f}) exceeds maximum threshold.")

                        # Secure extraction against zip-slip path traversal, absolute paths, UNC paths, and drive escapes
                        norm_name = member.filename.replace("\\", "/")

                        if norm_name.startswith("//") or member.filename.startswith("\\\\"):
                            raise SecurityError(f"UNC path detected in ZIP member: {member.filename}")

                        if (
                            norm_name.startswith("/")
                            or (len(norm_name) > 1 and norm_name[1] == ":")
                            or os.path.isabs(member.filename)
                            or Path(norm_name).is_absolute()
                        ):
                            raise SecurityError(f"Absolute path or drive letter escape detected in ZIP member: {member.filename}")

                        if norm_name.startswith("../") or "/../" in norm_name or norm_name == ".." or norm_name.endswith("/.."):
                            raise SecurityError(f"Path traversal detected in ZIP member: {member.filename}")

                        member_path = os.path.abspath(os.path.join(target_abs, norm_name))
                        try:
                            common = os.path.commonpath([target_abs, member_path])
                        except ValueError:
                            raise SecurityError(f"Cross-drive path traversal detected in ZIP member: {member.filename}")

                        if common != target_abs:
                            raise SecurityError(f"Zip slip attempt detected in member: {member.filename}")

                        # Handle duplicate paths safely without corruption
                        if norm_name in seen_members:
                            continue
                        seen_members.add(norm_name)

                    z.extractall(target_dir)
                return target_dir, True
            except zipfile.BadZipFile as e:
                shutil.rmtree(target_dir, ignore_errors=True)
                raise RuntimeError(f"Malformed or corrupted ZIP archive: {str(e)}")
            except SecurityError:
                shutil.rmtree(target_dir, ignore_errors=True)
                raise
            except Exception as e:
                shutil.rmtree(target_dir, ignore_errors=True)
                raise RuntimeError(f"Failed to extract ZIP archive: {str(e)}")

        elif source_type in ("dir", "local", "filesystem"):
            if not source or not isinstance(source, str) or not source.strip():
                raise ValueError("Repository source path or URL must not be empty.")
            resolved = os.path.abspath(source)
            # Prevent ingestion of host system root
            if resolved in ("/", "\\") or (len(resolved) <= 3 and resolved[1:3] in (":\\", ":/")):
                raise SecurityError("Direct ingestion of host system root drive is not permitted.")
            if not os.path.exists(resolved) or not os.path.isdir(resolved):
                raise FileNotFoundError(f"Directory not found: {source}")
            return resolved, False

        else:
            raise ValueError(f"Unsupported repository_source_type: {source_type}. Must be 'github', 'zip', or 'dir'.")

    def inventory(self, root_path: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Performs a comprehensive structural inventory of the repository root."""
        root_path = os.path.abspath(root_path)
        if not os.path.exists(root_path) or not os.path.isdir(root_path):
            raise FileNotFoundError(f"Repository root directory does not exist or is not a directory: {root_path}")

        file_inventory: List[str] = []
        source_files: List[Dict[str, Any]] = []
        configuration_files: List[Dict[str, Any]] = []
        dependency_files: List[Dict[str, Any]] = []
        database_files: List[Dict[str, Any]] = []
        infrastructure_files: List[Dict[str, Any]] = []
        test_files: List[Dict[str, Any]] = []
        documentation_files: List[Dict[str, Any]] = []
        ci_cd_files: List[Dict[str, Any]] = []
        generated_files: List[str] = []
        potentially_sensitive_files: List[Dict[str, Any]] = []
        entry_point_candidates: List[Dict[str, Any]] = []
        external_services: List[Dict[str, Any]] = []
        unknowns: List[Dict[str, Any]] = []

        warnings: List[str] = []
        skipped_files: List[Dict[str, str]] = []
        unsupported_files: List[Dict[str, str]] = []
        total_scanned_bytes = 0
        ingestion_status = "COMPLETE"
        scan_completeness = "full"

        detected_languages: Set[str] = set()
        detected_frameworks: Set[str] = set()

        # Directories that should be traversed despite starting with a dot
        INCLUDED_HIDDEN_DIRECTORIES = {".github", ".circleci", ".gitlab"}

        for dirpath, dirnames, filenames in os.walk(root_path):
            # Check for directory symlink escapes outside repository root
            for d in list(dirnames):
                d_full = os.path.join(dirpath, d)
                if os.path.islink(d_full):
                    try:
                        target_real = os.path.realpath(d_full)
                        try:
                            common = os.path.commonpath([root_path, target_real])
                        except ValueError:
                            common = ""
                        if common != root_path:
                            warnings.append(f"Skipped directory symlink pointing outside repository root: {d}")
                            skipped_files.append({
                                "path": os.path.relpath(d_full, root_path).replace("\\", "/"),
                                "reason": "DIRECTORY_SYMLINK_ESCAPE"
                            })
                            dirnames.remove(d)
                            continue
                    except OSError:
                        dirnames.remove(d)
                        continue

            # Exclude vendor and generated directories from recursive walk, preserving CI/CD configuration
            excluded_here = [
                d for d in dirnames
                if d in EXCLUDED_DIRECTORIES or (d.startswith(".") and d not in INCLUDED_HIDDEN_DIRECTORIES)
            ]
            for d in excluded_here:
                # Keep tracked generated paths
                rel_excluded = os.path.relpath(os.path.join(dirpath, d), root_path).replace("\\", "/")
                generated_files.append(rel_excluded)
                dirnames.remove(d)

            # Check maximum file count limit
            if len(file_inventory) >= MAX_LOCAL_FILES:
                warnings.append(f"Maximum local file count threshold reached ({MAX_LOCAL_FILES}). Halting further directory descent.")
                ingestion_status = "PARTIAL"
                scan_completeness = "partial"
                break

            # Check maximum scanned bytes limit
            if total_scanned_bytes >= MAX_LOCAL_BYTES:
                warnings.append(f"Maximum local scanned bytes threshold reached ({MAX_LOCAL_BYTES // (1024*1024)} MB). Halting further directory descent.")
                ingestion_status = "PARTIAL"
                scan_completeness = "partial"
                break

            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, root_path).replace("\\", "/")

                # Check file symlink escapes outside repository root
                if os.path.islink(full_path):
                    try:
                        target_real = os.path.realpath(full_path)
                        try:
                            common = os.path.commonpath([root_path, target_real])
                        except ValueError:
                            common = ""
                        if common != root_path:
                            warnings.append(f"Skipped file symlink pointing outside repository root: {rel_path}")
                            skipped_files.append({"path": rel_path, "reason": "FILE_SYMLINK_ESCAPE"})
                            continue
                    except OSError:
                        skipped_files.append({"path": rel_path, "reason": "UNREADABLE_SYMLINK"})
                        continue

                # Check file accessibility & size
                try:
                    fsize = os.path.getsize(full_path)
                    total_scanned_bytes += fsize
                except (OSError, PermissionError) as e:
                    warnings.append(f"Unreadable file metadata: {rel_path} ({str(e)})")
                    skipped_files.append({"path": rel_path, "reason": "UNREADABLE_METADATA"})
                    continue

                if fsize > MAX_SINGLE_FILE_BYTES:
                    warnings.append(f"File size exceeds maximum threshold ({MAX_SINGLE_FILE_BYTES // (1024*1024)} MB): {rel_path}")
                    skipped_files.append({"path": rel_path, "reason": "FILE_SIZE_LIMIT_EXCEEDED"})
                    file_inventory.append(rel_path)
                    continue

                file_inventory.append(rel_path)

                ext = Path(filename).suffix.lower()
                lang = EXTENSION_LANGUAGE_MAP.get(ext, "Unknown")
                if lang != "Unknown":
                    detected_languages.add(lang)

                # 1. CI/CD Files
                if ".github/workflows" in rel_path or filename in (".gitlab-ci.yml", "Jenkinsfile", ".travis.yml"):
                    ci_cd_files.append({
                        "path": rel_path,
                        "type": "ci_cd_workflow",
                        "language": lang if lang != "Unknown" else "YAML",
                        "purpose": "Continuous integration and deployment automation pipeline.",
                        "is_application_code": False,
                        "importance": "high"
                    })
                    continue

                # 2. Dependency Manifests
                if filename.lower() in DEPENDENCY_MANIFEST_NAMES:
                    dep_obj = {
                        "path": rel_path,
                        "type": "dependency_manifest",
                        "language": lang if lang != "Unknown" else "JSON/Text",
                        "purpose": f"Declares project dependencies and build specifications ({filename}).",
                        "is_application_code": False,
                        "importance": "high",
                    }
                    dependency_files.append(dep_obj)
                    # Extract frameworks from manifest content
                    self._extract_frameworks(full_path, filename, detected_frameworks, external_services)
                    continue

                # 3. Potentially Sensitive Files
                lower_fn = filename.lower()
                is_sensitive = (
                    lower_fn.startswith(".env")
                    or lower_fn.endswith((".pem", ".key", ".pfx", ".p12"))
                    or "id_rsa" in lower_fn
                    or lower_fn.startswith("credentials")
                    or lower_fn.startswith("secret")
                )
                if is_sensitive:
                    potentially_sensitive_files.append({
                        "path": rel_path,
                        "type": "potential_secret_or_env",
                        "language": lang if lang != "Unknown" else "Text/Config",
                        "purpose": "Potential environment configuration or key filename match (contents unread).",
                        "is_application_code": False,
                        "importance": "high",
                    })
                    # Dedicated secret/key files (not application source code) should not fall through to unknowns
                    if ext not in (".py", ".js", ".ts", ".go", ".java", ".c", ".cpp", ".rs"):
                        continue

                # 4. Infrastructure & Deployment Files
                if (
                    lower_fn.startswith("dockerfile")
                    or lower_fn.startswith("docker-compose")
                    or ext in (".tf", ".hcl")
                    or "k8s" in rel_path
                    or "helm" in rel_path
                ):
                    infrastructure_files.append({
                        "path": rel_path,
                        "type": "infrastructure_as_code",
                        "language": lang if lang != "Unknown" else "Infrastructure Config",
                        "purpose": "Containerization, orchestration, or infrastructure definition.",
                        "is_application_code": False,
                        "importance": "high",
                    })
                    continue

                # 5. Database & Schema Files
                if (
                    ext in DATABASE_EXTENSIONS
                    or "migration" in rel_path.lower()
                    or "schema" in lower_fn
                ) and ext not in (".js", ".ts", ".py"):
                    database_files.append({
                        "path": rel_path,
                        "type": "database_schema",
                        "language": lang if lang != "Unknown" else "SQL/Schema",
                        "purpose": "Database schema definition or data migration script.",
                        "is_application_code": False,
                        "importance": "high",
                    })
                    continue

                # 6. Test Files
                if (
                    lower_fn.startswith("test_")
                    or lower_fn.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "_test.go", "_test.kt", "Test.java", "Spec.scala"))
                    or lower_fn in ("test.py", "tests.py")
                    or "/tests/" in f"/{rel_path.lower()}"
                    or "/test/" in f"/{rel_path.lower()}"
                ):
                    test_files.append({
                        "path": rel_path,
                        "type": "test_suite",
                        "language": lang,
                        "purpose": "Automated verification test case or test suite.",
                        "is_application_code": False,
                        "importance": "medium",
                    })
                    continue

                # 7. Documentation Files
                if lower_fn.startswith("readme") or ext in (".md", ".rst") or "docs/" in rel_path.lower():
                    documentation_files.append({
                        "path": rel_path,
                        "type": "documentation",
                        "language": lang,
                        "purpose": "Human-readable documentation, specifications, or user guides.",
                        "is_application_code": False,
                        "importance": "medium" if "readme" in lower_fn else "low",
                    })
                    continue

                # 8. Configuration Files
                if lower_fn in CONFIG_FILENAMES or ext in (".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"):
                    configuration_files.append({
                        "path": rel_path,
                        "type": "configuration",
                        "language": lang,
                        "purpose": "Application or tooling configuration settings.",
                        "is_application_code": False,
                        "importance": "medium",
                    })
                    continue

                # 9. Source Code Files (Reconciled with supported languages: Python, JS, TS, Go, Java, Rust, C, C++, C#, PHP, Ruby, Swift, Kotlin, Scala)
                if lang in SOURCE_CODE_LANGUAGES:
                    is_entry = self._is_entry_point_candidate(filename, full_path, ext)
                    source_obj = {
                        "path": rel_path,
                        "type": "source_code",
                        "language": lang,
                        "purpose": f"Executable application logic ({lang}).",
                        "is_application_code": True,
                        "importance": "high" if is_entry else "medium",
                    }
                    source_files.append(source_obj)

                    if is_entry:
                        entry_point_candidates.append({
                            "path": rel_path,
                            "type": "entry_point_candidate",
                            "language": lang,
                            "purpose": "Application startup, server initialization, or CLI dispatch.",
                            "is_application_code": True,
                            "importance": "high",
                        })
                    continue

                # 10. Frontend Markup / Styling Source Files
                if lang in ("HTML", "CSS", "SCSS", "SASS", "LESS"):
                    source_files.append({
                        "path": rel_path,
                        "type": "source_code",
                        "language": lang,
                        "purpose": f"Frontend markup or stylesheet ({lang}).",
                        "is_application_code": True,
                        "importance": "medium" if "index" in filename.lower() else "low",
                    })
                    continue

                # 11. Scripting & Automation Shell Files
                if lang in ("Shell", "PowerShell", "Batch"):
                    source_files.append({
                        "path": rel_path,
                        "type": "source_code",
                        "language": lang,
                        "purpose": f"Automation or operational script ({lang}).",
                        "is_application_code": False,
                        "importance": "low",
                    })
                    continue

                # 12. Unknown / unclassified files
                if lang == "Unknown":
                    unknowns.append({
                        "path": rel_path,
                        "type": "unclassified_file",
                        "language": "UNKNOWN",
                        "purpose": "Unrecognized file format or proprietary asset.",
                        "is_application_code": False,
                        "importance": "low",
                    })
                    unsupported_files.append({"path": rel_path, "extension": ext})

        return {
            "schema_version": "1.0.0",
            "ingestion_status": ingestion_status,
            "scan_completeness": scan_completeness,
            "warnings": warnings,
            "skipped_files": skipped_files,
            "supported_languages": sorted(list(SOURCE_CODE_LANGUAGES)),
            "unsupported_files": unsupported_files,
            "repository": {
                "source_type": metadata.get("source_type", "UNKNOWN") if metadata else "UNKNOWN",
                "source": metadata.get("source", "UNKNOWN") if metadata else "UNKNOWN",
                "root_path": root_path,
                "total_files": len(file_inventory),
                "total_source_files": len(source_files),
                "total_test_files": len(test_files),
            },
            "languages": sorted(list(detected_languages)),
            "frameworks": sorted(list(detected_frameworks)),
            "file_inventory": file_inventory,
            "source_files": source_files,
            "configuration_files": configuration_files,
            "dependency_files": dependency_files,
            "database_files": database_files,
            "infrastructure_files": infrastructure_files,
            "test_files": test_files,
            "documentation_files": documentation_files,
            "ci_cd_files": ci_cd_files,
            "generated_files": generated_files,
            "potentially_sensitive_files": potentially_sensitive_files,
            "entry_point_candidates": entry_point_candidates,
            "external_services": external_services,
            "unknowns": unknowns,
        }

    def _is_entry_point_candidate(self, filename: str, full_path: str, ext: str) -> bool:
        """Determines if a source file is an entry point candidate."""
        entry_filenames = {
            "main.py", "app.py", "manage.py", "cli.py", "server.py", "wsgi.py", "asgi.py",
            "ingest.py", "pipeline.py", "run.py",
            "index.js", "server.js", "main.js", "app.js",
            "main.go", "main.rs", "Application.java", "Program.cs",
            "Main.kt", "Application.kt", "main.swift", "Main.scala"
        }
        if filename in entry_filenames:
            return True

        # Content check for main entry points
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(MAX_READ_BYTES)
                if ext == ".py" and ('if __name__ == "__main__":' in content or "if __name__ == '__main__':" in content):
                    return True
                if ext in (".js", ".ts") and ("app.listen(" in content or "createServer(" in content):
                    return True
                if ext == ".go" and "func main()" in content and "package main" in content:
                    return True
                if ext in (".kt", ".scala") and ("fun main(" in content or "def main(" in content):
                    return True
                if ext == ".swift" and ("@main" in content or "func main(" in content):
                    return True
        except Exception:
            pass

        return False

    def _extract_frameworks(
        self,
        full_path: str,
        filename: str,
        frameworks: Set[str],
        external_services: List[Dict[str, Any]]
    ):
        """Extracts framework and cloud/database service references from dependency manifests with ecosystem isolation."""
        import re
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(MAX_READ_BYTES)

            lower = content.lower()
            lower_fn = filename.lower()

            # Python Manifests
            if lower_fn in ("requirements.txt", "requirements-dev.txt", "pipfile", "pipfile.lock", "pyproject.toml", "setup.py", "setup.cfg", "poetry.lock"):
                py_frameworks = [
                    (r'\bfastapi\b', "FastAPI"),
                    (r'\bflask\b', "Flask"),
                    (r'\bdjango\b', "Django"),
                    (r'\bcelery\b', "Celery"),
                    (r'\btornado\b', "Tornado"),
                    (r'\bstarlette\b', "Starlette"),
                ]
                for pattern, fw_name in py_frameworks:
                    if re.search(pattern, lower):
                        frameworks.add(fw_name)

            # Node / JS Manifests
            elif lower_fn in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
                js_frameworks = [
                    (r'["\']express["\']|\bexpress\b', "Express"),
                    (r'["\']next["\']|\bnext\b', "Next.js"),
                    (r'["\']react["\']|\breact\b', "React"),
                    (r'["\']vue["\']|\bvue\b', "Vue"),
                    (r'@nestjs/|\bnestjs\b', "NestJS"),
                ]
                for pattern, fw_name in js_frameworks:
                    if re.search(pattern, lower):
                        frameworks.add(fw_name)

            # Go Manifests
            elif lower_fn in ("go.mod", "go.sum"):
                if re.search(r'\bgin-gonic/gin\b|\bgin\b', lower):
                    frameworks.add("Gin")
                if re.search(r'\bgofiber/fiber\b|\bfiber\b', lower):
                    frameworks.add("Fiber")

            # Java Manifests
            elif lower_fn in ("pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties"):
                if "spring-boot" in lower or "org.springframework" in lower:
                    frameworks.add("Spring Boot")

            # External Services & Datastores (with word boundaries / package token matching)
            services_to_check = [
                (r'\b(postgres|postgresql|psycopg|asyncpg)\b', "PostgreSQL Database"),
                (r'\b(mysql|mysqlclient|pymysql|mysql2)\b', "MySQL Database"),
                (r'\b(redis|ioredis)\b', "Redis In-Memory Cache"),
                (r'\b(kafka|confluent-kafka|kafkajs)\b', "Apache Kafka Message Broker"),
                (r'\b(rabbitmq|pika|amqplib)\b', "RabbitMQ Message Broker"),
                (r'\bboto3\b', "AWS SDK (Boto3)"),
                (r'@aws-sdk/', "AWS SDK for JavaScript"),
                (r'@google-cloud/|\bgoogle-cloud-', "Google Cloud Client Libraries"),
                (r'@azure/|\bazure-storage\b|\bazure-identity\b', "Azure Cloud SDK"),
                (r'\bstripe\b', "Stripe Payment Gateway"),
                (r'\bauth0\b', "Auth0 Identity Service"),
            ]
            for pattern, service_name in services_to_check:
                if re.search(pattern, lower):
                    if not any(e["name"] == service_name and e["detected_in"] == filename for e in external_services):
                        external_services.append({
                            "name": service_name,
                            "detected_in": filename,
                            "reference_type": "dependency_manifest_entry"
                        })

        except Exception:
            pass
