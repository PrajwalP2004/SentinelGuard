#!/usr/bin/env python3
"""
Phase 0 CLI Entry Point: Repository Ingestion Agent.

Usage:
    python ingest.py --source-type github --source https://github.com/org/repo.git
    python ingest.py --source-type zip --source /path/to/archive.zip
    python ingest.py --source-type dir --source /path/to/extracted/repo
    python ingest.py --source /path/to/project --output phase0_inventory.json
"""

import sys
import os
import re
import json
import shutil
import stat
import tempfile
import argparse
from typing import Optional, List

# UTF-8 stdout encoding on Windows
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Add root directory to python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.phase0.ingestion import RepositoryIngestionAgent


def safe_write_output(output_path: str, content: str) -> None:
    """Safely and atomically writes output content to destination path."""
    abs_path = os.path.abspath(output_path)
    parent_dir = os.path.dirname(abs_path)
    if parent_dir and not os.path.exists(parent_dir):
        os.makedirs(parent_dir, exist_ok=True)

    temp_path = None
    try:
        # Write to temporary file in the same directory for atomic os.replace()
        fd, temp_path = tempfile.mkstemp(
            prefix=".tmp_output_",
            dir=parent_dir or ".",
            text=True
        )
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        os.replace(temp_path, abs_path)
        temp_path = None
    except Exception as err:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise OSError(f"Failed to write output to '{output_path}': {err}") from err


def cleanup_temp_dir(temp_dir: Optional[str], source: Optional[str] = None) -> None:
    """Safely cleans up a temporary repository directory without masking exceptions or deleting persistent sources."""
    if not temp_dir:
        return

    try:
        resolved_temp = os.path.abspath(temp_dir)
        # Guard: never clean up if path does not exist or is not a directory
        if not os.path.exists(resolved_temp) or not os.path.isdir(resolved_temp):
            return

        # Guard: never clean up user-provided source path
        if source:
            resolved_source = os.path.abspath(source)
            if resolved_temp == resolved_source:
                return

        # Guard: never clean filesystem root or drive root
        if resolved_temp in ("/", "\\") or (len(resolved_temp) <= 3 and resolved_temp[1:3] in (":\\", ":/")):
            return

        def _remove_readonly(func, path, excinfo):
            try:
                os.chmod(path, stat.S_IWRITE)
                func(path)
            except Exception:
                raise

        shutil.rmtree(resolved_temp, onerror=_remove_readonly)
    except Exception as cleanup_err:
        print(
            f"Warning: Failed to clean up temporary directory '{temp_dir}': {cleanup_err}",
            file=sys.stderr,
        )


def is_supported_github_url(source: str) -> bool:
    """Checks whether the source matches supported GitHub repository URL formats."""
    clean = source.strip()
    if clean.startswith(("-", "--")):
        return False
    # Reject embedded credentials
    if "@" in clean and not clean.startswith("git@github.com:"):
        return False

    # Git SSH format: git@github.com:owner/repo(.git)
    if re.match(r"^git@github\.com:[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+?(?:\.git)?/?$", clean):
        return True

    # GitHub HTTPS URL: https://github.com/owner/repo(.git) or https://www.github.com/owner/repo(.git)
    if re.match(r"^https://(?:www\.)?github\.com/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+?(?:\.git)?/?$", clean):
        return True

    return False


def infer_source_type(source: str) -> str:
    """
    Infers the repository source type from the source string.
    Returns 'github', 'zip', or 'dir', or raises ValueError with an actionable message.
    """
    clean = source.strip()
    if not clean:
        raise ValueError("Repository source path or URL must not be empty.")

    # 1. Existing local filesystem paths
    if os.path.exists(clean):
        if os.path.isdir(clean):
            return "dir"
        if os.path.isfile(clean):
            if clean.lower().endswith(".zip"):
                return "zip"
            raise ValueError(
                f"Source '{source}' is an existing file, but not a supported ZIP archive (.zip). "
                "Specify --source-type explicitly if this is an alternate format."
            )

    # 2. Supported remote GitHub repository URLs (HTTPS and Git SSH)
    if is_supported_github_url(clean):
        return "github"

    # 3. Nonexistent local paths that clearly intended to be ZIP or directory
    if clean.lower().endswith(".zip"):
        raise ValueError(f"ZIP file not found at: {source}")

    if clean.startswith(("./", ".\\", "../", "..\\", "/", "\\")) or (len(clean) > 1 and clean[1] == ":"):
        raise ValueError(f"Directory not found: {source}")

    # 4. Ambiguous or unsupported source
    raise ValueError(
        f"Unable to infer source type for '{source}'. "
        "Specify --source-type explicitly ('github', 'zip', or 'dir')."
    )


def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(
        description="Phase 0 Repository Ingestion Agent: Ingests and structurally inventories a software repository."
    )
    parser.add_argument(
        "--source-type",
        choices=["github", "zip", "dir"],
        help="Type of repository source (github URL, zip file, or local directory). If omitted, inferred from --source."
    )
    parser.add_argument(
        "--source",
        required=True,
        help="Repository source (GitHub URL, path to ZIP file, or path to local directory)."
    )
    parser.add_argument(
        "--output",
        help="Optional path to write JSON output. If omitted, prints JSON to stdout."
    )

    args = parser.parse_args(argv)

    source = args.source.strip()
    source_type = args.source_type

    # Validate or infer source_type
    if source_type:
        source_type = source_type.lower().strip()
        supported_types = {"github", "zip", "dir"}
        if source_type not in supported_types:
            print(f"Error: Unsupported source type '{source_type}'. Must be 'github', 'zip', or 'dir'.", file=sys.stderr)
            sys.exit(1)

        # Pre-check local path existence for 'dir' and 'zip' before calling agent
        if source_type == "dir":
            if not os.path.exists(source):
                print(f"Error: Directory not found: {source}", file=sys.stderr)
                sys.exit(1)
            if not os.path.isdir(source):
                print(f"Error: Specified path is not a directory: {source}", file=sys.stderr)
                sys.exit(1)
        elif source_type == "zip":
            if not os.path.exists(source):
                print(f"Error: ZIP file not found at: {source}", file=sys.stderr)
                sys.exit(1)
            if not (os.path.isfile(source) and source.lower().endswith(".zip")):
                print(f"Error: Specified path is not a valid ZIP file: {source}", file=sys.stderr)
                sys.exit(1)
    else:
        try:
            source_type = infer_source_type(source)
        except ValueError as err:
            print(f"Error: {err}", file=sys.stderr)
            sys.exit(1)

    agent = RepositoryIngestionAgent()
    temp_dir_to_clean = None

    try:
        repo_path, is_temp = agent.obtain_repository(source_type=source_type, source=source)
        if is_temp:
            temp_dir_to_clean = repo_path

        metadata = {
            "source_type": source_type,
            "source": source
        }

        inventory_result = agent.inventory(root_path=repo_path, metadata=metadata)
        json_output = json.dumps(inventory_result, indent=2)

        if args.output:
            safe_write_output(args.output, json_output)
            print(f"Phase 0 Inventory written to {args.output}", file=sys.stderr)
        else:
            print(json_output)

    except Exception as e:
        print(f"Ingestion error: {str(e)}", file=sys.stderr)
        sys.exit(1)
    finally:
        cleanup_temp_dir(temp_dir_to_clean, source=source)


if __name__ == "__main__":
    main()
