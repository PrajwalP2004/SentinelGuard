"""
Phase 6: Code Smell and Maintainability Analysis Agent Module.

Analyzes implementation code for code smells, cyclomatic complexity, maintainability
hazards, and architectural coupling problems across 18 quality dimensions:
 1. Long Method (lines of code > 80)
 2. Deep Nesting (block indentation depth >= 4)
 3. High Cyclomatic Complexity (McCabe complexity > 15)
 4. God Class / Large Class (methods > 12 or lines > 250)
 5. Poor Exception Handling / Silent Exceptions (swallowing errors with pass/...)
 6. Repeated Conditionals (if/elif ladder with >= 4 branches)
 7. Hard-coded Configuration (large embedded dictionary/table constants >= 6 items)
 8. Duplicate Code (structurally verified identical routines across entry points)
 9. Primitive Obsession (untyped dictionary exchanges and raw string subscripting across phase boundaries)
10. Long Parameter List (functions declaring > 6 parameters, including pos-only, kw-only, and varargs)
11. Multiple Return Points (heuristic: functions with > 4 return statements in direct scope)
12. Dead / Unreachable Code (sequential block statements following unconditional return/raise/break/continue)
13. Dangerous Default Value (mutable default arguments such as [], {}, set(), or mutable factory calls)
14. Broad Exception Clause (catching bare except: or except BaseException: without re-raising)
15. Speculative Generality (concrete non-abstract functions/classes with only empty pass and no docstring)
16. Global State Mutation (functions declaring global variables and actively mutating them)
17. Excessive Local Imports (more than 2 inline import statements inside function body)
18. Magic Numbers in Logic (unexplained numeric literals > 10 in comparison expressions)
"""

import ast
import os
from typing import Dict, List, Any, Optional, Set, Tuple


class CodeSmellAnalysisAgent:
    """Agent that performs static analysis and code smell identification."""

    MAX_FILE_READ_SIZE = 5 * 1024 * 1024  # 5 MB per-file budget

    def __init__(
        self,
        root_path: str,
        phase1_reconstruction: Optional[Dict[str, Any]] = None,
    ):
        self.root_path = os.path.abspath(root_path)
        self.p1 = phase1_reconstruction or {}

    def analyze(self) -> Dict[str, Any]:
        """Runs the complete code smell and maintainability audit."""
        smells: List[Dict[str, Any]] = []
        diagnostics: List[Dict[str, Any]] = []

        python_files = self._collect_python_files()

        for rel_path, full_path in python_files:
            code_content = self._read_file_safe(full_path, rel_path, diagnostics)
            if code_content is None:
                continue

            try:
                tree = ast.parse(code_content, filename=rel_path)
            except SyntaxError as e:
                diagnostics.append({
                    "file": rel_path,
                    "status": "SYNTAX_ERROR",
                    "message": f"Invalid Python syntax: {e}"
                })
                continue

            smells.extend(self._inspect_ast(rel_path, tree, code_content))
            smells.extend(self._inspect_patterns(rel_path, tree, code_content))

        # Global architectural smells (based on bounded reads and empirical code evidence)
        smells.extend(self._inspect_architectural_smells(python_files, diagnostics))

        # Deduplicate deterministically by smell_id, file, and function_or_class
        seen: Set[Tuple[str, str, str]] = set()
        deduped: List[Dict[str, Any]] = []
        for s in smells:
            key = (s["smell_id"], s["file"], s["function_or_class"])
            if key not in seen:
                seen.add(key)
                deduped.append(s)

        # Deterministic sorting: primary by severity, secondary by file, tertiary by smell_id
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        deduped.sort(key=lambda x: (
            sev_order.get(x.get("severity", "INFO"), 5),
            x.get("file", ""),
            x.get("smell_id", "")
        ))

        return {
            "code_smells": deduped,
            "summary": {
                "total_smells": len(deduped),
                "problematic": sum(1 for s in deduped if s.get("classification") == "PROBLEMATIC"),
                "potentially_excessive": sum(1 for s in deduped if s.get("classification") == "POTENTIALLY_EXCESSIVE"),
                "justified": sum(1 for s in deduped if s.get("classification") == "JUSTIFIED"),
                "unknown": sum(1 for s in deduped if s.get("classification") == "UNKNOWN"),
            },
            "scan_diagnostics": diagnostics
        }

    def _read_file_safe(
        self,
        full_path: str,
        rel_path: str,
        diagnostics: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[str]:
        """Safely verifies canonical containment, bounds read to MAX_FILE_READ_SIZE bytes, and decodes."""
        canonical_root = os.path.realpath(self.root_path)
        try:
            real_file = os.path.realpath(full_path)
            if not (real_file == canonical_root or real_file.startswith(canonical_root + os.sep)):
                if diagnostics is not None:
                    diagnostics.append({
                        "file": rel_path,
                        "status": "REJECTED_EXTERNAL_PATH",
                        "message": "File path resolves outside canonical project root."
                    })
                return None

            with open(full_path, "rb") as f:
                raw_bytes = f.read(self.MAX_FILE_READ_SIZE + 1)

            if len(raw_bytes) > self.MAX_FILE_READ_SIZE:
                if diagnostics is not None:
                    diagnostics.append({
                        "file": rel_path,
                        "status": "SKIPPED_OVERSIZED",
                        "message": f"File size exceeds MAX_FILE_READ_SIZE ({self.MAX_FILE_READ_SIZE} bytes)."
                    })
                return None

            return raw_bytes.decode("utf-8", errors="replace")
        except (OSError, PermissionError) as e:
            if diagnostics is not None:
                diagnostics.append({
                    "file": rel_path,
                    "status": "UNREADABLE",
                    "message": f"Cannot read file: {e}"
                })
            return None
        except Exception as e:
            if diagnostics is not None:
                diagnostics.append({
                    "file": rel_path,
                    "status": "SCAN_ERROR",
                    "message": str(e)
                })
            return None

    def _collect_python_files(self) -> List[Tuple[str, str]]:
        """Collects Python source files within the canonical project root, rejecting external symlinks."""
        files: List[Tuple[str, str]] = []
        canonical_root = os.path.realpath(self.root_path)
        excluded_dirs = {
            ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
            ".tox", ".pytest_cache", ".idea", ".vscode"
        }

        for root, dirs, filenames in os.walk(self.root_path, followlinks=False):
            # Prune excluded or symlinked directory paths
            dirs[:] = [
                d for d in dirs
                if d not in excluded_dirs and not os.path.islink(os.path.join(root, d))
            ]

            for fn in filenames:
                if fn.endswith(".py"):
                    full = os.path.join(root, fn)
                    try:
                        real_file = os.path.realpath(full)
                        # Verify containment strictly within canonical root
                        if not (real_file == canonical_root or real_file.startswith(canonical_root + os.sep)):
                            continue
                    except (OSError, ValueError):
                        continue

                    rel = os.path.relpath(full, self.root_path).replace("\\", "/")
                    files.append((rel, full))

        files.sort(key=lambda x: x[0])
        return files

    def _inspect_ast(self, rel_path: str, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Performs comprehensive AST inspection across structural and cognitive code quality dimensions."""
        findings: List[Dict[str, Any]] = []
        clean_file = rel_path.replace("/", "_").replace("\\", "_").replace(".", "_")

        # Track if-elif ladder non-root nodes so we only flag the root of each ladder
        ladder_non_roots: Set[int] = set()

        for node in ast.walk(tree):
            # -------------------------------------------------------------
            # Dimension 1, 2, 3, 10, 11, 13, 15, 16, 17, 18: Functions
            # -------------------------------------------------------------
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                start_line, end_line, line_count = self._get_node_line_span(node)

                # 1. Long Method
                if line_count > 80:
                    is_problematic = line_count > 150
                    findings.append({
                        "smell_id": f"SMELL-LONG-METHOD-{clean_file}-{func_name.upper()}",
                        "category": "Long Method",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' spans {line_count} lines of code (lines {start_line}-{end_line}).",
                        "explanation": "Methods exceeding 80 lines of code accumulate multiple responsibilities, making them harder to comprehend, test, and maintain.",
                        "severity": "HIGH" if is_problematic else "MEDIUM",
                        "classification": "PROBLEMATIC" if is_problematic else "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "High cognitive load during modifications; changes are prone to unexpected regressions.",
                        "refactoring_strategy": "Extract Method refactoring: decompose procedural blocks into focused helper routines.",
                        "expected_benefit": "Improves unit testability, readability, and isolates discrete sub-tasks."
                    })

                # 2. Deep Nesting (excludes nested function/class bodies)
                max_depth = self._compute_nesting_depth(node)
                if max_depth >= 4:
                    is_problematic = max_depth >= 5
                    findings.append({
                        "smell_id": f"SMELL-DEEP-NEST-{clean_file}-{func_name.upper()}",
                        "category": "Deep Nesting",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' exhibits maximum block nesting depth of {max_depth} levels.",
                        "explanation": "Deeply nested control structures hinder cognitive comprehension and create exponential branch combinations.",
                        "severity": "HIGH" if is_problematic else "MEDIUM",
                        "classification": "PROBLEMATIC" if is_problematic else "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Difficult to branch-test completely; introduces edge-case execution hazards.",
                        "refactoring_strategy": "Invert conditionals using guard clauses and extract nested loop bodies into standalone functions.",
                        "expected_benefit": "Flattens execution paths to a linear, readable flow."
                    })

                # 3. High Cyclomatic Complexity (excludes nested function/class bodies)
                complexity = self._compute_cyclomatic_complexity(node)
                if complexity > 15:
                    findings.append({
                        "smell_id": f"SMELL-HIGH-COMPLEXITY-{clean_file}-{func_name.upper()}",
                        "category": "High Cyclomatic Complexity",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' has a calculated cyclomatic complexity score of {complexity} (threshold: 15).",
                        "explanation": "High cyclomatic complexity indicates a large number of linearly independent execution paths through the code.",
                        "severity": "HIGH" if complexity > 25 else "MEDIUM",
                        "classification": "PROBLEMATIC",
                        "maintenance_impact": "Requires a disproportionately large test matrix to achieve full branch coverage.",
                        "refactoring_strategy": "Replace complex conditional logic with polymorphism, table-driven lookup, or dedicated strategy classes.",
                        "expected_benefit": "Reduces test setup overhead and isolates individual branch concerns."
                    })

                # 10. Long Parameter List (> 6 params, counting positional, kw-only, and varargs; excluding self/cls)
                explicit_params = [
                    a.arg for a in (getattr(node.args, "posonlyargs", []) + node.args.args + getattr(node.args, "kwonlyargs", []))
                    if a.arg not in ("self", "cls")
                ]
                if node.args.vararg:
                    explicit_params.append(f"*{node.args.vararg.arg}")
                if node.args.kwarg:
                    explicit_params.append(f"**{node.args.kwarg.arg}")

                if len(explicit_params) > 6:
                    findings.append({
                        "smell_id": f"SMELL-LONG-PARAMS-{clean_file}-{func_name.upper()}",
                        "category": "Long Parameter List",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' declares {len(explicit_params)} parameters ({', '.join(explicit_params[:5])}...) at line {start_line}.",
                        "explanation": "Long parameter lists couple functions tightly to caller context and suggest missing abstractions.",
                        "severity": "MEDIUM",
                        "classification": "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Changes to caller data models require updating extensive positional signatures.",
                        "refactoring_strategy": "Introduce Parameter Object: group related arguments into a structured dataclass or TypedDict.",
                        "expected_benefit": "Simplifies call sites, enables default values, and prevents positional argument transpositions."
                    })

                # 11. Multiple Return Points (> 4 returns, excluding nested functions)
                returns = self._collect_scoped_nodes(node, ast.Return)
                if len(returns) > 4:
                    return_lines = ", ".join(str(r.lineno) for r in returns[:6])
                    findings.append({
                        "smell_id": f"SMELL-MANY-RETURNS-{clean_file}-{func_name.upper()}",
                        "category": "Multiple Return Points",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' contains {len(returns)} return statements (lines {return_lines}).",
                        "explanation": "Functions with excessive return statements obscure exit conditions, complicating control flow analysis and resource cleanup.",
                        "severity": "LOW",
                        "classification": "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Hard to trace guaranteed post-conditions or ensure symmetric resource disposal.",
                        "refactoring_strategy": "Consolidate return statements or decompose function into smaller single-exit routines.",
                        "expected_benefit": "Clarifies lifecycle and execution invariants."
                    })

                # 13. Dangerous Default Value (mutable default arguments such as [], {}, set(), or factory calls)
                all_defaults = node.args.defaults + [d for d in getattr(node.args, "kw_defaults", []) if d is not None]
                for default in all_defaults:
                    is_mutable = False
                    d_type = "collection"
                    if isinstance(default, ast.List):
                        is_mutable = True
                        d_type = "list"
                    elif isinstance(default, ast.Dict):
                        is_mutable = True
                        d_type = "dict"
                    elif isinstance(default, ast.Set):
                        is_mutable = True
                        d_type = "set"
                    elif isinstance(default, ast.Call) and isinstance(default.func, ast.Name):
                        if default.func.id in ("list", "dict", "set"):
                            is_mutable = True
                            d_type = default.func.id

                    if is_mutable:
                        findings.append({
                            "smell_id": f"SMELL-MUTABLE-DEFAULT-{clean_file}-{func_name.upper()}-L{default.lineno}",
                            "category": "Dangerous Default Value",
                            "file": rel_path,
                            "function_or_class": func_name,
                            "evidence": f"Function '{func_name}' defines mutable default {d_type} literal at line {default.lineno}.",
                            "explanation": "Default parameter values are evaluated once at function definition time, causing state mutations to persist across calls.",
                            "severity": "HIGH",
                            "classification": "PROBLEMATIC",
                            "maintenance_impact": "Subtle, non-deterministic bugs when callers mutate the default collection.",
                            "refactoring_strategy": "Use 'None' as default value and initialize the collection inside the function body ('val = val if val is not None else []').",
                            "expected_benefit": "Guarantees fresh, isolated state for every function invocation."
                        })

                # 15. Speculative Generality (empty stub function with only pass and no docstring/abstract decorator)
                if (
                    len(node.body) == 1
                    and isinstance(node.body[0], ast.Pass)
                    and not (node.name.startswith("__") and node.name.endswith("__"))
                    and not self._is_abstract_or_protocol_member(node)
                ):
                    findings.append({
                        "smell_id": f"SMELL-EMPTY-STUB-{clean_file}-{func_name.upper()}",
                        "category": "Speculative Generality",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' contains only an empty 'pass' statement without implementation at line {start_line}.",
                        "explanation": "Empty function stubs without abstract markers clutter APIs and indicate speculative or abandoned designs.",
                        "severity": "LOW",
                        "classification": "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Misleads developers into assuming functionality is implemented, failing silently at runtime.",
                        "refactoring_strategy": "Implement the routine, mark with @abstractmethod, or raise NotImplementedError explicitly.",
                        "expected_benefit": "Ensures callers are immediately alerted to unimplemented capabilities."
                    })

                # 16. Global State Mutation (use of 'global' keyword with verified mutation vs declaration)
                globals_used = self._collect_scoped_nodes(node, ast.Global)
                if globals_used:
                    g_names = {name for g in globals_used for name in g.names}
                    has_mutation = self._has_global_mutation(node, g_names)
                    findings.append({
                        "smell_id": f"SMELL-GLOBAL-MUTATION-{clean_file}-{func_name.upper()}",
                        "category": "Global State Mutation" if has_mutation else "Global Scope Coupling",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": (
                            f"Function '{func_name}' actively mutates module-level global variable(s) {', '.join(sorted(g_names))} at line {globals_used[0].lineno}."
                            if has_mutation else
                            f"Function '{func_name}' declares global variable(s) {', '.join(sorted(g_names))} at line {globals_used[0].lineno}."
                        ),
                        "explanation": "Direct mutation of module-level globals creates invisible coupling between disjoint subsystems.",
                        "severity": "MEDIUM" if has_mutation else "LOW",
                        "classification": "PROBLEMATIC" if has_mutation else "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Prevents concurrent execution and causes test interference through dirty global state.",
                        "refactoring_strategy": "Encapsulate mutable state in an instantiated service class or pass state explicitly via parameters.",
                        "expected_benefit": "Thread-safe, reentrant, and easily mockable components."
                    })

                # 17. Excessive Local Imports (more than 2 inline imports)
                local_imports = self._collect_scoped_nodes(node, (ast.Import, ast.ImportFrom))
                if len(local_imports) > 2:
                    imp_lines = ", ".join(str(imp.lineno) for imp in local_imports[:4])
                    findings.append({
                        "smell_id": f"SMELL-LOCAL-IMPORTS-{clean_file}-{func_name.upper()}",
                        "category": "Excessive Local Imports",
                        "file": rel_path,
                        "function_or_class": func_name,
                        "evidence": f"Function '{func_name}' contains {len(local_imports)} inline import statements (lines {imp_lines}).",
                        "explanation": "Inline imports are typically workarounds for circular dependencies or architectural coupling.",
                        "severity": "LOW",
                        "classification": "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Obscures module dependencies and incurs slight bytecode lookup overhead on repeated invocations.",
                        "refactoring_strategy": "Move imports to top of file and decouple circular module dependencies via interfaces or dependency injection.",
                        "expected_benefit": "Provides immediate visibility of module prerequisites and avoids circular dependency traps."
                    })

                # 18. Magic Numbers in Logic (raw comparison numbers > 10 not in common set, excluding booleans)
                common_safe_numbers = {
                    0, 1, 2, -1, 10, 100, 1000, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
                    60, 3600, 86400, 200, 201, 204, 301, 302, 400, 401, 403, 404, 500
                }
                seen_line_numbers: Set[Tuple[int, Any]] = set()
                comparisons = self._collect_scoped_nodes(node, ast.Compare)
                for cmp_node in comparisons:
                    for comp_val in [cmp_node.left] + cmp_node.comparators:
                        if (
                            isinstance(comp_val, ast.Constant)
                            and isinstance(comp_val.value, (int, float))
                            and not isinstance(comp_val.value, bool)
                        ):
                            num = comp_val.value
                            if num > 10 and num not in common_safe_numbers:
                                line_num_key = (getattr(comp_val, "lineno", 0), num)
                                if line_num_key not in seen_line_numbers:
                                    seen_line_numbers.add(line_num_key)
                                    findings.append({
                                        "smell_id": f"SMELL-MAGIC-NUMBER-{clean_file}-L{comp_val.lineno}",
                                        "category": "Magic Numbers",
                                        "file": rel_path,
                                        "function_or_class": func_name,
                                        "evidence": f"Comparison expression uses unexplained numeric literal {num} at line {comp_val.lineno}.",
                                        "explanation": "Hardcoded numeric constants lack semantic meaning and complicate threshold adjustments across files.",
                                        "severity": "LOW",
                                        "classification": "POTENTIALLY_EXCESSIVE",
                                        "maintenance_impact": "Changing an operational threshold requires hunting through procedural logic.",
                                        "refactoring_strategy": "Extract numeric literal to a named constant or configuration setting.",
                                        "expected_benefit": "Self-documenting code with a single point of configuration."
                                    })

            # -------------------------------------------------------------
            # Dimension 4: Large Classes / God Classes
            # -------------------------------------------------------------
            elif isinstance(node, ast.ClassDef):
                class_name = node.name
                methods = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                start_line, end_line, class_lines = self._get_node_line_span(node)

                if len(methods) > 12 or class_lines > 250:
                    is_problematic = len(methods) > 18 or class_lines > 350
                    findings.append({
                        "smell_id": f"SMELL-GOD-CLASS-{clean_file}-{class_name.upper()}",
                        "category": "God Class / Large Class",
                        "file": rel_path,
                        "function_or_class": class_name,
                        "evidence": f"Class '{class_name}' contains {len(methods)} methods and spans {class_lines} lines (lines {start_line}-{end_line}).",
                        "explanation": "The class coordinates multiple disjoint domain responsibilities, violating the Single Responsibility Principle.",
                        "severity": "HIGH" if is_problematic else "MEDIUM",
                        "classification": "PROBLEMATIC" if is_problematic else "POTENTIALLY_EXCESSIVE",
                        "maintenance_impact": "Changes to one subsystem require touching this class, creating merge conflicts and tight coupling.",
                        "refactoring_strategy": "Extract Class: split acquisition, validation, and scanning responsibilities into dedicated collaborating services.",
                        "expected_benefit": "Promotes cohesion, unit test isolation, and reusability."
                    })

            # -------------------------------------------------------------
            # Dimension 5 & 14: Exception Handling (Silent & Broad Handlers)
            # -------------------------------------------------------------
            elif isinstance(node, ast.ExceptHandler):
                exc_repr = self._format_exception_type(node.type)

                # 5. Silent Exception Handling (pass, ..., or docstring only)
                is_silent = False
                if len(node.body) == 0:
                    is_silent = True
                elif len(node.body) == 1:
                    first = node.body[0]
                    if isinstance(first, ast.Pass):
                        is_silent = True
                    elif isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                        if first.value.value is ... or isinstance(first.value.value, str):
                            is_silent = True

                if is_silent:
                    is_broad = exc_repr in ("bare except", "Exception", "BaseException")
                    findings.append({
                        "smell_id": f"SMELL-SILENT-EXCEPTION-{clean_file}-L{node.lineno}",
                        "category": "Poor Exception Handling",
                        "file": rel_path,
                        "function_or_class": f"Line {node.lineno}",
                        "evidence": f"Except handler catches '{exc_repr}' with a silent suppression statement (line {node.lineno}).",
                        "explanation": "Catching exceptions and ignoring them silently masks underlying system failures, data corruption, and security anomalies.",
                        "severity": "HIGH" if is_broad else "MEDIUM",
                        "classification": "PROBLEMATIC",
                        "maintenance_impact": "Bugs, encoding problems, and permission errors fail silently without actionable diagnostics.",
                        "refactoring_strategy": "Catch specific expected exceptions and record diagnostic log messages or raise handled domain errors.",
                        "expected_benefit": "Surfaces unexpected failures immediately while gracefully handling expected edge conditions."
                    })

                # 14. Broad Exception Clause (bare except or BaseException without re-raising)
                elif exc_repr in ("bare except", "BaseException"):
                    has_raise = any(isinstance(s, ast.Raise) for s in ast.walk(node))
                    if not has_raise:
                        findings.append({
                            "smell_id": f"SMELL-BROAD-EXCEPT-{clean_file}-L{node.lineno}",
                            "category": "Broad Exception Clause",
                            "file": rel_path,
                            "function_or_class": f"Line {node.lineno}",
                            "evidence": f"Except handler catches broad '{exc_repr}' at line {node.lineno} without re-raising.",
                            "explanation": "Catching bare except or BaseException intercepts critical system exit signals like KeyboardInterrupt and SystemExit.",
                            "severity": "MEDIUM",
                            "classification": "POTENTIALLY_EXCESSIVE",
                            "maintenance_impact": "Prevents normal process termination and debugging in interactive environments.",
                            "refactoring_strategy": "Narrow exception scope to Exception or specific standard error subclasses.",
                            "expected_benefit": "Maintains process lifecycle integrity."
                        })

            # -------------------------------------------------------------
            # Dimension 6: Repeated Conditionals (If-Elif Ladders)
            # -------------------------------------------------------------
            elif isinstance(node, ast.If):
                if id(node) not in ladder_non_roots:
                    ladder_chain = self._collect_if_ladder(node)
                    if len(ladder_chain) >= 4:
                        for child_if in ladder_chain[1:]:
                            ladder_non_roots.add(id(child_if))

                        findings.append({
                            "smell_id": f"SMELL-IF-ELIF-LADDER-{clean_file}-L{node.lineno}",
                            "category": "Repeated Conditionals",
                            "file": rel_path,
                            "function_or_class": f"Line {node.lineno}",
                            "evidence": f"Chained if/elif construct with {len(ladder_chain)} sequential branching conditions detected at line {node.lineno}.",
                            "explanation": "Large conditional ladders indicate procedural dispatch that grows linearly with each new type or condition.",
                            "severity": "MEDIUM",
                            "classification": "POTENTIALLY_EXCESSIVE",
                            "maintenance_impact": "Adding a new branch requires modifying centralized procedural code, violating Open/Closed Principle.",
                            "refactoring_strategy": "Replace Type Code with Strategy or Command Pattern (dictionary registry or polymorphic handlers).",
                            "expected_benefit": "Enables adding new cases independently without modifying existing conditional blocks."
                        })

        # -------------------------------------------------------------
        # Dimension 12: Dead / Unreachable Code (syntactic block level)
        # -------------------------------------------------------------
        findings.extend(self._find_dead_code(rel_path, tree, clean_file))

        return findings

    def _inspect_patterns(self, rel_path: str, tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Performs pattern inspection targeting in-code configuration mappings using AST."""
        findings: List[Dict[str, Any]] = []
        clean_file = rel_path.replace("/", "_").replace("\\", "_").replace(".", "_")

        # 7. Hardcoded Configuration & Magic Tables (AST Module-Level Assignments)
        for stmt in getattr(tree, "body", []):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        target_name = target.id
                        has_config_name = any(k in target_name for k in ("CONFIG", "MAP", "TABLE", "WEIGHTS", "RULES", "SETTING"))
                        entry_count = 0

                        if isinstance(stmt.value, ast.Dict):
                            entry_count = len(stmt.value.keys)
                        elif isinstance(stmt.value, (ast.List, ast.Set)):
                            entry_count = len(stmt.value.elts)

                        if has_config_name and entry_count >= 6:
                            findings.append({
                                "smell_id": f"SMELL-HARDCODED-CONFIG-{clean_file}-{target_name.upper()}",
                                "category": "Hard-coded Configuration",
                                "file": rel_path,
                                "function_or_class": target_name,
                                "evidence": f"Module-level constant '{target_name}' embeds a hardcoded mapping table with {entry_count} entries (line {stmt.lineno}).",
                                "explanation": "Static rule tables and scoring weights embedded in source files require code edits and redeployments to alter.",
                                "severity": "LOW",
                                "classification": "JUSTIFIED",
                                "maintenance_impact": "Configuration extensions require code modifications rather than operational configuration updates.",
                                "refactoring_strategy": "Externalize configuration mappings into structured JSON, YAML, or dataclass definitions.",
                                "expected_benefit": "Allows modifying language rules, weights, and file filters without editing core logic."
                            })

        return findings

    def _inspect_architectural_smells(
        self,
        python_files: List[Tuple[str, str]],
        diagnostics: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Inspects cross-cutting architectural smells using bounded reading and structural comparisons."""
        findings: List[Dict[str, Any]] = []

        # 8. Duplicated CLI Logic across Entry Points
        # Verify if pipeline.py and ingest.py both exist and share structurally identical functions
        pipeline_file = next((f for f in python_files if f[0] == "pipeline.py"), None)
        ingest_file = next((f for f in python_files if f[0] == "ingest.py"), None)

        if pipeline_file and ingest_file:
            p_code = self._read_file_safe(pipeline_file[1], pipeline_file[0], diagnostics)
            i_code = self._read_file_safe(ingest_file[1], ingest_file[0], diagnostics)

            if p_code and i_code:
                try:
                    tree_p = ast.parse(p_code, filename=pipeline_file[0])
                    tree_i = ast.parse(i_code, filename=ingest_file[0])

                    funcs_p = {
                        n.name: n for n in tree_p.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    }
                    funcs_i = {
                        n.name: n for n in tree_i.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                    }

                    shared_names = set(funcs_p.keys()) & set(funcs_i.keys())
                    matched_functions = []

                    for fn_name in shared_names:
                        fp = funcs_p[fn_name]
                        fi = funcs_i[fn_name]
                        # Compare structural AST representation (excluding line number attributes)
                        if ast.dump(fp, include_attributes=False) == ast.dump(fi, include_attributes=False):
                            matched_functions.append((fn_name, fp.lineno, fi.lineno))

                    # Also inspect stream reconfiguration blocks
                    has_p_reconfig = "sys.stdout.reconfigure" in p_code
                    has_i_reconfig = "sys.stdout.reconfigure" in i_code

                    if matched_functions or (has_p_reconfig and has_i_reconfig):
                        evidence_parts = []
                        for m_name, l_p, l_i in matched_functions:
                            evidence_parts.append(f"identical '{m_name}' function (pipeline.py:L{l_p}, ingest.py:L{l_i})")
                        if has_p_reconfig and has_i_reconfig:
                            evidence_parts.append("identical stdout UTF-8 reconfiguration stream wrapper")

                        findings.append({
                            "smell_id": "SMELL-DUPLICATE-CLI-LOGIC",
                            "category": "Duplicate Code",
                            "file": "pipeline.py / ingest.py",
                            "function_or_class": "safe_write_output / stream wrapper",
                            "evidence": f"Duplicate logic verified: {'; '.join(evidence_parts)}.",
                            "explanation": "Duplicate utility implementations lead to maintenance drift if bug fixes are made in one file but omitted in the other.",
                            "severity": "MEDIUM",
                            "classification": "PROBLEMATIC",
                            "maintenance_impact": "Modifying file-writing validation requires parallel edits across multiple entry points.",
                            "refactoring_strategy": "Extract shared CLI and file utilities into a shared module (e.g., src/common/cli.py).",
                            "expected_benefit": "Eliminates redundancy and guarantees uniform output validation across all entry points."
                        })
                except SyntaxError as e:
                    diagnostics.append({
                        "file": "pipeline.py / ingest.py",
                        "status": "SYNTAX_ERROR",
                        "message": f"Syntax error during duplicate code analysis: {e}"
                    })

        # 9. Primitive Obsession / Loose Dictionary Coupling across Phase Boundaries
        p1_file = next((f for f in python_files if "reconstruction.py" in f[0]), None)
        p2_file = next((f for f in python_files if "requirements.py" in f[0]), None)

        if p1_file and p2_file:
            p1_code = self._read_file_safe(p1_file[1], p1_file[0], diagnostics)
            p2_code = self._read_file_safe(p2_file[1], p2_file[0], diagnostics)

            if p1_code and p2_code:
                try:
                    tree_1 = ast.parse(p1_code, filename=p1_file[0])
                    tree_2 = ast.parse(p2_code, filename=p2_file[0])

                    # Check if p1 defines methods returning Dict[str, Any]
                    p1_returns_dict = any(
                        isinstance(n, ast.FunctionDef) and "Dict" in ast.unparse(n.returns)
                        for n in ast.walk(tree_1) if getattr(n, "returns", None)
                    )
                    # Check if p2 subscripts or accesses raw string keys from dictionary parameters
                    p2_raw_keys = []
                    for node in ast.walk(tree_2):
                        if (
                            isinstance(node, ast.Subscript)
                            and isinstance(getattr(node, "slice", None), ast.Constant)
                            and isinstance(node.slice.value, str)
                        ):
                            p2_raw_keys.append(node.slice.value)
                        elif (
                            isinstance(node, ast.Call)
                            and isinstance(getattr(node, "func", None), ast.Attribute)
                            and node.func.attr == "get"
                            and node.args
                            and isinstance(node.args[0], ast.Constant)
                            and isinstance(node.args[0].value, str)
                        ):
                            p2_raw_keys.append(node.args[0].value)

                    if p1_returns_dict and len(p2_raw_keys) >= 2:
                        sample_keys = ", ".join(f"'{k}'" for k in sorted(set(p2_raw_keys))[:4])
                        findings.append({
                            "smell_id": "SMELL-PRIMITIVE-OBSESSION-CONTRACTS",
                            "category": "Inappropriate Abstractions / Primitive Obsession",
                            "file": f"{p1_file[0]} / {p2_file[0]}",
                            "function_or_class": "Cross-Phase Data Exchange",
                            "evidence": f"Phases exchange raw Dict[str, Any] structures and index raw string keys ({sample_keys}) without typed schema models.",
                            "explanation": "Passing untyped dictionaries across phase boundaries lacks schema validation, autocomplete, and compile-time type safety.",
                            "severity": "MEDIUM",
                            "classification": "POTENTIALLY_EXCESSIVE",
                            "maintenance_impact": "Typos in dictionary key strings fail silently at runtime or produce empty result sets without warning.",
                            "refactoring_strategy": "Introduce typed dataclasses or Pydantic models for inter-phase contracts (Phase0Inventory, Phase1Model).",
                            "expected_benefit": "Enforces strict compile-time type verification, IDE autocompletion, and self-documenting data models."
                        })
                except SyntaxError as e:
                    diagnostics.append({
                        "file": f"{p1_file[0]} / {p2_file[0]}",
                        "status": "SYNTAX_ERROR",
                        "message": f"Syntax error during primitive obsession analysis: {e}"
                    })

        return findings

    # -------------------------------------------------------------------------
    # Helper Utilities (AST Metrics, Scoping, and Complexity Calculations)
    # -------------------------------------------------------------------------

    def _get_node_line_span(self, node: ast.AST) -> Tuple[int, int, int]:
        """Calculates accurate 1-indexed (start_line, end_line, span) for an AST node safely."""
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", None)
        if end is None:
            max_line = start
            for child in ast.walk(node):
                cline = getattr(child, "lineno", None)
                if cline and cline > max_line:
                    max_line = cline
            end = max_line
        span = max(1, end - start + 1)
        return start, end, span

    def _compute_cyclomatic_complexity(self, func_node: ast.AST) -> int:
        """
        Calculates McCabe Cyclomatic Complexity strictly within the function scope.
        Excludes nested function and class bodies.
        Base complexity = 1.
        Decision points (+1): if, for, async for, while, except, bool_op values - 1, if-exp, match cases.
        """
        complexity = 1
        stack = list(ast.iter_child_nodes(func_node))

        while stack:
            curr = stack.pop()
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Exclude nested functions and classes
                continue

            if isinstance(curr, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)):
                complexity += 1
            elif isinstance(curr, ast.BoolOp):
                complexity += max(0, len(curr.values) - 1)
            elif hasattr(ast, "Match") and isinstance(curr, ast.Match):
                for case in getattr(curr, "cases", []):
                    complexity += 1
                    if getattr(case, "guard", None):
                        complexity += 1

            stack.extend(ast.iter_child_nodes(curr))

        return complexity

    def _compute_nesting_depth(self, node: ast.AST, current_depth: int = 0) -> int:
        """
        Calculates maximum control structure nesting depth.
        Excludes nested function and class bodies from enclosing measurements.
        """
        max_d = current_depth

        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Do not traverse into nested functions or classes
                continue

            is_nesting_block = isinstance(child, (
                ast.If, ast.For, ast.AsyncFor, ast.While,
                ast.With, ast.AsyncWith, ast.Try, ast.ExceptHandler
            ))
            if hasattr(ast, "Match") and isinstance(child, getattr(ast, "Match", ())):
                is_nesting_block = True

            next_depth = current_depth + 1 if is_nesting_block else current_depth
            child_max = self._compute_nesting_depth(child, next_depth)
            if child_max > max_d:
                max_d = child_max

        return max_d

    def _collect_scoped_nodes(self, func_node: ast.AST, target_types: Any) -> List[ast.AST]:
        """Collects AST nodes of target_types belonging directly to func_node, excluding nested functions/classes."""
        collected = []
        stack = list(ast.iter_child_nodes(func_node))

        while stack:
            curr = stack.pop()
            if isinstance(curr, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(curr, target_types):
                collected.append(curr)
            stack.extend(ast.iter_child_nodes(curr))

        return collected

    def _collect_if_ladder(self, if_node: ast.If) -> List[ast.If]:
        """Walks an if/elif chain starting at if_node and returns the ordered list of If nodes in the ladder."""
        chain = [if_node]
        curr = if_node
        while len(curr.orelse) == 1 and isinstance(curr.orelse[0], ast.If):
            curr = curr.orelse[0]
            chain.append(curr)
        return chain

    def _find_dead_code(self, rel_path: str, tree: ast.AST, clean_file: str) -> List[Dict[str, Any]]:
        """
        Identifies unreachable statements immediately following an unconditional control transfer statement
        (return, raise, break, continue) sequentially within the exact same statement list block.
        Does not perform global or cross-procedural flow analysis.
        """
        findings = []

        for node in ast.walk(tree):
            for field in ("body", "orelse", "finalbody"):
                stmts = getattr(node, field, None)
                if isinstance(stmts, list) and len(stmts) > 1:
                    for i in range(len(stmts) - 1):
                        curr = stmts[i]
                        if isinstance(curr, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                            unreachable = stmts[i + 1]
                            stmt_type = type(unreachable).__name__
                            term_type = type(curr).__name__
                            u_line = getattr(unreachable, "lineno", 0)
                            c_line = getattr(curr, "lineno", 0)

                            findings.append({
                                "smell_id": f"SMELL-DEAD-CODE-{clean_file}-L{u_line}",
                                "category": "Dead Code",
                                "file": rel_path,
                                "function_or_class": f"Line {u_line}",
                                "evidence": f"Unreachable statement '{stmt_type}' at line {u_line} immediately follows unconditional '{term_type}' at line {c_line}.",
                                "explanation": "Code following an unconditional control transfer statement in the same syntactic block cannot be reached.",
                                "severity": "HIGH",
                                "classification": "PROBLEMATIC",
                                "maintenance_impact": "Creates dead code bloat and confuses developers about actual execution paths.",
                                "refactoring_strategy": "Remove the unreachable statements or correct enclosing branching logic.",
                                "expected_benefit": "Eliminates unreachable dead code and clarifies execution paths."
                            })
                            break  # Only flag the first dead statement in this block

        return findings

    def _is_abstract_or_protocol_member(self, node: ast.FunctionDef) -> bool:
        """Determines if a function is an abstract method or protocol declaration."""
        for d in node.decorator_list:
            if isinstance(d, ast.Name) and d.id in ("abstractmethod", "overload"):
                return True
            elif isinstance(d, ast.Attribute) and d.attr in ("abstractmethod", "overload"):
                return True
        return False

    def _has_global_mutation(self, func_node: ast.AST, global_names: Set[str]) -> bool:
        """Verifies if any declared global variable is actively written or augmented in func_node."""
        for child in ast.walk(func_node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id in global_names:
                        return True
            elif isinstance(child, ast.AugAssign):
                if isinstance(child.target, ast.Name) and child.target.id in global_names:
                    return True
        return False

    def _format_exception_type(self, type_node: Optional[ast.AST]) -> str:
        """Formats the caught exception type safely into a human-readable string."""
        if type_node is None:
            return "bare except"
        try:
            return ast.unparse(type_node)
        except Exception:
            if isinstance(type_node, ast.Name):
                return type_node.id
            elif isinstance(type_node, ast.Attribute):
                return f"{getattr(type_node.value, 'id', '')}.{type_node.attr}"
            return "Exception"
