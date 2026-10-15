"""
Unit and integration tests for Phase 6 Code Smell and Maintainability Analysis Agent.
Covers positive detections, negative detections, boundary limits, and pipeline integration.
"""

import os
import shutil
import tempfile
import unittest
from typing import Dict, Any

from src.phase6.code_smells import CodeSmellAnalysisAgent
from src.phase7.cross_domain import CrossDomainAnalysisAgent
from src.phase8.recommendations import RecommendationEngineAgent
from src.phase9.report import FinalReportGeneratorAgent
from pipeline import run_pipeline


class TestPhase6CodeSmellAgent(unittest.TestCase):
    """Test suite covering the 18 quality dimensions, boundary safety, and integration."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_phase6_")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _write_file(self, rel_path: str, content: str) -> str:
        full_path = os.path.join(self.test_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        return full_path

    # =========================================================================
    # Group A: Positive Detections
    # =========================================================================

    def test_positive_long_method(self):
        """Functions exceeding 80 lines must be flagged with category 'Long Method'."""
        lines = ["def lengthy_routine():"] + [f"    x_{i} = {i}" for i in range(90)] + ["    return x_89"]
        self._write_file("module.py", "\n".join(lines))

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "Long Method"]
        self.assertEqual(len(smells), 1)
        self.assertIn("lengthy_routine", smells[0]["function_or_class"])
        self.assertIn("92 lines", smells[0]["evidence"])

    def test_positive_deep_nesting(self):
        """Block nesting depth >= 4 must be flagged with category 'Deep Nesting'."""
        code = (
            "def deeply_nested(val):\n"
            "    if val > 0:\n"
            "        for i in range(val):\n"
            "            while i < 10:\n"
            "                if i % 2 == 0:\n"
            "                    print(i)\n"
            "                i += 1\n"
        )
        self._write_file("nest.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "Deep Nesting"]
        self.assertEqual(len(smells), 1)
        self.assertEqual(smells[0]["function_or_class"], "deeply_nested")
        self.assertIn("4 levels", smells[0]["evidence"])

    def test_positive_high_complexity(self):
        """Functions with cyclomatic complexity > 15 must be flagged."""
        # 16 decision points via if statements
        branches = "\n".join([f"    if x == {i}: return {i}" for i in range(16)])
        code = f"def high_branching(x):\n{branches}\n    return -1\n"
        self._write_file("complex.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "High Cyclomatic Complexity"]
        self.assertEqual(len(smells), 1)
        self.assertEqual(smells[0]["function_or_class"], "high_branching")
        self.assertIn("score of 17", smells[0]["evidence"])

    def test_positive_large_class(self):
        """Classes with > 12 methods or > 250 lines must be flagged."""
        methods = "\n".join([f"    def method_{i}(self): pass" for i in range(14)])
        code = f"class LargeGodClass:\n{methods}\n"
        self._write_file("god_class.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "God Class / Large Class"]
        self.assertEqual(len(smells), 1)
        self.assertEqual(smells[0]["function_or_class"], "LargeGodClass")
        self.assertIn("14 methods", smells[0]["evidence"])

    def test_positive_silent_exception(self):
        """Silent pass in except handlers must be flagged with category 'Poor Exception Handling'."""
        code = (
            "def worker():\n"
            "    try:\n"
            "        do_something()\n"
            "    except Exception:\n"
            "        pass\n"
            "    try:\n"
            "        do_other()\n"
            "    except:\n"
            "        ...\n"
        )
        self._write_file("err.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "Poor Exception Handling"]
        self.assertEqual(len(smells), 2)
        self.assertTrue(all("SILENT-EXCEPTION" in s["smell_id"] for s in smells))

    def test_positive_repeated_conditionals(self):
        """Chained if/elif ladders with >= 4 branches must be flagged."""
        code = (
            "def dispatch(kind):\n"
            "    if kind == 'a':\n"
            "        return 1\n"
            "    elif kind == 'b':\n"
            "        return 2\n"
            "    elif kind == 'c':\n"
            "        return 3\n"
            "    elif kind == 'd':\n"
            "        return 4\n"
            "    return 0\n"
        )
        self._write_file("dispatcher.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "Repeated Conditionals"]
        self.assertEqual(len(smells), 1)
        self.assertIn("4 sequential branching conditions", smells[0]["evidence"])

    def test_positive_hardcoded_configuration(self):
        """Embedded module-level configuration dictionaries must be flagged."""
        code = (
            "SYSTEM_RULES_CONFIG = {\n"
            "    'r1': 100,\n"
            "    'r2': 200,\n"
            "    'r3': 300,\n"
            "    'r4': 400,\n"
            "    'r5': 500,\n"
            "    'r6': 600,\n"
            "    'r7': 700,\n"
            "}\n"
        )
        self._write_file("config.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["category"] == "Hard-coded Configuration"]
        self.assertEqual(len(smells), 1)
        self.assertEqual(smells[0]["classification"], "JUSTIFIED")

    def test_positive_duplicate_cli_logic(self):
        """Duplicate safe_write_output routines in pipeline.py and ingest.py must be flagged."""
        cli_code = (
            "import sys\n"
            "if sys.platform == 'win32': sys.stdout.reconfigure(encoding='utf-8')\n"
            "def safe_write_output(path, data):\n"
            "    with open(path, 'w') as f: f.write(data)\n"
        )
        self._write_file("pipeline.py", cli_code)
        self._write_file("ingest.py", cli_code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["smell_id"] == "SMELL-DUPLICATE-CLI-LOGIC"]
        self.assertEqual(len(smells), 1)

    def test_positive_primitive_obsession_contracts(self):
        """Untyped dictionary exchanges across phase boundaries must be flagged."""
        p1 = (
            "from typing import Dict, Any\n"
            "class ProjectReconstructionAgent:\n"
            "    def reconstruct(self) -> Dict[str, Any]:\n"
            "        return {'source_files': [], 'apis': []}\n"
        )
        p2 = (
            "from typing import Dict, Any\n"
            "class RequirementsEngineeringAgent:\n"
            "    def __init__(self, p1: Dict[str, Any]):\n"
            "        self.files = p1.get('source_files', [])\n"
            "        self.apis = p1['apis']\n"
        )
        self._write_file("src/phase1/reconstruction.py", p1)
        self._write_file("src/phase2/requirements.py", p2)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        smells = [s for s in result["code_smells"] if s["smell_id"] == "SMELL-PRIMITIVE-OBSESSION-CONTRACTS"]
        self.assertEqual(len(smells), 1)

    def test_positive_remaining_dimensions(self):
        """Verifies Long Params, Multiple Returns, Dead Code, Mutable Default, Broad Except, Globals, Local Imports, Magic Numbers."""
        code = (
            "import os\n"
            "COUNTER = 0\n"
            "def multi_issue_func(p1, p2, p3, p4, p5, p6, p7, bad_default=[]):\n"
            "    global COUNTER\n"
            "    COUNTER += 1\n"
            "    import json\n"
            "    import math\n"
            "    import csv\n"
            "    if p1 > 9999:\n"
            "        return 1\n"
            "    elif p2 > 1:\n"
            "        return 2\n"
            "    elif p3 > 1:\n"
            "        return 3\n"
            "    elif p4 > 1:\n"
            "        return 4\n"
            "    return 5\n"
            "    unreachable_dead_code = 42\n"
        )
        self._write_file("multi.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        categories = {s["category"] for s in result["code_smells"]}
        self.assertIn("Long Parameter List", categories)
        self.assertIn("Dangerous Default Value", categories)
        self.assertIn("Multiple Return Points", categories)
        self.assertIn("Dead Code", categories)
        self.assertIn("Global State Mutation", categories)
        self.assertIn("Excessive Local Imports", categories)
        self.assertIn("Magic Numbers", categories)

    # =========================================================================
    # Group B: Negative Detections
    # =========================================================================

    def test_negative_short_simple_function(self):
        """Short, simple functions must produce no code smell findings."""
        code = (
            "def add_numbers(a: int, b: int) -> int:\n"
            "    return a + b\n"
        )
        self._write_file("clean.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        self.assertEqual(len(result["code_smells"]), 0)
        self.assertEqual(result["summary"]["total_smells"], 0)

    def test_negative_flat_low_complexity(self):
        """Flat functions with sequential if checks must not trigger deep nesting."""
        code = (
            "def flat_checker(x):\n"
            "    if x == 1: pass\n"
            "    if x == 2: pass\n"
            "    if x == 3: pass\n"
            "    return x\n"
        )
        self._write_file("flat.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        nest_smells = [s for s in result["code_smells"] if s["category"] == "Deep Nesting"]
        self.assertEqual(len(nest_smells), 0)

    def test_negative_exception_handler_with_logging(self):
        """Exception handlers with logging or recovery must not be flagged as silent exceptions."""
        code = (
            "import logging\n"
            "def worker():\n"
            "    try:\n"
            "        do_work()\n"
            "    except OSError as err:\n"
            "        logging.error(f'Failure: {err}')\n"
            "        return False\n"
        )
        self._write_file("handled.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        silent_smells = [s for s in result["code_smells"] if s["category"] == "Poor Exception Handling"]
        self.assertEqual(len(silent_smells), 0)

    def test_negative_conditionals_in_comments_and_strings(self):
        """If/elif ladders mentioned inside strings or comments must not trigger repeated conditionals."""
        code = (
            "\"\"\"\n"
            "Example ladder:\n"
            "elif x == 1:\n"
            "elif x == 2:\n"
            "elif x == 3:\n"
            "elif x == 4:\n"
            "\"\"\"\n"
            "# elif test:\n"
            "# elif test2:\n"
            "# elif test3:\n"
            "# elif test4:\n"
            "def regular_func():\n"
            "    return True\n"
        )
        self._write_file("comments.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        ladder_smells = [s for s in result["code_smells"] if s["category"] == "Repeated Conditionals"]
        self.assertEqual(len(ladder_smells), 0)

    def test_negative_config_identifier_in_comment(self):
        """Comments containing configuration identifiers must not trigger hardcoded configuration."""
        code = (
            "# Remember: do not define SEVERITY_WEIGHTS or SYSTEM_RULES_CONFIG in code.\n"
            "def execute():\n"
            "    return 42\n"
        )
        self._write_file("comment_config.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        config_smells = [s for s in result["code_smells"] if s["category"] == "Hard-coded Configuration"]
        self.assertEqual(len(config_smells), 0)

    def test_negative_similar_cli_not_duplicate(self):
        """Files with distinct, non-duplicate routines must not trigger duplicate CLI logic."""
        self._write_file("pipeline.py", "def run_pipe(): return 1\n")
        self._write_file("ingest.py", "def run_ingest(): return 2\n")

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        dup_smells = [s for s in result["code_smells"] if s["smell_id"] == "SMELL-DUPLICATE-CLI-LOGIC"]
        self.assertEqual(len(dup_smells), 0)

    def test_negative_typed_phase_contracts(self):
        """Phases using typed dataclasses must not trigger primitive obsession."""
        p1 = (
            "from dataclasses import dataclass\n"
            "@dataclass\n"
            "class ReconModel:\n"
            "    source_files: list\n"
        )
        p2 = (
            "class RequirementsAgent:\n"
            "    def __init__(self, model):\n"
            "        self.files = model.source_files\n"
        )
        self._write_file("src/phase1/reconstruction.py", p1)
        self._write_file("src/phase2/requirements.py", p2)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        prim_smells = [s for s in result["code_smells"] if s["smell_id"] == "SMELL-PRIMITIVE-OBSESSION-CONTRACTS"]
        self.assertEqual(len(prim_smells), 0)

    # =========================================================================
    # Group C: Boundary Cases & Robustness
    # =========================================================================

    def test_boundary_exact_thresholds(self):
        """Constructs exactly at threshold (e.g. 80 lines, nesting depth 3, 12 methods) must not trigger."""
        lines = ["def boundary_func():"] + [f"    x_{i} = {i}" for i in range(78)] + ["    return x_77"]
        self.assertEqual(len(lines), 80)  # Exactly 80 lines
        self._write_file("boundary_lines.py", "\n".join(lines))

        # Class with exactly 12 methods
        methods = "\n".join([f"    def m_{i}(self): pass" for i in range(12)])
        self._write_file("boundary_class.py", f"class ExactClass:\n{methods}\n")

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        long_methods = [s for s in result["code_smells"] if s["category"] == "Long Method"]
        god_classes = [s for s in result["code_smells"] if s["category"] == "God Class / Large Class"]

        self.assertEqual(len(long_methods), 0)
        self.assertEqual(len(god_classes), 0)

    def test_boundary_empty_and_syntax_error_files(self):
        """Empty files and invalid Python syntax must be safely diagnosed without crashing the agent."""
        self._write_file("empty.py", "")
        self._write_file("broken.py", "def broken_syntax(:\n")
        self._write_file("valid.py", "def valid_func(): return 1\n")

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        self.assertIn("scan_diagnostics", result)
        syntax_errors = [d for d in result["scan_diagnostics"] if d["status"] == "SYNTAX_ERROR"]
        self.assertEqual(len(syntax_errors), 1)
        self.assertEqual(syntax_errors[0]["file"], "broken.py")

    def test_boundary_oversized_file(self):
        """Files exceeding MAX_FILE_READ_SIZE must be safely skipped with diagnostic."""
        self._write_file("huge.py", "x = 1\n" * 100)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        agent.MAX_FILE_READ_SIZE = 10  # Temporarily lower limit for testing

        result = agent.analyze()
        oversized_diags = [d for d in result["scan_diagnostics"] if d["status"] == "SKIPPED_OVERSIZED"]
        self.assertEqual(len(oversized_diags), 1)

    def test_boundary_symlink_outside_root(self):
        """Symlinks pointing outside the project root must be rejected."""
        external_dir = tempfile.mkdtemp(prefix="external_")
        self.addCleanup(lambda: shutil.rmtree(external_dir, ignore_errors=True))

        ext_file = os.path.join(external_dir, "secret.py")
        with open(ext_file, "w", encoding="utf-8") as f:
            f.write("def stolen(): pass\n")

        symlink_path = os.path.join(self.test_dir, "sym_escape.py")
        try:
            os.symlink(ext_file, symlink_path)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation requires elevated privileges on this environment")

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        files = agent._collect_python_files()

        self.assertNotIn("sym_escape.py", [f[0] for f in files])

    def test_boundary_symlink_outside_root_mocked(self):
        """Mocks realpath pointing outside canonical root to verify rejection without OS symlink privilege."""
        from unittest.mock import patch
        self._write_file("simulated_symlink.py", "def evil(): pass\n")

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        canonical = os.path.realpath(self.test_dir)

        with patch("os.path.realpath", side_effect=lambda p: "C:\\outside\\escaped.py" if "simulated_symlink" in p else canonical):
            files = agent._collect_python_files()

        self.assertNotIn("simulated_symlink.py", [f[0] for f in files])

    def test_boundary_nested_functions_isolated(self):
        """Enclosing function must not absorb complexity or nesting depth from nested functions."""
        code = (
            "def outer_flat(x):\n"
            "    def inner_complex(y):\n"
            "        if y > 0:\n"
            "            for j in range(y):\n"
            "                while j < 5:\n"
            "                    if j % 2 == 0:\n"
            "                        return j\n"
            "    return x\n"
        )
        self._write_file("nested.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        outer_nest_smells = [
            s for s in result["code_smells"]
            if s["category"] == "Deep Nesting" and s["function_or_class"] == "outer_flat"
        ]
        self.assertEqual(len(outer_nest_smells), 0)

    def test_boundary_unicode_source_code(self):
        """Source files containing multibyte Unicode characters and emojis must parse correctly."""
        code = (
            "# 🚀 SentinelGuard Security System\n"
            "def internationalized_routine():\n"
            "    message = 'こんにちは世界 🛡️'\n"
            "    return message\n"
        )
        self._write_file("unicode_pkg.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        self.assertIsInstance(result["code_smells"], list)

    def test_boundary_stable_ids_and_deterministic_summary(self):
        """Repeated analysis runs must produce identical findings, sorting, and summary counts."""
        code = (
            "def func_a():\n"
            "    try:\n"
            "        do_work()\n"
            "    except Exception:\n"
            "        pass\n"
            "def func_b():\n"
            "    x = 100\n"
        )
        self._write_file("stable.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        r1 = agent.analyze()
        r2 = agent.analyze()

        self.assertEqual(r1["code_smells"], r2["code_smells"])
        self.assertEqual(r1["summary"], r2["summary"])

        s = r1["summary"]
        self.assertEqual(
            s["total_smells"],
            s["problematic"] + s["potentially_excessive"] + s["justified"] + s["unknown"]
        )

    # =========================================================================
    # Group D: Pipeline Integration and Downstream Compatibility
    # =========================================================================

    def test_integration_downstream_phases(self):
        """Verifies Phase 6 output schema conforms to Phase 7, Phase 8, and Phase 9 requirements."""
        agent6 = CodeSmellAnalysisAgent(root_path=self.test_dir)
        p6_output = agent6.analyze()

        # Phase 7 Consumption
        agent7 = CrossDomainAnalysisAgent(phase6_smells=p6_output["code_smells"])
        p7_output = agent7.analyze()
        self.assertIn("cross_domain_relationships", p7_output)

        # Phase 8 Consumption
        agent8 = RecommendationEngineAgent(phase6_smells=p6_output["code_smells"])
        p8_output = agent8.generate_recommendations()
        self.assertIn("recommendations", p8_output)

        # Phase 9 Consumption
        agent9 = FinalReportGeneratorAgent(phase6_smells=p6_output)
        p9_data = agent9.generate_report_data()
        self.assertIn("major_maintainability_findings", p9_data["executive_summary"])

    def test_dead_code_nested_branches_and_finally(self):
        """Verifies dead code detection inside branches and loops, while keeping finally blocks and subsequent branch statements alive."""
        code = (
            "def branch_and_loop_func(val):\n"
            "    if val > 10:\n"
            "        return val\n"
            "        dead_in_if = 1\n"
            "    else:\n"
            "        val += 1\n"
            "    # This is reachable when val <= 10\n"
            "    alive_after_if = val * 2\n"
            "    for i in range(5):\n"
            "        if i == 3:\n"
            "            break\n"
            "            dead_after_break = True\n"
            "    try:\n"
            "        return alive_after_if\n"
            "        dead_in_try = -1\n"
            "    finally:\n"
            "        # Finally block always executes, so this is NOT dead code\n"
            "        print('cleanup in finally')\n"
        )
        self._write_file("dead_blocks.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        dead_smells = [s for s in result["code_smells"] if s["category"] == "Dead Code"]
        # Expected dead lines: dead_in_if (L4), dead_after_break (L12), dead_in_try (L15)
        dead_lines = [s["evidence"] for s in dead_smells]
        self.assertEqual(len(dead_smells), 3)
        self.assertTrue(any("line 4" in e for e in dead_lines))
        self.assertTrue(any("line 12" in e for e in dead_lines))
        self.assertTrue(any("line 15" in e for e in dead_lines))
        # Ensure cleanup in finally is NOT flagged
        self.assertFalse(any("cleanup in finally" in e or "line 17" in e for e in dead_lines))

    def test_abstract_and_protocol_not_speculative_generality(self):
        """Abstract methods, overloaded methods, and functions with docstrings must not be flagged as speculative stubs."""
        code = (
            "from abc import ABC, abstractmethod\n"
            "from typing import overload\n"
            "class AbstractInterface(ABC):\n"
            "    @abstractmethod\n"
            "    def do_work(self):\n"
            "        pass\n"
            "    @overload\n"
            "    def query(self, id: int) -> str: ...\n"
            "    def documented_stub(self):\n"
            "        \"\"\"Interface placeholder for subclasses.\"\"\"\n"
            "        pass\n"
            "    def explicit_placeholder(self):\n"
            "        raise NotImplementedError('Subclass responsibility')\n"
        )
        self._write_file("abstract_module.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        stub_smells = [s for s in result["code_smells"] if s["category"] == "Speculative Generality"]
        self.assertEqual(len(stub_smells), 0)

    def test_global_declaration_vs_mutation(self):
        """Functions actively mutating globals are classified as PROBLEMATIC, while read-only globals are classified as POTENTIALLY_EXCESSIVE."""
        code_mutate = (
            "COUNTER = 0\n"
            "def increment():\n"
            "    global COUNTER\n"
            "    COUNTER += 1\n"
        )
        code_declare_only = (
            "CONFIG_VAL = 42\n"
            "def read_global():\n"
            "    global CONFIG_VAL\n"
            "    return CONFIG_VAL\n"
        )
        self._write_file("mutate.py", code_mutate)
        self._write_file("read_only.py", code_declare_only)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        mut_smells = [s for s in result["code_smells"] if s["file"] == "mutate.py" and "GLOBAL" in s["smell_id"]]
        read_smells = [s for s in result["code_smells"] if s["file"] == "read_only.py" and "GLOBAL" in s["smell_id"]]

        self.assertEqual(len(mut_smells), 1)
        self.assertEqual(mut_smells[0]["category"], "Global State Mutation")
        self.assertEqual(mut_smells[0]["classification"], "PROBLEMATIC")

        self.assertEqual(len(read_smells), 1)
        self.assertEqual(read_smells[0]["category"], "Global Scope Coupling")
        self.assertEqual(read_smells[0]["classification"], "POTENTIALLY_EXCESSIVE")

    def test_duplicate_cli_structural_match_vs_different_body(self):
        """Functions with same name but completely different AST bodies must NOT be flagged as duplicate code."""
        p_code = "def safe_write_output(path, data):\n    with open(path, 'w') as f: f.write(data)\n"
        i_code = "def safe_write_output(path, data):\n    import logging\n    logging.info('Completely different logic')\n    return False\n"

        self._write_file("pipeline.py", p_code)
        self._write_file("ingest.py", i_code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        dup_smells = [s for s in result["code_smells"] if s["smell_id"] == "SMELL-DUPLICATE-CLI-LOGIC"]
        self.assertEqual(len(dup_smells), 0)

    def test_magic_numbers_booleans_not_flagged(self):
        """Comparisons against booleans (True, False) must not be flagged as magic numbers."""
        code = (
            "def check_flag(status):\n"
            "    if status == True:\n"
            "        return 1\n"
            "    if status == False:\n"
            "        return 0\n"
            "    return -1\n"
        )
        self._write_file("bools.py", code)

        agent = CodeSmellAnalysisAgent(root_path=self.test_dir)
        result = agent.analyze()

        magic_smells = [s for s in result["code_smells"] if s["category"] == "Magic Numbers"]
        self.assertEqual(len(magic_smells), 0)

    def test_pipeline_phase6_execution(self):
        """Verifies pipeline.py successfully runs Phase 6 in isolation."""
        self._write_file("main.py", "def health(): return {'status': 'ok'}\n")
        p6_result = run_pipeline(source=self.test_dir, source_type="dir", phase="6")

        self.assertIn("code_smells", p6_result)
        self.assertIn("summary", p6_result)
        self.assertIn("total_smells", p6_result["summary"])


if __name__ == "__main__":
    unittest.main()
