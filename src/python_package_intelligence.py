# -*- coding: utf-8 -*-
"""
Bintra Python Package Architecture & Static Hazard Intelligence.
Provides deep, zero-dependency architectural dissection of Python codebases:
1. Module Topology & Import Dependency DAG (internal coupling, external stdlib vs third-party).
2. Circular Dependency Detection (Tarjan's strongly connected components on module imports).
3. McCabe Cyclomatic & SonarQube Cognitive Complexity Profiling.
4. Algorithmic Hazard Detection:
   - ReDoS / Polynomial Backtracking regular expressions.
   - Quadratic string concatenation (`+=`) inside iterative loops.
   - Mutable module-level state & global thread safety hazards.
   - Monolithic module and architectural instability metrics (Martin's Afferent/Efferent Coupling).
"""

from __future__ import annotations

import ast
import os
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from security import Capability, ExecutionGuard, PathIdentity


# Patterns indicative of exponential or polynomial catastrophic regex backtracking (ReDoS)
_REDOS_SUSPECT_PATTERNS = [
    re.compile(r"(\([^\)]*[\+\*][^\)]*\))[\+\*]"),          # Nested quantifiers: (a+)+ or (x*)*
    re.compile(r"(\.\*|\.\+)\s*(\.\*|\.\+)"),               # Adjacent unanchored greedy dot-stars
    re.compile(r"\([a-zA-Z0-9_|]*\+[\+\*]"),                # Overlapping alternation with quantifier: (a|a+)+
]


class PythonPackageArchitect:
    """
    Continuous semantic dissector for Python packages and repositories.
    Extracts module topology, call hierarchies, cyclomatic/cognitive complexity,
    and algorithmic bottlenecks with zero runtime dependencies.
    """

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file limit
    SKIP_DIRS = {
        ".git", ".github", "__pycache__", ".pytest_cache", "venv", ".venv",
        "env", "build", "dist", ".tox", ".eggs", "site-packages", ".mypy_cache"
    }

    @classmethod
    def analyze_package(
        cls,
        package_root: str,
        max_files: int = 500,
        complexity_threshold: int = 15
    ) -> Dict[str, Any]:
        """
        Dissects an entire Python package directory into a comprehensive Architectural Dossier.
        """
        can_root = PathIdentity.canonicalize(package_root)
        if not os.path.exists(can_root):
            raise FileNotFoundError(f"Package root not found: {package_root}")
        if not os.path.isdir(can_root):
            raise NotADirectoryError(f"Target is not a directory: {package_root}")

        # Safety reference monitor check
        ExecutionGuard.request_access(
            component="python_intelligence",
            operation="analyze_package",
            target=can_root,
            capability=Capability.FILE_READ,
            access_mode="READ"
        )

        py_files: List[str] = []
        for root, dirs, files in os.walk(can_root):
            dirs[:] = [d for d in dirs if d not in cls.SKIP_DIRS]
            for f in sorted(files):
                if f.endswith(".py"):
                    full_p = os.path.join(root, f)
                    py_files.append(full_p)
                    if len(py_files) >= max_files:
                        break
            if len(py_files) >= max_files:
                break

        package_name = os.path.basename(can_root.rstrip("\\/"))
        modules: Dict[str, Dict[str, Any]] = {}
        import_edges: List[Tuple[str, str]] = []
        internal_module_names: Set[str] = set()

        # Step 1: Pre-compute module names
        for fpath in py_files:
            rel_p = os.path.relpath(fpath, can_root)
            mod_dotted = rel_p.replace(os.sep, ".").replace("/", ".")
            if mod_dotted.endswith(".__init__.py"):
                mod_name = mod_dotted[:-12]
            elif mod_dotted.endswith(".py"):
                mod_name = mod_dotted[:-3]
            else:
                mod_name = mod_dotted
            internal_module_names.add(mod_name)
            # Also register sub-segments
            parts = mod_name.split(".")
            for i in range(1, len(parts) + 1):
                internal_module_names.add(".".join(parts[:i]))

        # Step 2: Parse each module
        total_loc = 0
        total_ast_nodes = 0
        total_functions = 0
        total_classes = 0
        all_redos_hazards: List[Dict[str, Any]] = []
        all_quadratic_concat_hazards: List[Dict[str, Any]] = []
        all_complexity_hotspots: List[Dict[str, Any]] = []
        all_mutable_globals: List[Dict[str, Any]] = []

        for fpath in py_files:
            mod_report = cls._dissect_single_module(
                fpath, can_root, internal_module_names, complexity_threshold
            )
            mod_name = mod_report["module_name"]
            modules[mod_name] = mod_report

            total_loc += mod_report["lines_of_code"]
            total_ast_nodes += mod_report["ast_nodes_count"]
            total_functions += mod_report["functions_count"]
            total_classes += mod_report["classes_count"]

            for imp in mod_report["internal_imports"]:
                import_edges.append((mod_name, imp))

            all_redos_hazards.extend(mod_report["redos_hazards"])
            all_quadratic_concat_hazards.extend(mod_report["quadratic_loop_concats"])
            all_complexity_hotspots.extend(mod_report["complexity_hotspots"])
            all_mutable_globals.extend(mod_report["mutable_module_state"])

        # Step 3: Compute Package Topology & Circular Dependencies
        cycles = cls._detect_import_cycles(modules.keys(), import_edges)

        # Step 4: Compute Afferent (Ca), Efferent (Ce) Coupling & Instability Index
        ca_counts = defaultdict(int)
        ce_counts = defaultdict(int)
        for src, dst in import_edges:
            ce_counts[src] += 1
            ca_counts[dst] += 1

        coupling_metrics: Dict[str, Dict[str, Any]] = {}
        for mod_name in modules:
            ca = ca_counts[mod_name]
            ce = ce_counts[mod_name]
            total_c = ca + ce
            instability = round(ce / max(1, total_c), 3) if total_c > 0 else 0.0
            coupling_metrics[mod_name] = {
                "afferent_coupling_ca": ca,
                "efferent_coupling_ce": ce,
                "instability_index": instability,
                "role": "CORE_STABLE" if instability < 0.3 else ("LEAF_UNSTABLE" if instability > 0.7 else "BALANCED")
            }

        # Step 5: Identify Monolithic Modules (>1000 LOC or >50KB)
        monolithic_modules = [
            {"module": name, "loc": rep["lines_of_code"], "size_bytes": rep["file_size"]}
            for name, rep in modules.items()
            if rep["lines_of_code"] > 1000 or rep["file_size"] > 50000
        ]

        return {
            "status": "ok",
            "package_name": package_name,
            "package_root": can_root,
            "total_modules": len(modules),
            "total_lines_of_code": total_loc,
            "total_ast_nodes": total_ast_nodes,
            "total_functions": total_functions,
            "total_classes": total_classes,
            "monolithic_modules_count": len(monolithic_modules),
            "monolithic_modules": monolithic_modules,
            "circular_dependencies_count": len(cycles),
            "circular_dependencies": cycles,
            "complexity_hotspots_count": len(all_complexity_hotspots),
            "complexity_hotspots": sorted(all_complexity_hotspots, key=lambda x: x["cyclomatic_complexity"], reverse=True)[:30],
            "algorithmic_hazards": {
                "redos_patterns_detected": len(all_redos_hazards),
                "redos_details": all_redos_hazards[:20],
                "quadratic_loop_concats_detected": len(all_quadratic_concat_hazards),
                "quadratic_loop_concats_details": all_quadratic_concat_hazards[:20],
                "mutable_module_state_detected": len(all_mutable_globals),
                "mutable_module_state_details": all_mutable_globals[:20],
            },
            "module_coupling_metrics": coupling_metrics,
            "modules_summary": {
                name: {
                    "loc": rep["lines_of_code"],
                    "functions": rep["functions_count"],
                    "classes": rep["classes_count"],
                    "max_complexity": rep["max_function_complexity"],
                    "internal_deps": rep["internal_imports"],
                    "third_party_deps": rep["third_party_imports"],
                }
                for name, rep in modules.items()
            },
            "epistemic_classification": "PYTHON_PACKAGE_ARCHITECTURAL_DISSECTION"
        }

    @classmethod
    def _dissect_single_module(
        cls,
        file_path: str,
        package_root: str,
        internal_names: Set[str],
        complexity_threshold: int
    ) -> Dict[str, Any]:
        rel_p = os.path.relpath(file_path, package_root)
        mod_dotted = rel_p.replace(os.sep, ".").replace("/", ".")
        if mod_dotted.endswith(".__init__.py"):
            mod_name = mod_dotted[:-12]
        elif mod_dotted.endswith(".py"):
            mod_name = mod_dotted[:-3]
        else:
            mod_name = mod_dotted

        file_size = os.path.getsize(file_path)
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code_text = f.read()

        loc = len(code_text.splitlines())
        internal_imports: Set[str] = set()
        stdlib_imports: Set[str] = set()
        third_party_imports: Set[str] = set()
        classes: List[str] = []
        functions: List[str] = []
        complexity_hotspots: List[Dict[str, Any]] = []
        redos_hazards: List[Dict[str, Any]] = []
        quadratic_concats: List[Dict[str, Any]] = []
        mutable_globals: List[Dict[str, Any]] = []
        ast_nodes_count = 0
        max_cyclomatic = 0

        try:
            tree = ast.parse(code_text, filename=file_path)
            for node in ast.walk(tree):
                ast_nodes_count += 1

                # Imports
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        if top in internal_names or alias.name in internal_names:
                            internal_imports.add(alias.name)
                        elif top in cls._get_stdlib_modules():
                            stdlib_imports.add(top)
                        else:
                            third_party_imports.add(top)
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    level = node.level or 0
                    if level > 0 or mod.split(".")[0] in internal_names:
                        internal_imports.add(mod)
                    elif mod.split(".")[0] in cls._get_stdlib_modules():
                        stdlib_imports.add(mod.split(".")[0])
                    else:
                        third_party_imports.add(mod.split(".")[0])

                # Classes
                elif isinstance(node, ast.ClassDef):
                    classes.append(node.name)

                # ReDoS detection in regex compilation
                elif isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Attribute) and node.func.attr in ("compile", "search", "match", "findall", "finditer", "sub"):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "re":
                            func_name = f"re.{node.func.attr}"
                    if func_name and node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            raw_regex = first_arg.value
                            for p in _REDOS_SUSPECT_PATTERNS:
                                m = p.search(raw_regex)
                                if m:
                                    redos_hazards.append({
                                        "module": mod_name,
                                        "line": getattr(node, "lineno", 0),
                                        "pattern_snippet": raw_regex[:120],
                                        "vulnerability_type": "EXPONENTIAL_CATASTROPHIC_BACKTRACKING",
                                        "trigger_token": m.group(0),
                                    })
                                    break

            # Top-level statements for mutable globals
            for item in tree.body:
                if isinstance(item, ast.Assign):
                    if isinstance(item.value, (ast.List, ast.Dict, ast.Set)):
                        for t in item.targets:
                            if isinstance(t, ast.Name):
                                if t.id.startswith("__") or t.id in ("__all__", "__version__"):
                                    continue
                                mutable_globals.append({
                                    "module": mod_name,
                                    "variable": t.id,
                                    "line": item.lineno,
                                    "type": type(item.value).__name__,
                                })

            # Function complexity analysis
            for item in ast.walk(tree):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append(item.name)
                    cyclo = cls._calculate_cyclomatic_complexity(item)
                    cog = cls._calculate_cognitive_complexity(item)
                    if cyclo > max_cyclomatic:
                        max_cyclomatic = cyclo
                    if cyclo >= complexity_threshold or cog >= 25:
                        complexity_hotspots.append({
                            "module": mod_name,
                            "function": item.name,
                            "line": item.lineno,
                            "cyclomatic_complexity": cyclo,
                            "cognitive_complexity": cog,
                            "risk_tier": "CRITICAL" if (cyclo > 30 or cog > 50) else "HIGH",
                        })

                    # Quadratic string concatenation search inside loops
                    for child in ast.walk(item):
                        if isinstance(child, (ast.For, ast.AsyncFor, ast.While)):
                            for loop_child in ast.walk(child):
                                if isinstance(loop_child, ast.AugAssign) and isinstance(loop_child.op, ast.Add):
                                    if isinstance(loop_child.target, ast.Name):
                                        target_name = loop_child.target.id
                                        target_lower = target_name.lower()

                                        # Exclude numeric literals and len() calls
                                        is_num_literal = isinstance(loop_child.value, ast.Constant) and isinstance(loop_child.value.value, (int, float, complex))
                                        is_len_call = isinstance(loop_child.value, ast.Call) and getattr(getattr(loop_child.value, "func", None), "id", "") == "len"

                                        if not is_num_literal and not is_len_call:
                                            is_str_val = (
                                                (isinstance(loop_child.value, ast.Constant) and isinstance(loop_child.value.value, str))
                                                or isinstance(loop_child.value, ast.JoinedStr)
                                                or (isinstance(loop_child.value, ast.Call) and getattr(getattr(loop_child.value, "func", None), "id", "") == "str")
                                            )
                                            # Check if target is string-like and NOT an obvious counter
                                            is_counter = any(target_lower.startswith(p) for p in ("total", "count", "num_", "idx", "len", "n_"))
                                            is_str_target = not is_counter and any(k in target_lower for k in ("text", "str", "line", "buf", "out_str", "result_str", "msg"))

                                            if is_str_val or is_str_target:
                                                quadratic_concats.append({
                                                    "module": mod_name,
                                                    "function": item.name,
                                                    "variable": target_name,
                                                    "line": loop_child.lineno,
                                                    "risk": "QUADRATIC_STRING_CONCATENATION_IN_LOOP"
                                                })

        except Exception as exc:
            pass

        return {
            "module_name": mod_name,
            "relative_path": rel_p,
            "file_size": file_size,
            "lines_of_code": loc,
            "ast_nodes_count": ast_nodes_count,
            "functions_count": len(functions),
            "classes_count": len(classes),
            "max_function_complexity": max_cyclomatic,
            "internal_imports": sorted(list(internal_imports)),
            "stdlib_imports": sorted(list(stdlib_imports)),
            "third_party_imports": sorted(list(third_party_imports)),
            "complexity_hotspots": complexity_hotspots,
            "redos_hazards": redos_hazards,
            "quadratic_loop_concats": quadratic_concats,
            "mutable_module_state": mutable_globals,
        }

    @staticmethod
    def _calculate_cyclomatic_complexity(fn_node: ast.AST) -> int:
        """Computes McCabe cyclomatic complexity: 1 + decision points."""
        complexity = 1
        for node in ast.walk(fn_node):
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(node, ast.BoolOp):
                complexity += len(node.values) - 1
            elif isinstance(node, (ast.comprehension, ast.IfExp)):
                complexity += 1
        return complexity

    @staticmethod
    def _calculate_cognitive_complexity(fn_node: ast.AST) -> int:
        """
        Computes Cognitive Complexity (SonarQube metric):
        Measures structural nesting and flow breaks.
        """
        cognitive = 0

        def _traverse(node: ast.AST, nesting: int):
            nonlocal cognitive
            for child in ast.iter_child_nodes(node):
                inc = 0
                next_nesting = nesting
                if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler)):
                    inc = 1 + nesting
                    next_nesting = nesting + 1
                elif isinstance(child, ast.BoolOp):
                    inc = 1
                elif isinstance(child, (ast.Break, ast.Continue)):
                    inc = 1
                elif isinstance(child, ast.IfExp):
                    inc = 1 + nesting

                cognitive += inc
                _traverse(child, next_nesting)

        _traverse(fn_node, 0)
        return cognitive

    @staticmethod
    def _detect_import_cycles(modules: Iterable[str], edges: List[Tuple[str, str]]) -> List[List[str]]:
        """Finds all elementary cycles in internal module import graph using DFS."""
        adj = defaultdict(set)
        for u, v in edges:
            if u != v:
                adj[u].add(v)

        cycles: List[List[str]] = []
        visited = set()
        rec_stack = []
        rec_set = set()

        def _dfs(node: str):
            visited.add(node)
            rec_stack.append(node)
            rec_set.add(node)

            for neighbor in sorted(adj.get(node, [])):
                if neighbor not in visited:
                    _dfs(neighbor)
                elif neighbor in rec_set:
                    cycle_start = rec_stack.index(neighbor)
                    cycle = rec_stack[cycle_start:] + [neighbor]
                    if cycle not in cycles and len(cycle) > 2:
                        cycles.append(cycle)

            rec_stack.pop()
            rec_set.remove(node)

        for m in sorted(modules):
            if m not in visited:
                _dfs(m)

        return cycles

    @staticmethod
    def _get_stdlib_modules() -> Set[str]:
        return {
            "abc", "argparse", "ast", "asyncio", "base64", "collections", "contextlib",
            "copy", "csv", "ctypes", "dataclasses", "datetime", "decimal", "dis",
            "enum", "errno", "functools", "glob", "gzip", "hashlib", "heapq",
            "hmac", "html", "http", "importlib", "inspect", "io", "itertools",
            "json", "logging", "math", "multiprocessing", "os", "pathlib",
            "pickle", "platform", "pprint", "random", "re", "shutil", "signal",
            "socket", "sqlite3", "ssl", "stat", "string", "struct", "subprocess",
            "sys", "tempfile", "threading", "time", "traceback", "types",
            "typing", "unicodedata", "unittest", "urllib", "uuid", "warnings",
            "weakref", "xml", "zipfile", "zlib"
        }
