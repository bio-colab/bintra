#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared Ghidra Headless Analyzer Runner.

Single authoritative execution engine for launching Ghidra's
``analyzeHeadless`` with the Bintra bridge scripts. Used by BOTH the CLI
(``bintra ghidra-headless``) and the MCP server (``bintra_ghidra_headless``)
so that binary discovery, command construction, timeout handling, output
metric parsing, and transient project cleanup can never drift between the
two entry surfaces.

Security note: callers remain responsible for ``ExecutionGuard.request_access``
authorization (their component/operation names are audit-relevant); this module
only executes an already-authorized analysis run and cleans up its transient
Ghidra project through ``GhidraProjectGuard``.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

SRC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SRC_DIR.parent

SCRIPT_ERROR_MARKERS = [
    "SCRIPT ERROR:",
    "Analysis failed for file:",
    "GhidraScriptLoadException",
    "RuntimeException:",
    "ERROR (GhidraScript)",
]


class GhidraHeadlessRunner:
    """Deterministic, shared ``analyzeHeadless`` execution pipeline."""

    @staticmethod
    def discover_headless_binary(ghidra_path: Optional[str] = None) -> Optional[Path]:
        """Discovers the analyzeHeadless launcher from env/config/common roots."""
        import os

        ghidra_path_val = ghidra_path or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
        headless_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
        alt_name = "analyzeHeadless" if os.name == "nt" else "analyzeHeadless.bat"

        if ghidra_path_val:
            p = Path(ghidra_path_val)
            cand = p / "support" / headless_name
            if cand.exists():
                return cand
            alt = p / "support" / alt_name
            if alt.exists():
                return alt

        candidates = [
            Path.home() / "tools" / "ghidra",
            Path.home() / "ghidra",
            Path(r"C:\ghidra") if os.name == "nt" else Path("/opt/ghidra"),
            Path(r"C:\tools\ghidra"),
            Path(r"D:\ghidra"),
        ]
        for cand_dir in candidates:
            cand = cand_dir / "support" / headless_name
            if cand.exists():
                return cand
            alt = cand_dir / "support" / alt_name
            if alt.exists():
                return alt
        return None

    @staticmethod
    def parse_bridge_metrics(stdout: str) -> Dict[str, int]:
        """Heuristically extracts summary metrics emitted by BintraGhidraBridge.java."""
        analyzed_funcs = 0
        opaque_detected = 0
        cff_detected = 0
        for line in (stdout or "").splitlines():
            if "Proven Invariant Tautologies" in line:
                try:
                    opaque_detected = int(line.split(":")[-1].strip())
                except Exception:
                    pass
            elif "Control Flow Flattening" in line:
                try:
                    cff_detected = int(line.split(":")[-1].strip())
                except Exception:
                    pass
            elif "Extracted High P-Code & Full CFG for" in line:
                try:
                    analyzed_funcs = int(line.split("for")[-1].split("/")[0].strip())
                except Exception:
                    pass
        return {
            "analyzed_functions_count": analyzed_funcs,
            "opaque_predicates_detected": opaque_detected,
            "cff_backbones_detected": cff_detected,
        }

    @classmethod
    def run(
        cls,
        binary_path: str,
        apply: bool = False,
        timeout_sec: int = 300,
        delete_project: bool = True,
        ghidra_path: Optional[str] = None,
        post_script: str = "BintraGhidraBridge.java",
        project_name: Optional[str] = None,
        project_dir: Optional[str] = None,
        max_cpu: Optional[int] = None,
        script_args: Optional[List[str]] = None,
        guard_component: str = "ghidra_headless",
    ) -> Dict[str, Any]:
        """
        Executes one headless analysis run and returns a machine-readable result.

        Raises ``FileNotFoundError`` when no Ghidra installation can be discovered.
        """
        from security import GhidraProjectGuard

        headless_bin = cls.discover_headless_binary(ghidra_path)
        if not headless_bin or not headless_bin.exists():
            raise FileNotFoundError(
                "analyzeHeadless executable not found. Configure GHIDRA_INSTALL_DIR or pass an explicit ghidra path."
            )

        script_dir = REPO_ROOT / "ghidra_scripts"
        proj_name = GhidraProjectGuard.sanitize_project_name(project_name)
        proj_dir = GhidraProjectGuard.resolve_project_dir(project_dir)
        rep_path, gpr_path = GhidraProjectGuard.register_and_prepare_project(guard_component, proj_dir, proj_name)

        effective_script_args = list(script_args or [])
        if apply and "apply" not in effective_script_args:
            effective_script_args.append("apply")

        cmd = [
            str(headless_bin),
            proj_dir,
            proj_name,
            "-import", binary_path,
            "-overwrite",
            "-scriptPath", str(script_dir),
            "-postScript", post_script,
        ]
        if max_cpu:
            cmd.extend(["-maxCpu", str(max_cpu)])
        cmd.extend(effective_script_args)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_sec,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            returncode = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as tex:
            stdout = tex.stdout or "" if isinstance(tex.stdout, str) else ""
            stderr = tex.stderr or "" if isinstance(tex.stderr, str) else ""
            returncode = 124
            timed_out = True

        project_cleaned = False
        if delete_project:
            project_cleaned = GhidraProjectGuard.clean_transient_project(guard_component, proj_dir, proj_name)

        combined = stdout + "\n" + stderr
        has_script_error = any(m in combined for m in SCRIPT_ERROR_MARKERS)
        effective_exit = returncode if returncode != 0 else (1 if has_script_error else 0)
        metrics = cls.parse_bridge_metrics(stdout)

        return {
            "command": cmd,
            "headless_binary": str(headless_bin),
            "exit_code": effective_exit,
            "raw_returncode": returncode,
            "is_timeout": timed_out,
            "timeout_seconds": timeout_sec,
            "script_error_detected": has_script_error,
            "is_error": effective_exit != 0,
            "project_name": proj_name,
            "project_dir": proj_dir,
            "project_cleaned": project_cleaned,
            "stdout": stdout,
            "stderr": stderr,
            "epistemic_classification": "GHIDRA_HEADLESS_BATCH_EXECUTION",
            **metrics,
        }
