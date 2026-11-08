#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural HEAD Assessment Patch (Windows-Native Compatible).

Applies the fixes that follow from the HEAD evaluation (see EVALUATION_HEAD_b49b17f.md),
in the same self-contained, single-script style as the project's own
`tools/rea_neural_patch.py` -- but using SURGICAL, IDEMPOTENT, DEFENSIVE edits
instead of re-embedding whole multi-thousand-line files.
"""

import os
import re
import sys
import time
import shutil
import argparse
import subprocess
from typing import List, Tuple, Optional


def configure_windows_utf8() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _read(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"    [io-error] could not read {path}: {e}")
        return None


def _write(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(content)


class Edit:
    def __init__(
        self,
        edit_id: str,
        rel_path: str,
        anchor: str,
        replacement: str,
        already_marker: str,
        description: str,
    ):
        self.edit_id = edit_id
        self.rel_path = rel_path
        self.anchor = anchor
        self.replacement = replacement
        self.already_marker = already_marker
        self.description = description

    def apply(self, target_root: str) -> Tuple[str, str]:
        """Returns (status, detail). status in {applied, already-applied, skipped}."""
        path = os.path.join(target_root, self.rel_path.replace("/", os.sep))
        content = _read(path)
        if content is None:
            return ("skipped", f"file not found: {self.rel_path}")

        if self.already_marker and self.already_marker in content:
            return ("already-applied", self.rel_path)

        # Normalize CRLF/LF for matching anchor
        norm_content = content.replace("\r\n", "\n")
        norm_anchor = self.anchor.replace("\r\n", "\n")

        if norm_anchor not in norm_content:
            return ("skipped", f"anchor not found in {self.rel_path}")

        occurrences = norm_content.count(norm_anchor)
        if occurrences != 1:
            return ("skipped", f"anchor is ambiguous ({occurrences}x) in {self.rel_path}")

        # If content has CRLF, convert replacement newlines to CRLF
        if "\r\n" in content:
            replacement_to_use = self.replacement.replace("\r\n", "\n").replace("\n", "\r\n")
            anchor_to_use = self.anchor.replace("\r\n", "\n").replace("\n", "\r\n")
        else:
            replacement_to_use = self.replacement.replace("\r\n", "\n")
            anchor_to_use = norm_anchor

        new_content = content.replace(anchor_to_use, replacement_to_use, 1)
        if new_content == content:
            return ("already-applied", self.rel_path)

        _write(path, new_content)
        return ("applied", self.rel_path)


def build_edits() -> List[Edit]:
    edits: List[Edit] = []

    # --- H1: Ghidra documentation honesty ---------------------------------
    h1_anchor = (
        "REA-Neural establishes a verified, bidirectional, closed-loop integration with "
        "**Ghidra 12.1.x / 11.x**.\n"
        "Rather than treating Ghidra as a detached decompiler or requiring manual JSON "
        "preparation, REA-Neural provides native in-engine Ghidra scripts (`ghidra_scripts/`) "
        "and automated CLI pipelines that execute the complete 6-step symbiotic reverse "
        "engineering cycle."
    )
    h1_replacement = (
        "REA-Neural provides **file-exchange + headless orchestration** integration with "
        "Ghidra (target 12.1.x / 11.x, **unverified**).\n"
        "> **Honest status (aligned with `README.md`):** there is **no live TCP/socket bridge** "
        "to a running Ghidra instance. What ships is: (a) in-engine scripts "
        "(`ghidra_scripts/ReaNeuralGhidraBridge.java`, `rea_extract_pcode.py`), (b) a headless "
        "orchestrator (`cli.py ghidra-headless`) that launches `analyzeHeadless.bat` with the "
        "bridge as a `-postScript`, and (c) a P-code vectorizer/matcher plus an annotation "
        "**plan generator** (`cli.py ghidra-analyze`) that consumes exported JSON. The 6-step "
        "cycle below is the DESIGN; the loop is only truly closed once `rea_extract_pcode.py` "
        "exports live P-code into `ghidra-analyze` automatically."
    )
    edits.append(Edit(
        "H1", "skills/reverse-engineer-anything/references/ghidra-bridge-status.md",
        h1_anchor, h1_replacement,
        already_marker="Honest status (aligned with `README.md`)",
        description="Align Ghidra status doc with README's honest 'no live bridge' wording.",
    ))

    # --- H2: SKILL.md drift ------------------------------------------------
    edits.append(Edit(
        "H2a", "skills/reverse-engineer-anything/SKILL.md",
        'metadata:\n  version: "7.3.0"\n  tool_count: 13',
        'metadata:\n  version: "7.4.0"\n  tool_count: 25',
        already_marker='version: "7.4.0"\n  tool_count: 25',
        description="Unify SKILL.md version to 7.4.0 and tool_count to the real 25.",
    ))
    edits.append(Edit(
        "H2b", "skills/reverse-engineer-anything/SKILL.md",
        "> **REA-Neural Agent-Native Architecture (v7.3.0):**  ",
        (
            "> **Fork honesty note:** this Windows-native fork ships a **25-tool Python MCP "
            "server** (`src/mcp_server.py`) + the Unified CLI. References below to the `rea-agents` "
            "npm package, `analyze-javascript-application`, Android, or Hopper are **inherited "
            "from upstream REA and are NOT shipped here**; use `python src/cli.py <command>` or the "
            "`rea_*` MCP tools instead.\n"
            ">\n"
            "> **REA-Neural Agent-Native Architecture (v7.4.0):**  "
        ),
        already_marker="Fork honesty note:",
        description="Insert honest fork banner clarifying upstream-only surface; bump header to 7.4.0.",
    ))

    # --- H3: hardcoded developer Ghidra path ------------------------------
    edits.append(Edit(
        "H3", "src/cli.py",
        'default=os.environ.get("GHIDRA_INSTALL_DIR", r"C:\\Users\\Eylias\\tools\\ghidra")',
        'default=os.environ.get("GHIDRA_INSTALL_DIR", r"C:\\ghidra")',
        already_marker='os.environ.get("GHIDRA_INSTALL_DIR", r"C:\\ghidra")',
        description="Replace leaked developer path with a neutral default (env still wins).",
    ))

    # --- H4: PowerShell ConvertTo-Json depth ------------------------------
    edits.append(Edit(
        "H4", "src/windows_intelligence/command_engine/powershell_executor.py",
        'command_str = f"{cmdlet} | ConvertTo-Json -Compress"',
        'command_str = f"{cmdlet} | ConvertTo-Json -Depth 4 -Compress"',
        already_marker="ConvertTo-Json -Depth 4 -Compress",
        description="Add -Depth 4 so nested CIM objects are not truncated at default depth 2.",
    ))

    # --- H5: sensory synthetic-sample disclosure --------------------------
    edits.append(Edit(
        "H5", "src/binary_neural_engine.py",
        "\"'telemetry' for the real computed values.\"",
        (
            "\"'telemetry' for the real computed values. When no --file/--hex input is \"\n"
            "                \"supplied, a FIXED synthetic code sample is analyzed, so senses still \"\n"
            "                \"report activity without a real target.\""
        ),
        already_marker="a FIXED synthetic code sample is analyzed",
        description="Extend score_semantics to disclose the synthetic default sample.",
    ))

    return edits


def make_backup(target_root: str) -> Optional[str]:
    parent = os.path.dirname(os.path.abspath(target_root.rstrip(os.sep)))
    base = os.path.basename(os.path.abspath(target_root.rstrip(os.sep)))
    dest = os.path.join(parent, f"{base}_backup_{time.strftime('%Y%m%d_%H%M%S')}")
    try:
        shutil.copytree(target_root, dest, ignore=shutil.ignore_patterns(".git"))
        return dest
    except Exception as e:
        print(f"[backup] FAILED: {e}")
        return None


def run_verify(target_root: str) -> int:
    test_file = os.path.join(target_root, "tests", "test_suite.py")
    if not os.path.isfile(test_file):
        print("[verify] tests/test_suite.py not found; skipping.")
        return 0
    src_dir = os.path.join(target_root, "src")
    print("\n[verify] Running tests/test_suite.py (honest output, failures included):")
    print("-" * 72)
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    try:
        proc = subprocess.run(
            [sys.executable, test_file],
            cwd=target_root, env=env, timeout=600
        )
        return proc.returncode
    except subprocess.TimeoutExpired:
        print("[verify] test run TIMED OUT after 600s.")
        return 1
    except Exception as e:
        print(f"[verify] test run FAILED to start: {e}")
        return 1


def main() -> None:
    configure_windows_utf8()
    ap = argparse.ArgumentParser(description="REA-Neural HEAD assessment patch (surgical, idempotent).")
    ap.add_argument("--target", required=True, help="Path to the extracted rea-neural repo root.")
    ap.add_argument("--backup", action="store_true", help="Create a timestamped backup before editing.")
    ap.add_argument("--verify", action="store_true", help="Run tests/test_suite.py after patching.")
    ap.add_argument("--dry-run", action="store_true", help="Report what would change without writing.")
    args = ap.parse_args()

    target_root = args.target
    if not os.path.isdir(target_root):
        print(f"[error] target directory does not exist: {target_root}")
        sys.exit(2)
    if not os.path.isfile(os.path.join(target_root, "README.md")):
        print(f"[warn] {target_root} does not look like the rea-neural root (no README.md).")

    print(f"REA-Neural HEAD Assessment Patch")
    print(f"target : {os.path.abspath(target_root)}")
    print(f"mode   : {'DRY-RUN' if args.dry_run else 'APPLY'}")
    print("=" * 72)

    if args.backup and not args.dry_run:
        dest = make_backup(target_root)
        if dest:
            print(f"[backup] created: {dest}")
        print("-" * 72)

    edits = build_edits()
    counts = {"applied": 0, "already-applied": 0, "skipped": 0}

    for e in edits:
        if args.dry_run:
            path = os.path.join(target_root, e.rel_path.replace("/", os.sep))
            content = _read(path)
            if content is None:
                status = "skipped (file not found)"
            elif e.already_marker and e.already_marker in content:
                status = "already-applied"
            else:
                norm_c = content.replace("\r\n", "\n")
                norm_a = e.anchor.replace("\r\n", "\n")
                if norm_a in norm_c and norm_c.count(norm_a) == 1:
                    status = "would-apply"
                elif norm_a in norm_c:
                    status = "skipped (ambiguous anchor)"
                else:
                    status = "skipped (anchor not found)"
            print(f"[{e.edit_id:<4}] {status:<28} {e.rel_path}")
            print(f"        -> {e.description}")
            continue

        status, detail = e.apply(target_root)
        counts[status] = counts.get(status, 0) + 1
        print(f"[{e.edit_id:<4}] {status:<16} {detail}")
        print(f"        -> {e.description}")

    print("=" * 72)
    if not args.dry_run:
        print(f"summary: applied={counts.get('applied',0)}  "
              f"already-applied={counts.get('already-applied',0)}  "
              f"skipped={counts.get('skipped',0)}")

    rc = 0
    if args.verify and not args.dry_run:
        rc = run_verify(target_root)
        print("-" * 72)
        print(f"[verify] test suite exit code: {rc} "
              f"({'OK' if rc == 0 else 'FAILURES / errors — shown above, not hidden'})")

    sys.exit(rc)


if __name__ == "__main__":
    main()
