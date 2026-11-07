#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Assessment Patch (Windows-Native Compatible).

Applies the fixes that follow from the REA-Neural evaluation (see EVALUATION.md),
in the same self-contained, single-script style as the project's own
`tools/rea_neural_patch.py` -- but using SURGICAL, IDEMPOTENT, DEFENSIVE edits
instead of re-embedding whole multi-thousand-line files.

Design principles (match the project's identity, do not hide failures):
  * Every edit is guarded: if the exact anchor text is not found, the file is
    LEFT UNTOUCHED and the action is reported as "skipped (anchor not found)".
  * Every edit is idempotent: re-running reports "already-applied" and changes nothing.
  * No capability is deleted. Scope-drift items (WSP model authoring) are FENCED and
    DOCUMENTED, never removed -- preserving lineage and honesty.
  * Windows-first: UTF-8 console, LF newlines preserved, atomic-ish writes.

What it changes (keyed to EVALUATION.md findings):
  F1  Ghidra honesty: README + planner docstring say "plan generation only, no transport";
      adds references/ghidra-bridge-status.md.
  F2  SKILL.md honest fork note: this fork ships no MCP server / 234 tools / rea-agents npm.
  F3  WSP scope drift: adds SCOPE.md and a stderr SCOPE WARNING on `synthesize-weights`.
  F4  Sensory honesty: adds `score_semantics` note clarifying efficiency scores are static.
  F5  Correctness: tightens ARM64 detection so stray `5f d6` bytes in x86 aren't misread.
  F6  Metadata: unifies version (-> 7.3.0) and author across pyproject/package.json.
  F7  Schema honesty: inspect_weight_subspace.json stops claiming GGUF / Evidence records.

Usage on Windows / cross-platform:
    python rea_neural_assessment_patch.py --target ".\\rea-neural" --backup --verify
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Tuple


def configure_windows_utf8() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# ============================================================================
# New file payloads
# ============================================================================

SCOPE_MD = """# REA-Neural -- Declared Scope & Boundaries

This document draws an explicit line so the project is not pulled toward the original
agenda of *"Sparks of Weight-Space Programming"* (modifying standalone AI models).

## In scope (what REA-Neural IS)
A reverse-engineering & security framework for **Windows compiled software**
(`.exe`, `.dll`, PE32/PE32+). Where a Windows binary **embeds** neural weights
(ONNX / TFLite / GGUF / Safetensors / DirectML / WinML), REA-Neural may:
- **Read / audit** those embedded weights WITHOUT executing the host binary
  (effective rank, backdoor/trojan spikes, induction structure, amenability verdict,
  SVD subspace inspection).
- **Neutralize** a specific malicious/pathological direction found inside an embedded
  model as part of securing or understanding that binary.

These are legitimate reverse-engineering operations on a shipped artifact.

## Out of scope (what REA-Neural is NOT)
REA-Neural does **not** pursue the WSP paper's own research goals of **improving,
training, merging, or synthesizing standalone AI models**. The following modules are
retained ONLY as archived historical/experimental lineage. They are **not** part of the
supported reverse-engineering surface and must not be presented as product capabilities:

- `WeightSpaceCompiler` (builds a network from scratch; exposed as CLI `synthesize-weights`)
- `CircuitGrafter.transplant_reasoning_subspace` (model merging across shapes)
- `CircuitGrafter.graft_conditional_subcircuit` (grafting new circuits into a model)
- `ForwardPassHarness.run_budgeted_optimization` (training-like weight optimization)

Running `synthesize-weights` emits a scope warning for this reason.

## Why
Respecting the project's identity means keeping its reverse-engineering mission sharp.
Auditing an embedded model to secure a binary is reverse engineering. Building, merging,
or optimizing a standalone model is not -- it is the paper's agenda, and it is out of scope.
"""

GHIDRA_BRIDGE_STATUS_MD = """# Ghidra Integration -- Honest Status

Short version: REA-Neural currently ships a **P-code vectorizer/matcher** and an
**annotation-plan generator**, not a live Ghidra bridge.

## What exists today (`src/ghidra_pcode_vectorizer.py`)
- `PcodeVectorizer` / `PcodeFunctionMatcher` -- real: vectorize a list of P-code ops into a
  64-D unit vector and match two routines by cosine similarity.
- `PcodeDeobfuscator` -- real: detect algebraic opaque predicates in a P-code op list.
- `GhidraAnnotationPlanner` -- builds JSON-RPC **plan dicts** (`set_address_name`,
  `annotate_native_function`, C-struct text). It returns dicts; it does nothing else.

## What does NOT exist yet (despite earlier README wording)
- **No transport.** There is no socket, no TCP client, no "authenticated loopback TCP",
  and no "database lock removal". Nothing connects to Ghidra.
- **No extraction.** There is no script that pulls P-code out of Ghidra. The JSON input to
  `match-pcode` / `deobfuscate-pcode` must currently be produced by hand or by an external tool.
- **Version.** "Ghidra 12.1.4" is an unverified target string.

## What a real integration would need (future work, not in this patch)
A `ghidra_scripts/` directory with a Headless/PyGhidra script that (a) exports High P-code to the
JSON shape these classes expect, and (b) applies the generated annotation plans back into the
Program Database. Only then is "bidirectional integration" an accurate description.
"""


# ============================================================================
# Surgical, idempotent, guarded edits
# ============================================================================

class EditResult:
    def __init__(self, path: str, label: str, status: str):
        self.path = path
        self.label = label
        self.status = status  # applied | already-applied | skipped (anchor not found) | skipped (file missing)

    def as_dict(self) -> Dict[str, str]:
        return {"file": self.path, "edit": self.label, "status": self.status}


# Each edit: (relative_path, label, old_text, new_text, already_marker)
#   already_marker: a substring whose presence means the edit is already applied.
EDITS: List[Tuple[str, str, str, str, str]] = [

    # ---- F5: tighten ARM64 detection -------------------------------------------------
    (
        "src/binary_neural_engine.py",
        "F5 ARM64 detection tightened (ignore stray 5f d6 in x86)",
        "            and (raw_bytes.endswith(b\"\\xc0\\x03\\x5f\\xd6\") or b\"\\x5f\\xd6\" in raw_bytes)\n",
        "            and raw_bytes.endswith(b\"\\xc0\\x03\\x5f\\xd6\")  # patched: require AArch64 RET terminator\n",
        "patched: require AArch64 RET terminator",
    ),

    # ---- F4: sensory score semantics note --------------------------------------------
    (
        "src/binary_neural_engine.py",
        "F4 add score_semantics disclosure to sensory report",
        '            "overall_sensory_efficiency": round(float(np.mean(scores)), 4),\n            "senses": senses_output,\n',
        '            "overall_sensory_efficiency": round(float(np.mean(scores)), 4),\n'
        '            "score_semantics": (\n'
        '                "efficiency_score/overall_sensory_efficiency are STATIC capability-presence "\n'
        '                "indicators (fixed per sense), NOT measured accuracy. Read each sense\'s "\n'
        '                "\'telemetry\' for the real computed values."\n'
        '            ),\n'
        '            "senses": senses_output,\n',
        "score_semantics",
    ),

    # ---- F3: scope warning on synthesize-weights -------------------------------------
    (
        "src/rea_neural_engine.py",
        "F3 scope warning on synthesize-weights (WSP model authoring)",
        '    elif args.command == "synthesize-weights":\n        tensors = WeightSpaceCompiler.compile_breakout_policy_network()\n',
        '    elif args.command == "synthesize-weights":\n'
        '        sys.stderr.write(\n'
        '            "[REA-Neural SCOPE WARNING] \'synthesize-weights\' BUILDS a neural network from "\n'
        '            "scratch. This is out of REA-Neural\'s reverse-engineering scope (it creates a "\n'
        '            "standalone AI model, the WSP paper\'s own agenda) and is kept only as archived "\n'
        '            "lineage. See SCOPE.md. It reverse-engineers no Windows binary.\\n"\n'
        '        )\n'
        '        tensors = WeightSpaceCompiler.compile_breakout_policy_network()\n',
        "SCOPE WARNING",
    ),

    # ---- F1: Ghidra planner docstring honesty ----------------------------------------
    (
        "src/ghidra_pcode_vectorizer.py",
        "F1 GhidraAnnotationPlanner transport-status disclosure",
        '    Constructs type-safe JSON-RPC payloads for mutating Ghidra\'s Program Database\n'
        '    (set_address_name, annotate_native_function, set_comment) on Windows.\n'
        '    """',
        '    Constructs type-safe JSON-RPC payloads for mutating Ghidra\'s Program Database\n'
        '    (set_address_name, annotate_native_function, set_comment) on Windows.\n\n'
        '    TRANSPORT STATUS (honest disclosure): this class only GENERATES plan dicts. It opens\n'
        '    NO socket/TCP connection, ships NO Ghidra-side script, and applies NOTHING by itself.\n'
        '    Executing a plan requires an external Ghidra Headless/PyGhidra script. See\n'
        '    references/ghidra-bridge-status.md.\n'
        '    """',
        "TRANSPORT STATUS",
    ),

    # ---- F1: README Ghidra intro softening -------------------------------------------
    (
        "README.md",
        "F1 README Ghidra intro -> plan-generation-only honesty",
        "Rather than treating Ghidra as a detached external decompiler, `REA-Neural` establishes a bidirectional pipeline with Ghidra 12.1.4:",
        "Rather than treating Ghidra as a detached external decompiler, `REA-Neural` is designed to feed and "
        "complement Ghidra. Current status: the repository ships the P-code vectorizer/matcher and an annotation "
        "**plan generator** only; it does **not** yet include a live transport/bridge to Ghidra "
        "(see `skills/reverse-engineer-anything/references/ghidra-bridge-status.md`). Target Ghidra version: 12.1.x (unverified).",
        "plan generator** only",
    ),

    # ---- F1: README "unlocked mutation / loopback TCP" softening ----------------------
    (
        "README.md",
        "F1 README remove 'loopback TCP / unlocked' overstatement",
        "- **Unlocked Windows Database Mutation:** Removes legacy read-only locks, permitting automated function "
        "renaming (`set_address_name`), prototype injection (`annotate_native_function`), and C-structure type "
        "synthesis on Windows via authenticated loopback TCP.",
        "- **Windows Database Mutation (plan generation):** Generates JSON-RPC **plans** for function renaming "
        "(`set_address_name`), prototype injection (`annotate_native_function`), and C-structure type synthesis. "
        "Applying a plan requires an external Ghidra-side script; REA-Neural does not open a TCP connection itself.",
        "Windows Database Mutation (plan generation)",
    ),

    # ---- F2: SKILL.md honest fork note -----------------------------------------------
    (
        "skills/reverse-engineer-anything/SKILL.md",
        "F2 SKILL.md honest fork note (no MCP server / 234 tools / rea-agents here)",
        "# REA\n\nUse REA when a claim depends on a shipped binary or package, decompilation,",
        "# REA\n\n"
        "> **REA-Neural fork note (honest scope):** this repository does **not** ship the upstream REA\n"
        "> MCP server, the `rea-agents` npm package, the `open_binary` tool, or the ~234 MCP tools referenced\n"
        "> below (those describe upstream REA). In this fork the **only** runnable surface is the\n"
        "> `python src/cli.py ...` commands. Treat MCP / `rea` / `npx rea-agents` instructions below as upstream\n"
        "> context, not capabilities present here.\n\n"
        "Use REA when a claim depends on a shipped binary or package, decompilation,",
        "fork note (honest scope)",
    ),

    # ---- F6: pyproject version unify -------------------------------------------------
    (
        "pyproject.toml",
        "F6 pyproject version -> 7.3.0 (match newest released feat in git history)",
        'version = "7.1.0"',
        'version = "7.3.0"',
        'version = "7.3.0"',
    ),

    # ---- F6: package.json version + author unify -------------------------------------
    (
        "package.json",
        "F6 package.json version -> 7.3.0",
        '"version": "7.0.0-neural.1",',
        '"version": "7.3.0",',
        '"version": "7.3.0",',
    ),
    (
        "package.json",
        "F6 package.json author -> bio-colab (match pyproject)",
        '"author": "Antigravity Research & REA Contributors",',
        '"author": "bio-colab",',
        '"author": "bio-colab",',
    ),

    # ---- F7: schema honesty (no GGUF / no Evidence record) ---------------------------
    (
        "schemas/inspect_weight_subspace.json",
        "F7 schema description: drop unimplemented GGUF + Evidence-record claims",
        "coordinate extreme blocks of a specific tensor within a safetensors or GGUF file using memory mapping. "
        "Never loads full model into memory. Returns compact singular values, directional vectors, and an "
        "authenticated Evidence record.",
        "coordinate extreme blocks of a specific tensor within a safetensors file using memory mapping. "
        "Never loads full model into memory. Returns compact singular values and directional vectors. "
        "(Note: GGUF input and Evidence records are not implemented in this repository.)",
        "not implemented in this repository",
    ),
    (
        "schemas/inspect_weight_subspace.json",
        "F7 schema path description: safetensors only",
        '"description": "Absolute filesystem path to the local .safetensors or .gguf model file."',
        '"description": "Absolute filesystem path to the local .safetensors model file."',
        'to the local .safetensors model file."',
    ),
]


# New files: (relative_path, content). Created only if absent (never overwrites).
NEW_FILES: List[Tuple[str, str]] = [
    ("SCOPE.md", SCOPE_MD),
    ("skills/reverse-engineer-anything/references/ghidra-bridge-status.md", GHIDRA_BRIDGE_STATUS_MD),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write(path: Path, text: str) -> None:
    # Preserve LF line endings explicitly for cross-platform consistency.
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def apply_one_edit(root: Path, rel: str, label: str, old: str, new: str, marker: str) -> EditResult:
    path = root / rel
    if not path.exists():
        return EditResult(rel, label, "skipped (file missing)")
    text = _read(path)
    if old in text:
        _write(path, text.replace(old, new, 1))
        return EditResult(rel, label, "applied")
    if marker and marker in text:
        return EditResult(rel, label, "already-applied")
    return EditResult(rel, label, "skipped (anchor not found)")


def create_new_files(root: Path) -> List[EditResult]:
    results: List[EditResult] = []
    for rel, content in NEW_FILES:
        path = root / rel
        if path.exists():
            results.append(EditResult(rel, "new file", "already-exists (left untouched)"))
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        _write(path, content)
        results.append(EditResult(rel, "new file", "created"))
    return results


def apply_all(target_dir: str, create_backup: bool) -> Dict[str, Any]:
    root = Path(target_dir).resolve()
    if not (root / "src").exists():
        raise FileNotFoundError(f"Target '{root}' does not look like a rea-neural checkout (no 'src/').")

    if create_backup:
        backup_dir = root.parent / f"{root.name}_backup"
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        shutil.copytree(root, backup_dir)

    results: List[EditResult] = []
    results.extend(create_new_files(root))
    for rel, label, old, new, marker in EDITS:
        results.append(apply_one_edit(root, rel, label, old, new, marker))

    counts: Dict[str, int] = {}
    for r in results:
        key = r.status.split(" (")[0]
        counts[key] = counts.get(key, 0) + 1

    return {
        "target_root": str(root),
        "backup_created": create_backup,
        "actions": [r.as_dict() for r in results],
        "summary_counts": counts,
    }


def run_verification(target_dir: str) -> Dict[str, Any]:
    """Runs the project's own test suite + a CLI smoke test. Reports the truth, including failures."""
    root = Path(target_dir).resolve()
    test_proc = subprocess.run(
        [sys.executable, "tests/test_suite.py"],
        cwd=str(root), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    sense_proc = subprocess.run(
        [sys.executable, str(root / "src" / "cli.py"), "sense", "--hex",
         "55 48 89 e5 48 31 c0 74 05 b8 55 00 00 00 5d c3"],
        cwd=str(root), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    sense_ok = False
    sense_detail: Any = sense_proc.stderr.strip()
    if sense_proc.returncode == 0:
        try:
            sense_detail = json.loads(sense_proc.stdout).get("active_senses_count")
            sense_ok = (sense_detail == 10)
        except Exception as exc:  # pragma: no cover - defensive
            sense_detail = f"json parse error: {exc}"
    return {
        "tests_passed": test_proc.returncode == 0,
        "test_returncode": test_proc.returncode,
        "test_output_tail": (test_proc.stdout + "\n" + test_proc.stderr).strip()[-4000:],
        "sense_smoke_passed": sense_ok,
        "sense_active_senses_count": sense_detail,
    }


def main() -> None:
    configure_windows_utf8()
    parser = argparse.ArgumentParser(
        description="Apply the REA-Neural assessment fixes (surgical, idempotent, reversible)."
    )
    parser.add_argument("--target", default=".",
                        help="Path to the rea-neural checkout (default: current directory).")
    parser.add_argument("--backup", action="store_true",
                        help="Copy the project to '<name>_backup' before editing.")
    parser.add_argument("--verify", action="store_true",
                        help="Run tests/test_suite.py and a CLI smoke test after patching.")
    args = parser.parse_args()

    summary = apply_all(args.target, create_backup=args.backup)
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    skipped_anchor = [a for a in summary["actions"] if a["status"].startswith("skipped (anchor")]
    if skipped_anchor:
        print("\n[NOTE] Some anchors were not found (upstream text may have changed). "
              "Those files were left UNTOUCHED -- nothing was corrupted:", file=sys.stderr)
        for a in skipped_anchor:
            print(f"  - {a['file']}: {a['edit']}", file=sys.stderr)

    exit_code = 0
    if args.verify:
        ver = run_verification(args.target)
        print("\n=== VERIFICATION ===")
        print(json.dumps(
            {k: v for k, v in ver.items() if k != "test_output_tail"},
            indent=2, ensure_ascii=False))
        print("\n--- test output (tail) ---")
        print(ver["test_output_tail"])
        if not ver["tests_passed"] or not ver["sense_smoke_passed"]:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
