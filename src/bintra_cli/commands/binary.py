"""Bintra CLI commands: PE inspection, deobfuscation, matching, patching and the 10-sense audit."""
import argparse
import json
import os
import sys

import binary_neural_engine
from binary_neural_engine import SensoryCortex



def cmd_sense(cmd: str) -> None:
    """bintra sense, sensory-audit"""
    parser = argparse.ArgumentParser(description="Bintra 10-Sense Diagnostic Audit")
    parser.add_argument("command", help="sense or sensory-audit")
    parser.add_argument("--file", "--binary", "--input", dest="file", default=None, help="Optional path to PE executable or .safetensors model")
    parser.add_argument("--hex", default=None, help="Optional hex string of machine code")
    args = parser.parse_args()
    report = SensoryCortex.evaluate_all_senses(file_path=args.file, code_hex=args.hex)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_patch_binary(cmd: str) -> None:
    """bintra patch-binary"""
    sys.argv[1] = "patch"
    # Normalize --file / --binary / --input to --source
    for alt in ("--file", "--binary", "--input"):
        if alt in sys.argv and "--source" not in sys.argv:
            idx = sys.argv.index(alt)
            sys.argv[idx] = "--source"
    # Guard: in-place source modification is strictly forbidden
    if "--source" in sys.argv and "--output" not in sys.argv:
        s_idx = sys.argv.index("--source")
        if s_idx + 1 < len(sys.argv):
            src_file = sys.argv[s_idx + 1]
            from security import ExecutionGuard
            scope = ExecutionGuard.get_current_scope()
            safe_out = os.path.join(scope.workspace_dir, "patched_" + os.path.basename(src_file))
            sys.argv.extend(["--output", safe_out])
    elif "--source" in sys.argv and "--output" in sys.argv:
        s_idx = sys.argv.index("--source")
        o_idx = sys.argv.index("--output")
        if s_idx + 1 < len(sys.argv) and o_idx + 1 < len(sys.argv):
            from security import PathIdentity, ExecutionGuard, TargetMutationError, OutOfScopeError, Capability
            src_f = sys.argv[s_idx + 1]
            out_f = sys.argv[o_idx + 1]
            if PathIdentity.is_same_file(src_f, out_f):
                raise TargetMutationError(
                    "TARGET_WRITE_FORBIDDEN: Direct in-place modification of target binaries is strictly forbidden by Bintra Safety Policy. Specify a distinct --output file in the workspace."
                )
            scope = ExecutionGuard.get_current_scope()
            if scope and scope.is_target_directory(out_f):
                raise TargetMutationError(
                    scope.target_directory_violation_message(out_f)
                )
            if not scope.is_inside_workspace(out_f):
                raise OutOfScopeError(
                    f"WRITE_OUTSIDE_WORKSPACE: Output path '{out_f}' is outside authorized workspace '{scope.workspace_dir}'."
                )
            ExecutionGuard.request_access(
                component="cli",
                operation="patch-binary",
                target=out_f,
                capability=Capability.WORKSPACE_WRITE,
                access_mode="WRITE"
            )
    # Normalize --patch to --patch-hex
    if "--patch" in sys.argv and "--patch-hex" not in sys.argv:
        p_idx = sys.argv.index("--patch")
        sys.argv[p_idx] = "--patch-hex"
    binary_neural_engine.main()


def cmd_match_functions(cmd: str) -> None:
    """bintra match-functions"""
    sys.argv[1] = "match"
    binary_neural_engine.main()


def cmd_deobfuscate(cmd: str) -> None:
    """bintra deobfuscate, dump, inspect, match, scan-hybrid"""
    # Normalize -f / --binary / -b / --input to --file for inspect, scan-hybrid, etc.
    for alt in ("-f", "--binary", "-b", "--input"):
        if alt in sys.argv and "--file" not in sys.argv:
            idx = sys.argv.index(alt)
            sys.argv[idx] = "--file"
    # Support positional argument: bintra inspect <file>
    if "--file" not in sys.argv and len(sys.argv) == 3:
        if not sys.argv[2].startswith("-"):
            sys.argv.insert(2, "--file")
    binary_neural_engine.main()

