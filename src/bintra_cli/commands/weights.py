"""Bintra CLI commands: Safetensors weight-space commands (audit, patch, diff, decompile) and archived lineage."""
import json
import sys

import bintra_engine



def cmd_synthesize_weights(cmd: str) -> None:
    """bintra synthesize-weights"""
    scope_msg = {
        "status": "decoupled_from_active_scope",
        "command": cmd,
        "message": (
            "Command 'synthesize-weights' has been decoupled from Bintra's active reverse-engineering interface. "
            "Per SCOPE.md, Bintra focuses on continuous semantic reverse engineering, decompilation, "
            "and embedded neural tensor auditing. Standalone neural model synthesis is preserved only as historical lineage."
        ),
        "reference": "SCOPE.md"
    }
    if "--archived-lineage" in sys.argv:
        print(f"[SCOPE WARNING] Running {cmd} under historical research lineage (--archived-lineage).")
        bintra_engine.main()
        return
    else:
        scope_msg["hint"] = "To invoke for paper reproduction, provide flag: --archived-lineage"
        print(json.dumps(scope_msg, indent=2))
        sys.exit(0)


def cmd_patch_weights(cmd: str) -> None:
    """bintra patch-weights"""
    sys.argv[1] = "patch"
    if "--source" in sys.argv and "--output" in sys.argv:
        s_idx = sys.argv.index("--source")
        o_idx = sys.argv.index("--output")
        if s_idx + 1 < len(sys.argv) and o_idx + 1 < len(sys.argv):
            from security import PathIdentity, ExecutionGuard, TargetMutationError, OutOfScopeError, Capability
            src_f = sys.argv[s_idx + 1]
            out_f = sys.argv[o_idx + 1]
            if PathIdentity.is_same_file(src_f, out_f):
                raise TargetMutationError(
                    "TARGET_WRITE_FORBIDDEN: Direct in-place modification of model weights is strictly forbidden by Bintra Safety Policy. Specify a distinct --output file in the workspace."
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
                operation="patch-weights",
                target=out_f,
                capability=Capability.WORKSPACE_WRITE,
                access_mode="WRITE"
            )
    for alt in ("--file", "--input", "--binary"):
        if alt in sys.argv and "--model" not in sys.argv:
            idx = sys.argv.index(alt)
            sys.argv[idx] = "--model"

    bintra_engine.main()


def cmd_decompile_circuit(cmd: str) -> None:
    """bintra decompile-circuit"""
    sys.argv[1] = "decompile"
    for alt in ("--file", "--input", "--binary"):
        if alt in sys.argv and "--model" not in sys.argv:
            idx = sys.argv.index(alt)
            sys.argv[idx] = "--model"

    bintra_engine.main()


def cmd_diff_weights(cmd: str) -> None:
    """bintra diff-weights"""
    sys.argv[1] = "diff"
    for alt in ("--file", "--input", "--binary"):
        if alt in sys.argv and "--model" not in sys.argv:
            idx = sys.argv.index(alt)
            sys.argv[idx] = "--model"

    bintra_engine.main()


def cmd_decompile(cmd: str) -> None:
    """bintra decompile, diff, probe-trace, subspace, verify-behavior, wsp-audit"""
    for alt in ("--file", "--input", "--binary"):
        if alt in sys.argv and "--model" not in sys.argv:
            idx = sys.argv.index(alt)
            sys.argv[idx] = "--model"

    bintra_engine.main()

