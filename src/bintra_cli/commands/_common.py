"""Shared helpers for CLI handlers: argv normalisation and write-path guarding."""
from typing import List, Optional, Sequence


def rename_flag(argv: List[str], aliases: Sequence[str], canonical: str) -> None:
    """Rewrites the first present alias of `canonical` in-place (no-op if `canonical` is present)."""
    for alt in aliases:
        if alt in argv and canonical not in argv:
            argv[argv.index(alt)] = canonical


def flag_value(argv: Sequence[str], flag: str) -> Optional[str]:
    """Value following `flag`, or None when the flag (or its value) is absent."""
    if flag in argv:
        idx = list(argv).index(flag)
        if idx + 1 < len(argv):
            return argv[idx + 1]
    return None


def guard_output_path(source: Optional[str], output: str, operation: str, in_place_message: str) -> None:
    """
    Enforces the write policy for CLI commands that produce a file:
      - never the source file itself (TARGET_WRITE_FORBIDDEN),
      - never inside an analysis target's directory tree,
      - always inside the authorised workspace,
    and records the mediated WORKSPACE_WRITE decision.
    """
    from security import Capability, ExecutionGuard, OutOfScopeError, PathIdentity, TargetMutationError

    if source and PathIdentity.is_same_file(source, output):
        raise TargetMutationError(in_place_message)
    scope = ExecutionGuard.get_current_scope()
    if scope and scope.is_target_directory(output):
        raise TargetMutationError(scope.target_directory_violation_message(output))
    if not scope.is_inside_workspace(output):
        raise OutOfScopeError(
            f"WRITE_OUTSIDE_WORKSPACE: Output path '{output}' is outside authorized workspace '{scope.workspace_dir}'."
        )
    ExecutionGuard.request_access(
        component="cli",
        operation=operation,
        target=output,
        capability=Capability.WORKSPACE_WRITE,
        access_mode="WRITE",
    )
