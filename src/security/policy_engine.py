# -*- coding: utf-8 -*-
"""
Bintra Policy Engine.
Evaluates system access requests against the Inviolable Safety Rules,
CapabilityRegistry grants, and Default Deny matrix.
Enforces read target scope boundaries and workspace write confinement.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from .capability_registry import PROHIBITED_HAZARDS, Capability, CapabilityRegistry
from .config import FORBIDDEN_CREDENTIAL_MARKERS, default_ghidra_bridge_marker_path
from .path_identity import PathIdentity
from .target_scope import TargetScope

_READ_CAPABILITIES: FrozenSet[Capability] = frozenset({
    Capability.FILE_READ,
    Capability.FILE_HASH,
    Capability.REGISTRY_READ,
    Capability.PROCESS_QUERY,
    Capability.SERVICE_QUERY,
    Capability.DEVICE_QUERY,
    Capability.DRIVER_QUERY,
    Capability.EVENT_LOG_READ,
    Capability.MINIDUMP_READ,
})

_FILESYSTEM_READ_CAPABILITIES: FrozenSet[Capability] = frozenset({
    Capability.FILE_READ,
    Capability.FILE_HASH,
    Capability.MINIDUMP_READ,
})

_MUTATING_OR_EXEC_CAPABILITIES: FrozenSet[Capability] = frozenset({
    Capability.WORKSPACE_WRITE,
    Capability.WORKSPACE_TEMP_CLEAN,
    Capability.TEMPDIR_MARKER_WRITE,
    Capability.SUBPROCESS_CATALOG_EXEC,
    Capability.GHIDRA_HEADLESS_EXEC,
    Capability.GHIDRA_PROJECT_MUTATE,
})

_ETW_CAPTURE_OPERATIONS: FrozenSet[str] = frozenset({
    "bintra_etw_capture",
    "start_session",
    "stop_session",
})

_ETW_CAPTURE_COMPONENTS: FrozenSet[str] = frozenset({
    "etw_capture_engine",
    "mcp_server",
    "cli",
})

_SUBPROCESS_OPERATIONS: FrozenSet[str] = frozenset({
    "run_subprocess",
    "execute_command",
    "execute_catalog_command",
    "run_bounded_process",
})


@dataclass(frozen=True)
class AccessRequest:
    """Structured description of an attempted operating system interaction."""

    component: str
    operation: str
    target: str
    requested_capability: Capability
    access_mode: str = "READ"  # "READ" | "WRITE" | "EXECUTE" | "QUERY" | "DELETE"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AccessDecision:
    """The authoritative determination returned by the Safety Kernel."""

    verdict: str  # "ALLOW" | "ALLOW_SCOPED" | "DENY"
    reason: str
    capability: Optional[Capability] = None
    side_effects: List[str] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        return self.verdict in ("ALLOW", "ALLOW_SCOPED")


def _cap_label(cap: Optional[Capability]) -> str:
    return cap.value if hasattr(cap, "value") else str(cap)


def _deny(reason: str, cap: Optional[Capability]) -> AccessDecision:
    return AccessDecision(verdict="DENY", reason=reason, capability=cap)


class PolicyEngine:
    """
    Evaluates every AccessRequest against formal non-destructive security rules.
    Default verdict is always DENY.
    """

    @classmethod
    def _evaluate_prerequisites(cls, request: AccessRequest, mode: str, cap: Capability) -> Optional[AccessDecision]:
        if cap in PROHIBITED_HAZARDS:
            return _deny(
                f"Hazardous capability '{_cap_label(cap)}' is unconditionally forbidden by Bintra Safety Policy.",
                cap,
            )

        # Central fail-closed tamper gate: any mutating or execution request is refused
        # regardless of whether it arrived via MCP, CLI, or direct Python API.
        if mode in ("WRITE", "MODIFY", "DELETE", "EXECUTE") or cap in _MUTATING_OR_EXEC_CAPABILITIES:
            from .audit_logger import AuditLogger

            if AuditLogger.is_tamper_detected():
                tamper_reason = AuditLogger.get_tamper_reason() or "audit hash/sequence integrity compromised"
                return _deny(
                    f"AUDIT_TAMPER_DETECTED: Refusing mutating or execution operation '{request.operation}' "
                    f"while audit integrity is compromised ({tamper_reason}).",
                    cap,
                )

        if request.operation in _SUBPROCESS_OPERATIONS:
            if request.metadata.get("shell") is True:
                return _deny("Arbitrary shell execution (shell=True) is unconditionally prohibited.", cap)
            if not request.metadata.get("is_catalog_command", False):
                return _deny("Only cataloged, pre-approved commands are permitted for subprocess execution.", cap)

        if not CapabilityRegistry.has_capability(request.component, cap):
            return _deny(
                f"CAPABILITY_NOT_GRANTED: Component '{request.component}' lacks declared capability '{_cap_label(cap)}'.",
                cap,
            )
        return None

    @classmethod
    def _evaluate_ghidra_capabilities(cls, request: AccessRequest, cap: Capability) -> Optional[AccessDecision]:
        if cap == Capability.GHIDRA_HEADLESS_EXEC:
            if request.metadata.get("shell") is True:
                return _deny("Arbitrary shell execution (shell=True) is unconditionally prohibited.", cap)
            return AccessDecision(
                verdict="ALLOW_SCOPED",
                reason=f"Authorized Ghidra headless analysis on target: '{request.target}'.",
                capability=cap,
                side_effects=["ghidra_headless_execution"],
            )

        if cap == Capability.GHIDRA_PROJECT_MUTATE:
            return AccessDecision(
                verdict="ALLOW_SCOPED",
                reason="Authorized Ghidra project database mutation in quarantined temp project.",
                capability=cap,
                side_effects=["ghidra_project_mutation"],
            )
        return None

    @classmethod
    def _evaluate_tempdir_marker_write(
        cls,
        request: AccessRequest,
        cap: Capability,
        scope: Optional[TargetScope],
    ) -> AccessDecision:
        target = request.target
        if request.component != "ghidra_live_bridge" or request.operation != "write_tempdir_discovery_marker":
            return _deny(
                "CAPABILITY_MISMATCH: TEMPDIR_MARKER_WRITE is reserved exclusively for ghidra_live_bridge marker publication.",
                cap,
            )

        expected_temp_marker = default_ghidra_bridge_marker_path()
        if not PathIdentity.is_same_file(target, expected_temp_marker):
            return _deny(
                f"TEMPDIR_PATH_FORBIDDEN: TEMPDIR_MARKER_WRITE may target only '{expected_temp_marker}', got '{target}'.",
                cap,
            )

        if scope and (scope.is_target_file(target) or scope.is_target_directory(target)):
            return _deny(
                f"TARGET_WRITE_FORBIDDEN: Marker path '{target}' conflicts with protected target scope.",
                cap,
            )

        return AccessDecision(
            verdict="ALLOW_SCOPED",
            reason=f"Authorized bridge discovery marker write in tempdir: '{target}'.",
            capability=cap,
            side_effects=["tempdir_marker_write"],
        )

    @classmethod
    def _evaluate_mutation_request(
        cls,
        request: AccessRequest,
        mode: str,
        cap: Capability,
        scope: Optional[TargetScope],
    ) -> AccessDecision:
        if mode == "WRITE" and cap == Capability.TEMPDIR_MARKER_WRITE:
            return cls._evaluate_tempdir_marker_write(request, cap, scope)

        if mode in ("WRITE", "MODIFY") and cap != Capability.WORKSPACE_WRITE:
            return _deny(
                f"CAPABILITY_MISMATCH: Mode '{mode}' requires Capability.WORKSPACE_WRITE, got '{_cap_label(cap)}'.",
                cap,
            )
        if mode == "DELETE" and cap != Capability.WORKSPACE_TEMP_CLEAN:
            return _deny(
                f"CAPABILITY_MISMATCH: Mode 'DELETE' requires Capability.WORKSPACE_TEMP_CLEAN, got '{_cap_label(cap)}'.",
                cap,
            )

        if scope is None:
            return _deny(
                f"SCOPE_REQUIRED: Mode '{mode}' requires an active TargetScope boundary.",
                cap,
            )

        target = request.target
        if scope.is_target_file(target):
            return _deny(
                f"TARGET_WRITE_FORBIDDEN: Target file '{target}' is strictly immutable.",
                cap,
            )

        if scope.is_target_directory(target):
            return _deny(
                f"TARGET_DIRECTORY_WRITE_FORBIDDEN: Writing inside target directory '{target}' is prohibited.",
                cap,
            )

        if not scope.is_inside_workspace(target):
            return _deny(
                f"WRITE_OUTSIDE_WORKSPACE: Path '{target}' is outside authorized workspace '{scope.workspace_dir}'.",
                cap,
            )

        if mode == "DELETE" and not scope.is_session_file(target):
            return _deny(
                f"UNAUTHORIZED_DELETION: Can only delete files created by Bintra in current session: '{target}'.",
                cap,
            )

        return AccessDecision(
            verdict="ALLOW_SCOPED",
            reason=f"Authorized write confined to workspace: '{target}'.",
            capability=cap,
            side_effects=["workspace_mutation"],
        )

    @classmethod
    def _evaluate_read_query_request(
        cls,
        request: AccessRequest,
        cap: Capability,
        scope: Optional[TargetScope],
    ) -> Optional[AccessDecision]:
        if cap not in _READ_CAPABILITIES:
            return None

        target = request.target
        if cap in _FILESYSTEM_READ_CAPABILITIES and target:
            norm_target = str(target).replace("/", "\\").lower()
            if any(marker in norm_target for marker in FORBIDDEN_CREDENTIAL_MARKERS):
                return _deny(
                    f"FORBIDDEN_SYSTEM_READ: Direct access to security credential store '{target}' is prohibited.",
                    cap,
                )
            if scope and getattr(scope, "strict_read_scope", False) and not scope.is_authorized_read_target(target):
                return _deny(
                    f"OUT_OF_SCOPE_READ: File '{target}' is outside designated read target scope.",
                    cap,
                )

        return AccessDecision(
            verdict="ALLOW",
            reason=f"Authorized read-only query for {_cap_label(cap)}.",
            capability=cap,
            side_effects=[],
        )

    @classmethod
    def evaluate(cls, request: AccessRequest, scope: Optional[TargetScope] = None) -> AccessDecision:
        """Evaluates an access request deterministically."""
        cap = request.requested_capability
        mode = request.access_mode.upper()

        prereq_denial = cls._evaluate_prerequisites(request, mode, cap)
        if prereq_denial is not None:
            return prereq_denial

        ghidra_decision = cls._evaluate_ghidra_capabilities(request, cap)
        if ghidra_decision is not None:
            return ghidra_decision

        if mode in ("WRITE", "DELETE", "MODIFY"):
            return cls._evaluate_mutation_request(request, mode, cap, scope)

        if mode in ("READ", "QUERY"):
            read_decision = cls._evaluate_read_query_request(request, cap, scope)
            if read_decision is not None:
                return read_decision

        if mode == "EXECUTE":
            if cap == Capability.SUBPROCESS_CATALOG_EXEC and request.metadata.get("is_catalog_command"):
                return AccessDecision(
                    verdict="ALLOW",
                    reason="Authorized catalog command execution.",
                    capability=cap,
                    side_effects=[],
                )
            if (
                cap == Capability.EVENT_LOG_READ
                and request.operation in _ETW_CAPTURE_OPERATIONS
                and request.component in _ETW_CAPTURE_COMPONENTS
            ):
                return AccessDecision(
                    verdict="ALLOW_SCOPED",
                    reason=f"Authorized live ETW capture session '{request.target}'.",
                    capability=cap,
                    side_effects=["etw_trace_session"],
                )

        return _deny(
            f"DEFAULT_DENY: Operation '{request.operation}' with capability '{cap}' and mode '{mode}' is not permitted.",
            cap,
        )
