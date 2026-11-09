# -*- coding: utf-8 -*-
"""
REA-Neural Policy Engine.
Evaluates system access requests against the 5 Inviolable Rules,
CapabilityRegistry grants, and Default Deny matrix.
Enforces read target scope boundaries and workspace write confinement.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from .capability_registry import Capability, PROHIBITED_HAZARDS, CapabilityRegistry
from .target_scope import TargetScope
from .path_identity import PathIdentity


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


class PolicyEngine:
    """
    Evaluates every AccessRequest against formal non-destructive security rules.
    Default verdict is always DENY.
    """

    @classmethod
    def evaluate(cls, request: AccessRequest, scope: Optional[TargetScope] = None) -> AccessDecision:
        """
        Evaluates an access request deterministically.
        """
        cap = request.requested_capability
        mode = request.access_mode.upper()
        target = request.target
        comp = request.component

        # Rule 1: Prohibited hazards are unconditionally denied
        if cap in PROHIBITED_HAZARDS:
            return AccessDecision(
                verdict="DENY",
                reason=f"Hazardous capability '{cap.value if hasattr(cap, 'value') else cap}' is unconditionally forbidden by REA Safety Policy.",
                capability=cap
            )

        # Rule 2: Shell=True or arbitrary command strings are unconditionally denied
        if request.operation in ("run_subprocess", "execute_command", "execute_catalog_command"):
            if request.metadata.get("shell") is True:
                return AccessDecision(
                    verdict="DENY",
                    reason="Arbitrary shell execution (shell=True) is unconditionally prohibited.",
                    capability=cap
                )
            if not request.metadata.get("is_catalog_command", False):
                return AccessDecision(
                    verdict="DENY",
                    reason="Only cataloged, pre-approved commands are permitted for subprocess execution.",
                    capability=cap
                )

        # Rule 3: Component Capability Verification (No Ambient Authority)
        if not CapabilityRegistry.has_capability(comp, cap):
            return AccessDecision(
                verdict="DENY",
                reason=f"CAPABILITY_NOT_GRANTED: Component '{comp}' lacks declared capability '{cap.value if hasattr(cap, 'value') else cap}'.",
                capability=cap
            )

        # Rule 4: Target binary and target directory write protection
        if mode in ("WRITE", "DELETE", "MODIFY"):
            # Enforce capability matching
            if mode in ("WRITE", "MODIFY") and cap != Capability.WORKSPACE_WRITE:
                return AccessDecision(
                    verdict="DENY",
                    reason=f"CAPABILITY_MISMATCH: Mode '{mode}' requires Capability.WORKSPACE_WRITE, got '{cap.value if hasattr(cap, 'value') else cap}'.",
                    capability=cap
                )
            if mode == "DELETE" and cap != Capability.WORKSPACE_TEMP_CLEAN:
                return AccessDecision(
                    verdict="DENY",
                    reason=f"CAPABILITY_MISMATCH: Mode 'DELETE' requires Capability.WORKSPACE_TEMP_CLEAN, got '{cap.value if hasattr(cap, 'value') else cap}'.",
                    capability=cap
                )

            if scope and scope.is_target_file(target):
                return AccessDecision(
                    verdict="DENY",
                    reason=f"TARGET_WRITE_FORBIDDEN: Target file '{target}' is strictly immutable.",
                    capability=cap
                )

            if scope and scope.is_target_directory(target):
                return AccessDecision(
                    verdict="DENY",
                    reason=f"TARGET_DIRECTORY_WRITE_FORBIDDEN: Writing inside target directory '{target}' is prohibited.",
                    capability=cap
                )

            # Rule 5: Workspace confinement for all writes
            if scope:
                if not scope.is_inside_workspace(target):
                    return AccessDecision(
                        verdict="DENY",
                        reason=f"WRITE_OUTSIDE_WORKSPACE: Path '{target}' is outside authorized workspace '{scope.workspace_dir}'.",
                        capability=cap
                    )

            # Rule 6: Deletion restricted to REA session files within workspace
            if mode == "DELETE" and scope:
                if not scope.is_session_file(target):
                    return AccessDecision(
                        verdict="DENY",
                        reason=f"UNAUTHORIZED_DELETION: Can only delete files created by REA in current session: '{target}'.",
                        capability=cap
                    )

            # Workspace write allowed with scope restriction
            return AccessDecision(
                verdict="ALLOW_SCOPED",
                reason=f"Authorized write confined to workspace: '{target}'.",
                capability=cap,
                side_effects=["workspace_mutation"]
            )

        # Rule 7: Read-only operations within authorized capabilities & read scope enforcement
        if mode in ("READ", "QUERY"):
            if cap in (
                Capability.FILE_READ, Capability.FILE_HASH, Capability.REGISTRY_READ,
                Capability.PROCESS_QUERY, Capability.SERVICE_QUERY, Capability.DEVICE_QUERY,
                Capability.DRIVER_QUERY, Capability.EVENT_LOG_READ, Capability.MINIDUMP_READ
            ):
                # If target is a filesystem path, validate read scope and prevent forbidden credential reads
                if cap in (Capability.FILE_READ, Capability.FILE_HASH, Capability.MINIDUMP_READ) and target and not target.startswith("\\\\"):
                    norm_target = str(target).replace("/", "\\").lower()
                    if "\\windows\\system32\\config\\sam" in norm_target or "\\windows\\system32\\config\\security" in norm_target:
                        return AccessDecision(
                            verdict="DENY",
                            reason=f"FORBIDDEN_SYSTEM_READ: Direct access to security credential store '{target}' is prohibited.",
                            capability=cap
                        )
                    if scope and getattr(scope, "strict_read_scope", False):
                        if not scope.is_authorized_read_target(target):
                            return AccessDecision(
                                verdict="DENY",
                                reason=f"OUT_OF_SCOPE_READ: File '{target}' is outside designated read target scope.",
                                capability=cap
                            )

                return AccessDecision(
                    verdict="ALLOW",
                    reason=f"Authorized read-only query for {cap.value if hasattr(cap, 'value') else cap}.",
                    capability=cap,
                    side_effects=[]
                )

        # Rule 8: Pre-approved catalog subprocess execution
        if mode == "EXECUTE":
            if cap == Capability.SUBPROCESS_CATALOG_EXEC and request.metadata.get("is_catalog_command"):
                return AccessDecision(
                    verdict="ALLOW",
                    reason="Authorized catalog command execution.",
                    capability=cap,
                    side_effects=[]
                )

        # Default: Deny
        return AccessDecision(
            verdict="DENY",
            reason=f"DEFAULT_DENY: Operation '{request.operation}' with capability '{cap}' and mode '{mode}' is not permitted.",
            capability=cap
        )
