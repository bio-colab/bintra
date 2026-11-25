# -*- coding: utf-8 -*-
"""
Bintra Execution Guard.
The Central Reference Monitor.
All interactions with Windows files, registries, processes, and subprocesses
must pass through this gateway to ensure Complete Mediation.
"""

import threading
from contextlib import contextmanager
from typing import Any, Dict, FrozenSet, Optional

from .audit_logger import AuditLogger
from .capability_registry import Capability
from .path_identity import PathIdentity
from .policy_engine import AccessDecision, AccessRequest, PolicyEngine
from .target_scope import TargetScope

_FILESYSTEM_CAPABILITIES: FrozenSet[Capability] = frozenset({
    Capability.FILE_READ,
    Capability.FILE_HASH,
    Capability.MINIDUMP_READ,
    Capability.WORKSPACE_WRITE,
    Capability.WORKSPACE_TEMP_CLEAN,
    Capability.TEMPDIR_MARKER_WRITE,
})

_FILESYSTEM_MODES: FrozenSet[str] = frozenset({"READ", "WRITE", "DELETE", "MODIFY"})


class SecurityViolationError(PermissionError):
    """Raised when an operation is rejected by the Bintra Safety Kernel."""

    def __init__(self, message: str, decision: Optional[AccessDecision] = None):
        super().__init__(message)
        self.decision = decision


class TargetMutationError(SecurityViolationError):
    """Raised when an operation attempts to mutate or write to a target binary."""


class OutOfScopeError(SecurityViolationError):
    """Raised when an operation targets an unapproved path outside authorized boundaries."""


class ExecutionGuard:
    """
    Central Reference Monitor enforcing mandatory access mediation across all tools.
    """

    _default_scope = TargetScope()
    _thread_local = threading.local()

    @classmethod
    def get_current_scope(cls) -> TargetScope:
        """Returns the active TargetScope for the current execution context."""
        cur = getattr(cls._thread_local, "scope", None)
        if cur is None:
            return cls._default_scope
        return cur

    @classmethod
    def set_current_scope(cls, scope: TargetScope) -> None:
        """Sets the active TargetScope for the current thread."""
        cls._thread_local.scope = scope

    @classmethod
    @contextmanager
    def scoped_session(cls, target_binary_path: Optional[str] = None, workspace_dir: Optional[str] = None):
        """Context manager establishing an isolated target and workspace session."""
        prev = getattr(cls._thread_local, "scope", None)
        new_scope = TargetScope(target_binary_path=target_binary_path, workspace_dir=workspace_dir)
        cls._thread_local.scope = new_scope
        try:
            yield new_scope
        finally:
            cls._thread_local.scope = prev

    @classmethod
    def _requires_path_canonicalization(cls, capability: Capability, access_mode: str, raw_target: str) -> bool:
        if capability in _FILESYSTEM_CAPABILITIES:
            return True
        return access_mode.upper() in _FILESYSTEM_MODES and not raw_target.startswith("\\\\")

    @classmethod
    def _raise_for_denial(cls, decision: AccessDecision) -> None:
        if "TARGET_WRITE_FORBIDDEN" in decision.reason or "TARGET_DIRECTORY_WRITE" in decision.reason:
            raise TargetMutationError(decision.reason, decision)
        if "WRITE_OUTSIDE_WORKSPACE" in decision.reason or "OUTSIDE_WORKSPACE" in decision.reason:
            raise OutOfScopeError(decision.reason, decision)
        raise SecurityViolationError(decision.reason, decision)

    @classmethod
    def request_access(
        cls,
        component: str,
        operation: str,
        target: str,
        capability: Capability,
        access_mode: str = "READ",
        metadata: Optional[Dict[str, Any]] = None,
        raise_on_deny: bool = True,
    ) -> AccessDecision:
        """
        Primary entry point for Reference Monitor mediation.
        Validates the request against policy, logs the determination,
        and either grants access or blocks execution.
        """
        meta = metadata or {}
        scope = cls.get_current_scope()
        raw_target = str(target)
        clean_target = raw_target

        if cls._requires_path_canonicalization(capability, access_mode, raw_target):
            try:
                clean_target = PathIdentity.canonicalize(target)
            except Exception as exc:
                decision = AccessDecision(
                    verdict="DENY",
                    reason=f"INVALID_PATH: {exc}",
                    capability=capability,
                )
                AuditLogger.log_decision(
                    component=component,
                    operation=operation,
                    target=target,
                    decision="DENY",
                    reason=decision.reason,
                    requested_capability=capability.value if capability else None,
                    result="DENIED",
                )
                if raise_on_deny:
                    raise SecurityViolationError(decision.reason, decision)
                return decision

        request = AccessRequest(
            component=component,
            operation=operation,
            target=clean_target,
            requested_capability=capability,
            access_mode=access_mode,
            metadata=meta,
        )

        decision = PolicyEngine.evaluate(request, scope)
        AuditLogger.log_decision(
            component=component,
            operation=operation,
            target=clean_target,
            decision=decision.verdict,
            reason=decision.reason,
            requested_capability=capability.value if capability else None,
            side_effects=decision.side_effects,
            result="ALLOWED" if decision.is_allowed else "DENIED",
            metadata=meta,
        )

        if not decision.is_allowed and raise_on_deny:
            cls._raise_for_denial(decision)

        return decision
