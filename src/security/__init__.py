# -*- coding: utf-8 -*-
"""
REA-Neural Safety Kernel & Execution Guard Layer.
Autonomous, non-destructive Reference Monitor for Windows system introspection.
"""

from .capability_registry import Capability, CapabilityRegistry, PROHIBITED_HAZARDS
from .path_identity import PathIdentity
from .target_scope import TargetScope
from .audit_logger import AuditLogger
from .policy_engine import PolicyEngine, AccessRequest, AccessDecision
from .execution_guard import (
    ExecutionGuard,
    SecurityViolationError,
    TargetMutationError,
    OutOfScopeError,
)
from .safe_file_access import SafeFileAccess
from .safe_registry_access import SafeRegistryAccess
from .safe_process_access import SafeProcessAccess
from .safe_subprocess import SafeSubprocessBroker

__all__ = [
    "Capability",
    "CapabilityRegistry",
    "PROHIBITED_HAZARDS",
    "PathIdentity",
    "TargetScope",
    "AuditLogger",
    "PolicyEngine",
    "AccessRequest",
    "AccessDecision",
    "ExecutionGuard",
    "SecurityViolationError",
    "TargetMutationError",
    "OutOfScopeError",
    "SafeFileAccess",
    "SafeRegistryAccess",
    "SafeProcessAccess",
    "SafeSubprocessBroker",
]
