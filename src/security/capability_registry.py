# -*- coding: utf-8 -*-
"""
Bintra Capability Registry.
Defines formal, typed capabilities required by analysis tools and providers.
Enforces the Principle of Least Privilege and No Ambient Authority.
"""

from enum import Enum
from typing import Dict, Set, FrozenSet


class Capability(str, Enum):
    """Enumeration of granular, typed system capabilities."""
    # Target Scope Capabilities (Read-Only)
    FILE_READ = "cap.file.read"
    FILE_HASH = "cap.file.hash"
    REGISTRY_READ = "cap.registry.read"
    PROCESS_QUERY = "cap.process.query"
    SERVICE_QUERY = "cap.service.query"
    DEVICE_QUERY = "cap.device.query"
    DRIVER_QUERY = "cap.driver.query"
    EVENT_LOG_READ = "cap.event_log.read"
    MINIDUMP_READ = "cap.minidump.read"

    # Workspace Capabilities (Controlled Write)
    WORKSPACE_WRITE = "cap.workspace.write"
    WORKSPACE_TEMP_CLEAN = "cap.workspace.temp_clean"
    TEMPDIR_MARKER_WRITE = "cap.tempdir.marker.write"

    # Gated Subprocess Capabilities
    SUBPROCESS_CATALOG_EXEC = "cap.subprocess.catalog_exec"

    # Strictly Prohibited System Mutation Capabilities (Always Denied by Policy)
    TARGET_MUTATE = "cap.hazard.target_mutate"
    REGISTRY_MUTATE = "cap.hazard.registry_mutate"
    PROCESS_MUTATE = "cap.hazard.process_mutate"
    SERVICE_MUTATE = "cap.hazard.service_mutate"
    DRIVER_MUTATE = "cap.hazard.driver_mutate"
    SHELL_FREE_EXEC = "cap.hazard.shell_free_exec"
    PRIVILEGE_ELEVATE = "cap.hazard.privilege_elevate"


# Immutable set of hazardous mutation capabilities that the policy unconditionally denies
PROHIBITED_HAZARDS: FrozenSet[Capability] = frozenset({
    Capability.TARGET_MUTATE,
    Capability.REGISTRY_MUTATE,
    Capability.PROCESS_MUTATE,
    Capability.SERVICE_MUTATE,
    Capability.DRIVER_MUTATE,
    Capability.SHELL_FREE_EXEC,
    Capability.PRIVILEGE_ELEVATE,
})


class CapabilityRegistry:
    """
    Maintains declared capabilities for registered components and providers.
    Prevents ambient privilege inheritance.
    """

    COMPONENT_CAPABILITIES: Dict[str, Set[Capability]] = {
        # Safe Gateways
        "safe_file_access": {
            Capability.FILE_READ,
            Capability.WORKSPACE_WRITE,
            Capability.WORKSPACE_TEMP_CLEAN
        },
        "safe_registry_access": {Capability.REGISTRY_READ},
        "safe_process_access": {Capability.PROCESS_QUERY},
        "safe_subprocess": {Capability.SUBPROCESS_CATALOG_EXEC},

        # System Introspection Providers
        "binary_inspector": {Capability.FILE_READ, Capability.FILE_HASH},
        "deobfuscator": {Capability.FILE_READ},
        "function_matcher": {Capability.FILE_READ},
        "device_inspector": {Capability.DEVICE_QUERY, Capability.DRIVER_QUERY},
        "driver_inspector": {Capability.DRIVER_QUERY},
        "process_inspector": {Capability.PROCESS_QUERY},
        "virtual_memory_inspector": {Capability.PROCESS_QUERY},
        "service_inspector": {Capability.SERVICE_QUERY},
        "registry_reader": {Capability.REGISTRY_READ},
        "event_collector": {Capability.EVENT_LOG_READ},
        "etw_capture_engine": {Capability.EVENT_LOG_READ},
        "ghidra_live_bridge": {Capability.FILE_READ, Capability.WORKSPACE_WRITE, Capability.TEMPDIR_MARKER_WRITE},
        "minidump_parser": {Capability.MINIDUMP_READ, Capability.FILE_READ},
        "crash_rca_engine": {Capability.MINIDUMP_READ, Capability.FILE_READ},
        "command_executor": {Capability.SUBPROCESS_CATALOG_EXEC},
        "cmd_executor": {Capability.SUBPROCESS_CATALOG_EXEC},

        # Mutation / Surgery Engines (Confined to Authorized Workspace Only)
        "binary_patcher": {Capability.WORKSPACE_WRITE},
        "weight_patcher": {Capability.WORKSPACE_WRITE},

        # Intelligence Engines
        "evidence_engine": {Capability.FILE_READ, Capability.WORKSPACE_WRITE},
        "dossier_generator": {Capability.WORKSPACE_WRITE},
        "causality_synthesizer": {Capability.FILE_READ, Capability.WORKSPACE_WRITE},
        "device_intelligence": {Capability.DEVICE_QUERY, Capability.DRIVER_QUERY},
        "process_intelligence": {Capability.PROCESS_QUERY, Capability.FILE_READ},

        # High-Level Invocation Interfaces
        "mcp_server": {
            Capability.FILE_READ, Capability.FILE_HASH, Capability.WORKSPACE_WRITE,
            Capability.REGISTRY_READ, Capability.PROCESS_QUERY, Capability.SERVICE_QUERY,
            Capability.DEVICE_QUERY, Capability.DRIVER_QUERY, Capability.EVENT_LOG_READ,
            Capability.MINIDUMP_READ, Capability.SUBPROCESS_CATALOG_EXEC
        },
        "cli": {
            Capability.FILE_READ, Capability.FILE_HASH, Capability.WORKSPACE_WRITE,
            Capability.REGISTRY_READ, Capability.PROCESS_QUERY, Capability.SERVICE_QUERY,
            Capability.DEVICE_QUERY, Capability.DRIVER_QUERY, Capability.EVENT_LOG_READ,
            Capability.MINIDUMP_READ, Capability.SUBPROCESS_CATALOG_EXEC
        },

        # Test Fixtures & Internal Testing
        "test_suite": {
            Capability.FILE_READ, Capability.FILE_HASH, Capability.WORKSPACE_WRITE,
            Capability.WORKSPACE_TEMP_CLEAN, Capability.REGISTRY_READ, Capability.PROCESS_QUERY,
            Capability.SUBPROCESS_CATALOG_EXEC
        },
        "sec_test": {
            Capability.FILE_READ, Capability.WORKSPACE_WRITE, Capability.WORKSPACE_TEMP_CLEAN,
            Capability.SUBPROCESS_CATALOG_EXEC
        }
    }

    @classmethod
    def get_capabilities(cls, component_name: str) -> Set[Capability]:
        """Returns declared capabilities for a component or an empty set (Default Deny)."""
        return cls.COMPONENT_CAPABILITIES.get(component_name, set()).copy()

    @classmethod
    def has_capability(cls, component_name: str, capability: Capability) -> bool:
        """Verifies if a component explicitly possesses a declared capability."""
        return capability in cls.COMPONENT_CAPABILITIES.get(component_name, set())

    @classmethod
    def register_component_capability(cls, component_name: str, capability: Capability) -> None:
        """Registers a capability grant for a component."""
        if component_name not in cls.COMPONENT_CAPABILITIES:
            cls.COMPONENT_CAPABILITIES[component_name] = set()
        cls.COMPONENT_CAPABILITIES[component_name].add(capability)
