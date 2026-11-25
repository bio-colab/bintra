# -*- coding: utf-8 -*-
"""
Bintra Capability Registry.
Defines formal, typed capabilities required by analysis tools and providers.
Enforces the Principle of Least Privilege and No Ambient Authority.
"""

from enum import Enum
from typing import Dict, FrozenSet, Set

from .config import DEFAULT_COMPONENT_CAPABILITY_NAMES


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
    GHIDRA_HEADLESS_EXEC = "cap.ghidra.headless_exec"
    GHIDRA_PROJECT_MUTATE = "cap.ghidra.project_mutate"

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


def _build_default_component_capabilities() -> Dict[str, Set[Capability]]:
    return {
        component: {Capability[cap_name] for cap_name in cap_names}
        for component, cap_names in DEFAULT_COMPONENT_CAPABILITY_NAMES.items()
    }


class CapabilityRegistry:
    """
    Maintains declared capabilities for registered components and providers.
    Prevents ambient privilege inheritance.
    """

    COMPONENT_CAPABILITIES: Dict[str, Set[Capability]] = _build_default_component_capabilities()

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
