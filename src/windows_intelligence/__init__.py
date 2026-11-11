# -*- coding: utf-8 -*-
"""
Bintra Windows System Intelligence Layer.
Provides holistic environment profiling, dependency resolution, hardware/driver audits,
security/privilege inspection, crash telemetry analysis (WER/EventLog/MiniDump),
immutable read-only command execution, deep dual-view registry intelligence,
and native SetupAPI / CfgMgr32 / PSAPI / SCM system introspection.
"""

# Core Legacy Facades & Diagnostics
from .os_profiler import WindowsOSProfiler
from .dependency_resolver import WindowsDependencyResolver
from .device_inspector import WindowsDeviceInspector
from .security_inspector import WindowsSecurityInspector
from .crash_analyzer import WindowsCrashAnalyzer
from .evidence_correlator import DiagnosticEvidenceCorrelator, DiagnosticEvidenceCorrelator as WindowsEvidenceCorrelator

# Command Engine Submodule
from .command_engine import (
    CommandSpec,
    CommandCatalog,
    CommandExecutor,
    PowerShellExecutor,
    OutputParsers
)

# Registry Intelligence Submodule
from .registry_intelligence import (
    RegistryCatalog,
    RegistryKeySpec,
    WindowsRegistryReader,
    WindowsRegistryAnalyzer
)

# Native System Introspection Submodule (Phase 2)
from .system_introspection import (
    NativeDeviceInspector,
    KernelDriverInspector,
    ServiceManagerInspector,
    ProcessMitigationInspector
)

# Runtime Telemetry & Crash Intelligence Submodule (Phase 3)
from .runtime_telemetry import (
    MiniDumpParser,
    EventLogCollector,
    EtwController,
    VirtualMemoryInspector,
    ProcessMemoryMapSnapshot,
    ProcessMemoryRegion,
    ProcessMemoryScanner,
    PointerScanner,
    StructureDissector,
    CrashRootCauseAnalyzer,
    EtwLiveCaptureSession,
    EtwEventRecord,
    EtwTimelineCorrelator
)

# Evidence Graph & Causality Engine Submodule (Phase 4)
from .evidence_engine import (
    EvidenceGraph,
    EvidenceNode,
    EvidenceEdge,
    CausalitySynthesizer
)

__all__ = [
    # Core Diagnostics
    "WindowsOSProfiler",
    "WindowsDependencyResolver",
    "WindowsDeviceInspector",
    "WindowsSecurityInspector",
    "WindowsCrashAnalyzer",
    "DiagnosticEvidenceCorrelator",
    "WindowsEvidenceCorrelator",
    # Command Engine
    "CommandSpec",
    "CommandCatalog",
    "CommandExecutor",
    "PowerShellExecutor",
    "OutputParsers",
    # Registry Intelligence
    "RegistryCatalog",
    "RegistryKeySpec",
    "WindowsRegistryReader",
    "WindowsRegistryAnalyzer",
    # Native System Introspection (Phase 2)
    "NativeDeviceInspector",
    "KernelDriverInspector",
    "ServiceManagerInspector",
    "ProcessMitigationInspector",
    # Runtime Telemetry & Crash Intelligence (Phase 3)
    "MiniDumpParser",
    "EventLogCollector",
    "EtwController",
    "VirtualMemoryInspector",
    "ProcessMemoryMapSnapshot",
    "ProcessMemoryRegion",
    "ProcessMemoryScanner",
    "PointerScanner",
    "StructureDissector",
    "CrashRootCauseAnalyzer",
    "EtwLiveCaptureSession",
    "EtwEventRecord",
    "EtwTimelineCorrelator",
    # Evidence Graph & Causality (Phase 4)
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceEdge",
    "CausalitySynthesizer"
]
