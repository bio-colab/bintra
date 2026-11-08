# -*- coding: utf-8 -*-
"""
REA-Neural Windows System Intelligence Layer.
Provides holistic environment profiling, dependency resolution, hardware/driver audits,
security/privilege inspection, crash telemetry analysis (WER/EventLog/MiniDump),
immutable read-only command execution, and deep dual-view registry intelligence.
"""

# Existing Core Submodules
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
    "WindowsRegistryAnalyzer"
]
