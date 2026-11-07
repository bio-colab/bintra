# -*- coding: utf-8 -*-
"""
REA-Neural Windows System Intelligence Layer.
Provides holistic environment profiling, dependency resolution, hardware/driver audits,
security/privilege inspection, crash telemetry analysis (WER/EventLog/MiniDump),
and cross-correlation of runtime failure evidence with static PE/Ghidra IR.
"""

from .os_profiler import WindowsOSProfiler
from .dependency_resolver import WindowsDependencyResolver
from .device_inspector import WindowsDeviceInspector
from .security_inspector import WindowsSecurityInspector
from .crash_analyzer import WindowsCrashAnalyzer
from .evidence_correlator import DiagnosticEvidenceCorrelator

# Alias for compatibility
WindowsEvidenceCorrelator = DiagnosticEvidenceCorrelator

__all__ = [
    "WindowsOSProfiler",
    "WindowsDependencyResolver",
    "WindowsDeviceInspector",
    "WindowsSecurityInspector",
    "WindowsCrashAnalyzer",
    "DiagnosticEvidenceCorrelator",
    "WindowsEvidenceCorrelator"
]
