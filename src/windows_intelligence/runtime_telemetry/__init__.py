# -*- coding: utf-8 -*-
"""
REA-Neural Windows Runtime Telemetry & Crash Intelligence Subsystem.
Provides deep multi-stream MiniDump parsing, multi-event Application/System Log collection,
Event Tracing for Windows (ETW) provider inspection, and passive Virtual Memory (VAD) layout inspection.
"""

from .minidump_parser import MiniDumpParser
from .event_log_collector import EventLogCollector
from .etw_controller import EtwController
from .virtual_memory_inspector import (
    VirtualMemoryInspector,
    ProcessMemoryMapSnapshot,
    ProcessMemoryRegion,
    ProcessMemoryScanner,
    PointerScanner,
    StructureDissector
)
from .crash_rca_engine import CrashRootCauseAnalyzer
from .etw_capture_engine import EtwLiveCaptureSession, EtwEventRecord, EtwTimelineCorrelator

__all__ = [
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
]
