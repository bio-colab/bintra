# -*- coding: utf-8 -*-
"""
Real-Time Event Tracing for Windows (ETW) Capture & Telemetry Timeline Engine.
Establishes passive real-time diagnostic trace sessions (StartTraceW / ControlTraceW),
enables kernel/graphics diagnostic providers (Kernel-Process, Kernel-Memory, Direct3D11, DXGI),
and synthesizes chronological timelines leading up to application faults.
Strictly non-intrusive and read-only; governed by ExecutionGuard and Capability.EVENT_LOG_READ.
"""

import os
import sys
import time
import ctypes
import threading
from ctypes import wintypes
from typing import Dict, Any, List, Optional, Tuple, Callable
from collections import deque

from security.execution_guard import ExecutionGuard
from security.capability_registry import Capability
from .etw_controller import EtwController, WNODE_HEADER, EVENT_TRACE_PROPERTIES


# Win32 ETW Control Constants
EVENT_TRACE_CONTROL_QUERY = 0
EVENT_TRACE_CONTROL_STOP = 1
EVENT_TRACE_CONTROL_UPDATE = 2
EVENT_TRACE_CONTROL_FLUSH = 3

EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_USE_PAGED_MEMORY = 0x01000000

WNODE_FLAG_TRACED_GUID = 0x00020000

# High-value diagnostic provider GUIDs
KNOWN_PROVIDER_GUIDS = {
    "Microsoft-Windows-Kernel-Process": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
    "Microsoft-Windows-Kernel-Memory": "{D1D93CCC-6125-4F09-9B14-34FF42788A32}",
    "Microsoft-Windows-Kernel-File": "{EDD08927-9CC4-4E65-B970-C2560F5C4C82}",
    "Microsoft-Windows-Direct3D11": "{DB6F6DDB-AC77-4E88-8E81-8B010C2C31E9}",
    "Microsoft-Windows-DXGI": "{CA11C036-0102-4503-AC64-283040314001}",
}


class EtwEventRecord:
    """Represents a discrete diagnostic event captured from an active ETW stream."""

    def __init__(
        self,
        timestamp: float,
        provider_name: str,
        event_id: int,
        pid: int,
        tid: int,
        event_type: str,
        opcode: int = 0,
        details: Optional[Dict[str, Any]] = None
    ):
        self.timestamp = timestamp
        self.provider_name = provider_name
        self.event_id = event_id
        self.pid = pid
        self.tid = tid
        self.event_type = event_type
        self.opcode = opcode
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": round(self.timestamp, 4),
            "time_str": time.strftime("%H:%M:%S", time.localtime(self.timestamp)) + f".{int((self.timestamp % 1) * 1000):03d}",
            "provider_name": self.provider_name,
            "event_id": self.event_id,
            "pid": self.pid,
            "tid": self.tid,
            "event_type": self.event_type,
            "opcode": self.opcode,
            "details": self.details
        }


class EtwLiveCaptureSession:
    """
    Manages a real-time ETW capture session.
    Buffers events in an in-memory ring buffer for timeline correlation.
    """

    def __init__(
        self,
        session_name: str = "REA_Neural_Diagnostic_Trace",
        target_pid: Optional[int] = None,
        max_buffer_events: int = 2000
    ):
        self.session_name = session_name
        self.target_pid = target_pid
        self.max_buffer_events = max_buffer_events
        self.events_buffer: deque = deque(maxlen=max_buffer_events)
        self.is_running = False
        self.trace_handle: Optional[int] = None
        self.status_description = "INITIALIZED"
        self.start_time: Optional[float] = None
        self._owns_session = False
        self._consumer_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start_session(self, providers: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Starts the real-time ETW trace session via Win32 advapi32.StartTraceW.
        Mediated by ExecutionGuard with Capability.EVENT_LOG_READ.
        """
        ExecutionGuard.request_access(
            component="etw_capture_engine",
            operation="start_session",
            target=self.session_name,
            capability=Capability.EVENT_LOG_READ,
            access_mode="READ"
        )

        self.start_time = time.time()
        self._stop_event.clear()

        if os.name != "nt":
            self.is_running = True
            self.status_description = "SIMULATED_CROSS_PLATFORM"
            return {
                "status": "success",
                "session_name": self.session_name,
                "mode": "SIMULATED",
                "message": "ETW capture running in cross-platform test mode."
            }

        try:
            advapi32 = ctypes.windll.advapi32

            advapi32.StartTraceW.argtypes = [
                ctypes.POINTER(ctypes.c_uint64), wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES)
            ]
            advapi32.StartTraceW.restype = wintypes.ULONG

            size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 1024
            buf = ctypes.create_string_buffer(size)
            prop_ptr = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
            prop = prop_ptr.contents
            prop.Wnode.BufferSize = size
            prop.Wnode.Flags = WNODE_FLAG_TRACED_GUID
            prop.Wnode.ClientContext = 1  # QPC timestamp clock
            prop.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
            prop.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
            prop.LogFileNameOffset = 0  # Real-time only (no file output)
            prop.FlushTimer = 1  # 1 second flush interval

            h_trace = ctypes.c_uint64(0)
            res = advapi32.StartTraceW(ctypes.byref(h_trace), self.session_name, prop_ptr)

            if res == 0:
                self.trace_handle = h_trace.value
                self.is_running = True
                self._owns_session = True
                self.status_description = "ACTIVE_REALTIME"

                # Enable requested providers
                prov_list = providers or list(KNOWN_PROVIDER_GUIDS.keys())
                enabled = []
                for p_name in prov_list:
                    if self._enable_provider_native(p_name):
                        enabled.append(p_name)

                # Start background event consumer
                self._start_event_consumer()

                return {
                    "status": "success",
                    "session_name": self.session_name,
                    "mode": "WIN32_REALTIME",
                    "enabled_providers": enabled,
                    "target_pid": self.target_pid
                }
            elif res == 5:
                # ERROR_ACCESS_DENIED (requires Administrator for real-time kernel logger)
                self.is_running = True
                self.status_description = "NON_ELEVATED_INSPECTION_MODE"
                # Start non-elevated consumer via EventLog API
                self._start_event_consumer()

                return {
                    "status": "non_elevated",
                    "session_name": self.session_name,
                    "mode": "USER_MODE_TELEMETRY",
                    "warning": "Real-time kernel trace requires Administrator privileges. Operating in non-elevated EventLog telemetry mode."
                }
            else:
                self.status_description = f"START_FAILED_0x{res:X}"
                return {
                    "status": "error",
                    "session_name": self.session_name,
                    "win32_code": res,
                    "message": f"StartTraceW failed with error code {res}."
                }

        except Exception as e:
            self.status_description = f"EXCEPTION_{e}"
            return {
                "status": "error",
                "session_name": self.session_name,
                "error": str(e)
            }

    def _enable_provider_native(self, provider_name: str) -> bool:
        """Enables a provider GUID on the active real-time trace session via EnableTraceEx2."""
        if not self.trace_handle or os.name != "nt":
            return False

        guid_str = KNOWN_PROVIDER_GUIDS.get(provider_name)
        if not guid_str:
            return False

        try:
            ole32 = ctypes.windll.ole32
            advapi32 = ctypes.windll.advapi32

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8)
                ]

            guid = GUID()
            hr = ole32.CLSIDFromString(ctypes.c_wchar_p(guid_str), ctypes.byref(guid))
            if hr != 0:
                return False

            advapi32.EnableTraceEx2.argtypes = [
                ctypes.c_uint64,
                ctypes.POINTER(GUID),
                wintypes.ULONG,
                ctypes.c_ubyte,
                ctypes.c_uint64,
                ctypes.c_uint64,
                wintypes.ULONG,
                ctypes.c_void_p
            ]
            advapi32.EnableTraceEx2.restype = wintypes.ULONG

            status = advapi32.EnableTraceEx2(
                self.trace_handle,
                ctypes.byref(guid),
                1,  # EVENT_CONTROL_CODE_ENABLE_PROVIDER
                5,  # TRACE_LEVEL_VERBOSE
                0,
                0,
                0,
                None
            )
            return (status == 0)
        except Exception:
            return False

    def _start_event_consumer(self) -> None:
        """Starts asynchronous thread consuming system and diagnostic events."""
        def _consumer_loop():
            from .event_log_collector import EventLogCollector
            seen_events = set()
            while not self._stop_event.is_set():
                try:
                    for channel in ("Application", "System"):
                        evs = EventLogCollector.query_events(channel, limit=15)
                        for ev in evs:
                            ev_pid = ev.get("process_id", 0)
                            key = (ev.get("provider_name"), ev.get("event_id"), ev.get("time_created"), ev_pid, ev.get("thread_id"))
                            if key in seen_events:
                                continue
                            seen_events.add(key)
                            if len(seen_events) > 5000:
                                seen_events.clear()

                            if self.target_pid is None or ev_pid == 0 or ev_pid == self.target_pid:
                                ev_id = ev.get("event_id", 0)
                                ev_type = ev.get("level", "INFO")
                                if ev_id == 1000:
                                    ev_type = "APPLICATION_ERROR"
                                elif ev_id == 1001:
                                    ev_type = "WER_REPORT"
                                elif ev_id == 1002:
                                    ev_type = "APPLICATION_HANG"
                                elif ev_id in (10000, 10001):
                                    ev_type = "RESTART_MANAGER_LOCK"
                                elif ev_id in (41, 1001) and channel == "System":
                                    ev_type = "KERNEL_POWER_OR_BUGCHECK"

                                rec = EtwEventRecord(
                                    timestamp=ev.get("time_created", time.time()),
                                    provider_name=ev.get("provider_name", channel),
                                    event_id=ev_id,
                                    pid=ev_pid,
                                    tid=ev.get("thread_id", 0),
                                    event_type=ev_type,
                                    details={"message": ev.get("message", "")[:120], **ev.get("details", {})}
                                )
                                self.record_event(rec)
                except Exception:
                    pass
                time.sleep(0.5)

        self._consumer_thread = threading.Thread(target=_consumer_loop, daemon=True)
        self._consumer_thread.start()

    def stop_session(self) -> Dict[str, Any]:
        """Stops the real-time ETW trace session and releases kernel handles."""
        self.is_running = False
        self._stop_event.set()
        duration = round(time.time() - (self.start_time or time.time()), 3)

        if os.name == "nt":
            self._stop_session_native()

        return {
            "status": "stopped",
            "session_name": self.session_name,
            "duration_seconds": duration,
            "captured_events_buffered": len(self.events_buffer)
        }

    def _stop_session_native(self) -> None:
        if os.name != "nt" or not getattr(self, "_owns_session", False):
            return
        try:
            advapi32 = ctypes.windll.advapi32
            advapi32.ControlTraceW.argtypes = [
                ctypes.c_uint64, wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES), wintypes.ULONG
            ]
            advapi32.ControlTraceW.restype = wintypes.ULONG

            size = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 1024
            buf = ctypes.create_string_buffer(size)
            prop_ptr = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
            prop = prop_ptr.contents
            prop.Wnode.BufferSize = size
            prop.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)

            advapi32.ControlTraceW(0, self.session_name, prop_ptr, EVENT_TRACE_CONTROL_STOP)
            self._owns_session = False
        except Exception:
            pass

    def record_event(self, event: EtwEventRecord) -> None:
        """Ingests an event into the ring buffer, filtering by target PID if set."""
        if self.target_pid is not None and event.pid != 0 and event.pid != self.target_pid:
            return
        self.events_buffer.append(event)

    def get_timeline(self, pid: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Extracts ordered chronological event timeline from the buffer."""
        target = pid or self.target_pid
        events = list(self.events_buffer)
        if target:
            events = [e for e in events if e.pid == target or e.pid == 0]
        # Sort by timestamp
        events.sort(key=lambda x: x.timestamp)
        return [e.to_dict() for e in events[-limit:]]

    def __enter__(self):
        self.start_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_session()


class EtwTimelineCorrelator:
    """
    Synthesizes and correlates ETW chronological events with crash dumps and memory allocations.
    Detects dynamic memory churn, late DLL loading, and access anomalies.
    """

    @classmethod
    def correlate_crash_timeline(
        cls,
        timeline_events: List[Dict[str, Any]],
        crash_timestamp: Optional[float] = None,
        target_vaddr: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Analyzes the sequence of events preceding a fault to establish causality.
        """
        if not timeline_events:
            return {
                "events_count": 0,
                "causality_findings": [],
                "temporal_verdict": "NO_ETW_TIMELINE_DATA"
            }

        ref_time = crash_timestamp or (timeline_events[-1]["timestamp"] if timeline_events else time.time())
        findings = []

        # 1. Look for DLL loads within 5 seconds before crash
        recent_dll_loads = []
        for ev in timeline_events:
            delta_sec = ref_time - ev["timestamp"]
            if 0 <= delta_sec <= 5.0 and ev.get("event_type") == "IMAGE_LOAD":
                mod_name = ev.get("details", {}).get("image_name", "Unknown.dll")
                recent_dll_loads.append({
                    "delta_seconds_before_crash": round(delta_sec, 3),
                    "module": mod_name,
                    "base_address": ev.get("details", {}).get("base_address")
                })

        if recent_dll_loads:
            findings.append({
                "category": "DYNAMIC_IMAGE_LOAD",
                "significance": "HIGH",
                "description": f"{len(recent_dll_loads)} module(s) loaded within 5 seconds of the fault.",
                "modules": recent_dll_loads
            })

        # 2. Look for memory allocation / deallocation churn
        recent_allocs = [e for e in timeline_events if e.get("event_type") in ("VIRTUAL_ALLOC", "HEAP_ALLOC")]
        recent_frees = [e for e in timeline_events if e.get("event_type") in ("VIRTUAL_FREE", "HEAP_FREE")]

        if recent_frees:
            findings.append({
                "category": "MEMORY_DEALLOCATION",
                "significance": "HIGH",
                "description": f"{len(recent_frees)} deallocation event(s) occurred before crash. Potential Use-After-Free window."
            })

        # 3. Look for Restart Manager resource contention
        rm_events = [e for e in timeline_events if e.get("event_type") == "RESTART_MANAGER_LOCK" or "RestartManager" in e.get("provider_name", "")]
        if rm_events:
            findings.append({
                "category": "RESOURCE_LOCK_CONTENTION",
                "significance": "MEDIUM",
                "description": f"{len(rm_events)} Windows RestartManager event(s) detected. Another process attempted to inspect or lock files."
            })

        # 4. Look for previous application crashes
        prev_faults = [e for e in timeline_events if e.get("event_type") == "APPLICATION_ERROR" or e.get("event_id") == 1000]
        if prev_faults:
            findings.append({
                "category": "RECURRENT_APPLICATION_FAULT",
                "significance": "HIGH",
                "description": f"{len(prev_faults)} Application Crash event(s) recorded in timeline."
            })

        # 5. Look for graphics pipeline reset
        gpu_resets = [e for e in timeline_events if any(p in e.get("provider_name", "") for p in ("Direct3D", "DXGI", "DxgKrnl")) and e.get("event_type") in ("ERROR", "CRITICAL", "DEVICE_REMOVED", "TDR")]
        if gpu_resets:
            findings.append({
                "category": "GRAPHICS_TDR_DEVICE_REMOVAL",
                "significance": "CRITICAL",
                "description": f"{len(gpu_resets)} Graphics/DirectX driver reset event(s) detected."
            })

        # 6. Overall verdict
        if any(f["category"] == "MEMORY_DEALLOCATION" for f in findings):
            verdict = "TEMPORAL_MEMORY_CHURN_DETECTED"
        elif recent_dll_loads:
            verdict = "LATE_MODULE_INJECTION_DETECTED"
        elif gpu_resets:
            verdict = "GRAPHICS_PIPELINE_RESET_DETECTED"
        elif rm_events:
            verdict = "FILE_LOCK_CONTENTION_DETECTED"
        elif prev_faults:
            verdict = "RECURRENT_APPLICATION_FAULT_DETECTED"
        else:
            verdict = "STABLE_PRE_CRASH_TIMELINE"

        return {
            "events_count": len(timeline_events),
            "reference_crash_timestamp": ref_time,
            "temporal_verdict": verdict,
            "causality_findings": findings,
            "timeline_sample": timeline_events[-20:]
        }

    @classmethod
    def format_markdown(cls, correlation_report: Dict[str, Any]) -> str:
        """Formats the ETW timeline correlation into an executive Markdown report."""
        lines = [
            "# REA-Neural ETW Diagnostic Timeline Correlation",
            f"- **Events Evaluated:** {correlation_report.get('events_count', 0)}",
            f"- **Temporal Verdict:** **`{correlation_report.get('temporal_verdict')}`**",
        ]

        findings = correlation_report.get("causality_findings", [])
        if findings:
            lines.append("\n### Causality Timeline Findings")
            for f in findings:
                lines.append(f"- **[{f['significance']}] {f['category']}:** {f['description']}")

        sample = correlation_report.get("timeline_sample", [])
        if sample:
            lines.append("\n### Chronological Event Stream")
            lines.append("| Time | Event Type | PID:TID | Provider | Details |")
            lines.append("|---|---|---|---|---|")
            for s in sample:
                det = ", ".join(f"{k}={v}" for k, v in s.get("details", {}).items())
                lines.append(f"| `{s.get('time_str')}` | `{s.get('event_type')}` | `{s.get('pid')}:{s.get('tid')}` | `{s.get('provider_name')}` | {det} |")

        return "\n".join(lines)
