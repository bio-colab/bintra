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
from collections import deque, OrderedDict

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
    """Represents a discrete diagnostic event captured from ETW, EventLog, module deltas, or manual injection."""

    def __init__(
        self,
        timestamp: float,
        provider_name: str,
        event_id: int,
        pid: int,
        tid: int,
        event_type: str,
        opcode: int = 0,
        details: Optional[Dict[str, Any]] = None,
        source: str = "synthetic_manual",
    ):
        self.timestamp = timestamp
        self.provider_name = provider_name
        self.event_id = event_id
        self.pid = pid
        self.tid = tid
        self.event_type = event_type
        self.opcode = opcode
        self.details = details or {}
        self.source = source

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
            "source": self.source,
            "details": self.details
        }


class EtwLiveCaptureSession:
    """
    Manages a real-time ETW capture session.
    Buffers events in an in-memory ring buffer for timeline correlation.
    """

    def __init__(
        self,
        session_name: str = "Bintra_Diagnostic_Trace",
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
        self._native_consumer_active = False
        self._native_trace_handle: Optional[int] = None
        self._native_consumer_thread: Optional[threading.Thread] = None
        self._native_callback_ref = None
        self._consumer_thread: Optional[threading.Thread] = None
        self._consumer_errors: deque = deque(maxlen=25)
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
                "is_simulated": True,
                "source": "synthetic",
                "etw_native_consumer_active": False,
                "telemetry_backend": "NONE_SIMULATED_NON_NT",
                "message": "ETW capture running in cross-platform simulated mode (no live kernel events captured on non-Windows hosts)."
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
                self.status_description = "ACTIVE_SESSION_EVENTLOG_POLLING"
                self._register_atexit_cleanup()

                # Enable requested providers
                prov_list = providers or list(KNOWN_PROVIDER_GUIDS.keys())
                enabled = []
                for p_name in prov_list:
                    if self._enable_provider_native(p_name):
                        enabled.append(p_name)

                # Start background event consumer (attaches OpenTraceW/ProcessTrace when session owned)
                self._start_event_consumer()
                native_active = bool(self._native_consumer_active)
                self.status_description = "NATIVE_ETW_ACTIVE" if native_active else "ACTIVE_SESSION_EVENTLOG_POLLING"

                return {
                    "status": "success",
                    "session_name": self.session_name,
                    "mode": "NATIVE_REALTIME_ETW" if native_active else "WIN32_SESSION_EVENTLOG_POLLING",
                    "is_simulated": False,
                    "source": "live_win32_etw_native" if native_active else "live_win32_session_with_eventlog_polling",
                    "etw_native_consumer_active": native_active,
                    "event_consumption_backend": "ADVAPI32_OPENTRACE_PROCESSTRACE+WEVTAPI" if native_active else "WEVTAPI_EVENT_LOG_POLLING",
                    "consumer_note": (
                        "Trace session opened via StartTraceW and consuming real-time EVENT_RECORD frames via OpenTraceW/ProcessTrace."
                        if native_active else
                        "Trace session opened via StartTraceW; OpenTraceW unavailable, polling Event Log / module deltas."
                    ),
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
                    "is_simulated": False,
                    "etw_native_consumer_active": False,
                    "event_consumption_backend": "WEVTAPI_EVENT_LOG_POLLING",
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

    @staticmethod
    def _classify_event_log_record(channel: str, ev_id: int, default_level: str) -> str:
        """Maps Windows Event Log channel + Event ID to canonical telemetry category without branch shadowing."""
        if channel == "System" and ev_id in (41, 1001):
            return "KERNEL_POWER_OR_BUGCHECK"
        if ev_id == 1000:
            return "APPLICATION_ERROR"
        if ev_id == 1001:
            return "WER_REPORT"
        if ev_id == 1002:
            return "APPLICATION_HANG"
        if ev_id in (10000, 10001):
            return "RESTART_MANAGER_LOCK"
        return default_level or "INFO"

    def _start_native_etw_consumer(self) -> bool:
        """
        Attaches a genuine Win32 OpenTraceW / ProcessTrace EVENT_RECORD consumer
        when the session owns an active kernel ETW trace session.
        """
        if os.name != "nt" or not self._owns_session:
            return False
        try:
            advapi32 = ctypes.windll.advapi32
            ole32 = ctypes.windll.ole32

            class _GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            class _SYSTEMTIME(ctypes.Structure):
                _fields_ = [
                    ("wYear", wintypes.WORD), ("wMonth", wintypes.WORD), ("wDayOfWeek", wintypes.WORD),
                    ("wDay", wintypes.WORD), ("wHour", wintypes.WORD), ("wMinute", wintypes.WORD),
                    ("wSecond", wintypes.WORD), ("wMilliseconds", wintypes.WORD),
                ]

            class _TZ_INFO(ctypes.Structure):
                _fields_ = [
                    ("Bias", wintypes.LONG), ("StandardName", wintypes.WCHAR * 32), ("StandardDate", _SYSTEMTIME),
                    ("StandardBias", wintypes.LONG), ("DaylightName", wintypes.WCHAR * 32),
                    ("DaylightDate", _SYSTEMTIME), ("DaylightBias", wintypes.LONG),
                ]

            class _ET_HDR(ctypes.Structure):
                _fields_ = [
                    ("Size", wintypes.USHORT), ("HeaderType", ctypes.c_ubyte), ("MarkerFlags", ctypes.c_ubyte),
                    ("Version", ctypes.c_ubyte * 4), ("ThreadId", wintypes.ULONG), ("ProcessId", wintypes.ULONG),
                    ("TimeStamp", ctypes.c_int64), ("Guid", _GUID), ("ClientContext", wintypes.ULONG),
                    ("Flags", wintypes.ULONG),
                ]

            class _BUF_CTX(ctypes.Structure):
                _fields_ = [("ProcessorNumber", ctypes.c_ubyte), ("Alignment", ctypes.c_ubyte), ("LoggerId", wintypes.USHORT)]

            class _ET(ctypes.Structure):
                _fields_ = [
                    ("Header", _ET_HDR), ("InstanceId", wintypes.ULONG), ("ParentInstanceId", wintypes.ULONG),
                    ("ParentGuid", _GUID), ("MofData", ctypes.c_void_p), ("MofLength", wintypes.ULONG),
                    ("BufferContext", _BUF_CTX),
                ]

            class _TL_HDR(ctypes.Structure):
                _fields_ = [
                    ("BufferSize", wintypes.ULONG), ("Version", wintypes.ULONG), ("ProviderVersion", wintypes.ULONG),
                    ("NumberOfProcessors", wintypes.ULONG), ("EndTime", ctypes.c_int64), ("TimerResolution", wintypes.ULONG),
                    ("MaximumFileSize", wintypes.ULONG), ("LogFileMode", wintypes.ULONG), ("BuffersWritten", wintypes.ULONG),
                    ("LogInstanceGuid", _GUID), ("LoggerName", wintypes.LPWSTR), ("LogFileName", wintypes.LPWSTR),
                    ("TimeZone", _TZ_INFO), ("BootTime", ctypes.c_int64), ("PerfFreq", ctypes.c_int64),
                    ("StartTime", ctypes.c_int64), ("ReservedFlags", wintypes.ULONG), ("BuffersLost", wintypes.ULONG),
                ]

            class _EVENT_TRACE_LOGFILEW(ctypes.Structure):
                _fields_ = [
                    ("LogFileName", wintypes.LPWSTR), ("LoggerName", wintypes.LPWSTR), ("CurrentTime", ctypes.c_int64),
                    ("BuffersRead", wintypes.ULONG), ("ProcessTraceMode", wintypes.ULONG),
                    ("CurrentEvent", _ET), ("LogfileHeader", _TL_HDR),
                    ("BufferCallback", ctypes.c_void_p), ("BufferSize", wintypes.ULONG),
                    ("Filled", wintypes.ULONG), ("EventsLost", wintypes.ULONG),
                    ("EventRecordCallback", ctypes.c_void_p), ("IsKernelTrace", wintypes.ULONG),
                    ("Context", ctypes.c_void_p),
                ]

            class _EVENT_DESCRIPTOR(ctypes.Structure):
                _fields_ = [
                    ("Id", wintypes.USHORT), ("Version", ctypes.c_ubyte), ("Channel", ctypes.c_ubyte),
                    ("Level", ctypes.c_ubyte), ("Opcode", ctypes.c_ubyte), ("Task", wintypes.USHORT),
                    ("Keyword", ctypes.c_uint64),
                ]

            class _EVENT_HEADER(ctypes.Structure):
                _fields_ = [
                    ("Size", wintypes.USHORT), ("HeaderType", wintypes.USHORT), ("Flags", wintypes.USHORT),
                    ("EventProperty", wintypes.USHORT), ("ThreadId", wintypes.ULONG), ("ProcessId", wintypes.ULONG),
                    ("TimeStamp", ctypes.c_int64), ("ProviderId", _GUID),
                    ("EventDescriptor", _EVENT_DESCRIPTOR), ("ProcessorTime", ctypes.c_uint64),
                    ("ActivityId", _GUID),
                ]

            class _EVENT_RECORD(ctypes.Structure):
                _fields_ = [
                    ("EventHeader", _EVENT_HEADER), ("BufferContext", _BUF_CTX),
                    ("ExtendedDataCount", wintypes.USHORT), ("UserDataLength", wintypes.USHORT),
                    ("ExtendedData", ctypes.c_void_p), ("UserData", ctypes.c_void_p),
                    ("UserContext", ctypes.c_void_p),
                ]

            # Build normalized GUID -> provider name lookup map
            guid_to_name: Dict[Tuple[int, int, int, Tuple[int, ...]], str] = {}
            for p_name, g_str in KNOWN_PROVIDER_GUIDS.items():
                g = _GUID()
                if ole32.CLSIDFromString(ctypes.c_wchar_p(g_str), ctypes.byref(g)) == 0:
                    guid_to_name[(g.Data1, g.Data2, g.Data3, tuple(g.Data4))] = p_name

            def _on_event_record(rec_ptr):
                if self._stop_event.is_set() or not rec_ptr:
                    return
                try:
                    hdr = rec_ptr.contents.EventHeader
                    ev_pid = int(hdr.ProcessId)
                    ev_tid = int(hdr.ThreadId)
                    if self.target_pid is not None and ev_pid != self.target_pid:
                        return
                    ev_id = int(hdr.EventDescriptor.Id)
                    opcode = int(hdr.EventDescriptor.Opcode)
                    g = hdr.ProviderId
                    p_name = guid_to_name.get(
                        (g.Data1, g.Data2, g.Data3, tuple(g.Data4)),
                        f"{{{g.Data1:08X}-{g.Data2:04X}-{g.Data3:04X}}}",
                    )
                    # Convert FILETIME (100ns since 1601) when valid, otherwise wall-clock epoch
                    raw_ts = int(hdr.TimeStamp)
                    if 125_000_000_000_000_000 <= raw_ts <= 160_000_000_000_000_000:
                        ts = (raw_ts - 116_444_736_000_000_000) / 10_000_000.0
                    else:
                        ts = time.time()

                    ev_type = f"ETW_EVENT_{ev_id}"
                    if p_name == "Microsoft-Windows-Kernel-Process":
                        ev_type = {
                            1: "PROCESS_START",
                            2: "PROCESS_STOP",
                            3: "THREAD_START",
                            4: "THREAD_STOP",
                            5: "IMAGE_LOAD",
                            6: "IMAGE_UNLOAD",
                        }.get(ev_id, f"KERNEL_PROCESS_{ev_id}")
                    elif p_name == "Microsoft-Windows-Kernel-Memory":
                        ev_type = "VIRTUAL_FREE" if (ev_id in (2, 10) or opcode == 2) else "VIRTUAL_ALLOC"
                    elif p_name in ("Microsoft-Windows-Direct3D11", "Microsoft-Windows-DXGI"):
                        if hdr.EventDescriptor.Level <= 2:
                            ev_type = "DEVICE_REMOVED" if ev_id in (10, 11, 20) else "ERROR"

                    self.record_event(EtwEventRecord(
                        timestamp=ts,
                        provider_name=p_name,
                        event_id=ev_id,
                        pid=ev_pid,
                        tid=ev_tid,
                        event_type=ev_type,
                        opcode=opcode,
                        details={"native_etw": True, "user_data_length": int(rec_ptr.contents.UserDataLength)},
                        source="etw_native",
                    ))
                except Exception as cb_err:
                    self._consumer_errors.append(f"etw_callback_error: {cb_err}")

            CB_TYPE = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_EVENT_RECORD))
            cb_inst = CB_TYPE(_on_event_record)

            logfile = _EVENT_TRACE_LOGFILEW()
            logfile.LoggerName = ctypes.c_wchar_p(self.session_name)
            # PROCESS_TRACE_MODE_REAL_TIME (0x100) | PROCESS_TRACE_MODE_EVENT_RECORD (0x10000000)
            logfile.ProcessTraceMode = 0x00000100 | 0x10000000
            logfile.EventRecordCallback = ctypes.cast(cb_inst, ctypes.c_void_p)

            advapi32.OpenTraceW.argtypes = [ctypes.POINTER(_EVENT_TRACE_LOGFILEW)]
            advapi32.OpenTraceW.restype = ctypes.c_uint64
            advapi32.ProcessTrace.argtypes = [
                ctypes.POINTER(ctypes.c_uint64), wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p
            ]
            advapi32.ProcessTrace.restype = wintypes.ULONG

            h_trace = int(advapi32.OpenTraceW(ctypes.byref(logfile)))
            INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF
            if h_trace == 0 or h_trace == INVALID_HANDLE:
                return False

            self._native_callback_ref = cb_inst
            self._native_trace_handle = h_trace
            self._native_consumer_active = True

            def _pump_process_trace():
                try:
                    arr = (ctypes.c_uint64 * 1)(h_trace)
                    advapi32.ProcessTrace(arr, 1, None, None)
                except Exception as pt_err:
                    self._consumer_errors.append(f"ProcessTrace error: {pt_err}")

            self._native_consumer_thread = threading.Thread(target=_pump_process_trace, daemon=True)
            self._native_consumer_thread.start()
            return True
        except Exception as err:
            self._consumer_errors.append(f"OpenTraceW setup failed: {err}")
            return False

    def _start_event_consumer(self) -> None:
        """Starts native OpenTraceW/ProcessTrace consumer (when elevated) plus EventLog & module delta monitor."""
        if os.name == "nt" and self._owns_session:
            self._start_native_etw_consumer()

        def _consumer_loop():
            from .event_log_collector import EventLogCollector
            seen_events: "OrderedDict[tuple, bool]" = OrderedDict()
            MAX_SEEN = 5000
            known_modules: Optional[Dict[str, Tuple[str, str]]] = None
            last_tracked_pid: Optional[int] = None

            while not self._stop_event.is_set():
                try:
                    for channel in ("Application", "System"):
                        evs = EventLogCollector.query_events(channel, limit=15)
                        for ev in evs:
                            ev_pid = ev.get("process_id", 0)
                            key = (
                                ev.get("provider_name"),
                                ev.get("event_id"),
                                ev.get("time_created"),
                                ev_pid,
                                ev.get("thread_id"),
                            )
                            if key in seen_events:
                                seen_events.move_to_end(key)
                                continue
                            seen_events[key] = True
                            while len(seen_events) > MAX_SEEN:
                                seen_events.popitem(last=False)

                            # Exclude PID=0 global EventLog noise when monitoring a specific PID
                            admit = (self.target_pid is None) or (ev_pid == self.target_pid)
                            if admit:
                                ev_id = ev.get("event_id", 0)
                                ev_type = self._classify_event_log_record(channel, ev_id, ev.get("level", "INFO"))
                                rec = EtwEventRecord(
                                    timestamp=ev.get("time_created", time.time()),
                                    provider_name=ev.get("provider_name", channel),
                                    event_id=ev_id,
                                    pid=ev_pid,
                                    tid=ev.get("thread_id", 0),
                                    event_type=ev_type,
                                    details={"message": ev.get("message", "")[:120], **ev.get("details", {})},
                                    source="event_log_polling",
                                )
                                self.record_event(rec)

                    # Dynamic Toolhelp32 module tracking for targeted PID (works if target_pid is set before or after session start)
                    curr_pid = self.target_pid
                    if curr_pid and os.name == "nt":
                        from windows_intelligence.process_intelligence import ModuleInventory
                        if curr_pid != last_tracked_pid or known_modules is None:
                            last_tracked_pid = curr_pid
                            known_modules = {}
                            try:
                                mod_res = ModuleInventory.get_modules_for_process(curr_pid)
                                now_t = time.time()
                                for m in mod_res.get("modules", []):
                                    m_name = str(m.get("module_name", ""))
                                    low_name = m_name.lower()
                                    b_addr = str(m.get("base_address", "0x0"))
                                    known_modules[low_name] = (m_name, b_addr)
                                    self.record_event(EtwEventRecord(
                                        timestamp=now_t,
                                        provider_name="Bintra-Toolhelp32-ModuleMonitor",
                                        event_id=5,
                                        pid=curr_pid,
                                        tid=0,
                                        event_type="IMAGE_LOAD",
                                        details={"image_name": m_name, "base_address": b_addr, "baseline": True},
                                        source="toolhelp_module_baseline",
                                    ))
                            except Exception as mod_err:
                                self._consumer_errors.append(f"Module baseline failed: {mod_err}")
                        else:
                            # Delta tracking: new loads and unloads
                            try:
                                mod_res = ModuleInventory.get_modules_for_process(curr_pid)
                                current_mods = {
                                    str(m.get("module_name", "")).lower(): (str(m.get("module_name", "")), str(m.get("base_address", "0x0")))
                                    for m in mod_res.get("modules", [])
                                }
                                now_t = time.time()
                                for low_name, (orig_name, base_addr) in current_mods.items():
                                    if low_name not in known_modules:
                                        known_modules[low_name] = (orig_name, base_addr)
                                        self.record_event(EtwEventRecord(
                                            timestamp=now_t,
                                            provider_name="Bintra-Toolhelp32-ModuleMonitor",
                                            event_id=5,
                                            pid=curr_pid,
                                            tid=0,
                                            event_type="IMAGE_LOAD",
                                            details={"image_name": orig_name, "base_address": base_addr},
                                            source="toolhelp_module_delta",
                                        ))
                                # Detect unloads
                                unloaded_names = [k for k in known_modules if k not in current_mods]
                                for low_name in unloaded_names:
                                    orig_name, base_addr = known_modules.pop(low_name)
                                    self.record_event(EtwEventRecord(
                                        timestamp=now_t,
                                        provider_name="Bintra-Toolhelp32-ModuleMonitor",
                                        event_id=6,
                                        pid=curr_pid,
                                        tid=0,
                                        event_type="IMAGE_UNLOAD",
                                        details={"image_name": orig_name, "base_address": base_addr},
                                        source="toolhelp_module_delta",
                                    ))
                            except Exception as delta_err:
                                self._consumer_errors.append(f"Module delta failed: {delta_err}")
                except Exception as exc:
                    self._consumer_errors.append(f"consumer_loop error: {exc}")
                self._stop_event.wait(0.5)

        self._consumer_thread = threading.Thread(target=_consumer_loop, daemon=True)
        self._consumer_thread.start()

    def stop_session(self) -> Dict[str, Any]:
        """Stops the real-time ETW trace session and releases kernel and consumer handles."""
        self.is_running = False
        self._stop_event.set()
        duration = round(time.time() - (self.start_time or time.time()), 3)

        if os.name == "nt" and self._native_trace_handle:
            try:
                advapi32 = ctypes.windll.advapi32
                advapi32.CloseTrace.argtypes = [ctypes.c_uint64]
                advapi32.CloseTrace.restype = wintypes.ULONG
                advapi32.CloseTrace(self._native_trace_handle)
            except Exception as err:
                self._consumer_errors.append(f"CloseTrace error: {err}")
            finally:
                self._native_trace_handle = None
                self._native_consumer_active = False

        if os.name == "nt":
            self._stop_session_native()

        for t in (self._native_consumer_thread, self._consumer_thread):
            if t and t.is_alive():
                t.join(timeout=1.0)

        return {
            "status": "stopped",
            "session_name": self.session_name,
            "duration_seconds": duration,
            "captured_events_buffered": len(self.events_buffer),
            "consumer_errors_count": len(self._consumer_errors),
            "consumer_errors": list(self._consumer_errors),
        }

    def _register_atexit_cleanup(self) -> None:
        """Registers an interpreter-exit guard so owned native ETW trace sessions do not leak."""
        if getattr(self, "_atexit_registered", False):
            return
        import atexit
        import weakref
        self._atexit_registered = True
        self_ref = weakref.ref(self)

        def _cleanup():
            inst = self_ref()
            if inst is not None and getattr(inst, "_owns_session", False):
                inst.stop_session()

        atexit.register(_cleanup)

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
        except Exception:
            pass
        finally:
            self._owns_session = False

    def record_event(self, event: EtwEventRecord) -> None:
        """Ingests an event into the ring buffer, filtering by target PID if set."""
        if self.target_pid is not None and event.pid != 0 and event.pid != self.target_pid:
            return
        self.events_buffer.append(event)

    def get_timeline(
        self,
        pid: Optional[int] = None,
        limit: int = 100,
        include_global: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """
        Extracts ordered chronological event timeline from the buffer.
        When an explicit pid is passed, pid==0 global events are excluded by default
        (set include_global=True to include them).
        """
        target = pid if pid is not None else self.target_pid
        events = list(self.events_buffer)
        if target is not None:
            allow_zero = include_global if include_global is not None else (pid is None)
            if allow_zero:
                events = [e for e in events if e.pid == target or e.pid == 0]
            else:
                events = [e for e in events if e.pid == target]
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

        # 6. Look for Kernel-Power / BugCheck events (System ID 41/1001)
        bugchecks = [e for e in timeline_events if e.get("event_type") == "KERNEL_POWER_OR_BUGCHECK"]
        if bugchecks:
            findings.append({
                "category": "KERNEL_POWER_OR_BUGCHECK",
                "significance": "CRITICAL",
                "description": f"{len(bugchecks)} System BugCheck/Kernel-Power unexpected termination event(s) detected."
            })

        # 7. Event provenance accounting
        event_sources: Dict[str, int] = {}
        for ev in timeline_events:
            src = ev.get("source", "unknown")
            event_sources[src] = event_sources.get(src, 0) + 1

        # 8. Overall verdict
        if any(f["category"] == "MEMORY_DEALLOCATION" for f in findings):
            verdict = "TEMPORAL_MEMORY_CHURN_DETECTED"
        elif recent_dll_loads:
            verdict = "LATE_MODULE_INJECTION_DETECTED"
        elif gpu_resets:
            verdict = "GRAPHICS_PIPELINE_RESET_DETECTED"
        elif bugchecks:
            verdict = "KERNEL_BUGCHECK_RECORDED"
        elif rm_events:
            verdict = "FILE_LOCK_CONTENTION_DETECTED"
        elif prev_faults:
            verdict = "RECURRENT_APPLICATION_FAULT_DETECTED"
        else:
            verdict = "STABLE_PRE_CRASH_TIMELINE"

        return {
            "events_count": len(timeline_events),
            "event_sources": event_sources,
            "has_native_etw_events": event_sources.get("etw_native", 0) > 0,
            "reference_crash_timestamp": ref_time,
            "temporal_verdict": verdict,
            "causality_findings": findings,
            "timeline_sample": timeline_events[-20:]
        }

    @classmethod
    def format_markdown(cls, correlation_report: Dict[str, Any]) -> str:
        """Formats the ETW timeline correlation into an executive Markdown report."""
        lines = [
            "# Bintra ETW Diagnostic Timeline Correlation",
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
