# -*- coding: utf-8 -*-
"""
Event Tracing for Windows (ETW) Subsystem & Provider Inspector.
Queries active ETW trace sessions and interrogates critical diagnostic providers
(Kernel-Process, Direct3D11, DXGI, DxgKrnl, Kernel-File) via advapi32.dll ControlTraceW.
"""

import os
import sys
import struct
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", wintypes.ULONG),
        ("ProviderId", wintypes.ULONG),
        ("HistoricalContext", ctypes.c_uint64),
        ("TimeStamp", ctypes.c_int64),
        ("Guid", ctypes.c_byte * 16),
        ("ClientContext", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", wintypes.ULONG),
        ("MinimumBuffers", wintypes.ULONG),
        ("MaximumBuffers", wintypes.ULONG),
        ("MaximumFileSize", wintypes.ULONG),
        ("LogFileMode", wintypes.ULONG),
        ("FlushTimer", wintypes.ULONG),
        ("EnableFlags", wintypes.ULONG),
        ("AgeLimit", wintypes.LONG),
        ("NumberOfBuffers", wintypes.ULONG),
        ("FreeBuffers", wintypes.ULONG),
        ("EventsLost", wintypes.ULONG),
        ("BuffersWritten", wintypes.ULONG),
        ("LogBuffersLost", wintypes.ULONG),
        ("RealTimeBuffersLost", wintypes.ULONG),
        ("LoggerThreadId", wintypes.HANDLE),
        ("LogFileNameOffset", wintypes.ULONG),
        ("LoggerNameOffset", wintypes.ULONG),
    ]


class EtwController:
    """
    Non-destructive ETW session and diagnostic provider inspection engine.
    Uses Win32 advapi32 ControlTraceW with EVENT_TRACE_CONTROL_QUERY.
    """

    # Curated knowledge catalog of high-value diagnostic ETW providers
    CATALOG_DIAGNOSTIC_PROVIDERS = {
        "Microsoft-Windows-Kernel-Process": {
            "guid": "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}",
            "category": "Process & Thread Lifecycle",
            "keywords": ["WINEVENT_KEYWORD_PROCESS", "WINEVENT_KEYWORD_THREAD", "WINEVENT_KEYWORD_IMAGE"],
            "diagnostic_value": "Tracks process creation, thread crashes, and DLL image loading."
        },
        "Microsoft-Windows-Kernel-File": {
            "guid": "{EDD08927-9CC4-4E65-B970-C2560F5C4C82}",
            "category": "File I/O & Storage",
            "keywords": ["FILE_IO", "FILENAME"],
            "diagnostic_value": "Audits missing application assets, read locks, and storage contention."
        },
        "Microsoft-Windows-Kernel-Network": {
            "guid": "{7DD42A49-5329-4832-8DFD-43D979153A88}",
            "category": "Networking & Sockets",
            "keywords": ["TCPIP", "UDP"],
            "diagnostic_value": "Diagnoses client-server handshake drops and socket binding errors."
        },
        "Microsoft-Windows-Direct3D11": {
            "guid": "{DB6F6DDB-AC77-4E88-8E81-8B010C2C31E9}",
            "category": "Graphics (Direct3D 11)",
            "keywords": ["D3D11_DEVICE", "D3D11_CONTEXT"],
            "diagnostic_value": "Identifies shader compile failures and DirectX device creation faults."
        },
        "Microsoft-Windows-DXGI": {
            "guid": "{CA11C036-0102-4503-AC64-283040314001}",
            "category": "Graphics (DXGI / Presentation)",
            "keywords": ["PRESENT", "DEVICE_REMOVED"],
            "diagnostic_value": "Captures DXGI_ERROR_DEVICE_REMOVED and fullscreen swapchain resets."
        },
        "Microsoft-Windows-DxgKrnl": {
            "guid": "{802EC45A-1E99-4B83-9920-87C98277BA9D}",
            "category": "Kernel Graphics Driver (WDDM)",
            "keywords": ["TDR", "SCHEDULER"],
            "diagnostic_value": "Detects GPU Timeout Detection and Recovery (TDR) driver hangs."
        },
        "Microsoft-Windows-Application-Experience": {
            "guid": "{8A54B4B1-6D55-46DF-BF8A-85C1181FA11A}",
            "category": "AppCompat & Shims",
            "keywords": ["SHIM_APPLIED", "COMPAT_EVAL"],
            "diagnostic_value": "Traces AppCompatFlags runtime emulation layers applied to binaries."
        },
        "Microsoft-Windows-Kernel-PnP": {
            "guid": "{9C205A39-1250-487D-ABD7-E831C62907E2}",
            "category": "Hardware & PnP Lifecycle",
            "keywords": ["PNP_ENUMERATION", "PNP_DRIVER_START", "PNP_PROBLEM"],
            "diagnostic_value": "Tracks hardware device attachment, removal, driver binding, and CM_PROB_* errors."
        },
        "Microsoft-Windows-USB-USBHUB3": {
            "guid": "{AC52AD17-CC01-4F07-BE22-83AAF68F7EF8}",
            "category": "Hardware Ports (USB 3.0 Hub)",
            "keywords": ["PORT_STATUS", "DEVICE_CONNECT", "POWER_STATE"],
            "diagnostic_value": "Audits SuperSpeed USB 3.0 Hub port state transitions and peripheral handshakes."
        },
        "Microsoft-Windows-USB-UCX": {
            "guid": "{36DA065A-25EF-42A7-BD1B-38BB878633D9}",
            "category": "Hardware Ports (USB Host Controller)",
            "keywords": ["CONTROLLER_RESET", "ENDPOINT_PIPE"],
            "diagnostic_value": "Diagnoses USB host controller driver faults and endpoint pipe stalls."
        },
        "Microsoft-Windows-Kernel-Disk": {
            "guid": "{C7BDE69A-E1E0-4142-B506-1E00F13196E6}",
            "category": "Storage & Physical Disk",
            "keywords": ["DISK_IO", "DRIVER_LATENCY"],
            "diagnostic_value": "Measures physical disk I/O request packets, response latency, and storage hardware health."
        }
    }
    # Backward compatibility alias
    KNOWN_PROVIDERS = CATALOG_DIAGNOSTIC_PROVIDERS

    STANDARD_SESSIONS = [
        "Eventlog-Application",
        "Eventlog-System",
        "DiagLog",
        "Circular Kernel Context Logger",
        "NT Kernel Logger",
        "WdiContextLog",
        "ScreenOn"
    ]

    ERROR_CODES = {
        0: "ACTIVE_ACCESSIBLE",
        5: "SYSTEM_PROTECTED (Access Denied / Elevated Session)",
        4201: "INACTIVE (Not Running)",
        161: "INVALID_PATH",
        87: "INVALID_PARAMETER"
    }

    @classmethod
    def query_trace_session(cls, session_name: str) -> Dict[str, Any]:
        """
        Queries an active ETW trace session status using ControlTraceW with EVENT_TRACE_CONTROL_QUERY (0).
        """
        if os.name != "nt":
            return {"status": "error", "error": "ETW requires Windows NT", "session_name": session_name}

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
            prop.LogFileNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 512

            status_code = advapi32.ControlTraceW(0, session_name, prop_ptr, 0)
            status_desc = cls.ERROR_CODES.get(status_code, f"Win32_Error_{status_code}")

            is_active = status_code in (0, 5)
            session_info: Dict[str, Any] = {
                "session_name": session_name,
                "is_active": is_active,
                "is_accessible": status_code == 0,
                "is_system_protected": status_code == 5,
                "status_code": status_code,
                "status_description": status_desc
            }

            if status_code == 0:
                session_info["buffers_written"] = prop.BuffersWritten
                session_info["events_lost"] = prop.EventsLost
                session_info["number_of_buffers"] = prop.NumberOfBuffers
                session_info["free_buffers"] = prop.FreeBuffers

            return session_info
        except Exception as e:
            return {"session_name": session_name, "is_active": False, "is_accessible": False, "is_system_protected": False, "error": str(e)}

    @classmethod
    def enumerate_registered_providers(cls, query: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """
        Dynamically enumerates registered ETW providers on the host system via tdh.dll (TdhEnumerateProviders).
        Supports case-insensitive keyword filtering by provider name or GUID.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "ETW provider enumeration requires Windows NT."
            }

        try:
            tdh = ctypes.WinDLL("tdh.dll")

            class GUID_STRUCT(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8)
                ]
                def to_str(self) -> str:
                    d4_1 = "".join(f"{b:02X}" for b in self.Data4[:2])
                    d4_2 = "".join(f"{b:02X}" for b in self.Data4[2:])
                    return f"{{{self.Data1:08X}-{self.Data2:04X}-{self.Data3:04X}-{d4_1}-{d4_2}}}"

            class TRACE_PROVIDER_INFO(ctypes.Structure):
                _fields_ = [
                    ("ProviderGuid", GUID_STRUCT),
                    ("SchemaSource", wintypes.ULONG),
                    ("ProviderNameOffset", wintypes.ULONG)
                ]

            buf_size = wintypes.ULONG(0)
            tdh.TdhEnumerateProviders(None, ctypes.byref(buf_size))
            if buf_size.value == 0:
                return {"status": "error", "message": "TdhEnumerateProviders returned 0 buffer size."}

            buf = ctypes.create_string_buffer(buf_size.value)
            res = tdh.TdhEnumerateProviders(ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(buf_size))
            if res != 0:
                return {"status": "error", "error_code": res, "message": f"TdhEnumerateProviders failed with {res}."}

            num_providers = wintypes.ULONG.from_buffer_copy(buf[:4]).value
            item_size = ctypes.sizeof(TRACE_PROVIDER_INFO)
            matches = []

            q_lower = query.lower() if query else None

            for i in range(num_providers):
                off = 8 + (i * item_size)
                if off + item_size > buf_size.value:
                    break
                item = TRACE_PROVIDER_INFO.from_buffer_copy(buf[off:off+item_size])
                name_off = item.ProviderNameOffset
                if name_off < buf_size.value:
                    raw = buf[name_off:]
                    idx = 0
                    while idx < len(raw) - 1:
                        if raw[idx] == 0 and raw[idx+1] == 0:
                            break
                        idx += 2
                    name = raw[:idx].decode("utf-16le", errors="ignore")
                else:
                    name = "UNKNOWN"

                guid_str = item.ProviderGuid.to_str()
                if not q_lower or q_lower in name.lower() or q_lower in guid_str.lower():
                    matches.append({
                        "name": name,
                        "guid": guid_str,
                        "schema_source": "MANIFEST" if item.SchemaSource == 0 else "MOF"
                    })

            return {
                "status": "success",
                "total_system_providers": num_providers,
                "matched_count": len(matches),
                "filter": query,
                "providers": matches[:limit],
                "truncated": len(matches) > limit
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @classmethod
    def audit_active_kernel_providers(cls, limit: int = 50) -> Dict[str, Any]:
        """
        Enumerates all ETW providers actively registered with the Windows kernel via advapi32.dll EnumerateTraceGuidsEx.
        """
        if os.name != "nt":
            return {"status": "not_applicable", "platform": sys.platform}

        try:
            advapi32 = ctypes.WinDLL("advapi32.dll")
            ret_len = wintypes.ULONG(0)
            res = advapi32.EnumerateTraceGuidsEx(0, None, 0, None, 0, ctypes.byref(ret_len))
            if ret_len.value == 0:
                return {"status": "error", "message": f"EnumerateTraceGuidsEx failed with code {res}."}

            buf = ctypes.create_string_buffer(ret_len.value)
            res2 = advapi32.EnumerateTraceGuidsEx(0, None, 0, ctypes.cast(buf, ctypes.c_void_p), ret_len.value, ctypes.byref(ret_len))
            if res2 != 0:
                return {"status": "error", "error_code": res2}

            count = ret_len.value // 16
            guids = []
            for i in range(min(count, limit)):
                off = i * 16
                raw_g = buf[off:off+16]
                d1, d2, d3 = struct.unpack_from("<IHH", raw_g, 0)
                d4_1 = "".join(f"{b:02X}" for b in raw_g[8:10])
                d4_2 = "".join(f"{b:02X}" for b in raw_g[10:16])
                guids.append(f"{{{d1:08X}-{d2:04X}-{d3:04X}-{d4_1}-{d4_2}}}")

            return {
                "status": "success",
                "active_kernel_providers_count": count,
                "sample_guids": guids
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @classmethod
    def query_provider_instances(cls, guid_str: str) -> Dict[str, Any]:
        """
        Interrogates live kernel registration of a specific ETW provider.
        Identifies process IDs (PIDs) hosting the provider and their active enable status.
        """
        if os.name != "nt":
            return {"status": "not_applicable", "platform": sys.platform}

        try:
            ole32 = ctypes.WinDLL("ole32.dll")
            advapi32 = ctypes.WinDLL("advapi32.dll")

            class GUID_STRUCT(ctypes.Structure):
                _fields_ = [
                    ("Data1", wintypes.DWORD),
                    ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD),
                    ("Data4", wintypes.BYTE * 8)
                ]

            class TRACE_PROVIDER_INSTANCE_INFO(ctypes.Structure):
                _fields_ = [
                    ("NextOffset", wintypes.ULONG),
                    ("EnableCount", wintypes.ULONG),
                    ("Pid", wintypes.ULONG),
                    ("Flags", wintypes.ULONG)
                ]

            guid = GUID_STRUCT()
            hr = ole32.CLSIDFromString(ctypes.c_wchar_p(guid_str), ctypes.byref(guid))
            if hr != 0:
                return {"status": "error", "error": f"Invalid GUID format: '{guid_str}'"}

            ret_len = wintypes.ULONG(0)
            res = advapi32.EnumerateTraceGuidsEx(1, ctypes.byref(guid), ctypes.sizeof(guid), None, 0, ctypes.byref(ret_len))
            # 122 = ERROR_INSUFFICIENT_BUFFER (expected on size query)
            if res not in (0, 122) or ret_len.value == 0:
                return {
                    "status": "dormant",
                    "guid": guid_str,
                    "is_active_in_kernel": False,
                    "instance_count": 0,
                    "instances": []
                }

            buf = ctypes.create_string_buffer(ret_len.value)
            res2 = advapi32.EnumerateTraceGuidsEx(1, ctypes.byref(guid), ctypes.sizeof(guid), ctypes.cast(buf, ctypes.c_void_p), ret_len.value, ctypes.byref(ret_len))
            if res2 != 0:
                return {"status": "error", "guid": guid_str, "error_code": res2}

            num_inst = wintypes.ULONG.from_buffer_copy(buf[:4]).value
            instances = []
            offset = 8
            for _ in range(num_inst):
                if offset + 16 > ret_len.value:
                    break
                inst = TRACE_PROVIDER_INSTANCE_INFO.from_buffer_copy(buf[offset:offset+16])
                instances.append({
                    "pid": inst.Pid,
                    "enable_count": inst.EnableCount,
                    "is_enabled": inst.EnableCount > 0,
                    "flags": inst.Flags
                })
                if inst.NextOffset == 0:
                    break
                offset += inst.NextOffset

            return {
                "status": "active",
                "guid": guid_str,
                "is_active_in_kernel": True,
                "instance_count": num_inst,
                "instances": instances
            }
        except Exception as e:
            return {"status": "error", "guid": guid_str, "error": str(e)}

    @classmethod
    def audit_etw_providers(cls) -> Dict[str, Any]:
        """Returns curated catalog of known high-value Windows kernel and graphics ETW diagnostic providers."""
        return {
            "status": "success",
            "total_providers": len(cls.CATALOG_DIAGNOSTIC_PROVIDERS),
            "providers": cls.CATALOG_DIAGNOSTIC_PROVIDERS
        }

    @classmethod
    def audit_telemetry_system(cls) -> Dict[str, Any]:
        """
        Runs comprehensive health audit of the host ETW telemetry infrastructure:
        - Evaluates known diagnostic providers.
        - Interrogates standard system and application trace sessions.
        - Quantifies total registered and kernel-active ETW providers.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "ETW telemetry requires a Windows NT host system."
            }
        sessions = [cls.query_trace_session(s) for s in cls.STANDARD_SESSIONS]
        active_sessions = [s for s in sessions if s.get("is_active")]
        accessible_sessions = [s for s in sessions if s.get("is_accessible")]
        protected_sessions = [s for s in sessions if s.get("is_system_protected")]

        system_total_providers = 0
        active_kernel_guids = 0
        try:
            tdh = ctypes.WinDLL("tdh.dll")
            buf_size = wintypes.ULONG(0)
            tdh.TdhEnumerateProviders(None, ctypes.byref(buf_size))
            if buf_size.value > 4:
                buf = ctypes.create_string_buffer(buf_size.value)
                if tdh.TdhEnumerateProviders(ctypes.cast(buf, ctypes.c_void_p), ctypes.byref(buf_size)) == 0:
                    system_total_providers = wintypes.ULONG.from_buffer_copy(buf[:4]).value
        except Exception:
            pass

        try:
            adv = ctypes.WinDLL("advapi32.dll")
            ret_len = wintypes.ULONG(0)
            adv.EnumerateTraceGuidsEx(0, None, 0, None, 0, ctypes.byref(ret_len))
            active_kernel_guids = ret_len.value // 16
        except Exception:
            pass

        return {
            "status": "success",
            "is_windows": os.name == "nt",
            "standard_sessions_probed": len(sessions),
            "active_sessions_count": len(active_sessions),
            "accessible_sessions_count": len(accessible_sessions),
            "system_protected_sessions_count": len(protected_sessions),
            "system_total_registered_providers": system_total_providers,
            "active_kernel_providers_count": active_kernel_guids,
            "active_sessions": [s["session_name"] for s in active_sessions],
            "accessible_sessions": [s["session_name"] for s in accessible_sessions],
            "system_protected_sessions": [s["session_name"] for s in protected_sessions],
            "sessions": sessions,
            "registered_providers_count": len(cls.CATALOG_DIAGNOSTIC_PROVIDERS),
            "providers": cls.CATALOG_DIAGNOSTIC_PROVIDERS
        }

    @classmethod
    def capture_bounded_session(
        cls,
        session_name: str = "Bintra_Diagnostic_Trace",
        duration_sec: float = 2.0,
        provider_name: str = "Microsoft-Windows-Kernel-Process",
        workspace_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Attempts to create and collect a bounded, target-specific ETW trace session.
        Uses Win32 StartTraceW and ControlTraceW via advapi32.dll with strict maximum file size constraints.
        Enforces fail-closed elevation checking: returns structured elevation requirement if unprivileged.
        """
        if os.name != "nt":
            return {"status": "error", "error": "ETW capture requires Windows NT"}

        advapi32 = ctypes.windll.advapi32
        out_dir = workspace_dir or os.path.abspath("./workspace")
        os.makedirs(out_dir, exist_ok=True)
        etl_path = os.path.join(out_dir, f"{session_name}.etl")

        s_name_bytes = (session_name + "\0").encode("utf-16le")
        log_path_bytes = (etl_path + "\0").encode("utf-16le")

        header_size = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        total_size = header_size + len(s_name_bytes) + len(log_path_bytes) + 64

        buf = ctypes.create_string_buffer(total_size)
        prop_ptr = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
        prop = prop_ptr.contents

        prop.Wnode.BufferSize = total_size
        prop.Wnode.Flags = 0x00020000  # WNODE_FLAG_TRACED_GUID
        prop.Wnode.ClientContext = 1  # QPC
        prop.LogFileMode = 0x00000002  # EVENT_TRACE_FILE_MODE_SEQUENTIAL
        prop.MaximumFileSize = 10  # 10 MB strict limit to prevent disk exhaustion

        name_offset = header_size
        file_offset = header_size + len(s_name_bytes)

        prop.LoggerNameOffset = name_offset
        prop.LogFileNameOffset = file_offset

        ctypes.memmove(ctypes.byref(buf, name_offset), s_name_bytes, len(s_name_bytes))
        ctypes.memmove(ctypes.byref(buf, file_offset), log_path_bytes, len(log_path_bytes))

        trace_handle = ctypes.c_uint64(0)
        advapi32.StartTraceW.argtypes = [ctypes.POINTER(ctypes.c_uint64), wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES)]
        advapi32.StartTraceW.restype = wintypes.ULONG

        status = advapi32.StartTraceW(ctypes.byref(trace_handle), session_name, prop_ptr)

        if status == 5:
            return {
                "status": "elevation_required",
                "session_name": session_name,
                "error_code": 5,
                "error": "ERROR_ACCESS_DENIED",
                "diagnostic_explanation": (
                    "Live ETW trace session creation requires administrative privileges (SE_SYSTEM_PROFILE_NAME) "
                    "or membership in the Windows 'Performance Log Users' group."
                ),
                "safe_alternatives": [
                    "Query existing active trace sessions via EtwController.query_trace_session()",
                    "Audit high-value provider schemas via EtwController.audit_etw_providers()",
                    "Collect empirical crash telemetry via MiniDumpParser and EventLogCollector"
                ]
            }
        elif status == 0:
            import time
            advapi32.ControlTraceW.argtypes = [ctypes.c_uint64, wintypes.LPCWSTR, ctypes.POINTER(EVENT_TRACE_PROPERTIES), wintypes.ULONG]
            advapi32.ControlTraceW.restype = wintypes.ULONG
            try:
                time.sleep(min(duration_sec, 5.0))
            finally:
                advapi32.ControlTraceW(trace_handle.value, session_name, prop_ptr, 1)  # EVENT_TRACE_CONTROL_STOP = 1
            return {
                "status": "success",
                "session_name": session_name,
                "etl_file": etl_path,
                "duration_seconds": duration_sec,
                "buffers_written": prop.BuffersWritten,
                "events_lost": prop.EventsLost
            }
        elif status == 183:  # ERROR_ALREADY_EXISTS
            return {
                "status": "already_active",
                "session_name": session_name,
                "error_code": 183,
                "error": "Session already active on host"
            }
        else:
            return {
                "status": "failed",
                "session_name": session_name,
                "error_code": status,
                "error": cls.ERROR_CODES.get(status, f"Win32_Error_{status}")
            }

