# -*- coding: utf-8 -*-
"""
Deep Windows Event Log Telemetry Collector.
Interrogates the Windows Event Log infrastructure via native Win32 WEVTAPI (wevtapi.dll)
with in-process XML rendering (EvtQuery, EvtNext, EvtRender) and fallback to wevtutil.
Extracts Event ID 1000 (Application Crash), 1001 (Windows Error Reporting),
1002 (Application Hang), and System Event 41/1001 (Kernel Power / BugCheck BSOD).
"""

import os
import ctypes
from ctypes import wintypes
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional


class EventLogCollector:
    """
    Collects structured crash and failure events from Windows Event Log channels.
    Extracts faulting binaries, exception codes, fault offsets, and WER problem signatures.
    Prefers native in-process Win32 wevtapi.dll, with automatic fallback to wevtutil.
    """

    COMMON_EXCEPTION_CODES = {
        0xC0000005: "STATUS_ACCESS_VIOLATION",
        0xC00000FD: "STATUS_STACK_OVERFLOW",
        0xC0000135: "STATUS_DLL_NOT_FOUND",
        0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
        0x80000003: "STATUS_BREAKPOINT",
        0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC0000374: "STATUS_HEAP_CORRUPTION",
        0xE06D7363: "STATUS_CPP_EXCEPTION"
    }

    LAST_QUERY_ERRORS: List[str] = []
    _wevtapi = None
    _EVT_HANDLE = wintypes.HANDLE
    _initialized = False
    _backend_used: str = "none"

    @classmethod
    def _init_native_wevtapi(cls) -> bool:
        """Initializes Win32 wevtapi.dll function bindings if running on Windows NT."""
        if cls._initialized:
            return cls._wevtapi is not None
        cls._initialized = True
        if os.name != "nt":
            return False
        try:
            wevtapi = ctypes.WinDLL("wevtapi.dll")
            cls._EVT_HANDLE = wintypes.HANDLE

            wevtapi.EvtQuery.restype = cls._EVT_HANDLE
            wevtapi.EvtQuery.argtypes = [cls._EVT_HANDLE, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]

            wevtapi.EvtNext.restype = wintypes.BOOL
            wevtapi.EvtNext.argtypes = [cls._EVT_HANDLE, wintypes.DWORD, ctypes.POINTER(cls._EVT_HANDLE), wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

            wevtapi.EvtRender.restype = wintypes.BOOL
            wevtapi.EvtRender.argtypes = [cls._EVT_HANDLE, cls._EVT_HANDLE, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)]

            wevtapi.EvtClose.restype = wintypes.BOOL
            wevtapi.EvtClose.argtypes = [cls._EVT_HANDLE]

            cls._wevtapi = wevtapi
            return True
        except Exception as e:
            cls.LAST_QUERY_ERRORS.append(f"wevtapi.dll native init failed: {e}")
            cls._wevtapi = None
            return False

    @classmethod
    def _execute_native_query(cls, channel: str, xpath: str, max_events: int = 20) -> Optional[List[ET.Element]]:
        """Queries Windows Event Log using in-process Win32 wevtapi.dll functions."""
        if not cls._init_native_wevtapi():
            return None

        # EvtQueryChannelPath (0x1) | EvtQueryReverseDirection (0x200)
        flags = 0x1 | 0x200
        try:
            h_query = cls._wevtapi.EvtQuery(None, channel, xpath, flags)
            if not h_query:
                err = ctypes.GetLastError()
                cls.LAST_QUERY_ERRORS.append(f"EvtQuery failed on channel '{channel}' (Win32 error {err})")
                return None

            events_array = (cls._EVT_HANDLE * max_events)()
            returned = wintypes.DWORD(0)
            nodes: List[ET.Element] = []

            try:
                ok = cls._wevtapi.EvtNext(h_query, max_events, events_array, 2000, 0, ctypes.byref(returned))
                count = returned.value
                err = ctypes.GetLastError()

                # If EvtNext failed with an error other than ERROR_NO_MORE_ITEMS (259) and yielded 0 records,
                # mark query as failed to trigger fallback rather than masking error.
                if not ok and err != 259 and count == 0:
                    cls.LAST_QUERY_ERRORS.append(f"EvtNext failed on channel '{channel}' (Win32 error {err})")
                    return None

                for i in range(count):
                    h_event = events_array[i]
                    if not h_event:
                        continue
                    try:
                        buf_size = wintypes.DWORD(0)
                        prop_count = wintypes.DWORD(0)
                        cls._wevtapi.EvtRender(None, h_event, 1, 0, None, ctypes.byref(buf_size), ctypes.byref(prop_count))
                        if buf_size.value > 0:
                            buf = ctypes.create_unicode_buffer(buf_size.value // 2 + 2)
                            if cls._wevtapi.EvtRender(None, h_event, 1, buf_size.value, buf, ctypes.byref(buf_size), ctypes.byref(prop_count)):
                                xml_str = buf.value
                                if xml_str:
                                    node = ET.fromstring(xml_str)
                                    nodes.append(node)
                    except Exception as ex:
                        cls.LAST_QUERY_ERRORS.append(f"EvtRender parse error on channel '{channel}': {ex}")
                    finally:
                        cls._wevtapi.EvtClose(h_event)
            finally:
                cls._wevtapi.EvtClose(h_query)

            return nodes
        except Exception as e:
            cls.LAST_QUERY_ERRORS.append(f"Native wevtapi exception on channel '{channel}': {e}")
            return None

    @classmethod
    def _execute_wevtutil_fallback(cls, channel: str, xpath: str, max_events: int = 20) -> List[ET.Element]:
        """Fallback query runner using SafeSubprocessBroker with catalog command 'event_query'."""
        if os.name != "nt":
            return []

        extra_flags = [
            channel,
            f"/q:{xpath}",
            f"/c:{max_events}",
            "/rd:true",
            "/f:RenderedXml"
        ]

        stdout_data = ""
        try:
            # Mediate execution through SafeSubprocessBroker to avoid raw unbrokered subprocess invocation
            from security.safe_subprocess import SafeSubprocessBroker
            res = SafeSubprocessBroker.execute_catalog_command("event_query", extra_flags=extra_flags, timeout=8)
            stdout_data = res.get("stdout", "")
        except Exception as broker_err:
            # Fallback to direct subprocess if security module is absent in minimal standalone execution
            try:
                cmd = ["wevtutil", "qe"] + extra_flags
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
                if res.returncode != 0:
                    err_msg = res.stderr.strip() or f"wevtutil exited with code {res.returncode} on channel '{channel}'"
                    cls.LAST_QUERY_ERRORS.append(err_msg)
                    return []
                stdout_data = res.stdout
            except Exception as e:
                cls.LAST_QUERY_ERRORS.append(f"wevtutil execution exception on channel '{channel}': {str(e)}")
                return []

        if not stdout_data:
            return []

        raw_xml = f"<Events>{stdout_data}</Events>"
        try:
            root = ET.fromstring(raw_xml)
            return root.findall(".//{*}Event")
        except Exception:
            return []

    @classmethod
    def _execute_event_query(cls, channel: str, xpath: str, max_events: int = 20) -> List[ET.Element]:
        """Primary entrypoint: requests authorization from ExecutionGuard, attempts native Win32 wevtapi.dll query first, with brokered wevtutil fallback."""
        try:
            from security import ExecutionGuard, Capability
            ExecutionGuard.request_access(
                component="event_collector",
                operation="query_events",
                target=f"channel:{channel}",
                capability=Capability.EVENT_LOG_READ,
                access_mode="QUERY",
                metadata={"channel": channel, "max_events": max_events}
            )
        except Exception as sec_e:
            cls.LAST_QUERY_ERRORS.append(f"Security mediation rejection on channel '{channel}': {sec_e}")
            return []

        native_nodes = cls._execute_native_query(channel, xpath, max_events)
        if native_nodes is not None:
            cls._backend_used = "wevtapi.dll (native Win32 in-process)"
            return native_nodes

        cls._backend_used = "wevtutil (subprocess fallback)"
        return cls._execute_wevtutil_fallback(channel, xpath, max_events)

    @classmethod
    def _execute_wevtutil_query(cls, channel: str, xpath: str, max_events: int = 20) -> List[ET.Element]:
        """Backwards-compatible wrapper delegating to _execute_event_query."""
        return cls._execute_event_query(channel, xpath, max_events)

    @classmethod
    def query_application_errors(cls, app_name_filter: Optional[str] = None, max_events: int = 20) -> List[Dict[str, Any]]:
        """
        Queries Application Event Log for Event ID 1000 (Application Error).
        Extracts faulting executable, faulting module, exception code, and fault offset RVA.
        """
        xpath = "*[System[Provider[@Name='Application Error'] and (EventID=1000)]]"
        event_nodes = cls._execute_event_query("Application", xpath, max_events)

        events = []
        for event_elem in event_nodes:
            data_elements = event_elem.findall(".//{*}Data")
            if not data_elements:
                continue

            named_map: Dict[str, str] = {}
            positional_list: List[str] = []
            for d in data_elements:
                name = d.get("Name", "")
                val = (d.text or "").strip()
                positional_list.append(val)
                if name:
                    named_map[name.lower()] = val

            app_name = (
                named_map.get("faultingapplicationname") or
                named_map.get("appname") or
                (positional_list[0] if len(positional_list) > 0 else "")
            )

            if app_name_filter:
                filter_lower = os.path.basename(app_name_filter).lower()
                if filter_lower not in app_name.lower():
                    continue

            time_elem = event_elem.find(".//{*}TimeCreated")
            time_created = time_elem.get("SystemTime") if time_elem is not None else None

            app_ver = (
                named_map.get("faultingapplicationversion") or
                named_map.get("appversion") or
                (positional_list[1] if len(positional_list) > 1 else None)
            )

            fault_mod = (
                named_map.get("faultingmodulename") or
                named_map.get("modulename") or
                (positional_list[3] if len(positional_list) > 3 else None)
            )

            raw_exc = (
                named_map.get("exceptioncode") or
                (positional_list[6] if len(positional_list) > 6 else "")
            )

            raw_offset = (
                named_map.get("faultingoffset") or
                named_map.get("faultoffset") or
                (positional_list[7] if len(positional_list) > 7 else "")
            )

            pid = (
                named_map.get("faultingprocessid") or
                (positional_list[8] if len(positional_list) > 8 else None)
            )

            exc_int = None
            if raw_exc:
                try:
                    exc_int = int(raw_exc, 16)
                except ValueError:
                    pass

            clean_offset = raw_offset.strip()
            if clean_offset and not clean_offset.startswith("0x"):
                clean_offset = f"0x{clean_offset}"

            events.append({
                "event_id": 1000,
                "event_type": "APPLICATION_ERROR",
                "time_created": time_created,
                "app_name": app_name,
                "app_version": app_ver,
                "fault_module": fault_mod,
                "exception_code": hex(exc_int) if exc_int is not None else raw_exc,
                "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_int, "UNKNOWN_EXCEPTION"),
                "fault_offset": clean_offset or "0x0",
                "process_id": pid
            })

        return events

    @classmethod
    def query_wer_events(cls, app_name_filter: Optional[str] = None, max_events: int = 20) -> List[Dict[str, Any]]:
        """
        Queries Application Event Log for Event ID 1001 (Windows Error Reporting).
        Extracts Bucket ID, Problem Signatures (P1-P10), and CabId.
        """
        xpath = "*[System[Provider[@Name='Windows Error Reporting'] and (EventID=1001)]]"
        event_nodes = cls._execute_event_query("Application", xpath, max_events)

        events = []
        for event_elem in event_nodes:
            data_elements = event_elem.findall(".//{*}Data")
            if not data_elements:
                continue

            named_map: Dict[str, str] = {}
            positional_list: List[str] = []
            for d in data_elements:
                name = d.get("Name", "")
                val = (d.text or "").strip()
                positional_list.append(val)
                if name:
                    named_map[name.lower()] = val

            time_elem = event_elem.find(".//{*}TimeCreated")
            time_created = time_elem.get("SystemTime") if time_elem is not None else None

            bucket = named_map.get("bucket") or (positional_list[0] if len(positional_list) > 0 else "")
            event_name = named_map.get("eventname") or (positional_list[1] if len(positional_list) > 1 else "")
            p1 = named_map.get("p1") or (positional_list[2] if len(positional_list) > 2 else "")
            p2 = named_map.get("p2") or (positional_list[3] if len(positional_list) > 3 else "")
            cab_id = named_map.get("cabid") or (positional_list[11] if len(positional_list) > 11 else "")

            if app_name_filter:
                filter_lower = os.path.basename(app_name_filter).lower()
                matched = any(filter_lower in str(x).lower() for x in (p1, p2, bucket, positional_list))
                if not matched:
                    continue

            events.append({
                "event_id": 1001,
                "event_type": "WINDOWS_ERROR_REPORTING",
                "time_created": time_created,
                "bucket": bucket,
                "event_name": event_name,
                "problem_signature_p1": p1,
                "problem_signature_p2": p2,
                "cab_id": cab_id,
                "signatures": positional_list[:10]
            })

        return events

    @classmethod
    def query_application_hangs(cls, app_name_filter: Optional[str] = None, max_events: int = 10) -> List[Dict[str, Any]]:
        """
        Queries Application Event Log for Event ID 1002 (Application Hang).
        Extracts hanging executable name, process ID, and hang type.
        """
        xpath = "*[System[Provider[@Name='Application Hang'] and (EventID=1002)]]"
        event_nodes = cls._execute_event_query("Application", xpath, max_events)

        events = []
        for event_elem in event_nodes:
            data_elements = event_elem.findall(".//{*}Data")
            if not data_elements:
                continue

            vals = [(d.text or "").strip() for d in data_elements]
            app_name = vals[0] if len(vals) > 0 else ""

            if app_name_filter:
                filter_lower = os.path.basename(app_name_filter).lower()
                if filter_lower not in app_name.lower():
                    continue

            time_elem = event_elem.find(".//{*}TimeCreated")
            time_created = time_elem.get("SystemTime") if time_elem is not None else None

            events.append({
                "event_id": 1002,
                "event_type": "APPLICATION_HANG",
                "time_created": time_created,
                "app_name": app_name,
                "app_version": vals[1] if len(vals) > 1 else None,
                "process_id": vals[2] if len(vals) > 2 else None,
                "hang_signature": vals[3] if len(vals) > 3 else None
            })

        return events

    @classmethod
    def query_system_crashes(cls, max_events: int = 5) -> List[Dict[str, Any]]:
        """
        Queries System Event Log for Kernel-Power (Event ID 41) or BugCheck (Event ID 1001)
        representing full host kernel panics or unexpected shutdowns.
        """
        xpath = "*[System[(EventID=41 or EventID=1001) and (Provider[@Name='Microsoft-Windows-Kernel-Power'] or Provider[@Name='BugCheck'] or Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'])]]"
        event_nodes = cls._execute_event_query("System", xpath, max_events)

        events = []
        for event_elem in event_nodes:
            time_elem = event_elem.find(".//{*}TimeCreated")
            time_created = time_elem.get("SystemTime") if time_elem is not None else None
            id_elem = event_elem.find(".//{*}EventID")
            event_id = int(id_elem.text) if id_elem is not None and id_elem.text else 0

            data_elements = event_elem.findall(".//{*}Data")
            named_data = {d.get("Name", f"Param_{i}"): (d.text or "").strip() for i, d in enumerate(data_elements)}

            events.append({
                "event_id": event_id,
                "channel": "System",
                "time_created": time_created,
                "event_type": "KERNEL_POWER_OR_BUGCHECK",
                "parameters": named_data
            })

        return events

    @classmethod
    def collect_all_telemetry(cls, app_name_filter: Optional[str] = None) -> Dict[str, Any]:
        """Gathers unified event log failure telemetry across all failure categories."""
        cls.LAST_QUERY_ERRORS = []
        crashes = cls.query_application_errors(app_name_filter)
        wers = cls.query_wer_events(app_name_filter)
        hangs = cls.query_application_hangs(app_name_filter)
        system_events = cls.query_system_crashes(max_events=3)

        status_str = "success" if not cls.LAST_QUERY_ERRORS else "partial_success"

        return {
            "status": status_str,
            "backend": cls._backend_used,
            "filter": app_name_filter,
            "query_errors": list(cls.LAST_QUERY_ERRORS),
            "counts": {
                "application_crashes_1000": len(crashes),
                "wer_events_1001": len(wers),
                "application_hangs_1002": len(hangs),
                "system_crashes": len(system_events)
            },
            "application_crashes": crashes,
            "wer_events": wers,
            "application_hangs": hangs,
            "system_crashes": system_events
        }
