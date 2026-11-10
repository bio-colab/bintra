# -*- coding: utf-8 -*-
"""
Windows Crash, WER, and Event Log Telemetry Analyzer.
Extracts Application Error events (Event ID 1000/1001), parses Report.wer files,
and provides a native pure-Python MiniDump (.dmp) header/stream parser.
"""

import os
import sys
import glob
import struct
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional


class WindowsCrashAnalyzer:
    """
    Collects and parses Windows Error Reporting (WER) dossiers, Application Event Logs,
    and user-mode crash dumps to extract empirical exception codes and faulting RVAs.
    """

    COMMON_EXCEPTION_CODES = {
        0xC0000005: "STATUS_ACCESS_VIOLATION (Memory Read/Write/Execute Violation)",
        0xC00000FD: "STATUS_STACK_OVERFLOW (Recursive Exhaustion / Corrupted Frame)",
        0xC0000135: "STATUS_DLL_NOT_FOUND (Missing Dynamic Link Library)",
        0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND (Missing Procedure Export in DLL)",
        0xC000001D: "STATUS_ILLEGAL_INSTRUCTION (Unsupported CPU Vector / Corrupted Opcode)",
        0x80000003: "STATUS_BREAKPOINT (Hardcoded Debug Break / Assertion Failure)",
        0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xE06D7363: "STATUS_CPP_EXCEPTION (Unhandled C++ Exception / MSVC Runtime)"
    }

    @classmethod
    def scan_wer_report_archive(cls, app_name_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scans Windows Error Reporting archives in ProgramData and LocalAppData
        for Report.wer failure dossiers.
        """
        wer_dirs = [
            os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\WER\ReportArchive"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\WER\ReportArchive")
        ]

        found_reports = []
        for base_dir in wer_dirs:
            if not os.path.isdir(base_dir):
                continue
            pattern = os.path.join(base_dir, "*", "Report.wer")
            for report_path in glob.glob(pattern):
                try:
                    rep_data = cls._parse_wer_file(report_path)
                    if rep_data:
                        app_name = rep_data.get("app_name", "").lower()
                        if app_name_filter:
                            filter_lower = os.path.basename(app_name_filter).lower()
                            if filter_lower not in app_name:
                                continue
                        found_reports.append(rep_data)
                except Exception:
                    continue

        return found_reports

    @classmethod
    def _parse_wer_file(cls, wer_path: str) -> Optional[Dict[str, Any]]:
        """Parses key-value parameters from a Windows Report.wer document."""
        if not os.path.isfile(wer_path):
            return None

        # WER files are typically encoded in UTF-16 LE with BOM or UTF-8
        try:
            with open(wer_path, "rb") as bf:
                raw_bytes = bf.read()
        except OSError:
            return None

        if not raw_bytes:
            return None

        text = None
        if raw_bytes.startswith(b"\xff\xfe"):
            text = raw_bytes.decode("utf-16-le", errors="replace")
        elif raw_bytes.startswith(b"\xfe\xff"):
            text = raw_bytes.decode("utf-16-be", errors="replace")
        elif raw_bytes.startswith(b"\xef\xbb\xbf"):
            text = raw_bytes.decode("utf-8-sig", errors="replace")
        elif b"\x00" in raw_bytes[:100]:
            try:
                text = raw_bytes.decode("utf-16-le")
            except UnicodeDecodeError:
                text = raw_bytes.decode("latin-1", errors="replace")
        else:
            try:
                text = raw_bytes.decode("utf-8")
            except UnicodeDecodeError:
                text = raw_bytes.decode("latin-1", errors="replace")

        if not text:
            return None

        fields: Dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip()

        event_type = fields.get("EventType", "Unknown")
        app_name = fields.get("Sig[0].Value") or fields.get("AppPath", "")
        fault_module = fields.get("Sig[3].Value") or fields.get("FaultModule", "")
        exc_code_str = fields.get("Sig[6].Value") or fields.get("ExceptionCode", "")
        fault_offset_str = fields.get("Sig[7].Value") or fields.get("FaultOffset", "")

        exc_code_int = None
        if exc_code_str:
            try:
                exc_code_int = int(exc_code_str, 16)
            except ValueError:
                pass

        clean_offset = fault_offset_str.strip() if fault_offset_str else ""
        if clean_offset and not clean_offset.startswith("0x"):
            clean_offset = f"0x{clean_offset}"

        return {
            "source": "WER_REPORT",
            "file_path": wer_path,
            "event_time": fields.get("EventTime"),
            "event_type": event_type,
            "app_name": app_name,
            "fault_module": fault_module,
            "exception_code": hex(exc_code_int) if exc_code_int is not None else exc_code_str,
            "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_code_int, "UNKNOWN_EXCEPTION"),
            "fault_offset": clean_offset or "0x0"
        }

    @classmethod
    def query_event_log(cls, app_name_filter: Optional[str] = None, max_events: int = 10) -> List[Dict[str, Any]]:
        """
        Interrogates Windows Application Event Log for Event ID 1000 (Application Error)
        using wevtutil query utility with defensive timeouts.
        Handles both named Data elements and standard positional EventData structures.
        """
        if os.name != "nt":
            return []

        # Target Application Error Event 1000 specifically to avoid unrelated events
        xpath = "*[System[Provider[@Name='Application Error'] and (EventID=1000)]]"
        cmd = [
            "wevtutil", "qe", "Application",
            f"/q:{xpath}",
            f"/c:{max_events}",
            "/rd:true",
            "/f:RenderedXml"
        ]

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode != 0 or not res.stdout:
                return []
        except Exception:
            return []

        events = []
        raw_xml = f"<Events>{res.stdout}</Events>"
        try:
            root = ET.fromstring(raw_xml)
            for event_elem in root.findall(".//{*}Event"):
                data_elements = event_elem.findall(".//{*}Data")
                if not data_elements:
                    continue

                named_map: Dict[str, str] = {}
                positional_list: List[str] = []
                for data_elem in data_elements:
                    name = data_elem.get("Name", "")
                    val = (data_elem.text or "").strip()
                    positional_list.append(val)
                    if name:
                        named_map[name.lower()] = val

                # Standard Windows Event 1000 schema:
                # Positional indices when Name attribute is omitted:
                # [0]: Faulting application name
                # [1]: Faulting application version
                # [2]: Faulting application timestamp
                # [3]: Faulting module name
                # [4]: Faulting module version
                # [5]: Faulting module timestamp
                # [6]: Exception code
                # [7]: Faulting offset (RVA)
                # [8]: Faulting process ID
                # [9]: Faulting application start time
                # [10]: Faulting application path
                # [11]: Faulting module path
                # [12]: Report ID

                app_name = (
                    named_map.get("faultingapplicationname") or
                    named_map.get("appname") or
                    (positional_list[0] if len(positional_list) > 0 else "")
                )

                if app_name_filter:
                    filter_lower = os.path.basename(app_name_filter).lower()
                    if filter_lower not in app_name.lower():
                        continue

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

                fault_mod_ver = (
                    named_map.get("faultingmoduleversion") or
                    named_map.get("moduleversion") or
                    (positional_list[4] if len(positional_list) > 4 else None)
                )

                exc_raw = (
                    named_map.get("exceptioncode") or
                    (positional_list[6] if len(positional_list) > 6 else "")
                )

                raw_offset = (
                    named_map.get("faultingoffset") or
                    named_map.get("faultoffset") or
                    named_map.get("offset") or
                    (positional_list[7] if len(positional_list) > 7 else "")
                )

                pid = (
                    named_map.get("faultingprocessid") or
                    named_map.get("processid") or
                    (positional_list[8] if len(positional_list) > 8 else None)
                )

                app_path = (
                    named_map.get("faultingapplicationpath") or
                    named_map.get("applicationpath") or
                    (positional_list[10] if len(positional_list) > 10 else None)
                )

                mod_path = (
                    named_map.get("faultingmodulepath") or
                    named_map.get("modulepath") or
                    (positional_list[11] if len(positional_list) > 11 else None)
                )

                exc_int = None
                if exc_raw:
                    try:
                        exc_int = int(exc_raw, 16)
                    except ValueError:
                        pass

                clean_offset = raw_offset.strip()
                if clean_offset and not clean_offset.startswith("0x"):
                    clean_offset = f"0x{clean_offset}"

                events.append({
                    "source": "EVENT_LOG_1000",
                    "app_name": app_name,
                    "app_version": app_ver,
                    "app_path": app_path,
                    "fault_module": fault_mod,
                    "fault_module_version": fault_mod_ver,
                    "fault_module_path": mod_path,
                    "exception_code": hex(exc_int) if exc_int is not None else exc_raw,
                    "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_int, "UNKNOWN_EXCEPTION"),
                    "fault_offset": clean_offset or "0x0",
                    "process_id": pid
                })
        except Exception:
            pass

        return events

    @classmethod
    def _read_minidump_string(cls, f, rva: int) -> str:
        """Reads a UTF-16 LE MINIDUMP_STRING at the specified RVA."""
        try:
            f.seek(rva)
            (length,) = struct.unpack("<I", f.read(4))
            raw_str = f.read(length)
            return raw_str.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return ""

    @classmethod
    def parse_minidump(cls, dmp_path: str) -> Dict[str, Any]:
        """
        Pure-Python MiniDump parser (reads Signature 'MDMP' and Directory Streams).
        Extracts ExceptionRecord (Stream 6) and Loaded Modules (Stream 4) without WinDbg.
        Correlates faulting exception address against loaded modules to identify the
        faulting module and relative virtual address (FaultingOffset/RVA).
        """
        if not os.path.isfile(dmp_path):
            return {"status": "error", "error": f"Dump file not found: {dmp_path}"}

        with open(dmp_path, "rb") as f:
            header = f.read(32)
            if len(header) < 32 or header[:4] != b"MDMP":
                return {"status": "error", "error": "Invalid MiniDump magic signature (expected 'MDMP')"}

            sig, ver, num_streams, stream_dir_rva, checksum, time_date = struct.unpack("<IIIIII", header[:24])

            f.seek(stream_dir_rva)
            dir_bytes = f.read(num_streams * 12)

            exception_info = None
            modules: List[Dict[str, Any]] = []

            # Pass 1: Parse ExceptionStream (Stream 6)
            for i in range(num_streams):
                entry = dir_bytes[i * 12 : (i + 1) * 12]
                if len(entry) < 12:
                    break
                st_type, data_size, rva = struct.unpack("<III", entry)

                if st_type == 6 and data_size >= 168:
                    f.seek(rva)
                    exc_bytes = f.read(data_size)
                    thread_id, _, exc_code, exc_flags, exc_record, exc_addr = struct.unpack("<IIIIQQ", exc_bytes[:32])
                    exception_info = {
                        "thread_id": thread_id,
                        "exception_code": hex(exc_code),
                        "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_code, "UNKNOWN_EXCEPTION"),
                        "exception_address": hex(exc_addr),
                        "exception_address_int": exc_addr
                    }

            # Pass 2: Parse ModuleListStream (Stream 4)
            for i in range(num_streams):
                entry = dir_bytes[i * 12 : (i + 1) * 12]
                if len(entry) < 12:
                    break
                st_type, data_size, rva = struct.unpack("<III", entry)

                if st_type == 4 and data_size >= 4:
                    f.seek(rva)
                    (mod_num,) = struct.unpack("<I", f.read(4))
                    for m_idx in range(min(mod_num, 256)):
                        mod_record = f.read(108)
                        if len(mod_record) < 108:
                            break
                        base_img, size_img, chksum, timestamp, name_rva = struct.unpack("<QIIII", mod_record[:24])
                        cur_pos = f.tell()
                        mod_name_str = cls._read_minidump_string(f, name_rva)
                        f.seek(cur_pos)

                        modules.append({
                            "name": os.path.basename(mod_name_str),
                            "path": mod_name_str,
                            "base_address": hex(base_img),
                            "base_int": base_img,
                            "size": size_img,
                            "end_address": hex(base_img + size_img)
                        })

            # Correlate exception address with modules to determine fault module & RVA
            fault_module = None
            fault_offset = None
            if exception_info and "exception_address_int" in exception_info:
                exc_addr = exception_info["exception_address_int"]
                for mod in modules:
                    base = mod["base_int"]
                    size = mod["size"]
                    if base <= exc_addr < base + size:
                        fault_module = mod["name"]
                        fault_offset = hex(exc_addr - base)
                        break

                if fault_module:
                    exception_info["fault_module"] = fault_module
                    exception_info["fault_offset"] = fault_offset
                del exception_info["exception_address_int"]

        return {
            "status": "success",
            "file": dmp_path,
            "format": "MINIDUMP",
            "stream_count": num_streams,
            "module_count": len(modules),
            "exception_info": exception_info,
            "modules_preview": [m["name"] for m in modules[:10]]
        }

    @classmethod
    def collect_crash_evidence(cls, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Gathers all available crash evidence from WER archives, Event Logs, and MiniDump files."""
        if sys.platform != "win32":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "WindowsCrashAnalyzer requires a Windows host system."
            }
        wer_reports = cls.scan_wer_report_archive(binary_path)
        event_logs = cls.query_event_log(binary_path)

        # Scan for minidump files in WER directories and local crash dump paths
        dmp_reports = []
        dmp_candidates = []
        search_dirs = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps"),
            os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\WER\ReportArchive"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\WER\ReportArchive")
        ]
        for d in search_dirs:
            if os.path.isdir(d):
                for dmp_file in glob.glob(os.path.join(d, "**", "*.dmp"), recursive=True):
                    if binary_path:
                        b_name = os.path.basename(binary_path).lower()
                        if b_name not in os.path.basename(dmp_file).lower():
                            continue
                    dmp_candidates.append(dmp_file)

        for dmp_path in dmp_candidates[:3]:
            try:
                parsed_dmp = cls.parse_minidump(dmp_path)
                if parsed_dmp.get("status") == "success":
                    dmp_reports.append(parsed_dmp)
            except Exception:
                pass

        return {
            "status": "success",
            "query_target": binary_path,
            "wer_reports_found": len(wer_reports),
            "event_log_errors_found": len(event_logs),
            "minidumps_found": len(dmp_reports),
            "wer_reports": wer_reports,
            "event_log_errors": event_logs,
            "minidumps": dmp_reports
        }
