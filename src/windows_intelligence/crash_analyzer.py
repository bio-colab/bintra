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

        return {
            "source": "WER_REPORT",
            "file_path": wer_path,
            "event_time": fields.get("EventTime"),
            "event_type": event_type,
            "app_name": app_name,
            "fault_module": fault_module,
            "exception_code": hex(exc_code_int) if exc_code_int is not None else exc_code_str,
            "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_code_int, "UNKNOWN_EXCEPTION"),
            "fault_offset": fault_offset_str if fault_offset_str.startswith("0x") else f"0x{fault_offset_str}"
        }

    @classmethod
    def query_event_log(cls, app_name_filter: Optional[str] = None, max_events: int = 5) -> List[Dict[str, Any]]:
        """
        Interrogates Windows Application Event Log for Event ID 1000 (Application Error)
        using wevtutil query utility with defensive timeouts.
        """
        if os.name != "nt":
            return []

        xpath = "*[System[(EventID=1000)]]"
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
                data_map = {}
                for data_elem in event_elem.findall(".//{*}Data"):
                    name = data_elem.get("Name", "")
                    val = data_elem.text or ""
                    if name:
                        data_map[name] = val

                app_name = data_map.get("AppName", "")
                if app_name_filter:
                    filter_lower = os.path.basename(app_name_filter).lower()
                    if filter_lower not in app_name.lower():
                        continue

                exc_hex = data_map.get("ExceptionCode", "")
                exc_int = None
                if exc_hex:
                    try:
                        exc_int = int(exc_hex, 16)
                    except ValueError:
                        pass

                events.append({
                    "source": "EVENT_LOG_1000",
                    "app_name": app_name,
                    "app_version": data_map.get("AppVersion"),
                    "fault_module": data_map.get("ModuleName"),
                    "fault_module_version": data_map.get("ModuleVersion"),
                    "exception_code": exc_hex,
                    "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_int, "UNKNOWN_EXCEPTION"),
                    "fault_offset": f"0x{data_map.get('Offset', '')}",
                    "process_id": data_map.get("ProcessId")
                })
        except Exception:
            pass

        return events

    @classmethod
    def parse_minidump(cls, dmp_path: str) -> Dict[str, Any]:
        """
        Pure-Python MiniDump parser (reads Signature 'MDMP' and Directory Streams).
        Extracts ExceptionRecord (Stream 6) and Loaded Modules (Stream 4) without WinDbg.
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
            module_count = 0

            for i in range(num_streams):
                entry = dir_bytes[i * 12 : (i + 1) * 12]
                if len(entry) < 12:
                    break
                st_type, data_size, rva = struct.unpack("<III", entry)

                # Stream 6: ExceptionStream
                if st_type == 6 and data_size >= 168:
                    f.seek(rva)
                    exc_bytes = f.read(data_size)
                    thread_id, _, exc_code, exc_flags, exc_record, exc_addr = struct.unpack("<IIIIQQ", exc_bytes[:32])
                    exception_info = {
                        "thread_id": thread_id,
                        "exception_code": hex(exc_code),
                        "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_code, "UNKNOWN_EXCEPTION"),
                        "exception_address": hex(exc_addr)
                    }
                # Stream 4: ModuleListStream
                elif st_type == 4 and data_size >= 4:
                    f.seek(rva)
                    (mod_num,) = struct.unpack("<I", f.read(4))
                    module_count = mod_num

        return {
            "status": "success",
            "file": dmp_path,
            "format": "MINIDUMP",
            "stream_count": num_streams,
            "module_count": module_count,
            "exception_info": exception_info
        }

    @classmethod
    def collect_crash_evidence(cls, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Gathers all available crash evidence from WER archives and Event Logs."""
        wer_reports = cls.scan_wer_report_archive(binary_path)
        event_logs = cls.query_event_log(binary_path)

        return {
            "status": "success",
            "query_target": binary_path,
            "wer_reports_found": len(wer_reports),
            "event_log_errors_found": len(event_logs),
            "wer_reports": wer_reports,
            "event_log_errors": event_logs
        }
