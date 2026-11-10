# -*- coding: utf-8 -*-
"""
Pure-Python Multi-Stream MiniDump (.dmp) Parser & Crash Intelligence Engine.
Parses MDMP directory headers, SystemInfo (Stream 7), ThreadList (Stream 3),
ModuleList (Stream 4), MiscInfo (Stream 15), and ExceptionRecord (Stream 6).
Provides deterministic root cause attribution and access violation parameter analysis
(Read / Write / DEP execution, NULL pointer dereferences).
"""

import os
import glob
import struct
from typing import Dict, Any, List, Optional


class MiniDumpParser:
    """
    Authoritative pure-Python MiniDump parser without external debugging dependencies.
    Extracts empirical crash telemetry, faulting modules, RVAs, and access violation targets.
    """

    COMMON_EXCEPTION_CODES = {
        0xC0000005: "STATUS_ACCESS_VIOLATION",
        0xC00000FD: "STATUS_STACK_OVERFLOW",
        0xC0000135: "STATUS_DLL_NOT_FOUND",
        0xC0000139: "STATUS_ENTRYPOINT_NOT_FOUND",
        0xC000001D: "STATUS_ILLEGAL_INSTRUCTION",
        0x80000003: "STATUS_BREAKPOINT",
        0xC0000094: "STATUS_INTEGER_DIVIDE_BY_ZERO",
        0xC0000025: "STATUS_NONCONTINUABLE_EXCEPTION",
        0xC0000374: "STATUS_HEAP_CORRUPTION",
        0xE06D7363: "STATUS_CPP_EXCEPTION"
    }

    PROCESSOR_ARCH_MAP = {
        0: "x86 (32-bit)",
        5: "ARM",
        6: "IA64",
        9: "AMD64 (x64 64-bit)",
        12: "ARM64"
    }

    ACCESS_VIOLATION_TYPES = {
        0: "READ",
        1: "WRITE",
        8: "EXECUTE (DEP / NX Violation)"
    }

    STREAM_NAMES = {
        0: "UnusedStream",
        1: "ReservedStream0",
        2: "ReservedStream1",
        3: "ThreadListStream",
        4: "ModuleListStream",
        5: "MemoryListStream",
        6: "ExceptionStream",
        7: "SystemInfoStream",
        8: "ThreadExListStream",
        9: "Memory64ListStream",
        10: "CommentStreamA",
        11: "CommentStreamW",
        12: "HandleDataStream",
        13: "FunctionTableStream",
        14: "UnloadedModuleListStream",
        15: "MiscInfoStream",
        16: "MemoryInfoListStream",
        17: "ThreadInfoListStream",
        18: "HandleOperationListStream",
        19: "TokenStream"
    }

    @classmethod
    def _read_minidump_string(cls, f, rva: int) -> str:
        """Reads a UTF-16 LE MINIDUMP_STRING structure at the specified RVA."""
        try:
            f.seek(rva)
            raw_len = f.read(4)
            if len(raw_len) < 4:
                return ""
            (length,) = struct.unpack("<I", raw_len)
            raw_str = f.read(length)
            return raw_str.decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            return ""

    @classmethod
    def parse_minidump(cls, dmp_path: str) -> Dict[str, Any]:
        """
        Parses a Windows MiniDump file across all standard streams:
        Stream 6 (Exception), Stream 4 (Modules), Stream 7 (SystemInfo),
        Stream 3 (Threads), and Stream 10 (MiscInfo).
        """
        if not os.path.isfile(dmp_path):
            return {"status": "error", "error": f"Dump file not found: {dmp_path}"}

        try:
            file_size = os.path.getsize(dmp_path)
            with open(dmp_path, "rb") as f:
                header = f.read(32)
                if len(header) < 32 or header[:4] != b"MDMP":
                    return {"status": "error", "error": "Invalid MiniDump magic signature (expected 'MDMP')"}

                sig, ver, num_streams, stream_dir_rva, checksum, time_date = struct.unpack("<IIIIII", header[:24])

                if num_streams == 0:
                    return {
                        "status": "error",
                        "error": "Corrupted or empty MiniDump: zero streams declared in header.",
                        "file_path": dmp_path
                    }
                if num_streams > 4096 or stream_dir_rva >= file_size:
                    return {
                        "status": "error",
                        "error": (
                            f"Corrupted MiniDump header: invalid stream directory "
                            f"(streams={num_streams}, dir_rva={hex(stream_dir_rva)}, file_size={file_size})."
                        ),
                        "file_path": dmp_path
                    }

                f.seek(stream_dir_rva)
                max_dir_bytes = min(num_streams * 12, max(0, file_size - stream_dir_rva))
                dir_bytes = f.read(max_dir_bytes)

                streams_detected = []
                stream_map: Dict[int, tuple] = {}
                for i in range(len(dir_bytes) // 12):
                    entry = dir_bytes[i * 12 : (i + 1) * 12]
                    if len(entry) < 12:
                        break
                    st_type, data_size, rva = struct.unpack("<III", entry)
                    # Defensive stream bounds verification against file size
                    if rva < 0 or rva + data_size > file_size:
                        continue
                    stream_map[st_type] = (data_size, rva)
                    streams_detected.append({
                        "stream_id": st_type,
                        "stream_name": cls.STREAM_NAMES.get(st_type, f"CustomStream_{st_type}"),
                        "data_size": data_size,
                        "rva": hex(rva)
                    })

                # 1. System Info Stream (Stream 7)
                system_info = None
                if 7 in stream_map:
                    sz, rva = stream_map[7]
                    system_info = cls._parse_system_info_stream(f, rva, sz, file_size)

                # 2. Misc Info Stream (Stream 15)
                # Note: Stream 10 is CommentStreamA in the Microsoft MiniDump specification; Stream 15 is MiscInfoStream.
                misc_info = None
                if 15 in stream_map:
                    sz, rva = stream_map[15]
                    misc_info = cls._parse_misc_info_stream(f, rva, sz, file_size)

                # 3. Thread List Stream (Stream 3)
                threads = []
                if 3 in stream_map:
                    sz, rva = stream_map[3]
                    threads = cls._parse_thread_list_stream(f, rva, sz, file_size)

                # 4. Module List Stream (Stream 4)
                modules = []
                if 4 in stream_map:
                    sz, rva = stream_map[4]
                    modules = cls._parse_module_list_stream(f, rva, sz, file_size)

                # 5. Exception Stream (Stream 6)
                exception_info = None
                if 6 in stream_map:
                    sz, rva = stream_map[6]
                    exception_info = cls._parse_exception_stream(f, rva, sz, file_size)

                # 6. Correlate Fault Address with Loaded Modules
                cls._correlate_fault(exception_info, modules)

                return {
                    "status": "success",
                    "file_path": dmp_path,
                    "format": "MINIDUMP_MDMP",
                    "timestamp": time_date,
                    "process_id": misc_info.get("process_id") if misc_info else None,
                    "stream_count": num_streams,
                    "streams": streams_detected,
                    "system_info": system_info,
                    "misc_info": misc_info,
                    "thread_count": len(threads),
                    "module_count": len(modules),
                    "threads": threads,
                    "modules": modules,
                    "exception_info": exception_info,
                    "modules_sample": [m["name"] for m in modules[:10]]
                }
        except Exception as e:
            err_detail = str(e).strip() or type(e).__name__
            return {
                "status": "error",
                "error": f"Failed to parse minidump ({type(e).__name__}): {err_detail}",
                "file_path": dmp_path,
            }

    @classmethod
    def _parse_system_info_stream(cls, f, rva: int, size: int, file_size: int = 0) -> Optional[Dict[str, Any]]:
        """Parses MINIDUMP_SYSTEM_INFO (Stream 7)."""
        if size < 48 or rva < 0 or (file_size > 0 and rva + size > file_size):
            return None
        f.seek(rva)
        fmt = "<HHHBBIIIIIHH16s"
        raw = f.read(48)
        if len(raw) < 48:
            return None
        arch, level, rev, num_cpu, prod_type, major, minor, build, plat, csd_rva, suite, res2, _ = struct.unpack(fmt, raw)
        return {
            "processor_architecture": cls.PROCESSOR_ARCH_MAP.get(arch, f"Unknown_Arch_{arch}"),
            "processor_level": level,
            "processor_revision": hex(rev),
            "number_of_processors": num_cpu,
            "product_type": "Workstation" if prod_type == 1 else "Server",
            "os_version": f"{major}.{minor}.{build}",
            "build_number": build,
            "platform_id": plat
        }

    @classmethod
    def _parse_misc_info_stream(cls, f, rva: int, size: int, file_size: int = 0) -> Optional[Dict[str, Any]]:
        """Parses MINIDUMP_MISC_INFO (Stream 15)."""
        if size < 24 or rva < 0 or (file_size > 0 and rva + size > file_size):
            return None
        f.seek(rva)
        raw = f.read(24)
        if len(raw) < 24:
            return None
        size_info, flags, pid, create_time, user_time, kernel_time = struct.unpack("<IIIIII", raw)
        return {
            "process_id": pid if (flags & 0x1) else None,
            "process_create_time": create_time if (flags & 0x2) else None,
            "process_user_time_ms": user_time if (flags & 0x2) else None,
            "process_kernel_time_ms": kernel_time if (flags & 0x2) else None
        }

    @classmethod
    def _parse_thread_list_stream(cls, f, rva: int, size: int, file_size: int = 0) -> List[Dict[str, Any]]:
        """Parses MINIDUMP_THREAD_LIST (Stream 3)."""
        if size < 4 or rva < 0 or (file_size > 0 and rva + size > file_size):
            return []
        f.seek(rva)
        raw_num = f.read(4)
        if len(raw_num) < 4:
            return []
        (num_threads,) = struct.unpack("<I", raw_num)
        threads = []
        fmt_thread = "<IIIIQQIIII"
        for _ in range(min(num_threads, 512)):
            t_bytes = f.read(48)
            if len(t_bytes) < 48:
                break
            tid, susp, pri_class, pri, teb, stack_base, stack_size, stack_rva, ctx_size, ctx_rva = struct.unpack(fmt_thread, t_bytes)
            threads.append({
                "thread_id": tid,
                "suspend_count": susp,
                "teb": hex(teb),
                "stack_base": hex(stack_base),
                "stack_size_bytes": stack_size
            })
        return threads

    @classmethod
    def _parse_module_list_stream(cls, f, rva: int, size: int, file_size: int = 0) -> List[Dict[str, Any]]:
        """Parses MINIDUMP_MODULE_LIST (Stream 4)."""
        if size < 4 or rva < 0 or (file_size > 0 and rva + size > file_size):
            return []
        f.seek(rva)
        raw_num = f.read(4)
        if len(raw_num) < 4:
            return []
        (num_modules,) = struct.unpack("<I", raw_num)
        modules = []
        for _ in range(min(num_modules, 512)):
            mod_record = f.read(108)
            if len(mod_record) < 108:
                break
            base_img, size_img, chksum, timestamp, name_rva = struct.unpack("<QIIII", mod_record[:24])
            cur_pos = f.tell()
            mod_path = cls._read_minidump_string(f, name_rva)
            f.seek(cur_pos)

            modules.append({
                "name": os.path.basename(mod_path),
                "path": mod_path,
                "base_address": hex(base_img),
                "base_int": base_img,
                "size": size_img,
                "end_address": hex(base_img + size_img),
                "checksum": hex(chksum),
                "timestamp": timestamp
            })
        return modules

    @classmethod
    def _parse_exception_stream(cls, f, rva: int, size: int, file_size: int = 0) -> Optional[Dict[str, Any]]:
        """Parses MINIDUMP_EXCEPTION_STREAM (Stream 6) including access violation parameters."""
        if size < 168 or rva < 0 or (file_size > 0 and rva + size > file_size):
            return None
        f.seek(rva)
        fmt = "<IIIIQQII15QII"
        exc_bytes = f.read(168)
        if len(exc_bytes) < 168:
            return None

        vals = struct.unpack(fmt, exc_bytes)
        thread_id = vals[0]
        exc_code = vals[2]
        exc_flags = vals[3]
        exc_record = vals[4]
        exc_addr = vals[5]
        num_params = vals[6]
        params = list(vals[8:23])[:min(num_params, 15)]

        info: Dict[str, Any] = {
            "thread_id": thread_id,
            "exception_code": hex(exc_code),
            "exception_name": cls.COMMON_EXCEPTION_CODES.get(exc_code, "UNKNOWN_EXCEPTION"),
            "exception_address": hex(exc_addr),
            "exception_address_int": exc_addr,
            "number_parameters": num_params,
            "parameters": [hex(p) for p in params]
        }

        # Deep Access Violation (0xC0000005) parameter diagnostics
        if exc_code == 0xC0000005 and len(params) >= 2:
            access_type_raw = params[0]
            target_addr = params[1]
            access_type_name = cls.ACCESS_VIOLATION_TYPES.get(access_type_raw, f"UNKNOWN_OP_{access_type_raw}")
            is_null_ptr = (target_addr < 0x10000)

            info["access_violation_details"] = {
                "operation": access_type_name,
                "access_type": access_type_name,
                "target_virtual_address": hex(target_addr),
                "is_null_pointer_dereference": is_null_ptr,
                "probable_cause": "Hypothesis: Probable NULL Pointer Dereference (Access target < 0x10000)" if is_null_ptr
                                 else f"Hypothesis: Invalid Memory {access_type_name} at unmapped/protected address {hex(target_addr)}"
            }

        # Extract ThreadContext registers
        ctx_size = vals[23]
        ctx_rva = vals[24]
        if ctx_size > 0 and ctx_rva > 0:
            try:
                cur_pos = f.tell()
                f.seek(ctx_rva)
                ctx_bytes = f.read(ctx_size)
                f.seek(cur_pos)
                if len(ctx_bytes) >= 1232:
                    # x64 context
                    (rip,) = struct.unpack("<Q", ctx_bytes[248:256])
                    (rsp,) = struct.unpack("<Q", ctx_bytes[152:160])
                    (rbp,) = struct.unpack("<Q", ctx_bytes[160:168])
                    (rax,) = struct.unpack("<Q", ctx_bytes[120:128])
                    (rcx,) = struct.unpack("<Q", ctx_bytes[128:136])
                    (rdx,) = struct.unpack("<Q", ctx_bytes[136:144])
                    (rbx,) = struct.unpack("<Q", ctx_bytes[144:152])
                    (rsi,) = struct.unpack("<Q", ctx_bytes[168:176])
                    (rdi,) = struct.unpack("<Q", ctx_bytes[176:184])
                    (r8,) = struct.unpack("<Q", ctx_bytes[184:192])
                    (r9,) = struct.unpack("<Q", ctx_bytes[192:200])
                    (r10,) = struct.unpack("<Q", ctx_bytes[200:208])
                    (r11,) = struct.unpack("<Q", ctx_bytes[208:216])
                    (r12,) = struct.unpack("<Q", ctx_bytes[216:224])
                    (r13,) = struct.unpack("<Q", ctx_bytes[224:232])
                    (r14,) = struct.unpack("<Q", ctx_bytes[232:240])
                    (r15,) = struct.unpack("<Q", ctx_bytes[240:248])
                    info["thread_registers"] = {
                        "arch": "x64",
                        "rip": hex(rip),
                        "rsp": hex(rsp),
                        "rbp": hex(rbp),
                        "rax": hex(rax),
                        "rbx": hex(rbx),
                        "rcx": hex(rcx),
                        "rdx": hex(rdx),
                        "rsi": hex(rsi),
                        "rdi": hex(rdi),
                        "r8": hex(r8),
                        "r9": hex(r9),
                        "r10": hex(r10),
                        "r11": hex(r11),
                        "r12": hex(r12),
                        "r13": hex(r13),
                        "r14": hex(r14),
                        "r15": hex(r15),
                    }
                    info["thread_context"] = dict(info["thread_registers"])
                elif len(ctx_bytes) >= 716:
                    # x86 context
                    (eip,) = struct.unpack("<I", ctx_bytes[184:188])
                    (esp,) = struct.unpack("<I", ctx_bytes[196:200])
                    (ebp,) = struct.unpack("<I", ctx_bytes[180:184])
                    (eax,) = struct.unpack("<I", ctx_bytes[176:180])
                    (ecx,) = struct.unpack("<I", ctx_bytes[160:164])
                    (edx,) = struct.unpack("<I", ctx_bytes[164:168])
                    info["thread_registers"] = {
                        "arch": "x86",
                        "eip": hex(eip),
                        "esp": hex(esp),
                        "ebp": hex(ebp),
                        "eax": hex(eax),
                        "ecx": hex(ecx),
                        "edx": hex(edx)
                    }
                    info["thread_context"] = dict(info["thread_registers"])
            except Exception:
                pass

        return info

    @classmethod
    def _correlate_fault(cls, exception_info: Optional[Dict[str, Any]], modules: List[Dict[str, Any]]) -> None:
        """Determines the enclosing faulting module and relative virtual address (FaultingOffset/RVA)."""
        if not exception_info or "exception_address_int" not in exception_info:
            return

        exc_addr = exception_info["exception_address_int"]
        fault_module = None
        fault_offset = None

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
            exception_info["fault_rva"] = fault_offset
            exception_info["fault_virtual_address"] = hex(exc_addr)
            exception_info["is_unloaded_or_unmapped"] = False
        else:
            exception_info["fault_module"] = "UNKNOWN_MODULE"
            exception_info["fault_offset"] = hex(exc_addr)
            exception_info["fault_rva"] = "0x0"
            exception_info["fault_virtual_address"] = hex(exc_addr)
            exception_info["is_unloaded_or_unmapped"] = True

        del exception_info["exception_address_int"]

    @classmethod
    def discover_local_dumps(cls, app_name_filter: Optional[str] = None) -> List[str]:
        """
        Discovers MiniDump files across standard Windows dump locations:
        - %LOCALAPPDATA%\\CrashDumps
        - %ProgramData%\\Microsoft\\Windows\\WER\\ReportArchive
        - %LOCALAPPDATA%\\Microsoft\\Windows\\WER\\ReportArchive
        - %SYSTEMROOT%\\Minidump
        """
        search_dirs = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps"),
            os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\WER\ReportArchive"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\WER\ReportArchive"),
            os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "Minidump")
        ]

        dmp_files = []
        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            for f in glob.glob(os.path.join(d, "**", "*.dmp"), recursive=True):
                if app_name_filter:
                    filter_lower = os.path.basename(app_name_filter).lower()
                    if filter_lower not in os.path.basename(f).lower():
                        continue
                dmp_files.append(f)

        return sorted(dmp_files, key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)

    @classmethod
    def audit_dumps(cls, app_name_filter: Optional[str] = None, max_dumps: int = 5) -> Dict[str, Any]:
        """Conducts a complete audit of crash dumps on the host system."""
        dumps = cls.discover_local_dumps(app_name_filter)
        parsed_reports = []
        for dmp_path in dumps[:max_dumps]:
            res = cls.parse_minidump(dmp_path)
            if res.get("status") == "success":
                parsed_reports.append(res)

        return {
            "status": "success",
            "filter": app_name_filter,
            "total_dumps_discovered": len(dumps),
            "dumps_analyzed": len(parsed_reports),
            "crash_reports": parsed_reports
        }
