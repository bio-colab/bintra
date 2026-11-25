# -*- coding: utf-8 -*-
"""
Automated Crash Root Cause Analysis (RCA) Engine.
Correlates Windows MiniDump (.dmp) ExceptionRecords, full thread context registers,
and target memory operand bounds with Capstone machine code disassembly and
VirtualMemoryInspector spatial page classifications.
Provides deterministic attribution of Access Violations (0xC0000005) and Stack Overflows (0xC00000FD).
Strictly read-only; governed by ExecutionGuard and Capability.MINIDUMP_READ.
"""

import os
import re
from typing import Dict, Any, List, Optional, Tuple, Union

from security.execution_guard import ExecutionGuard
from security.capability_registry import Capability
from .minidump_parser import MiniDumpParser
from .virtual_memory_inspector import VirtualMemoryInspector

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False


class CrashRootCauseAnalyzer:
    """
    Authoritative crash diagnostic and root-cause attribution engine.
    Bridges post-mortem exception records with live disassembly and spatial memory bounds.
    """

    NULL_PAGE_BOUND = 0x10000

    POISON_PATTERNS = {
        0xCCCCCCCCCCCCCCCC: "MSVC_UNINITIALIZED_STACK_VARIABLE (0xCC)",
        0xCDCDCDCDCDCDCDCD: "MSVC_CLEAN_HEAP_ALLOCATION (0xCD)",
        0xDDDDDDDDDDDDDDDD: "MSVC_DEAD_FREED_HEAP_BLOCK (0xDD)",
        0xFDFDFDFDFDFDFDFD: "MSVC_NO_MANS_LAND_GUARD_PAGE (0xFD)",
        0xFEEEFEEEFEEEFEEE: "NT_HEAP_FREED_BLOCK (0xFEEE)",
        0xBAADF00DBAADF00D: "NT_HEAP_UNINITIALIZED_ALLOCATION (0xBAADF00D)",
    }

    @classmethod
    def analyze_crash(
        cls,
        dump_target: Union[str, Dict[str, Any]],
        binary_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Synthesizes a comprehensive Root Cause Analysis (RCA) report from a MiniDump.
        Mediated by ExecutionGuard with Capability.MINIDUMP_READ and Capability.FILE_READ.
        """
        ExecutionGuard.request_access(
            component="crash_rca_engine",
            operation="analyze_crash",
            target=str(dump_target) if isinstance(dump_target, str) else "parsed_dump_dict",
            capability=Capability.MINIDUMP_READ,
            access_mode="READ"
        )

        # 1. Parse MiniDump if file path provided
        if isinstance(dump_target, str):
            parsed_dump = MiniDumpParser.parse_minidump(dump_target)
        else:
            parsed_dump = dump_target

        if not parsed_dump or parsed_dump.get("status") != "success":
            return {
                "status": "error",
                "message": "Invalid or unparseable MiniDump record",
                "dump_result": parsed_dump
            }

        exc_info = parsed_dump.get("exception_info") or {}
        exc_code_raw = exc_info.get("exception_code", "0x0")
        try:
            exc_code = int(exc_code_raw, 16) if isinstance(exc_code_raw, str) else int(exc_code_raw)
        except ValueError:
            exc_code = 0

        exc_name = exc_info.get("exception_name", "UNKNOWN_EXCEPTION")
        fault_module = exc_info.get("fault_module", "Unknown")
        is_unmapped = bool(exc_info.get("is_unloaded_or_unmapped")) or fault_module in ("UNKNOWN_MODULE", "UNKNOWN_OR_UNLOADED_MODULE")
        fault_offset_str = exc_info.get("fault_offset", "0x0")
        try:
            parsed_offset = int(fault_offset_str, 16) if isinstance(fault_offset_str, str) else int(fault_offset_str)
        except ValueError:
            parsed_offset = 0
        fault_rva = 0 if is_unmapped else parsed_offset
        fault_va_str = exc_info.get("exception_address") or exc_info.get("fault_virtual_address") or hex(parsed_offset)

        registers = exc_info.get("thread_registers") or {}
        arch = registers.get("arch", "x64")

        # Access Violation parameters
        av_details = exc_info.get("access_violation_details") or {}
        access_type = av_details.get("access_type") or av_details.get("operation") or "UNKNOWN"
        target_vaddr_raw = av_details.get("target_virtual_address")
        if target_vaddr_raw is None:
            target_vaddr_raw = av_details.get("target_address")
        target_vaddr: Optional[int] = None
        if target_vaddr_raw is not None:
            try:
                target_vaddr = int(target_vaddr_raw, 16) if isinstance(target_vaddr_raw, str) else int(target_vaddr_raw)
            except (ValueError, TypeError):
                target_vaddr = None

        # 2. Memory Spatial Classification of Target Address
        spatial_verdict = cls._classify_target_memory(target_vaddr, parsed_dump)

        fault_va_int: Optional[int] = None
        try:
            fault_va_int = int(fault_va_str, 16) if isinstance(fault_va_str, str) else int(fault_va_str)
        except (ValueError, TypeError):
            fault_va_int = None

        # 3. Disassembly of the Instruction Window
        disasm_report = cls._disassemble_fault_window(
            binary_path=binary_path,
            fault_module=fault_module,
            fault_rva=fault_rva,
            arch=arch,
            parsed_dump=parsed_dump,
            fault_va=fault_va_int,
        )

        # 4. Operand and Register Blame Analysis
        control_transfer = cls._classify_control_transfer_fault(
            access_type=access_type,
            target_vaddr=target_vaddr,
            fault_va=fault_va_int,
            registers=registers,
            parsed_dump=parsed_dump,
        )
        if control_transfer is not None:
            blame_analysis = control_transfer
        else:
            blame_analysis = cls._attribute_culprit_register(
                disasm_report=disasm_report,
                registers=registers,
                target_vaddr=target_vaddr,
                access_type=access_type,
                spatial_verdict=spatial_verdict
            )

        # 4b. Non access-violation exceptions carry their root cause in the code itself.
        if blame_analysis.get("root_cause") == "UNKNOWN_TARGET_ADDRESS":
            non_av = cls._classify_non_av_exception(exc_code, exc_info.get("parameters") or [])
            if non_av is not None:
                blame_analysis = non_av

        # 5. Build RCA Dossier
        root_cause = blame_analysis["root_cause"]
        confidence = blame_analysis["confidence"]
        culprit_reg = blame_analysis.get("culprit_register")
        culprit_val = blame_analysis.get("culprit_value")

        return {
            "status": "success",
            "exception_code": f"0x{exc_code:08X}",
            "exception_name": exc_name,
            "fault_module": fault_module,
            "fault_rva": f"0x{fault_rva:X}",
            "fault_virtual_address": fault_va_str,
            "is_unmapped_fault_address": is_unmapped,
            "architecture": arch,
            "access_type": access_type,
            "target_address": f"0x{target_vaddr:016X}" if target_vaddr is not None else "UNAVAILABLE",
            "root_cause_classification": root_cause,
            "confidence": confidence,
            "culprit_register": culprit_reg,
            "culprit_register_value": culprit_val,
            "memory_spatial_classification": spatial_verdict,
            "disassembly_window": disasm_report,
            "blame_details": blame_analysis,
            "remediation_advice": cls._generate_remediation(
                root_cause,
                culprit_reg,
                fault_module,
                fault_rva,
                probable_caller=blame_analysis.get("probable_caller"),
            )
        }

    @classmethod
    def _classify_target_memory(cls, target_vaddr: int, parsed_dump: Dict[str, Any]) -> Dict[str, Any]:
        """Classifies the target memory location violated by the exception."""
        if target_vaddr is None:
            return {
                "category": "UNKNOWN_TARGET_ADDRESS",
                "severity": "UNKNOWN",
                "description": "Exception record has no target virtual address (non-memory exception or incomplete dump)."
            }
        if target_vaddr < cls.NULL_PAGE_BOUND:
            return {
                "category": "NULL_PAGE_TRAP",
                "status": "DETERMINISTIC_NULL_DEREFERENCE",
                "offset_from_null": target_vaddr,
                "is_null_trap": True,
                "description": f"Target address 0x{target_vaddr:X} is within the 64 KB Windows zero-page trap buffer (0x0 - 0x10000)."
            }

        # Check for poison / debug allocation patterns
        for pattern_val, pattern_desc in cls.POISON_PATTERNS.items():
            if target_vaddr == pattern_val:
                return {
                    "category": "POISONED_POINTER",
                    "status": "USE_AFTER_FREE_OR_UNINITIALIZED",
                    "pattern": pattern_desc,
                    "description": f"Target address matches known debug allocator poison pattern: {pattern_desc}."
                }

        # Check thread stacks in dump
        for th in parsed_dump.get("threads", []):
            st_base_raw = th.get("stack_base")
            st_size = th.get("stack_size_bytes", 0)
            if st_base_raw and st_size > 0:
                try:
                    st_base = int(st_base_raw, 16) if isinstance(st_base_raw, str) else int(st_base_raw)
                    if st_size > 0 and st_base <= target_vaddr < (st_base + st_size):
                        return {
                            "category": "THREAD_STACK",
                            "status": "VALID_STACK_REGION",
                            "thread_id": th.get("thread_id"),
                            "description": f"Target address resides within the stack bounds of Thread {th.get('thread_id')}."
                        }
                except ValueError:
                    pass

        # Check memory segments if present in dump
        for mem in parsed_dump.get("memory_segments", []):
            m_start = mem.get("start", 0)
            m_size = mem.get("size", 0)
            if m_start <= target_vaddr < m_start + m_size:
                return {
                    "category": mem.get("category", "COMMITTED_DYNAMIC_MEMORY"),
                    "status": "VALID_MAPPED_SEGMENT",
                    "description": f"Target address belongs to committed memory segment at 0x{m_start:X} ({m_size} bytes)."
                }

        # Memory captured inside the dump (MemoryListStream / Memory64ListStream) was
        # readable at crash time, so it is mapped (the fault is a protection issue).
        for rng in parsed_dump.get("memory_ranges", []) or []:
            try:
                r_start, r_end = int(rng.get("start_va", 0)), int(rng.get("end_va", 0))
            except (TypeError, ValueError):
                continue
            if r_start <= target_vaddr < r_end:
                return {
                    "category": "CAPTURED_MAPPED_MEMORY",
                    "status": "VALID_MAPPED_SEGMENT",
                    "region_start": f"0x{r_start:X}",
                    "description": f"Target address lies in memory captured by the dump (0x{r_start:X}-0x{r_end:X}); it was mapped at crash time, so the fault is a protection/ownership violation rather than an unmapped pointer."
                }

        # Check against modules in dump
        for mod in parsed_dump.get("modules", []):
            m_base = cls._to_int(mod.get("base_address", 0))
            m_size = cls._to_int(mod.get("size", 0))
            if m_base <= target_vaddr < m_base + m_size:
                return {
                    "category": "MODULE_IMAGE",
                    "module_name": mod.get("name"),
                    "rva": f"0x{target_vaddr - m_base:X}",
                    "description": f"Target address resides within loaded module {mod.get('name')}."
                }

        # Cross-query live VAD only if PID is recorded in dump (Stream 15), live, and target_vaddr is known
        pid = parsed_dump.get("process_id")
        if pid and pid > 0 and target_vaddr is not None:
            try:
                snap = VirtualMemoryInspector.inspect_process(pid)
                if not getattr(snap, "is_simulated", False):
                    cls_info = snap.classify_address(target_vaddr)
                    if cls_info.get("status") == "COMMITTED":
                        enriched = dict(cls_info)
                        enriched["vad_live_pid_reuse_caveat"] = (
                            f"Live VAD state queried from PID {pid}; verify process start time against dump timestamp to rule out PID reuse."
                        )
                        return enriched
            except Exception:
                pass

        return {
            "category": "UNMAPPED_DYNAMIC_MEMORY",
            "status": "WILD_OR_FREED_POINTER",
            "description": "Target address does not belong to any mapped PE module or thread stack (likely unallocated heap or dangling pointer)."
        }

    @staticmethod
    def _to_int(value: Any, default: int = 0) -> int:
        try:
            if isinstance(value, str):
                return int(value, 16) if value.lower().startswith("0x") else int(value)
            return int(value)
        except (TypeError, ValueError):
            return default

    @classmethod
    def _read_dump_memory(cls, parsed_dump: Dict[str, Any], va: int, length: int) -> Optional[bytes]:
        """Reads bytes captured in the dump's memory list at virtual address `va`."""
        dump_path = parsed_dump.get("file_path")
        if not dump_path or va is None or not os.path.isfile(dump_path):
            return None
        for rng in parsed_dump.get("memory_ranges", []) or []:
            try:
                r_start, r_end, f_rva = int(rng["start_va"]), int(rng["end_va"]), int(rng["file_rva"])
            except (KeyError, TypeError, ValueError):
                continue
            if r_start <= va < r_end:
                n = min(length, r_end - va)
                try:
                    with open(dump_path, "rb") as fh:
                        fh.seek(f_rva + (va - r_start))
                        data = fh.read(n)
                    return data or None
                except OSError:
                    return None
        return None

    @staticmethod
    def _read_pe_identity(path: str) -> Optional[Tuple[int, int, int]]:
        """Returns (TimeDateStamp, SizeOfImage, CheckSum) from a PE header, or None."""
        import struct
        try:
            with open(path, "rb") as fh:
                hdr = fh.read(4096)
            if hdr[:2] != b"MZ":
                return None
            e_lfanew = struct.unpack_from("<I", hdr, 0x3C)[0]
            if e_lfanew + 24 + 68 > len(hdr) or hdr[e_lfanew:e_lfanew + 4] != b"PE\0\0":
                return None
            timestamp = struct.unpack_from("<I", hdr, e_lfanew + 8)[0]
            size_of_image = struct.unpack_from("<I", hdr, e_lfanew + 24 + 56)[0]
            checksum = struct.unpack_from("<I", hdr, e_lfanew + 24 + 64)[0]
            return timestamp, size_of_image, checksum
        except (OSError, struct.error):
            return None

    @classmethod
    def _verify_module_image(
        cls,
        path: str,
        mod_rec: Optional[Dict[str, Any]],
        pe_info: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str]:
        """
        Compares an on-disk image against the module record captured in the dump.
        Requires strong build identity (CodeView RSDS GUID+Age or non-zero CheckSum +
        TimeDateStamp + SizeOfImage) before returning 'VERIFIED'. Timestamp+SizeOfImage
        alone returns 'HEADER_MATCH_ONLY' (treated as unverified for deterministic blame).
        """
        if not mod_rec:
            return "UNVERIFIABLE", "No module record in the dump to compare against."
        ident = cls._read_pe_identity(path)
        if ident is None:
            return "UNVERIFIABLE", f"'{path}' has no readable PE header."
        exp_ts = mod_rec.get("timestamp")
        exp_size = mod_rec.get("size")
        exp_csum = cls._to_int(mod_rec.get("checksum"), 0)
        exp_pdb = mod_rec.get("pdb") if isinstance(mod_rec.get("pdb"), dict) else None
        if exp_ts in (None, 0) and exp_size in (None, 0) and exp_csum == 0 and not exp_pdb:
            return "UNVERIFIABLE", "Dump module record carries no PE identity metadata."
        disk_ts, disk_size, disk_csum = ident
        mismatches = []
        if exp_ts not in (None, 0) and cls._to_int(exp_ts) != disk_ts:
            mismatches.append(f"TimeDateStamp dump=0x{cls._to_int(exp_ts):08X} disk=0x{disk_ts:08X}")
        if exp_size not in (None, 0) and cls._to_int(exp_size) != disk_size:
            mismatches.append(f"SizeOfImage dump=0x{cls._to_int(exp_size):X} disk=0x{disk_size:X}")
        if exp_csum != 0 and disk_csum != exp_csum:
            mismatches.append(f"CheckSum dump=0x{exp_csum:08X} disk=0x{disk_csum:08X}")

        pdb_verified = False
        if exp_pdb and exp_pdb.get("signature") == "RSDS" and exp_pdb.get("guid"):
            if pe_info is None:
                try:
                    from binary_neural_engine import BinaryFormatInspector
                    pe_info = BinaryFormatInspector.inspect(path)
                except Exception:
                    pe_info = None
            dbg = pe_info.get("debug_directory", {}) if isinstance(pe_info, dict) else {}
            disk_guid = str(dbg.get("pdb_guid") or "").strip("{}").lower()
            disk_age = dbg.get("pdb_age")
            exp_guid = str(exp_pdb.get("guid") or "").strip("{}").lower()
            exp_age = exp_pdb.get("age")
            if disk_guid:
                if (exp_guid, exp_age) != (disk_guid, disk_age):
                    mismatches.append(f"CodeView RSDS dump={exp_guid}:{exp_age} disk={disk_guid}:{disk_age}")
                else:
                    pdb_verified = True

        if mismatches:
            return "MISMATCH", "On-disk image differs from the image loaded at crash time: " + "; ".join(mismatches)

        checksum_verified = bool(exp_csum != 0 and disk_csum == exp_csum)
        if pdb_verified or checksum_verified:
            evidence = "CodeView RSDS GUID/Age" if pdb_verified else "non-zero PE CheckSum + TimeDateStamp + SizeOfImage"
            return "VERIFIED", f"Strong build identity verified via {evidence}."

        return (
            "HEADER_MATCH_ONLY",
            "TimeDateStamp and SizeOfImage match, but no stronger build identity (CodeView RSDS GUID/Age or non-zero CheckSum) could be verified; treating disassembly as unverified.",
        )

    @staticmethod
    def _fmt_insn(i, faulting: bool) -> Dict[str, Any]:
        return {
            "rva": f"0x{i.address:X}",
            "mnemonic": i.mnemonic,
            "op_str": i.op_str,
            "bytes": i.bytes.hex(),
            "is_faulting_instruction": faulting,
        }

    @classmethod
    def _disassemble_window_from_reader(cls, md, read_at, fault_rva: int) -> Optional[Dict[str, Any]]:
        """Disassembles around `fault_rva` using `read_at(delta, length)` (delta relative to the fault)."""
        fwd_chunk = read_at(0, 64)
        if not fwd_chunk:
            return None
        fwd = list(md.disasm(fwd_chunk, fault_rva))
        if not fwd:
            return None
        best_pre: List[Dict[str, Any]] = []
        lookback = read_at(-32, 32) or b""
        n = len(lookback)
        for back_off in range(n, 0, -1):
            trial = list(md.disasm(lookback[n - back_off:], fault_rva - back_off))
            if trial and trial[-1].address + trial[-1].size == fault_rva:
                best_pre = [cls._fmt_insn(i, False) for i in trial]
                break
        offending = cls._fmt_insn(fwd[0], True)
        return {
            "offending_instruction": offending,
            "instructions": best_pre + [offending] + [cls._fmt_insn(i, False) for i in fwd[1:6]],
        }

    @classmethod
    def _disassemble_fault_window(
        cls,
        binary_path: Optional[str],
        fault_module: str,
        fault_rva: int,
        arch: str,
        parsed_dump: Dict[str, Any],
        fault_va: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Disassembles the instruction stream surrounding the faulting instruction.

        Code-byte provenance, in order of trust:
          1. DUMP_MEMORY  - bytes captured inside the dump at the faulting VA (exact runtime code).
          2. ON_DISK_IMAGE of the *faulting module* (never another module), identity-checked
             against the dump's module record; a proven version MISMATCH is refused.
        """
        if not HAS_CAPSTONE:
            return {"available": False, "reason": "Capstone disassembler is not installed."}
        if fault_rva == 0:
            return {"available": False, "reason": "Fault address is not inside any loaded module (unmapped/unloaded code or a jump to an invalid address); there is no module image to disassemble."}

        mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True

        mod_rec = next((m for m in parsed_dump.get("modules", []) if str(m.get("name", "")).lower() == str(fault_module).lower()), None)
        notes: List[str] = []

        # 1. Exact runtime bytes captured in the dump itself
        if fault_va is not None and parsed_dump.get("memory_ranges"):
            def _dump_reader(delta: int, ln: int) -> Optional[bytes]:
                va = fault_va + delta
                return cls._read_dump_memory(parsed_dump, va, ln) if va >= 0 else None

            win = cls._disassemble_window_from_reader(md, _dump_reader, fault_rva)
            if win:
                win.update({
                    "available": True,
                    "code_source": "DUMP_MEMORY",
                    "image_identity": "RUNTIME_BYTES",
                    "binary_analyzed": parsed_dump.get("file_path"),
                    "faulting_rva": f"0x{fault_rva:X}",
                })
                return win

        # 2. On-disk image of the faulting module only
        candidates: List[str] = []
        if binary_path and os.path.isfile(binary_path):
            if os.path.basename(binary_path).lower() == str(fault_module).lower():
                candidates.append(binary_path)
            else:
                notes.append(f"Provided binary '{os.path.basename(binary_path)}' is not the faulting module '{fault_module}'; it was not used for disassembly.")
        if mod_rec and mod_rec.get("path") and os.path.isfile(mod_rec["path"]) and mod_rec["path"] not in candidates:
            candidates.append(mod_rec["path"])

        if not candidates:
            return {
                "available": False,
                "reason": f"Faulting module '{fault_module}' is not available on local disk and its code bytes were not captured in the dump.",
                "notes": notes,
            }

        last_reason = ""
        for resolved_bin in candidates:
            identity, identity_detail = cls._verify_module_image(resolved_bin, mod_rec)
            if identity == "MISMATCH":
                last_reason = f"{identity_detail} ('{resolved_bin}'). Disassembling it would describe different code than what crashed."
                continue
            try:
                from binary_neural_engine import BinaryFormatInspector
                pe_info = BinaryFormatInspector.inspect(resolved_bin)
                file_offset = BinaryFormatInspector.rva_to_offset(pe_info, fault_rva)
                if file_offset is None:
                    last_reason = f"Fault RVA 0x{fault_rva:X} does not map to any initialized file section in '{resolved_bin}'."
                    continue

                def _disk_reader(delta: int, ln: int, _p=resolved_bin, _o=file_offset) -> Optional[bytes]:
                    pos = _o + delta
                    if pos < 0:
                        ln += pos
                        pos = 0
                    if ln <= 0:
                        return None
                    with open(_p, "rb") as fh:
                        fh.seek(pos)
                        return fh.read(ln)

                win = cls._disassemble_window_from_reader(md, _disk_reader, fault_rva)
                if not win:
                    last_reason = f"Failed to decode machine code at fault RVA 0x{fault_rva:X} in '{resolved_bin}'."
                    continue
                win.update({
                    "available": True,
                    "code_source": "ON_DISK_IMAGE",
                    "image_identity": identity,
                    "image_identity_detail": identity_detail,
                    "binary_analyzed": resolved_bin,
                    "faulting_rva": f"0x{fault_rva:X}",
                })
                if notes:
                    win["notes"] = notes
                return win
            except Exception as e:
                last_reason = f"Disassembly inspection error: {e}"
        return {"available": False, "reason": last_reason or "No usable code source.", "notes": notes}

    @classmethod
    def _module_for_address(cls, parsed_dump: Dict[str, Any], va: int) -> Optional[Tuple[str, int]]:
        for mod in parsed_dump.get("modules", []) or []:
            base = cls._to_int(mod.get("base_address", mod.get("base_int", 0)))
            size = cls._to_int(mod.get("size", 0))
            if base and size and base <= va < base + size:
                return str(mod.get("name")), va - base
        return None

    @classmethod
    def _classify_control_transfer_fault(
        cls,
        access_type: str,
        target_vaddr: Optional[int],
        fault_va: Optional[int],
        registers: Dict[str, Any],
        parsed_dump: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Execute faults where the instruction pointer itself is the bad address (call/jmp/ret
        through a NULL or corrupted pointer). There is no faulting instruction to disassemble;
        the most useful evidence is the return address left on top of the stack.
        """
        is_exec = "EXECUTE" in str(access_type).upper()
        if not is_exec or target_vaddr is None:
            return None
        if fault_va is not None and fault_va != target_vaddr:
            return None
        arch = str(registers.get("arch", "x64"))
        ptr_size = 8 if arch == "x64" else 4
        sp_key = next((k for k in ("rsp", "RSP", "esp", "ESP") if k in registers), None)
        caller = None
        if sp_key is not None:
            sp = cls._to_int(registers[sp_key])
            raw = cls._read_dump_memory(parsed_dump, sp, ptr_size)
            if raw and len(raw) == ptr_size:
                ret = int.from_bytes(raw, "little")
                hit = cls._module_for_address(parsed_dump, ret)
                caller = {
                    "return_address": f"0x{ret:X}",
                    "module": hit[0] if hit else None,
                    "module_rva": f"0x{hit[1]:X}" if hit else None,
                }
        ip_name = "RIP" if ptr_size == 8 else "EIP"
        if target_vaddr < cls.NULL_PAGE_BOUND:
            root = "NULL_FUNCTION_POINTER_CALL"
            why = f"The instruction pointer itself is 0x{target_vaddr:X}: control was transferred (call/jmp/ret) through a NULL or near-NULL function pointer."
        else:
            root = "INVALID_CONTROL_TRANSFER"
            why = f"The instruction pointer 0x{target_vaddr:X} is not executable (DEP/NX or unmapped): a corrupted function pointer, vtable entry or return address."
        if caller and caller.get("module"):
            why += f" The top-of-stack return address points into {caller['module']}+{caller['module_rva']}, the probable caller."
        return {
            "root_cause": root,
            "confidence": "HIGH_HEURISTIC",
            "culprit_register": ip_name,
            "culprit_value": f"0x{target_vaddr:X}",
            "probable_caller": caller,
            "details": why,
        }

    _REG_ALIASES = {
        "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
        "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    }
    _REG_RE = re.compile(r"^(r(?:[0-9]|1[0-5])[dwb]?|[re]?(?:ax|bx|cx|dx|si|di|bp|sp|ip))$")

    @classmethod
    def _parse_memory_operand(cls, expr: str) -> Dict[str, Any]:
        """Parses 'base + index*scale +/- disp' (Intel syntax, spaces removed) into components."""
        expr = expr.split(":")[-1]  # drop segment prefix
        tokens = [t for t in expr.replace("-", "+-").split("+") if t]
        base = index = None
        scale = 1
        disp = 0
        for t in tokens:
            neg = t.startswith("-")
            core = t[1:] if neg else t
            if "*" in core:
                a, b = core.split("*", 1)
                reg, num = (a, b) if cls._REG_RE.match(a) else (b, a)
                index = reg
                try:
                    scale = int(num, 0)
                except ValueError:
                    scale = 1
            elif cls._REG_RE.match(core):
                if base is None:
                    base = core
                else:
                    index, scale = core, 1
            else:
                try:
                    v = int(core, 0)
                    disp += -v if neg else v
                except ValueError:
                    pass
        return {"base": base, "index": index, "scale": scale, "disp": disp}

    @classmethod
    def _reg_value(cls, registers: Dict[str, Any], reg: str) -> Optional[int]:
        names = [reg, reg.upper()]
        wide = cls._REG_ALIASES.get(reg)
        if wide:
            names += [wide, wide.upper()]
        for n in names:
            if n in registers:
                v = cls._to_int(registers[n], default=-1)
                if v < 0:
                    return None
                if wide and n.lower() == wide:
                    v &= 0xFFFFFFFF
                return v
        return None

    @classmethod
    def _attribute_culprit_register(
        cls,
        disasm_report: Dict[str, Any],
        registers: Dict[str, Any],
        target_vaddr: Optional[int],
        access_type: str,
        spatial_verdict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Correlates the memory operand of the faulting instruction with the thread context.
        A register is only blamed when base + index*scale + disp reproduces the faulting
        address exactly; otherwise the evidence is reported as inconsistent instead of
        inventing a NULL dereference.
        """
        if target_vaddr is None:
            return {
                "root_cause": "UNKNOWN_TARGET_ADDRESS",
                "confidence": "LOW_NON_MEMORY_OR_INCOMPLETE",
                "culprit_register": None,
                "culprit_value": None,
                "details": spatial_verdict.get("description", "No faulting memory address recorded in exception payload.")
            }

        offending = disasm_report.get("offending_instruction") if disasm_report.get("available") else None

        if not offending:
            if spatial_verdict.get("is_null_trap"):
                return {
                    "root_cause": "PROBABLE_NULL_POINTER_DEREFERENCE",
                    "confidence": "HIGH_HEURISTIC",
                    "culprit_register": None,
                    "culprit_value": None,
                    "details": f"Target address 0x{target_vaddr:X} is in NULL page trap buffer. (Disassembly unavailable: {disasm_report.get('reason', 'n/a')})."
                }
            if spatial_verdict.get("category") == "POISONED_POINTER":
                culprit_r = None
                culprit_v = None
                for r_name, r_val_raw in registers.items():
                    if r_name == "arch":
                        continue
                    r_int = cls._to_int(r_val_raw, default=-1)
                    if r_int in cls.POISON_PATTERNS:
                        culprit_r = r_name.upper()
                        culprit_v = f"0x{r_int:016X}"
                        break
                return {
                    "root_cause": "USE_AFTER_FREE_OR_UNINITIALIZED",
                    "confidence": "CONFIDENT_DETERMINISTIC" if culprit_r else "HIGH_HEURISTIC",
                    "culprit_register": culprit_r,
                    "culprit_value": culprit_v,
                    "details": spatial_verdict.get("description", "Target address matches allocator poison pattern.")
                }
            return {
                "root_cause": f"INVALID_MEMORY_{access_type}",
                "confidence": "MEDIUM_HEURISTIC",
                "culprit_register": None,
                "culprit_value": None,
                "details": f"Memory access violation at 0x{target_vaddr:X} without local instruction context ({disasm_report.get('reason', 'disassembly unavailable')})."
            }

        verified_code = (
            disasm_report.get("code_source") == "DUMP_MEMORY"
            or disasm_report.get("image_identity") in ("VERIFIED", "RUNTIME_BYTES", None)
        )
        op_str = offending.get("op_str", "")
        mem_match = re.search(r"\[([a-z0-9\+\-\*\s_:]+)\]", op_str, re.IGNORECASE)
        if not mem_match:
            return {
                "root_cause": f"UNEXPECTED_FAULT_ON_{offending.get('mnemonic', 'INST').upper()}",
                "confidence": "MEDIUM_HEURISTIC",
                "culprit_register": None,
                "culprit_value": None,
                "details": f"Faulting instruction '{offending.get('mnemonic')} {op_str}' has no explicit memory operand (implicit stack/string access)."
            }

        mem_expr = mem_match.group(1).lower().replace(" ", "")
        parts = cls._parse_memory_operand(mem_expr)
        base, index, scale, disp = parts["base"], parts["index"], parts["scale"], parts["disp"]
        if not base and not index:
            return {
                "root_cause": "COMPLEX_MEMORY_OPERAND_FAULT",
                "confidence": "LOW_HEURISTIC",
                "culprit_register": None,
                "culprit_value": None,
                "details": f"Could not identify base register in memory expression [{mem_expr}]."
            }
        if base in ("rip", "eip"):
            return {
                "root_cause": f"RIP_RELATIVE_ACCESS_FAULT_{access_type}",
                "confidence": "MEDIUM_HEURISTIC",
                "culprit_register": "RIP",
                "culprit_value": None,
                "operand_expression": f"[{mem_expr}]",
                "details": "Fault on a RIP-relative global access: the global/section mapping itself is invalid or protected (e.g. writing to read-only data)."
            }

        culprit = base or index
        base_val = cls._reg_value(registers, base) if base else 0
        index_val = cls._reg_value(registers, index) if index else 0
        if base_val is None or index_val is None:
            missing = base if base_val is None else index
            return {
                "root_cause": f"REGISTER_UNAVAILABLE_{access_type}",
                "confidence": "LOW_HEURISTIC",
                "culprit_register": str(missing).upper(),
                "culprit_value": None,
                "operand_expression": f"[{mem_expr}]",
                "details": f"Register {str(missing).upper()} is absent from thread register context; cannot verify pointer value."
            }

        width_mask = 0xFFFFFFFF if str(registers.get("arch", "x64")) != "x64" else 0xFFFFFFFFFFFFFFFF
        computed_addr = (base_val + index_val * scale + disp) & width_mask
        is_exact_match = computed_addr == (target_vaddr & width_mask)
        culprit_val = base_val if base else index_val
        common: Dict[str, Any] = {
            "culprit_register": culprit.upper(),
            "culprit_value": f"0x{culprit_val:016X}",
            "displacement": f"0x{disp:X}" if disp >= 0 else f"-0x{-disp:X}",
            "operand_expression": f"[{mem_expr}]",
            "computed_address": f"0x{computed_addr:X}",
        }
        if index:
            common.update({"index_register": index.upper(), "index_value": f"0x{index_val:X}", "scale": scale})

        if not is_exact_match:
            return dict(common, **{
                "root_cause": "OPERAND_CONTEXT_MISMATCH",
                "confidence": "LOW_HEURISTIC",
                "details": (
                    f"Decoded operand [{mem_expr}] evaluates to 0x{computed_addr:X} with the captured registers, but the "
                    f"faulting address is 0x{target_vaddr:X}. The disassembled code is probably not what executed "
                    f"(mismatched image or mis-synchronised decode), so no register is blamed."
                ),
            })

        confidence = "CONFIDENT_DETERMINISTIC" if verified_code else "HIGH_HEURISTIC"
        if culprit_val == 0 or (target_vaddr < cls.NULL_PAGE_BOUND and culprit_val < cls.NULL_PAGE_BOUND):
            return dict(common, **{
                "root_cause": "DETERMINISTIC_NULL_POINTER_DEREFERENCE",
                "confidence": confidence,
                "details": f"Register {culprit.upper()} is NULL (0x{culprit_val:X}). Instruction accessed [{mem_expr}] = 0x{target_vaddr:X}, tripping the Windows zero-page trap buffer."
            })

        for p_val, p_desc in cls.POISON_PATTERNS.items():
            if (culprit_val & width_mask) == (p_val & width_mask):
                return dict(common, **{
                    "root_cause": "USE_AFTER_FREE_OR_UNINITIALIZED",
                    "confidence": confidence,
                    "details": f"Register {culprit.upper()} contains allocator poison pattern: {p_desc}. Memory was accessed after being freed or was never initialized."
                })

        if culprit in ("rsp", "esp", "rbp", "ebp") and spatial_verdict.get("category") in ("STACK_GUARD", "THREAD_STACK"):
            return dict(common, **{
                "root_cause": "STACK_OVERFLOW_GUARD_PAGE_VIOLATION",
                "confidence": confidence,
                "details": f"Stack pointer {culprit.upper()} collided with the stack guard page, indicating uncontrolled recursion or excessive stack allocation."
            })

        if spatial_verdict.get("status") == "VALID_MAPPED_SEGMENT":
            return dict(common, **{
                "root_cause": f"PROTECTION_VIOLATION_{access_type}",
                "confidence": confidence,
                "details": f"[{mem_expr}] = 0x{computed_addr:X} points into memory that was mapped at crash time; the {str(access_type).lower()} violated its page protection (e.g. writing read-only/shared data, or a stale pointer into a reused region)."
            })

        return dict(common, **{
            "root_cause": f"WILD_POINTER_DEREFERENCE_{access_type}",
            "confidence": confidence if verified_code else "MEDIUM_HEURISTIC",
            "details": f"Register {culprit.upper()} holds an invalid pointer (0x{culprit_val:X}); [{mem_expr}] = 0x{computed_addr:X} is unmapped or protected."
        })

    FAST_FAIL_CODES = {
        0: "FAST_FAIL_LEGACY_GS_VIOLATION", 1: "FAST_FAIL_VTGUARD_CHECK_FAILURE",
        2: "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE", 3: "FAST_FAIL_CORRUPT_LIST_ENTRY",
        4: "FAST_FAIL_INCORRECT_STACK", 5: "FAST_FAIL_INVALID_ARG", 6: "FAST_FAIL_GS_COOKIE_INIT",
        7: "FAST_FAIL_FATAL_APP_EXIT", 8: "FAST_FAIL_RANGE_CHECK_FAILURE",
        9: "FAST_FAIL_UNSAFE_REGISTRY_ACCESS", 10: "FAST_FAIL_GUARD_ICALL_CHECK_FAILURE",
        11: "FAST_FAIL_GUARD_WRITE_CHECK_FAILURE", 13: "FAST_FAIL_INVALID_FIBER_SWITCH",
        14: "FAST_FAIL_INVALID_SET_OF_CONTEXT", 15: "FAST_FAIL_INVALID_REFERENCE_COUNT",
        18: "FAST_FAIL_INVALID_JUMP_BUFFER", 19: "FAST_FAIL_MRDATA_MODIFIED",
        20: "FAST_FAIL_CERTIFICATION_FAILURE", 21: "FAST_FAIL_INVALID_EXCEPTION_CHAIN",
        22: "FAST_FAIL_CRYPTO_LIBRARY", 23: "FAST_FAIL_INVALID_CALL_IN_DLL_CALLOUT",
        24: "FAST_FAIL_INVALID_IMAGE_BASE", 25: "FAST_FAIL_DLOAD_PROTECTION_FAILURE",
        26: "FAST_FAIL_UNSAFE_EXTENSION_CALL", 37: "FAST_FAIL_GUARD_SS_FAILURE",
        38: "FAST_FAIL_LOADER_CONTINUITY_FAILURE", 48: "FAST_FAIL_HEAP_METADATA_CORRUPTION",
    }

    NON_AV_ROOT_CAUSES = {
        0xC00000FD: ("STACK_OVERFLOW", "HIGH_HEURISTIC", "The thread exhausted its stack (unbounded recursion or very large stack allocations)."),
        0xC0000374: ("HEAP_CORRUPTION", "HIGH_HEURISTIC", "The NT heap detected corrupted metadata (buffer overrun, double free or use-after-free earlier in execution)."),
        0xC0000409: ("STACK_BUFFER_OVERRUN_OR_FAST_FAIL", "HIGH_HEURISTIC", "The process terminated itself via __fastfail or a /GS security check; the sub-code identifies which integrity check failed."),
        0xC0000602: ("FAIL_FAST_EXCEPTION", "HIGH_HEURISTIC", "The process requested immediate termination (RaiseFailFastException) after detecting an unrecoverable state."),
        0xC000027B: ("WINRT_STOWED_EXCEPTION", "HIGH_HEURISTIC", "An unhandled WinRT/UWP exception was stowed and re-raised by the app model; the original error is in the stowed exception information (restricted error string / HRESULT)."),
        0x40000015: ("FATAL_APP_EXIT_ABORT", "HIGH_HEURISTIC", "The application called abort() or FatalAppExit (CRT abort, failed assertion or unhandled std::terminate)."),
        0xE06D7363: ("UNHANDLED_CPP_EXCEPTION", "HIGH_HEURISTIC", "A C++ exception (throw) propagated to the top of the thread without a matching catch."),
        0x80000003: ("BREAKPOINT_OR_DEBUG_ASSERT", "MEDIUM_HEURISTIC", "An int3 breakpoint executed without a debugger (DebugBreak, __debugbreak or a failed debug assertion)."),
        0xC0000420: ("ASSERTION_FAILURE", "HIGH_HEURISTIC", "A runtime assertion (int 2c) failed."),
        0xC000001D: ("ILLEGAL_INSTRUCTION", "HIGH_HEURISTIC", "The CPU met an undefined opcode (corrupted code, jump into data, or an instruction set extension the CPU lacks such as AVX)."),
        0xC0000096: ("PRIVILEGED_INSTRUCTION", "HIGH_HEURISTIC", "A privileged instruction ran in user mode (corrupted code or jump into data)."),
        0xC0000094: ("INTEGER_DIVIDE_BY_ZERO", "HIGH_HEURISTIC", "An integer division by zero was executed."),
        0xC0000095: ("INTEGER_OVERFLOW", "HIGH_HEURISTIC", "An integer overflow trap was raised."),
        0xC0000006: ("IN_PAGE_ERROR", "HIGH_HEURISTIC", "A page could not be read from its backing file (disk/network error, or the image was replaced/removed while running)."),
        0xC0000008: ("INVALID_HANDLE", "HIGH_HEURISTIC", "An invalid or already-closed handle was used."),
        0xC0000017: ("OUT_OF_MEMORY", "HIGH_HEURISTIC", "A memory allocation could not be satisfied."),
        0xC0000135: ("DLL_NOT_FOUND", "HIGH_HEURISTIC", "A statically imported DLL could not be located by the loader."),
        0xC0000139: ("ENTRYPOINT_NOT_FOUND", "HIGH_HEURISTIC", "An imported function is missing from the DLL that was loaded (version mismatch)."),
        0xC0000142: ("DLL_INIT_FAILED", "HIGH_HEURISTIC", "A DLL's DllMain returned FALSE during process initialization."),
        0xC06D007E: ("DELAYLOAD_MODULE_NOT_FOUND", "HIGH_HEURISTIC", "A delay-loaded DLL could not be found on first use."),
        0xC06D007F: ("DELAYLOAD_PROC_NOT_FOUND", "HIGH_HEURISTIC", "A delay-loaded function is missing from its DLL."),
        0xC0000194: ("POSSIBLE_DEADLOCK", "MEDIUM_HEURISTIC", "A critical section wait timed out (possible deadlock)."),
        0xCFFFFFFF: ("APPLICATION_HANG", "MEDIUM_HEURISTIC", "The dump was taken for a hung (non-responsive) application, not a crash."),
    }

    @classmethod
    def _classify_non_av_exception(cls, exc_code: int, parameters: List[Any]) -> Optional[Dict[str, Any]]:
        entry = cls.NON_AV_ROOT_CAUSES.get(exc_code)
        if entry is None:
            return None
        root, conf, details = entry
        result: Dict[str, Any] = {
            "root_cause": root,
            "confidence": conf,
            "culprit_register": None,
            "culprit_value": None,
            "details": details,
        }
        if exc_code == 0xC0000409 and parameters:
            sub = cls._to_int(parameters[0], default=-1)
            if sub >= 0:
                name = cls.FAST_FAIL_CODES.get(sub, f"FAST_FAIL_CODE_{sub}")
                result["fast_fail_code"] = sub
                result["fast_fail_name"] = name
                result["details"] += f" Sub-code {sub} = {name}."
        return result

    @classmethod
    def _generate_remediation(
        cls,
        root_cause: str,
        culprit_reg: Optional[str],
        module: str,
        rva: int,
        probable_caller: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Synthesizes actionable remediation instructions for the software developer."""
        rva_hex = f"0x{rva:X}"
        if root_cause in ("NULL_FUNCTION_POINTER_CALL", "INVALID_CONTROL_TRANSFER"):
            caller_mod = (probable_caller or {}).get("module")
            caller_rva = (probable_caller or {}).get("module_rva")
            caller_ret = (probable_caller or {}).get("return_address")
            if caller_mod and caller_rva:
                caller_loc = (
                    f"`{caller_mod}+{caller_rva}` (return address `{caller_ret}`)"
                    if caller_ret
                    else f"`{caller_mod}+{caller_rva}`"
                )
                if root_cause == "NULL_FUNCTION_POINTER_CALL":
                    return (
                        f"Control transferred to NULL/zero through an indirect call, jump, or vtable slot "
                        f"near probable caller {caller_loc}. Inspect the indirect call site preceding "
                        f"`{caller_mod}+{caller_rva}` and guard the function/vtable pointer against `nullptr`."
                    )
                return (
                    f"Control transferred to non-executable or unmapped memory near `{module}+{rva_hex}` "
                    f"from probable caller {caller_loc}. Audit indirect call targets, vtable integrity, "
                    f"and stack return addresses around `{caller_mod}+{caller_rva}`."
                )
        if "NULL_POINTER" in root_cause:
            reg_name = culprit_reg or "object pointer"
            return (
                f"Verify that `{reg_name}` is checked for NULL before invocation at `{module}+{rva_hex}`. "
                f"Add a defensive guard: `if ({reg_name.lower()} == nullptr) {{ return / handle_error(); }}`."
            )
        if "USE_AFTER_FREE" in root_cause:
            return (
                f"Investigate object lifecycle for pointer in `{culprit_reg}` at `{module}+{rva_hex}`. "
                "Ensure pointer is set to `nullptr` immediately after `free()` or `delete`, or migrate to smart pointers (`std::shared_ptr`/`std::unique_ptr`)."
            )
        non_av_advice = {
            "WINRT_STOWED_EXCEPTION": f"Extract the stowed exception (restricted error string / HRESULT) from the dump (WinDbg: !pde.dse) to find the original failing WinRT call before {module}+{rva_hex}; wrap async continuations in try/catch.",
            "FATAL_APP_EXIT_ABORT": f"Find who called abort()/std::terminate near {module}+{rva_hex}: check failed assert(), exceptions escaping destructors or noexcept functions, and pure virtual calls.",
            "UNHANDLED_CPP_EXCEPTION": f"Catch the C++ exception propagating out of {module}+{rva_hex}, or add a handler at the thread entry point.",
            "HEAP_CORRUPTION": "Reproduce with PageHeap (gflags /p /enable <exe> /full) or AddressSanitizer to catch the first invalid heap write.",
            "STACK_BUFFER_OVERRUN_OR_FAST_FAIL": f"Inspect the fast-fail sub-code; for stack cookie failures audit local buffers of the function at {module}+{rva_hex} for overruns.",
            "DLL_NOT_FOUND": "Run 'bintra resolve-deps --binary <exe>' to identify the missing DLL and redistribute it.",
            "ENTRYPOINT_NOT_FOUND": "Run 'bintra resolve-deps --binary <exe>'; an older DLL than expected is being loaded.",
            "ILLEGAL_INSTRUCTION": "Check whether the binary requires CPU features (AVX/AVX2) the host lacks, or whether code was overwritten.",
            "APPLICATION_HANG": "Inspect all thread stacks for lock waits; this is a hang, not a memory fault.",
        }
        if root_cause in non_av_advice:
            return non_av_advice[root_cause]
        if "STACK_OVERFLOW" in root_cause:
            return (
                f"Review call graph leading to `{module}+{rva_hex}` for unbounded recursion or large local buffer allocations (`alloca` / stack arrays). "
                "Allocate large buffers on the heap or enforce recursion depth limits."
            )
        return f"Audit memory safety and pointer bounds surrounding `{module}+{rva_hex}`."

    @classmethod
    def format_markdown(cls, report: Dict[str, Any]) -> str:
        """Formats the RCA report into an executive diagnostic Markdown document."""
        if report.get("status") != "success":
            return f"# Crash RCA Error\n{report.get('message', 'Unknown failure')}"

        lines = [
            "# Bintra Automated Crash Root-Cause Analysis (RCA)",
            f"- **Exception Code:** `{report.get('exception_code')}` ({report.get('exception_name')})",
            f"- **Faulting Module:** `{report.get('fault_module')}` (RVA: `{report.get('fault_rva')}`)",
            f"- **Target Address:** `{report.get('target_address')}` (Violation: `{report.get('access_type')}`)",
            f"- **Root Cause Verdict:** **`{report.get('root_cause_classification')}`**",
            f"- **Confidence:** `{report.get('confidence')}`",
        ]

        if report.get("culprit_register"):
            lines.append(f"- **Culprit Register:** `{report.get('culprit_register')}` = `{report.get('culprit_register_value')}`")

        # Disassembly window
        disasm = report.get("disassembly_window", {})
        if disasm.get("available") and disasm.get("instructions"):
            lines.append("\n### Offending Instruction Disassembly Window")
            lines.append("```x86asm")
            for inst in disasm.get("instructions", []):
                ptr = "--> " if inst.get("is_faulting_instruction") else "    "
                lines.append(f"{ptr}{inst['rva']}:  {inst['mnemonic']:<8} {inst['op_str']}")
            lines.append("```")

        # Blame details
        blame = report.get("blame_details", {})
        if blame.get("details"):
            lines.append("\n### Diagnostic Attribution")
            lines.append(f"> {blame.get('details')}")

        # Remediation
        if report.get("remediation_advice"):
            lines.append("\n### Remediation Guidance")
            lines.append(f"💡 {report.get('remediation_advice')}")

        return "\n".join(lines)
