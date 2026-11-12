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
import sys
from typing import Dict, Any, List, Optional, Tuple, Union

from security.execution_guard import ExecutionGuard
from security.capability_registry import Capability
from .minidump_parser import MiniDumpParser
from .virtual_memory_inspector import VirtualMemoryInspector, ProcessMemoryMapSnapshot

try:
    import capstone
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

        # 3. Disassembly of the Instruction Window
        disasm_report = cls._disassemble_fault_window(
            binary_path=binary_path,
            fault_module=fault_module,
            fault_rva=fault_rva,
            arch=arch,
            parsed_dump=parsed_dump
        )

        # 4. Operand and Register Blame Analysis
        blame_analysis = cls._attribute_culprit_register(
            disasm_report=disasm_report,
            registers=registers,
            target_vaddr=target_vaddr,
            access_type=access_type,
            spatial_verdict=spatial_verdict
        )

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
            "remediation_advice": cls._generate_remediation(root_cause, culprit_reg, fault_module, fault_rva)
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

        # Check against modules in dump
        for mod in parsed_dump.get("modules", []):
            m_base = int(mod.get("base_address", "0x0"), 16) if isinstance(mod.get("base_address"), str) else int(mod.get("base_address", 0))
            m_size = int(mod.get("size", 0))
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

    @classmethod
    def _disassemble_fault_window(
        cls,
        binary_path: Optional[str],
        fault_module: str,
        fault_rva: int,
        arch: str,
        parsed_dump: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Disassembles the instruction stream surrounding the faulting instruction."""
        if not HAS_CAPSTONE or fault_rva == 0:
            return {
                "available": False,
                "reason": "Capstone disassembler not available or invalid fault RVA"
            }

        # Locate binary file on disk if not provided
        resolved_bin = binary_path
        if not resolved_bin or not os.path.isfile(resolved_bin):
            for m in parsed_dump.get("modules", []):
                if m.get("name", "").lower() == fault_module.lower():
                    cand_path = m.get("path")
                    if cand_path and os.path.isfile(cand_path):
                        resolved_bin = cand_path
                        break

        if not resolved_bin or not os.path.isfile(resolved_bin):
            return {
                "available": False,
                "reason": f"Target binary '{fault_module}' not found on local disk for offline disassembly."
            }

        try:
            from binary_neural_engine import BinaryFormatInspector
            pe_info = BinaryFormatInspector.inspect(resolved_bin)
            file_offset = BinaryFormatInspector.rva_to_offset(pe_info, fault_rva)
            if file_offset is None:
                return {
                    "available": False,
                    "reason": f"Fault RVA 0x{fault_rva:X} does not map to any initialized file section in '{resolved_bin}'."
                }

            mode = CS_MODE_64 if arch == "x64" else CS_MODE_32
            md = Cs(CS_ARCH_X86, mode)
            md.detail = True

            # 1. Guaranteed disassembly of the offending instruction and forward window
            with open(resolved_bin, "rb") as f:
                f.seek(file_offset)
                fwd_chunk = f.read(64)

            fwd_instructions = list(md.disasm(fwd_chunk, fault_rva))
            if not fwd_instructions:
                return {
                    "available": False,
                    "reason": f"Failed to decode machine code at fault RVA 0x{fault_rva:X}."
                }

            offending_inst = {
                "rva": f"0x{fwd_instructions[0].address:X}",
                "mnemonic": fwd_instructions[0].mnemonic,
                "op_str": fwd_instructions[0].op_str,
                "bytes": fwd_instructions[0].bytes.hex(),
                "is_faulting_instruction": True
            }

            # 2. Synchronized lookback for preceding instructions
            max_lookback = min(32, file_offset)
            with open(resolved_bin, "rb") as f:
                f.seek(file_offset - max_lookback)
                lookback_bytes = f.read(max_lookback)

            best_pre = []
            for back_off in range(max_lookback, 0, -1):
                trial_chunk = lookback_bytes[max_lookback - back_off:]
                trial_base = fault_rva - back_off
                trial_insts = list(md.disasm(trial_chunk, trial_base))
                if trial_insts:
                    last_inst = trial_insts[-1]
                    if last_inst.address + last_inst.size == fault_rva:
                        best_pre = [{
                            "rva": f"0x{i.address:X}",
                            "mnemonic": i.mnemonic,
                            "op_str": i.op_str,
                            "bytes": i.bytes.hex(),
                            "is_faulting_instruction": False
                        } for i in trial_insts]
                        break

            all_instructions = best_pre + [offending_inst] + [{
                "rva": f"0x{i.address:X}",
                "mnemonic": i.mnemonic,
                "op_str": i.op_str,
                "bytes": i.bytes.hex(),
                "is_faulting_instruction": False
            } for i in fwd_instructions[1:6]]

            return {
                "available": True,
                "binary_analyzed": resolved_bin,
                "faulting_rva": f"0x{fault_rva:X}",
                "offending_instruction": offending_inst,
                "instructions": all_instructions
            }

        except Exception as e:
            return {
                "available": False,
                "reason": f"Disassembly inspection error: {e}"
            }

    @classmethod
    def _attribute_culprit_register(
        cls,
        disasm_report: Dict[str, Any],
        registers: Dict[str, Any],
        target_vaddr: Optional[int],
        access_type: str,
        spatial_verdict: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlates the memory operand in the faulting instruction with register context."""
        if target_vaddr is None:
            return {
                "root_cause": "UNKNOWN_TARGET_ADDRESS",
                "confidence": "LOW_NON_MEMORY_OR_INCOMPLETE",
                "culprit_register": None,
                "culprit_value": None,
                "details": spatial_verdict.get("description", "No faulting memory address recorded in exception payload.")
            }

        offending = disasm_report.get("offending_instruction") if disasm_report.get("available") else None

        # Fallback if disassembly is unavailable
        if not offending:
            if spatial_verdict.get("is_null_trap"):
                return {
                    "root_cause": "PROBABLE_NULL_POINTER_DEREFERENCE",
                    "confidence": "HIGH_HEURISTIC",
                    "culprit_register": None,
                    "culprit_value": None,
                    "details": f"Target address 0x{target_vaddr:X} is in NULL page trap buffer. (Disassembly offline)."
                }
            if spatial_verdict.get("category") == "POISONED_POINTER":
                # Check which register held the poisoned value
                culprit_r = None
                culprit_v = None
                for r_name, r_val_raw in registers.items():
                    if r_name == "arch":
                        continue
                    try:
                        r_int = int(r_val_raw, 16) if isinstance(r_val_raw, str) else int(r_val_raw)
                        if r_int in cls.POISON_PATTERNS:
                            culprit_r = r_name.upper()
                            culprit_v = f"0x{r_int:016X}"
                            break
                    except ValueError:
                        pass
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
                "details": f"Memory access violation at 0x{target_vaddr:X} without local instruction context."
            }

        op_str = offending.get("op_str", "")
        # Parse memory operand: e.g. "qword ptr [rcx + 0x28]" or "[rax]" or "[rdi + rsi*4]"
        mem_match = re.search(r"\[([a-z0-9\+\*\s_]+)\]", op_str, re.IGNORECASE)
        if not mem_match:
            return {
                "root_cause": f"UNEXPECTED_FAULT_ON_{offending.get('mnemonic', 'INST').upper()}",
                "confidence": "MEDIUM_HEURISTIC",
                "culprit_register": None,
                "culprit_value": None,
                "details": f"Faulting instruction '{offending.get('mnemonic')} {op_str}' has no bracketed memory operand."
            }

        mem_expr = mem_match.group(1).lower().replace(" ", "")
        candidate_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]

        found_reg = None
        for r in candidate_regs:
            if r in mem_expr:
                found_reg = r
                break

        if not found_reg:
            return {
                "root_cause": "COMPLEX_MEMORY_OPERAND_FAULT",
                "confidence": "LOW_HEURISTIC",
                "culprit_register": None,
                "culprit_value": None,
                "details": f"Could not identify base register in memory expression [{mem_expr}]."
            }

        sub_to_64 = {
            "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
            "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
        }
        reg_candidates = [found_reg, found_reg.upper()]
        if found_reg in sub_to_64:
            reg_candidates.extend([sub_to_64[found_reg], sub_to_64[found_reg].upper()])
        reg_key = next((k for k in reg_candidates if k in registers), None)
        if reg_key is None:
            return {
                "root_cause": f"REGISTER_UNAVAILABLE_{access_type}",
                "confidence": "LOW_HEURISTIC",
                "culprit_register": found_reg.upper(),
                "culprit_value": None,
                "operand_expression": f"[{mem_expr}]",
                "details": f"Register {found_reg.upper()} is absent from thread register context; cannot verify pointer value."
            }
        reg_val_str = registers[reg_key]
        try:
            reg_val = int(reg_val_str, 16) if isinstance(reg_val_str, str) else int(reg_val_str)
            if found_reg in sub_to_64 and reg_key.lower() == sub_to_64[found_reg]:
                reg_val &= 0xFFFFFFFF
        except (ValueError, TypeError):
            reg_val = 0

        # Extract numeric displacement (e.g. + 0x28 or + 40)
        disp = 0
        disp_match = re.search(r"([+-](?:0x[0-9a-f]+|[0-9]+))", mem_expr)
        if disp_match:
            try:
                disp = int(disp_match.group(1), 0)
            except ValueError:
                disp = 0

        # Mathematical verification: (reg_val + disp) == target_vaddr
        computed_addr = (reg_val + disp) & 0xFFFFFFFFFFFFFFFF
        is_exact_match = (computed_addr == target_vaddr) or (reg_val == target_vaddr and disp == 0)

        # 1. Deterministic NULL pointer dereference
        if reg_val == 0:
            return {
                "root_cause": "DETERMINISTIC_NULL_POINTER_DEREFERENCE",
                "confidence": "CONFIDENT_DETERMINISTIC" if is_exact_match else "HIGH_HEURISTIC",
                "culprit_register": found_reg.upper(),
                "culprit_value": f"0x{reg_val:016X}",
                "displacement": f"0x{disp:X}",
                "operand_expression": f"[{mem_expr}]",
                "details": f"Register {found_reg.upper()} is NULL (0x0). Instruction attempted to access [{found_reg.upper()} + 0x{disp:X}] = 0x{target_vaddr:X}, tripping the Windows zero-page trap buffer."
            }

        # 2. Poison / Freed Heap Dereference
        for p_val, p_desc in cls.POISON_PATTERNS.items():
            if reg_val == p_val:
                return {
                    "root_cause": "USE_AFTER_FREE_OR_UNINITIALIZED",
                    "confidence": "CONFIDENT_DETERMINISTIC",
                    "culprit_register": found_reg.upper(),
                    "culprit_value": f"0x{reg_val:016X}",
                    "displacement": f"0x{disp:X}",
                    "operand_expression": f"[{mem_expr}]",
                    "details": f"Register {found_reg.upper()} contains allocator poison pattern: {p_desc}. Memory was accessed after being freed or was never initialized."
                }

        # 3. Stack Overflow or Out of Bounds
        if found_reg in ("rsp", "esp", "rbp", "ebp") and spatial_verdict.get("category") == "STACK_GUARD":
            return {
                "root_cause": "STACK_OVERFLOW_GUARD_PAGE_VIOLATION",
                "confidence": "CONFIDENT_DETERMINISTIC",
                "culprit_register": found_reg.upper(),
                "culprit_value": f"0x{reg_val:016X}",
                "details": f"Stack pointer {found_reg.upper()} collided with stack guard page, indicating uncontrolled recursion or excessive stack allocation."
            }

        return {
            "root_cause": f"WILD_POINTER_DEREFERENCE_{access_type}",
            "confidence": "HIGH_HEURISTIC" if is_exact_match else "MEDIUM_HEURISTIC",
            "culprit_register": found_reg.upper(),
            "culprit_value": f"0x{reg_val:016X}",
            "displacement": f"0x{disp:X}",
            "operand_expression": f"[{mem_expr}]",
            "details": f"Register {found_reg.upper()} contains an invalid pointer (0x{reg_val:X}). Computed address 0x{computed_addr:X} is unmapped or protected."
        }

    @classmethod
    def _generate_remediation(
        cls,
        root_cause: str,
        culprit_reg: Optional[str],
        module: str,
        rva: int
    ) -> str:
        """Synthesizes actionable remediation instructions for the software developer."""
        rva_hex = f"0x{rva:X}"
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
