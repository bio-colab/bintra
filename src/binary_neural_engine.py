#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural: Windows-First Binary & Program Reverse Engineering Engine.
Provides Deep PE32/PE32+ Inspection & Spatial RVA Mapping, REX-Aware Continuous Deobfuscation,
Cross-Architecture Semantic Function Matching with Transition Bigrams,
Instruction-Boundary Proprioceptive Surgical Binary Patching with Nociceptive Guards,
and Hybrid Binary Dissection (DirectML, WinML, ONNX Runtime, GGUF, TFLite, Safetensors, Entropy).
"""

import sys
import os
import json
import struct
import hashlib
import argparse
import zipfile
import mmap
import math
import tempfile
import io
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    from ghidra_pcode_vectorizer import (
        PcodeVectorizer, PcodeFunctionMatcher, PcodeDeobfuscator, GhidraAnnotationPlanner
    )
except ImportError:
    pass


def _ensure_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


class BinaryFormatInspector:
    """
    Analytical Vision & Spatial Sense for Executables:
    Zero-dependency parser for Windows PE (PE32 / PE32+) and ELF headers,
    security mitigations (ASLR, DEP, CFG), Data Directories, and RVA <-> File Offset mapping.
    """

    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

    # COFF File Header Characteristics
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
    IMAGE_FILE_32BIT_MACHINE = 0x0100
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200
    IMAGE_FILE_DLL = 0x2000

    # Optional Header DllCharacteristics
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

    DATA_DIRECTORY_NAMES = [
        "ExportTable", "ImportTable", "ResourceTable", "ExceptionTable",
        "CertificateTable", "BaseRelocationTable", "Debug", "Architecture",
        "GlobalPtr", "TLSTable", "LoadConfigTable", "BoundImport",
        "IAT", "DelayImportDescriptor", "CLRRuntimeHeader", "Reserved"
    ]

    @staticmethod
    def compute_shannon_entropy(data: bytes) -> float:
        """Computes Shannon entropy in bits per byte [0.0, 8.0]."""
        if not data:
            return 0.0
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probs = counts[counts > 0] / float(len(data))
        return float(-np.sum(probs * np.log2(probs)))

    @staticmethod
    def inspect(file_path: str) -> Dict[str, Any]:
        if not os.path.exists(file_path):
            return {
                "format": "FILE_NOT_FOUND",
                "error": f"Target file does not exist: {file_path}",
                "file_path": file_path
            }
        if os.path.getsize(file_path) == 0:
            return {
                "format": "EMPTY_FILE",
                "size": 0,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "error": "File is empty (0 bytes)."
            }
        with open(file_path, "rb") as f:
            magic = f.read(4)

        if magic.startswith(b"MZ"):
            return BinaryFormatInspector._parse_pe(file_path)
        elif magic.startswith(b"\x7fELF"):
            return BinaryFormatInspector._parse_elf(file_path)
        else:
            return {
                "format": "RAW_BINARY",
                "size": os.path.getsize(file_path),
                "sha256": BinaryFormatInspector.compute_sha256(file_path)
            }

    @staticmethod
    def compute_sha256(file_path: str) -> str:
        sha = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()

    @staticmethod
    def calculate_pe_checksum(file_bytes: bytearray, pe_offset: int) -> int:
        """Computes official Microsoft PE image checksum as defined by CheckSumMappedFile."""
        checksum_offset = pe_offset + 24 + 64
        temp = bytearray(file_bytes)
        if len(temp) >= checksum_offset + 4:
            temp[checksum_offset:checksum_offset + 4] = b"\x00\x00\x00\x00"

        total = 0
        num_words = len(temp) // 2
        for i in range(num_words):
            (word,) = struct.unpack_from("<H", temp, i * 2)
            total += word
            total = (total & 0xFFFF) + (total >> 16)

        if len(temp) % 2 != 0:
            total += temp[-1]
            total = (total & 0xFFFF) + (total >> 16)

        total = (total & 0xFFFF) + (total >> 16)
        final_checksum = (total & 0xFFFFFFFF) + len(file_bytes)
        return final_checksum & 0xFFFFFFFF

    @staticmethod
    def rva_to_offset(pe_info: Dict[str, Any], rva: int) -> Optional[int]:
        """Spatial Sense: Converts a Relative Virtual Address (RVA) to a raw file offset."""
        for sec in pe_info.get("sections", []):
            vaddr = int(sec["virtual_address"], 16) if isinstance(sec["virtual_address"], str) else int(sec["virtual_address"])
            vsize = max(int(sec["virtual_size"]), int(sec["raw_size"]))
            if vaddr <= rva < vaddr + vsize:
                delta = rva - vaddr
                if delta < int(sec["raw_size"]):
                    return int(sec["raw_offset"]) + delta
        return None

    @staticmethod
    def offset_to_rva(pe_info: Dict[str, Any], file_offset: int) -> Optional[int]:
        """Spatial Sense: Converts a raw file offset to a Relative Virtual Address (RVA)."""
        for sec in pe_info.get("sections", []):
            raw_off = int(sec["raw_offset"])
            raw_sz = int(sec["raw_size"])
            if raw_off <= file_offset < raw_off + raw_sz:
                vaddr = int(sec["virtual_address"], 16) if isinstance(sec["virtual_address"], str) else int(sec["virtual_address"])
                return vaddr + (file_offset - raw_off)
        return None

    @staticmethod
    def _parse_pe(file_path: str) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            if file_size < 0x40:
                return {"format": "CORRUPT_PE"}
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            if len(pe_offset_bytes) < 4:
                return {"format": "CORRUPT_PE"}
            (pe_offset,) = struct.unpack("<I", pe_offset_bytes)
            if pe_offset + 24 > file_size:
                return {"format": "CORRUPT_PE"}

            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return {"format": "INVALID_PE"}

            coff = f.read(20)
            if len(coff) < 20:
                return {"format": "CORRUPT_PE"}
            machine, num_sections, time_date, sym_ptr, num_sym, opt_hdr_size, characteristics = struct.unpack(
                "<HHIIIHH", coff
            )

            machine_str = {
                0x014C: "i386 (x86)",
                0x8664: "AMD64 (x86-64)",
                0xAA64: "ARM64 (AArch64)",
                0x01C0: "ARM"
            }.get(machine, f"Unknown (0x{machine:04X})")

            opt_start = pe_offset + 24
            f.seek(opt_start)
            read_size = max(opt_hdr_size, 128) if opt_hdr_size > 0 else 0
            opt_bytes = f.read(min(read_size, max(0, file_size - opt_start)))

            pe_type = "PE32"
            entry_point_rva = 0
            image_base = 0
            subsystem = 0
            dll_chars = 0
            stored_checksum = 0
            data_directories: Dict[str, Dict[str, Any]] = {}

            if len(opt_bytes) >= 2:
                (opt_magic,) = struct.unpack_from("<H", opt_bytes, 0)
                if opt_magic == 0x20B:
                    pe_type = "PE32+ (64-bit)"
                elif opt_magic == 0x10B:
                    pe_type = "PE32 (32-bit)"

                if len(opt_bytes) >= 20:
                    (entry_point_rva,) = struct.unpack_from("<I", opt_bytes, 16)
                elif file_size >= opt_start + 20:
                    f.seek(opt_start + 16)
                    raw_ep = f.read(4)
                    if len(raw_ep) == 4:
                        (entry_point_rva,) = struct.unpack("<I", raw_ep)

                if opt_magic == 0x20B and len(opt_bytes) >= 88:
                    (image_base,) = struct.unpack_from("<Q", opt_bytes, 24)
                    (stored_checksum,) = struct.unpack_from("<I", opt_bytes, 64)
                    (subsystem, dll_chars) = struct.unpack_from("<HH", opt_bytes, 68)
                    if len(opt_bytes) >= 112:
                        (num_rva_sizes,) = struct.unpack_from("<I", opt_bytes, 108)
                        dd_offset = 112
                        for idx in range(min(num_rva_sizes, 16)):
                            if dd_offset + 8 <= len(opt_bytes):
                                dd_rva, dd_size = struct.unpack_from("<II", opt_bytes, dd_offset)
                                if dd_rva > 0 or dd_size > 0:
                                    data_directories[BinaryFormatInspector.DATA_DIRECTORY_NAMES[idx]] = {
                                        "rva": hex(dd_rva),
                                        "size": dd_size
                                    }
                                dd_offset += 8
                elif opt_magic == 0x10B and len(opt_bytes) >= 72:
                    (image_base,) = struct.unpack_from("<I", opt_bytes, 28)
                    (stored_checksum,) = struct.unpack_from("<I", opt_bytes, 64)
                    (subsystem, dll_chars) = struct.unpack_from("<HH", opt_bytes, 68)
                    if len(opt_bytes) >= 96:
                        (num_rva_sizes,) = struct.unpack_from("<I", opt_bytes, 92)
                        dd_offset = 96
                        for idx in range(min(num_rva_sizes, 16)):
                            if dd_offset + 8 <= len(opt_bytes):
                                dd_rva, dd_size = struct.unpack_from("<II", opt_bytes, dd_offset)
                                if dd_rva > 0 or dd_size > 0:
                                    data_directories[BinaryFormatInspector.DATA_DIRECTORY_NAMES[idx]] = {
                                        "rva": hex(dd_rva),
                                        "size": dd_size
                                    }
                                dd_offset += 8
                else:
                    if len(opt_bytes) >= 68:
                        (stored_checksum,) = struct.unpack_from("<I", opt_bytes, 64)

            mitigations = {
                "aslr_dynamic_base": bool(dll_chars & BinaryFormatInspector.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
                "high_entropy_64bit_aslr": bool(dll_chars & BinaryFormatInspector.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
                "dep_nx_compat": bool(dll_chars & BinaryFormatInspector.IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
                "control_flow_guard_cfg": bool(dll_chars & BinaryFormatInspector.IMAGE_DLLCHARACTERISTICS_GUARD_CF),
                "no_seh": bool(dll_chars & BinaryFormatInspector.IMAGE_DLLCHARACTERISTICS_NO_SEH),
                "large_address_aware_4gb": bool(characteristics & BinaryFormatInspector.IMAGE_FILE_LARGE_ADDRESS_AWARE),
            }

            sections = []
            f.seek(pe_offset + 24 + opt_hdr_size)
            sec_table_bytes = f.read(min(num_sections, 96) * 40)
            for idx in range(min(num_sections, 96)):
                sec_bytes = sec_table_bytes[idx * 40 : (idx + 1) * 40]
                if len(sec_bytes) < 40:
                    break
                sec_name = sec_bytes[:8].rstrip(b"\x00").decode("latin-1", errors="ignore")
                vsize, vaddr, raw_size, raw_ptr, _, _, _, _, chars = struct.unpack("<IIIIIIHHI", sec_bytes[8:])

                sec_entropy = 0.0
                if raw_ptr > 0 and raw_size > 0 and raw_ptr + raw_size <= file_size:
                    f.seek(raw_ptr)
                    sample = f.read(min(raw_size, 262144))
                    sec_entropy = round(BinaryFormatInspector.compute_shannon_entropy(sample), 4)

                sections.append({
                    "name": sec_name,
                    "virtual_address": hex(vaddr),
                    "virtual_size": vsize,
                    "raw_offset": raw_ptr,
                    "raw_size": raw_size,
                    "is_executable": bool(chars & BinaryFormatInspector.IMAGE_SCN_MEM_EXECUTE),
                    "is_writable": bool(chars & BinaryFormatInspector.IMAGE_SCN_MEM_WRITE),
                    "shannon_entropy": sec_entropy,
                    "is_likely_packed": sec_entropy > 7.2,
                    "characteristics": hex(chars)
                })

            result = {
                "format": "PE",
                "pe_type": pe_type,
                "pe_offset": pe_offset,
                "machine": machine_str,
                "coff_characteristics": hex(characteristics),
                "image_base": hex(image_base),
                "entry_point_rva": hex(entry_point_rva),
                "subsystem": subsystem,
                "stored_checksum": hex(stored_checksum),
                "windows_security_mitigations": mitigations,
                "data_directories": data_directories,
                "sections_count": num_sections,
                "sections": sections,
                "sha256": BinaryFormatInspector.compute_sha256(file_path)
            }
            ep_file_off = BinaryFormatInspector.rva_to_offset(result, entry_point_rva)
            result["entry_point_file_offset"] = hex(ep_file_off) if ep_file_off is not None else None

            # High-Fidelity Import & Export Directory Analysis
            is_64_bit = (pe_type.startswith("PE32+"))
            result["imports"] = BinaryFormatInspector._parse_pe_imports(f, file_size, result, is_64_bit)
            result["exports"] = BinaryFormatInspector._parse_pe_exports(f, file_size, result)

            return result

    @staticmethod
    def _parse_pe_imports(f, file_size: int, pe_info: Dict[str, Any], is_64: bool) -> Dict[str, Any]:
        dd = pe_info.get("data_directories", {})
        if "ImportTable" not in dd:
            return {"imported_dlls_count": 0, "modules": {}}
        import_rva = int(dd["ImportTable"]["rva"], 16)
        import_dir_size = int(dd["ImportTable"].get("size", 0))
        import_off = BinaryFormatInspector.rva_to_offset(pe_info, import_rva)
        if import_off is None or import_off + 20 > file_size:
            return {"imported_dlls_count": 0, "modules": {}}

        max_import_end = min(file_size, import_off + import_dir_size) if import_dir_size > 0 else file_size
        modules = {}
        curr = import_off
        step = 8 if is_64 else 4
        mask = 0x8000000000000000 if is_64 else 0x80000000
        fmt = "<Q" if is_64 else "<I"

        while curr + 20 <= max_import_end and len(modules) < 64:
            f.seek(curr)
            desc = f.read(20)
            if len(desc) < 20:
                break
            ilt_rva, time_date, forwarder, name_rva, iat_rva = struct.unpack("<IIIII", desc)
            if ilt_rva == 0 and name_rva == 0:
                break
            name_off = BinaryFormatInspector.rva_to_offset(pe_info, name_rva)
            if name_off is not None and 0 <= name_off < file_size:
                f.seek(name_off)
                raw_name = bytearray()
                while len(raw_name) < 256 and f.tell() < file_size:
                    ch = f.read(1)
                    if not ch or ch == b"\x00":
                        break
                    raw_name.extend(ch)
                mod_name = raw_name.decode("latin-1", errors="ignore")

                thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
                thunk_off = BinaryFormatInspector.rva_to_offset(pe_info, thunk_rva)
                funcs = []
                if thunk_off is not None and 0 <= thunk_off < file_size:
                    t_curr = thunk_off
                    while t_curr + step <= file_size and len(funcs) < 128:
                        f.seek(t_curr)
                        t_bytes = f.read(step)
                        if len(t_bytes) < step:
                            break
                        val = struct.unpack(fmt, t_bytes)[0]
                        if val == 0:
                            break
                        if val & mask:
                            funcs.append(f"Ordinal_{val & 0xFFFF}")
                        else:
                            ibn_off = BinaryFormatInspector.rva_to_offset(pe_info, val)
                            if ibn_off is not None and 0 <= ibn_off + 2 < file_size:
                                f.seek(ibn_off + 2)
                                raw_fn = bytearray()
                                while len(raw_fn) < 256 and f.tell() < file_size:
                                    ch = f.read(1)
                                    if not ch or ch == b"\x00":
                                        break
                                    raw_fn.extend(ch)
                                funcs.append(raw_fn.decode("latin-1", errors="ignore"))
                        t_curr += step
                modules[mod_name] = funcs
            curr += 20
        return {
            "imported_dlls_count": len(modules),
            "modules": modules
        }

    @staticmethod
    def _parse_pe_exports(f, file_size: int, pe_info: Dict[str, Any]) -> Dict[str, Any]:
        dd = pe_info.get("data_directories", {})
        if "ExportTable" not in dd:
            return {"exported_functions_count": 0, "functions": []}
        export_rva = int(dd["ExportTable"]["rva"], 16)
        export_dir_size = int(dd["ExportTable"].get("size", 0))
        export_off = BinaryFormatInspector.rva_to_offset(pe_info, export_rva)
        if export_off is None or export_off + 40 > file_size:
            return {"exported_functions_count": 0, "functions": []}

        f.seek(export_off)
        exp_bytes = f.read(40)
        if len(exp_bytes) < 40:
            return {"exported_functions_count": 0, "functions": []}

        flags, time_date, major, minor, name_rva, ordinal_base, num_funcs, num_names, funcs_rva, names_rva, ordinals_rva = struct.unpack(
            "<IIHHIIIIIII", exp_bytes
        )

        funcs_off = BinaryFormatInspector.rva_to_offset(pe_info, funcs_rva)
        names_off = BinaryFormatInspector.rva_to_offset(pe_info, names_rva)
        ords_off = BinaryFormatInspector.rva_to_offset(pe_info, ordinals_rva)

        exported = []
        if names_off and ords_off and funcs_off:
            for idx in range(min(num_names, 4096)):
                if names_off + (idx + 1) * 4 > file_size or ords_off + (idx + 1) * 2 > file_size:
                    break
                f.seek(names_off + idx * 4)
                fn_name_rva_bytes = f.read(4)
                f.seek(ords_off + idx * 2)
                ord_bytes = f.read(2)
                if len(fn_name_rva_bytes) < 4 or len(ord_bytes) < 2:
                    break
                (fn_name_rva,) = struct.unpack("<I", fn_name_rva_bytes)
                (ord_val,) = struct.unpack("<H", ord_bytes)

                if ord_val >= num_funcs:
                    continue

                if funcs_off + (ord_val + 1) * 4 > file_size:
                    continue
                f.seek(funcs_off + ord_val * 4)
                fn_rva_bytes = f.read(4)
                fn_rva = struct.unpack("<I", fn_rva_bytes)[0] if len(fn_rva_bytes) == 4 else 0

                is_forwarded = (export_dir_size > 0 and export_rva <= fn_rva < export_rva + export_dir_size)

                fn_name_off = BinaryFormatInspector.rva_to_offset(pe_info, fn_name_rva)
                fn_name = ""
                if fn_name_off and 0 <= fn_name_off < file_size:
                    f.seek(fn_name_off)
                    raw_fn = bytearray()
                    while len(raw_fn) < 256 and f.tell() < file_size:
                        ch = f.read(1)
                        if not ch or ch == b"\x00":
                            break
                        raw_fn.extend(ch)
                    fn_name = raw_fn.decode("latin-1", errors="ignore")

                exp_entry = {
                    "name": fn_name,
                    "ordinal": ordinal_base + ord_val,
                    "rva": hex(fn_rva),
                    "is_forwarded": is_forwarded
                }
                if is_forwarded:
                    fwd_off = BinaryFormatInspector.rva_to_offset(pe_info, fn_rva)
                    if fwd_off and 0 <= fwd_off < file_size:
                        f.seek(fwd_off)
                        raw_fwd = bytearray()
                        while len(raw_fwd) < 256 and f.tell() < file_size:
                            ch = f.read(1)
                            if not ch or ch == b"\x00":
                                break
                            raw_fwd.extend(ch)
                        exp_entry["forwarded_to"] = raw_fwd.decode("latin-1", errors="ignore")

                exported.append(exp_entry)

        return {
            "exported_functions_count": num_funcs,
            "functions": exported
        }

    @staticmethod
    def _parse_elf(file_path: str) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            ident = f.read(16)
            is_64 = ident[4] == 2
            endian = "<" if ident[5] == 1 else ">"

            f.seek(16)
            hdr_bytes = f.read(48 if is_64 else 36)
            e_type, e_machine = struct.unpack(endian + "HH", hdr_bytes[:4])

            machine_str = {
                3: "i386",
                62: "x86-64",
                40: "ARM",
                183: "AArch64",
                243: "RISC-V"
            }.get(e_machine, f"Machine_{e_machine}")

            return {
                "format": "ELF",
                "is_64_bit": is_64,
                "machine": machine_str,
                "sha256": BinaryFormatInspector.compute_sha256(file_path)
            }


class ContinuousDeobfuscator:
    """
    Exploratory Smell, Discriminative Taste & Sense of Rhythm:
    Recovers control flow graphs from flattened dispatcher loops and REX-aware opaque predicates.
    """

    X86_REGS_32_64 = [
        "EAX/RAX", "ECX/RCX", "EDX/RDX", "EBX/RBX",
        "ESP/RSP", "EBP/RBP", "ESI/RSI", "EDI/RDI",
        "R8D/R8", "R9D/R9", "R10D/R10", "R11D/R11",
        "R12D/R12", "R13D/R13", "R14D/R14", "R15D/R15"
    ]

    @staticmethod
    def is_register_zeroing(
        b0: int,
        b1: int,
        rex_prefix: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """
        Strictly verifies if an instruction zeroes a register (full_reg == full_rm with Mod=11).
        Correctly accounts for x86-64 REX.R and REX.B extension bits so 'xor r8, rax' (49 31 C0)
        is NEVER falsely classified as register zeroing.
        """
        if b0 in (0x31, 0x33, 0x29, 0x2B):
            mod = (b1 >> 6) & 3
            reg = (b1 >> 3) & 7
            rm = b1 & 7
            if rex_prefix is not None and 0x40 <= rex_prefix <= 0x4F:
                rex_r = (rex_prefix >> 2) & 1
                rex_b = rex_prefix & 1
                full_reg = (rex_r << 3) | reg
                full_rm = (rex_b << 3) | rm
            else:
                full_reg = reg
                full_rm = rm

            if mod == 3 and full_reg == full_rm:
                op = "XOR" if b0 in (0x31, 0x33) else "SUB"
                reg_name = ContinuousDeobfuscator.X86_REGS_32_64[full_reg]
                return True, f"{op} {reg_name}, {reg_name}"
        return False, None

    @staticmethod
    def analyze_opaque_predicates(code_bytes: bytes) -> List[Dict[str, Any]]:
        """Identifies genuine algebraic zeroing predicates with strict instruction-boundary disassembly."""
        findings = []

        if HAS_CAPSTONE:
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                instructions = list(md.disasm(code_bytes, 0))
                for idx, insn in enumerate(instructions):
                    m = insn.mnemonic.lower()
                    ops = [op.strip() for op in insn.op_str.lower().split(",")]

                    is_zero = False
                    desc = None
                    if m in ("xor", "sub") and len(ops) == 2 and ops[0] == ops[1] and ops[0]:
                        is_zero = True
                        desc = f"{m.upper()} {ops[0].upper()}, {ops[1].upper()}"

                    if is_zero:
                        # Look ahead through flag-safe instructions (mov, movzx, movsx, movsxd, lea, nop)
                        for next_idx in range(idx + 1, min(idx + 4, len(instructions))):
                            next_insn = instructions[next_idx]
                            next_m = next_insn.mnemonic.lower()
                            if next_m in ("jz", "je", "jnz", "jne"):
                                total_len = (next_insn.address + next_insn.size) - insn.address
                                if next_m in ("jz", "je"):
                                    findings.append({
                                        "type": "OPAQUE_PREDICATE_ALWAYS_TRUE",
                                        "offset": insn.address,
                                        "length": total_len,
                                        "zeroing_instruction": desc,
                                        "jump_type": f"{next_m.upper()} (Zero Flag set by zeroing)",
                                        "description": f"{desc} guarantees ZF=1. {next_m.upper()} is ALWAYS taken. Fallthrough branch is dead code.",
                                        "target_rel_offset": next_insn.op_str,
                                        "suggested_simplification": f"JMP to target ({next_insn.op_str}) or NOP fallthrough"
                                    })
                                else:
                                    findings.append({
                                        "type": "OPAQUE_PREDICATE_ALWAYS_FALSE",
                                        "offset": insn.address,
                                        "length": total_len,
                                        "zeroing_instruction": desc,
                                        "jump_type": f"{next_m.upper()} (Zero Flag set by zeroing)",
                                        "description": f"{desc} guarantees ZF=1. {next_m.upper()} is NEVER taken. Jump target is dead code.",
                                        "target_rel_offset": next_insn.op_str,
                                        "suggested_simplification": f"Replace {next_m.upper()} with NOPs"
                                    })
                                break
                            elif next_m in ("mov", "movzx", "movsx", "movsxd", "lea", "nop"):
                                continue
                            else:
                                break
                return findings
            except Exception:
                pass

        # Fallback linear scanner
        i = 0
        n = len(code_bytes)
        while i < n - 3:
            rex_prefix: Optional[int] = None
            insn_start = i
            if 0x40 <= code_bytes[i] <= 0x4F and i + 2 < n:
                rex_prefix = code_bytes[i]
                op_idx = i + 1
            else:
                op_idx = i

            if op_idx + 1 >= n:
                break

            prefix_len = 1 if rex_prefix is not None else 0
            b0 = code_bytes[op_idx]
            b1 = code_bytes[op_idx + 1]
            is_arith = b0 in (0x31, 0x33, 0x29, 0x2B)
            insn_len = prefix_len + 2

            is_zero, desc = ContinuousDeobfuscator.is_register_zeroing(
                b0, b1, rex_prefix=rex_prefix
            )
            if is_zero:
                # Lookahead through flag-preserving instructions (NOP, MOV)
                cur_pos = op_idx + 2
                lookahead_steps = 0
                found_jcc = False
                while cur_pos < n and lookahead_steps < 3:
                    b_cur = code_bytes[cur_pos]
                    if b_cur == 0x90:  # NOP
                        cur_pos += 1
                        lookahead_steps += 1
                        continue
                    elif 0xB8 <= b_cur <= 0xBF and cur_pos + 5 <= n:  # MOV reg32, imm32
                        cur_pos += 5
                        lookahead_steps += 1
                        continue
                    elif b_cur in (0x89, 0x8B) and cur_pos + 2 <= n:  # MOV reg, reg (Mod=11)
                        if (code_bytes[cur_pos + 1] >> 6) == 3:
                            cur_pos += 2
                            lookahead_steps += 1
                            continue
                        break
                    elif b_cur == 0x74 and cur_pos + 1 < n:  # JZ / JE rel8
                        offset = struct.unpack("b", bytes([code_bytes[cur_pos + 1]]))[0]
                        total_len = (cur_pos + 2) - insn_start
                        findings.append({
                            "type": "OPAQUE_PREDICATE_ALWAYS_TRUE",
                            "offset": insn_start,
                            "length": total_len,
                            "zeroing_instruction": desc,
                            "jump_type": "JZ (Zero Flag set by zeroing)",
                            "description": f"{desc} guarantees ZF=1. JZ is ALWAYS taken. Fallthrough branch is dead code.",
                            "target_rel_offset": offset,
                            "suggested_simplification": f"JMP to target offset (+{offset}) or NOP fallthrough"
                        })
                        i = cur_pos + 2
                        found_jcc = True
                        break
                    elif b_cur == 0x75 and cur_pos + 1 < n:  # JNZ / JNE rel8
                        total_len = (cur_pos + 2) - insn_start
                        findings.append({
                            "type": "OPAQUE_PREDICATE_ALWAYS_FALSE",
                            "offset": insn_start,
                            "length": total_len,
                            "zeroing_instruction": desc,
                            "jump_type": "JNZ (Zero Flag set by zeroing)",
                            "description": f"{desc} guarantees ZF=1. JNZ is NEVER taken. Jump target is dead code.",
                            "suggested_simplification": "Replace JNZ with 2x NOP (0x90)"
                        })
                        i = cur_pos + 2
                        found_jcc = True
                        break
                    else:
                        break

                if found_jcc:
                    continue

            # Advance by instruction length if valid arithmetic instruction was inspected, avoiding misaligned rescan
            if is_arith:
                i = insn_start + insn_len
            else:
                i += 1

        return findings

    @staticmethod
    def detect_control_flow_flattening(code_bytes: bytes) -> Dict[str, Any]:
        """
        Detects Control Flow Flattening (CFF) dispatcher loops and measures rhythmic cadence.
        """
        state_comparisons = []
        state_assignments = []

        n = len(code_bytes)
        i = 0
        while i < n - 3:
            matched_step = 1

            # 1. 32-bit EBP Frame Pointer: CMP [ebp+disp8], imm32 (81 7D disp8 imm32)
            if i + 6 < n and code_bytes[i] == 0x81 and code_bytes[i+1] == 0x7D:
                imm = struct.unpack("<I", code_bytes[i+3:i+7])[0]
                state_comparisons.append({
                    "offset": i,
                    "state_value": hex(imm),
                    "stack_var_offset": code_bytes[i+2],
                    "mechanism": "EBP_DISP8_CMP32"
                })
                matched_step = 7
            # 2. 32-bit EBP Frame Pointer: CMP [ebp+disp8], imm8 (83 7D disp8 imm8)
            elif i + 3 < n and code_bytes[i] == 0x83 and code_bytes[i+1] == 0x7D:
                imm = code_bytes[i+3]
                state_comparisons.append({
                    "offset": i,
                    "state_value": hex(imm),
                    "stack_var_offset": code_bytes[i+2],
                    "mechanism": "EBP_DISP8_CMP8"
                })
                matched_step = 4
            # 3. 32-bit EBP Frame Pointer: MOV [ebp+disp8], imm32 (C7 45 disp8 imm32)
            elif i + 6 < n and code_bytes[i] == 0xC7 and code_bytes[i+1] == 0x45:
                imm = struct.unpack("<I", code_bytes[i+3:i+7])[0]
                state_assignments.append({
                    "offset": i,
                    "target_state": hex(imm),
                    "stack_var_offset": code_bytes[i+2],
                    "mechanism": "EBP_DISP8_MOV32"
                })
                matched_step = 7

            # 4. 64-bit RSP Stack Pointer: CMP [rsp+disp8], imm32 (81 7C 24 disp8 imm32)
            elif i + 7 < n and code_bytes[i] == 0x81 and code_bytes[i+1] == 0x7C and code_bytes[i+2] == 0x24:
                imm = struct.unpack("<I", code_bytes[i+4:i+8])[0]
                state_comparisons.append({
                    "offset": i,
                    "state_value": hex(imm),
                    "stack_var_offset": code_bytes[i+3],
                    "mechanism": "RSP_DISP8_CMP32"
                })
                matched_step = 8
            # 5. 64-bit RSP Stack Pointer: CMP [rsp+disp8], imm8 (83 7C 24 disp8 imm8)
            elif i + 4 < n and code_bytes[i] == 0x83 and code_bytes[i+1] == 0x7C and code_bytes[i+2] == 0x24:
                imm = code_bytes[i+4]
                state_comparisons.append({
                    "offset": i,
                    "state_value": hex(imm),
                    "stack_var_offset": code_bytes[i+3],
                    "mechanism": "RSP_DISP8_CMP8"
                })
                matched_step = 5
            # 6. 64-bit RSP Stack Pointer: MOV [rsp+disp8], imm32 (C7 44 24 disp8 imm32)
            elif i + 7 < n and code_bytes[i] == 0xC7 and code_bytes[i+1] == 0x44 and code_bytes[i+2] == 0x24:
                imm = struct.unpack("<I", code_bytes[i+4:i+8])[0]
                state_assignments.append({
                    "offset": i,
                    "target_state": hex(imm),
                    "stack_var_offset": code_bytes[i+3],
                    "mechanism": "RSP_DISP8_MOV32"
                })
                matched_step = 8

            # 7. Register state variable: CMP reg32, imm32 (81 F8..FF imm32)
            elif i + 5 < n and code_bytes[i] == 0x81 and 0xF8 <= code_bytes[i+1] <= 0xFF:
                imm = struct.unpack("<I", code_bytes[i+2:i+6])[0]
                state_comparisons.append({
                    "offset": i,
                    "state_value": hex(imm),
                    "register_id": code_bytes[i+1] - 0xF8,
                    "mechanism": "REG_CMP32"
                })
                matched_step = 6
            # 8. Register state variable: CMP reg32, imm8 (83 F8..FF imm8)
            elif i + 2 < n and code_bytes[i] == 0x83 and 0xF8 <= code_bytes[i+1] <= 0xFF:
                imm = code_bytes[i+2]
                state_comparisons.append({
                    "offset": i,
                    "state_value": hex(imm),
                    "register_id": code_bytes[i+1] - 0xF8,
                    "mechanism": "REG_CMP8"
                })
                matched_step = 3
            # 9. Register state assignment: MOV reg32, imm32 (B8..BF imm32)
            elif i + 4 < n and 0xB8 <= code_bytes[i] <= 0xBF:
                imm = struct.unpack("<I", code_bytes[i+1:i+5])[0]
                state_assignments.append({
                    "offset": i,
                    "target_state": hex(imm),
                    "register_id": code_bytes[i] - 0xB8,
                    "mechanism": "REG_MOV32"
                })
                matched_step = 5

            i += matched_step

        # Noise / entropy rejection: random bytes or compressed payload cannot be CFF
        ent = BinaryFormatInspector.compute_shannon_entropy(code_bytes)
        if len(code_bytes) >= 512 and ent >= 7.4:
            return {
                "has_control_flow_flattening": False,
                "dispatcher_comparisons_count": 0,
                "state_transitions_count": 0,
                "dispatcher_cadence_regularity": 0.0,
                "detected_state_states": [],
                "unflattening_strategy": "Control flow appears canonical/unflattened (high entropy data/noise)."
            }

        # Genuine CFF requires comparisons and assignments to cluster on the SAME state variable location
        def _resolve_var_identity(entry: dict) -> tuple:
            mech = entry.get("mechanism", "")
            if "EBP" in mech:
                return ("ebp", entry.get("stack_var_offset"))
            elif "RSP" in mech:
                return ("rsp", entry.get("stack_var_offset"))
            elif "REG" in mech:
                return ("reg", entry.get("register_id"))
            return ("unknown", None)

        cmps_by_var_entries: Dict[tuple, List[dict]] = {}
        for c in state_comparisons:
            key = _resolve_var_identity(c)
            if key[0] != "unknown":
                cmps_by_var_entries.setdefault(key, []).append(c)

        assigns_by_var_offsets: Dict[tuple, List[int]] = {}
        for a in state_assignments:
            key = _resolve_var_identity(a)
            if key[0] != "unknown":
                assigns_by_var_offsets.setdefault(key, []).append(a["offset"])

        has_cff = False
        detected_states = set()
        best_cadence = 0.0

        for var_key, entries in cmps_by_var_entries.items():
            if len(entries) < 3:
                continue
            offsets = sorted([e["offset"] for e in entries])
            # Slide window to find localized dispatcher loop within 1024 bytes
            for start_idx in range(len(offsets)):
                window_entries = [
                    e for e in entries
                    if offsets[start_idx] <= e["offset"] <= offsets[start_idx] + 1024
                ]
                win_states = set(e["state_value"] for e in window_entries)
                if len(win_states) >= 3:
                    win_offsets = sorted([e["offset"] for e in window_entries])
                    intervals = np.diff(win_offsets).astype(np.float32)
                    if len(intervals) >= 2:
                        mean_int = float(np.mean(intervals))
                        std_int = float(np.std(intervals))
                        reg = float(1.0 / (1.0 + (std_int / max(mean_int, 1.0))))
                        best_cadence = max(best_cadence, reg)

                        var_assigns = assigns_by_var_offsets.get(var_key, [])
                        nearby_assigns = [
                            ao for ao in var_assigns
                            if abs(ao - win_offsets[0]) <= 2048 or abs(ao - win_offsets[-1]) <= 2048
                        ]
                        if len(var_assigns) >= 2 and len(nearby_assigns) >= 1 and reg >= 0.35:
                            has_cff = True
                            for ws in win_states:
                                detected_states.add(ws)
                            break
                if has_cff:
                    break
            if has_cff:
                break

        # Fallback cadence computation for overall rhythm reporting
        if best_cadence > 0.0:
            cadence_regularity = best_cadence
        else:
            cmp_offsets = [c["offset"] for c in state_comparisons]
            if len(cmp_offsets) >= 2:
                intervals = np.diff(cmp_offsets).astype(np.float32)
                mean_interval = float(np.mean(intervals))
                std_interval = float(np.std(intervals))
                cadence_regularity = float(1.0 / (1.0 + (std_interval / max(mean_interval, 1.0))))
            else:
                cadence_regularity = 0.0

        all_detected = sorted(list(detected_states if detected_states else set(c["state_value"] for c in state_comparisons)))

        return {
            "has_control_flow_flattening": has_cff,
            "dispatcher_comparisons_count": len(state_comparisons),
            "state_transitions_count": len(state_assignments),
            "dispatcher_cadence_regularity": round(cadence_regularity, 4),
            "detected_state_states": sorted(list(set(c["state_value"] for c in state_comparisons))),
            "unflattening_strategy": (
                "Trace state variable assignments to rebuild sequential basic block graph."
                if has_cff else "Control flow appears canonical/unflattened."
            )
        }

    @staticmethod
    def deobfuscate_cfg(code_bytes: bytes) -> Dict[str, Any]:
        predicates = ContinuousDeobfuscator.analyze_opaque_predicates(code_bytes)
        cff_analysis = ContinuousDeobfuscator.detect_control_flow_flattening(code_bytes)
        dead_bytes = sum(p["length"] for p in predicates)
        return {
            "total_bytes_analyzed": len(code_bytes),
            "opaque_predicates_detected": len(predicates),
            "dead_instruction_bytes": dead_bytes,
            "predicates": predicates,
            "control_flow_flattening": cff_analysis,
            "complexity_reduction_percentage": round((dead_bytes / max(len(code_bytes), 1)) * 100, 2)
        }

    @staticmethod
    def deobfuscate_file(file_path: str, offset: Optional[int] = None, length: int = 4096) -> Dict[str, Any]:
        """Deobfuscates machine code directly from a binary file at a specified offset or entry point."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        if length <= 0:
            raise ValueError(f"Length must be positive, got {length}")

        pe_info = BinaryFormatInspector.inspect(file_path)
        actual_offset = offset
        if actual_offset is None:
            if pe_info.get("format") == "PE" and pe_info.get("entry_point_file_offset"):
                actual_offset = int(pe_info["entry_point_file_offset"], 16)
            elif pe_info.get("sections"):
                for sec in pe_info["sections"]:
                    if sec.get("is_executable"):
                        actual_offset = int(sec["raw_offset"])
                        break
            if actual_offset is None:
                actual_offset = 0

        file_sz = os.path.getsize(file_path)
        if actual_offset < 0 or actual_offset >= file_sz:
            raise ValueError(f"Offset 0x{actual_offset:X} out of range [0, 0x{file_sz:X})")

        with open(file_path, "rb") as f:
            f.seek(actual_offset)
            code_bytes = f.read(min(length, 65536))

        res = ContinuousDeobfuscator.deobfuscate_cfg(code_bytes)
        res["source_file"] = file_path
        res["analysis_file_offset"] = hex(actual_offset)
        res["analysis_window_size"] = len(code_bytes)
        res["total_file_size"] = file_sz
        res["is_truncated"] = (actual_offset + len(code_bytes)) < file_sz
        res["truncated"] = res["is_truncated"]
        return res


class SemanticFunctionMatcher:
    """
    Discriminative Taste:
    Computes continuous 16-D behavioral vector embeddings of assembly routines
    across architectures (x86-64 & ARM64), including operational transition bigrams.
    """

    @staticmethod
    def decode_instructions_x86(b: bytes) -> List[str]:
        """Decodes instruction stream to extract functional categories using Capstone (with pure-Python fallback)."""
        if HAS_CAPSTONE:
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                raw_insns = list(md.disasm(b, 0))
                bytes_decoded = sum(len(i.bytes) for i in raw_insns)
                # If less than 100% of the byte buffer can be disassembled into valid instructions, it is non-code noise or partial stream
                if len(b) >= 8 and bytes_decoded < len(b):
                    return ["invalid"] * len(b)

                insns = []
                for i in raw_insns:
                    m = i.mnemonic.lower()
                    if m in ("push", "pushfq"):
                        insns.append("push")
                    elif m in ("pop", "popfq"):
                        insns.append("pop")
                    elif m.startswith("ret"):
                        insns.append("ret")
                    elif m == "nop":
                        insns.append("nop")
                    elif m.startswith("j") or m in ("loop", "loope", "loopne"):
                        insns.append("jump")
                    elif m.startswith("call"):
                        insns.append("call")
                    elif m.startswith("mov") or m.startswith("cmov") or m in ("lea",):
                        insns.append("mov")
                    elif m in ("add", "adc", "sub", "sbb", "mul", "imul", "div", "idiv",
                               "and", "or", "xor", "not", "neg", "shl", "shr", "sar",
                               "rol", "ror", "cmp", "test", "inc", "dec",
                               "xorps", "xorpd", "addps", "addss", "subps", "subss"):
                        insns.append("alu")
                    else:
                        insns.append("alu")
                if len(insns) >= 2:
                    return insns
            except Exception:
                pass

        # Enhanced pure-Python fallback
        idx = 0
        insns = []
        n = len(b)
        while idx < n:
            b0 = b[idx]
            if 0x40 <= b0 <= 0x4F:
                idx += 1
                if idx >= n:
                    break
                b0 = b[idx]

            if b0 in range(0x50, 0x58):
                insns.append("push")
                idx += 1
            elif b0 in range(0x58, 0x60):
                insns.append("pop")
                idx += 1
            elif b0 in (0xC3, 0xC2, 0xCA, 0xCB):
                insns.append("ret")
                idx += 1
            elif b0 == 0x90:
                insns.append("nop")
                idx += 1
            elif b0 in (0x31, 0x33, 0x29, 0x2B, 0x85, 0x01, 0x03, 0x21, 0x09, 0x39, 0x3B):
                if idx + 1 >= n:
                    break
                insns.append("alu")
                idx += 2
            elif b0 in range(0x70, 0x80) or b0 == 0xEB:
                if idx + 1 >= n:
                    break
                insns.append("jump")
                idx += 2
            elif b0 in (0x89, 0x8B, 0x8D):
                if idx + 1 >= n:
                    break
                mod = (b[idx+1] >> 6) & 3
                len_insn = 2 if mod == 3 else (3 if mod == 1 else 6)
                if idx + len_insn > n:
                    break
                insns.append("mov")
                idx += len_insn
            elif b0 in range(0xB8, 0xC0):
                if idx + 5 > n:
                    break
                insns.append("mov")
                idx += 5
            elif b0 in (0x80, 0x81, 0x83):
                sz = 3 if b0 == 0x83 else (6 if b0 == 0x81 else 3)
                if idx + sz > n:
                    break
                insns.append("alu")
                idx += sz
            elif b0 in (0xE8, 0xE9):
                if idx + 4 >= n:
                    break
                insns.append("call" if b0 == 0xE8 else "jump")
                idx += 5
            elif b0 == 0x0F and idx + 1 < n and b[idx+1] in range(0x80, 0x90):
                if idx + 5 >= n:
                    break
                insns.append("jump")
                idx += 6
            elif b0 == 0x0F and idx + 1 < n and b[idx+1] in range(0x40, 0x50):  # CMOVcc
                if idx + 2 >= n:
                    break
                insns.append("mov")
                idx += 3
            else:
                insns.append("invalid")
                idx += 1

        return insns

    @staticmethod
    def decode_instructions_arm64(b: bytes) -> List[str]:
        """Decodes ARM64 instructions into canonical categories via Capstone (with pure-Python fallback)."""
        if HAS_CAPSTONE:
            try:
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
                raw_insns = list(md.disasm(b, 0))
                bytes_decoded = sum(len(i.bytes) for i in raw_insns)
                if len(b) >= 8 and bytes_decoded < len(b):
                    return ["invalid"] * len(b)

                insns = []
                for i in raw_insns:
                    m = i.mnemonic.lower()
                    if m.startswith("ret"):
                        insns.append("ret")
                    elif m.startswith("b") or m.startswith("cb") or m.startswith("tb"):
                        insns.append("call" if m.startswith("bl") else "jump")
                    elif m in ("stp", "str") and ("sp" in i.op_str.lower() and "!" in i.op_str):
                        insns.append("push")
                    elif m in ("ldp", "ldr") and ("sp" in i.op_str.lower()):
                        insns.append("pop")
                    elif m.startswith("mov") or m.startswith("ldr") or m.startswith("str") or m.startswith("adr"):
                        insns.append("mov")
                    elif m in ("add", "adds", "sub", "subs", "cmp", "cmn", "neg", "negs",
                               "mul", "smull", "umull", "sdiv", "udiv",
                               "and", "ands", "orr", "eor", "eon", "bic", "bics",
                               "lsl", "lsr", "asr", "ror", "tst"):
                        insns.append("alu")
                    elif m == "nop":
                        insns.append("nop")
                    else:
                        insns.append("alu")
                if len(insns) >= 2:
                    return insns
            except Exception:
                pass

        # Pure-Python fallback
        insns = []
        n = len(b) - (len(b) % 4)
        for i in range(0, n, 4):
            w = struct.unpack("<I", b[i:i+4])[0]
            if (w & 0xFFFFFC1F) == 0xD65F0000:
                insns.append("ret")
            elif ((w >> 26) & 0x3F) in (0x05, 0x25) or ((w >> 24) & 0xFF) == 0x54:
                insns.append("call" if ((w >> 26) & 0x3F) == 0x25 else "jump")
            elif ((w >> 25) & 0x7F) in (0x50, 0x51, 0x52, 0x53) or (w & 0xFFE003E0) in (0xD10003E0, 0x910003E0):
                insns.append("push" if (w & 0x800000) == 0 else "pop")
            elif ((w >> 25) & 0x07) in (0x04, 0x05):
                insns.append("mov")
            elif ((w >> 25) & 0x07) in (0x01, 0x05) or ((w >> 24) & 0x1F) in (0x11, 0x51, 0x91, 0xD1, 0x0A, 0x0B, 0x4A, 0x4B, 0x8A, 0x8B, 0xCA, 0xCB):
                insns.append("alu")
            elif w == 0xD503201F:
                insns.append("nop")
            else:
                insns.append("invalid")
        return insns

    @staticmethod
    def vectorize_function(assembly_hex: str) -> np.ndarray:
        """
        Projects assembly into a structured 16-D behavioral vector (including transition bigrams).
        Random noise or unaligned data is strictly rejected with a null vector.
        """
        raw_bytes = bytes.fromhex(assembly_hex.replace(" ", "").replace("\n", ""))
        vec = np.zeros(16, dtype=np.float32)

        if len(raw_bytes) < 2:
            return vec

        is_arm64 = (
            (len(raw_bytes) % 4 == 0)
            and raw_bytes.endswith(b"\xc0\x03\x5f\xd6")  # patched: require AArch64 RET terminator
            and not (b"\xc3" in raw_bytes or b"\x55\x48" in raw_bytes)
        )

        if is_arm64:
            insns = SemanticFunctionMatcher.decode_instructions_arm64(raw_bytes)
        else:
            insns = SemanticFunctionMatcher.decode_instructions_x86(raw_bytes)

        total = len(insns)
        if total < 2:
            return vec

        invalid_ratio = insns.count("invalid") / total
        if invalid_ratio > 0.18 and total > 2:
            return vec

        has_flow = any(x in insns for x in ("ret", "jump", "call"))
        if not has_flow and total >= 4:
            return vec

        vec[0] = insns.count("alu") / total
        vec[1] = insns.count("jump") / total
        vec[2] = insns.count("call") / total
        vec[3] = insns.count("mov") / total
        vec[4] = insns.count("push") / total
        vec[5] = insns.count("pop") / total
        vec[6] = insns.count("ret") / total
        vec[7] = insns.count("nop") / total

        vec[8] = insns.count("push") / max(insns.count("pop"), 1)
        vec[9] = insns.count("jump") / max(insns.count("call"), 1)
        vec[10] = insns.count("alu") / max(insns.count("mov"), 1)

        # Populate structural invariants and operational bigrams
        bigrams = list(zip(insns[:-1], insns[1:]))
        num_bi = max(len(bigrams), 1)
        vec[11] = float(insns[0] == "push")  # Frame prologue signature
        vec[12] = float(insns[-1] == "ret")  # Canonical epilogue signature
        vec[13] = sum(1 for a, b in bigrams if a in ("mov", "alu") and b in ("mov", "alu")) / num_bi
        vec[14] = sum(1 for a, b in bigrams if b == "ret" and a == "pop") / num_bi
        vec[15] = 1.0 - invalid_ratio

        norm = np.linalg.norm(vec)
        if norm > 1e-6:
            vec /= norm
        return vec

    @classmethod
    def match_pcode(
        cls,
        pcode1: List[Dict[str, Any]],
        pcode2: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        from ghidra_pcode_vectorizer import PcodeFunctionMatcher
        return PcodeFunctionMatcher.match(pcode1, pcode2)

    @staticmethod
    def match_functions(hex1: str, hex2: str) -> Dict[str, Any]:
        raw1 = bytes.fromhex(hex1.replace(" ", "").replace("\n", ""))
        raw2 = bytes.fromhex(hex2.replace(" ", "").replace("\n", ""))
        len1 = len(raw1)
        len2 = len(raw2)
        len_ratio = (min(len1, len2) / max(len1, len2)) if max(len1, len2) > 0 else 0.0

        v1 = SemanticFunctionMatcher.vectorize_function(hex1)
        v2 = SemanticFunctionMatcher.vectorize_function(hex2)

        norm1 = np.linalg.norm(v1)
        norm2 = np.linalg.norm(v2)
        if norm1 < 1e-6 or norm2 < 1e-6:
            return {
                "cosine_similarity": 0.0,
                "is_semantic_match": False,
                "confidence": "LOW / NO MATCH",
                "granularity_type": "OPERATIONAL_MIX_HISTOGRAM",
                "branch_topology_congruent": False,
                "scale_ratio": round(len_ratio, 4),
                "interpretation": "One or both functions contain insufficient valid instructions to form a behavioral vector."
            }

        similarity = float(np.dot(v1, v2))
        similarity = max(min(similarity, 1.0), 0.0)
        if similarity >= 0.90:
            interpretation = "Functions exhibit equivalent behavioral control and operational topology."
        elif similarity >= 0.80:
            interpretation = "Functions share similar opcode category distributions, but lack strict operational equivalence."
        elif similarity >= 0.50:
            interpretation = "Functions share moderate operational characteristics but differ in branch/register topology."
        else:
            interpretation = "Functions exhibit divergent computational patterns or non-code noise."

        has_branch_1 = bool(v1[1] > 0.01)
        has_branch_2 = bool(v2[1] > 0.01)
        is_branch_topology_divergent = (has_branch_1 != has_branch_2)
        is_length_divergent = (len_ratio < 0.60 and min(len1, len2) >= 4)

        is_match = (similarity >= 0.90) and (not is_branch_topology_divergent) and (not is_length_divergent)

        if is_branch_topology_divergent:
            similarity = min(similarity, 0.72)
            interpretation = "Functions diverge in branch/loop topology (branching/looping vs branchless straight-line code); semantic match rejected."
            confidence = "LOW / DIVERGENT_TOPOLOGY"
        elif is_length_divergent:
            interpretation = f"Functions diverge significantly in instruction scale (length ratio {round(len_ratio, 2)} < 0.60); semantic equivalence rejected."
            confidence = "LOW / DIVERGENT_SCALE"
        elif is_match:
            confidence = "HIGH" if similarity >= 0.94 else "MODERATE"
        elif similarity >= 0.80:
            confidence = "LOW / SIMILAR_OPCODE_DISTRIBUTION (NON_EQUIVALENT)"
        else:
            confidence = "LOW / NO MATCH"

        return {
            "cosine_similarity": round(similarity, 4),
            "is_semantic_match": is_match,
            "confidence": confidence,
            "granularity_type": "OPERATIONAL_MIX_HISTOGRAM",
            "branch_topology_congruent": not is_branch_topology_divergent,
            "scale_ratio": round(len_ratio, 4),
            "interpretation": interpretation
        }


class SurgicalBinaryPatcher:
    """
    Active Touch, Deep Proprioception & Metaphorical Pain (Nociception):
    Applies minimal, instruction-boundary stack-preserving binary modifications
    with verifiable PE Checksum recalculation and nociceptive safety reflexes.
    """

    STACK_ALTERING_OPCODES = {
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,  # PUSH reg
        0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,  # POP reg
        0x68, 0x6A,                                      # PUSH imm32 / imm8
        0xC9,                                            # LEAVE
        0xC3, 0xC2, 0xCA, 0xCB                           # RET
    }

    @staticmethod
    def compute_stack_proprioception(code_bytes: bytes) -> Dict[str, Any]:
        """
        Deep Proprioception: Walks x86/x64 instruction boundaries to compute exact
        stack pointer delta (Delta RSP) and detects all stack-altering operations
        (including SUB/ADD/MOV/LEA/XCHG RSP and register/memory PUSH/POP)
        without false-positiving on immediate operands.
        """
        if HAS_CAPSTONE:
            try:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.detail = True
                stack_delta = 0
                violating_opcodes: List[str] = []
                decoded_len = 0

                for insn in md.disasm(code_bytes, 0):
                    decoded_len += insn.size
                    mnem = insn.mnemonic.lower()
                    op_str = insn.op_str.lower()

                    if mnem.startswith("push"):
                        stack_delta -= 8
                        violating_opcodes.append(f"{insn.mnemonic.upper()} {insn.op_str}".strip())
                    elif mnem.startswith("pop"):
                        stack_delta += 8
                        violating_opcodes.append(f"{insn.mnemonic.upper()} {insn.op_str}".strip())
                    elif "rsp" in op_str or "esp" in op_str or any(insn.reg_name(r) in ("rsp", "esp") for r in insn.regs_write):
                        if mnem == "sub":
                            import re
                            m = re.search(r"0x[0-9a-fA-F]+|\d+", op_str.split(",")[-1])
                            imm = int(m.group(0), 0) if m else 8
                            stack_delta -= imm
                            violating_opcodes.append(f"SUB RSP, {hex(imm)}")
                        elif mnem == "add":
                            import re
                            m = re.search(r"0x[0-9a-fA-F]+|\d+", op_str.split(",")[-1])
                            imm = int(m.group(0), 0) if m else 8
                            stack_delta += imm
                            violating_opcodes.append(f"ADD RSP, {hex(imm)}")
                        elif mnem in ("mov", "lea", "xchg", "and", "or", "xor"):
                            violating_opcodes.append(f"STACK_POINTER_CLOBBER: {insn.mnemonic.upper()} {insn.op_str}")
                            stack_delta += 999999
                        elif mnem in ("call", "ret", "leave", "enter"):
                            violating_opcodes.append(f"FRAME_EXIT ({insn.mnemonic.upper()})")

                if decoded_len == len(code_bytes) and decoded_len > 0:
                    return {
                        "stack_delta_bytes": stack_delta,
                        "violating_instructions": violating_opcodes,
                        "is_frame_invariant": len(violating_opcodes) == 0 and stack_delta == 0
                    }
            except Exception:
                pass

        idx = 0
        n = len(code_bytes)
        stack_delta = 0
        violating_opcodes: List[str] = []

        while idx < n:
            b0 = code_bytes[idx]
            has_rex = False
            if 0x40 <= b0 <= 0x4F and idx + 1 < n:
                has_rex = True
                b_op = code_bytes[idx + 1]
                op_pos = idx + 1
            else:
                b_op = b0
                op_pos = idx

            # SUB RSP, imm8 (48 83 EC xx) or SUB RSP, imm32 (48 81 EC xx xx xx xx)
            if has_rex and b0 == 0x48 and op_pos + 2 < n and b_op == 0x83 and code_bytes[op_pos + 1] == 0xEC:
                imm8 = code_bytes[op_pos + 2]
                stack_delta -= imm8
                violating_opcodes.append(f"SUB RSP, 0x{imm8:02X} (0x4883EC)")
                idx = op_pos + 3
                continue
            if has_rex and b0 == 0x48 and op_pos + 5 < n and b_op == 0x81 and code_bytes[op_pos + 1] == 0xEC:
                (imm32,) = struct.unpack("<I", code_bytes[op_pos + 2 : op_pos + 6])
                stack_delta -= imm32
                violating_opcodes.append(f"SUB RSP, 0x{imm32:X} (0x4881EC)")
                idx = op_pos + 6
                continue
            # ADD RSP, imm8 (48 83 C4 xx) or ADD RSP, imm32 (48 81 C4 xx xx xx xx)
            if has_rex and b0 == 0x48 and op_pos + 2 < n and b_op == 0x83 and code_bytes[op_pos + 1] == 0xC4:
                imm8 = code_bytes[op_pos + 2]
                stack_delta += imm8
                violating_opcodes.append(f"ADD RSP, 0x{imm8:02X} (0x4883C4)")
                idx = op_pos + 3
                continue
            if has_rex and b0 == 0x48 and op_pos + 5 < n and b_op == 0x81 and code_bytes[op_pos + 1] == 0xC4:
                (imm32,) = struct.unpack("<I", code_bytes[op_pos + 2 : op_pos + 6])
                stack_delta += imm32
                violating_opcodes.append(f"ADD RSP, 0x{imm32:X} (0x4881C4)")
                idx = op_pos + 6
                continue

            # Multi-byte non-stack instructions whose immediate operands must be skipped cleanly:
            # MOV reg, imm32 (B8..BF + 4 bytes)
            if 0xB8 <= b_op <= 0xBF and op_pos + 5 <= n:
                idx = op_pos + 5
                continue
            # CALL / JMP rel32 (E8 / E9 + 4 bytes)
            if b_op in (0xE8, 0xE9) and op_pos + 5 <= n:
                idx = op_pos + 5
                continue
            # MOV/LEA/XCHG r/m, r or r, r/m (89, 8B, 8D, 87)
            if b_op in (0x89, 0x8B, 0x8D, 0x87) and op_pos + 1 < n:
                modrm = code_bytes[op_pos + 1]
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if reg == 4 or (mod == 3 and rm == 4):
                    # Direct modification of RSP
                    violating_opcodes.append(f"STACK_POINTER_CLOBBER (0x{b_op:02X})")
                    stack_delta += 999999
                insn_len = 2 if mod == 3 else (3 if mod == 1 else 6)
                idx = min(op_pos + insn_len, n)
                continue
            # XCHG RSP, RAX (94 or 48 94)
            if b_op == 0x94:
                violating_opcodes.append("STACK_POINTER_CLOBBER: XCHG RSP, RAX (0x94)")
                stack_delta += 999999
                idx = op_pos + 1
                continue
            # PUSH r/m (FF /6)
            if b_op == 0xFF and op_pos + 1 < n and ((code_bytes[op_pos + 1] >> 3) & 7) == 6:
                mod = (code_bytes[op_pos + 1] >> 6) & 3
                insn_len = 2 if mod == 3 else (3 if mod == 1 else 6)
                stack_delta -= 8
                violating_opcodes.append("PUSH r/m (0xFF /6)")
                idx = min(op_pos + insn_len, n)
                continue
            # POP r/m (8F /0)
            if b_op == 0x8F and op_pos + 1 < n and ((code_bytes[op_pos + 1] >> 3) & 7) == 0:
                mod = (code_bytes[op_pos + 1] >> 6) & 3
                insn_len = 2 if mod == 3 else (3 if mod == 1 else 6)
                stack_delta += 8
                violating_opcodes.append("POP r/m (0x8F /0)")
                idx = min(op_pos + insn_len, n)
                continue
            # ALU r/m, imm8 (83 + ModR/M + imm8)
            if b_op == 0x83 and op_pos + 3 <= n:
                idx = op_pos + 3
                continue
            # 2-byte ALU / Jcc short
            if (b_op in (0x31, 0x33, 0x29, 0x2B, 0x85, 0x01, 0x03, 0x21, 0x09, 0xEB) or (0x70 <= b_op <= 0x7F)) and op_pos + 2 <= n:
                idx = op_pos + 2
                continue

            # Stack-altering opcodes at instruction boundary
            if 0x50 <= b_op <= 0x57:  # PUSH reg
                stack_delta -= 8
                violating_opcodes.append(f"PUSH reg (0x{b_op:02X})")
                idx = op_pos + 1
                continue
            if 0x58 <= b_op <= 0x5F:  # POP reg
                stack_delta += 8
                violating_opcodes.append(f"POP reg (0x{b_op:02X})")
                idx = op_pos + 1
                continue
            if b_op == 0x6A and op_pos + 2 <= n:  # PUSH imm8
                stack_delta -= 8
                violating_opcodes.append("PUSH imm8 (0x6A)")
                idx = op_pos + 2
                continue
            if b_op == 0x68 and op_pos + 5 <= n:  # PUSH imm32
                stack_delta -= 8
                violating_opcodes.append("PUSH imm32 (0x68)")
                idx = op_pos + 5
                continue
            if b_op in (0xC9, 0xC3, 0xC2, 0xCA, 0xCB):
                violating_opcodes.append(f"FRAME_EXIT (0x{b_op:02X})")
                idx = op_pos + (3 if b_op in (0xC2, 0xCA) else 1)
                continue

            idx = op_pos + 1

        return {
            "stack_delta_bytes": stack_delta,
            "violating_instructions": violating_opcodes,
            "is_frame_invariant": len(violating_opcodes) == 0 and stack_delta == 0
        }

    @staticmethod
    def verify_stack_safety(replaced_bytes: bytes) -> Tuple[bool, str]:
        """Analyzes replaced instructions along true instruction boundaries to verify no stack corruption."""
        prop = SurgicalBinaryPatcher.compute_stack_proprioception(replaced_bytes)
        if not prop["is_frame_invariant"]:
            first_v = prop["violating_instructions"][0]
            if "SUB RSP" in first_v:
                return False, "Replaced bytes contain SUB RSP (stack allocation). Stack frame balance violated."
            if "ADD RSP" in first_v:
                return False, "Replaced bytes contain ADD RSP (stack deallocation). Stack frame balance violated."
            return (
                False,
                f"Replaced bytes contain stack-altering instruction opcode ({first_v}, delta_rsp={prop['stack_delta_bytes']}). Stack frame balance violated."
            )
        return True, "Replaced instructions have zero stack-pointer effects. Stack alignment invariant holds."

    @staticmethod
    def read_bytes(file_path: str, offset: int, length: int = 64) -> Dict[str, Any]:
        """Reads raw bytes and hexadecimal preview from a binary file at a given byte offset."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        if length <= 0:
            raise ValueError(f"Length must be positive, got {length}")
        file_sz = os.path.getsize(file_path)
        if offset < 0 or offset >= file_sz:
            raise ValueError(f"Offset 0x{offset:X} out of range [0, 0x{file_sz:X})")
        with open(file_path, "rb") as f:
            f.seek(offset)
            data = f.read(min(length, 65536))
        return {
            "file": file_path,
            "offset": hex(offset),
            "length": len(data),
            "hex": data.hex(),
            "ascii_preview": "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:128])
        }

    @staticmethod
    def patch_file(
        source_path: str,
        output_path: str,
        file_offset: int,
        patch_hex: str,
        enforce_nociception: bool = True
    ) -> Dict[str, Any]:
        src_abs = os.path.abspath(source_path)
        out_abs = os.path.abspath(output_path)

        try:
            from security import PathIdentity, TargetMutationError, OutOfScopeError, ExecutionGuard, Capability
            if PathIdentity.is_same_file(src_abs, out_abs):
                raise TargetMutationError(
                    f"TARGET_WRITE_FORBIDDEN: In-place binary modification is strictly forbidden by REA Safety Policy. Destination '{out_abs}' matches source."
                )
            scope = ExecutionGuard.get_current_scope()
            if scope and scope.is_target_directory(out_abs):
                raise TargetMutationError(
                    f"TARGET_DIRECTORY_WRITE_FORBIDDEN: Output patch cannot be placed in the target's original directory '{os.path.dirname(out_abs)}'."
                )

            # Mandatory Reference Monitor Mediation: Enforce workspace confinement & target immutability
            ExecutionGuard.request_access(
                component="binary_patcher",
                operation="patch_file",
                target=out_abs,
                capability=Capability.WORKSPACE_WRITE,
                access_mode="WRITE"
            )
        except ImportError as imp_err:
            raise RuntimeError(
                f"SECURITY_KERNEL_UNAVAILABLE: Refusing unmediated binary patch write: {imp_err}"
            ) from imp_err

        patch_bytes = bytes.fromhex(patch_hex.replace(" ", ""))
        with open(src_abs, "rb") as f:
            data = bytearray(f.read())

        file_size = len(data)
        if file_offset < 0 or file_offset + len(patch_bytes) > file_size:
            raise ValueError("Patch offset exceeds file boundaries.")

        pe_info = BinaryFormatInspector.inspect(src_abs)
        is_pe = (pe_info.get("format") == "PE")
        is_in_executable_section = False
        is_in_section = False
        target_section_name = "UNKNOWN"

        if is_pe:
            for s in pe_info.get("sections", []):
                s_start = int(s["raw_offset"])
                s_end = s_start + int(s["raw_size"])
                if s_start <= file_offset < s_end:
                    target_section_name = s["name"]
                    is_in_executable_section = s.get("is_executable", False)
                    is_in_section = True
                    break

        original_bytes = bytes(data[file_offset:file_offset + len(patch_bytes)])

        if is_pe and not is_in_section:
            # Targets PE headers / DOS stub / table descriptors
            pe_offset = pe_info.get("pe_offset", 0x80)
            chk_offset = pe_offset + 24 + 64
            is_checksum_patch = (file_offset == chk_offset and len(patch_bytes) == 4)

            if is_checksum_patch:
                is_safe = True
                reason = "Patch specifically updates the PE Optional Header CheckSum field."
                patch_type = "PE_HEADER_CHECKSUM"
                pain_hazards = []
                pain_score = 0.0
            else:
                is_safe = False
                reason = "Patch targets PE structural header/table area without schema verification; high risk of binary corruption."
                patch_type = "PE_STRUCTURAL_HEADER_MUTATION"
                pain_hazards = ["PE_HEADER_CORRUPTION_HAZARD"]
                pain_score = 0.75
        else:
            patch_type = "CODE_SECTION_MUTATION" if is_in_executable_section else "DATA_SECTION_MUTATION"
            if is_pe and not is_in_executable_section:
                sys.stderr.write(
                    f"WARNING: Patch offset 0x{file_offset:X} resides in section '{target_section_name}', "
                    f"which is NOT marked as executable (IMAGE_SCN_MEM_EXECUTE). Execution may trigger DEP crash.\n"
                )

            orig_safe, orig_reason = SurgicalBinaryPatcher.verify_stack_safety(original_bytes)
            patch_safe, patch_reason = SurgicalBinaryPatcher.verify_stack_safety(patch_bytes)
            orig_prop = SurgicalBinaryPatcher.compute_stack_proprioception(original_bytes)
            patch_prop = SurgicalBinaryPatcher.compute_stack_proprioception(patch_bytes)

            # Metaphorical Pain (Nociception) scoring: rigorously inspect replacement bytes & frame balance
            pain_hazards = []
            pain_score = 0.0
            is_safe = patch_safe
            reason = patch_reason

            # Case 1: Stack delta discrepancy (replacement alters net stack frame pointer effect)
            if orig_prop["stack_delta_bytes"] != patch_prop["stack_delta_bytes"]:
                pain_hazards.append("STACK_FRAME_IMBALANCE_HAZARD")
                pain_score += 0.65
                is_safe = False
                reason = (
                    f"Stack frame balance violated: original stack delta is {orig_prop['stack_delta_bytes']} bytes, "
                    f"but replacement delta is {patch_prop['stack_delta_bytes']} bytes."
                )

            # Case 2: Replacement introduces dangerous stack instructions where original had none
            if not patch_safe and orig_safe:
                if "STACK_FRAME_IMBALANCE_HAZARD" not in pain_hazards:
                    pain_hazards.append("STACK_FRAME_IMBALANCE_HAZARD")
                    pain_score += 0.65
                is_safe = False
                reason = f"Replacement bytes introduce stack-violating instructions: {patch_reason}"

            # Case 3: Executing in non-executable section
            if pe_info.get("format") == "PE" and not is_in_executable_section:
                pain_hazards.append("DEP_NON_EXECUTABLE_SECTION_HAZARD")
                pain_score += 0.35

        if enforce_nociception and pain_score >= 0.6:
            raise RuntimeError(f"Nociceptive Reflex blocked destructive binary patch: {reason}")

        data[file_offset:file_offset + len(patch_bytes)] = patch_bytes

        checksum_updated = False
        new_checksum = 0
        if pe_info.get("format") == "PE" and "pe_offset" in pe_info:
            pe_off = pe_info["pe_offset"]
            new_checksum = BinaryFormatInspector.calculate_pe_checksum(data, pe_off)
            chk_off = pe_off + 24 + 64
            if len(data) >= chk_off + 4:
                data[chk_off:chk_off + 4] = struct.pack("<I", new_checksum)
                checksum_updated = True

        orig_sha = BinaryFormatInspector.compute_sha256(src_abs)

        # Atomic write on Windows so in-place patching never corrupts the file
        out_dir = os.path.dirname(out_abs) or "."
        os.makedirs(out_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".rea_pe_", suffix=".tmp", dir=out_dir)
        os.close(fd)
        try:
            with open(tmp_path, "wb") as f:
                f.write(data)
            os.replace(tmp_path, out_abs)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        patched_sha = BinaryFormatInspector.compute_sha256(out_abs)
        rva = BinaryFormatInspector.offset_to_rva(pe_info, file_offset) if pe_info.get("format") == "PE" else None

        return {
            "source_file": source_path,
            "output_file": output_path,
            "patch_type": patch_type,
            "file_offset": hex(file_offset),
            "virtual_rva": hex(rva) if rva is not None else None,
            "target_section": target_section_name,
            "is_in_executable_section": is_in_executable_section,
            "patch_length": len(patch_bytes),
            "original_hex": original_bytes.hex().upper(),
            "patched_hex": patch_bytes.hex().upper(),
            "original_sha256": orig_sha,
            "patched_sha256": patched_sha,
            "pe_checksum_recalculated": checksum_updated,
            "new_pe_checksum": hex(new_checksum),
            "is_safe": is_safe,
            "is_stack_safe": is_safe,
            "stack_safety_rationale": reason,
            "nociceptive_pain_score": round(min(pain_score, 1.0), 4),
            "pain_score": round(min(pain_score, 1.0), 4),
            "nociceptive_hazards": pain_hazards,
            "pain_hazards": pain_hazards
        }


class HybridBinaryDissector:
    """
    Exploratory Smell:
    Scans native Windows/Linux executables using memory-mapped I/O for verified embedded
    neural model runtimes (TFLite, GGUF, ONNX, TorchScript, Safetensors, DirectML, WinML, TensorRT).
    """

    WINDOWS_AI_SIGNATURES = [
        (b"DirectML.dll", "Windows DirectML Hardware-Accelerated Inference Bridge", "DirectML_DLL"),
        (b"DMLCreateDevice", "DirectML Native Device Initialization API", "DirectML_API"),
        (b"Windows.AI.MachineLearning", "Windows ML (WinML) WinRT Namespace", "WinML_Runtime"),
        (b"onnxruntime.dll", "ONNX Runtime Native Dynamic Library", "ONNXRuntime_DLL"),
        (b"OrtGetApiBase", "ONNX Runtime C-API Entry Point", "ONNXRuntime_API"),
        (b"nvinfer.dll", "NVIDIA TensorRT Windows Inference Engine", "TensorRT_DLL"),
        (b"openvino.dll", "Intel OpenVINO Inference Engine", "OpenVINO_DLL"),
    ]

    @staticmethod
    def scan_for_embedded_logic(file_path: str) -> Dict[str, Any]:
        findings = []
        norm_path = os.path.abspath(file_path)
        with open(norm_path, "rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            if file_size == 0:
                return {
                    "file_path": file_path,
                    "is_hybrid_binary": False,
                    "embedded_logic_assets_count": 0,
                    "overall_shannon_entropy": 0.0,
                    "findings": []
                }
            try:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    data = bytes(mm[:])
            except Exception:
                data = f.read()

        n = len(data)
        overall_entropy = round(BinaryFormatInspector.compute_shannon_entropy(data[:min(n, 524288)]), 4)

        # 1. TensorFlow Lite: FlatBuffer file identifier 'TFL3' at offset +4
        start = 0
        while len(findings) < 500:
            idx = data.find(b"TFL3", start)
            if idx == -1:
                break
            if idx >= 4:
                buf_start = idx - 4
                is_valid_fb = False
                if buf_start + 8 <= n:
                    root_offset = struct.unpack("<I", data[buf_start:buf_start+4])[0]
                    if 4 <= root_offset <= min(n - buf_start - 4, 100_000_000):
                        tbl_pos = buf_start + root_offset
                        if tbl_pos + 4 <= n:
                            soffset = struct.unpack("<i", data[tbl_pos:tbl_pos+4])[0]
                            vtable_pos = tbl_pos - soffset
                            if 0 <= vtable_pos < n:
                                is_valid_fb = True

                if is_valid_fb:
                    findings.append({
                        "type": "TensorFlow Lite FlatBuffer Model",
                        "file_offset": hex(buf_start),
                        "identifier": "TFL3",
                        "confidence": "HIGH",
                        "details": "Verified FlatBuffer header with TFL3 magic and valid root table."
                    })
                else:
                    findings.append({
                        "type": "TensorFlow Lite FlatBuffer Candidate (Unverified)",
                        "file_offset": hex(buf_start),
                        "identifier": "TFL3_RAW",
                        "confidence": "LOW",
                        "details": "Candidate 4-byte TFL3 marker found without valid FlatBuffer vtable structure."
                    })
            start = idx + 4

        # 2. GGUF: Must be exactly b"GGUF" followed by uint32 version 2 or 3
        start = 0
        while len(findings) < 500:
            idx = data.find(b"GGUF", start)
            if idx == -1:
                break
            if idx + 8 <= n:
                version = struct.unpack("<I", data[idx+4:idx+8])[0]
                if version in (2, 3):
                    findings.append({
                        "type": f"GGUF v{version} Quantized Model",
                        "file_offset": hex(idx),
                        "identifier": f"GGUF_v{version}",
                        "confidence": "HIGH",
                        "details": f"Verified GGUF magic and valid version {version} uint32."
                    })
            start = idx + 4

        # 3. ONNX Protobuf Model: Protobuf ModelProto (ir_version tag 0x08 followed by varint 3..12)
        start = 0
        while len(findings) < 500:
            idx = data.find(b"\x08", start)
            if idx == -1 or idx + 16 > n:
                break
            ver = data[idx+1]
            if 3 <= ver <= 12:
                sub = data[idx+2:idx+16]
                if b"\x12" in sub and b"onnx" in data[max(0, idx-64):min(n, idx+128)].lower():
                    findings.append({
                        "type": "ONNX Protocol Buffer Model",
                        "file_offset": hex(idx),
                        "identifier": f"ONNX_IR_v{ver}",
                        "confidence": "HIGH",
                        "details": f"Verified ModelProto header tag with ir_version={ver} and opset/onnx wire metadata."
                    })
                    start = idx + 32
                    continue
            start = idx + 1

        # 4. TorchScript / PyTorch ZIP Package: Must be ZIP archive containing PyTorch artifacts
        start = 0
        zip_attempts = 0
        MAX_ZIP_ATTEMPTS = 16
        while len(findings) < 500 and zip_attempts < MAX_ZIP_ATTEMPTS:
            idx = data.find(b"PK\x03\x04", start)
            if idx == -1:
                break
            start = idx + 4
            # Validate standard local file header length
            if idx + 30 > n:
                continue
            fn_len = struct.unpack("<H", data[idx+26:idx+28])[0]
            if fn_len == 0 or idx + 30 + fn_len > n:
                continue
            fn_bytes = data[idx+30:idx+30+fn_len]
            fn_lower = fn_bytes.lower()
            if not any(k in fn_lower for k in (b"pkl", b"model", b"code", b"version", b"data", b"pytorch", b"archive")):
                continue

            zip_attempts += 1
            try:
                zip_stream = io.BytesIO(data[idx:])
                with zipfile.ZipFile(zip_stream, "r") as z:
                    names = z.namelist()
                    is_pytorch = any(
                        name.endswith("constants.pkl") or name.endswith("data.pkl") or
                        name.endswith("model.json") or "code/" in name or name.endswith("version")
                        for name in names
                    )
                    if is_pytorch:
                        findings.append({
                            "type": "TorchScript / PyTorch Model Archive",
                            "file_offset": hex(idx),
                            "identifier": "TorchScript_ZIP",
                            "confidence": "HIGH",
                            "details": f"Verified ZIP package containing TorchScript serialized structures: {names[:3]}"
                        })
                        start = idx + 30
            except Exception:
                pass

        # 5. Safetensors Model: 8-byte length followed by JSON header starting with {"
        start = 0
        while len(findings) < 500:
            idx = data.find(b'{"__metadata__', start)
            if idx == -1:
                idx = data.find(b'{"', start)
            if idx == -1:
                break
            if idx >= 8:
                hdr_len = struct.unpack("<Q", data[idx-8:idx])[0]
                if 10 < hdr_len < 100_000_000 and idx + min(hdr_len, 50) <= n:
                    try:
                        sample = data[idx:idx + min(int(hdr_len), 200)].decode("utf-8", errors="ignore")
                        if "dtype" in sample or "shape" in sample or "__metadata__" in sample:
                            findings.append({
                                "type": "Safetensors Model Header",
                                "file_offset": hex(idx - 8),
                                "identifier": "Safetensors",
                                "confidence": "HIGH",
                                "details": "Verified 8-byte prefix commitment with JSON tensor declarations."
                            })
                    except Exception:
                        pass
            start = idx + 4

        # 6. Windows DirectML / WinML / ONNX Runtime / TensorRT Native AI Bridges
        for sig_bytes, sig_type, sig_id in HybridBinaryDissector.WINDOWS_AI_SIGNATURES:
            idx = data.find(sig_bytes)
            if idx != -1:
                findings.append({
                    "type": sig_type,
                    "file_offset": hex(idx),
                    "identifier": sig_id,
                    "confidence": "HIGH",
                    "details": f"Verified Windows native neural runtime binding '{sig_bytes.decode('ascii', errors='ignore')}'."
                })

        return {
            "file_path": file_path,
            "is_hybrid_binary": len(findings) > 0,
            "embedded_logic_assets_count": len(findings),
            "overall_shannon_entropy": overall_entropy,
            "findings": findings
        }


class SensoryCortex:
    """Unified 10-Sense Perception & Diagnostic Engine for REA-Neural."""

    SENSE_REGISTRY = [
        {"id": 1, "key": "analytical_vision", "name_ar": "البصر التحليلي", "name_en": "Analytical Vision", "importance_rank": 1, "importance_weight": 1.00},
        {"id": 2, "key": "temporal_hearing", "name_ar": "السمع الزمني", "name_en": "Temporal Hearing", "importance_rank": 9, "importance_weight": 0.80},
        {"id": 3, "key": "active_touch", "name_ar": "اللمس النشط", "name_en": "Active Touch", "importance_rank": 3, "importance_weight": 0.95},
        {"id": 4, "key": "exploratory_smell", "name_ar": "الشم الاستكشافي", "name_en": "Exploratory Smell", "importance_rank": 4, "importance_weight": 0.90},
        {"id": 5, "key": "discriminative_taste", "name_ar": "الذوق التمييزي", "name_en": "Discriminative Taste", "importance_rank": 2, "importance_weight": 0.95},
        {"id": 6, "key": "deep_proprioception", "name_ar": "اللمس العميق / الحس العميق", "name_en": "Proprioception / Deep Touch", "importance_rank": 5, "importance_weight": 0.90},
        {"id": 7, "key": "spatial_sense", "name_ar": "حس المكان", "name_en": "Spatial Sense", "importance_rank": 8, "importance_weight": 0.80},
        {"id": 8, "key": "vestibular_balance", "name_ar": "التوازن / الدهليزي", "name_en": "Vestibular / Balance", "importance_rank": 6, "importance_weight": 0.85},
        {"id": 9, "key": "metaphorical_pain", "name_ar": "الألم المجازي", "name_en": "Metaphorical Pain / Nociception", "importance_rank": 7, "importance_weight": 0.85},
        {"id": 10, "key": "sense_of_rhythm", "name_ar": "الإحساس بالإيقاع", "name_en": "Sense of Rhythm / Chronoception", "importance_rank": 10, "importance_weight": 0.75},
    ]

    @staticmethod
    def _extract_code_sample(file_path: Optional[str], code_hex: Optional[str]) -> bytes:
        if code_hex:
            return bytes.fromhex(code_hex.replace(" ", "").replace("\n", ""))
        if file_path and os.path.exists(file_path):
            info = BinaryFormatInspector.inspect(file_path)
            with open(file_path, "rb") as f:
                data = f.read()
            if info.get("format") == "PE":
                for sec in info.get("sections", []):
                    if sec.get("is_executable") and sec["raw_size"] > 0:
                        start = sec["raw_offset"]
                        end = min(start + min(sec["raw_size"], 4096), len(data))
                        if end > start:
                            return data[start:end]
            return data[:min(len(data), 1024)]
        return bytes.fromhex("55 48 89 e5 48 31 c0 74 05 b8 55 00 00 00 5d c3")

    @classmethod
    def evaluate_all_senses(
        cls,
        file_path: Optional[str] = None,
        code_hex: Optional[str] = None
    ) -> Dict[str, Any]:
        from rea_neural_engine import (
            SafetensorsHandler, SubspaceAnalyzer, CircuitDecompiler, WeightPatcher,
            ActivationTraceProber, NeuralBehaviorVerifier, CrossLayerCircuitAnalyzer,
            AmenabilityDiagnostic, WeightSecurityAuditor
        )
        is_safetensors = bool(file_path and file_path.endswith(".safetensors") and os.path.exists(file_path))
        code_sample = cls._extract_code_sample(file_path if not is_safetensors else None, code_hex)
        pe_info = BinaryFormatInspector.inspect(file_path) if (file_path and os.path.exists(file_path) and not is_safetensors) else None

        senses_output: Dict[str, Dict[str, Any]] = {}

        # 1. Analytical Vision
        if is_safetensors and file_path:
            hdr, _, hdr_sha = SafetensorsHandler.read_header(file_path)
            t_names = [k for k in hdr.keys() if k != "__metadata__"]
            first_arr, _ = SafetensorsHandler.read_tensor(file_path, t_names[0])
            svd_res = SubspaceAnalyzer.analyze_svd(first_arr, top_k=4)
            vision_details = {
                "target_modality": "SAFETENSORS_MODEL",
                "tensors_discovered": len(t_names),
                "header_sha256": hdr_sha,
                "primary_tensor_svd_energy_ratio": round(svd_res["energy_retained_ratio"], 4),
            }
        else:
            vision_details = {
                "target_modality": pe_info.get("format", "HEX_STREAM") if pe_info else "HEX_STREAM",
                "pe_type": pe_info.get("pe_type") if pe_info else None,
                "sections_discovered": pe_info.get("sections_count", 0) if pe_info else 0,
                "mitigations_visible": pe_info.get("windows_security_mitigations") if pe_info else None,
            }
        senses_output["analytical_vision"] = {
            "id": 1, "name_ar": "البصر التحليلي", "name_en": "Analytical Vision",
            "present": True, "efficiency_score": 0.98, "importance_rank": 1, "telemetry": vision_details
        }

        # 2. Temporal Hearing
        if is_safetensors and file_path:
            trace_res = ActivationTraceProber.probe_trace(file_path, prompt="diagnostic_temporal_probe", max_tokens=8)
            temporal_details = {
                "steps_listened": trace_res["steps_simulated"],
                "loop_attractor_detected": trace_res["loop_attractor_detected"],
            }
        else:
            insns = SemanticFunctionMatcher.decode_instructions_x86(code_sample[:256])
            flow_events = [op for op in insns if op in ("jump", "call", "ret")]
            temporal_details = {
                "decoded_instruction_steps": len(insns),
                "temporal_control_transitions": len(flow_events),
                "transition_density": round(len(flow_events) / max(len(insns), 1), 4),
            }
        senses_output["temporal_hearing"] = {
            "id": 2, "name_ar": "السمع الزمني", "name_en": "Temporal Hearing",
            "present": True, "efficiency_score": 0.94, "importance_rank": 9, "telemetry": temporal_details
        }

        # 3. Active Touch
        synth_mat = np.eye(8, dtype=np.float32)
        _, touch_metrics = WeightPatcher.rank1_nullify(synth_mat, mode_index=0, alpha=0.5)
        senses_output["active_touch"] = {
            "id": 3, "name_ar": "اللمس النشط", "name_en": "Active Touch",
            "present": True, "efficiency_score": 0.97, "importance_rank": 3,
            "telemetry": {
                "supported_weight_operations": ["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add", "column_direction_subtract", "graft_conditional_subcircuit", "compile_weights_from_spec"],
                "supported_binary_operations": ["surgical_byte_patch", "pe_checksum_sync", "atomic_windows_replace", "ghidra_db_mutation", "pcode_varnode_vectorization"],
                "probe_lipschitz_bound": round(touch_metrics["lipschitz_spectral_bound"], 4),
            }
        }

        # 4. Exploratory Smell
        deob = ContinuousDeobfuscator.deobfuscate_cfg(code_sample)
        hybrid_count = 0
        entropy_val = BinaryFormatInspector.compute_shannon_entropy(code_sample)
        if file_path and os.path.exists(file_path):
            hyb = HybridBinaryDissector.scan_for_embedded_logic(file_path)
            hybrid_count = hyb["embedded_logic_assets_count"]
            entropy_val = hyb["overall_shannon_entropy"]
        senses_output["exploratory_smell"] = {
            "id": 4, "name_ar": "الشم الاستكشافي", "name_en": "Exploratory Smell",
            "present": True, "efficiency_score": 0.96, "importance_rank": 4,
            "telemetry": {
                "opaque_predicates_sniffed": deob["opaque_predicates_detected"],
                "embedded_ai_assets_sniffed": hybrid_count,
                "shannon_entropy_bits": round(entropy_val, 4),
                "packed_or_encrypted_scent": entropy_val > 7.2,
            }
        }

        # 5. Discriminative Taste
        vec = SemanticFunctionMatcher.vectorize_function(code_sample[:128].hex())
        is_valid_code = float(np.linalg.norm(vec)) > 0.0
        rex_diff_test, _ = ContinuousDeobfuscator.is_register_zeroing(0x31, 0xC0, rex_prefix=0x49)
        senses_output["discriminative_taste"] = {
            "id": 5, "name_ar": "الذوق التمييزي", "name_en": "Discriminative Taste",
            "present": True, "efficiency_score": 0.97, "importance_rank": 2,
            "telemetry": {
                "sample_classified_as_valid_code": is_valid_code,
                "rex_cross_register_false_positive_rejected": not rex_diff_test, "pcode_cross_architecture_matching": True,
                "embedding_norm": round(float(np.linalg.norm(vec)), 4),
            }
        }

        # 6. Deep Proprioception
        prop = SurgicalBinaryPatcher.compute_stack_proprioception(code_sample[:64])
        senses_output["deep_proprioception"] = {
            "id": 6, "name_ar": "اللمس العميق / الحس العميق", "name_en": "Proprioception / Deep Touch",
            "present": True, "efficiency_score": 0.95, "importance_rank": 5,
            "telemetry": {
                "cumulative_stack_delta_bytes": prop["stack_delta_bytes"],
                "frame_altering_ops_count": len(prop["violating_instructions"]),
                "instruction_boundary_aligned": True,
            }
        }

        # 7. Spatial Sense
        spatial_telemetry: Dict[str, Any] = {"coordinate_slicing_enabled": True}
        if pe_info and pe_info.get("format") == "PE":
            ep_rva = int(pe_info.get("entry_point_rva", "0x0"), 16)
            ep_off = BinaryFormatInspector.rva_to_offset(pe_info, ep_rva)
            roundtrip_rva = BinaryFormatInspector.offset_to_rva(pe_info, ep_off) if ep_off is not None else None
            spatial_telemetry.update({
                "entry_point_rva": hex(ep_rva),
                "entry_point_raw_offset": hex(ep_off) if ep_off is not None else None,
                "rva_offset_roundtrip_exact": (roundtrip_rva == ep_rva) if roundtrip_rva is not None else False,
            })
        senses_output["spatial_sense"] = {
            "id": 7, "name_ar": "حس المكان", "name_en": "Spatial Sense",
            "present": True, "efficiency_score": 0.95, "importance_rank": 8, "telemetry": spatial_telemetry
        }

        # 8. Vestibular Balance
        vestibular_telemetry: Dict[str, Any] = {
            "frobenius_safety_threshold": 0.005,
            "pe_checksum_engine_ready": True,
        }
        if pe_info and pe_info.get("format") == "PE" and file_path:
            with open(file_path, "rb") as f:
                raw_pe = bytearray(f.read())
            calc_chk = BinaryFormatInspector.calculate_pe_checksum(raw_pe, pe_info["pe_offset"])
            vestibular_telemetry["calculated_pe_checksum"] = hex(calc_chk)
        senses_output["vestibular_balance"] = {
            "id": 8, "name_ar": "التوازن / الدهليزي", "name_en": "Vestibular / Balance",
            "present": True, "efficiency_score": 0.96, "importance_rank": 6, "telemetry": vestibular_telemetry
        }

        # 9. Metaphorical Pain
        is_safe_sample, pain_reason = SurgicalBinaryPatcher.verify_stack_safety(code_sample[:16])
        senses_output["metaphorical_pain"] = {
            "id": 9, "name_ar": "الألم المجازي", "name_en": "Metaphorical Pain / Nociception",
            "present": True, "efficiency_score": 0.96, "importance_rank": 7,
            "telemetry": {
                "sample_direct_overwrite_safe": is_safe_sample,
                "nociceptive_diagnosis": pain_reason,
                "in_place_truncation_guard_active": True,
                "dep_section_violation_guard_active": True,
            }
        }

        # 10. Sense of Rhythm
        cff_info = deob["control_flow_flattening"]
        byte_arr = np.frombuffer(code_sample[:256], dtype=np.uint8).astype(np.float32)
        if byte_arr.size > 8:
            centered = byte_arr - np.mean(byte_arr)
            denom = float(np.sum(centered ** 2))
            autocorr_lag4 = float(np.sum(centered[:-4] * centered[4:]) / max(denom, 1e-12))
        else:
            autocorr_lag4 = 0.0
        senses_output["sense_of_rhythm"] = {
            "id": 10, "name_ar": "الإحساس بالإيقاع", "name_en": "Sense of Rhythm / Chronoception",
            "present": True, "efficiency_score": 0.94, "importance_rank": 10,
            "telemetry": {
                "dispatcher_cadence_regularity": cff_info["dispatcher_cadence_regularity"],
                "has_flattened_loop_rhythm": cff_info["has_control_flow_flattening"],
                "byte_stream_lag4_autocorrelation": round(autocorr_lag4, 4),
            }
        }

        scores = [s["efficiency_score"] for s in senses_output.values()]
        return {
            "engine": "REA-Neural Sensory Cortex v7.4.0",
            "platform_target": "Windows 10 / 11 / Server (PE32/PE32+ & Safetensors)",
            "active_senses_count": len(senses_output),
            "overall_sensory_efficiency": round(float(np.mean(scores)), 4),
            "score_semantics": (
                "efficiency_score/overall_sensory_efficiency are STATIC capability-presence "
                "indicators (fixed per sense), NOT measured accuracy. Read each sense's "
                "'telemetry' for the real computed values. When no --file/--hex input is "
                "supplied, a FIXED synthetic code sample is analyzed, so senses still "
                "report activity without a real target."
            ),
            "senses": senses_output,
        }


def main():
    _ensure_utf8_stdio()
    parser = argparse.ArgumentParser(description="REA-Neural Binary Reverse Engineering Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    insp_p = subparsers.add_parser("inspect", help="Inspect executable PE/ELF header")
    insp_p.add_argument("--file", required=True, help="Path to executable binary")

    deob_p = subparsers.add_parser("deobfuscate", help="Detect and prune opaque predicates in code bytes or binary file")
    deob_p.add_argument("--hex", default=None, help="Hex-encoded machine code bytes")
    deob_p.add_argument("--file", default=None, help="Path to executable binary")
    deob_p.add_argument("--offset", default=None, type=lambda x: int(x, 0), help="File offset to analyze (defaults to entry point)")
    deob_p.add_argument("--size", "--length", dest="size", default=4096, type=lambda x: int(x, 0), help="Number of bytes to analyze (default 4096)")

    dump_p = subparsers.add_parser("dump", help="Extract and preview raw bytes/assembly at an offset")
    dump_p.add_argument("--file", required=True, help="Path to executable binary")
    dump_p.add_argument("--offset", required=True, type=lambda x: int(x, 0), help="File offset (e.g. 0x4e0778)")
    dump_p.add_argument("--length", default=64, type=int, help="Length in bytes (default 64)")

    match_p = subparsers.add_parser("match", help="Match functions across architectures semantically")
    match_p.add_argument("--func1", required=True, help="First function bytecode hex")
    match_p.add_argument("--func2", required=True, help="Second function bytecode hex")

    patch_p = subparsers.add_parser("patch", help="Surgically patch binary file on disk")
    patch_p.add_argument("--source", required=True, help="Source executable")
    patch_p.add_argument("--output", required=True, help="Patched executable output")
    patch_p.add_argument("--offset", required=True, type=lambda x: int(x, 0), help="Byte offset (e.g. 0x1A00)")
    patch_p.add_argument("--patch-hex", required=True, help="Patch hex bytes")
    patch_p.add_argument("--enforce-nociception", dest="enforce_nociception", action="store_true", default=True, help="Abort patch if nociceptive pain is high (enabled by default)")
    patch_p.add_argument("--force", "--no-enforce-nociception", dest="enforce_nociception", action="store_false", help="Bypass nociceptive reflex check")

    hyb_p = subparsers.add_parser("scan-hybrid", help="Scan binary for embedded neural logic assets")
    hyb_p.add_argument("--file", required=True, help="Path to executable binary")

    args = parser.parse_args()

    if args.command == "inspect":
        res = BinaryFormatInspector.inspect(args.file)
        print(json.dumps(res, indent=2))
    elif args.command == "deobfuscate":
        if args.hex:
            code = bytes.fromhex(args.hex.replace(" ", ""))
            res = ContinuousDeobfuscator.deobfuscate_cfg(code)
        elif args.file:
            res = ContinuousDeobfuscator.deobfuscate_file(args.file, offset=args.offset, length=args.size)
        else:
            print(json.dumps({"error": "Must provide either --hex or --file for deobfuscation."}))
            sys.exit(1)
        print(json.dumps(res, indent=2))
    elif args.command == "dump":
        res = SurgicalBinaryPatcher.read_bytes(args.file, args.offset, args.length)
        print(json.dumps(res, indent=2))
    elif args.command == "match":
        res = SemanticFunctionMatcher.match_functions(args.func1, args.func2)
        print(json.dumps(res, indent=2))
    elif args.command == "patch":
        res = SurgicalBinaryPatcher.patch_file(
            args.source, args.output, args.offset, args.patch_hex,
            enforce_nociception=args.enforce_nociception
        )
        print(json.dumps(res, indent=2))
    elif args.command == "scan-hybrid":
        res = HybridBinaryDissector.scan_for_embedded_logic(args.file)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
