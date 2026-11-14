# -*- coding: utf-8 -*-
"""
Bintra PE Deep Forensics & Semantic Binary Diffing Engine (Strictly Read-Only).
Cross-platform static analysis for Windows PE32/PE32+ executables and DLLs:
  1. .pdata Exception / Unwind Table function boundary recovery (x64).
  2. MSVC RTTI recovery (CompleteObjectLocator, TypeDescriptor, ClassHierarchy, vftables).
  3. Offline Local PDB / CodeView (RSDS) MSF 7.00 verification & symbol correlation (zero network).
  4. Semantic Binary Diffing combining WL-CFG hashing, behavioral/P-Code vectors, and API anchors.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import struct
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np
except ImportError:
    np = None  # type: ignore

from security import ExecutionGuard, Capability, SafeFileAccess, TargetScope


# ---------------------------------------------------------------------------
# Low-level PE Section & RVA -> File Offset Helpers
# ---------------------------------------------------------------------------

def _parse_pe_layout(data: bytes) -> Dict[str, Any]:
    """Minimal, bounds-checked PE32/PE32+ header & section table parser."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("Not a valid PE file (missing MZ header).")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("Not a valid PE file (missing PE signature).")

    coff_off = e_lfanew + 4
    machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff_off)
    opt_off = coff_off + 20
    if opt_off + opt_size > len(data) or opt_size < 24:
        raise ValueError("Truncated PE optional header.")

    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe64 = (magic == 0x20B)
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"Unsupported PE optional magic: 0x{magic:04x}")

    if is_pe64:
        if opt_size < 112:
            raise ValueError("Truncated PE32+ optional header.")
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        num_rva_sizes = struct.unpack_from("<I", data, opt_off + 108)[0]
        dd_off = opt_off + 112
    else:
        if opt_size < 96:
            raise ValueError("Truncated PE32 optional header.")
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        num_rva_sizes = struct.unpack_from("<I", data, opt_off + 92)[0]
        dd_off = opt_off + 96

    data_dirs: List[Tuple[int, int]] = []
    for i in range(min(num_rva_sizes, 16)):
        if dd_off + (i + 1) * 8 <= opt_off + opt_size:
            rva, sz = struct.unpack_from("<II", data, dd_off + i * 8)
            data_dirs.append((rva, sz))
        else:
            data_dirs.append((0, 0))

    sec_off = opt_off + opt_size
    sections: List[Dict[str, Any]] = []
    for i in range(num_sections):
        entry_off = sec_off + i * 40
        if entry_off + 40 > len(data):
            break
        raw_name = data[entry_off:entry_off + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        vsize, va, rsize, roff, _, _, _, _, chars = struct.unpack_from("<IIIIIIHHI", data, entry_off + 8)
        sections.append({
            "name": name,
            "virtual_size": vsize,
            "virtual_address": va,
            "raw_size": rsize,
            "raw_offset": roff,
            "characteristics": chars,
        })

    return {
        "machine": machine,
        "is_pe64": is_pe64,
        "image_base": image_base,
        "data_directories": data_dirs,
        "sections": sections,
    }


def _rva_to_offset(rva: int, sections: List[Dict[str, Any]]) -> Optional[int]:
    if rva == 0:
        return None
    for sec in sections:
        va = sec["virtual_address"]
        span = max(sec["virtual_size"], sec["raw_size"])
        if va <= rva < va + span:
            delta = rva - va
            if delta < sec["raw_size"]:
                return sec["raw_offset"] + delta
            return None
    return None


def _va_to_rva(va: int, image_base: int) -> int:
    if va >= image_base:
        return va - image_base
    return -1


# ---------------------------------------------------------------------------
# 1. PE Deep Forensics Inspector (.pdata, MSVC RTTI, Offline PDB/RSDS)
# ---------------------------------------------------------------------------

class PeDeepForensicsInspector:
    """
    Strictly read-only deep forensics for PE32/PE32+ binaries:
      - .pdata x64 RUNTIME_FUNCTION & UNWIND_INFO function boundary recovery
      - MSVC RTTI CompleteObjectLocator / TypeDescriptor / vftable extraction
      - CodeView RSDS extraction & offline local PDB MSF 7.00 verification
    """

    def __init__(self, component_name: str = "pe_deep_forensics"):
        self.component_name = component_name

    def _read_binary_bytes(self, file_path: str) -> bytes:
        scope = TargetScope(target_binary_path=file_path)
        return SafeFileAccess.read_bytes(file_path)

    def extract_pdata_functions(
        self, data: bytes, layout: Optional[Dict[str, Any]] = None, limit: int = 2000
    ) -> Dict[str, Any]:
        """Extracts x64 RUNTIME_FUNCTION entries from the PE Exception Directory (index 3)."""
        if layout is None:
            layout = _parse_pe_layout(data)
        if not layout["is_pe64"]:
            return {
                "supported": False,
                "reason": "PE32 (32-bit) binaries do not use x64 .pdata RUNTIME_FUNCTION tables.",
                "function_count": 0,
                "functions": [],
            }

        dirs = layout["data_directories"]
        if len(dirs) <= 3 or dirs[3][0] == 0 or dirs[3][1] == 0:
            return {
                "supported": True,
                "reason": "No Exception Directory (.pdata) present.",
                "function_count": 0,
                "functions": [],
            }

        exc_rva, exc_size = dirs[3]
        exc_off = _rva_to_offset(exc_rva, layout["sections"])
        if exc_off is None or exc_off >= len(data):
            return {
                "supported": True,
                "reason": "Exception Directory RVA could not be mapped to file offset.",
                "function_count": 0,
                "functions": [],
            }

        avail = min(exc_size, len(data) - exc_off)
        total_entries = avail // 12
        functions: List[Dict[str, Any]] = []
        image_base = layout["image_base"]

        for idx in range(min(total_entries, limit)):
            off = exc_off + idx * 12
            begin_rva, end_rva, unwind_rva = struct.unpack_from("<III", data, off)
            if begin_rva == 0 and end_rva == 0:
                continue
            unwind_info: Dict[str, Any] = {}
            u_off = _rva_to_offset(unwind_rva, layout["sections"])
            if u_off is not None and u_off + 4 <= len(data):
                ver_flags, prolog_sz, code_cnt, frame_info = struct.unpack_from("<BBBB", data, u_off)
                unwind_info = {
                    "version": ver_flags & 0x07,
                    "flags": (ver_flags >> 3) & 0x1F,
                    "has_ehandler": bool((ver_flags >> 3) & 0x01),
                    "has_uhandler": bool((ver_flags >> 3) & 0x02),
                    "is_chained": bool((ver_flags >> 3) & 0x04),
                    "prolog_size": prolog_sz,
                    "unwind_codes_count": code_cnt,
                    "frame_register": frame_info & 0x0F,
                }
            functions.append({
                "begin_rva": hex(begin_rva),
                "end_rva": hex(end_rva),
                "va_start": hex(image_base + begin_rva),
                "size_bytes": max(0, end_rva - begin_rva),
                "unwind_rva": hex(unwind_rva),
                "unwind_info": unwind_info,
            })

        return {
            "supported": True,
            "exception_directory_rva": hex(exc_rva),
            "exception_directory_size": exc_size,
            "total_runtime_functions": total_entries,
            "returned_count": len(functions),
            "truncated": total_entries > limit,
            "functions": functions,
        }

    def extract_msvc_rtti(
        self, data: bytes, layout: Optional[Dict[str, Any]] = None, limit: int = 250
    ) -> Dict[str, Any]:
        """
        Scans .rdata / .data for MSVC RTTI TypeDescriptors (.?AV...@@ / .?AU...@@)
        and correlates CompleteObjectLocators & vftable candidates.
        """
        if layout is None:
            layout = _parse_pe_layout(data)
        is_pe64 = layout["is_pe64"]
        image_base = layout["image_base"]
        sections = layout["sections"]

        # Map file offsets back to RVA for sections
        def _off_to_rva(file_off: int) -> Optional[int]:
            for sec in sections:
                ro = sec["raw_offset"]
                rs = sec["raw_size"]
                if ro <= file_off < ro + rs:
                    return sec["virtual_address"] + (file_off - ro)
            return None

        # 1. Locate MSVC RTTI TypeDescriptor names (e.g. .?AVMyClass@@ or .?AUMyStruct@@)
        td_pattern = re.compile(rb"\.\?[AU]V?[A-Za-z0-9_@?$]+@@\x00")
        name_offset_in_td = 16 if is_pe64 else 8

        type_descriptors: Dict[int, Dict[str, Any]] = {}
        for m in td_pattern.finditer(data):
            name_off = m.start()
            td_off = name_off - name_offset_in_td
            if td_off < 0:
                continue
            td_rva = _off_to_rva(td_off)
            if td_rva is None:
                continue
            raw_sym = m.group(0)[:-1].decode("ascii", errors="replace")
            type_descriptors[td_rva] = {
                "mangled_name": raw_sym,
                "demangled_hint": self._demangle_msvc_rtti_name(raw_sym),
                "td_rva": hex(td_rva),
                "td_va": hex(image_base + td_rva),
            }
            if len(type_descriptors) >= limit * 2:
                break

        # 2. Scan .rdata / .data for CompleteObjectLocator (COL) structs pointing to discovered TypeDescriptors
        col_matches: List[Dict[str, Any]] = []
        vftables: List[Dict[str, Any]] = []
        ptr_size = 8 if is_pe64 else 4
        ptr_fmt = "<Q" if is_pe64 else "<I"

        col_rvas: Dict[int, Dict[str, Any]] = {}
        for sec in sections:
            if not any(tag in sec["name"].lower() for tag in (".rdata", ".data", "const")):
                continue
            sec_start = sec["raw_offset"]
            sec_end = min(len(data), sec_start + sec["raw_size"])
            if is_pe64:
                # x64 COL: signature(4)=1, offset(4), cdOffset(4), pTypeDescriptor(4 RVA), pClassDescriptor(4 RVA), pSelf(4 RVA)
                for off in range(sec_start, sec_end - 24 + 1, 4):
                    sig, v_off, cd_off, p_td, p_cd, p_self = struct.unpack_from("<IIIIII", data, off)
                    if sig == 1 and p_td in type_descriptors:
                        actual_rva = _off_to_rva(off)
                        if actual_rva is not None and p_self == actual_rva:
                            entry = {
                                "col_rva": hex(actual_rva),
                                "col_va": hex(image_base + actual_rva),
                                "type": type_descriptors[p_td]["mangled_name"],
                                "demangled_hint": type_descriptors[p_td]["demangled_hint"],
                                "vtable_offset": v_off,
                                "cd_offset": cd_off,
                                "class_hierarchy_rva": hex(p_cd),
                            }
                            col_rvas[image_base + actual_rva] = entry
                            col_matches.append(entry)
                            if len(col_matches) >= limit:
                                break
            else:
                # x86 COL: signature(4)=0, offset(4), cdOffset(4), pTypeDescriptor(4 VA), pClassDescriptor(4 VA)
                for off in range(sec_start, sec_end - 20 + 1, 4):
                    sig, v_off, cd_off, p_td_va, p_cd_va = struct.unpack_from("<IIIII", data, off)
                    p_td_rva = _va_to_rva(p_td_va, image_base)
                    if sig == 0 and p_td_rva in type_descriptors:
                        actual_rva = _off_to_rva(off)
                        if actual_rva is not None:
                            entry = {
                                "col_rva": hex(actual_rva),
                                "col_va": hex(image_base + actual_rva),
                                "type": type_descriptors[p_td_rva]["mangled_name"],
                                "demangled_hint": type_descriptors[p_td_rva]["demangled_hint"],
                                "vtable_offset": v_off,
                                "cd_offset": cd_off,
                                "class_hierarchy_va": hex(p_cd_va),
                            }
                            col_rvas[image_base + actual_rva] = entry
                            col_matches.append(entry)
                            if len(col_matches) >= limit:
                                break

        # 3. Locate vftable pointers (slot[-1] == col_va, slot[0..] == code section pointers)
        if col_rvas:
            exec_ranges = [
                (image_base + s["virtual_address"], image_base + s["virtual_address"] + max(s["virtual_size"], s["raw_size"]))
                for s in sections
                if (s["characteristics"] & 0x20000000) or (".text" in s["name"].lower())
            ]
            for sec in sections:
                if not any(tag in sec["name"].lower() for tag in (".rdata", ".data", "const")):
                    continue
                sec_start = sec["raw_offset"]
                sec_end = min(len(data), sec_start + sec["raw_size"])
                for off in range(sec_start, sec_end - ptr_size * 2 + 1, ptr_size):
                    cand_col_va = struct.unpack_from(ptr_fmt, data, off)[0]
                    if cand_col_va in col_rvas:
                        first_fn_va = struct.unpack_from(ptr_fmt, data, off + ptr_size)[0]
                        if any(lo <= first_fn_va < hi for lo, hi in exec_ranges):
                            vft_rva = _off_to_rva(off + ptr_size)
                            methods: List[str] = []
                            m_off = off + ptr_size
                            while m_off + ptr_size <= sec_end and len(methods) < 64:
                                fn_va = struct.unpack_from(ptr_fmt, data, m_off)[0]
                                if any(lo <= fn_va < hi for lo, hi in exec_ranges):
                                    methods.append(hex(fn_va))
                                    m_off += ptr_size
                                else:
                                    break
                            vftables.append({
                                "type": col_rvas[cand_col_va]["type"],
                                "demangled_hint": col_rvas[cand_col_va]["demangled_hint"],
                                "vftable_rva": hex(vft_rva) if vft_rva is not None else None,
                                "vftable_va": hex(image_base + vft_rva) if vft_rva is not None else None,
                                "method_count": len(methods),
                                "method_vas_sample": methods[:16],
                            })
                            if len(vftables) >= limit:
                                break

        return {
            "type_descriptors_count": len(type_descriptors),
            "complete_object_locators_count": len(col_matches),
            "vftables_count": len(vftables),
            "type_descriptors": list(type_descriptors.values())[:limit],
            "complete_object_locators": col_matches[:limit],
            "vftables": vftables[:limit],
        }

    @staticmethod
    def _demangle_msvc_rtti_name(mangled: str) -> str:
        # Clean structural demangling for .?AVClass@Namespace@@ -> Namespace::Class
        core = mangled
        prefix = "class "
        if core.startswith(".?AV"):
            core = core[4:]
        elif core.startswith(".?AU"):
            core = core[4:]
            prefix = "struct "
        if core.endswith("@@"):
            core = core[:-2]
        parts = [p for p in core.split("@") if p]
        if not parts:
            return mangled
        return prefix + "::".join(reversed(parts))

    def correlate_local_pdb(
        self, data: bytes, binary_path: str, pdb_path: Optional[str] = None,
        layout: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Extracts CodeView RSDS GUID/Age from IMAGE_DEBUG_DIRECTORY and verifies
        any matching local .pdb file (strictly offline, zero network calls).
        """
        if layout is None:
            layout = _parse_pe_layout(data)
        dirs = layout["data_directories"]
        rsds_records: List[Dict[str, Any]] = []

        if len(dirs) > 6 and dirs[6][0] != 0 and dirs[6][1] >= 28:
            dbg_rva, dbg_size = dirs[6]
            dbg_off = _rva_to_offset(dbg_rva, layout["sections"])
            if dbg_off is not None:
                count = min(dbg_size, len(data) - dbg_off) // 28
                for i in range(count):
                    e_off = dbg_off + i * 28
                    _, _, _, _, dbg_type, size_of_data, _, ptr_raw = struct.unpack_from("<IIHHIIII", data, e_off)
                    if dbg_type == 2 and ptr_raw != 0 and ptr_raw + size_of_data <= len(data):
                        cv = data[ptr_raw:ptr_raw + size_of_data]
                        if cv[:4] == b"RSDS" and len(cv) >= 24:
                            d1, d2, d3 = struct.unpack_from("<IHH", cv, 4)
                            d4 = cv[12:20]
                            age = struct.unpack_from("<I", cv, 20)[0]
                            pdb_str = cv[24:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                            guid_str = f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:2].hex()}-{d4[2:].hex()}"
                            rsds_records.append({
                                "signature": "RSDS",
                                "guid": guid_str.upper(),
                                "age": age,
                                "embedded_pdb_path": pdb_str,
                            })

        candidate_pdb: Optional[str] = None
        if pdb_path:
            candidate_pdb = pdb_path
        elif rsds_records:
            emb = rsds_records[0]["embedded_pdb_path"]
            base_dir = os.path.dirname(os.path.abspath(binary_path))
            local_by_name = os.path.join(base_dir, os.path.basename(emb.replace("\\", "/")))
            stem_pdb = os.path.splitext(os.path.abspath(binary_path))[0] + ".pdb"
            if os.path.isfile(local_by_name):
                candidate_pdb = local_by_name
            elif os.path.isfile(stem_pdb):
                candidate_pdb = stem_pdb

        pdb_verification: Dict[str, Any] = {
            "offline_only": True,
            "local_pdb_found": False,
            "local_pdb_path": candidate_pdb,
            "msf_valid": False,
            "guid_match": False,
        }

        if candidate_pdb and os.path.isfile(candidate_pdb):
            scope = TargetScope(target_binary_path=candidate_pdb)
            pdb_bytes = SafeFileAccess.read_bytes(candidate_pdb)
            pdb_verification["local_pdb_found"] = True
            pdb_verification["local_pdb_size"] = len(pdb_bytes)
            msf_magic = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
            if pdb_bytes.startswith(msf_magic) and len(pdb_bytes) >= 56:
                pdb_verification["msf_valid"] = True
                block_size, _, num_blocks, num_dir_bytes, _, block_map_addr = struct.unpack_from("<IIIIII", pdb_bytes, 32)
                pdb_verification["msf_block_size"] = block_size
                pdb_verification["msf_num_blocks"] = num_blocks
                # Read Stream 1 (PDB Info Stream) if directory fits cleanly
                pdb_info = self._try_read_msf_pdb_info(pdb_bytes, block_size, num_dir_bytes, block_map_addr)
                if pdb_info:
                    pdb_verification["pdb_stream_info"] = pdb_info
                    if rsds_records and pdb_info.get("guid") == rsds_records[0]["guid"]:
                        pdb_verification["guid_match"] = True

        return {
            "rsds_records": rsds_records,
            "pdb_verification": pdb_verification,
        }

    @staticmethod
    def _try_read_msf_pdb_info(
        pdb_bytes: bytes, block_size: int, num_dir_bytes: int, block_map_addr: int
    ) -> Optional[Dict[str, Any]]:
        if block_size not in (512, 1024, 2048, 4096) or block_map_addr == 0:
            return None
        dir_map_off = block_map_addr * block_size
        num_dir_blocks = math.ceil(num_dir_bytes / block_size)
        if dir_map_off + num_dir_blocks * 4 > len(pdb_bytes):
            return None
        dir_blocks = struct.unpack_from(f"<{num_dir_blocks}I", pdb_bytes, dir_map_off)
        dir_data = bytearray()
        for blk in dir_blocks:
            b_off = blk * block_size
            if b_off + block_size > len(pdb_bytes):
                return None
            dir_data.extend(pdb_bytes[b_off:b_off + block_size])
        dir_data = dir_data[:num_dir_bytes]
        if len(dir_data) < 4:
            return None
        num_streams = struct.unpack_from("<I", dir_data, 0)[0]
        if num_streams < 2 or 4 + num_streams * 4 > len(dir_data):
            return None
        stream_sizes = struct.unpack_from(f"<{num_streams}I", dir_data, 4)
        cursor = 4 + num_streams * 4
        stream_blocks: List[List[int]] = []
        for s_sz in stream_sizes:
            if s_sz == 0xFFFFFFFF or s_sz == 0:
                stream_blocks.append([])
                continue
            n_blk = math.ceil(s_sz / block_size)
            if cursor + n_blk * 4 > len(dir_data):
                return None
            stream_blocks.append(list(struct.unpack_from(f"<{n_blk}I", dir_data, cursor)))
            cursor += n_blk * 4

        # Stream 1 is PDB Info Stream (Version(4), Signature(4), Age(4), GUID(16))
        s1_blocks = stream_blocks[1]
        if not s1_blocks or stream_sizes[1] < 28:
            return None
        s1_data = bytearray()
        for blk in s1_blocks:
            b_off = blk * block_size
            if b_off + block_size > len(pdb_bytes):
                return None
            s1_data.extend(pdb_bytes[b_off:b_off + block_size])
        version, sig, age = struct.unpack_from("<III", s1_data, 0)
        d1, d2, d3 = struct.unpack_from("<IHH", s1_data, 12)
        d4 = bytes(s1_data[20:28])
        guid_str = f"{d1:08x}-{d2:04x}-{d3:04x}-{d4[:2].hex()}-{d4[2:].hex()}".upper()
        return {
            "version": version,
            "signature": sig,
            "age": age,
            "guid": guid_str,
            "num_streams": num_streams,
        }

    def inspect(self, file_path: str, pdb_path: Optional[str] = None, limit: int = 500) -> Dict[str, Any]:
        """Full read-only deep PE forensics pass (.pdata + MSVC RTTI + Local PDB)."""
        data = self._read_binary_bytes(file_path)
        layout = _parse_pe_layout(data)
        pdata = self.extract_pdata_functions(data, layout=layout, limit=limit)
        rtti = self.extract_msvc_rtti(data, layout=layout, limit=min(limit, 250))
        pdb = self.correlate_local_pdb(data, binary_path=file_path, pdb_path=pdb_path, layout=layout)
        return {
            "status": "ok",
            "file": os.path.abspath(file_path),
            "sha256": hashlib.sha256(data).hexdigest(),
            "architecture": "x64 (PE32+)" if layout["is_pe64"] else "x86 (PE32)",
            "image_base": hex(layout["image_base"]),
            "pdata_functions": pdata,
            "msvc_rtti": rtti,
            "pdb_correlation": pdb,
            "epistemic_classification": "DETERMINISTIC_BINARY_STRUCTURE_PARSE",
        }


# ---------------------------------------------------------------------------
# 2. Semantic Binary Differ (Exports, .pdata Functions, or Ghidra Functions)
# ---------------------------------------------------------------------------

class SemanticBinaryDiffer:
    """
    Cross-version and cross-build binary diffing engine.
    Compares:
      - PE structural metadata, imports/exports, .pdata function counts, RTTI classes
      - Ghidra / P-Code exported function sets using WL-CFG hashes, 64-D P-Code cosine,
        and String/API anchor Jaccard similarity.
    """

    def __init__(self, component_name: str = "pe_deep_forensics"):
        self.component_name = component_name

    def diff_pe_binaries(self, baseline_path: str, target_path: str) -> Dict[str, Any]:
        """Compares two PE binaries deterministically using .pdata, RTTI, and section/byte digests."""
        inspector = PeDeepForensicsInspector(component_name=self.component_name)
        base_res = inspector.inspect(baseline_path, limit=5000)
        targ_res = inspector.inspect(target_path, limit=5000)

        base_rtti_types = {x["type"] for x in base_res["msvc_rtti"].get("type_descriptors", [])}
        targ_rtti_types = {x["type"] for x in targ_res["msvc_rtti"].get("type_descriptors", [])}

        base_pdata_cnt = base_res["pdata_functions"].get("total_runtime_functions", 0)
        targ_pdata_cnt = targ_res["pdata_functions"].get("total_runtime_functions", 0)

        return {
            "status": "ok",
            "baseline_file": base_res["file"],
            "target_file": targ_res["file"],
            "identical_sha256": base_res["sha256"] == targ_res["sha256"],
            "baseline_sha256": base_res["sha256"],
            "target_sha256": targ_res["sha256"],
            "pdata_function_delta": targ_pdata_cnt - base_pdata_cnt,
            "baseline_pdata_count": base_pdata_cnt,
            "target_pdata_count": targ_pdata_cnt,
            "rtti_classes_added": sorted(targ_rtti_types - base_rtti_types)[:100],
            "rtti_classes_removed": sorted(base_rtti_types - targ_rtti_types)[:100],
            "rtti_classes_shared_count": len(base_rtti_types & targ_rtti_types),
            "epistemic_classification": "DETERMINISTIC_PE_DIFF",
        }

    def diff_function_exports(
        self, baseline_funcs: List[Dict[str, Any]], target_funcs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Semantic diffing of two Ghidra/P-Code function lists using:
          1. Exact WL-CFG + opcode signature hash match (IDENTICAL)
          2. 64-D P-Code cosine + API/String anchor Jaccard match (EQUIVALENT or MODIFIED)
          3. Unmatched sets (ADDED / REMOVED)
        """
        from ghidra_pcode_vectorizer import PcodeVectorizer, WeisfeilerLehmanCfgHasher

        vec = PcodeVectorizer()
        wl = WeisfeilerLehmanCfgHasher()

        def _prep(fn: Dict[str, Any]) -> Dict[str, Any]:
            ops = fn.get("pcode_ops", [])
            bbs = fn.get("basic_blocks", [])
            v = PcodeVectorizer.vectorize_high_function(ops, basic_blocks=bbs).get("vector", [])
            wl_hash = wl.compute_wl_hash(bbs, pcode_ops=ops)
            anchors = set(fn.get("api_calls", []) + fn.get("strings", []))
            return {
                "name": fn.get("name", fn.get("address", "unknown")),
                "address": fn.get("address", "0x0"),
                "vector": v,
                "wl_hash": wl_hash,
                "anchors": anchors,
                "op_count": len(ops),
            }

        base_prepped = [_prep(f) for f in baseline_funcs]
        targ_prepped = [_prep(f) for f in target_funcs]

        matched_base = set()
        matched_targ = set()
        identical: List[Dict[str, Any]] = []
        equivalent: List[Dict[str, Any]] = []
        modified: List[Dict[str, Any]] = []

        # Pass 1: Exact WL-CFG hash + name/anchor match
        for bi, b in enumerate(base_prepped):
            for ti, t in enumerate(targ_prepped):
                if ti in matched_targ:
                    continue
                if b["wl_hash"] == t["wl_hash"] and b["op_count"] > 0:
                    matched_base.add(bi)
                    matched_targ.add(ti)
                    identical.append({
                        "baseline": b["name"],
                        "target": t["name"],
                        "wl_hash": b["wl_hash"],
                        "classification": "IDENTICAL",
                    })
                    break

        # Pass 2: Semantic similarity (0.75 * P-Code cosine + 0.25 * Anchor Jaccard)
        for bi, b in enumerate(base_prepped):
            if bi in matched_base:
                continue
            best_ti = -1
            best_score = -1.0
            best_cos = 0.0
            best_jac = 0.0
            for ti, t in enumerate(targ_prepped):
                if ti in matched_targ:
                    continue
                cos = self._cosine(b["vector"], t["vector"])
                jac = self._jaccard(b["anchors"], t["anchors"])
                combined = 0.75 * cos + 0.25 * jac if (b["anchors"] or t["anchors"]) else cos
                if combined > best_score:
                    best_score = combined
                    best_ti = ti
                    best_cos = cos
                    best_jac = jac
            if best_ti >= 0 and best_score >= 0.78:
                matched_base.add(bi)
                matched_targ.add(best_ti)
                t = targ_prepped[best_ti]
                cls_label = "SEMANTICALLY_EQUIVALENT" if best_score >= 0.92 else "MODIFIED"
                entry = {
                    "baseline": b["name"],
                    "target": t["name"],
                    "combined_score": round(best_score, 4),
                    "pcode_cosine": round(best_cos, 4),
                    "anchor_jaccard": round(best_jac, 4),
                    "classification": cls_label,
                }
                if cls_label == "SEMANTICALLY_EQUIVALENT":
                    equivalent.append(entry)
                else:
                    modified.append(entry)

        removed = [base_prepped[i]["name"] for i in range(len(base_prepped)) if i not in matched_base]
        added = [targ_prepped[i]["name"] for i in range(len(targ_prepped)) if i not in matched_targ]

        return {
            "status": "ok",
            "summary": {
                "baseline_count": len(base_prepped),
                "target_count": len(targ_prepped),
                "identical_count": len(identical),
                "semantically_equivalent_count": len(equivalent),
                "modified_count": len(modified),
                "removed_count": len(removed),
                "added_count": len(added),
            },
            "identical": identical,
            "semantically_equivalent": equivalent,
            "modified": modified,
            "removed": removed,
            "added": added,
            "epistemic_classification": "WL_CFG_HASH_AND_PCODE_HEURISTIC_DIFF",
        }

    @staticmethod
    def _cosine(a: Any, b: Any) -> float:
        if np is not None:
            na = float(np.linalg.norm(a))
            nb = float(np.linalg.norm(b))
            if na == 0.0 or nb == 0.0:
                return 0.0
            return float(np.dot(a, b) / (na * nb))
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb) if na and nb else 0.0

    @staticmethod
    def _jaccard(a: set, b: set) -> float:
        if not a and not b:
            return 0.0
        return len(a & b) / float(len(a | b))
