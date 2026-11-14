# -*- coding: utf-8 -*-
"""
Bintra Python Bytecode & Frozen Binary Intelligence.
Provides:
  1. PythonBytecodeAnalyzer: Disassembles CPython bytecode (.py / .pyc) via `dis`
     and `marshal`, constructs Control-Flow Basic Blocks with P-Code-mapped opcodes,
     and feeds them directly into `WeisfeilerLehmanCfgHasher`.
  2. FrozenPythonDetector: Detects .pyd C-extensions, PyInstaller archives,
     Cython modules, and Nuitka-compiled binaries in PE executables.
"""

import dis
import hashlib
import marshal
import os
import struct
import types
from typing import Any, Dict, List, Optional, Set, Tuple

from ghidra_pcode_vectorizer import WeisfeilerLehmanCfgHasher


# Mapping from CPython opname categories to canonical P-Code-like opcodes
_CPYTHON_TO_PCODE: Dict[str, str] = {
    "LOAD_CONST": "COPY",
    "LOAD_FAST": "LOAD",
    "LOAD_FAST_CHECK": "LOAD",
    "LOAD_GLOBAL": "LOAD",
    "LOAD_NAME": "LOAD",
    "LOAD_ATTR": "LOAD",
    "LOAD_METHOD": "LOAD",
    "STORE_FAST": "STORE",
    "STORE_GLOBAL": "STORE",
    "STORE_NAME": "STORE",
    "STORE_ATTR": "STORE",
    "CALL": "CALL",
    "CALL_FUNCTION": "CALL",
    "CALL_METHOD": "CALL",
    "CALL_FUNCTION_KW": "CALL",
    "CALL_FUNCTION_EX": "CALL",
    "RETURN_VALUE": "RETURN",
    "RETURN_CONST": "RETURN",
    "JUMP_FORWARD": "BRANCH",
    "JUMP_BACKWARD": "BRANCH",
    "JUMP_ABSOLUTE": "BRANCH",
    "POP_JUMP_IF_FALSE": "CBRANCH",
    "POP_JUMP_IF_TRUE": "CBRANCH",
    "POP_JUMP_FORWARD_IF_FALSE": "CBRANCH",
    "POP_JUMP_FORWARD_IF_TRUE": "CBRANCH",
    "POP_JUMP_BACKWARD_IF_FALSE": "CBRANCH",
    "POP_JUMP_BACKWARD_IF_TRUE": "CBRANCH",
    "FOR_ITER": "CBRANCH",
    "BINARY_OP": "INT_ADD",
    "BINARY_ADD": "INT_ADD",
    "BINARY_SUBTRACT": "INT_SUB",
    "BINARY_MULTIPLY": "INT_MULT",
    "COMPARE_OP": "INT_EQUAL",
    "IS_OP": "INT_EQUAL",
    "CONTAINS_OP": "INT_EQUAL",
    "RAISE_VARARGS": "CALLIND",
}

_UNCONDITIONAL_JUMPS = {"JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_ABSOLUTE"}
_CONDITIONAL_JUMPS = {
    "POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
    "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_FORWARD_IF_TRUE",
    "POP_JUMP_BACKWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_TRUE",
    "FOR_ITER",
}
_TERMINATORS = _UNCONDITIONAL_JUMPS | _CONDITIONAL_JUMPS | {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"}


class PythonBytecodeAnalyzer:
    """Disassembles .py / .pyc code objects into Basic Blocks & WL-CFG hashes."""

    MAX_PYC_BYTES = 32 * 1024 * 1024  # 32 MB safety cap

    @classmethod
    def load_code_object(cls, file_path: str) -> Tuple[types.CodeType, Dict[str, Any]]:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        size = os.path.getsize(file_path)
        if size > cls.MAX_PYC_BYTES:
            raise ValueError(f"File exceeds {cls.MAX_PYC_BYTES} byte safety limit.")

        if file_path.lower().endswith(".pyc"):
            with open(file_path, "rb") as f:
                data = f.read()
            if len(data) < 16:
                raise ValueError("Invalid .pyc file: shorter than 16-byte PEP 552 header.")
            magic_num = struct.unpack("<H", data[:2])[0]
            bitfield = struct.unpack("<I", data[4:8])[0]
            code_obj = marshal.loads(data[16:])
            if not isinstance(code_obj, types.CodeType):
                raise ValueError("Unmarshaled .pyc payload is not a CodeType.")
            return code_obj, {
                "input_type": "PYC_BYTECODE",
                "pyc_magic": hex(magic_num),
                "pep552_bitfield": bitfield,
            }

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
        code_obj = compile(source, file_path, "exec")
        return code_obj, {"input_type": "PYTHON_SOURCE_COMPILED"}

    @staticmethod
    def _map_opcode_to_pcode(opname: str) -> str:
        return _CPYTHON_TO_PCODE.get(opname, f"PY_{opname}")

    @classmethod
    def code_to_basic_blocks(cls, code_obj: types.CodeType) -> List[Dict[str, Any]]:
        insns = list(dis.get_instructions(code_obj))
        if not insns:
            return []

        offset_to_idx = {ins.offset: i for i, ins in enumerate(insns)}
        block_starts: Set[int] = {insns[0].offset}

        for i, ins in enumerate(insns):
            if ins.is_jump_target:
                block_starts.add(ins.offset)
            if ins.opname in _TERMINATORS:
                if isinstance(ins.argval, int) and ins.argval in offset_to_idx:
                    block_starts.add(ins.argval)
                if i + 1 < len(insns):
                    block_starts.add(insns[i + 1].offset)

        sorted_starts = sorted(block_starts)
        start_to_block_id = {off: f"BB_{off:04x}" for off in sorted_starts}

        blocks: List[Dict[str, Any]] = []
        current_insns: List[dis.Instruction] = []
        current_start = insns[0].offset

        def _flush(b_start: int, b_insns: List[dis.Instruction], next_off: Optional[int]) -> None:
            if not b_insns:
                return
            last = b_insns[-1]
            succs: List[str] = []
            if last.opname in _UNCONDITIONAL_JUMPS:
                if isinstance(last.argval, int) and last.argval in start_to_block_id:
                    succs.append(start_to_block_id[last.argval])
            elif last.opname in _CONDITIONAL_JUMPS:
                if isinstance(last.argval, int) and last.argval in start_to_block_id:
                    succs.append(start_to_block_id[last.argval])
                if next_off is not None and next_off in start_to_block_id:
                    succs.append(start_to_block_id[next_off])
            elif last.opname not in {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS"}:
                if next_off is not None and next_off in start_to_block_id:
                    succs.append(start_to_block_id[next_off])

            pcode_ops = [
                {
                    "offset": hex(ins.offset),
                    "cpython_op": ins.opname,
                    "opcode": cls._map_opcode_to_pcode(ins.opname),
                    "arg": ins.argrepr or None,
                }
                for ins in b_insns
            ]
            blocks.append({
                "id": start_to_block_id[b_start],
                "start_offset": hex(b_start),
                "instruction_count": len(b_insns),
                "successors": succs,
                "pcode_ops": pcode_ops,
            })

        for i, ins in enumerate(insns):
            if i > 0 and ins.offset in block_starts:
                _flush(current_start, current_insns, ins.offset)
                current_start = ins.offset
                current_insns = [ins]
            else:
                current_insns.append(ins)
        _flush(current_start, current_insns, None)
        return blocks

    @classmethod
    def _collect_code_objects(cls, root: types.CodeType, limit: int = 100) -> List[types.CodeType]:
        collected: List[types.CodeType] = []
        queue: List[types.CodeType] = [root]
        while queue and len(collected) < limit:
            co = queue.pop(0)
            collected.append(co)
            for c in co.co_consts:
                if isinstance(c, types.CodeType):
                    queue.append(c)
        return collected

    @classmethod
    def analyze_file(cls, file_path: str, limit: int = 50) -> Dict[str, Any]:
        root_co, meta = cls.load_code_object(file_path)
        hasher = WeisfeilerLehmanCfgHasher(iterations=2)
        code_objs = cls._collect_code_objects(root_co, limit=limit)

        functions_report: List[Dict[str, Any]] = []
        total_blocks = 0
        total_insns = 0

        for co in code_objs:
            bbs = cls.code_to_basic_blocks(co)
            wl_hash = hasher.compute_wl_hash(basic_blocks=bbs)
            ins_cnt = sum(b["instruction_count"] for b in bbs)
            total_blocks += len(bbs)
            total_insns += ins_cnt
            functions_report.append({
                "name": co.co_name,
                "firstlineno": co.co_firstlineno,
                "argcount": co.co_argcount,
                "basic_blocks_count": len(bbs),
                "instructions_count": ins_cnt,
                "wl_cfg_hash": wl_hash,
                "basic_blocks_preview": bbs[:5],
            })

        with open(file_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

        return {
            "status": "ok",
            "file": os.path.abspath(file_path),
            "sha256": sha256,
            "metadata": meta,
            "code_objects_analyzed": len(functions_report),
            "total_basic_blocks": total_blocks,
            "total_bytecode_instructions": total_insns,
            "functions": functions_report,
        }

    @classmethod
    def compare_bytecode(cls, baseline_path: str, target_path: str) -> Dict[str, Any]:
        base = cls.analyze_file(baseline_path, limit=200)
        targ = cls.analyze_file(target_path, limit=200)
        base_map = {f["name"]: f["wl_cfg_hash"] for f in base["functions"]}
        targ_map = {f["name"]: f["wl_cfg_hash"] for f in targ["functions"]}

        matched_identical = []
        modified = []
        for name in sorted(set(base_map) & set(targ_map)):
            if base_map[name] == targ_map[name]:
                matched_identical.append(name)
            else:
                modified.append({"name": name, "baseline_wl": base_map[name], "target_wl": targ_map[name]})

        return {
            "status": "ok",
            "diff_mode": "PYTHON_BYTECODE_WL_CFG_DIFF",
            "matched_identical_count": len(matched_identical),
            "modified_count": len(modified),
            "added_functions": sorted(set(targ_map) - set(base_map)),
            "removed_functions": sorted(set(base_map) - set(targ_map)),
            "modified_functions": modified[:50],
        }


class FrozenPythonDetector:
    """
    Detects Python Frozen Executables & C-Extensions inside PE binaries:
      - Windows .pyd C-Extension DLLs (PyInit_* / python3*.dll)
      - PyInstaller executables (MEI magic, PYZ archive, pyi- markers)
      - Cython compiled modules (__pyx_ symbols)
      - Nuitka compiled binaries (__nuitka_ markers)
    """

    MARKERS: List[Tuple[bytes, str, str]] = [
        (b"MEI\x0c\x0b\x0a\x0b\x0e\x08", "PyInstaller CArchive Cookie", "PYINSTALLER"),
        (b"PYZ\x00", "PyInstaller PYZ Bytecode Archive", "PYINSTALLER"),
        (b"pyi-windows-manifest-filename", "PyInstaller Bootloader Manifest", "PYINSTALLER"),
        (b"PyInit_", "CPython C-Extension / .pyd Entrypoint", "CPYTHON_PYD_EXT"),
        (b"__pyx_", "Cython Compiled C-Extension Symbol", "CYTHON"),
        (b"__nuitka_", "Nuitka Compiled Python Binary Marker", "NUITKA"),
        (b"python311.dll", "CPython 3.11 Runtime Dependency", "CPYTHON_RUNTIME"),
        (b"python312.dll", "CPython 3.12 Runtime Dependency", "CPYTHON_RUNTIME"),
        (b"python310.dll", "CPython 3.10 Runtime Dependency", "CPYTHON_RUNTIME"),
    ]

    @classmethod
    def scan_bytes(cls, data: bytes, file_path: str = "") -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        categories: Set[str] = set()
        for sig, desc, cat in cls.MARKERS:
            idx = data.find(sig)
            if idx != -1:
                categories.add(cat)
                findings.append({
                    "category": cat,
                    "description": desc,
                    "offset": hex(idx),
                    "marker": sig.decode("ascii", errors="replace"),
                })

        is_pyd_ext = file_path.lower().endswith(".pyd") or ("CPYTHON_PYD_EXT" in categories)
        return {
            "is_frozen_python": len(findings) > 0,
            "is_pyd_extension": is_pyd_ext,
            "detected_toolchains": sorted(categories),
            "markers_count": len(findings),
            "markers": findings,
        }
