# -*- coding: utf-8 -*-
"""
Bintra CPython Live Memory Forensics (Strictly Read-Only).
Built on top of VirtualMemoryInspector and StructureDissector to inspect
64-bit CPython 3.11/3.12 object layouts (PyObject, PyASCIIObject, PyLongObject,
PyDictObject, PyDictKeysObject) in live processes or raw memory dumps.
"""

import struct
from typing import Any, Dict, List, Optional


class CPythonMemoryForensics:
    """
    Strictly read-only forensic parser for 64-bit CPython heap objects.
    Provides both deterministic raw-buffer parsing (offline/unit-testable)
    and live PID memory inspection via VirtualMemoryInspector + StructureDissector.
    """

    PTR_SIZE = 8  # x64 CPython

    @staticmethod
    def parse_pyobject_header(raw: bytes, base_address: int = 0) -> Dict[str, Any]:
        """Parses standard 64-bit PyObject header: ob_refcnt (8B) + ob_type (8B)."""
        if len(raw) < 16:
            return {"status": "error", "error": "Buffer shorter than 16 bytes for PyObject header."}
        ob_refcnt, ob_type = struct.unpack("<qQ", raw[:16])
        return {
            "status": "ok",
            "address": hex(base_address),
            "ob_refcnt": ob_refcnt,
            "ob_type_ptr": hex(ob_type),
            "immortal_hint": ob_refcnt >= 0x3FFFFFFF,
        }

    @classmethod
    def inspect_pyascii_buffer(cls, raw: bytes, base_address: int = 0) -> Dict[str, Any]:
        """
        Parses 64-bit CPython PyASCIIObject:
          +0x00: ob_refcnt (8B)
          +0x08: ob_type   (8B)
          +0x10: length    (8B)
          +0x18: hash      (8B)
          +0x20: state     (4B bitfield: interned:2, kind:3, compact:1, ascii:1, ...)
          +0x24: padding   (4B)
          +0x28: inline UTF-8/ASCII payload (for compact ASCII strings)
        """
        if len(raw) < 40:
            return {"status": "error", "error": "Buffer shorter than 40 bytes for PyASCIIObject."}
        hdr = cls.parse_pyobject_header(raw, base_address)
        length, str_hash, state = struct.unpack("<qqI", raw[16:36])
        kind = (state >> 2) & 0x7
        compact = bool((state >> 5) & 0x1)
        is_ascii = bool((state >> 6) & 0x1)

        preview = None
        if compact and is_ascii and 0 <= length <= 256 and len(raw) >= 40 + length:
            preview = raw[40:40 + length].decode("ascii", errors="replace")

        return {
            "status": "ok",
            "object_kind": "PyASCIIObject",
            **hdr,
            "length": length,
            "hash": hex(str_hash & 0xFFFFFFFFFFFFFFFF),
            "char_kind": kind,
            "compact": compact,
            "is_ascii": is_ascii,
            "value_preview": preview,
        }

    @classmethod
    def inspect_pylong_buffer(cls, raw: bytes, base_address: int = 0) -> Dict[str, Any]:
        """
        Parses 64-bit CPython 3.12+ PyLongObject (compact lv_tag layout):
          +0x00: ob_refcnt (8B)
          +0x08: ob_type   (8B)
          +0x10: lv_tag    (8B: sign = tag & 3 [0=pos, 1=zero, 2=neg], ndigits = tag >> 3)
          +0x18: ob_digit[0..] (uint32_t 30-bit limbs)
        """
        if len(raw) < 28:
            return {"status": "error", "error": "Buffer shorter than 28 bytes for PyLongObject."}
        hdr = cls.parse_pyobject_header(raw, base_address)
        (lv_tag,) = struct.unpack("<Q", raw[16:24])
        sign_bits = lv_tag & 0x3
        ndigits = lv_tag >> 3
        val = 0
        if sign_bits != 1 and 0 < ndigits <= 8 and len(raw) >= 24 + ndigits * 4:
            for i in range(ndigits):
                (limb,) = struct.unpack("<I", raw[24 + i * 4:28 + i * 4])
                val += (limb & 0x3FFFFFFF) << (30 * i)
            if sign_bits == 2:
                val = -val
        return {
            "status": "ok",
            "object_kind": "PyLongObject",
            **hdr,
            "ndigits": ndigits,
            "sign": "zero" if sign_bits == 1 else ("negative" if sign_bits == 2 else "positive"),
            "decoded_value": val,
        }

    @classmethod
    def inspect_pydict_buffer(
        cls,
        dict_raw: bytes,
        keys_raw: Optional[bytes] = None,
        base_address: int = 0,
    ) -> Dict[str, Any]:
        """
        Parses 64-bit CPython PyDictObject:
          +0x00: ob_refcnt (8B)
          +0x08: ob_type   (8B)
          +0x10: ma_used   (8B)
          +0x18: ma_version_tag (8B)
          +0x20: ma_keys   (8B pointer to PyDictKeysObject)
          +0x28: ma_values (8B pointer to PyDictValues or NULL)
        If `keys_raw` is supplied, also parses PyDictKeysObject header & entry pointers.
        """
        if len(dict_raw) < 48:
            return {"status": "error", "error": "Buffer shorter than 48 bytes for PyDictObject."}
        hdr = cls.parse_pyobject_header(dict_raw, base_address)
        ma_used, ma_version_tag, ma_keys_ptr, ma_values_ptr = struct.unpack("<qQQQ", dict_raw[16:48])
        result: Dict[str, Any] = {
            "status": "ok",
            "object_kind": "PyDictObject",
            **hdr,
            "ma_used": ma_used,
            "ma_version_tag": hex(ma_version_tag),
            "ma_keys_ptr": hex(ma_keys_ptr),
            "ma_values_ptr": hex(ma_values_ptr),
            "is_split_table": ma_values_ptr != 0,
        }

        if keys_raw and len(keys_raw) >= 32:
            # PyDictKeysObject (CPython 3.11/3.12):
            # +0x00 dk_refcnt (8B), +0x08 dk_log2_size (1B), +0x09 dk_log2_index_bytes (1B),
            # +0x0A dk_kind (1B), +0x0B pad, +0x0C dk_version (4B), +0x10 dk_usable (8B), +0x18 dk_nentries (8B)
            dk_refcnt, log2_sz, log2_idx, dk_kind, _pad, dk_ver, dk_usable, dk_nentries = struct.unpack(
                "<qBBBBIqq", keys_raw[:32]
            )
            index_bytes = 1 << min(log2_idx, 10)
            entries_offset = 32 + index_bytes
            entries: List[Dict[str, Any]] = []
            max_entries = min(max(dk_nentries, 0), 32)
            for i in range(max_entries):
                off = entries_offset + i * 24  # PyDictKeyEntry: me_hash(8B), me_key(8B), me_value(8B)
                if off + 24 > len(keys_raw):
                    break
                me_hash, me_key, me_val = struct.unpack("<qQQ", keys_raw[off:off + 24])
                entries.append({
                    "index": i,
                    "me_hash": hex(me_hash & 0xFFFFFFFFFFFFFFFF),
                    "me_key_ptr": hex(me_key),
                    "me_value_ptr": hex(me_val),
                })
            result["keys_table"] = {
                "dk_refcnt": dk_refcnt,
                "dk_table_size": 1 << min(log2_sz, 20),
                "dk_kind": dk_kind,
                "dk_usable": dk_usable,
                "dk_nentries": dk_nentries,
                "entries_parsed": entries,
            }
        return result

    @classmethod
    def inspect_live_process(
        cls,
        pid: int,
        address: int,
        object_type: str = "pyobject",
    ) -> Dict[str, Any]:
        """
        Live read-only CPython object inspection using VirtualMemoryInspector & StructureDissector.
        """
        from .virtual_memory_inspector import VirtualMemoryInspector, StructureDissector

        read_sz = 128 if object_type in ("pyascii", "pylong") else 64
        mem = VirtualMemoryInspector._read_memory_internal(pid, address, read_sz, allow_partial=True)
        if mem.get("status") != "ok" or not mem.get("data"):
            return {
                "status": "error",
                "pid": pid,
                "address": hex(address),
                "error": mem.get("error", "Unable to read target process memory."),
            }
        raw = mem["data"]
        struct_res = StructureDissector.dissect(pid, address, size=min(len(raw), 64), struct_name=object_type)

        if object_type == "pydict":
            parsed = cls.inspect_pydict_buffer(raw, base_address=address)
            keys_ptr = int(parsed.get("ma_keys_ptr", "0x0"), 16)
            if keys_ptr:
                kmem = VirtualMemoryInspector._read_memory_internal(pid, keys_ptr, 256, allow_partial=True)
                if kmem.get("status") == "ok" and kmem.get("data"):
                    parsed = cls.inspect_pydict_buffer(raw, keys_raw=kmem["data"], base_address=address)
        elif object_type == "pyascii":
            parsed = cls.inspect_pyascii_buffer(raw, base_address=address)
        elif object_type == "pylong":
            parsed = cls.inspect_pylong_buffer(raw, base_address=address)
        else:
            parsed = cls.parse_pyobject_header(raw, base_address=address)

        return {
            "status": parsed.get("status", "ok"),
            "pid": pid,
            "cpython_object": parsed,
            "structure_dissection": struct_res,
        }
