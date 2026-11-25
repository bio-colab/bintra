# -*- coding: utf-8 -*-
"""
Windows Registry Editor (regedit.exe) Integration Subsystem.
Provides comprehensive registry interaction:
1. Deep Registry Key Reading & Valuation (all 5 hives: HKLM, HKCU, HKCR, HKU, HKCC).
2. Multi-Mode Registry Search (Keys, Value Names, and Value Data) with depth & timeout guards.
3. Industry-Standard .reg File Parser (Windows Registry Editor Version 5.00 AST generation).
4. Live Registry Export to .reg file format (compatible with regedit.exe).
5. Registry Drift & Policy Verification Engine (.reg expected vs. live Windows registry diff).

Zero external dependencies: uses Python standard library and winreg.
Degrades gracefully on non-Windows NT environments.
"""

import os
import sys
import re
import struct
import time
from typing import Dict, Any, List, Optional

try:
    import winreg
except ImportError:
    winreg = None

try:
    from security import SafeFileAccess
except ImportError:
    SafeFileAccess = None

from .registry_reader import WindowsRegistryReader


class WindowsRegistryEditor:
    """
    High-level Windows Registry Editor abstraction.
    Mirrors and extends regedit.exe capabilities with automated search,
    .reg file parsing, programmatic export, and live drift auditing.
    """

    HIVE_FULL_MAP = {
        "HKEY_LOCAL_MACHINE": getattr(winreg, "HKEY_LOCAL_MACHINE", 0x80000002) if winreg else 0x80000002,
        "HKEY_CURRENT_USER": getattr(winreg, "HKEY_CURRENT_USER", 0x80000001) if winreg else 0x80000001,
        "HKEY_CLASSES_ROOT": getattr(winreg, "HKEY_CLASSES_ROOT", 0x80000000) if winreg else 0x80000000,
        "HKEY_USERS": getattr(winreg, "HKEY_USERS", 0x80000003) if winreg else 0x80000003,
        "HKEY_CURRENT_CONFIG": getattr(winreg, "HKEY_CURRENT_CONFIG", 0x80000005) if winreg else 0x80000005,
        "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", 0x80000002) if winreg else 0x80000002,
        "HKCU": getattr(winreg, "HKEY_CURRENT_USER", 0x80000001) if winreg else 0x80000001,
        "HKCR": getattr(winreg, "HKEY_CLASSES_ROOT", 0x80000000) if winreg else 0x80000000,
        "HKU": getattr(winreg, "HKEY_USERS", 0x80000003) if winreg else 0x80000003,
        "HKCC": getattr(winreg, "HKEY_CURRENT_CONFIG", 0x80000005) if winreg else 0x80000005,
    }

    CANONICAL_HIVE_NAME = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
        "HKCU": "HKEY_CURRENT_USER",
        "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS",
        "HKEY_USERS": "HKEY_USERS",
        "HKCC": "HKEY_CURRENT_CONFIG",
        "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
    }

    SHORT_HIVE_NAME = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKLM": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKCU": "HKCU",
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKCR": "HKCR",
        "HKEY_USERS": "HKU",
        "HKU": "HKU",
        "HKEY_CURRENT_CONFIG": "HKCC",
        "HKCC": "HKCC",
    }

    @classmethod
    def _is_windows(cls) -> bool:
        return os.name == "nt" and winreg is not None

    @classmethod
    def normalize_hive(cls, hive: Optional[str], canonical: bool = False) -> Optional[str]:
        """Normalizes hive string to standard format (HKLM or HKEY_LOCAL_MACHINE)."""
        if not hive:
            return None
        h = hive.strip().upper()
        if canonical:
            return cls.CANONICAL_HIVE_NAME.get(h)
        return cls.SHORT_HIVE_NAME.get(h)

    @classmethod
    def _get_view_flag(cls, view: str) -> int:
        v = str(view).lower()
        if v in ("64", "x64", "win64"):
            return getattr(winreg, "KEY_WOW64_64KEY", 0x0100) if winreg else 0x0100
        elif v in ("32", "x86", "win32"):
            return getattr(winreg, "KEY_WOW64_32KEY", 0x0200) if winreg else 0x0200
        return 0

    @classmethod
    def read_key(
        cls,
        hive: str,
        subkey: str,
        view: str = "dual",
        include_subkeys: bool = True,
        max_subkeys: int = 100
    ) -> Dict[str, Any]:
        """
        Reads a registry key with all values and subkeys using WindowsRegistryReader.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Windows Registry inspection requires Windows NT.",
                "hive": hive,
                "subkey": subkey
            }
        return WindowsRegistryReader.read_key(
            hive=hive,
            subkey=subkey,
            view=view,
            include_subkeys=include_subkeys,
            max_subkeys=max_subkeys
        )

    @classmethod
    def search(
        cls,
        query: str,
        hive: str = "HKLM",
        root_key: str = "",
        search_keys: bool = True,
        search_values: bool = True,
        search_data: bool = True,
        match_case: bool = False,
        match_whole_string: bool = False,
        max_depth: int = 3,
        limit: int = 50,
        view: str = "64",
        timeout_seconds: float = 10.0
    ) -> Dict[str, Any]:
        """
        Conducts a deep, multi-target search across registry keys, value names, and value data.
        Equivalent to regedit.exe Find (Ctrl+F) with safety limits against runaway traversals.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Windows Registry search requires Windows NT.",
                "query": query,
                "matched_count": 0,
                "matches": []
            }

        norm_short = cls.normalize_hive(hive, canonical=False)
        norm_canon = cls.normalize_hive(hive, canonical=True)
        if not norm_short:
            return {"status": "error", "error": f"Unknown hive identifier '{hive}'."}

        hive_handle = cls.HIVE_FULL_MAP.get(norm_short)
        view_flag = cls._get_view_flag(view)
        access_mask = winreg.KEY_READ | view_flag

        target_q = query if match_case else query.lower()
        if not target_q:
            return {"status": "error", "error": "Search query cannot be empty."}

        matches: List[Dict[str, Any]] = []
        start_time = time.time()
        keys_scanned = 0
        values_scanned = 0

        def _is_match(candidate: Any) -> bool:
            if candidate is None:
                return False
            cand_str = str(candidate)
            cmp_cand = cand_str if match_case else cand_str.lower()
            if match_whole_string:
                return cmp_cand == target_q
            return target_q in cmp_cand

        def _traverse(current_path: str, depth: int):
            nonlocal keys_scanned, values_scanned
            if len(matches) >= limit or (time.time() - start_time) > timeout_seconds:
                return

            keys_scanned += 1
            try:
                with winreg.OpenKey(hive_handle, current_path, 0, access_mask) as key:
                    num_subkeys, num_values, last_mod_ft = winreg.QueryInfoKey(key)

                    # 1. Check Key Name match
                    if search_keys and current_path:
                        leaf_name = current_path.split("\\")[-1]
                        if _is_match(leaf_name):
                            matches.append({
                                "match_type": "key_name",
                                "hive": norm_short,
                                "canonical_path": f"{norm_canon}\\{current_path}",
                                "key_path": current_path,
                                "name": leaf_name,
                                "matched_value": leaf_name,
                                "preview": f"Key [{norm_canon}\\{current_path}]"
                            })
                            if len(matches) >= limit:
                                return

                    # 2. Inspect Values in current key
                    if search_values or search_data:
                        for v_idx in range(num_values):
                            if len(matches) >= limit or (time.time() - start_time) > timeout_seconds:
                                return
                            values_scanned += 1
                            try:
                                v_name, v_data, v_type = winreg.EnumValue(key, v_idx)
                                val_label = v_name or "(Default)"
                                type_name = WindowsRegistryReader.REG_TYPE_NAMES.get(v_type, f"TYPE_{v_type}")

                                # Match value name
                                if search_values and _is_match(val_label):
                                    matches.append({
                                        "match_type": "value_name",
                                        "hive": norm_short,
                                        "canonical_path": f"{norm_canon}\\{current_path}",
                                        "key_path": current_path,
                                        "value_name": val_label,
                                        "value_type": type_name,
                                        "value_data": str(v_data),
                                        "preview": f"Value name '{val_label}' in [{norm_canon}\\{current_path}]"
                                    })
                                    if len(matches) >= limit:
                                        return

                                # Match value data
                                if search_data:
                                    data_matched = False
                                    match_str = ""
                                    if isinstance(v_data, (bytes, bytearray)):
                                        hex_str = v_data.hex(" ").upper()
                                        if _is_match(hex_str):
                                            data_matched = True
                                            match_str = hex_str[:60] + "..." if len(hex_str) > 60 else hex_str
                                    elif isinstance(v_data, list):  # REG_MULTI_SZ
                                        for elem in v_data:
                                            if _is_match(elem):
                                                data_matched = True
                                                match_str = elem
                                                break
                                    elif _is_match(v_data):
                                        data_matched = True
                                        match_str = str(v_data)

                                    if data_matched:
                                        matches.append({
                                            "match_type": "value_data",
                                            "hive": norm_short,
                                            "canonical_path": f"{norm_canon}\\{current_path}",
                                            "key_path": current_path,
                                            "value_name": val_label,
                                            "value_type": type_name,
                                            "value_data": str(v_data),
                                            "preview": f"Data in '{val_label}' = '{match_str}'"
                                        })
                                        if len(matches) >= limit:
                                            return
                            except (OSError, PermissionError):
                                pass

                    # 3. Recurse into child subkeys
                    if depth < max_depth:
                        for s_idx in range(num_subkeys):
                            if len(matches) >= limit or (time.time() - start_time) > timeout_seconds:
                                return
                            try:
                                child_name = winreg.EnumKey(key, s_idx)
                                child_path = f"{current_path}\\{child_name}" if current_path else child_name
                                _traverse(child_path, depth + 1)
                            except (OSError, PermissionError):
                                pass

            except (FileNotFoundError, PermissionError, OSError):
                pass

        _traverse(root_key, 0)
        elapsed = time.time() - start_time

        return {
            "status": "success",
            "platform": sys.platform,
            "query": query,
            "hive": norm_short,
            "root_key": root_key or "\\",
            "matched_count": len(matches),
            "keys_scanned": keys_scanned,
            "values_scanned": values_scanned,
            "elapsed_seconds": round(elapsed, 4),
            "timed_out": elapsed >= timeout_seconds,
            "limit": limit,
            "matches": matches
        }

    @classmethod
    def parse_reg_file(cls, reg_content_or_path: str) -> Dict[str, Any]:
        """
        Parses Windows Registry Editor Version 5.00 format text into a structured AST.
        Supports UTF-16LE with BOM, UTF-8, ANSI, multi-line values, hex(2), hex(7), hex(b), and dwords.
        """
        content = ""
        is_file = False
        source_path = None

        # Check if argument is a readable file path
        if len(reg_content_or_path) < 1024:
            try:
                if os.path.isfile(reg_content_or_path):
                    is_file = True
                    source_path = os.path.abspath(reg_content_or_path)
                    if SafeFileAccess:
                        raw_bytes = SafeFileAccess.read_bytes(source_path)
                    else:
                        with open(source_path, "rb") as f:
                            raw_bytes = f.read()
                    # Decode BOM or encoding
                    if raw_bytes.startswith(b"\xff\xfe"):
                        content = raw_bytes.decode("utf-16le", errors="replace")
                    elif raw_bytes.startswith(b"\xef\xbb\xbf"):
                        content = raw_bytes.decode("utf-8-sig", errors="replace")
                    else:
                        try:
                            content = raw_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            content = raw_bytes.decode("latin1", errors="replace")
            except Exception as exc:
                from security import SecurityViolationError
                if isinstance(exc, SecurityViolationError):
                    raise
                pass

        if not content:
            content = reg_content_or_path

        lines = content.splitlines()
        if not lines:
            return {"status": "error", "error": "Empty registry file or content."}

        # Check header
        header = lines[0].strip()
        format_version = "5.00" if "Version 5.00" in header else ("4.0" if "REGEDIT4" in header else "Unknown")

        # Pre-process multi-line continuations (lines ending with \) using O(N) list builder
        merged_lines: List[str] = []
        buffer_parts: List[str] = []
        for raw_l in lines[1:]:
            l = raw_l.strip()
            if not l or l.startswith(";") or l.startswith("#"):
                continue  # skip comments and blank lines

            if l.endswith("\\"):
                buffer_parts.append(l[:-1].strip())
            else:
                buffer_parts.append(l)
                merged_lines.append("".join(buffer_parts))
                buffer_parts = []
        if buffer_parts:
            merged_lines.append("".join(buffer_parts))

        # Parse sections and key values
        parsed_keys: Dict[str, Dict[str, Any]] = {}
        current_key: Optional[str] = None
        total_values = 0

        for line in merged_lines:
            # Check key section header e.g. [HKEY_LOCAL_MACHINE\SOFTWARE\...]
            if line.startswith("[") and line.endswith("]"):
                inner = line[1:-1].strip()
                is_deletion = inner.startswith("-")
                key_path = inner[1:] if is_deletion else inner
                current_key = key_path
                parsed_keys[current_key] = {
                    "is_deletion": is_deletion,
                    "values": {}
                }
                continue

            if not current_key:
                continue

            # Parse value assignment: "Name"=Type:Value or @="Default"
            val_match = re.match(r'^("(?:[^"\\]|\\.)*"|@)\s*=\s*(.*)$', line)
            if not val_match:
                continue

            raw_name, raw_val = val_match.groups()
            total_values += 1

            # Determine value name
            if raw_name == "@":
                val_name = "(Default)"
            else:
                val_name = raw_name[1:-1].replace('\\"', '"').replace('\\\\', '\\')

            parsed_val = cls._decode_reg_value_literal(raw_val)
            parsed_keys[current_key]["values"][val_name] = parsed_val

        return {
            "status": "success",
            "format_version": format_version,
            "is_file": is_file,
            "source_path": source_path,
            "keys_count": len(parsed_keys),
            "values_count": total_values,
            "keys": parsed_keys
        }

    @classmethod
    def _decode_reg_value_literal(cls, raw_val: str) -> Dict[str, Any]:
        """Decodes raw reg file literals into typed Python values."""
        val_str = raw_val.strip()

        # 1. Deletion marker: "Value"=-
        if val_str == "-":
            return {"type": "DELETE", "value": None}

        # 2. String: "Hello \"World\""
        if val_str.startswith('"') and val_str.endswith('"'):
            inner = val_str[1:-1].replace('\\"', '"').replace('\\\\', '\\')
            return {"type": "REG_SZ", "value": inner}

        # 3. DWORD: dword:00000001
        if val_str.lower().startswith("dword:"):
            hex_part = val_str[6:].strip()
            try:
                int_val = int(hex_part, 16)
                return {"type": "REG_DWORD", "value": int_val, "hex": f"0x{int_val:08X}"}
            except ValueError:
                return {"type": "REG_DWORD", "value": 0, "raw": hex_part}

        # 4. QWORD: hex(b):01,00,00,00,00,00,00,00
        if val_str.lower().startswith("hex(b):"):
            hex_bytes = val_str[7:].replace(",", "").strip()
            try:
                b = bytes.fromhex(hex_bytes)
                if len(b) == 8:
                    q_val = struct.unpack("<Q", b)[0]
                    return {"type": "REG_QWORD", "value": q_val, "hex": f"0x{q_val:016X}"}
            except Exception:
                pass
            return {"type": "REG_QWORD", "value": hex_bytes, "raw": True}

        # 5. EXPAND_SZ: hex(2):25,00,53,00,... (UTF-16LE string)
        if val_str.lower().startswith("hex(2):"):
            hex_bytes = val_str[7:].replace(",", "").strip()
            try:
                b = bytes.fromhex(hex_bytes)
                decoded = b.decode("utf-16le", errors="replace").rstrip("\x00")
                return {"type": "REG_EXPAND_SZ", "value": decoded}
            except Exception:
                return {"type": "REG_EXPAND_SZ", "value": hex_bytes, "raw": True}

        # 6. MULTI_SZ: hex(7):61,00,00,00,62,00,00,00,00,00
        if val_str.lower().startswith("hex(7):"):
            hex_bytes = val_str[7:].replace(",", "").strip()
            try:
                b = bytes.fromhex(hex_bytes)
                parts = b.decode("utf-16le", errors="replace").split("\x00")
                clean_parts = [p for p in parts if p]
                return {"type": "REG_MULTI_SZ", "value": clean_parts}
            except Exception:
                return {"type": "REG_MULTI_SZ", "value": hex_bytes, "raw": True}

        # 7. BINARY: hex:01,02,03...
        if val_str.lower().startswith("hex:"):
            hex_bytes = val_str[4:].replace(",", " ").upper().strip()
            clean_hex = hex_bytes.replace(" ", "")
            return {
                "type": "REG_BINARY",
                "value": hex_bytes,
                "length": len(clean_hex) // 2
            }

        return {"type": "UNKNOWN", "value": val_str}

    @classmethod
    def export_key(
        cls,
        hive: str,
        subkey: str,
        output_path: Optional[str] = None,
        recursive: bool = False,
        max_depth: int = 1,
        view: str = "64"
    ) -> Dict[str, Any]:
        """
        Exports a live Windows registry key to official Windows Registry Editor Version 5.00 syntax.
        Can write to a valid .reg file or return as text string.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Registry export requires Windows NT.",
            }

        norm_short = cls.normalize_hive(hive, canonical=False)
        norm_canon = cls.normalize_hive(hive, canonical=True)
        if not norm_short:
            return {"status": "error", "error": f"Unknown hive identifier '{hive}'."}

        hive_handle = cls.HIVE_FULL_MAP.get(norm_short)
        view_flag = cls._get_view_flag(view)
        access = winreg.KEY_READ | view_flag

        exported_lines = [
            "Windows Registry Editor Version 5.00",
            ""
        ]

        keys_exported = 0
        values_exported = 0

        def _format_value_for_export(v_name: str, v_data: Any, v_type: int) -> str:
            name_label = "@" if not v_name or v_name == "(Default)" else f'"{v_name.replace(chr(92), chr(92)+chr(92)).replace(chr(34), chr(92)+chr(34))}"'

            if v_type == 1:  # REG_SZ
                escaped = str(v_data).replace("\\", "\\\\").replace('"', '\\"')
                return f'{name_label}="{escaped}"'
            elif v_type == 4 and isinstance(v_data, int):  # REG_DWORD
                return f'{name_label}=dword:{v_data:08x}'
            elif v_type == 2:  # REG_EXPAND_SZ
                utf16 = str(v_data).encode("utf-16le") + b"\x00\x00"
                hex_seq = ",".join(f"{b:02x}" for b in utf16)
                return f"{name_label}=hex(2):{hex_seq}"
            elif v_type == 7 and isinstance(v_data, list):  # REG_MULTI_SZ
                joined = b"".join(str(s).encode("utf-16le") + b"\x00\x00" for s in v_data) + b"\x00\x00"
                hex_seq = ",".join(f"{b:02x}" for b in joined)
                return f"{name_label}=hex(7):{hex_seq}"
            elif v_type == 11 and isinstance(v_data, int):  # REG_QWORD
                packed = struct.pack("<Q", v_data)
                hex_seq = ",".join(f"{b:02x}" for b in packed)
                return f"{name_label}=hex(b):{hex_seq}"
            elif v_type == 3:  # REG_BINARY
                b = v_data if isinstance(v_data, (bytes, bytearray)) else bytes.fromhex(str(v_data).replace(" ", ""))
                hex_seq = ",".join(f"{byte:02x}" for byte in b)
                return f"{name_label}=hex:{hex_seq}"
            else:
                return f'; Unknown type {v_type} for {name_label}'

        def _export_node(curr_subkey: str, depth: int):
            nonlocal keys_exported, values_exported
            try:
                with winreg.OpenKey(hive_handle, curr_subkey, 0, access) as key:
                    keys_exported += 1
                    section_header = f"[{norm_canon}\\{curr_subkey}]" if curr_subkey else f"[{norm_canon}]"
                    exported_lines.append(section_header)

                    num_subkeys, num_vals, _ = winreg.QueryInfoKey(key)
                    for v_idx in range(num_vals):
                        try:
                            vn, vd, vt = winreg.EnumValue(key, v_idx)
                            val_line = _format_value_for_export(vn, vd, vt)
                            exported_lines.append(val_line)
                            values_exported += 1
                        except Exception:
                            pass
                    exported_lines.append("")

                    if recursive and depth < max_depth:
                        for s_idx in range(min(num_subkeys, 100)):
                            try:
                                child = winreg.EnumKey(key, s_idx)
                                child_path = f"{curr_subkey}\\{child}" if curr_subkey else child
                                _export_node(child_path, depth + 1)
                            except Exception:
                                pass
            except Exception:
                pass

        _export_node(subkey, 0)
        full_text = "\n".join(exported_lines)

        if output_path:
            if SafeFileAccess:
                out_file = SafeFileAccess.write_workspace_file(output_path, full_text)
            else:
                out_file = os.path.abspath(output_path)
                os.makedirs(os.path.dirname(out_file), exist_ok=True)
                with open(out_file, "w", encoding="utf-8-sig") as f:
                    f.write(full_text)

        return {
            "status": "success",
            "hive": norm_short,
            "subkey": subkey,
            "output_path": output_path,
            "keys_exported": keys_exported,
            "values_exported": values_exported,
            "reg_content": full_text
        }

    @classmethod
    def diff_reg_file(cls, reg_content_or_path: str, view: str = "64") -> Dict[str, Any]:
        """
        Audits a .reg file against the live Windows registry.
        Detects drift, missing keys, and modified policy values.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Registry diff requires Windows NT.",
            }

        ast = cls.parse_reg_file(reg_content_or_path)
        if ast.get("status") != "success":
            return ast

        keys_dict = ast.get("keys", {})
        view_flag = cls._get_view_flag(view)
        access = winreg.KEY_READ | view_flag

        diff_results: List[Dict[str, Any]] = []
        matched_count = 0
        drifted_count = 0
        missing_count = 0

        for full_key, k_data in keys_dict.items():
            # Split hive and subkey: e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft
            parts = full_key.split("\\", 1)
            raw_hive = parts[0]
            subkey_path = parts[1] if len(parts) > 1 else ""

            norm_hive = cls.normalize_hive(raw_hive)
            hive_handle = cls.HIVE_FULL_MAP.get(norm_hive)

            is_key_deletion = bool(k_data.get("is_deletion", False))

            if not hive_handle:
                diff_results.append({
                    "full_key": full_key,
                    "status": "unsupported_hive",
                    "error": f"Cannot audit hive '{raw_hive}'"
                })
                missing_count += 1
                continue

            # Case A: Key Deletion specified [-HKEY_...]
            if is_key_deletion:
                try:
                    with winreg.OpenKey(hive_handle, subkey_path, 0, access) as key:
                        drifted_count += 1
                        diff_results.append({
                            "full_key": full_key,
                            "status": "drifted",
                            "type": "KEY_DELETION",
                            "expected": "KEY_ABSENT",
                            "actual": "KEY_PRESENT",
                            "detail": "Registry key exists in live registry but .reg specified deletion"
                        })
                except FileNotFoundError:
                    matched_count += 1
                    diff_results.append({
                        "full_key": full_key,
                        "status": "matched",
                        "type": "KEY_DELETION",
                        "expected": "KEY_ABSENT",
                        "actual": "KEY_ABSENT",
                        "detail": "Registry key is absent from live registry as specified"
                    })
                except Exception as e:
                    drifted_count += 1
                    diff_results.append({
                        "full_key": full_key,
                        "status": "error",
                        "error": str(e)
                    })
                continue

            # Case B: Standard Key
            try:
                with winreg.OpenKey(hive_handle, subkey_path, 0, access) as key:
                    values_in_file = k_data.get("values", {})
                    for v_name, v_spec in values_in_file.items():
                        exp_val = v_spec.get("value")
                        exp_type = v_spec.get("type")
                        query_name = "" if v_name == "(Default)" else v_name

                        # Subcase B1: Value Deletion specified "Val"=-
                        if exp_type == "DELETE":
                            try:
                                live_val, live_type_int = winreg.QueryValueEx(key, query_name)
                                drifted_count += 1
                                diff_results.append({
                                    "full_key": full_key,
                                    "value_name": v_name,
                                    "status": "drifted",
                                    "type": "VALUE_DELETION",
                                    "expected": "VALUE_ABSENT",
                                    "actual": str(live_val),
                                    "detail": f"Value '{v_name}' exists in live registry but .reg specified deletion"
                                })
                            except FileNotFoundError:
                                matched_count += 1
                                diff_results.append({
                                    "full_key": full_key,
                                    "value_name": v_name,
                                    "status": "matched",
                                    "type": "VALUE_DELETION",
                                    "expected": "VALUE_ABSENT",
                                    "actual": "VALUE_ABSENT",
                                    "detail": f"Value '{v_name}' is absent from live registry as specified"
                                })
                            continue

                        # Subcase B2: Normal Value check
                        try:
                            live_val, live_type_int = winreg.QueryValueEx(key, query_name)
                            live_type_str = WindowsRegistryReader.REG_TYPE_NAMES.get(live_type_int, f"TYPE_{live_type_int}")

                            # Normalize live_val for comparison
                            if isinstance(live_val, (bytes, bytearray)):
                                live_cmp = live_val.hex(" ").upper()
                            else:
                                live_cmp = live_val

                            # Compare
                            is_match = False
                            if exp_type == "REG_BINARY":
                                is_match = str(exp_val).replace(" ", "").upper() == str(live_cmp).replace(" ", "").upper()
                            else:
                                is_match = (str(exp_val) == str(live_cmp))

                            if is_match:
                                matched_count += 1
                                diff_results.append({
                                    "full_key": full_key,
                                    "value_name": v_name,
                                    "status": "matched",
                                    "type": exp_type,
                                    "expected_value": exp_val,
                                    "actual_value": live_cmp
                                })
                            else:
                                drifted_count += 1
                                diff_results.append({
                                    "full_key": full_key,
                                    "value_name": v_name,
                                    "status": "drifted",
                                    "expected_type": exp_type,
                                    "actual_type": live_type_str,
                                    "expected_value": exp_val,
                                    "actual_value": live_cmp
                                })

                        except FileNotFoundError:
                            missing_count += 1
                            diff_results.append({
                                "full_key": full_key,
                                "value_name": v_name,
                                "status": "missing_value",
                                "expected_type": exp_type,
                                "expected_value": exp_val
                            })
            except FileNotFoundError:
                missing_count += 1
                diff_results.append({
                    "full_key": full_key,
                    "status": "missing_key",
                    "error": "Key does not exist on live Windows system"
                })

        total_checked = matched_count + drifted_count + missing_count
        score = (matched_count / total_checked * 100.0) if total_checked > 0 else 100.0

        return {
            "status": "success",
            "platform": sys.platform,
            "format_version": ast.get("format_version"),
            "source_path": ast.get("source_path"),
            "total_items_checked": total_checked,
            "matched_count": matched_count,
            "drifted_count": drifted_count,
            "missing_count": missing_count,
            "compliance_percentage": round(score, 2),
            "diff_items": diff_results
        }
