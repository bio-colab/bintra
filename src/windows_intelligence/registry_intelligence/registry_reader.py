# -*- coding: utf-8 -*-
"""
Dual-View Windows Registry Reader.
Reads registry keys under both 64-bit (KEY_WOW64_64KEY) and 32-bit (KEY_WOW64_32KEY)
perspectives to detect WOW64 redirection divergence and configuration anomalies.
"""

import os
import sys
import datetime
from typing import Dict, Any, List, Optional, Tuple

try:
    import winreg
except ImportError:
    winreg = None


class WindowsRegistryReader:
    """
    Directly queries the Windows Registry with strict dual-architecture awareness.
    Identifies discrepancies between native 64-bit views and 32-bit WOW64 views.
    """

    HIVE_MAP = {
        "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", 0x80000002) if winreg else 0x80000002,
        "HKCU": getattr(winreg, "HKEY_CURRENT_USER", 0x80000001) if winreg else 0x80000001,
        "HKCR": getattr(winreg, "HKEY_CLASSES_ROOT", 0x80000000) if winreg else 0x80000000,
        "HKU": getattr(winreg, "HKEY_USERS", 0x80000003) if winreg else 0x80000003,
        "HKCC": getattr(winreg, "HKEY_CURRENT_CONFIG", 0x80000005) if winreg else 0x80000005
    }

    HIVE_ALIASES = {
        "HKEY_LOCAL_MACHINE": "HKLM",
        "HKEY_CURRENT_USER": "HKCU",
        "HKEY_CLASSES_ROOT": "HKCR",
        "HKEY_USERS": "HKU",
        "HKEY_CURRENT_CONFIG": "HKCC"
    }

    REG_TYPE_NAMES = {
        0: "REG_NONE",
        1: "REG_SZ",
        2: "REG_EXPAND_SZ",
        3: "REG_BINARY",
        4: "REG_DWORD",
        5: "REG_DWORD_BIG_ENDIAN",
        6: "REG_LINK",
        7: "REG_MULTI_SZ",
        8: "REG_RESOURCE_LIST",
        9: "REG_FULL_RESOURCE_DESCRIPTOR",
        10: "REG_RESOURCE_REQUIREMENTS_LIST",
        11: "REG_QWORD"
    }

    @classmethod
    def normalize_hive_name(cls, hive: Optional[str]) -> Optional[str]:
        """Normalizes full hive strings (e.g. HKEY_LOCAL_MACHINE) or abbreviations to standard HKLM format."""
        if not hive:
            return None
        h = hive.strip().upper()
        if h in cls.HIVE_MAP:
            return h
        return cls.HIVE_ALIASES.get(h)

    @classmethod
    def format_reg_value(cls, val_data: Any, val_type: int) -> Dict[str, Any]:
        """Formats registry values safely for JSON output, CLI tables, and hex inspection."""
        type_name = cls.REG_TYPE_NAMES.get(val_type, f"TYPE_{val_type}")
        if isinstance(val_data, (bytes, bytearray)):
            return {
                "value": val_data.hex(" ").upper(),
                "type": type_name,
                "raw_bytes_len": len(val_data),
                "is_binary": True
            }
        elif val_type in (4, 11) and isinstance(val_data, int):  # REG_DWORD, REG_QWORD
            return {
                "value": val_data,
                "hex": f"0x{val_data:08X}" if val_type == 4 else f"0x{val_data:016X}",
                "type": type_name
            }
        return {
            "value": val_data,
            "type": type_name
        }

    @classmethod
    def enumerate_subkeys(
        cls,
        hive_handle: int,
        subkey: str,
        view_flag: int = 0,
        max_subkeys: int = 100
    ) -> List[str]:
        """Enumerates child subkey names under a given registry path in a specific view."""
        subkeys, _, _ = cls.enumerate_subkeys_with_count(hive_handle, subkey, view_flag, max_subkeys)
        return subkeys

    @classmethod
    def enumerate_subkeys_with_count(
        cls,
        hive_handle: int,
        subkey: str,
        view_flag: int = 0,
        max_subkeys: int = 100
    ) -> Tuple[List[str], int, bool]:
        """
        Enumerates child subkey names along with total count and truncation status.
        Returns: (sampled_subkeys, total_subkeys_count, is_truncated)
        """
        if not winreg:
            return [], 0, False
        access = winreg.KEY_READ | view_flag
        subkeys = []
        total_count = 0
        try:
            with winreg.OpenKey(hive_handle, subkey, 0, access) as key:
                try:
                    total_count, _, _ = winreg.QueryInfoKey(key)
                except Exception:
                    total_count = 0
                idx = 0
                while len(subkeys) < max_subkeys:
                    try:
                        child = winreg.EnumKey(key, idx)
                        subkeys.append(child)
                        idx += 1
                    except OSError:
                        break
                if total_count == 0:
                    total_count = len(subkeys)
        except Exception:
            pass
        is_truncated = total_count > len(subkeys)
        return subkeys, total_count, is_truncated

    @classmethod
    def _read_single_view(
        cls,
        hive_handle: int,
        subkey: str,
        view_flag: int,
        target_values: Optional[Tuple[str, ...]] = None,
        include_subkeys: bool = False,
        max_subkeys: int = 50
    ) -> Dict[str, Any]:
        """Reads values from a key using an explicit architecture view flag."""
        if not winreg:
            return {"exists": False, "error": "winreg module unavailable on non-Windows"}

        access = winreg.KEY_READ | view_flag
        try:
            with winreg.OpenKey(hive_handle, subkey, 0, access) as key:
                last_modified_utc = None
                try:
                    _, _, last_mod_ft = winreg.QueryInfoKey(key)
                    if last_mod_ft > 0:
                        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=last_mod_ft // 10)
                        last_modified_utc = dt.isoformat()
                except Exception:
                    pass

                values = {}
                if target_values and len(target_values) > 0:
                    for val_name in target_values:
                        try:
                            val_data, val_type = winreg.QueryValueEx(key, val_name)
                            values[val_name] = cls.format_reg_value(val_data, val_type)
                        except FileNotFoundError:
                            pass
                else:
                    # Enumerate all values in the key
                    idx = 0
                    while True:
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, idx)
                            idx += 1
                            values[val_name or "(Default)"] = cls.format_reg_value(val_data, val_type)
                        except OSError:
                            break

                result: Dict[str, Any] = {
                    "exists": True,
                    "last_modified_utc": last_modified_utc,
                    "values_count": len(values),
                    "values": values
                }

                if include_subkeys:
                    subkeys, total_count, is_truncated = cls.enumerate_subkeys_with_count(
                        hive_handle, subkey, view_flag, max_subkeys=max_subkeys
                    )
                    result["subkeys_count"] = len(subkeys)
                    result["total_subkeys"] = total_count
                    result["is_truncated"] = is_truncated
                    result["subkeys"] = subkeys

                    # Deep sample child values if target_values was specified
                    if target_values and len(target_values) > 0 and subkeys:
                        child_samples = {}
                        for child in subkeys[:20]:
                            child_path = f"{subkey}\\{child}"
                            c_res = cls._read_single_view(
                                hive_handle, child_path, view_flag,
                                target_values=target_values, include_subkeys=False
                            )
                            if c_res.get("exists") and c_res.get("values"):
                                child_samples[child] = c_res.get("values")
                        if child_samples:
                            result["child_values"] = child_samples

                return result
        except FileNotFoundError:
            return {"exists": False}
        except PermissionError:
            return {"exists": True, "access_denied": True, "error": "AccessDenied"}
        except Exception as e:
            return {"exists": False, "error": str(e)}

    @classmethod
    def query_key_dual_view(
        cls,
        hive: str,
        subkey: str,
        target_values: Optional[Tuple[str, ...]] = None,
        include_subkeys: bool = False,
        max_subkeys: int = 50
    ) -> Dict[str, Any]:
        """
        Queries a registry key under both 64-bit and 32-bit perspectives,
        detecting WOW64 redirection and value discrepancies.
        """
        norm_hive = cls.normalize_hive_name(hive)
        if not norm_hive:
            return {
                "status": "error",
                "error": f"Unknown hive identifier '{hive}'. Supported: {list(cls.HIVE_MAP.keys())}"
            }
        hive_upper = norm_hive
        hive_handle = cls.HIVE_MAP.get(hive_upper)
        if not hive_handle:
            return {
                "status": "error",
                "error": f"Unknown hive identifier '{hive}'. Supported: {list(cls.HIVE_MAP.keys())}"
            }

        flag_64 = getattr(winreg, "KEY_WOW64_64KEY", 0x0100) if winreg else 0x0100
        flag_32 = getattr(winreg, "KEY_WOW64_32KEY", 0x0200) if winreg else 0x0200

        res_64 = cls._read_single_view(hive_handle, subkey, flag_64, target_values, include_subkeys=include_subkeys, max_subkeys=max_subkeys)
        res_32 = cls._read_single_view(hive_handle, subkey, flag_32, target_values, include_subkeys=include_subkeys, max_subkeys=max_subkeys)

        # Detect discrepancies between views
        has_discrepancy = False
        discrepancy_details = []

        if res_64.get("exists") != res_32.get("exists"):
            has_discrepancy = True
            discrepancy_details.append(
                f"Key exists in 64-bit view ({res_64.get('exists')}) but differs in 32-bit view ({res_32.get('exists')})"
            )
        elif res_64.get("exists") and res_32.get("exists"):
            vals_64 = res_64.get("values", {})
            vals_32 = res_32.get("values", {})
            all_keys = set(vals_64.keys()) | set(vals_32.keys())
            for k in all_keys:
                v64 = vals_64.get(k, {}).get("value")
                v32 = vals_32.get(k, {}).get("value")
                if v64 != v32:
                    has_discrepancy = True
                    discrepancy_details.append(f"Value '{k}' differs: 64-bit='{v64}' vs 32-bit='{v32}'")

            if include_subkeys:
                sub_64 = set(res_64.get("subkeys", []))
                sub_32 = set(res_32.get("subkeys", []))
                if sub_64 != sub_32:
                    has_discrepancy = True
                    diff_cnt = abs(len(sub_64) - len(sub_32))
                    discrepancy_details.append(f"Child subkey count differs: 64-bit={len(sub_64)} vs 32-bit={len(sub_32)} (diff={diff_cnt})")

        return {
            "status": "success",
            "hive": hive_upper,
            "subkey": subkey,
            "view_64": res_64,
            "view_32": res_32,
            "has_discrepancy": has_discrepancy,
            "discrepancy_count": len(discrepancy_details),
            "discrepancies": discrepancy_details
        }

    @classmethod
    def read_key(
        cls,
        hive: str,
        subkey: str,
        view: str = "dual",
        target_values: Optional[Tuple[str, ...]] = None,
        include_subkeys: bool = True,
        max_subkeys: int = 100
    ) -> Dict[str, Any]:
        """
        Reads a Windows registry key with flexible architecture view selection.
        view options:
          - 'dual' (default): queries both 64-bit and 32-bit views and highlights discrepancies.
          - '64' or 'x64': queries native 64-bit view (KEY_WOW64_64KEY).
          - '32' or 'x86': queries WOW64 32-bit redirected view (KEY_WOW64_32KEY).
          - 'native': queries without explicit WOW64 flags.
        """
        if not winreg or os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Windows Registry inspection requires Windows NT.",
                "hive": hive,
                "subkey": subkey
            }

        norm_hive = cls.normalize_hive_name(hive)
        if not norm_hive:
            return {
                "status": "error",
                "error": f"Unknown hive identifier '{hive}'. Supported: {list(cls.HIVE_MAP.keys())}"
            }

        if view == "dual":
            return cls.query_key_dual_view(
                hive=norm_hive,
                subkey=subkey,
                target_values=target_values,
                include_subkeys=include_subkeys,
                max_subkeys=max_subkeys
            )

        hive_handle = cls.HIVE_MAP.get(norm_hive)
        flag = 0
        if str(view).lower() in ("64", "x64", "win64"):
            flag = getattr(winreg, "KEY_WOW64_64KEY", 0x0100)
        elif str(view).lower() in ("32", "x86", "win32"):
            flag = getattr(winreg, "KEY_WOW64_32KEY", 0x0200)

        single_res = cls._read_single_view(
            hive_handle=hive_handle,
            subkey=subkey,
            view_flag=flag,
            target_values=target_values,
            include_subkeys=include_subkeys,
            max_subkeys=max_subkeys
        )

        return {
            "status": "success",
            "hive": norm_hive,
            "subkey": subkey,
            "view": view,
            "result": single_res
        }
