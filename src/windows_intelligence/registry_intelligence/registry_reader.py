# -*- coding: utf-8 -*-
"""
Dual-View Windows Registry Reader.
Reads registry keys under both 64-bit (KEY_WOW64_64KEY) and 32-bit (KEY_WOW64_32KEY)
perspectives to detect WOW64 redirection divergence and configuration anomalies.
"""

import os
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

    REG_TYPE_NAMES = {
        1: "REG_SZ",
        2: "REG_EXPAND_SZ",
        3: "REG_BINARY",
        4: "REG_DWORD",
        7: "REG_MULTI_SZ",
        11: "REG_QWORD"
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
        if not winreg:
            return []
        access = winreg.KEY_READ | view_flag
        subkeys = []
        try:
            with winreg.OpenKey(hive_handle, subkey, 0, access) as key:
                idx = 0
                while len(subkeys) < max_subkeys:
                    try:
                        child = winreg.EnumKey(key, idx)
                        subkeys.append(child)
                        idx += 1
                    except OSError:
                        break
        except Exception:
            pass
        return subkeys

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
                values = {}
                if target_values and len(target_values) > 0:
                    for val_name in target_values:
                        try:
                            val_data, val_type = winreg.QueryValueEx(key, val_name)
                            values[val_name] = {
                                "value": val_data,
                                "type": cls.REG_TYPE_NAMES.get(val_type, f"TYPE_{val_type}")
                            }
                        except FileNotFoundError:
                            pass
                else:
                    # Enumerate all values in the key
                    idx = 0
                    while True:
                        try:
                            val_name, val_data, val_type = winreg.EnumValue(key, idx)
                            idx += 1
                            values[val_name or "(Default)"] = {
                                "value": val_data,
                                "type": cls.REG_TYPE_NAMES.get(val_type, f"TYPE_{val_type}")
                            }
                        except OSError:
                            break

                result: Dict[str, Any] = {
                    "exists": True,
                    "values_count": len(values),
                    "values": values
                }

                if include_subkeys:
                    subkeys = cls.enumerate_subkeys(hive_handle, subkey, view_flag, max_subkeys=max_subkeys)
                    result["subkeys_count"] = len(subkeys)
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
            return {"exists": True, "error": "AccessDenied"}
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
        hive_upper = hive.upper()
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
