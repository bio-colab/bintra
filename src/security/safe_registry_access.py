# -*- coding: utf-8 -*-
"""
REA-Neural Safe Registry Access Gateway.
Guarantees strictly read-only Registry inspection (KEY_READ | KEY_WOW64_64KEY).
Forbids KEY_WRITE, KEY_ALL_ACCESS, and registry mutation APIs.
"""

import sys
from typing import Dict, Any, List, Optional, Tuple

if sys.platform == "win32":
    import winreg
else:
    winreg = None

from .execution_guard import ExecutionGuard
from .capability_registry import Capability


class SafeRegistryAccess:
    """
    Authorized read-only Registry query gateway mediated by ExecutionGuard.
    """

    HIVE_MAP = {
        "HKLM": getattr(winreg, "HKEY_LOCAL_MACHINE", 0x80000002) if winreg else 0x80000002,
        "HKEY_LOCAL_MACHINE": getattr(winreg, "HKEY_LOCAL_MACHINE", 0x80000002) if winreg else 0x80000002,
        "HKCU": getattr(winreg, "HKEY_CURRENT_USER", 0x80000001) if winreg else 0x80000001,
        "HKEY_CURRENT_USER": getattr(winreg, "HKEY_CURRENT_USER", 0x80000001) if winreg else 0x80000001,
        "HKCR": getattr(winreg, "HKEY_CLASSES_ROOT", 0x80000000) if winreg else 0x80000000,
        "HKEY_CLASSES_ROOT": getattr(winreg, "HKEY_CLASSES_ROOT", 0x80000000) if winreg else 0x80000000,
    }

    @classmethod
    def query_value(cls, root: str, subkey: str, value_name: str) -> Dict[str, Any]:
        """
        Reads a single registry value safely with KEY_READ rights.
        """
        target_repr = f"{root}\\{subkey}\\{value_name}"
        ExecutionGuard.request_access(
            component="safe_registry_access",
            operation="query_value",
            target=target_repr,
            capability=Capability.REGISTRY_READ,
            access_mode="QUERY"
        )

        if not winreg:
            return {"status": "unsupported", "error": "winreg is only available on Windows"}

        hive = cls.HIVE_MAP.get(root.upper())
        if not hive:
            return {"status": "error", "error": f"Unknown registry hive '{root}'"}

        try:
            sam = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0x0100)
            with winreg.OpenKey(hive, subkey, 0, sam) as key:
                val, val_type = winreg.QueryValueEx(key, value_name)
                return {
                    "status": "success",
                    "root": root,
                    "subkey": subkey,
                    "value_name": value_name,
                    "value": val,
                    "value_type": val_type
                }
        except FileNotFoundError:
            return {"status": "not_found", "value": None}
        except PermissionError:
            return {"status": "access_denied", "error": "ACCESS_DENIED (Insufficient permissions for query)"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    @classmethod
    def enumerate_values(cls, root: str, subkey: str) -> Dict[str, Any]:
        """
        Enumerates all values under a registry key using KEY_READ.
        """
        target_repr = f"{root}\\{subkey}"
        ExecutionGuard.request_access(
            component="safe_registry_access",
            operation="enumerate_values",
            target=target_repr,
            capability=Capability.REGISTRY_READ,
            access_mode="QUERY"
        )

        if not winreg:
            return {"status": "unsupported", "error": "winreg is only available on Windows"}

        hive = cls.HIVE_MAP.get(root.upper())
        if not hive:
            return {"status": "error", "error": f"Unknown registry hive '{root}'"}

        values = {}
        try:
            sam = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0x0100)
            with winreg.OpenKey(hive, subkey, 0, sam) as key:
                idx = 0
                while True:
                    try:
                        vname, vval, _ = winreg.EnumValue(key, idx)
                        values[vname] = vval
                        idx += 1
                    except OSError:
                        break
            return {"status": "success", "values_count": len(values), "values": values}
        except FileNotFoundError:
            return {"status": "not_found", "values_count": 0, "values": {}}
        except PermissionError:
            return {"status": "access_denied", "error": "ACCESS_DENIED"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}
