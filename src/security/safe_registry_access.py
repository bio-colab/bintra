# -*- coding: utf-8 -*-
"""
Bintra Safe Registry Access Gateway.
Guarantees strictly read-only Registry inspection (KEY_READ | KEY_WOW64_64KEY).
Forbids KEY_WRITE, KEY_ALL_ACCESS, and registry mutation APIs.
"""

import sys
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional, Tuple

if sys.platform == "win32":
    import winreg
else:
    winreg = None

from .capability_registry import Capability
from .config import resolve_winreg_hive_map
from .execution_guard import ExecutionGuard


class SafeRegistryAccess:
    """
    Authorized read-only Registry query gateway mediated by ExecutionGuard.
    """

    HIVE_MAP: Dict[str, int] = resolve_winreg_hive_map()

    @classmethod
    @contextmanager
    def _open_readonly_key(cls, root: str, subkey: str) -> Iterator[Tuple[Optional[Any], Optional[Dict[str, Any]]]]:
        if not winreg:
            yield None, {"status": "unsupported", "error": "winreg is only available on Windows"}
            return

        hive = cls.HIVE_MAP.get(str(root).upper())
        if not hive:
            yield None, {"status": "error", "error": f"Unknown registry hive '{root}'"}
            return

        sam = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0x0100)
        with winreg.OpenKey(hive, subkey, 0, sam) as key:
            yield key, None

    @classmethod
    def query_value(cls, root: str, subkey: str, value_name: str) -> Dict[str, Any]:
        """Reads a single registry value safely with KEY_READ rights."""
        ExecutionGuard.request_access(
            component="safe_registry_access",
            operation="query_value",
            target=f"{root}\\{subkey}\\{value_name}",
            capability=Capability.REGISTRY_READ,
            access_mode="QUERY",
        )

        try:
            with cls._open_readonly_key(root, subkey) as (key, err_resp):
                if err_resp is not None:
                    return err_resp
                val, val_type = winreg.QueryValueEx(key, value_name)
                return {
                    "status": "success",
                    "root": root,
                    "subkey": subkey,
                    "value_name": value_name,
                    "value": val,
                    "value_type": val_type,
                }
        except FileNotFoundError:
            return {"status": "not_found", "value": None}
        except PermissionError:
            return {"status": "access_denied", "error": "ACCESS_DENIED (Insufficient permissions for query)"}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    @classmethod
    def enumerate_values(cls, root: str, subkey: str) -> Dict[str, Any]:
        """Enumerates all values under a registry key using KEY_READ."""
        ExecutionGuard.request_access(
            component="safe_registry_access",
            operation="enumerate_values",
            target=f"{root}\\{subkey}",
            capability=Capability.REGISTRY_READ,
            access_mode="QUERY",
        )

        values: Dict[str, Any] = {}
        try:
            with cls._open_readonly_key(root, subkey) as (key, err_resp):
                if err_resp is not None:
                    return err_resp
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
