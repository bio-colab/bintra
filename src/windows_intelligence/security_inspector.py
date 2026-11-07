# -*- coding: utf-8 -*-
"""
Windows Security, Token Integrity, and Folder Permission Inspector.
Inspects process token integrity levels (Low/Medium/High/System), UAC elevation,
and tests write permissions against application installation directories.
"""

import os
import sys
import ctypes
from typing import Dict, Any, Optional

try:
    import winreg
except ImportError:
    winreg = None


class WindowsSecurityInspector:
    """
    Audits security token integrity, administrative elevation, and filesystem ACLs
    to diagnose silent failures and ACCESS_DENIED (0x80070005) permission crashes.
    """

    INTEGRITY_LEVEL_MAP = {
        0x0000: "Untrusted",
        0x1000: "Low (Sandboxed / AppContainer)",
        0x2000: "Medium (Standard User)",
        0x3000: "High (Elevated Administrator)",
        0x4000: "System",
        0x5000: "Protected Process"
    }

    @classmethod
    def is_elevated(cls) -> bool:
        """Determines if the current process is running with administrative elevation."""
        if os.name != "nt":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @classmethod
    def get_token_integrity_level(cls) -> Dict[str, Any]:
        """Queries the security token of the current process for its Integrity Level."""
        if os.name != "nt":
            return {"integrity_level": "N/A", "is_windows": False}

        TOKEN_QUERY = 0x0008
        TokenIntegrityLevel = 25  # TOKEN_INFORMATION_CLASS enum

        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        token_handle = ctypes.c_void_p()
        proc_handle = kernel32.GetCurrentProcess()

        if not advapi32.OpenProcessToken(proc_handle, TOKEN_QUERY, ctypes.byref(token_handle)):
            return {"error": "Failed to open process token"}

        try:
            length = ctypes.c_ulong()
            advapi32.GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, ctypes.byref(length))
            if length.value == 0:
                return {"error": "Failed to determine token buffer size"}

            buf = ctypes.create_string_buffer(length.value)
            if not advapi32.GetTokenInformation(token_handle, TokenIntegrityLevel, buf, length, ctypes.byref(length)):
                return {"error": "Failed to retrieve token information"}

            # Cast buffer to TOKEN_MANDATORY_LABEL (SID_AND_ATTRIBUTES)
            p_sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
            get_sub_authority_count = advapi32.GetSidSubAuthorityCount
            get_sub_authority_count.restype = ctypes.POINTER(ctypes.c_ubyte)
            sub_auth_count_ptr = get_sub_authority_count(p_sid)
            count = sub_auth_count_ptr[0]

            get_sub_authority = advapi32.GetSidSubAuthority
            get_sub_authority.restype = ctypes.POINTER(ctypes.c_ulong)
            rid = get_sub_authority(p_sid, count - 1)[0]

            level_str = cls.INTEGRITY_LEVEL_MAP.get(rid, f"Custom_RID_0x{rid:04X}")
            return {
                "rid": hex(rid),
                "integrity_level": level_str,
                "is_elevated": (rid >= 0x3000)
            }
        except Exception as e:
            return {"error": str(e)}
        finally:
            kernel32.CloseHandle(token_handle)

    @classmethod
    def test_directory_write_access(cls, target_dir: str) -> Dict[str, Any]:
        """
        Tests if the current security token has physical write permissions in target_dir.
        Crucial for diagnosing legacy software installed in 'Program Files' that crashes
        when attempting to write game saves or config files without virtualization.
        """
        if not os.path.isdir(target_dir):
            return {"directory": target_dir, "exists": False, "is_writable": False}

        test_file = os.path.join(target_dir, f".rea_perm_probe_{os.getpid()}.tmp")
        is_writable = False
        error_msg = None

        try:
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("probe")
            is_writable = True
        except PermissionError as e:
            error_msg = f"PermissionError: {e}"
        except OSError as e:
            error_msg = f"OSError: {e}"
        finally:
            if os.path.exists(test_file):
                try:
                    os.remove(test_file)
                except OSError:
                    pass

        return {
            "directory": target_dir,
            "exists": True,
            "is_writable": is_writable,
            "error": error_msg,
            "is_program_files_path": (
                r"program files" in target_dir.lower() or
                r"program files (x86)" in target_dir.lower()
            )
        }

    @classmethod
    def audit(cls, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Runs security and privilege audit for application context."""
        integrity = cls.get_token_integrity_level()
        elevated = cls.is_elevated()
        app_dir = os.path.dirname(os.path.abspath(binary_path)) if binary_path else None
        dir_perms = cls.test_directory_write_access(app_dir) if app_dir else None

        return {
            "status": "success",
            "is_elevated_admin": elevated,
            "token_integrity": integrity,
            "directory_write_permissions": dir_perms
        }
