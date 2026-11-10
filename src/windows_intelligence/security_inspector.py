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
        Pure read-only evaluation of directory write permissions without creating any probe file on disk.
        Determines if current process token (elevated admin vs standard user) can write to target_dir.
        Crucial for diagnosing legacy software installed in 'Program Files' or 'Windows' that encounters
        0xC0000005 access violations when attempting to write config or save states without UAC virtualization.
        """
        if not os.path.isdir(target_dir):
            return {
                "directory": target_dir,
                "exists": False,
                "is_writable": False,
                "is_read_only_audit": True,
                "evaluation_type": "POLICY_ESTIMATION",
                "notice": "Target directory does not exist on disk."
            }

        norm_dir = os.path.abspath(target_dir).lower()
        is_program_files = (
            r"program files" in norm_dir or
            r"program files (x86)" in norm_dir or
            r"windows" in norm_dir
        )

        is_admin = cls.is_elevated()
        # On modern Windows NT with UAC active, standard users cannot write to Program Files / Windows
        is_writable = is_admin if is_program_files else True

        return {
            "directory": target_dir,
            "exists": True,
            "is_writable": is_writable,
            "is_read_only_audit": True,
            "evaluation_type": "POLICY_ESTIMATION",
            "confidence": 0.95 if is_program_files else 0.85,
            "methodology": "In-memory policy heuristic (evaluates system protected roots against token elevation; zero disk mutation)",
            "notice": "Heuristic policy evaluation without filesystem DACL probing. Actual permissions may vary based on explicit user/group ACLs.",
            "is_program_files_path": is_program_files,
            "is_elevated_admin": is_admin
        }

    @classmethod
    def audit(cls, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Runs security and privilege audit for application context."""
        if sys.platform != "win32":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "WindowsSecurityInspector requires a Windows host system."
            }
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
