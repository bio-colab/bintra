# -*- coding: utf-8 -*-
"""
Bintra Path Identity & Jail Boundary Enforcer.
Provides deterministic canonical path resolution, anti-traversal defense,
and protection against NTFS Junctions, Symbolic Links, and Alternate Data Streams (ADS).
"""

import os
import sys
import ctypes
from typing import Optional


class PathIdentity:
    """
    Validates, normalizes, and canonicalizes filesystem paths.
    Guarantees strict confinement within declared scope boundaries.
    """

    @classmethod
    def canonicalize(cls, path: str) -> str:
        """
        Resolves relative components, symlinks, and junction points to obtain
        the authoritative physical path.
        """
        if not path or not isinstance(path, str):
            raise ValueError("Path must be a non-empty string.")

        # Guard against NULL byte injection
        if "\x00" in path:
            raise ValueError("Path contains invalid NULL byte character.")

        # Guard against Alternate Data Streams (ADS)
        cls._validate_no_ads(path)

        # Guard against raw device namespace escapes
        if path.startswith(("\\\\.\\", "\\\\?\\")):
            raise ValueError("Direct device and raw NT namespaces are prohibited.")

        norm_path = os.path.normpath(os.path.abspath(path))

        # On Windows, resolve reparse points (symlinks/junctions) via GetFinalPathNameByHandleW
        if sys.platform == "win32" and os.path.exists(norm_path):
            final_path = cls._get_final_path_win32(norm_path)
            if final_path:
                return final_path

        return os.path.realpath(norm_path)

    @classmethod
    def _validate_no_ads(cls, path: str) -> None:
        """Ensures the path does not target an Alternate Data Stream (:stream)."""
        # Drive letter colon (e.g. C:) is permitted at index 1
        tail = path[2:] if (len(path) >= 2 and path[1] == ":") else path
        if ":" in tail:
            raise ValueError(f"Alternate Data Streams (:stream) are prohibited: '{path}'.")

    @classmethod
    def _get_final_path_win32(cls, file_path: str) -> Optional[str]:
        """Queries kernel for the true final volume path via GetFinalPathNameByHandleW."""
        try:
            FILE_READ_ATTRIBUTES = 0x0080
            FILE_SHARE_READ = 0x0001
            FILE_SHARE_WRITE = 0x0002
            FILE_SHARE_DELETE = 0x0004
            OPEN_EXISTING = 3
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # Allows opening directories as well as files

            handle = ctypes.windll.kernel32.CreateFileW(
                file_path,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None
            )
            if handle == -1 or handle == 0:
                return None

            try:
                buf = ctypes.create_unicode_buffer(1024)
                # VOLUME_NAME_DOS = 0x0
                res = ctypes.windll.kernel32.GetFinalPathNameByHandleW(handle, buf, 1024, 0)
                if res > 0:
                    clean = buf.value
                    # Strip \\?\ prefix returned by Win32
                    if clean.startswith("\\\\?\\UNC\\"):
                        clean = "\\\\" + clean[8:]
                    elif clean.startswith("\\\\?\\"):
                        clean = clean[4:]
                    return os.path.normpath(clean)
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            pass
        return None

    @classmethod
    def is_within_directory(cls, candidate_path: str, parent_directory: str) -> bool:
        """
        Determines if candidate_path is strictly contained within parent_directory.
        Protects against path traversal (../) and escaping symlinks.
        """
        try:
            can_cand = cls.canonicalize(candidate_path)
            can_parent = cls.canonicalize(parent_directory)
            rel = os.path.relpath(can_cand, can_parent)
            return not rel.startswith("..") and not os.path.isabs(rel) and rel != ".."
        except Exception:
            return False

    @classmethod
    def is_same_file(cls, path_a: str, path_b: str) -> bool:
        """Determines if two path strings point to the exact same canonical file on disk, including hard links."""
        try:
            can_a = cls.canonicalize(path_a)
            can_b = cls.canonicalize(path_b)
            if os.path.normcase(can_a) == os.path.normcase(can_b):
                return True
            # Check filesystem inode / device identity (handles hard links across Windows NTFS and POSIX)
            if os.path.exists(can_a) and os.path.exists(can_b):
                return os.path.samefile(can_a, can_b)
            return False
        except Exception:
            return False
