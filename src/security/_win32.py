# -*- coding: utf-8 -*-
"""
Shared low-level OS and cryptographic helpers for Bintra Security Kernel.

Centralizes thread-safe Win32 kernel32 prototype initialization and streaming
SHA-256 hashing to eliminate duplicated ctypes bindings and I/O loops.
"""

import ctypes
import hashlib
import os
import sys
import threading
from typing import Any, Optional, Tuple

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_ALL = 0x0001 | 0x0002 | 0x0004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

_K32_LOCK = threading.Lock()
_K32_INSTANCE: Optional[Any] = None


def streaming_file_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Computes a streaming SHA-256 hex digest of a regular file on disk."""
    digest = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while chunk := fh.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def get_kernel32() -> Any:
    """
    Returns a cached WinDLL('kernel32', use_last_error=True) handle with
    argtypes/restype configured exactly once under a lock.
    """
    global _K32_INSTANCE
    if sys.platform != "win32":
        raise RuntimeError("kernel32 is only available on Windows")
    if _K32_INSTANCE is not None:
        return _K32_INSTANCE

    with _K32_LOCK:
        if _K32_INSTANCE is None:
            from ctypes import wintypes

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateFileW.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            k32.CreateFileW.restype = wintypes.HANDLE

            k32.GetFinalPathNameByHandleW.argtypes = [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

            k32.OpenProcess.argtypes = [
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ]
            k32.OpenProcess.restype = wintypes.HANDLE

            k32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            k32.QueryFullProcessImageNameW.restype = wintypes.BOOL

            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL
            _K32_INSTANCE = k32
    return _K32_INSTANCE


def close_handle_quiet(handle: Any) -> None:
    """Safely closes a Win32 handle if open, suppressing cleanup errors."""
    if not handle or sys.platform != "win32":
        return
    try:
        invalid = ctypes.c_void_p(-1).value
        if handle == invalid or handle == -1:
            return
        get_kernel32().CloseHandle(handle)
    except Exception:
        pass


def get_final_path_win32(file_path: str) -> Optional[str]:
    """Resolves the canonical volume/DOS path for an existing file or directory via Win32."""
    if sys.platform != "win32":
        return None
    try:
        k32 = get_kernel32()
        invalid_handle = ctypes.c_void_p(-1).value
        handle = k32.CreateFileW(
            file_path,
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if not handle or handle == invalid_handle or handle == -1:
            return None

        try:
            buf_len = 1024
            buf = ctypes.create_unicode_buffer(buf_len)
            res = k32.GetFinalPathNameByHandleW(handle, buf, buf_len, 0)
            if buf_len <= res <= 32768:
                buf_len = res + 1
                buf = ctypes.create_unicode_buffer(buf_len)
                res = k32.GetFinalPathNameByHandleW(handle, buf, buf_len, 0)
            if 0 < res < buf_len:
                clean = buf.value
                if clean.startswith("\\\\?\\UNC\\"):
                    clean = "\\\\" + clean[8:]
                elif clean.startswith("\\\\?\\"):
                    clean = clean[4:]
                return os.path.normpath(clean)
        finally:
            close_handle_quiet(handle)
    except Exception:
        return None
    return None


def open_process_limited(pid: int) -> Tuple[Optional[Any], int]:
    """Acquires PROCESS_QUERY_LIMITED_INFORMATION handle and returns (handle, last_error)."""
    k32 = get_kernel32()
    ctypes.set_last_error(0)
    handle = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    err = ctypes.get_last_error() if not handle else 0
    return (handle or None), err


def query_process_image_path_from_handle(handle: Any) -> Optional[str]:
    """Queries the Win32 executable image path from an already-opened process handle."""
    from ctypes import wintypes

    k32 = get_kernel32()
    buf_len = 1024
    buf = ctypes.create_unicode_buffer(buf_len)
    size = wintypes.DWORD(buf_len)
    if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        return buf.value
    return None
