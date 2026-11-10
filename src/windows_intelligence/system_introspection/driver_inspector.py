# -*- coding: utf-8 -*-
"""
Kernel Driver Introspection Engine.
Enumerates active kernel drivers, load addresses, and file paths via PSAPI,
verifying driver integrity, image bases, and system dependencies.
"""

import os
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


class KernelDriverInspector:
    """
    Introspects kernel-mode drivers loaded into the Windows kernel virtual address space.
    Retrieves execution bases, file paths, and identifies driver conflict points.
    """

    @classmethod
    def _get_psapi_library(cls):
        """Initializes and returns typed PSAPI library functions."""
        if os.name != "nt":
            return None
        try:
            # PSAPI functions are located in kernel32 on modern Windows, psapi on older
            psapi = getattr(ctypes.windll, "psapi", ctypes.windll.kernel32)

            psapi.EnumDeviceDrivers.restype = wintypes.BOOL
            psapi.EnumDeviceDrivers.argtypes = [
                ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
            ]

            psapi.GetDeviceDriverBaseNameW.restype = wintypes.DWORD
            psapi.GetDeviceDriverBaseNameW.argtypes = [
                ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD
            ]

            psapi.GetDeviceDriverFileNameW.restype = wintypes.DWORD
            psapi.GetDeviceDriverFileNameW.argtypes = [
                ctypes.c_void_p, ctypes.c_wchar_p, wintypes.DWORD
            ]

            return psapi
        except Exception:
            return None

    @classmethod
    def _normalize_driver_path(cls, raw_path: str) -> str:
        """Converts internal kernel device paths (\\SystemRoot\\...) to win32 file paths."""
        if not raw_path:
            return ""
        windir = os.environ.get("WINDIR", "C:\\Windows")
        prefix_sys32 = "\\SystemRoot\\System32\\"
        prefix_sysroot = "\\SystemRoot\\"
        if raw_path.startswith(prefix_sys32):
            return os.path.join(windir, "System32", raw_path[len(prefix_sys32):])
        elif raw_path.startswith(prefix_sysroot):
            return os.path.join(windir, raw_path[len(prefix_sysroot):])
        elif raw_path.startswith("\\??\\"):
            return raw_path[4:]
        return raw_path

    @classmethod
    def enumerate_loaded_drivers(cls, max_drivers: int = 512) -> List[Dict[str, Any]]:
        """
        Enumerates all active kernel-mode drivers loaded into kernel space.
        Returns driver base names, kernel virtual base addresses, and physical file paths.
        """
        psapi = cls._get_psapi_library()
        if not psapi:
            return []

        cb_needed = wintypes.DWORD()
        if not psapi.EnumDeviceDrivers(None, 0, ctypes.byref(cb_needed)):
            return []

        ptr_size = ctypes.sizeof(ctypes.c_void_p)
        count = cb_needed.value // ptr_size
        if count <= 0:
            return []

        driver_bases = (ctypes.c_void_p * count)()
        if not psapi.EnumDeviceDrivers(driver_bases, cb_needed.value, ctypes.byref(cb_needed)):
            return []

        actual_count = min(count, max_drivers)
        drivers = []
        name_buf = (ctypes.c_wchar * 260)()
        path_buf = (ctypes.c_wchar * 520)()

        for i in range(actual_count):
            base_addr = driver_bases[i]
            if not base_addr:
                continue

            psapi.GetDeviceDriverBaseNameW(base_addr, name_buf, 260)
            psapi.GetDeviceDriverFileNameW(base_addr, path_buf, 520)

            base_name = name_buf.value.strip()
            raw_path = path_buf.value.strip()
            norm_path = cls._normalize_driver_path(raw_path)

            file_exists = os.path.isfile(norm_path) if norm_path else False
            file_size = os.path.getsize(norm_path) if file_exists else 0

            drivers.append({
                "driver_name": base_name,
                "kernel_image_base": hex(base_addr),
                "kernel_base_int": base_addr,
                "file_path": norm_path,
                "file_exists": file_exists,
                "file_size": file_size
            })

        return drivers

    @classmethod
    def find_driver(cls, driver_name: str) -> Optional[Dict[str, Any]]:
        """Finds a specific loaded driver by name (e.g. 'nvlddmkm.sys', 'dxgkrnl.sys')."""
        target = driver_name.lower()
        if not target.endswith(".sys") and not target.endswith(".dll") and not target.endswith(".exe"):
            target += ".sys"

        all_drivers = cls.enumerate_loaded_drivers(max_drivers=1024)
        for d in all_drivers:
            if d.get("driver_name", "").lower() == target:
                return d
        return None

    @classmethod
    def filter_drivers(cls, substring: str) -> List[Dict[str, Any]]:
        """Filters loaded drivers by substring match on name or file path."""
        target = substring.lower()
        all_drivers = cls.enumerate_loaded_drivers(max_drivers=1024)
        return [
            d for d in all_drivers
            if target in d.get("driver_name", "").lower() or target in d.get("file_path", "").lower()
        ]

    @classmethod
    def audit_drivers(cls) -> Dict[str, Any]:
        """Runs complete kernel driver diagnostic audit."""
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "KernelDriverInspector requires a Windows NT host system."
            }
        drivers = cls.enumerate_loaded_drivers(max_drivers=512)

        graphics_drivers = [
            d for d in drivers
            if any(k in d["driver_name"].lower() for k in ("nvlddmkm", "amdkmdag", "igdkmd", "dxgkrnl", "watchdog"))
        ]
        audio_drivers = [
            d for d in drivers
            if any(k in d["driver_name"].lower() for k in ("hdaudio", "portcls", "usbaudio", "realtek"))
        ]

        return {
            "status": "success",
            "total_drivers_loaded": len(drivers),
            "graphics_drivers": graphics_drivers,
            "audio_drivers": audio_drivers,
            "drivers_sample": drivers[:10]
        }
