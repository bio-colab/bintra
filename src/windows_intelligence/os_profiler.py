# -*- coding: utf-8 -*-
"""
Windows Environment & Compatibility Profiler.
Directly interrogates Windows NT kernel via RtlGetVersion, registry compatibility layers,
and processor architectures without manifest spoofing.
"""

import os
import sys
import platform
import ctypes
from typing import Dict, Any, Optional

try:
    import winreg
except ImportError:
    winreg = None  # Non-Windows fallback for unit testing


class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [
        ("dwOSVersionInfoSize", ctypes.c_ulong),
        ("dwMajorVersion", ctypes.c_ulong),
        ("dwMinorVersion", ctypes.c_ulong),
        ("dwBuildNumber", ctypes.c_ulong),
        ("dwPlatformId", ctypes.c_ulong),
        ("szCSDVersion", ctypes.c_wchar * 128),
        ("wServicePackMajor", ctypes.c_ushort),
        ("wServicePackMinor", ctypes.c_ushort),
        ("wSuiteMask", ctypes.c_ushort),
        ("wProductType", ctypes.c_ubyte),
        ("wReserved", ctypes.c_ubyte),
    ]


class SYSTEM_INFO(ctypes.Structure):
    _fields_ = [
        ("wProcessorArchitecture", ctypes.c_ushort),
        ("wReserved", ctypes.c_ushort),
        ("dwPageSize", ctypes.c_ulong),
        ("lpMinimumApplicationAddress", ctypes.c_void_p),
        ("lpMaximumApplicationAddress", ctypes.c_void_p),
        ("dwActiveProcessorMask", ctypes.c_size_t),
        ("dwNumberOfProcessors", ctypes.c_ulong),
        ("dwProcessorType", ctypes.c_ulong),
        ("dwAllocationGranularity", ctypes.c_ulong),
        ("wProcessorLevel", ctypes.c_ushort),
        ("wProcessorRevision", ctypes.c_ushort),
    ]


class WindowsOSProfiler:
    """
    Interrogates the host Windows operating system to establish an incontrovertible
    environmental baseline for application execution and compatibility auditing.
    """

    ARCH_MAP = {
        0: "x86 (32-bit)",
        5: "ARM",
        6: "Itanium",
        9: "x64 (AMD64)",
        12: "ARM64",
        0xFFFF: "Unknown"
    }

    PRODUCT_TYPE_MAP = {
        1: "Workstation (Client)",
        2: "Domain Controller",
        3: "Server"
    }

    @classmethod
    def get_real_kernel_version(cls) -> Dict[str, Any]:
        """
        Invokes ntdll.RtlGetVersion to read true kernel version,
        bypassing compatibility manifests that cause GetVersionEx to lie.
        """
        if os.name != "nt":
            return {
                "os": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "is_windows": False
            }

        osvi = OSVERSIONINFOEXW()
        osvi.dwOSVersionInfoSize = ctypes.sizeof(OSVERSIONINFOEXW)

        try:
            ntdll = ctypes.windll.ntdll
            status = ntdll.RtlGetVersion(ctypes.byref(osvi))
            if status != 0:
                raise OSError(f"RtlGetVersion failed with NTSTATUS: {status}")

            major = osvi.dwMajorVersion
            minor = osvi.dwMinorVersion
            build = osvi.dwBuildNumber
            prod_type = cls.PRODUCT_TYPE_MAP.get(osvi.wProductType, f"Type_{osvi.wProductType}")

            friendly_name = "Windows"
            if major == 10 and minor == 0:
                if build >= 22000:
                    friendly_name = "Windows 11"
                else:
                    friendly_name = "Windows 10"
            elif major == 6:
                if minor == 1:
                    friendly_name = "Windows 7"
                elif minor == 2:
                    friendly_name = "Windows 8"
                elif minor == 3:
                    friendly_name = "Windows 8.1"
            elif major == 5:
                friendly_name = "Windows XP"

            return {
                "is_windows": True,
                "friendly_name": friendly_name,
                "major_version": major,
                "minor_version": minor,
                "build_number": build,
                "service_pack": osvi.szCSDVersion,
                "product_type": prod_type,
                "suite_mask": hex(osvi.wSuiteMask)
            }
        except Exception as e:
            return {
                "is_windows": True,
                "error": str(e),
                "fallback_platform": platform.platform()
            }

    @classmethod
    def get_system_architecture(cls) -> Dict[str, Any]:
        """Retrieves native hardware and host architecture via GetNativeSystemInfo."""
        if os.name != "nt":
            return {"native_architecture": platform.machine(), "is_windows": False}

        sys_info = SYSTEM_INFO()
        try:
            ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(sys_info))
            arch_code = sys_info.wProcessorArchitecture
            arch_str = cls.ARCH_MAP.get(arch_code, f"Unknown_Arch_{arch_code}")
            return {
                "native_architecture": arch_str,
                "processor_count": sys_info.dwNumberOfProcessors,
                "page_size": sys_info.dwPageSize,
                "allocation_granularity": sys_info.dwAllocationGranularity
            }
        except Exception as e:
            return {"native_architecture": platform.machine(), "error": str(e)}

    @classmethod
    def get_process_wow64_status(cls) -> Dict[str, Any]:
        """
        Directly checks whether the active process is executing under WOW64
        (Windows 32-bit on Windows 64-bit emulation) via kernel32.IsWow64Process.
        """
        if os.name != "nt":
            return {"is_wow64": False, "reason": "non_windows"}

        try:
            is_wow64 = ctypes.c_int(0)
            cur_proc = ctypes.windll.kernel32.GetCurrentProcess()
            if hasattr(ctypes.windll.kernel32, "IsWow64Process"):
                if ctypes.windll.kernel32.IsWow64Process(cur_proc, ctypes.byref(is_wow64)):
                    return {
                        "is_wow64": bool(is_wow64.value),
                        "emulation_mode": "WOW64 (32-bit process on 64-bit OS)" if is_wow64.value else "Native"
                    }
        except Exception as e:
            return {"is_wow64": False, "error": str(e)}

        return {"is_wow64": False, "emulation_mode": "Native"}

    @classmethod
    def get_registry_os_details(cls) -> Dict[str, Any]:
        """Reads detailed build, releaseId, and installation type from CurrentVersion registry."""
        if not winreg:
            return {}

        details = {}
        reg_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ) as key:
                for val_name in (
                    "ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild",
                    "UBR", "EditionID", "InstallationType", "CurrentVersion"
                ):
                    try:
                        val, _ = winreg.QueryValueEx(key, val_name)
                        details[val_name.lower()] = val
                    except FileNotFoundError:
                        pass
        except Exception:
            pass
        return details

    @classmethod
    def check_app_compatibility_flags(cls, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspects Windows Application Compatibility Flags (AppCompatFlags\\Layers)
        in both HKCU and HKLM to detect if Windows is applying compatibility shims
        (e.g. WINXPSP3, RUNASADMIN, HIGHDPIAWARE, 640X480) to the target binary.
        """
        if not winreg or not binary_path:
            return {"compatibility_mode_active": False, "shims": []}

        norm_path = os.path.abspath(binary_path)
        active_shims = []

        sub_key = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        for hive_name, hive in (("HKCU", winreg.HKEY_CURRENT_USER), ("HKLM", winreg.HKEY_LOCAL_MACHINE)):
            try:
                with winreg.OpenKey(hive, sub_key, 0, winreg.KEY_READ) as key:
                    try:
                        val, _ = winreg.QueryValueEx(key, norm_path)
                        active_shims.append({
                            "hive": hive_name,
                            "path": norm_path,
                            "raw_flags": val,
                            "parsed_shims": [s.strip() for s in val.split() if s.strip()]
                        })
                    except FileNotFoundError:
                        pass
            except Exception:
                pass

        return {
            "binary": norm_path,
            "compatibility_mode_active": len(active_shims) > 0,
            "shims_count": len(active_shims),
            "shims": active_shims
        }

    @classmethod
    def profile(cls, binary_path: Optional[str] = None) -> Dict[str, Any]:
        """Generates comprehensive OS environmental profile."""
        kernel = cls.get_real_kernel_version()
        arch = cls.get_system_architecture()
        process_wow64 = cls.get_process_wow64_status()
        reg_info = cls.get_registry_os_details()
        compat = cls.check_app_compatibility_flags(binary_path) if binary_path else None

        report = {
            "status": "success",
            "kernel": kernel,
            "architecture": arch,
            "process_wow64": process_wow64,
            "registry_info": reg_info
        }
        if compat:
            report["compatibility_shims"] = compat
        return report
