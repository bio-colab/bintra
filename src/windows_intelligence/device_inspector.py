# -*- coding: utf-8 -*-
"""
Windows Graphics, DirectX, and Hardware Subsystem Inspector.
Interrogates GPU display adapters, driver versions, and legacy DirectX runtimes (DDraw/D3D8/D3D9).
"""

import os
import sys
from typing import Dict, Any, List

try:
    import winreg
except ImportError:
    winreg = None


class WindowsDeviceInspector:
    """
    Audits graphics adapters, driver releases, and DirectX subsystem capabilities
    to identify hardware incompatibility and graphics initialization crashes.
    """

    @classmethod
    def get_graphics_adapters(cls) -> List[Dict[str, Any]]:
        """
        Enumerates physical and virtual display adapters from the Windows device class registry:
        GUID {4d36e968-e325-11ce-bfc1-08002be10318}
        """
        if not winreg:
            return []

        adapters = []
        base_path = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_path, 0, winreg.KEY_READ) as class_key:
                idx = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(class_key, idx)
                        idx += 1
                        if not sub_name.isdigit():
                            continue
                        sub_path = f"{base_path}\\{sub_name}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub_path, 0, winreg.KEY_READ) as dev_key:
                            adapter_info: Dict[str, Any] = {"device_index": sub_name}
                            for prop in ("DriverDesc", "DriverVersion", "ProviderName", "DriverDate", "MatchingDeviceId"):
                                try:
                                    val, _ = winreg.QueryValueEx(dev_key, prop)
                                    adapter_info[prop.lower()] = val
                                except FileNotFoundError:
                                    pass
                            if "driverdesc" in adapter_info:
                                adapters.append(adapter_info)
                    except OSError:
                        break
        except Exception:
            pass
        return adapters

    @classmethod
    def audit_directx_runtimes(cls) -> Dict[str, Any]:
        """
        Checks presence of modern and legacy DirectX dynamic libraries in System32 / SysWOW64:
        - Legacy: ddraw.dll (DirectDraw), d3d8.dll (Direct3D 8), d3d9.dll (Direct3D 9), dsound.dll (DirectSound)
        - Modern: d3d11.dll, d3d12.dll, dxgi.dll
        """
        windir = os.environ.get("WINDIR", r"C:\Windows")
        sys32 = os.path.join(windir, "System32")
        syswow64 = os.path.join(windir, "SysWOW64")

        runtimes = {
            "legacy_directdraw": {
                "dll": "ddraw.dll",
                "x64_present": os.path.isfile(os.path.join(sys32, "ddraw.dll")),
                "x86_present": os.path.isfile(os.path.join(syswow64, "ddraw.dll")) if os.path.exists(syswow64) else os.path.isfile(os.path.join(sys32, "ddraw.dll"))
            },
            "legacy_direct3d8": {
                "dll": "d3d8.dll",
                "x64_present": os.path.isfile(os.path.join(sys32, "d3d8.dll")),
                "x86_present": os.path.isfile(os.path.join(syswow64, "d3d8.dll")) if os.path.exists(syswow64) else os.path.isfile(os.path.join(sys32, "d3d8.dll"))
            },
            "legacy_direct3d9": {
                "dll": "d3d9.dll",
                "x64_present": os.path.isfile(os.path.join(sys32, "d3d9.dll")),
                "x86_present": os.path.isfile(os.path.join(syswow64, "d3d9.dll")) if os.path.exists(syswow64) else os.path.isfile(os.path.join(sys32, "d3d9.dll"))
            },
            "legacy_directsound": {
                "dll": "dsound.dll",
                "x64_present": os.path.isfile(os.path.join(sys32, "dsound.dll")),
                "x86_present": os.path.isfile(os.path.join(syswow64, "dsound.dll")) if os.path.exists(syswow64) else os.path.isfile(os.path.join(sys32, "dsound.dll"))
            },
            "modern_direct3d11": {
                "dll": "d3d11.dll",
                "x64_present": os.path.isfile(os.path.join(sys32, "d3d11.dll")),
                "x86_present": os.path.isfile(os.path.join(syswow64, "d3d11.dll")) if os.path.exists(syswow64) else True
            },
            "modern_direct3d12": {
                "dll": "d3d12.dll",
                "x64_present": os.path.isfile(os.path.join(sys32, "d3d12.dll")),
                "x86_present": os.path.isfile(os.path.join(syswow64, "d3d12.dll")) if os.path.exists(syswow64) else True
            }
        }

        # Registry version string if available
        dx_reg_ver = None
        if winreg:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\DirectX", 0, winreg.KEY_READ) as k:
                    dx_reg_ver, _ = winreg.QueryValueEx(k, "Version")
            except Exception:
                pass

        return {
            "registry_version": dx_reg_ver,
            "subsystems": runtimes
        }

    @classmethod
    def audit(cls) -> Dict[str, Any]:
        """Runs complete graphics and hardware subsystem diagnosis."""
        return {
            "status": "success",
            "graphics_adapters": cls.get_graphics_adapters(),
            "directx_runtimes": cls.audit_directx_runtimes()
        }
