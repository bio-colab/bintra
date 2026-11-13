# -*- coding: utf-8 -*-
"""
Native Windows Device and Hardware Subsystem Introspection.
Directly interrogates Windows Plug-and-Play manager and Configuration Manager via
SetupAPI.dll and CfgMgr32.dll to inspect live device instances, driver bindings,
and hardware problem codes (CM_PROB_*).
"""

import os
import sys
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8)
    ]


class SP_DEVINFO_DATA(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("ClassGuid", GUID),
        ("DevInst", wintypes.DWORD),
        ("Reserved", ctypes.c_size_t),
    ]


class NativeDeviceInspector:
    """
    Inspects active Windows Plug-and-Play device instances using official
    SetupAPI and Configuration Manager (CfgMgr32) APIs rather than raw registry keys.
    """

    CM_PROB_DESCRIPTIONS = {
        0: "Healthy",
        1: "CM_PROB_NOT_CONFIGURED (Device is not configured correctly)",
        3: "CM_PROB_OUT_OF_MEMORY (Driver out of memory)",
        10: "CM_PROB_FAILED_START (Device cannot start)",
        12: "CM_PROB_NORMAL_CONFLICT (Cannot find enough free resources)",
        14: "CM_PROB_NEED_RESTART (Restart required)",
        18: "CM_PROB_REINSTALL (Reinstall drivers for this device)",
        22: "CM_PROB_DISABLED (Device is disabled)",
        28: "CM_PROB_FAILED_INSTALL (Drivers for this device are not installed)",
        31: "CM_PROB_FAILED_ADD (Device is not working properly; driver load failed)",
        37: "CM_PROB_FAILED_DRIVER_ENTRY (Windows cannot initialize device driver)",
        39: "CM_PROB_DRIVER_FAILED_LOAD (Driver corrupted or missing)",
        43: "CM_PROB_FAILED_POST_START (Windows stopped device because it reported problems)",
        45: "CM_PROB_PHANTOM (Hardware device not currently connected)",
        48: "CM_PROB_BLOCKED_DRIVER (Software/driver blocked from starting)",
        52: "CM_PROB_UNSIGNED_DRIVER (Cannot verify digital signature for drivers)",
    }

    @classmethod
    def describe_problem_code(cls, code: int) -> str:
        return cls.CM_PROB_DESCRIPTIONS.get(int(code), f"CM_PROB_{int(code)}")

    DIGCF_PRESENT = 0x00000002
    DIGCF_ALLCLASSES = 0x00000004

    # SetupAPI Device Registry Properties (SPDRP_*)
    SPDRP_DEVICEDESC = 0x00000000
    SPDRP_HARDWAREID = 0x00000001
    SPDRP_COMPATIBLEIDS = 0x00000002
    SPDRP_SERVICE = 0x00000004
    SPDRP_CLASS = 0x00000007
    SPDRP_CLASSGUID = 0x00000008
    SPDRP_DRIVER = 0x00000009
    SPDRP_MFG = 0x0000000B
    SPDRP_FRIENDLYNAME = 0x0000000C

    # CfgMgr32 Device Status Bits (DN_*)
    DN_STARTABLE = 0x00000001
    DN_STARTED = 0x00000008
    DN_DISABLEABLE = 0x00002000
    DN_REMOVABLE = 0x00004000
    DN_HAS_PROBLEM = 0x00000400

    # CfgMgr32 Problem Codes (CM_PROB_*)
    CM_PROBLEM_NAMES = {
        0: "CM_PROB_OK (Device working normally)",
        1: "CM_PROB_NOT_CONFIGURED",
        10: "CM_PROB_FAILED_START (Device failed to start / Driver init failure)",
        12: "CM_PROB_NORMAL_CONFLICT (Resource arbitration conflict)",
        14: "CM_PROB_NEED_RESTART (System restart required)",
        18: "CM_PROB_REINSTALL (Reinstallation needed)",
        20: "CM_PROB_FAILED_ADD",
        22: "CM_PROB_DISABLED (Device is disabled)",
        28: "CM_PROB_FAILED_INSTALL (Drivers not installed)",
        31: "CM_PROB_FAILED_POST_START",
        43: "CM_PROB_CODE43 (Device reported fatal error / GPU driver crash)"
    }

    @classmethod
    def _get_setupapi_library(cls):
        """Initializes and returns typed setupapi and cfgmgr32 ctypes libraries."""
        if os.name != "nt":
            return None, None
        try:
            setupapi = ctypes.windll.setupapi
            cfgmgr32 = ctypes.windll.cfgmgr32

            # Configure explicit 64-bit safe function signatures
            setupapi.SetupDiGetClassDevsW.restype = ctypes.c_void_p
            setupapi.SetupDiGetClassDevsW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, wintypes.HWND, wintypes.DWORD]

            setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
            setupapi.SetupDiEnumDeviceInfo.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(SP_DEVINFO_DATA)]

            setupapi.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL
            setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA), wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
            ]

            setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
            setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(SP_DEVINFO_DATA),
                ctypes.c_wchar_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
            ]

            setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
            setupapi.SetupDiDestroyDeviceInfoList.argtypes = [ctypes.c_void_p]

            cfgmgr32.CM_Get_DevNode_Status.restype = wintypes.DWORD
            cfgmgr32.CM_Get_DevNode_Status.argtypes = [
                ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.DWORD
            ]

            return setupapi, cfgmgr32
        except Exception:
            return None, None

    @classmethod
    def _read_device_property(cls, setupapi, dev_info: int, dev_data: SP_DEVINFO_DATA, prop_id: int) -> Optional[str]:
        """Reads a wide string device property from SetupAPI."""
        buf = (ctypes.c_wchar * 512)()
        prop_type = wintypes.DWORD()
        req_size = wintypes.DWORD()
        success = setupapi.SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            ctypes.byref(dev_data),
            prop_id,
            ctypes.byref(prop_type),
            ctypes.byref(buf),
            ctypes.sizeof(buf),
            ctypes.byref(req_size)
        )
        return buf.value.strip() if success and buf.value else None

    @classmethod
    def _read_multi_sz_property(cls, setupapi, dev_info: int, dev_data: SP_DEVINFO_DATA, prop_id: int) -> List[str]:
        """Reads a REG_MULTI_SZ property containing multiple null-terminated wide strings."""
        buf = (ctypes.c_wchar * 2048)()
        prop_type = wintypes.DWORD()
        req_size = wintypes.DWORD()
        success = setupapi.SetupDiGetDeviceRegistryPropertyW(
            dev_info,
            ctypes.byref(dev_data),
            prop_id,
            ctypes.byref(prop_type),
            ctypes.byref(buf),
            ctypes.sizeof(buf),
            ctypes.byref(req_size)
        )
        if success and req_size.value > 0:
            raw_wchars = buf[:req_size.value // 2]
            return [s for s in raw_wchars.split('\x00') if s]
        return []

    @classmethod
    def enumerate_devices(
        cls,
        filter_problems_only: bool = False,
        class_filter: Optional[str] = None,
        max_devices: int = 1024
    ) -> List[Dict[str, Any]]:
        """
        Enumerates live PnP device instances from the Windows kernel.
        Extracts device descriptions, hardware IDs, service bindings,
        status flags, and CM_PROB_* error codes.
        """
        setupapi, cfgmgr32 = cls._get_setupapi_library()
        if not setupapi or not cfgmgr32:
            return []

        flags = cls.DIGCF_PRESENT | cls.DIGCF_ALLCLASSES
        dev_info = setupapi.SetupDiGetClassDevsW(None, None, None, flags)
        if not dev_info or dev_info == -1:
            return []

        devices = []
        dev_data = SP_DEVINFO_DATA()
        dev_data.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)

        idx = 0
        while len(devices) < max_devices:
            if not setupapi.SetupDiEnumDeviceInfo(dev_info, idx, ctypes.byref(dev_data)):
                break
            idx += 1

            # Read Device Instance ID (the true canonical string ID, e.g. PCI\VEN_... or USB\VID_...)
            id_buf = (ctypes.c_wchar * 512)()
            req_id_sz = wintypes.DWORD()
            if setupapi.SetupDiGetDeviceInstanceIdW(dev_info, ctypes.byref(dev_data), id_buf, len(id_buf), ctypes.byref(req_id_sz)):
                inst_id_str = id_buf.value
            else:
                inst_id_str = f"DevNode_{dev_data.DevInst}"

            # Query device status via Configuration Manager (CfgMgr32)
            dev_status = wintypes.DWORD()
            problem_code = wintypes.DWORD()
            cr = cfgmgr32.CM_Get_DevNode_Status(
                ctypes.byref(dev_status),
                ctypes.byref(problem_code),
                dev_data.DevInst,
                0
            )

            status_available = (cr == 0)
            has_problem = (status_available and bool(dev_status.value & cls.DN_HAS_PROBLEM))
            prob_num = problem_code.value if status_available else 0

            # Filter out healthy devices when filter_problems_only is requested
            if filter_problems_only and not has_problem:
                continue

            # Read device properties
            dev_desc = cls._read_device_property(setupapi, dev_info, dev_data, cls.SPDRP_DEVICEDESC)
            friendly_name = cls._read_device_property(setupapi, dev_info, dev_data, cls.SPDRP_FRIENDLYNAME)
            hw_ids = cls._read_multi_sz_property(setupapi, dev_info, dev_data, cls.SPDRP_HARDWAREID)
            compat_ids = cls._read_multi_sz_property(setupapi, dev_info, dev_data, cls.SPDRP_COMPATIBLEIDS)
            cls_name = cls._read_device_property(setupapi, dev_info, dev_data, cls.SPDRP_CLASS)
            service = cls._read_device_property(setupapi, dev_info, dev_data, cls.SPDRP_SERVICE)
            driver = cls._read_device_property(setupapi, dev_info, dev_data, cls.SPDRP_DRIVER)
            mfg = cls._read_device_property(setupapi, dev_info, dev_data, cls.SPDRP_MFG)

            if class_filter:
                if not cls_name or class_filter.lower() not in cls_name.lower():
                    continue

            name_repr = friendly_name or dev_desc or "Unknown PnP Device"

            devices.append({
                "device_instance_id": inst_id_str,
                "devnode_handle": dev_data.DevInst,
                "name": name_repr,
                "description": dev_desc,
                "class": cls_name,
                "hardware_id": hw_ids[0] if hw_ids else None,
                "hardware_ids": hw_ids,
                "compatible_ids": compat_ids,
                "service": service,
                "driver_key": driver,
                "manufacturer": mfg,
                "is_started": bool(dev_status.value & cls.DN_STARTED) if status_available else False,
                "has_problem": has_problem,
                "problem_code": prob_num,
                "problem_description": cls.describe_problem_code(prob_num) if has_problem else "Healthy",
                "problem_name": cls.CM_PROBLEM_NAMES.get(prob_num, f"CM_PROB_{prob_num}"),
                "status_available": status_available
            })

        setupapi.SetupDiDestroyDeviceInfoList(dev_info)
        return devices

    @classmethod
    def audit_hardware_health(cls) -> Dict[str, Any]:
        """
        Conducts an authoritative hardware diagnostic audit:
        - Enumerates all live display adapters.
        - Identifies any PnP devices in error state (Code 10, Code 43, etc.).
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "NativeDeviceInspector requires a Windows NT host system."
            }
        all_devs = cls.enumerate_devices(max_devices=512)
        problem_devs = [d for d in all_devs if d.get("has_problem") or d.get("problem_code", 0) > 0]
        display_devs = [d for d in all_devs if (d.get("class") or "").lower() == "display"]
        audio_devs = [d for d in all_devs if (d.get("class") or "").lower() in ("media", "audioendpoint")]

        is_healthy = len(problem_devs) == 0

        return {
            "status": "success",
            "is_hardware_healthy": is_healthy,
            "total_pnp_devices_enumerated": len(all_devs),
            "problem_devices_count": len(problem_devs),
            "display_adapters_count": len(display_devs),
            "audio_devices_count": len(audio_devs),
            "display_adapters": display_devs,
            "audio_devices": audio_devs[:5],
            "problem_devices": problem_devs
        }

    @classmethod
    def get_problem_description(cls, code: int) -> str:
        """Returns the symbolic name for a PnP problem code (CM_PROB_*)."""
        return cls.CM_PROBLEM_NAMES.get(code, f"CM_PROB_UNKNOWN_{code}")
