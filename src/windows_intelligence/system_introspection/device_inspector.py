# -*- coding: utf-8 -*-
"""
Native Windows Device and Hardware Subsystem Introspection.
Directly interrogates Windows Plug-and-Play manager and Configuration Manager via
SetupAPI.dll and CfgMgr32.dll to inspect live device instances, driver bindings,
and hardware problem codes (CM_PROB_*).
"""

import os
import sys
import collections
import struct
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
        0: "Healthy (Device working normally)",
        1: "CM_PROB_NOT_CONFIGURED (Device is not configured correctly)",
        2: "CM_PROB_DEVLOADER_FAILED (Device loader failed)",
        3: "CM_PROB_OUT_OF_MEMORY (Driver out of memory)",
        4: "CM_PROB_ENTRY_IS_WRONG_TYPE (Device entry is wrong type)",
        5: "CM_PROB_LACKED_ARBITRATOR (Lacked arbitrator for resource)",
        6: "CM_PROB_BOOT_CONFIG_CONFLICT (Boot config conflict)",
        7: "CM_PROB_FAILED_FILTER (Failed filter)",
        8: "CM_PROB_DEVLOADER_NOT_FOUND (Device loader not found)",
        9: "CM_PROB_INVALID_DATA (Invalid data in registry or firmware)",
        10: "CM_PROB_FAILED_START (Device cannot start)",
        11: "CM_PROB_LIAR (Device failed or reported impossible state)",
        12: "CM_PROB_NORMAL_CONFLICT (Cannot find enough free resources)",
        13: "CM_PROB_NOT_VERIFIED (Device not verified)",
        14: "CM_PROB_NEED_RESTART (Restart required)",
        15: "CM_PROB_REENUMERATION (Reenumeration required)",
        16: "CM_PROB_PARTIAL_LOG_CONF (Partial logical configuration)",
        17: "CM_PROB_UNKNOWN_RESOURCE (Unknown resource type)",
        18: "CM_PROB_REINSTALL (Reinstall drivers for this device)",
        19: "CM_PROB_REGISTRY (Registry returned a failure)",
        20: "CM_PROB_VXDLDR (VxD loader failure)",
        21: "CM_PROB_WILL_BE_REMOVED (Device is being removed)",
        22: "CM_PROB_DISABLED (Device is disabled)",
        23: "CM_PROB_DEVLOADER_NOT_READY (Devloader not ready)",
        24: "CM_PROB_DEVICE_NOT_THERE (Hardware device not present / disconnected)",
        25: "CM_PROB_MOVED (Device moved)",
        26: "CM_PROB_TOO_EARLY (Device called too early)",
        27: "CM_PROB_NO_VALID_LOG_CONF (No valid logical configuration)",
        28: "CM_PROB_FAILED_INSTALL (Drivers for this device are not installed)",
        29: "CM_PROB_HARDWARE_DISABLED (Device hardware is disabled)",
        30: "CM_PROB_CANT_SHARE_IRQ (Cannot share IRQ)",
        31: "CM_PROB_FAILED_ADD (Device is not working properly; driver load failed / AddDevice error)",
        32: "CM_PROB_DISABLED_SERVICE (Driver service is disabled)",
        33: "CM_PROB_TRANSLATION_FAILED (Resource translation failed)",
        34: "CM_PROB_NO_SOFTCONFIG (No soft config found)",
        35: "CM_PROB_BIOS_TABLE (Machine BIOS table error)",
        36: "CM_PROB_IRQ_TRANSLATION_FAILED (IRQ translation failed)",
        37: "CM_PROB_FAILED_DRIVER_ENTRY (Windows cannot initialize device driver)",
        38: "CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD (Driver failed prior unload)",
        39: "CM_PROB_DRIVER_FAILED_LOAD (Driver corrupted or missing)",
        40: "CM_PROB_DRIVER_SERVICE_KEY_INVALID (Driver service registry key invalid)",
        41: "CM_PROB_LEGACY_SERVICE_NO_DEVICES (Legacy service created no devices)",
        42: "CM_PROB_DUPLICATE_DEVICE (Duplicate device instance detected)",
        43: "CM_PROB_FAILED_POST_START (Windows stopped device because it reported problems / Code 43)",
        44: "CM_PROB_HALTED (Device halted)",
        45: "CM_PROB_PHANTOM (Hardware device not currently connected)",
        46: "CM_PROB_SYSTEM_SHUTDOWN (System is shutting down)",
        47: "CM_PROB_HELD_FOR_EJECT (Device prepared for safe removal but not removed)",
        48: "CM_PROB_DRIVER_BLOCKED (Software for this device has been blocked from starting)",
        49: "CM_PROB_REGISTRY_TOO_LARGE (System registry hive exceeds size limit)",
        50: "CM_PROB_SETPROPERTIES_FAILED (Windows cannot apply all device properties)",
        51: "CM_PROB_WAITING_ON_DEPENDENCY (Device waiting on another device to start)",
        52: "CM_PROB_UNSIGNED_DRIVER (Cannot verify digital signature for drivers)",
        53: "CM_PROB_USED_BY_DEBUGGER (Device disabled because kernel debugger uses it)",
        54: "CM_PROB_DEVICE_RESET (Device is not working properly because Windows cannot reset it)",
        55: "CM_PROB_CONSOLE_LOCKED (Console lock required / Session locked)",
        56: "CM_PROB_NEED_CLASS_CONFIG (Device class configuration in progress)",
        57: "CM_PROB_GUEST_ASSIGNMENT_FAILED (Guest assignment failed)",
    }

    @classmethod
    def describe_problem_code(cls, code: int) -> str:
        if int(code) == 0:
            return "Healthy"
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

    # CfgMgr32 Problem Codes (CM_PROB_*) - Canonical Microsoft SDK cfg.h definitions
    CM_PROBLEM_NAMES = {
        0: "CM_PROB_OK",
        1: "CM_PROB_NOT_CONFIGURED",
        2: "CM_PROB_DEVLOADER_FAILED",
        3: "CM_PROB_OUT_OF_MEMORY",
        4: "CM_PROB_ENTRY_IS_WRONG_TYPE",
        5: "CM_PROB_LACKED_ARBITRATOR",
        6: "CM_PROB_BOOT_CONFIG_CONFLICT",
        7: "CM_PROB_FAILED_FILTER",
        8: "CM_PROB_DEVLOADER_NOT_FOUND",
        9: "CM_PROB_INVALID_DATA",
        10: "CM_PROB_FAILED_START",
        11: "CM_PROB_LIAR",
        12: "CM_PROB_NORMAL_CONFLICT",
        13: "CM_PROB_NOT_VERIFIED",
        14: "CM_PROB_NEED_RESTART",
        15: "CM_PROB_REENUMERATION",
        16: "CM_PROB_PARTIAL_LOG_CONF",
        17: "CM_PROB_UNKNOWN_RESOURCE",
        18: "CM_PROB_REINSTALL",
        19: "CM_PROB_REGISTRY",
        20: "CM_PROB_VXDLDR",
        21: "CM_PROB_WILL_BE_REMOVED",
        22: "CM_PROB_DISABLED",
        23: "CM_PROB_DEVLOADER_NOT_READY",
        24: "CM_PROB_DEVICE_NOT_THERE",
        25: "CM_PROB_MOVED",
        26: "CM_PROB_TOO_EARLY",
        27: "CM_PROB_NO_VALID_LOG_CONF",
        28: "CM_PROB_FAILED_INSTALL",
        29: "CM_PROB_HARDWARE_DISABLED",
        30: "CM_PROB_CANT_SHARE_IRQ",
        31: "CM_PROB_FAILED_ADD",
        32: "CM_PROB_DISABLED_SERVICE",
        33: "CM_PROB_TRANSLATION_FAILED",
        34: "CM_PROB_NO_SOFTCONFIG",
        35: "CM_PROB_BIOS_TABLE",
        36: "CM_PROB_IRQ_TRANSLATION_FAILED",
        37: "CM_PROB_FAILED_DRIVER_ENTRY",
        38: "CM_PROB_DRIVER_FAILED_PRIOR_UNLOAD",
        39: "CM_PROB_DRIVER_FAILED_LOAD",
        40: "CM_PROB_DRIVER_SERVICE_KEY_INVALID",
        41: "CM_PROB_LEGACY_SERVICE_NO_DEVICES",
        42: "CM_PROB_DUPLICATE_DEVICE",
        43: "CM_PROB_FAILED_POST_START",
        44: "CM_PROB_HALTED",
        45: "CM_PROB_PHANTOM",
        46: "CM_PROB_SYSTEM_SHUTDOWN",
        47: "CM_PROB_HELD_FOR_EJECT",
        48: "CM_PROB_DRIVER_BLOCKED",
        49: "CM_PROB_REGISTRY_TOO_LARGE",
        50: "CM_PROB_SETPROPERTIES_FAILED",
        51: "CM_PROB_WAITING_ON_DEPENDENCY",
        52: "CM_PROB_UNSIGNED_DRIVER",
        53: "CM_PROB_USED_BY_DEBUGGER",
        54: "CM_PROB_DEVICE_RESET",
        55: "CM_PROB_CONSOLE_LOCKED",
        56: "CM_PROB_NEED_CLASS_CONFIG",
        57: "CM_PROB_GUEST_ASSIGNMENT_FAILED",
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

            if hasattr(cfgmgr32, "CM_Get_Parent"):
                cfgmgr32.CM_Get_Parent.restype = wintypes.DWORD
                cfgmgr32.CM_Get_Parent.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.DWORD]

            if hasattr(cfgmgr32, "CM_Get_Child"):
                cfgmgr32.CM_Get_Child.restype = wintypes.DWORD
                cfgmgr32.CM_Get_Child.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.DWORD]

            if hasattr(cfgmgr32, "CM_Get_Sibling"):
                cfgmgr32.CM_Get_Sibling.restype = wintypes.DWORD
                cfgmgr32.CM_Get_Sibling.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, wintypes.DWORD]

            if hasattr(cfgmgr32, "CM_Get_Device_IDW"):
                cfgmgr32.CM_Get_Device_IDW.restype = wintypes.DWORD
                cfgmgr32.CM_Get_Device_IDW.argtypes = [wintypes.DWORD, wintypes.LPWSTR, wintypes.ULONG, wintypes.ULONG]

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

        invalid_hdevinfo = ctypes.c_void_p(-1).value
        flags = cls.DIGCF_PRESENT | cls.DIGCF_ALLCLASSES
        dev_info = setupapi.SetupDiGetClassDevsW(None, None, None, flags)
        if not dev_info or dev_info == invalid_hdevinfo:
            return []

        devices = []
        try:
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
                prob_num = problem_code.value if status_available else 0
                has_problem = (status_available and (bool(dev_status.value & cls.DN_HAS_PROBLEM) or prob_num > 0))

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

                # Query parent DevNode and canonical parent instance ID
                parent_devnode_val = None
                parent_id_str = None
                if hasattr(cfgmgr32, "CM_Get_Parent"):
                    p_inst = wintypes.DWORD()
                    cr_p = cfgmgr32.CM_Get_Parent(ctypes.byref(p_inst), dev_data.DevInst, 0)
                    if cr_p == 0:
                        parent_devnode_val = p_inst.value
                        if hasattr(cfgmgr32, "CM_Get_Device_IDW"):
                            p_buf = (ctypes.c_wchar * 512)()
                            cr_pid = cfgmgr32.CM_Get_Device_IDW(p_inst.value, p_buf, 512, 0)
                            if cr_pid == 0 and p_buf.value:
                                parent_id_str = p_buf.value
                            else:
                                parent_id_str = f"DevNode_{p_inst.value}"

                name_repr = friendly_name or dev_desc or "Unknown PnP Device"
                if not status_available:
                    prob_desc = "Status Unavailable (CM_Get_DevNode_Status failed)"
                    prob_name = "CM_PROB_STATUS_UNAVAILABLE"
                elif has_problem:
                    prob_desc = cls.describe_problem_code(prob_num)
                    prob_name = cls.CM_PROBLEM_NAMES.get(prob_num, f"CM_PROB_{prob_num}")
                else:
                    prob_desc = "Healthy"
                    prob_name = cls.CM_PROBLEM_NAMES.get(0, "CM_PROB_OK")

                devices.append({
                    "device_instance_id": inst_id_str,
                    "devnode_handle": dev_data.DevInst,
                    "parent_devnode": parent_devnode_val,
                    "parent_device_id": parent_id_str,
                    "name": name_repr,
                    "friendly_name": friendly_name,
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
                    "problem_description": prob_desc,
                    "problem_name": prob_name,
                    "status_available": status_available
                })
        finally:
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
        all_devs = cls.enumerate_devices(max_devices=2048)
        problem_devs = [d for d in all_devs if d.get("has_problem") or d.get("problem_code", 0) > 0]
        status_unavailable_devs = [d for d in all_devs if d.get("status_available") is False]
        display_devs = [d for d in all_devs if (d.get("class") or "").lower() == "display"]
        audio_devs = [d for d in all_devs if (d.get("class") or "").lower() in ("media", "audioendpoint")]

        soft_problem_codes = {14, 15, 21, 22, 24, 25, 29, 45, 47}
        if not all_devs:
            health_classification = "UNKNOWN"
        elif problem_devs:
            has_hard_fault = any(int(d.get("problem_code", 0)) not in soft_problem_codes for d in problem_devs)
            health_classification = "FAULTING" if has_hard_fault else "DEGRADED"
        elif status_unavailable_devs:
            health_classification = "UNKNOWN"
        else:
            health_classification = "HEALTHY"

        is_healthy = (len(problem_devs) == 0 and len(all_devs) > 0 and len(status_unavailable_devs) == 0)

        return {
            "status": "success",
            "is_hardware_healthy": is_healthy,
            "health_classification": health_classification,
            "total_pnp_devices_enumerated": len(all_devs),
            "problem_devices_count": len(problem_devs),
            "status_unavailable_count": len(status_unavailable_devs),
            "display_adapters_count": len(display_devs),
            "audio_devices_count": len(audio_devs),
            "audio_devices_truncated": len(audio_devs) > 5,
            "display_adapters": display_devs,
            "audio_devices": audio_devs[:5],
            "problem_devices": problem_devs
        }

    @classmethod
    def get_problem_description(cls, code: int) -> str:
        """Returns the symbolic name for a PnP problem code (CM_PROB_*)."""
        return cls.CM_PROBLEM_NAMES.get(code, f"CM_PROB_UNKNOWN_{code}")

    STORAGE_BUS_TYPES = {
        0: "Unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394",
        5: "SSA", 6: "Fibre", 7: "USB", 8: "RAID", 9: "iSCSI",
        10: "SAS", 11: "SATA", 12: "SD", 13: "MMC", 14: "Virtual",
        15: "FileBackedVirtual", 16: "Spaces", 17: "NVMe", 18: "SCM", 19: "UFS"
    }

    DRIVE_TYPES = {
        0: "DRIVE_UNKNOWN",
        1: "DRIVE_NO_ROOT_DIR",
        2: "DRIVE_REMOVABLE",
        3: "DRIVE_FIXED",
        4: "DRIVE_REMOTE",
        5: "DRIVE_CDROM",
        6: "DRIVE_RAMDISK"
    }

    @classmethod
    def build_device_topology(
        cls,
        max_devices: int = 500,
        bus_filter: Optional[str] = None,
        problems_only: bool = False,
        format: str = "json"
    ) -> Dict[str, Any]:
        """
        Constructs an authoritative bus hierarchy and dependency tree of live PnP devices
        from Windows Kernel DevNodes and SetupAPI.

        Args:
            max_devices: Upper bound on devices to enumerate (default: 500).
            bus_filter: Optional substring filter on bus / root instance prefix (e.g. 'USB', 'PCI', 'ACPI').
            problems_only: When True, filters topology to only display branches containing CM_PROB_* errors.
            format: Output representation: 'json' (nested dict tree), 'tree' (indented ASCII), or 'mermaid' (Mermaid graph TD).
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "NativeDeviceInspector requires a Windows NT host.",
                "format": format,
                "total_nodes": 0,
                "roots": [],
                "rendered": ""
            }

        raw_devices = cls.enumerate_devices(filter_problems_only=False, max_devices=max_devices)
        if not raw_devices:
            return {
                "status": "empty",
                "total_nodes": 0,
                "roots": [],
                "rendered": "No PnP devices enumerated."
            }

        device_map = {d["device_instance_id"]: d for d in raw_devices}
        children_map = collections.defaultdict(list)

        for d in raw_devices:
            parent_id = d.get("parent_device_id")
            if parent_id and parent_id in device_map:
                children_map[parent_id].append(d["device_instance_id"])

        # Determine retained nodes based on filters
        retained_ids = set(device_map.keys())

        if problems_only:
            problem_ids = {d["device_instance_id"] for d in raw_devices if d.get("has_problem") or d.get("problem_code", 0) > 0}
            needed_ids = set()
            for pid in problem_ids:
                curr = pid
                while curr:
                    needed_ids.add(curr)
                    p_dev = device_map.get(curr)
                    curr = p_dev.get("parent_device_id") if p_dev else None
            retained_ids &= needed_ids

        if bus_filter:
            bf_upper = bus_filter.strip().upper()
            matched_roots = set()
            for did, d in device_map.items():
                inst_match = bf_upper in did.upper()
                class_match = bool(d.get("class") and bf_upper in d["class"].upper())
                service_match = bool(d.get("service") and bf_upper in d["service"].upper())
                if inst_match or class_match or service_match:
                    matched_roots.add(did)

            # Include matched roots and all their descendants
            descendant_ids = set()
            def _collect_descendants(curr_id):
                descendant_ids.add(curr_id)
                for child_id in children_map.get(curr_id, []):
                    if child_id not in descendant_ids:
                        _collect_descendants(child_id)

            for m_id in matched_roots:
                _collect_descendants(m_id)

            retained_ids &= descendant_ids

        # Identify roots among retained IDs
        root_ids = []
        for did in raw_devices:
            inst_id = did["device_instance_id"]
            if inst_id not in retained_ids:
                continue
            parent_id = did.get("parent_device_id")
            # A node is a root if it has no parent, parent is HTREE\ROOT\0, or parent is not in retained_ids
            if not parent_id or parent_id.upper() == r"HTREE\ROOT\0" or parent_id not in retained_ids:
                root_ids.append(inst_id)

        # 1. JSON Nested Hierarchy
        visited = set()
        def _build_json_node(dev_id):
            if dev_id in visited:
                return None
            visited.add(dev_id)
            d = device_map[dev_id]
            child_nodes = []
            for cid in children_map.get(dev_id, []):
                if cid in retained_ids and cid not in visited:
                    c_dict = _build_json_node(cid)
                    if c_dict:
                        child_nodes.append(c_dict)
            return {
                "device_instance_id": d["device_instance_id"],
                "name": d["name"],
                "class": d.get("class"),
                "hardware_id": d.get("hardware_id"),
                "service": d.get("service"),
                "is_started": d.get("is_started", False),
                "has_problem": d.get("has_problem", False),
                "problem_code": d.get("problem_code", 0),
                "problem_name": d.get("problem_name", "Healthy"),
                "problem_description": d.get("problem_description", "Healthy"),
                "children": child_nodes
            }

        json_roots = []
        for r_id in root_ids:
            r_node = _build_json_node(r_id)
            if r_node:
                json_roots.append(r_node)

        # 2. Indented ASCII Tree
        tree_lines = []
        tree_visited = set()
        def _render_tree_node(dev_id, prefix="", is_last=True):
            if dev_id in tree_visited:
                return
            tree_visited.add(dev_id)
            d = device_map[dev_id]
            connector = "└── " if is_last else "├── "
            cls_str = f" [{d['class']}]" if d.get("class") else ""
            prob_str = f" [!] {d.get('problem_name')}" if d.get("has_problem") else ""
            tree_lines.append(f"{prefix}{connector}{d['name']}{cls_str} ({d['device_instance_id']}){prob_str}")

            child_prefix = prefix + ("    " if is_last else "│   ")
            child_ids = [cid for cid in children_map.get(dev_id, []) if cid in retained_ids and cid not in tree_visited]
            for idx, cid in enumerate(child_ids):
                _render_tree_node(cid, child_prefix, idx == len(child_ids) - 1)

        for idx, r_id in enumerate(root_ids):
            _render_tree_node(r_id, "", idx == len(root_ids) - 1)

        tree_str = "\n".join(tree_lines)

        # 3. Mermaid Flowchart
        mermaid_lines = ["graph TD"]
        node_aliases = {}
        for idx, did in enumerate(retained_ids):
            node_aliases[did] = f"dev_{idx}"

        for did in retained_ids:
            d = device_map[did]
            alias = node_aliases[did]
            clean_name = d["name"].replace('"', "'").replace("[", "(").replace("]", ")")
            leaf_id = did.split("\\")[-1][:25].replace('"', "'")
            mermaid_lines.append(f'  {alias}["{clean_name}<br/><code>{leaf_id}</code>"]')
            if d.get("has_problem"):
                mermaid_lines.append(f"  style {alias} fill:#ffcccc,stroke:#e74c3c,stroke-width:2px")

        for pid, cids in children_map.items():
            if pid in node_aliases:
                for cid in cids:
                    if cid in node_aliases:
                        mermaid_lines.append(f"  {node_aliases[pid]} --> {node_aliases[cid]}")

        mermaid_str = "\n".join(mermaid_lines)

        selected_render = json_roots if format == "json" else (mermaid_str if format == "mermaid" else tree_str)

        return {
            "status": "success",
            "format": format,
            "total_nodes": len(retained_ids),
            "root_nodes_count": len(root_ids),
            "roots": json_roots,
            "rendered": selected_render
        }

    @classmethod
    def audit_storage_devices(cls, max_drives: int = 16) -> Dict[str, Any]:
        """
        Conducts read-only kernel inspection of physical disk drives and mounted logical volumes.
        Interrogates IOCTL_STORAGE_QUERY_PROPERTY to identify physical bus interfaces (NVMe, SATA, USB),
        drive models, firmware revisions, and volume mount configurations.
        Strictly zero mutation, fail-closed read-only access.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "epistemic_scope": "STORAGE_BUS_AND_VOLUME_TOPOLOGY",
                "smart_health_analyzed": False,
                "message": "Storage device inspection requires a Windows NT host.",
                "physical_drives": [],
                "logical_volumes": [],
                "summary": {"total_physical_drives": 0, "total_logical_volumes": 0}
            }

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID
        ]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.GetLogicalDrives.restype = wintypes.DWORD
        kernel32.GetLogicalDrives.argtypes = []
        kernel32.GetVolumeInformationW.restype = wintypes.BOOL
        kernel32.GetVolumeInformationW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            wintypes.DWORD
        ]
        kernel32.GetDiskFreeSpaceExW.restype = wintypes.BOOL
        kernel32.GetDiskFreeSpaceExW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong)
        ]
        kernel32.GetDriveTypeW.restype = wintypes.UINT
        kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]

        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        OPEN_EXISTING = 3
        IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400

        class STORAGE_PROPERTY_QUERY(ctypes.Structure):
            _fields_ = [
                ("PropertyId", wintypes.DWORD),
                ("QueryType", wintypes.DWORD),
                ("AdditionalParameters", ctypes.c_byte * 1)
            ]

        # 1. Enumerate Physical Drives via IOCTL_STORAGE_QUERY_PROPERTY
        physical_drives = []
        for drive_idx in range(max_drives):
            drive_path = f"\\\\.\\PhysicalDrive{drive_idx}"
            handle = kernel32.CreateFileW(
                drive_path,
                0,  # Query metadata only (no read/write data access required)
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None
            )
            if handle == INVALID_HANDLE_VALUE or handle is None or handle == 0:
                continue

            try:
                query = STORAGE_PROPERTY_QUERY(0, 0)  # StorageDeviceProperty, PropertyStandardQuery
                out_buf = (ctypes.c_byte * 1024)()
                bytes_returned = wintypes.DWORD()
                ok = kernel32.DeviceIoControl(
                    handle,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    ctypes.byref(query),
                    ctypes.sizeof(query),
                    ctypes.byref(out_buf),
                    len(out_buf),
                    ctypes.byref(bytes_returned),
                    None
                )
                if ok and bytes_returned.value >= 32:
                    raw = bytes(out_buf[:bytes_returned.value])
                    version, size, dev_type, dev_mod, removable, queueing, v_off, p_off, r_off, s_off, bus_type = struct.unpack_from(
                        "<IIBB??IIIII", raw, 0
                    )

                    def _extract_str(offset: int) -> str:
                        if 0 < offset < len(raw):
                            end = raw.find(b"\x00", offset)
                            if end != -1:
                                return raw[offset:end].decode("latin1", errors="replace").strip()
                            return raw[offset:].decode("latin1", errors="replace").strip()
                        return ""

                    bus_name = cls.STORAGE_BUS_TYPES.get(bus_type, f"Bus_{bus_type}")
                    physical_drives.append({
                        "device_path": drive_path,
                        "drive_index": drive_idx,
                        "bus_type": bus_name,
                        "bus_type_raw": bus_type,
                        "vendor_id": _extract_str(v_off),
                        "product_id": _extract_str(p_off),
                        "product_revision": _extract_str(r_off),
                        "serial_number": _extract_str(s_off),
                        "is_removable": removable,
                        "command_queueing": queueing
                    })
            except Exception:
                pass
            finally:
                kernel32.CloseHandle(handle)

        # 2. Enumerate Logical Volumes
        logical_volumes = []
        try:
            drives_mask = kernel32.GetLogicalDrives()
            for i in range(26):
                if drives_mask & (1 << i):
                    drive_letter = f"{chr(ord('A') + i)}:\\"
                    vol_name_buf = (ctypes.c_wchar * 260)()
                    fs_name_buf = (ctypes.c_wchar * 260)()
                    serial_num = wintypes.DWORD()
                    max_component_len = wintypes.DWORD()
                    fs_flags = wintypes.DWORD()

                    vol_ok = kernel32.GetVolumeInformationW(
                        drive_letter,
                        vol_name_buf,
                        260,
                        ctypes.byref(serial_num),
                        ctypes.byref(max_component_len),
                        ctypes.byref(fs_flags),
                        fs_name_buf,
                        260
                    )

                    free_bytes = ctypes.c_ulonglong()
                    total_bytes = ctypes.c_ulonglong()
                    total_free_bytes = ctypes.c_ulonglong()
                    space_ok = kernel32.GetDiskFreeSpaceExW(
                        drive_letter,
                        ctypes.byref(free_bytes),
                        ctypes.byref(total_bytes),
                        ctypes.byref(total_free_bytes)
                    )

                    drive_type_code = kernel32.GetDriveTypeW(drive_letter)
                    drive_type_str = cls.DRIVE_TYPES.get(drive_type_code, f"DRIVE_{drive_type_code}")

                    used_bytes = max(0, total_bytes.value - free_bytes.value) if space_ok else 0
                    total_gb = round(total_bytes.value / (1024 ** 3), 2) if space_ok else 0.0
                    free_gb = round(free_bytes.value / (1024 ** 3), 2) if space_ok else 0.0
                    used_gb = round(used_bytes / (1024 ** 3), 2) if space_ok else 0.0
                    used_pct = round((used_bytes / total_bytes.value * 100), 1) if (space_ok and total_bytes.value > 0) else 0.0

                    logical_volumes.append({
                        "drive_letter": drive_letter,
                        "volume_name": vol_name_buf.value if vol_ok else "",
                        "file_system": fs_name_buf.value if vol_ok else "Unknown",
                        "volume_serial_number": f"{serial_num.value:08X}" if vol_ok else None,
                        "drive_type": drive_type_str,
                        "total_bytes": total_bytes.value if space_ok else 0,
                        "free_bytes": free_bytes.value if space_ok else 0,
                        "used_bytes": used_bytes,
                        "total_gb": total_gb,
                        "free_gb": free_gb,
                        "used_gb": used_gb,
                        "used_percentage": used_pct
                    })
        except Exception:
            pass

        # 3. Summary Classification
        bus_counts = collections.Counter(d["bus_type"] for d in physical_drives)
        summary = {
            "total_physical_drives": len(physical_drives),
            "total_logical_volumes": len(logical_volumes),
            "nvme_drives_count": bus_counts.get("NVMe", 0),
            "sata_drives_count": bus_counts.get("SATA", 0),
            "usb_drives_count": bus_counts.get("USB", 0),
            "bus_type_distribution": dict(bus_counts)
        }

        return {
            "status": "success",
            "epistemic_scope": "STORAGE_BUS_AND_VOLUME_TOPOLOGY",
            "smart_health_analyzed": False,
            "physical_drives": physical_drives,
            "logical_volumes": logical_volumes,
            "summary": summary
        }
