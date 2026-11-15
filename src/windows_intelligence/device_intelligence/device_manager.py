# -*- coding: utf-8 -*-
"""
Windows Device Manager Telemetry and Deep Hardware Introspection.
Provides comprehensive parity with devmgmt.msc:
1. Hierarchical Class Categorization (Friendly view matching Device Manager).
2. Driver Registry Binding Extraction (Version, Date, Provider, InfPath, Section).
3. Live Device Enumeration with Status & Diagnostic Problem Codes (CM_PROB_*).
4. Multi-Field Instant Device Search (Names, IDs, Class, Vendor, Driver, Service).
5. Comprehensive Device Properties Dossier (General, Driver, Hardware IDs, Topology).

Zero external dependencies: uses Python standard library, ctypes, and winreg.
Degrades gracefully on non-Windows NT environments.
"""

import os
import sys
from typing import Dict, Any, List, Optional

try:
    import winreg
except ImportError:
    winreg = None


class DeviceManagerInspector:
    """
    Direct interface to Windows Device Manager data structures and kernel device tree.
    Extracts PnP device nodes, driver store details, hardware identifiers, and bus locations.
    """

    FRIENDLY_CLASS_NAMES: Dict[str, str] = {
        "AudioEndpoint": "Audio inputs and outputs",
        "AudioProcessingObject": "Audio Processing Objects",
        "Battery": "Batteries",
        "Biometric": "Biometric devices",
        "Bluetooth": "Bluetooth",
        "Camera": "Cameras",
        "Computer": "Computer",
        "CVAULT": "ControlVault Devices",
        "DiskDrive": "Disk drives",
        "Display": "Display adapters",
        "Firmware": "Firmware",
        "HDC": "IDE ATA/ATAPI controllers",
        "HIDClass": "Human Interface Devices",
        "Image": "Imaging devices",
        "Keyboard": "Keyboards",
        "MEDIA": "Sound, video and game controllers",
        "Monitor": "Monitors",
        "Mouse": "Mice and other pointing devices",
        "MTD": "Memory technology devices",
        "Net": "Network adapters",
        "PrintQueue": "Print queues",
        "Printer": "Printers",
        "Processor": "Processors",
        "Proximity": "Proximity devices",
        "SCSIAdapter": "Storage controllers",
        "SecurityDevices": "Security devices",
        "SmartCardFilter": "Smart card filters",
        "SmartCardReader": "Smart card readers",
        "SoftwareComponent": "Software components",
        "SoftwareDevice": "Software devices",
        "System": "System devices",
        "UCM": "USB Connector Managers",
        "USB": "Universal Serial Bus controllers",
        "Volume": "Storage volumes",
    }

    @classmethod
    def _is_windows(cls) -> bool:
        return os.name == "nt"

    @classmethod
    def _get_winreg(cls):
        return winreg if cls._is_windows() else None

    @classmethod
    def _get_driver_registry_info(cls, driver_key: Optional[str]) -> Dict[str, Any]:
        """
        Reads driver version, release date, provider, and INF metadata
        from HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\<driver_key>.
        """
        result: Dict[str, Any] = {
            "driver_version": None,
            "driver_date": None,
            "provider_name": None,
            "inf_path": None,
            "inf_section": None,
            "matching_device_id": None,
            "driver_desc": None,
        }
        if not driver_key or not cls._is_windows():
            return result

        reg = cls._get_winreg()
        if not reg:
            return result

        try:
            full_path = rf"SYSTEM\CurrentControlSet\Control\Class\{driver_key}"
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, full_path) as k:
                for reg_field, res_field in [
                    ("DriverVersion", "driver_version"),
                    ("DriverDate", "driver_date"),
                    ("ProviderName", "provider_name"),
                    ("InfPath", "inf_path"),
                    ("InfSection", "inf_section"),
                    ("MatchingDeviceId", "matching_device_id"),
                    ("DriverDesc", "driver_desc"),
                ]:
                    try:
                        val, _ = reg.QueryValueEx(k, reg_field)
                        result[res_field] = str(val).strip() if val is not None else None
                    except (FileNotFoundError, OSError):
                        pass
        except (FileNotFoundError, OSError, PermissionError):
            pass

        return result

    @classmethod
    def get_friendly_class_name(cls, class_name: Optional[str]) -> str:
        """Returns the canonical English friendly name for a device class."""
        if not class_name:
            return "Other devices"
        return cls.FRIENDLY_CLASS_NAMES.get(class_name, f"{class_name} devices")

    @classmethod
    def get_device_classes(cls) -> Dict[str, Any]:
        """
        Returns all device classes with device counts, problem counts, and friendly names.
        Mirrors the default tree view of devmgmt.msc.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "DeviceManagerInspector requires Windows NT.",
                "total_classes": 0,
                "total_devices": 0,
                "classes": []
            }

        from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
        raw_devices = NativeDeviceInspector.enumerate_devices(max_devices=4096)

        class_map: Dict[str, Dict[str, Any]] = {}
        total_problems = 0
        total_unknown = 0

        for d in raw_devices:
            c_name = d.get("class") or "Other"
            has_prob = bool(d.get("has_problem")) or (d.get("problem_code", 0) > 0)
            status_avail = d.get("status_available", True)
            prob_desc = d.get("problem_description", "")
            is_unknown = (not status_avail) or ("Status Unavailable" in prob_desc) or (d.get("problem_name") == "CM_PROB_STATUS_UNAVAILABLE")

            if has_prob:
                status_cat = "problem"
                total_problems += 1
            elif is_unknown:
                status_cat = "unknown"
                total_unknown += 1
            else:
                status_cat = "healthy"

            if c_name not in class_map:
                class_map[c_name] = {
                    "class_name": c_name,
                    "friendly_name": cls.get_friendly_class_name(c_name),
                    "device_count": 0,
                    "problem_count": 0,
                    "unknown_count": 0,
                    "healthy_count": 0,
                    "devices": []
                }

            class_map[c_name]["device_count"] += 1
            if status_cat == "problem":
                class_map[c_name]["problem_count"] += 1
            elif status_cat == "unknown":
                class_map[c_name]["unknown_count"] += 1
            else:
                class_map[c_name]["healthy_count"] += 1

            class_map[c_name]["devices"].append({
                "device_instance_id": d.get("device_instance_id"),
                "name": d.get("name"),
                "status_classification": status_cat,
                "has_problem": has_prob,
                "problem_code": d.get("problem_code", 0),
                "is_started": d.get("is_started", False),
            })

        sorted_classes = sorted(class_map.values(), key=lambda x: x["friendly_name"].lower())

        return {
            "status": "success",
            "platform": sys.platform,
            "total_classes": len(sorted_classes),
            "total_devices": len(raw_devices),
            "total_problems": total_problems,
            "total_unknown": total_unknown,
            "classes": sorted_classes
        }

    @classmethod
    def list_devices(
        cls,
        class_filter: Optional[str] = None,
        problems_only: bool = False,
        limit: int = 200
    ) -> Dict[str, Any]:
        """
        Lists live PnP devices enriched with driver store metadata,
        bus locations, and Configuration Manager status codes.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "DeviceManagerInspector requires Windows NT.",
                "total_devices": 0,
                "matched_count": 0,
                "devices": []
            }

        from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
        raw_devices = NativeDeviceInspector.enumerate_devices(
            filter_problems_only=problems_only,
            class_filter=class_filter,
            max_devices=4096
        )

        enriched: List[Dict[str, Any]] = []
        for d in raw_devices:
            driver_info = cls._get_driver_registry_info(d.get("driver_key"))
            cls_name = d.get("class") or "Other"

            item = {
                "device_instance_id": d.get("device_instance_id"),
                "name": d.get("name"),
                "friendly_name": d.get("friendly_name"),
                "description": d.get("description"),
                "class": cls_name,
                "class_friendly": cls.get_friendly_class_name(cls_name),
                "driver_version": driver_info.get("driver_version"),
                "driver_date": driver_info.get("driver_date"),
                "driver_provider": driver_info.get("provider_name") or d.get("manufacturer"),
                "inf_path": driver_info.get("inf_path"),
                "matching_device_id": driver_info.get("matching_device_id"),
                "hardware_id": d.get("hardware_id"),
                "location": d.get("location_information"),
                "bus_enumerator": d.get("bus_enumerator"),
                "service": d.get("service"),
                "is_started": d.get("is_started", False),
                "has_problem": d.get("has_problem", False),
                "problem_code": d.get("problem_code", 0),
                "problem_name": d.get("problem_name", "CM_PROB_OK"),
                "problem_description": d.get("problem_description", "Healthy"),
                "pdo_name": d.get("pdo_name"),
                "parent_device_id": d.get("parent_device_id"),
            }
            enriched.append(item)

        total_matched = len(enriched)
        if limit and limit > 0:
            enriched = enriched[:limit]

        return {
            "status": "success",
            "platform": sys.platform,
            "total_devices": len(raw_devices),
            "matched_count": total_matched,
            "class_filter": class_filter,
            "problems_only": problems_only,
            "limit": limit,
            "devices": enriched
        }

    @classmethod
    def search_devices(cls, query: str, limit: int = 50) -> Dict[str, Any]:
        """
        Instant search across device names, instance IDs, hardware IDs,
        driver versions, vendors, services, and bus locations.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "DeviceManagerInspector requires Windows NT.",
                "query": query,
                "matched_count": 0,
                "devices": []
            }

        q = (query or "").strip().lower()
        if not q:
            return cls.list_devices(limit=limit)

        from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
        raw_devices = NativeDeviceInspector.enumerate_devices(max_devices=4096)

        matches: List[Dict[str, Any]] = []
        for d in raw_devices:
            # Check fields
            name = (d.get("name") or "").lower()
            friendly = (d.get("friendly_name") or "").lower()
            desc = (d.get("description") or "").lower()
            inst_id = (d.get("device_instance_id") or "").lower()
            hw_id = (d.get("hardware_id") or "").lower()
            hw_ids = " ".join(d.get("hardware_ids") or []).lower()
            cls_name = (d.get("class") or "").lower()
            service = (d.get("service") or "").lower()
            mfg = (d.get("manufacturer") or "").lower()
            loc = (d.get("location_information") or "").lower()
            bus = (d.get("bus_enumerator") or "").lower()

            hit = False
            match_field = ""
            for field_val, field_name in [
                (name, "name"),
                (friendly, "friendly_name"),
                (desc, "description"),
                (inst_id, "instance_id"),
                (hw_id, "hardware_id"),
                (hw_ids, "hardware_ids"),
                (cls_name, "class"),
                (service, "service"),
                (mfg, "manufacturer"),
                (loc, "location"),
                (bus, "bus_enumerator"),
            ]:
                if q in field_val:
                    hit = True
                    match_field = field_name
                    break

            if not hit:
                # Check driver registry
                driver_info = cls._get_driver_registry_info(d.get("driver_key"))
                d_ver = (driver_info.get("driver_version") or "").lower()
                d_prov = (driver_info.get("provider_name") or "").lower()
                d_inf = (driver_info.get("inf_path") or "").lower()
                if q in d_ver or q in d_prov or q in d_inf:
                    hit = True
                    match_field = "driver_info"

            if hit:
                driver_info = cls._get_driver_registry_info(d.get("driver_key"))
                c_name = d.get("class") or "Other"
                matches.append({
                    "device_instance_id": d.get("device_instance_id"),
                    "name": d.get("name"),
                    "match_field": match_field,
                    "class": c_name,
                    "class_friendly": cls.get_friendly_class_name(c_name),
                    "driver_version": driver_info.get("driver_version"),
                    "driver_date": driver_info.get("driver_date"),
                    "driver_provider": driver_info.get("provider_name") or d.get("manufacturer"),
                    "inf_path": driver_info.get("inf_path"),
                    "hardware_id": d.get("hardware_id"),
                    "location": d.get("location_information"),
                    "bus_enumerator": d.get("bus_enumerator"),
                    "service": d.get("service"),
                    "is_started": d.get("is_started", False),
                    "has_problem": d.get("has_problem", False),
                    "problem_code": d.get("problem_code", 0),
                    "problem_name": d.get("problem_name", "CM_PROB_OK"),
                    "problem_description": d.get("problem_description", "Healthy"),
                })

        total_matched = len(matches)
        if limit and limit > 0:
            matches = matches[:limit]

        return {
            "status": "success",
            "platform": sys.platform,
            "query": query,
            "matched_count": total_matched,
            "limit": limit,
            "devices": matches
        }

    @classmethod
    def get_device_details(cls, device_id_or_name: str) -> Dict[str, Any]:
        """
        Retrieves the complete Device Manager Properties Sheet for a specific device,
        including General, Driver, Hardware IDs, Status Diagnostics, and Topology.
        """
        if not cls._is_windows():
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "DeviceManagerInspector requires Windows NT.",
                "query": device_id_or_name,
                "device": None
            }

        q = (device_id_or_name or "").strip().lower()
        if not q:
            return {"status": "error", "error": "device_id_or_name is required"}

        from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
        raw_devices = NativeDeviceInspector.enumerate_devices(max_devices=4096)

        target = None
        # 1. Exact match on device_instance_id
        for d in raw_devices:
            if (d.get("device_instance_id") or "").lower() == q:
                target = d
                break

        # 2. Exact match on name
        if not target:
            for d in raw_devices:
                if (d.get("name") or "").lower() == q:
                    target = d
                    break

        # 3. Substring match on device_instance_id
        if not target:
            for d in raw_devices:
                if q in (d.get("device_instance_id") or "").lower():
                    target = d
                    break

        # 4. Substring match on name or friendly name
        if not target:
            for d in raw_devices:
                if q in (d.get("name") or "").lower() or q in (d.get("friendly_name") or "").lower():
                    target = d
                    break

        if not target:
            return {
                "status": "not_found",
                "query": device_id_or_name,
                "error": f"Device matching '{device_id_or_name}' was not found in active PnP tree."
            }

        driver_info = cls._get_driver_registry_info(target.get("driver_key"))
        c_name = target.get("class") or "Other"

        return {
            "status": "success",
            "platform": sys.platform,
            "query": device_id_or_name,
            "device": {
                "general": {
                    "name": target.get("name"),
                    "friendly_name": target.get("friendly_name"),
                    "description": target.get("description"),
                    "class": c_name,
                    "class_guid": target.get("class_guid"),
                    "class_friendly": cls.get_friendly_class_name(c_name),
                    "manufacturer": target.get("manufacturer"),
                    "location": target.get("location_information"),
                    "bus_enumerator": target.get("bus_enumerator"),
                    "pdo_name": target.get("pdo_name"),
                    "service": target.get("service"),
                },
                "status_diagnostics": {
                    "is_started": target.get("is_started", False),
                    "has_problem": target.get("has_problem", False),
                    "problem_code": target.get("problem_code", 0),
                    "problem_name": target.get("problem_name", "CM_PROB_OK"),
                    "problem_description": target.get("problem_description", "Healthy"),
                    "status_available": target.get("status_available", True),
                },
                "driver": {
                    "driver_version": driver_info.get("driver_version"),
                    "driver_date": driver_info.get("driver_date"),
                    "provider_name": driver_info.get("provider_name") or target.get("manufacturer"),
                    "inf_path": driver_info.get("inf_path"),
                    "inf_section": driver_info.get("inf_section"),
                    "matching_device_id": driver_info.get("matching_device_id"),
                    "driver_desc": driver_info.get("driver_desc"),
                    "driver_key": target.get("driver_key"),
                },
                "hardware_ids": {
                    "primary_hardware_id": target.get("hardware_id"),
                    "all_hardware_ids": target.get("hardware_ids") or [],
                    "compatible_ids": target.get("compatible_ids") or [],
                },
                "topology": {
                    "device_instance_id": target.get("device_instance_id"),
                    "devnode_handle": target.get("devnode_handle"),
                    "parent_devnode": target.get("parent_devnode"),
                    "parent_device_id": target.get("parent_device_id"),
                }
            }
        }
