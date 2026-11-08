# -*- coding: utf-8 -*-
"""
Rich Hardware Device Identity Parser.
Extracts structured bus topologies, vendor IDs, device IDs, subsystem descriptors,
and revision numbers from Windows Device Instance IDs and Hardware IDs.
"""

import re
from typing import Dict, Any, List, Optional


KNOWN_PCI_VENDORS = {
    "8086": "Intel Corporation",
    "10DE": "NVIDIA Corporation",
    "1002": "Advanced Micro Devices, Inc. (AMD / ATI)",
    "1022": "Advanced Micro Devices, Inc. (AMD)",
    "10EC": "Realtek Semiconductor Corp.",
    "14E4": "Broadcom Inc.",
    "168C": "Qualcomm Atheros",
    "1043": "ASUSTeK Computer Inc.",
    "1028": "Dell Inc.",
    "103C": "HP Inc.",
    "17AA": "Lenovo",
    "1B21": "ASMedia Technology Inc.",
    "1D6A": "Aquantia Corp.",
    "15B7": "Sandisk Corp / Western Digital",
    "144D": "Samsung Electronics Co Ltd"
}

KNOWN_USB_VENDORS = {
    "046D": "Logitech, Inc.",
    "0BDA": "Realtek Semiconductor Corp.",
    "045E": "Microsoft Corp.",
    "04E8": "Samsung Electronics Co., Ltd",
    "05AC": "Apple, Inc.",
    "0489": "Foxconn / Hon Hai Precision Ind. Co., Ltd.",
    "0CF3": "Qualcomm Atheros Communications",
    "8087": "Intel Corp.",
    "1532": "Razer USA, Ltd.",
    "1B1C": "Corsair Memory, Inc.",
    "0955": "NVIDIA Corp.",
    "03F0": "HP Inc.",
    "17EF": "Lenovo"
}


class DeviceIdentity:
    """
    Parses canonical Windows Device Instance IDs and Hardware ID arrays
    into typed bus architectures, vendor profiles, and device hardware signatures.
    """

    @classmethod
    def parse_device_instance(cls, device_record: Any) -> Dict[str, Any]:
        """
        Parses a device record or instance ID string into an authoritative
        hardware identity specification.
        """
        if isinstance(device_record, str):
            device_record = {"device_instance_id": device_record}
        inst_id = device_record.get("device_instance_id", "")
        hw_ids = device_record.get("hardware_ids", [])
        compat_ids = device_record.get("compatible_ids", [])
        cls_name = device_record.get("class", "Unknown")
        dev_name = device_record.get("name", "Unknown Device")

        # Determine Bus Type
        bus_type = "UNKNOWN"
        parts = inst_id.split("\\", 1)
        if parts:
            bus_type = parts[0].upper()

        vendor_id = None
        device_id = None
        subsys_id = None
        revision = None
        vendor_name = None

        # Inspect Hardware IDs for PCI / USB signatures
        all_ids = (hw_ids or []) + [inst_id]
        for hid in all_ids:
            hid_upper = hid.upper()
            if "PCI\\" in hid_upper or "VEN_" in hid_upper:
                bus_type = "PCI"
                v_m = re.search(r"VEN_([0-9A-F]{4})", hid_upper)
                d_m = re.search(r"DEV_([0-9A-F]{4})", hid_upper)
                s_m = re.search(r"SUBSYS_([0-9A-F]{8})", hid_upper)
                r_m = re.search(r"REV_([0-9A-F]{2})", hid_upper)
                if v_m and not vendor_id:
                    vendor_id = v_m.group(1)
                    vendor_name = KNOWN_PCI_VENDORS.get(vendor_id)
                if d_m and not device_id:
                    device_id = d_m.group(1)
                if s_m and not subsys_id:
                    subsys_id = s_m.group(1)
                if r_m and not revision:
                    revision = r_m.group(1)
                if vendor_id and device_id:
                    break
            elif "USB\\" in hid_upper or "VID_" in hid_upper:
                bus_type = "USB"
                v_m = re.search(r"VID_([0-9A-F]{4})", hid_upper)
                p_m = re.search(r"PID_([0-9A-F]{4})", hid_upper)
                r_m = re.search(r"REV_([0-9A-F]{4})", hid_upper)
                if v_m and not vendor_id:
                    vendor_id = v_m.group(1)
                    vendor_name = KNOWN_USB_VENDORS.get(vendor_id)
                if p_m and not device_id:
                    device_id = p_m.group(1)
                if r_m and not revision:
                    revision = r_m.group(1)
                if vendor_id and device_id:
                    break
            elif "HDAUDIO\\" in hid_upper:
                bus_type = "HDAUDIO"
            elif "ACPI\\" in hid_upper:
                bus_type = "ACPI"
            elif "HID\\" in hid_upper:
                bus_type = "HID"
            elif "BTH\\" in hid_upper or "BTHENUM\\" in hid_upper:
                bus_type = "BLUETOOTH"

        return {
            "device_name": dev_name,
            "device_class": cls_name,
            "device_instance_id": inst_id,
            "bus_type": bus_type,
            "vendor_id": vendor_id,
            "vendor_name": vendor_name or device_record.get("manufacturer") or "Unknown Vendor",
            "device_id": device_id,
            "subsystem_id": subsys_id,
            "revision": revision,
            "primary_hardware_id": hw_ids[0] if hw_ids else None,
            "hardware_ids_count": len(hw_ids),
            "hardware_ids": hw_ids,
            "compatible_ids_count": len(compat_ids),
            "compatible_ids": compat_ids,
            "bound_service": device_record.get("service"),
            "driver_key": device_record.get("driver_key"),
            "has_problem": device_record.get("has_problem", False),
            "problem_code": device_record.get("problem_code", 0),
            "problem_name": device_record.get("problem_name", "HEALTHY")
        }
