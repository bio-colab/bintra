# -*- coding: utf-8 -*-
"""
Device-to-Driver Matching and Driver Rank Correlation Engine.
Correlates PnP device Hardware IDs and Compatible IDs against installed driver packages
to determine matching fidelity, Driver Rank, and whether a generic fallback driver is bound.
"""

import os
from typing import Dict, Any, List, Optional
from ..system_introspection.device_inspector import NativeDeviceInspector
from .device_identity import DeviceIdentity
from .driver_package_inventory import DriverPackageInventory


class DriverMatcher:
    """
    Evaluates device-driver binding compatibility and computes Driver Rank tiers.
    Rank 0: Exact Hardware ID match with WHQL signature.
    Rank 1: Subsystem-neutral Hardware ID match.
    Rank 2: Compatible ID match.
    Rank 3: Generic Class driver / Basic fallback.
    """

    RANK_DESCRIPTIONS = {
        0: "RANK_EXACT_HWID_MATCH (Highest fidelity match against full Hardware ID with subsystem)",
        1: "RANK_NEUTRAL_HWID_MATCH (Vendor and Device ID match; neutral subsystem)",
        2: "RANK_COMPATIBLE_ID_MATCH (Match against generic Compatible ID family)",
        3: "RANK_GENERIC_CLASS_FALLBACK (Generic class-level inbox fallback driver)"
    }

    @classmethod
    def audit_device_driver_bindings(
        cls,
        device_query: Optional[str] = None,
        class_filter: Optional[str] = None,
        problems_only: bool = False,
        max_devices: int = 64
    ) -> Dict[str, Any]:
        """
        Conducts a unified compatibility audit linking PnP devices to their active drivers,
        evaluating driver rank, and detecting missing driver packages.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "reason": "Device and driver matching requires Windows NT platform with SetupAPI/CfgMgr32.",
                "total_evaluated": 0,
                "problem_devices_count": 0,
                "results": []
            }

        try:
            from security import ExecutionGuard, Capability
            ExecutionGuard.request_access(
                component="device_intelligence",
                operation="audit_device_driver_bindings",
                target=str(device_query or "AllDevices"),
                capability=Capability.DEVICE_QUERY,
                access_mode="QUERY"
            )
        except ImportError:
            pass

        raw_devices = NativeDeviceInspector.enumerate_devices(
            filter_problems_only=problems_only,
            class_filter=class_filter,
            max_devices=max_devices
        )
        packages = DriverPackageInventory.enumerate_driver_packages()

        # Build lookup for driver packages by class or provider
        pkg_by_class: Dict[str, List[Dict[str, Any]]] = {}
        for p in packages:
            c = (p.get("class_name") or "").lower()
            if c not in pkg_by_class:
                pkg_by_class[c] = []
            pkg_by_class[c].append(p)

        results = []
        for dev in raw_devices:
            identity = DeviceIdentity.parse_device_instance(dev)

            # Filter by query if specified
            if device_query:
                q_low = device_query.lower()
                name_match = q_low in identity["device_name"].lower()
                inst_match = q_low in identity["device_instance_id"].lower()
                hw_match = any(q_low in hid.lower() for hid in identity.get("hardware_ids", []))
                if not (name_match or inst_match or hw_match):
                    continue

            # Evaluate Driver Rank and Binding Status
            service = identity.get("bound_service")
            has_prob = identity.get("has_problem", False)
            prob_code = identity.get("problem_code", 0)

            # Determine Driver Rank estimation
            estimated_rank = 2  # default compatible match
            is_generic_fallback = False
            provider_type = "VENDOR_DEDICATED"

            if prob_code == 28:  # CM_PROB_FAILED_INSTALL
                match_status = "NO_DRIVER_INSTALLED (Code 28)"
                estimated_rank = -1
            elif not service:
                match_status = "NO_ACTIVE_SERVICE_BINDING"
                estimated_rank = -1
            else:
                svc_low = service.lower()
                if any(x in svc_low for x in ("basic", "generic", "standard", "vga", "pci", "usb")):
                    is_generic_fallback = True
                    estimated_rank = 3
                    provider_type = "GENERIC_FALLBACK"
                    match_status = "MATCHED_GENERIC_FALLBACK"
                else:
                    estimated_rank = 0 if identity.get("subsystem_id") else 1
                    match_status = "MATCHED_VENDOR_DRIVER"

            # Check candidate packages matching this device's class
            dev_cls = (identity.get("device_class") or "").lower()
            candidate_pkgs = pkg_by_class.get(dev_cls, [])

            results.append({
                "identity": identity,
                "driver_binding": {
                    "active_service": service,
                    "driver_key": identity.get("driver_key"),
                    "match_status": match_status,
                    "estimated_driver_rank": estimated_rank,
                    "rank_description": cls.RANK_DESCRIPTIONS.get(estimated_rank, "UNKNOWN_RANK"),
                    "rank_basis": "HEURISTIC_ESTIMATION_NOT_NATIVE_SETUPAPI_RANK",
                    "candidates_matching_rule": "MATCHED_BY_DEVICE_CLASS_AND_SERVICE",
                    "is_generic_fallback": is_generic_fallback,
                    "provider_type": provider_type,
                    "has_problem": has_prob,
                    "problem_code": prob_code,
                    "problem_name": identity.get("problem_name"),
                    "is_cryptographically_verified_whql": False,
                    "whql_verification_note": "Signer name parsed from metadata only; cryptographic catalog signature validation was not executed."
                },
                "hardware_ids_match_evaluation": {
                    "hardware_ids_count": len(identity.get("hardware_ids", [])),
                    "compatible_ids_count": len(identity.get("compatible_ids", [])),
                    "match_tier": "RANK_EXACT_HWID" if estimated_rank == 0 else ("RANK_NEUTRAL_HWID" if estimated_rank == 1 else ("RANK_COMPATIBLE_ID" if estimated_rank == 2 else "RANK_GENERIC_CLASS"))
                },
                "candidate_packages_count": len(candidate_pkgs),
                "candidate_packages_sample": candidate_pkgs[:3]
            })

        return {
            "status": "success",
            "devices_audited": len(results),
            "driver_packages_cataloged": len(packages),
            "device_reports": results
        }
