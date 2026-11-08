# -*- coding: utf-8 -*-
"""
Driver Package and Driver Store Inventory Engine.
Interrogates the Windows Driver Store and PnPUtil package database to catalog
installed OEM and inbox driver packages (.inf, .cat, .sys).
"""

import os
import glob
from typing import Dict, Any, List, Optional
from ..command_engine.cmd_executor import CommandExecutor


class DriverPackageInventory:
    """
    Interrogates installed Windows driver packages using PnPUtil and Driver Store telemetry.
    Maps published INF filenames (oemXX.inf) to original INF names, providers, versions, and signers.
    """

    @classmethod
    def enumerate_driver_packages(cls) -> List[Dict[str, Any]]:
        """
        Enumerates all third-party and inbox driver packages registered in the Windows Driver Store.
        Uses CommandExecutor('pnp_drivers') without shell=True.
        """
        res = CommandExecutor.execute("pnp_drivers")
        if res.get("status") != "success":
            return []

        raw_packages = res.get("data", [])
        packages = []

        for p in raw_packages:
            pub_name = p.get("published_name", "")
            orig_name = p.get("original_name", "")
            provider = p.get("provider_name", "")
            cls_name = p.get("class_name", "")
            driver_date = p.get("driver_date_and_version", "")
            signer = p.get("signer_name", "")

            # Parse date and version if combined
            d_date = None
            d_ver = None
            if driver_date:
                parts = [x.strip() for x in driver_date.split("/") if x.strip()]
                if len(parts) >= 2:
                    d_date = parts[0]
                    d_ver = parts[1]
                else:
                    d_ver = driver_date

            packages.append({
                "published_name": pub_name,
                "original_name": orig_name,
                "provider_name": provider,
                "class_name": cls_name,
                "driver_date": d_date,
                "driver_version": d_ver,
                "signer_name": signer,
                "is_whql_signed": bool(signer and "microsoft" in signer.lower())
            })

        return packages

    @classmethod
    def find_driver_package_by_name(cls, inf_name_or_keyword: str) -> List[Dict[str, Any]]:
        """Searches driver packages by published name (e.g. oem12.inf) or original name."""
        kw = inf_name_or_keyword.lower().strip()
        matches = []
        for p in cls.enumerate_driver_packages():
            pub = p.get("published_name", "").lower()
            orig = p.get("original_name", "").lower()
            prov = p.get("provider_name", "").lower()
            if kw in pub or kw in orig or kw in prov:
                matches.append(p)
        return matches
