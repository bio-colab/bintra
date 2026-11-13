# -*- coding: utf-8 -*-
"""
Driver Package and Driver Store Inventory Engine.
Interrogates the Windows Driver Store and PnPUtil package database to catalog
installed OEM and inbox driver packages (.inf, .cat, .sys).
"""

import os
import glob
import re
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
                "is_whql_signed": bool(signer and "microsoft" in signer.lower()),
                "declared_signer_name": signer,
                "declared_microsoft_signer": bool(signer and "microsoft" in signer.lower()),
                "is_cryptographically_verified_whql": False
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

    @classmethod
    def parse_inf_text(cls, inf_text: str, source_name: str = "offline.inf") -> Dict[str, Any]:
        """Cross-platform offline parser for Windows .inf driver setup files."""
        class_match = re.search(r"^\s*Class\s*=\s*([^;\r\n]+)", inf_text, re.MULTILINE | re.IGNORECASE)
        provider_match = re.search(r"^\s*Provider\s*=\s*([^;\r\n]+)", inf_text, re.MULTILINE | re.IGNORECASE)
        ver_match = re.search(r"^\s*DriverVer\s*=\s*([^;\r\n]+)", inf_text, re.MULTILINE | re.IGNORECASE)
        cat_match = re.search(r"^\s*CatalogFile(?:\.NT\w*)?\s*=\s*([^;\r\n]+)", inf_text, re.MULTILINE | re.IGNORECASE)

        # Resolve %Token% from [Strings] section
        strings_map: Dict[str, str] = {}
        in_strings = False
        for line in inf_text.splitlines():
            stripped = line.split(";", 1)[0].strip()
            if not stripped:
                continue
            if stripped.startswith("[") and stripped.endswith("]"):
                in_strings = stripped.lower() == "[strings]"
                continue
            if in_strings and "=" in stripped:
                k, v = stripped.split("=", 1)
                strings_map[k.strip().lower()] = v.strip().strip('"')

        def _resolve(val: Optional[str]) -> Optional[str]:
            if not val:
                return None
            v = val.strip().strip('"')
            if v.startswith("%") and v.endswith("%"):
                return strings_map.get(v[1:-1].lower(), v)
            return v

        hwid_matches = re.findall(
            r"((?:PCI|USB|HDAUDIO|HID|ACPI|SCSI|NVME|SWD|BTHENUM)\\[A-Za-z0-9_&\\-]+)",
            inf_text,
            re.IGNORECASE,
        )
        hardware_ids = sorted({h.upper() for h in hwid_matches})

        driver_date, driver_version = None, None
        if ver_match:
            parts = [x.strip() for x in ver_match.group(1).split(",")]
            if len(parts) >= 1:
                driver_date = parts[0]
            if len(parts) >= 2:
                driver_version = parts[1]

        return {
            "source": source_name,
            "class_name": _resolve(class_match.group(1)) if class_match else None,
            "provider_name": _resolve(provider_match.group(1)) if provider_match else None,
            "driver_date": driver_date,
            "driver_version": driver_version,
            "catalog_file": _resolve(cat_match.group(1)) if cat_match else None,
            "hardware_ids": hardware_ids,
        }

    @classmethod
    def parse_offline_inf(cls, inf_path: str) -> Dict[str, Any]:
        """Reads and parses an .inf driver file cross-platform (UTF-16/UTF-8/Latin-1)."""
        with open(inf_path, "rb") as f:
            raw = f.read(1024 * 1024)
        if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
            text = raw.decode("utf-16", errors="ignore")
        else:
            text = raw.decode("utf-8", errors="ignore")
        return cls.parse_inf_text(text, source_name=os.path.basename(inf_path))
