# -*- coding: utf-8 -*-
"""
Typed Structured Output Parsers for Windows Command Engine.
Transforms unformatted text, CSV, and XML output into normalized JSON schemas.
"""

import re
import csv
import io
from typing import Dict, Any, List, Optional


class OutputParsers:
    """Standardized parsers for Windows diagnostic utility outputs."""

    @classmethod
    def parse_csv_records(cls, raw_output: str) -> List[Dict[str, Any]]:
        """Parses standard CSV output (e.g. from tasklist /fo csv, driverquery /fo csv)."""
        if not raw_output or not raw_output.strip():
            return []

        cleaned = raw_output.strip()
        f = io.StringIO(cleaned)
        reader = csv.DictReader(f)
        records = []
        for row in reader:
            normalized = {}
            for k, v in row.items():
                if k:
                    clean_k = k.strip().lower().replace(" ", "_").replace("/", "_").replace("#", "num")
                    normalized[clean_k] = (v.strip() if v else "")
            records.append(normalized)
        return records

    @classmethod
    def parse_ver(cls, raw_output: str) -> Dict[str, Any]:
        """Parses output from 'cmd /c ver' to extract OS version and build."""
        clean = raw_output.strip()
        match = re.search(r"Version\s+([\d\.]+)", clean, re.IGNORECASE)
        build_match = re.search(r"(\d+)\.([\d\.]+)$", clean)
        return {
            "raw_string": clean,
            "version": match.group(1) if match else clean,
            "build": build_match.group(2) if build_match else None
        }

    @classmethod
    def parse_whoami_csv(cls, raw_output: str) -> Dict[str, Any]:
        """
        Parses complex multi-table CSV output from 'whoami /all /fo csv':
        Extracts User Info, Group Memberships, and Security Privileges.
        """
        if not raw_output:
            return {}

        lines = [line.strip() for line in raw_output.strip().splitlines() if line.strip()]
        sections: Dict[str, List[Dict[str, str]]] = {
            "user_info": [],
            "groups": [],
            "privileges": []
        }

        current_header = None
        current_rows = []

        for line in lines:
            # Check for header rows
            if "User Name" in line and "SID" in line:
                current_header = "user_info"
                continue
            elif "Group Name" in line and "Type" in line:
                current_header = "groups"
                continue
            elif "Privilege Name" in line and "Description" in line:
                current_header = "privileges"
                continue

            if current_header and line.startswith('"'):
                f = io.StringIO(line)
                row = next(csv.reader(f), [])
                if current_header == "user_info" and len(row) >= 2:
                    sections["user_info"].append({"user_name": row[0], "sid": row[1]})
                elif current_header == "groups" and len(row) >= 4:
                    sections["groups"].append({
                        "group_name": row[0], "type": row[1], "sid": row[2], "attributes": row[3]
                    })
                elif current_header == "privileges" and len(row) >= 3:
                    sections["privileges"].append({
                        "privilege_name": row[0], "description": row[1], "state": row[2]
                    })

        return {
            "user": sections["user_info"][0] if sections["user_info"] else None,
            "groups_count": len(sections["groups"]),
            "groups": sections["groups"],
            "privileges_count": len(sections["privileges"]),
            "privileges": sections["privileges"]
        }

    @classmethod
    def parse_sc_query(cls, raw_output: str) -> List[Dict[str, Any]]:
        """Parses output from 'sc query type= service' into structured service definitions."""
        if not raw_output:
            return []

        services = []
        current: Dict[str, Any] = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("SERVICE_NAME:"):
                if current:
                    services.append(current)
                current = {"service_name": line.split(":", 1)[1].strip()}
            elif ":" in line and current:
                k, v = line.split(":", 1)
                clean_k = k.strip().lower()
                clean_v = v.strip()
                if clean_k == "display_name":
                    current["display_name"] = clean_v
                elif clean_k == "type":
                    current["type"] = clean_v
                elif clean_k == "state":
                    current["state"] = clean_v
                elif clean_k == "win32_exit_code":
                    current["win32_exit_code"] = clean_v

        if current:
            services.append(current)
        return services

    @classmethod
    def parse_pnputil_drivers(cls, raw_output: str) -> List[Dict[str, Any]]:
        """Parses output from 'pnputil /enum-drivers' into driver package definitions."""
        if not raw_output:
            return []

        packages = []
        current: Dict[str, str] = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    packages.append(current)
                    current = {}
                continue

            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip().lower().replace(" ", "_")
                v_clean = v.strip()
                current[k_clean] = v_clean

        if current:
            packages.append(current)
        return packages

    @classmethod
    def parse_pnputil_devices(cls, raw_output: str) -> List[Dict[str, Any]]:
        """Parses output from 'pnputil /enum-devices /problem' to extract faulting devices."""
        if not raw_output:
            return []

        devices = []
        current: Dict[str, str] = {}

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    devices.append(current)
                    current = {}
                continue

            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip().lower().replace(" ", "_")
                v_clean = v.strip()
                current[k_clean] = v_clean

        if current:
            devices.append(current)
        return devices

    @classmethod
    def parse_key_value_blocks(cls, raw_output: str) -> Dict[str, Any]:
        """Parses colon-separated key-value blocks (used for bcdedit, powercfg)."""
        if not raw_output:
            return {}

        results: Dict[str, Any] = {}
        for line in raw_output.splitlines():
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                k = parts[0].strip().lower().replace(" ", "_")
                v = parts[1].strip()
                results[k] = v
        return results

    @classmethod
    def dispatch_parser(cls, parser_name: str, raw_output: str) -> Any:
        """Dispatches raw output to the corresponding parser method."""
        method = getattr(cls, parser_name, None)
        if method and callable(method):
            return method(raw_output)
        return {"raw_text": raw_output}
