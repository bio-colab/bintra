# -*- coding: utf-8 -*-
"""
Immutable Command Catalog for Windows System Introspection.
Defines strict specifications, whitelisted parameters, build compatibility thresholds,
and schema metadata for read-only Windows commands.
"""

import os
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple


@dataclass(frozen=True)
class CommandSpec:
    """Immutable contract specification for a read-only Windows command."""
    command_id: str
    binary_name: str
    fixed_arguments: Tuple[str, ...]
    allowed_flags: Tuple[str, ...]
    min_windows_build: int
    requires_admin: bool
    timeout_seconds: int
    parser_name: str
    output_schema: str
    description: str


class CommandCatalog:
    """
    Catalog of verified read-only Windows diagnostic commands.
    Prevents arbitrary shell execution by ensuring only pre-approved
    commands and whitelisted argument combinations can be executed.
    """

    CATALOG: Dict[str, CommandSpec] = {
        "os_ver": CommandSpec(
            command_id="os_ver",
            binary_name="cmd.exe",
            fixed_arguments=("/c", "ver"),
            allowed_flags=(),
            min_windows_build=2600,  # Windows XP+
            requires_admin=False,
            timeout_seconds=5,
            parser_name="parse_ver",
            output_schema="windows.ver.v1",
            description="Query canonical kernel version string via cmd /c ver"
        ),
        "sys_info": CommandSpec(
            command_id="sys_info",
            binary_name="systeminfo.exe",
            fixed_arguments=("/fo", "csv"),
            allowed_flags=(),
            min_windows_build=2600,
            requires_admin=False,
            timeout_seconds=25,
            parser_name="parse_csv_records",
            output_schema="windows.systeminfo.v1",
            description="Query comprehensive host hardware, memory, and hotfix configuration"
        ),
        "whoami_privs": CommandSpec(
            command_id="whoami_privs",
            binary_name="whoami.exe",
            fixed_arguments=("/all", "/fo", "csv"),
            allowed_flags=(),
            min_windows_build=6000,  # Windows Vista+
            requires_admin=False,
            timeout_seconds=10,
            parser_name="parse_whoami_csv",
            output_schema="windows.whoami.v1",
            description="Query user SID, group memberships, and token privileges"
        ),
        "proc_list": CommandSpec(
            command_id="proc_list",
            binary_name="tasklist.exe",
            fixed_arguments=("/v", "/fo", "csv"),
            allowed_flags=("/svc",),
            min_windows_build=2600,
            requires_admin=False,
            timeout_seconds=15,
            parser_name="parse_csv_records",
            output_schema="windows.processes.v1",
            description="Enumerate active running processes, window titles, and memory usage"
        ),
        "service_list": CommandSpec(
            command_id="service_list",
            binary_name="sc.exe",
            fixed_arguments=("query", "type=", "service"),
            allowed_flags=("state=", "all", "inactive"),
            min_windows_build=2600,
            requires_admin=False,
            timeout_seconds=15,
            parser_name="parse_sc_query",
            output_schema="windows.services.v1",
            description="Enumerate Windows service instances, state, and win32 exit codes"
        ),
        "driver_list": CommandSpec(
            command_id="driver_list",
            binary_name="driverquery.exe",
            fixed_arguments=("/v", "/fo", "csv"),
            allowed_flags=(),
            min_windows_build=2600,
            requires_admin=False,
            timeout_seconds=20,
            parser_name="parse_csv_records",
            output_schema="windows.drivers.v1",
            description="Query installed kernel drivers, display names, link dates, and memory bases"
        ),
        "pnp_drivers": CommandSpec(
            command_id="pnp_drivers",
            binary_name="pnputil.exe",
            fixed_arguments=("/enum-drivers",),
            allowed_flags=(),
            min_windows_build=10240,  # Modern PnPUtil requires Win10+
            requires_admin=False,
            timeout_seconds=20,
            parser_name="parse_pnputil_drivers",
            output_schema="windows.pnputil.drivers.v1",
            description="Enumerate 3rd-party OEM published driver packages (INF)"
        ),
        "pnp_devices_problem": CommandSpec(
            command_id="pnp_devices_problem",
            binary_name="pnputil.exe",
            fixed_arguments=("/enum-devices", "/problem"),
            allowed_flags=(),
            min_windows_build=10240,
            requires_admin=False,
            timeout_seconds=20,
            parser_name="parse_pnputil_devices",
            output_schema="windows.pnputil.devices.v1",
            description="Enumerate Plug-and-Play devices reporting non-zero problem codes"
        ),
        "boot_cfg": CommandSpec(
            command_id="boot_cfg",
            binary_name="bcdedit.exe",
            fixed_arguments=("/enum", "{current}"),
            allowed_flags=(),
            min_windows_build=6000,
            requires_admin=True,
            timeout_seconds=10,
            parser_name="parse_key_value_blocks",
            output_schema="windows.bcdedit.v1",
            description="Query boot configuration data (TestSigning, NX/DEP policy, SafeBoot)"
        ),
        "power_cfg": CommandSpec(
            command_id="power_cfg",
            binary_name="powercfg.exe",
            fixed_arguments=("/query",),
            allowed_flags=(),
            min_windows_build=2600,
            requires_admin=False,
            timeout_seconds=10,
            parser_name="parse_key_value_blocks",
            output_schema="windows.powercfg.v1",
            description="Query active Windows power scheme and device power management settings"
        )
    }

    @classmethod
    def get_spec(cls, command_id: str) -> Optional[CommandSpec]:
        """Retrieves a command specification by its canonical ID."""
        return cls.CATALOG.get(command_id)

    @classmethod
    def list_available_commands(cls, current_build: Optional[int] = None) -> List[Dict[str, Any]]:
        """Lists registered commands filtered by host OS build compatibility."""
        results = []
        for cmd_id, spec in sorted(cls.CATALOG.items()):
            is_supported = True if current_build is None else (current_build >= spec.min_windows_build)
            results.append({
                "command_id": cmd_id,
                "binary": spec.binary_name,
                "description": spec.description,
                "min_build": spec.min_windows_build,
                "supported": is_supported,
                "requires_admin": spec.requires_admin,
                "output_schema": spec.output_schema
            })
        return results

    @classmethod
    def resolve_executable_path(cls, binary_name: str) -> Optional[str]:
        """Resolves system binary within System32 or standard system paths."""
        windir = os.environ.get("WINDIR", r"C:\Windows")
        sys32 = os.path.join(windir, "System32")
        candidate = os.path.join(sys32, binary_name)
        if os.path.isfile(candidate):
            return candidate

        # Fallback strictly to trusted system directories (SysWOW64, Windows)
        syswow64 = os.path.join(windir, "SysWOW64", binary_name)
        if os.path.isfile(syswow64):
            return syswow64
        win_bin = os.path.join(windir, binary_name)
        if os.path.isfile(win_bin):
            return win_bin
        return None
