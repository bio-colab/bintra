# -*- coding: utf-8 -*-
"""
Centralized configuration and policy constants for Bintra Security Kernel & Audit.

Separates static security policies, catalogs, path defaults, and tuning knobs
from runtime enforcement logic.
"""

import math
import os
import re
import tempfile
from typing import Dict, Pattern, Tuple

BINTRA_DIR_NAME = ".bintra"
GHIDRA_BRIDGE_MARKER_FILENAME = ".bintra_bridge.json"
AUDIT_REDACTED_MARKER = "***REDACTED***"

SUBPROCESS_DEFAULT_TIMEOUT_SEC = 15
SUBPROCESS_MAX_OUTPUT_BYTES = 10 * 1024 * 1024
SUBPROCESS_MAX_STDERR_BYTES = 2 * 1024 * 1024
SUBPROCESS_STREAM_CHUNK_BYTES = 8192

DEFAULT_AUDIT_SEGMENT_MAX_BYTES = 2 * 1024 * 1024

AUDIT_SENSITIVE_PATTERNS: Tuple[Pattern[str], ...] = (
    re.compile(
        r"(password|passwd|pwd|secret|token|bearer|apikey|api_key)=([^&\s]+)",
        re.IGNORECASE,
    ),
    re.compile(r"(--password|--token|--key|--secret)\s+([^\s]+)", re.IGNORECASE),
)

FORBIDDEN_CREDENTIAL_MARKERS: Tuple[str, ...] = (
    "\\windows\\system32\\config\\sam",
    "\\windows\\system32\\config\\security",
    "\\windows\\system32\\config\\system",
    "\\windows\\system32\\config\\default",
    "\\windows\\ntds\\ntds.dit",
    "\\windows\\repair\\sam",
    "\\windows\\repair\\security",
    "\\windows\\repair\\system",
)

POSIX_PROTECTED_SYSTEM_DIRS: Tuple[str, ...] = (
    "/bin",
    "/sbin",
    "/usr",
    "/etc",
    "/lib",
    "/lib64",
    "/boot",
    "/root",
    "/dev",
    "/proc",
    "/sys",
)

SUBPROCESS_CATALOG: Dict[str, Dict[str, object]] = {
    "os_ver": {
        "exe": "cmd.exe",
        "base_args": ["/c", "ver"],
        "allowed_flags": [],
        "risk": "read_only",
    },
    "system_info": {
        "exe": "systeminfo.exe",
        "base_args": ["/fo", "csv"],
        "allowed_flags": [],
        "risk": "read_only",
    },
    "task_list": {
        "exe": "tasklist.exe",
        "base_args": ["/v", "/fo", "csv"],
        "allowed_flags": ["/fi", "/m"],
        "risk": "read_only",
    },
    "driver_list": {
        "exe": "driverquery.exe",
        "base_args": ["/v", "/fo", "csv"],
        "allowed_flags": ["/si"],
        "risk": "read_only",
    },
    "pnp_drivers": {
        "exe": "pnputil.exe",
        "base_args": ["/enum-drivers"],
        "allowed_flags": [],
        "risk": "read_only",
    },
    "pnp_devices": {
        "exe": "pnputil.exe",
        "base_args": ["/enum-devices", "/problem"],
        "allowed_flags": ["/connected", "/disconnected"],
        "risk": "read_only",
    },
    "service_query": {
        "exe": "sc.exe",
        "base_args": ["query", "type=", "service", "state=", "all"],
        "allowed_flags": ["bufsize="],
        "risk": "read_only",
    },
    "driver_service_query": {
        "exe": "sc.exe",
        "base_args": ["query", "type=", "driver", "state=", "all"],
        "allowed_flags": ["bufsize="],
        "risk": "read_only",
    },
    "whoami": {
        "exe": "whoami.exe",
        "base_args": ["/all", "/fo", "csv"],
        "allowed_flags": ["/priv", "/groups", "/user"],
        "risk": "read_only",
    },
    "fltmc_filters": {
        "exe": "fltmc.exe",
        "base_args": ["filters"],
        "allowed_flags": ["instances"],
        "risk": "read_only",
    },
    "event_query": {
        "exe": "wevtutil.exe",
        "base_args": ["qe"],
        "allowed_flags": [
            "Application",
            "System",
            "Security",
            "/q:",
            "/c:",
            "/rd:",
            "/f:",
        ],
        "risk": "read_only",
    },
}

# Declarative capability matrix keyed by component name. Entries are resolved
# into Capability members inside CapabilityRegistry at import time to preserve an
# acyclic dependency graph while keeping policy configuration out of code.
DEFAULT_COMPONENT_CAPABILITY_NAMES: Dict[str, Tuple[str, ...]] = {
    # Safe Gateways
    "safe_file_access": ("FILE_READ", "WORKSPACE_WRITE", "WORKSPACE_TEMP_CLEAN"),
    "safe_registry_access": ("REGISTRY_READ",),
    "safe_process_access": ("PROCESS_QUERY",),
    "safe_subprocess": ("SUBPROCESS_CATALOG_EXEC",),
    # System Introspection Providers
    "deobfuscator": ("FILE_READ",),
    "function_matcher": ("FILE_READ",),
    "pe_deep_forensics": ("FILE_READ", "FILE_HASH"),
    "device_inspector": ("DEVICE_QUERY", "DRIVER_QUERY"),
    "driver_inspector": ("DRIVER_QUERY",),
    "process_inspector": ("PROCESS_QUERY",),
    "virtual_memory_inspector": ("PROCESS_QUERY",),
    "service_inspector": ("SERVICE_QUERY",),
    "registry_reader": ("REGISTRY_READ",),
    "event_collector": ("EVENT_LOG_READ",),
    "etw_capture_engine": ("EVENT_LOG_READ",),
    "ghidra_live_bridge": ("FILE_READ", "WORKSPACE_WRITE", "TEMPDIR_MARKER_WRITE"),
    "minidump_parser": ("MINIDUMP_READ", "FILE_READ"),
    "crash_rca_engine": ("MINIDUMP_READ", "FILE_READ"),
    "command_executor": ("SUBPROCESS_CATALOG_EXEC",),
    "cmd_executor": ("SUBPROCESS_CATALOG_EXEC",),
    "powershell_executor": ("SUBPROCESS_CATALOG_EXEC",),
    # Mutation / Surgery Engines (Confined to Authorized Workspace Only)
    "binary_patcher": ("WORKSPACE_WRITE",),
    "weight_patcher": ("WORKSPACE_WRITE",),
    # Intelligence Engines
    "analysis_orchestrator": ("FILE_READ", "FILE_HASH", "MINIDUMP_READ"),
    "evidence_engine": ("FILE_READ", "WORKSPACE_WRITE"),
    "causality_synthesizer": ("FILE_READ", "WORKSPACE_WRITE"),
    "device_intelligence": ("DEVICE_QUERY", "DRIVER_QUERY"),
    "signature_intelligence": ("FILE_READ", "DRIVER_QUERY", "DEVICE_QUERY"),
    "process_intelligence": ("PROCESS_QUERY", "FILE_READ"),
    "python_intelligence": ("FILE_READ",),
    "registry_editor": ("REGISTRY_READ", "WORKSPACE_WRITE", "FILE_READ"),
    "ghidra_headless": (
        "GHIDRA_HEADLESS_EXEC",
        "GHIDRA_PROJECT_MUTATE",
        "FILE_READ",
        "WORKSPACE_WRITE",
        "WORKSPACE_TEMP_CLEAN",
    ),
    "ghidra_analyzer": ("FILE_READ", "WORKSPACE_WRITE", "WORKSPACE_TEMP_CLEAN"),
    "ghidra_export_store": ("FILE_READ", "WORKSPACE_WRITE", "WORKSPACE_TEMP_CLEAN"),
    "binary_diff": ("FILE_READ",),
    # High-Level Invocation Interfaces
    "mcp_server": (
        "FILE_READ",
        "FILE_HASH",
        "WORKSPACE_WRITE",
        "REGISTRY_READ",
        "PROCESS_QUERY",
        "SERVICE_QUERY",
        "DEVICE_QUERY",
        "DRIVER_QUERY",
        "EVENT_LOG_READ",
        "MINIDUMP_READ",
        "SUBPROCESS_CATALOG_EXEC",
        "GHIDRA_HEADLESS_EXEC",
        "GHIDRA_PROJECT_MUTATE",
        "WORKSPACE_TEMP_CLEAN",
    ),
    "cli": (
        "FILE_READ",
        "FILE_HASH",
        "WORKSPACE_WRITE",
        "REGISTRY_READ",
        "PROCESS_QUERY",
        "SERVICE_QUERY",
        "DEVICE_QUERY",
        "DRIVER_QUERY",
        "EVENT_LOG_READ",
        "MINIDUMP_READ",
        "SUBPROCESS_CATALOG_EXEC",
        "GHIDRA_HEADLESS_EXEC",
        "GHIDRA_PROJECT_MUTATE",
        "WORKSPACE_TEMP_CLEAN",
    ),
    # Test Fixtures & Internal Testing
    "test_suite": (
        "FILE_READ",
        "FILE_HASH",
        "WORKSPACE_WRITE",
        "WORKSPACE_TEMP_CLEAN",
        "REGISTRY_READ",
        "PROCESS_QUERY",
        "SUBPROCESS_CATALOG_EXEC",
        "GHIDRA_HEADLESS_EXEC",
        "GHIDRA_PROJECT_MUTATE",
    ),
    "sec_test": (
        "FILE_READ",
        "WORKSPACE_WRITE",
        "WORKSPACE_TEMP_CLEAN",
        "SUBPROCESS_CATALOG_EXEC",
    ),
}


def default_bintra_home() -> str:
    """Returns the per-user Bintra home directory (~/.bintra)."""
    user_home = os.path.expanduser("~")
    if not user_home or user_home == "~":
        user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or tempfile.gettempdir()
    return os.path.join(user_home, BINTRA_DIR_NAME)


def default_workspace_dir() -> str:
    """Returns the default sandboxed workspace directory."""
    return os.path.join(default_bintra_home(), "workspace")


def default_ghidra_projects_dir() -> str:
    """Returns the default directory for transient Ghidra projects."""
    return os.path.join(default_workspace_dir(), "ghidra_projects")


def default_audit_log_dir() -> str:
    """Returns the default directory for tamper-evident audit logs."""
    return os.path.join(default_bintra_home(), "logs")


def default_audit_log_file() -> str:
    """Returns the default active audit journal path."""
    return os.path.join(default_audit_log_dir(), "audit.jsonl")


def default_ghidra_bridge_marker_path() -> str:
    """Returns the strict expected path for the Ghidra bridge discovery marker."""
    return os.path.join(tempfile.gettempdir(), GHIDRA_BRIDGE_MARKER_FILENAME)


def windows_protected_system_dirs() -> Tuple[str, ...]:
    """Returns protected Windows OS directories unsuitable as mutable workspaces."""
    return (
        os.environ.get("SystemRoot", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("ProgramData", r"C:\ProgramData"),
    )


def resolve_audit_segment_max_bytes() -> int:
    """Parses BINTRA_AUDIT_SEGMENT_MB safely, falling back to 2 MiB on invalid values."""
    raw = os.environ.get("BINTRA_AUDIT_SEGMENT_MB", "2")
    try:
        mb = float(raw)
    except ValueError:
        return DEFAULT_AUDIT_SEGMENT_MAX_BYTES
    if not math.isfinite(mb) or mb < 0:
        return DEFAULT_AUDIT_SEGMENT_MAX_BYTES
    return int(mb * 1024 * 1024)


def resolve_winreg_hive_map() -> Dict[str, int]:
    """Resolves canonical Windows Registry hive handles, with cross-platform fallbacks."""
    try:
        import winreg

        return {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        }
    except ImportError:
        return {
            "HKLM": 0x80000002,
            "HKEY_LOCAL_MACHINE": 0x80000002,
            "HKCU": 0x80000001,
            "HKEY_CURRENT_USER": 0x80000001,
            "HKCR": 0x80000000,
            "HKEY_CLASSES_ROOT": 0x80000000,
        }
