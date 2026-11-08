# -*- coding: utf-8 -*-
"""
Failure Evidence Correlation Engine.
Cross-correlates Windows OS telemetry, crash records (WER/EventLog), and dependency health
with static PE sections and Ghidra High P-Code decompilation to establish root-cause diagnoses.
"""

import os
import sys
from typing import Dict, Any, List, Optional

sys_path_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if sys_path_dir not in sys.path:
    sys.path.insert(0, sys_path_dir)

from binary_neural_engine import BinaryFormatInspector
from .os_profiler import WindowsOSProfiler
from .dependency_resolver import WindowsDependencyResolver
from .device_inspector import WindowsDeviceInspector
from .security_inspector import WindowsSecurityInspector
from .crash_analyzer import WindowsCrashAnalyzer


class DiagnosticEvidenceCorrelator:
    """
    Correlates runtime failure evidence with static binary structure.
    Answers: 'What occurred inside Windows, and what exact binary construct caused it?'
    Ensures strict semantic correctness: FaultingOffset is treated as an RVA,
    and external module crashes are distinguished from target binary code faults.
    """

    @classmethod
    def correlate(
        cls,
        binary_path: str,
        crash_record: Optional[Dict[str, Any]] = None,
        ghidra_export: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end failure evidence correlation:
        1. Profiles Host OS & Compatibility Shims.
        2. Resolves DLL Dependencies and verifies exports.
        3. Inspects GPU / DirectX runtime capabilities.
        4. Audits Token Integrity and directory write ACLs.
        5. Collects or processes crash records (ExceptionCode, FaultOffset, FaultModule).
        6. Verifies fault module identity and maps RVA to PE section and Ghidra functions.
        7. Synthesizes an authoritative Failure Evidence Dossier.
        """
        norm_path = os.path.abspath(binary_path)

        # 1. Environmental Telemetry
        os_data = WindowsOSProfiler.profile(norm_path)
        dep_data = WindowsDependencyResolver.audit_dependencies(norm_path)
        hw_data = WindowsDeviceInspector.audit()
        sec_data = WindowsSecurityInspector.audit(norm_path)

        # 2. Crash Telemetry (either passed or scanned)
        if not crash_record:
            crash_collection = WindowsCrashAnalyzer.collect_crash_evidence(norm_path)
            reports = crash_collection.get("wer_reports", [])
            events = crash_collection.get("event_log_errors", [])
            dumps = crash_collection.get("minidumps", [])

            if reports:
                crash_record = reports[0]
            elif events:
                crash_record = events[0]
            elif dumps and dumps[0].get("exception_info"):
                exc_inf = dumps[0]["exception_info"]
                crash_record = {
                    "source": "MINIDUMP",
                    "file_path": dumps[0]["file"],
                    "app_name": os.path.basename(norm_path),
                    "fault_module": exc_inf.get("fault_module") or os.path.basename(norm_path),
                    "exception_code": exc_inf.get("exception_code"),
                    "exception_name": exc_inf.get("exception_name"),
                    "fault_offset": exc_inf.get("fault_offset", "0x0")
                }

        # 3. Static Binary Mapping with Strict Module Attribution
        pe_info = BinaryFormatInspector.inspect(norm_path)
        binary_mapping = None
        target_name = os.path.basename(norm_path).lower()

        is_internal_fault = False
        raw_fault_module = ""
        fault_offset = 0

        if crash_record:
            raw_fault_module = (crash_record.get("fault_module") or "").strip()
            fault_offset_str = crash_record.get("fault_offset", "0x0")
            try:
                fault_offset = int(fault_offset_str, 16) if isinstance(fault_offset_str, str) else int(fault_offset_str)
            except ValueError:
                fault_offset = 0

            # Check if fault module matches target executable
            if raw_fault_module:
                is_internal_fault = (target_name == os.path.basename(raw_fault_module).lower())
            else:
                is_internal_fault = True

        if crash_record and pe_info.get("format") == "PE":
            if is_internal_fault:
                # In Windows crash telemetry, FaultingOffset is the Relative Virtual Address (RVA)
                fault_rva = fault_offset
                image_base = int(pe_info.get("image_base", "0x400000"), 16)
                va = image_base + fault_rva
                file_offset = BinaryFormatInspector.rva_to_offset(pe_info, fault_rva)

                def _to_int(val):
                    if isinstance(val, int):
                        return val
                    if isinstance(val, str):
                        v = val.strip()
                        if v.startswith("0x") or v.startswith("0X"):
                            return int(v, 16)
                        return int(v) if v.isdigit() else 0
                    return 0

                # Locate section matching the RVA
                target_sec = None
                for sec in pe_info.get("sections", []):
                    va_start = _to_int(sec.get("virtual_address", 0))
                    va_size = max(_to_int(sec.get("virtual_size", 0)), _to_int(sec.get("raw_size", 0)))
                    if va_start <= fault_rva < va_start + va_size:
                        target_sec = sec
                        break

                binary_mapping = {
                    "is_internal_fault": True,
                    "target_module": os.path.basename(norm_path),
                    "fault_rva": hex(fault_rva),
                    "fault_virtual_address": hex(va),
                    "file_offset": hex(file_offset) if file_offset is not None else None,
                    "fault_section": target_sec["name"] if target_sec else "UNMAPPED_RVA_SPACE",
                    "is_executable_section": target_sec.get("is_executable", False) if target_sec else False
                }

                # Map into Ghidra Decompiled Functions using true instruction / block bounds
                if ghidra_export and va is not None:
                    functions = ghidra_export.get("functions", [])
                    matching_func = None
                    for func in functions:
                        try:
                            f_entry = int(func.get("entry_point", "0x0"), 16)
                            f_size = func.get("size")
                            if f_size is not None and isinstance(f_size, int) and f_size > 0:
                                if f_entry <= va < f_entry + f_size:
                                    matching_func = func
                                    break

                            # Check basic block bounds if exported
                            blocks = func.get("basic_blocks", [])
                            if blocks:
                                b_starts = [int(b["start"], 16) for b in blocks if "start" in b]
                                b_ends = [
                                    int(b["end"], 16) if "end" in b else (int(b["start"], 16) + int(b.get("size", 1)))
                                    for b in blocks if "start" in b
                                ]
                                if b_starts and min(b_starts) <= va <= max(b_ends):
                                    matching_func = func
                                    break

                            # Check exact instruction / pcode addresses without arbitrary expansion
                            f_ops = func.get("pcode_ops", [])
                            if f_ops:
                                op_addrs = [int(op["address"], 16) for op in f_ops if "address" in op]
                                if op_addrs and min(op_addrs) <= va <= max(op_addrs):
                                    matching_func = func
                                    break

                            if f_entry == va:
                                matching_func = func
                                break
                        except Exception:
                            continue

                    if matching_func:
                        binary_mapping["ghidra_function_name"] = matching_func.get("name")
                        binary_mapping["ghidra_function_entry"] = matching_func.get("entry_point")
            else:
                # External module failure: crash occurred inside third-party or system runtime
                binary_mapping = {
                    "is_internal_fault": False,
                    "target_module": os.path.basename(norm_path),
                    "external_fault_module": raw_fault_module,
                    "fault_rva": hex(fault_offset),
                    "attribution": "EXTERNAL_DEPENDENCY_OR_SYSTEM_MODULE"
                }

        # 4. Synthesize Root Cause Verdict & Remediation Advisory
        verdict = "HEALTHY_ENVIRONMENT"
        severity = "INFO"
        root_cause_points = []
        remediation_steps = []

        if dep_data.get("missing_dlls_count", 0) > 0:
            missing_names = [d["imported_name"] for d in dep_data.get("missing_dlls", [])]
            verdict = "MISSING_DLL_DEPENDENCIES"
            severity = "CRITICAL"
            root_cause_points.append(f"Missing required dynamic libraries: {', '.join(missing_names)}")
            remediation_steps.append("Install the required runtime packages or place the missing DLLs in the application directory.")

        if dep_data.get("architecture_mismatches_count", 0) > 0:
            verdict = "ARCHITECTURE_MISMATCH_FAILURE"
            severity = "CRITICAL"
            root_cause_points.append("Application attempted to load a dynamic library compiled for an incompatible CPU architecture (e.g. 64-bit DLL into 32-bit process).")
            remediation_steps.append("Replace the mismatched libraries with binaries matching the application's native architecture.")

        if sec_data.get("directory_write_permissions", {}).get("is_writable") is False:
            if sec_data["directory_write_permissions"].get("is_program_files_path"):
                root_cause_points.append("Target resides in 'Program Files' but current security token lacks write permission. Application may fail when creating logs or save state.")
                remediation_steps.append("Launch application with administrative elevation or enable Windows UAC Directory Virtualization.")

        if crash_record:
            exc_name = crash_record.get("exception_name", "UNKNOWN_EXCEPTION")
            if is_internal_fault:
                verdict = f"CRASH_TELEMETRY_RECORDED: {exc_name}"
                severity = "CRITICAL"
                root_cause_points.append(
                    f"Empirical crash recorded in target '{target_name}': {crash_record.get('exception_code')} ({exc_name}) "
                    f"at RVA {hex(fault_offset)}."
                )
            else:
                verdict = f"EXTERNAL_MODULE_CRASH: {raw_fault_module} ({exc_name})"
                severity = "CRITICAL"
                root_cause_points.append(
                    f"Empirical fault did NOT originate within '{target_name}' code sections. "
                    f"The crash occurred inside external module '{raw_fault_module}' at RVA {hex(fault_offset)} "
                    f"({crash_record.get('exception_code')} {exc_name})."
                )
                remediation_steps.append(
                    f"Audit calls from '{target_name}' to '{raw_fault_module}'. Verify compatible graphics runtimes, "
                    f"Direct3D device initialization, or patch invalid pointer parameters passed across the DLL boundary."
                )

        dossier = {
            "status": "success",
            "binary_path": norm_path,
            "verdict": verdict,
            "severity": severity,
            "root_cause_summary": root_cause_points or ["No critical failure conditions detected in host Windows environment."],
            "remediation_advisory": remediation_steps or ["System and application dependencies are healthy."],
            "os_environment": os_data,
            "dependency_health": dep_data,
            "graphics_and_hardware": hw_data,
            "security_and_privileges": sec_data,
            "crash_telemetry": crash_record,
            "binary_mapping": binary_mapping
        }

        return dossier

    @classmethod
    def format_markdown(cls, dossier: Dict[str, Any]) -> str:
        """Renders the Failure Evidence Dossier as an executive Markdown report."""
        lines = [
            "# REA-Neural Failure Evidence Dossier",
            "",
            f"**Target Binary:** `{dossier.get('binary_path')}`  ",
            f"**Diagnosis Verdict:** `{dossier.get('verdict')}`  ",
            f"**Severity Level:** `{dossier.get('severity')}`  ",
            "",
            "## 1. Root Cause Summary",
        ]
        for rc in dossier.get("root_cause_summary", []):
            lines.append(f"- {rc}")

        lines.extend([
            "",
            "## 2. Engineering Remediation Advisory",
        ])
        for rem in dossier.get("remediation_advisory", []):
            lines.append(f"1. {rem}")

        # Crash Telemetry
        crash = dossier.get("crash_telemetry")
        if crash:
            lines.extend([
                "",
                "## 3. Crash Telemetry & Exception Details",
                f"- **Source:** `{crash.get('source')}`",
                f"- **Exception Code:** `{crash.get('exception_code')}` ({crash.get('exception_name')})",
                f"- **Faulting Module:** `{crash.get('fault_module')}`",
                f"- **Fault Offset (RVA):** `{crash.get('fault_offset')}`"
            ])

        # Binary Mapping
        mapping = dossier.get("binary_mapping")
        if mapping:
            lines.extend([
                "",
                "## 4. Static Binary & Ghidra IR Correlation"
            ])
            if mapping.get("is_internal_fault"):
                lines.extend([
                    f"- **Faulting Section:** `{mapping.get('fault_section')}` (Executable: {mapping.get('is_executable_section')})",
                    f"- **Relative Virtual Address (RVA):** `{mapping.get('fault_rva')}`",
                    f"- **Virtual Address (VA):** `{mapping.get('fault_virtual_address')}`",
                    f"- **Raw File Offset:** `{mapping.get('file_offset')}`",
                ])
                if mapping.get("ghidra_function_name"):
                    lines.append(f"- **Ghidra Function:** `{mapping.get('ghidra_function_name')}` (Entry: `{mapping.get('ghidra_function_entry')}`)")
            else:
                lines.extend([
                    "- **Attribution:** External Dependency / System Runtime",
                    f"- **External Module:** `{mapping.get('external_fault_module')}`",
                    f"- **External RVA:** `{mapping.get('fault_rva')}`",
                    f"- **Notice:** Fault did not occur within `{mapping.get('target_module')}` static code boundaries."
                ])

        # Dependencies
        deps = dossier.get("dependency_health", {})
        lines.extend([
            "",
            "## 5. Dependency Resolution Matrix",
            f"- **Architecture:** `{deps.get('binary_architecture')}` ({deps.get('loader_mode')})",
            f"- **Resolved DLLs:** {deps.get('resolved_dlls_count')}/{deps.get('total_imported_dlls')}",
            f"- **Missing DLLs:** {deps.get('missing_dlls_count')}",
            f"- **Architecture Mismatches:** {deps.get('architecture_mismatches_count')}",
            f"- **Missing Exported Symbols:** {deps.get('missing_exports_count')}"
        ])

        # OS & Hardware
        os_env = dossier.get("os_environment", {})
        kernel = os_env.get("kernel", {})
        lines.extend([
            "",
            "## 6. Host Windows Environment & Hardware",
            f"- **OS:** {kernel.get('friendly_name', 'Windows')} (Build {kernel.get('build_number', 'Unknown')})",
            f"- **Architecture:** {os_env.get('architecture', {}).get('native_architecture', 'Unknown')}",
            f"- **Elevation:** Admin={dossier.get('security_and_privileges', {}).get('is_elevated_admin')}"
        ])

        return "\n".join(lines)
