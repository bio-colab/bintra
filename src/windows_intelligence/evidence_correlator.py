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
        6. Maps Fault Offset to PE section and Ghidra decompilation function/P-Code.
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
            crash_record = reports[0] if reports else (events[0] if events else None)

        # 3. Static Binary Mapping
        pe_info = BinaryFormatInspector.inspect(norm_path)
        binary_mapping = None

        if crash_record and pe_info.get("format") == "PE":
            fault_offset_str = crash_record.get("fault_offset", "0x0")
            try:
                fault_offset = int(fault_offset_str, 16) if isinstance(fault_offset_str, str) else int(fault_offset_str)
            except ValueError:
                fault_offset = 0

            # Determine faulting section
            target_sec = None
            for sec in pe_info.get("sections", []):
                s_off = int(sec["raw_offset"])
                s_size = int(sec["raw_size"])
                if s_off <= fault_offset < s_off + s_size:
                    target_sec = sec
                    break

            rva = BinaryFormatInspector.offset_to_rva(pe_info, fault_offset)
            image_base = int(pe_info.get("image_base", "0x400000"), 16)
            va = (image_base + rva) if rva is not None else None

            binary_mapping = {
                "fault_offset": hex(fault_offset),
                "fault_rva": hex(rva) if rva is not None else None,
                "fault_virtual_address": hex(va) if va is not None else None,
                "fault_section": target_sec["name"] if target_sec else "UNMAPPED_SPACE",
                "is_executable_section": target_sec.get("is_executable", False) if target_sec else False
            }

            # Map into Ghidra Decompiled Functions if available
            if ghidra_export and va is not None:
                functions = ghidra_export.get("functions", [])
                matching_func = None
                for func in functions:
                    try:
                        f_entry = int(func.get("entry_point", "0x0"), 16)
                        # Estimate function range if not given
                        f_ops = func.get("pcode_ops", [])
                        if f_ops:
                            first_addr = int(f_ops[0].get("address", "0x0"), 16)
                            last_addr = int(f_ops[-1].get("address", "0x0"), 16)
                            if first_addr <= va <= max(last_addr, first_addr + 4096):
                                matching_func = func
                                break
                    except Exception:
                        continue

                if matching_func:
                    binary_mapping["ghidra_function_name"] = matching_func.get("name")
                    binary_mapping["ghidra_function_entry"] = matching_func.get("entry_point")

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
            verdict = f"CRASH_TELEMETRY_RECORDED: {crash_record.get('exception_name', 'UNKNOWN')}"
            severity = "CRITICAL"
            root_cause_points.append(
                f"Empirical crash recorded: {crash_record.get('exception_code')} ({crash_record.get('exception_name')}) "
                f"at module '{crash_record.get('fault_module')}' offset {crash_record.get('fault_offset')}."
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
                f"- **Fault Offset:** `{crash.get('fault_offset')}`"
            ])

        # Binary Mapping
        mapping = dossier.get("binary_mapping")
        if mapping:
            lines.extend([
                "",
                "## 4. Static Binary & Ghidra IR Correlation",
                f"- **Section:** `{mapping.get('fault_section')}` (Executable: {mapping.get('is_executable_section')})",
                f"- **Relative Virtual Address (RVA):** `{mapping.get('fault_rva')}`",
                f"- **Virtual Address (VA):** `{mapping.get('fault_virtual_address')}`",
            ])
            if mapping.get("ghidra_function_name"):
                lines.append(f"- **Ghidra Function:** `{mapping.get('ghidra_function_name')}` (Entry: `{mapping.get('ghidra_function_entry')}`)")

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
