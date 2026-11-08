# -*- coding: utf-8 -*-
"""
Evidence Causality Synthesizer.
Unifies static PE structures, Ghidra High P-Code AST / CFG nodes,
host Windows OS policies, PnP device health, kernel drivers, and empirical crash telemetry
into an interconnected Evidence Graph and authoritative Failure Evidence Dossier.
"""

import os
import sys
from typing import Dict, Any, List, Optional

from binary_neural_engine import BinaryFormatInspector
from .graph_model import EvidenceGraph
from ..os_profiler import WindowsOSProfiler
from ..dependency_resolver import WindowsDependencyResolver
from ..device_inspector import WindowsDeviceInspector
from ..security_inspector import WindowsSecurityInspector
from ..system_introspection import NativeDeviceInspector, KernelDriverInspector
from ..runtime_telemetry import MiniDumpParser, EventLogCollector


class CausalitySynthesizer:
    """
    Synthesizes multi-source forensic evidence into a formal directed Evidence Graph G = (V, E).
    Derives causal paths from low-level memory faults (NULL pointer dereference, DEP violation)
    through Ghidra basic blocks and PE sections to driver and OS compatibility states.
    """

    @classmethod
    def build_evidence_graph(
        cls,
        binary_path: str,
        crash_record: Optional[Dict[str, Any]] = None,
        ghidra_export: Optional[Dict[str, Any]] = None
    ) -> EvidenceGraph:
        """Constructs the comprehensive diagnostic Evidence Graph."""
        graph = EvidenceGraph()
        norm_path = os.path.abspath(binary_path)
        bin_name = os.path.basename(norm_path)
        bin_id = f"TARGET:{bin_name}"

        # 1. Target Binary Node
        pe_info = BinaryFormatInspector.inspect(norm_path)
        img_base_str = pe_info.get("image_base", "0x400000")
        img_base = int(img_base_str, 16) if isinstance(img_base_str, str) else img_base_str

        graph.add_node(
            bin_id,
            node_type="BINARY_TARGET",
            label=bin_name,
            format=pe_info.get("format"),
            image_base=hex(img_base),
            mitigations=pe_info.get("windows_security_mitigations", {})
        )

        # 2. Host OS Node
        os_prof = WindowsOSProfiler.profile(norm_path)
        kernel_info = os_prof.get("kernel", {})
        os_node_id = "HOST_OS"
        graph.add_node(
            os_node_id,
            node_type="HOST_OS",
            label=f"Windows {kernel_info.get('build_number', 'NT')}",
            build_number=kernel_info.get("build_number"),
            is_wow64=kernel_info.get("is_wow64_process"),
            compat_layer=os_prof.get("appcompat_flags", {}).get("applied_layers")
        )
        graph.add_edge(bin_id, os_node_id, relation="HOSTED_ON")

        # 3. PE Sections
        section_nodes = {}
        for sec in pe_info.get("sections", []):
            s_name = sec.get("name", "").strip()
            if not s_name:
                continue
            sec_id = f"SEC:{s_name}"
            va = sec.get("virtual_address", 0)
            va_int = int(va, 16) if isinstance(va, str) else int(va)
            vsize = sec.get("virtual_size", sec.get("raw_size", 0))
            vsize_int = int(vsize, 16) if isinstance(vsize, str) else int(vsize)

            graph.add_node(
                sec_id,
                node_type="PE_SECTION",
                label=s_name,
                virtual_address=hex(va_int),
                virtual_size=vsize_int,
                is_executable=sec.get("is_executable", False),
                is_writable=sec.get("is_writable", False)
            )
            graph.add_edge(bin_id, sec_id, relation="HAS_SECTION")
            section_nodes[s_name] = (va_int, vsize_int, sec_id)

        # 4. Dependency Resolution
        dep_audit = WindowsDependencyResolver.audit_dependencies(norm_path)
        for dll_info in dep_audit.get("resolved_dlls", []):
            dll_name = dll_info.get("imported_name", "")
            if not dll_name:
                continue
            dll_id = f"DLL:{dll_name.lower()}"
            graph.add_node(
                dll_id,
                node_type="IMPORTED_DLL",
                label=dll_name,
                status="RESOLVED",
                disk_path=dll_info.get("resolved_path")
            )
            graph.add_edge(bin_id, dll_id, relation="DEPENDS_ON")

        for miss in dep_audit.get("missing_dlls", []):
            m_name = miss.get("imported_name", "")
            m_id = f"DLL:{m_name.lower()}"
            graph.add_node(
                m_id,
                node_type="IMPORTED_DLL",
                label=m_name,
                status="MISSING",
                severity="CRITICAL"
            )
            graph.add_edge(bin_id, m_id, relation="MISSING_DEPENDENCY")

        # 5. Hardware Subsystems & Kernel Drivers
        hw_audit = NativeDeviceInspector.audit_hardware_health()
        for idx, disp in enumerate(hw_audit.get("display_adapters", [])[:2]):
            disp_id = f"HW:DISPLAY_{idx+1}"
            graph.add_node(
                disp_id,
                node_type="HARDWARE_DEVICE",
                label=disp.get("name", "Display Adapter"),
                device_class="Display",
                has_problem=disp.get("has_problem", False),
                problem_code=disp.get("problem_code", 0),
                problem_name=disp.get("problem_name", "HEALTHY")
            )

        drv_audit = KernelDriverInspector.audit_drivers()
        for gdrv in drv_audit.get("graphics_drivers", [])[:3]:
            drv_id = f"DRV:{gdrv['driver_name'].lower()}"
            graph.add_node(
                drv_id,
                node_type="KERNEL_DRIVER",
                label=gdrv["driver_name"],
                image_base=gdrv.get("kernel_image_base"),
                file_path=gdrv.get("file_path")
            )
            # Link display devices to driver
            for idx in range(min(len(hw_audit.get("display_adapters", [])), 2)):
                graph.add_edge(f"HW:DISPLAY_{idx+1}", drv_id, relation="RESOLVES_TO_DRIVER")

        # 6. Ghidra Decompiled AST & P-Code Basic Blocks
        func_entry_map = {}
        if ghidra_export:
            for func in ghidra_export.get("functions", []):
                fname = func.get("name", "func")
                fentry = func.get("entry_point", "0x0")
                fentry_int = int(fentry, 16) if isinstance(fentry, str) else int(fentry)
                fsize = func.get("size", 0) or 0
                f_id = f"FUNC:{fname}"

                graph.add_node(
                    f_id,
                    node_type="GHIDRA_FUNCTION",
                    label=fname,
                    entry_point=hex(fentry_int),
                    size=fsize
                )
                func_entry_map[f_id] = (fentry_int, fsize)

                # Link enclosing PE section to Ghidra function
                rva = fentry_int - img_base
                for s_name, (va_start, va_size, sec_id) in section_nodes.items():
                    if va_start <= rva < va_start + va_size:
                        graph.add_edge(sec_id, f_id, relation="CONTAINS_FUNCTION")
                        break

                # Basic blocks
                for b in func.get("basic_blocks", []):
                    b_start = b.get("start", "0x0")
                    b_id = f"BLOCK:{fname}_{b_start}"
                    graph.add_node(
                        b_id,
                        node_type="GHIDRA_BASIC_BLOCK",
                        label=f"{fname}[{b_start}]",
                        start=b_start,
                        end=b.get("end")
                    )
                    graph.add_edge(f_id, b_id, relation="CONTAINS_BLOCK")

        # 7. Empirical Crash Telemetry Integration
        if not crash_record:
            # Auto-retrieve from MiniDumps or WER
            dumps = MiniDumpParser.audit_dumps(bin_name, max_dumps=1)
            if dumps.get("crash_reports"):
                rep = dumps["crash_reports"][0]
                exc = rep.get("exception_info") or {}
                crash_record = {
                    "source": "MINIDUMP",
                    "file_path": rep.get("file_path"),
                    "exception_code": exc.get("exception_code"),
                    "exception_name": exc.get("exception_name"),
                    "fault_module": exc.get("fault_module"),
                    "fault_offset": exc.get("fault_offset", "0x0"),
                    "access_violation_details": exc.get("access_violation_details")
                }

        if crash_record:
            crash_id = "CRASH_TELEMETRY"
            exc_code = crash_record.get("exception_code", "UNKNOWN")
            exc_name = crash_record.get("exception_name", "UNKNOWN")
            fault_mod = crash_record.get("fault_module") or bin_name
            raw_offset = crash_record.get("fault_offset", "0x0")
            offset_int = int(raw_offset, 16) if isinstance(raw_offset, str) else int(raw_offset)

            graph.add_node(
                crash_id,
                node_type="CRASH_TELEMETRY",
                label=f"{exc_name} ({exc_code})",
                exception_code=exc_code,
                exception_name=exc_name,
                fault_module=fault_mod,
                fault_offset=hex(offset_int),
                source=crash_record.get("source", "TELEMETRY")
            )
            graph.add_edge(bin_id, crash_id, relation="REPORTED_CRASH")

            # Access Violation Root Cause Node
            av_details = crash_record.get("access_violation_details")
            if av_details:
                root_id = "AV_ROOT_CAUSE"
                graph.add_node(
                    root_id,
                    node_type="ACCESS_VIOLATION_ROOT",
                    label=f"{av_details.get('operation')} @ {av_details.get('target_virtual_address')}",
                    operation=av_details.get("operation"),
                    target_virtual_address=av_details.get("target_virtual_address"),
                    is_null_pointer_dereference=av_details.get("is_null_pointer_dereference", False),
                    cause=av_details.get("probable_cause")
                )
                graph.add_edge(crash_id, root_id, relation="CAUSED_BY_VIOLATION")

            # Map Fault Offset (RVA) to Section
            is_internal = os.path.basename(fault_mod).lower() == bin_name.lower()
            if is_internal:
                for s_name, (va_start, va_size, sec_id) in section_nodes.items():
                    if va_start <= offset_int < va_start + va_size:
                        graph.add_edge(crash_id, sec_id, relation="FALLS_WITHIN_SECTION")
                        break

                # Map to Ghidra Function
                crash_va = img_base + offset_int
                for f_id, (fentry_int, fsize) in func_entry_map.items():
                    if fsize > 0 and fentry_int <= crash_va < fentry_int + fsize:
                        graph.add_edge(crash_id, f_id, relation="FAULTS_INSIDE_FUNCTION")
                        break
            else:
                ext_dll_id = f"DLL:{fault_mod.lower()}"
                if ext_dll_id in graph.nodes:
                    graph.add_edge(crash_id, ext_dll_id, relation="FAULTS_INSIDE_EXTERNAL_DLL")

        return graph

    @classmethod
    def synthesize_dossier(
        cls,
        binary_path: str,
        crash_record: Optional[Dict[str, Any]] = None,
        ghidra_export: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes unified evidence synthesis:
        Builds the formal Evidence Graph, extracts the primary causal path,
        and generates an executive engineering failure dossier.
        """
        norm_path = os.path.abspath(binary_path)
        bin_name = os.path.basename(norm_path)
        graph = cls.build_evidence_graph(norm_path, crash_record=crash_record, ghidra_export=ghidra_export)

        # 1. Evaluate Findings
        verdict = "HEALTHY_ENVIRONMENT"
        severity = "INFO"
        root_cause_points: List[str] = []
        remediation_steps: List[str] = []

        # Check missing dependencies
        missing_dlls = [n for n in graph.nodes.values() if n.node_type == "IMPORTED_DLL" and n.properties.get("status") == "MISSING"]
        if missing_dlls:
            verdict = "MISSING_DLL_DEPENDENCIES"
            severity = "CRITICAL"
            m_names = [n.label for n in missing_dlls]
            root_cause_points.append(f"Application cannot start due to missing runtime libraries: {', '.join(m_names)}.")
            remediation_steps.append("Install required Visual C++ / DirectX redistributable runtimes or place DLLs alongside executable.")

        # Check PnP Hardware Problems
        problem_devs = [n for n in graph.nodes.values() if n.node_type == "HARDWARE_DEVICE" and n.properties.get("has_problem")]
        if problem_devs:
            severity = "HIGH" if severity != "CRITICAL" else severity
            for pd in problem_devs:
                root_cause_points.append(f"Hardware Device '{pd.label}' reported non-zero status code: {pd.properties.get('problem_name')}.")
            remediation_steps.append("Update or reinstall host display/audio drivers to resolve device error state.")

        # Check Crash Telemetry & Access Violation
        crash_node = graph.get_node("CRASH_TELEMETRY")
        av_root = graph.get_node("AV_ROOT_CAUSE")

        if crash_node:
            exc_code = crash_node.properties.get("exception_code")
            exc_name = crash_node.properties.get("exception_name")
            fault_mod = crash_node.properties.get("fault_module")
            fault_rva = crash_node.properties.get("fault_offset")

            is_internal = os.path.basename(fault_mod).lower() == bin_name.lower()
            if is_internal:
                verdict = f"INTERNAL_BINARY_CRASH: {exc_name} ({exc_code})"
                severity = "CRITICAL"
                root_cause_points.append(
                    f"Fatal crash inside '{bin_name}' at RVA {fault_rva} ({exc_name} {exc_code})."
                )
            else:
                verdict = f"EXTERNAL_DEPENDENCY_CRASH: {fault_mod} ({exc_name})"
                severity = "CRITICAL"
                root_cause_points.append(
                    f"Fatal fault inside external module '{fault_mod}' at RVA {fault_rva}."
                )

            if av_root:
                op = av_root.properties.get("operation")
                addr = av_root.properties.get("target_virtual_address")
                is_null = av_root.properties.get("is_null_pointer_dereference")
                if is_null:
                    root_cause_points.append(
                        f"Root Cause Confirmed: NULL Pointer Dereference ({op} at virtual address {addr}). An uninitialized object or null struct pointer was accessed."
                    )
                    remediation_steps.append("Inspect pointer validation preceding the faulting instruction or add a NULL safety guard.")
                else:
                    root_cause_points.append(f"Memory Access Violation: Invalid {op} at unmapped/protected address {addr}.")

        # 2. Extract Causal Path
        causal_chain = []
        if "AV_ROOT_CAUSE" in graph.nodes and f"TARGET:{bin_name}" in graph.nodes:
            causal_chain = graph.find_causal_path(f"TARGET:{bin_name}", "AV_ROOT_CAUSE")

        return {
            "status": "success",
            "binary_path": norm_path,
            "verdict": verdict,
            "severity": severity,
            "root_cause_summary": root_cause_points or ["No critical failure conditions detected in host environment."],
            "remediation_advisory": remediation_steps or ["System and application dependencies are healthy."],
            "causal_chain": causal_chain,
            "evidence_graph": graph.to_dict(),
            "mermaid_diagram": graph.to_mermaid()
        }
