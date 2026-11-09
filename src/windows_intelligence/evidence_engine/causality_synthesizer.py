# -*- coding: utf-8 -*-
"""
Evidence Causality Synthesizer.
Unifies static PE structures, Ghidra High P-Code AST / CFG nodes,
host Windows OS policies, PnP device health, kernel drivers, and empirical crash telemetry
into an interconnected Evidence Graph and authoritative Failure Evidence Dossier.
Implements strict epistemic rigor: partitioning findings into FACTS, OBSERVATIONS, and HYPOTHESES.
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
    Maintains strict separation between verified empirical Facts, environmental Observations,
    and diagnostic Hypotheses.
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

        # 5. Hardware Subsystems & Kernel Drivers (strictly correlated, no blind mesh)
        hw_audit = NativeDeviceInspector.audit_hardware_health()
        drv_audit = KernelDriverInspector.audit_drivers()

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

        for gdrv in drv_audit.get("graphics_drivers", [])[:4]:
            drv_name = gdrv["driver_name"].lower()
            drv_id = f"DRV:{drv_name}"
            graph.add_node(
                drv_id,
                node_type="KERNEL_DRIVER",
                label=gdrv["driver_name"],
                image_base=gdrv.get("kernel_image_base"),
                file_path=gdrv.get("file_path")
            )
            # Strictly correlate display device with driver via service name or vendor matching
            for idx, disp in enumerate(hw_audit.get("display_adapters", [])[:2]):
                disp_id = f"HW:DISPLAY_{idx+1}"
                disp_name = disp.get("name", "").lower()
                disp_srv = disp.get("service_name", "").lower() if disp.get("service_name") else ""
                correlated = False
                if disp_srv and disp_srv in drv_name:
                    correlated = True
                elif any(v in disp_name and v in drv_name for v in ("nvidia", "intel", "amd", "ati", "vmware", "vbox")):
                    correlated = True
                if correlated:
                    graph.add_edge(disp_id, drv_id, relation="RESOLVES_TO_DRIVER")

        # 5.1 Process & Resource Intelligence: File Locks and Active Instances
        try:
            from ..process_intelligence import FileUsageInspector, ProcessInventory
            locks = FileUsageInspector.inspect_file_locks(norm_path)
            if locks.get("is_locked"):
                for proc in locks.get("locking_processes", []):
                    lock_pid = proc.get("process_id")
                    lock_id = f"LOCK:{lock_pid}"
                    graph.add_node(
                        lock_id,
                        node_type="FILE_LOCK",
                        label=f"Locked by: {proc.get('app_name', 'PID')} ({lock_pid})",
                        process_id=lock_pid,
                        app_name=proc.get("app_name")
                    )
                    graph.add_edge(bin_id, lock_id, relation="LOCKED_BY")

            active_procs = ProcessInventory.find_processes_by_file(norm_path)
            for ap in active_procs:
                ap_pid = ap.get("process_id")
                proc_id = f"PROC:{ap_pid}"
                graph.add_node(
                    proc_id,
                    node_type="RUNNING_INSTANCE",
                    label=f"Running: {ap.get('exe_name', bin_name)} ({ap_pid})",
                    process_id=ap_pid,
                    parent_process_id=ap.get("parent_process_id")
                )
                graph.add_edge(bin_id, proc_id, relation="RUNNING_AS")
        except Exception:
            pass

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

                # Basic blocks supporting start, end, stop, and size
                for b in func.get("basic_blocks", []):
                    b_start = b.get("start", "0x0")
                    b_id = f"BLOCK:{fname}_{b_start}"
                    b_end = b.get("end") or b.get("stop")
                    b_size = b.get("size")
                    graph.add_node(
                        b_id,
                        node_type="GHIDRA_BASIC_BLOCK",
                        label=f"{fname}[{b_start}]",
                        start=b_start,
                        end=b_end,
                        size=b_size
                    )
                    graph.add_edge(f_id, b_id, relation="CONTAINS_BLOCK")

        # 7. Empirical Crash Telemetry Integration (without presumptive fallback)
        if not crash_record:
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
                    "access_violation_details": exc.get("access_violation_details"),
                    "thread_context": exc.get("thread_context")
                }

        if crash_record:
            crash_id = "CRASH_TELEMETRY"
            exc_code = crash_record.get("exception_code", "UNKNOWN")
            exc_name = crash_record.get("exception_name", "UNKNOWN")

            raw_fault_mod = crash_record.get("fault_module")
            if raw_fault_mod and str(raw_fault_mod).strip() and str(raw_fault_mod).strip() not in ("UNKNOWN_MODULE", "UNKNOWN_OR_UNLOADED_MODULE"):
                fault_mod = str(raw_fault_mod).strip()
                is_internal = os.path.basename(fault_mod).lower() == bin_name.lower()
            else:
                fault_mod = "UNKNOWN_MODULE"
                is_internal = False

            raw_offset = crash_record.get("fault_offset", "0x0")
            try:
                offset_int = int(raw_offset, 16) if isinstance(raw_offset, str) else int(raw_offset)
            except ValueError:
                offset_int = 0

            graph.add_node(
                crash_id,
                node_type="CRASH_TELEMETRY",
                label=f"{exc_name} ({exc_code})",
                exception_code=exc_code,
                exception_name=exc_name,
                fault_module=fault_mod,
                fault_offset=hex(offset_int),
                is_internal_fault=is_internal,
                source=crash_record.get("source", "TELEMETRY")
            )
            graph.add_edge(bin_id, crash_id, relation="REPORTED_CRASH")

            # Access Violation Root Cause Node
            av_details = crash_record.get("access_violation_details")
            if av_details:
                root_id = "AV_ROOT_CAUSE"
                target_addr = av_details.get("target_virtual_address", "0x0")
                is_null = av_details.get("is_null_pointer_dereference", False)

                # Check if near-zero address (< 0x10000)
                try:
                    t_int = int(target_addr, 16) if isinstance(target_addr, str) else int(target_addr)
                    if t_int < 0x10000:
                        is_null = True
                except Exception:
                    pass

                cause_label = (
                    "Probable Cause Hypothesis: High-probability NULL pointer dereference"
                    if is_null else
                    f"Memory Access Violation: Invalid {av_details.get('operation')} at unmapped address {target_addr}"
                )

                graph.add_node(
                    root_id,
                    node_type="ACCESS_VIOLATION_ROOT",
                    label=f"{av_details.get('operation')} @ {target_addr}",
                    operation=av_details.get("operation"),
                    target_virtual_address=target_addr,
                    is_null_pointer_dereference=is_null,
                    cause=cause_label
                )
                graph.add_edge(crash_id, root_id, relation="CAUSED_BY_VIOLATION")

            # Map Fault Offset (RVA) to Section if internal
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
            elif fault_mod != "UNKNOWN_MODULE":
                ext_dll_id = f"DLL:{fault_mod.lower()}"
                if ext_dll_id in graph.nodes:
                    graph.add_edge(crash_id, ext_dll_id, relation="FAULTS_INSIDE_EXTERNAL_DLL")

        # 8. Corroborating Event Log Telemetry Node Integration
        try:
            evts = EventLogCollector.query_application_errors(bin_name, max_events=3)
            for idx, ev in enumerate(evts):
                ev_id = f"EVT_LOG:{idx+1}"
                graph.add_node(
                    ev_id,
                    node_type="EVENT_LOG_RECORD",
                    label=f"Event 1000 ({ev.get('fault_module')} @ {ev.get('fault_offset')})",
                    time_created=ev.get("time_created"),
                    fault_module=ev.get("fault_module"),
                    exception_code=ev.get("exception_code"),
                    fault_offset=ev.get("fault_offset")
                )
                graph.add_edge(bin_id, ev_id, relation="HAS_EVENT_LOG_RECORD")
                if crash_record and "CRASH_TELEMETRY" in graph.nodes:
                    graph.add_edge("CRASH_TELEMETRY", ev_id, relation="CORROBORATED_BY_EVENT_LOG")
        except Exception:
            pass

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
        1. Gathers OS environment, dependencies, hardware, security, and crash telemetry.
        2. Strictly partitions evidence into verified FACTS, environmental OBSERVATIONS, and HYPOTHESES.
        3. Builds the formal Evidence Graph and extracts the primary causal path.
        4. Generates an authoritative, single-source-of-truth Failure Evidence Dossier.
        """
        norm_path = os.path.abspath(binary_path)
        bin_name = os.path.basename(norm_path)

        # 1. Environmental Telemetry
        os_data = WindowsOSProfiler.profile(norm_path)
        dep_data = WindowsDependencyResolver.audit_dependencies(norm_path)
        hw_data = WindowsDeviceInspector.audit()
        sec_data = WindowsSecurityInspector.audit(norm_path)

        # Safety Kernel & Target Integrity Baseline
        safety_kernel_report: Dict[str, Any] = {}
        try:
            from security import ExecutionGuard, AuditLogger
            scope = ExecutionGuard.get_current_scope()
            scope.register_target(norm_path)
            integrity = scope.verify_target_integrity(norm_path)
            safety_kernel_report = {
                "enforcement_mode": "REFERENCE_MONITOR",
                "target_integrity": integrity,
                "audit_summary": AuditLogger.summarize()
            }
        except Exception as _sec_exc:
            safety_kernel_report = {"status": "uninitialized", "error": str(_sec_exc)}

        # Process & Resource Intelligence Telemetry
        resource_data: Dict[str, Any] = {}
        try:
            from ..process_intelligence import FileUsageInspector, ProcessInventory
            resource_data = {
                "file_locks": FileUsageInspector.inspect_file_locks(norm_path),
                "running_instances": ProcessInventory.find_processes_by_file(norm_path)
            }
        except Exception as _res_exc:
            resource_data = {"error": str(_res_exc)}

        # 2. Multi-Source Crash Telemetry Discovery & Chronological Timeline Synthesis
        discovered_events: List[Dict[str, Any]] = []
        discovered_wers: List[Dict[str, Any]] = []
        dumps: Dict[str, Any] = {}
        try:
            discovered_events = EventLogCollector.query_application_errors(bin_name, max_events=5)
            discovered_wers = EventLogCollector.query_wer_events(bin_name, max_events=5)
            dumps = MiniDumpParser.audit_dumps(bin_name, max_dumps=5)
        except Exception:
            pass

        timeline: List[Dict[str, Any]] = []
        for ev in discovered_events:
            timeline.append({
                "timestamp": ev.get("time_created") or "UNKNOWN_TIME",
                "source": "EVENT_LOG_1000",
                "event_type": "APPLICATION_CRASH",
                "fault_module": ev.get("fault_module"),
                "fault_offset": ev.get("fault_offset"),
                "exception_code": ev.get("exception_code"),
                "summary": f"Application Error (Event 1000): {ev.get('app_name')} crashed in {ev.get('fault_module')} at offset {ev.get('fault_offset')}"
            })
        for wer in discovered_wers:
            timeline.append({
                "timestamp": wer.get("time_created") or "UNKNOWN_TIME",
                "source": "WER_1001",
                "event_type": "ERROR_REPORTING",
                "bucket": wer.get("bucket"),
                "summary": f"Windows Error Reporting (Event 1001): Bucket {wer.get('bucket')} ({wer.get('event_name')})"
            })
        for dmp in dumps.get("crash_reports", []):
            d_exc = dmp.get("exception_info") or {}
            d_time = "UNKNOWN_TIME"
            f_path = dmp.get("file_path", "")
            if f_path and os.path.exists(f_path):
                import datetime
                mtime = os.path.getmtime(f_path)
                d_time = datetime.datetime.fromtimestamp(mtime, tz=datetime.timezone.utc).isoformat()
            timeline.append({
                "timestamp": d_time,
                "source": "MINIDUMP",
                "event_type": "MEMORY_DUMP",
                "fault_module": d_exc.get("fault_module"),
                "fault_offset": d_exc.get("fault_offset"),
                "exception_code": d_exc.get("exception_code"),
                "summary": f"MiniDump generated: {os.path.basename(f_path)} ({d_exc.get('exception_code')} {d_exc.get('exception_name')})"
            })
        timeline.sort(key=lambda x: str(x.get("timestamp", "")))

        if not crash_record:
            if dumps.get("crash_reports"):
                rep = dumps["crash_reports"][0]
                exc = rep.get("exception_info") or {}
                crash_record = {
                    "source": "MINIDUMP",
                    "file_path": rep.get("file_path"),
                    "app_name": bin_name,
                    "fault_module": exc.get("fault_module"),
                    "exception_code": exc.get("exception_code"),
                    "exception_name": exc.get("exception_name"),
                    "fault_offset": exc.get("fault_offset", "0x0"),
                    "access_violation_details": exc.get("access_violation_details"),
                    "thread_context": exc.get("thread_context")
                }
            elif discovered_events:
                ev = discovered_events[0]
                crash_record = {
                    "source": "EVENT_LOG_1000",
                    "app_name": bin_name,
                    "fault_module": ev.get("fault_module"),
                    "exception_code": ev.get("exception_code"),
                    "exception_name": ev.get("exception_name"),
                    "fault_offset": ev.get("fault_offset", "0x0")
                }

        # 3. Static Binary Mapping with Strict Epistemic Module Attribution
        pe_info = BinaryFormatInspector.inspect(norm_path)
        binary_mapping = None
        target_name = bin_name.lower()

        is_internal_fault = False
        raw_fault_module = "UNKNOWN_MODULE"
        fault_offset = 0

        if crash_record:
            raw_mod = crash_record.get("fault_module")
            if raw_mod and str(raw_mod).strip() and str(raw_mod).strip() not in ("UNKNOWN_MODULE", "UNKNOWN_OR_UNLOADED_MODULE"):
                raw_fault_module = str(raw_mod).strip()
                is_internal_fault = (target_name == os.path.basename(raw_fault_module).lower())
            else:
                raw_fault_module = "UNKNOWN_MODULE"
                is_internal_fault = False

            fault_offset_str = crash_record.get("fault_offset", "0x0")
            try:
                fault_offset = int(fault_offset_str, 16) if isinstance(fault_offset_str, str) else int(fault_offset_str)
            except ValueError:
                fault_offset = 0

        if crash_record and pe_info.get("format") == "PE":
            if is_internal_fault:
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

                target_sec = None
                for sec in pe_info.get("sections", []):
                    va_start = _to_int(sec.get("virtual_address", 0))
                    va_size = max(_to_int(sec.get("virtual_size", 0)), _to_int(sec.get("raw_size", 0)))
                    if va_start <= fault_rva < va_start + va_size:
                        target_sec = sec
                        break

                binary_mapping = {
                    "is_internal_fault": True,
                    "target_module": bin_name,
                    "fault_rva": hex(fault_rva),
                    "fault_virtual_address": hex(va),
                    "file_offset": hex(file_offset) if file_offset is not None else None,
                    "fault_section": target_sec["name"] if target_sec else "UNMAPPED_RVA_SPACE",
                    "is_executable_section": target_sec.get("is_executable", False) if target_sec else False
                }

                # Map into Ghidra Decompiled Functions
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

                            # Exact basic block interval containment check (b_start <= va <= b_end)
                            blocks = func.get("basic_blocks", [])
                            matched_block = None
                            for b in blocks:
                                if "start" not in b:
                                    continue
                                try:
                                    b_s = int(b["start"], 16)
                                    if b.get("end") or b.get("stop"):
                                        b_e = int(b.get("end") or b.get("stop"), 16)
                                    elif b.get("size"):
                                        b_e = b_s + int(b["size"])
                                    else:
                                        b_e = b_s + 1
                                    if b_s <= va <= b_e:
                                        matching_func = func
                                        matched_block = b
                                        break
                                except (ValueError, TypeError):
                                    continue
                            if matching_func:
                                if matched_block:
                                    binary_mapping["ghidra_basic_block"] = matched_block.get("start")
                                break

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
                attribution_val = (
                    "ATTRIBUTION_UNKNOWN" if raw_fault_module == "UNKNOWN_MODULE"
                    else "EXTERNAL_DEPENDENCY_OR_SYSTEM_MODULE"
                )
                binary_mapping = {
                    "is_internal_fault": False,
                    "target_module": bin_name,
                    "external_fault_module": raw_fault_module,
                    "fault_rva": hex(fault_offset),
                    "attribution": attribution_val
                }

        # 4. Strict Epistemic Evidence Partitioning: FACTS vs OBSERVATIONS vs HYPOTHESES
        facts: List[str] = []
        observations: List[str] = []
        hypotheses: List[str] = []

        root_cause_points: List[str] = []
        remediation_steps: List[str] = []
        verdict = "HEALTHY_ENVIRONMENT"
        severity = "INFO"

        # (A) Empirical Facts
        if crash_record:
            exc_code = crash_record.get("exception_code", "UNKNOWN")
            exc_name = crash_record.get("exception_name", "UNKNOWN")
            facts.append(f"Recorded crash exception code: {exc_code} ({exc_name}) at offset {hex(fault_offset)}.")
            if safety_kernel_report.get("target_integrity", {}).get("is_intact"):
                b_hash = safety_kernel_report["target_integrity"].get("baseline_sha256", "")[:16]
                facts.append(f"Target binary integrity verified by Safety Kernel: zero mutation (SHA-256: {b_hash}...).")

            if is_internal_fault and binary_mapping:
                facts.append(
                    f"Fault offset {hex(fault_offset)} is confirmed internal RVA within '{bin_name}' section '{binary_mapping.get('fault_section')}' "
                    f"(Virtual Address: {binary_mapping.get('fault_virtual_address')})."
                )
                if binary_mapping.get("ghidra_function_name"):
                    facts.append(
                        f"Faulting virtual address maps directly into Ghidra function '{binary_mapping.get('ghidra_function_name')}' "
                        f"(Entry: {binary_mapping.get('ghidra_function_entry')})."
                    )
            elif raw_fault_module != "UNKNOWN_MODULE":
                facts.append(f"Faulting module is explicitly reported as external runtime: '{raw_fault_module}'.")

            ctx = crash_record.get("thread_context") or crash_record.get("thread_registers")
            if ctx and isinstance(ctx, dict):
                reg_str = ", ".join(f"{k}={v}" for k, v in list(ctx.items())[:6])
                facts.append(f"CPU thread context registers at exception: {reg_str}.")

        # (B) Environmental Observations
        k_info = os_data.get("kernel", {})
        observations.append(
            f"Host OS: Windows Build {k_info.get('build_number')} (Architecture: {os_data.get('architecture', {}).get('native_architecture')}, WOW64: {k_info.get('is_wow64_process')})."
        )
        observations.append(
            f"Dependency Resolution: {dep_data.get('resolved_dlls_count')}/{dep_data.get('total_imported_dlls')} DLLs resolved. "
            f"Missing DLLs: {dep_data.get('missing_dlls_count')}, Architecture Mismatches: {dep_data.get('architecture_mismatches_count')}."
        )
        observations.append(
            f"Security Context: Admin={sec_data.get('is_elevated_admin')}, Directory Writable={sec_data.get('directory_write_permissions', {}).get('is_writable')}."
        )

        # (B.1) Process & Resource Observations and Facts
        fl = resource_data.get("file_locks", {})
        if fl.get("is_locked"):
            p_names = [f"{p.get('app_name', 'PID')} ({p.get('process_id')})" for p in fl.get("locking_processes", [])]
            facts.append(f"Target file is actively LOCKED on disk by {len(p_names)} process(es): {', '.join(p_names)}.")
            observations.append(f"File lock handles prevent write, modification, or patching operations on '{bin_name}'.")
            if not is_internal_fault and not crash_record and verdict == "HEALTHY_ENVIRONMENT":
                verdict = "FILE_LOCKED_BY_ACTIVE_PROCESS"
                severity = "WARNING"
            root_cause_points.append(f"Target binary file is locked by running process(es): {', '.join(p_names)}.")
            remediation_steps.append("Close or terminate the locking application before attempting to modify or patch the binary.")

        for rproc in resource_data.get("running_instances", []):
            facts.append(f"Target binary is currently running as active process PID {rproc.get('process_id')} ('{rproc.get('exe_name')}').")

        # (C) Diagnostic Hypotheses & Root Cause Synthesis
        if dep_data.get("missing_dlls_count", 0) > 0:
            missing_names = [d["imported_name"] for d in dep_data.get("missing_dlls", [])]
            verdict = "MISSING_DLL_DEPENDENCIES"
            severity = "CRITICAL"
            hypotheses.append(f"Missing required runtime libraries prevent program initialization: {', '.join(missing_names)}.")
            root_cause_points.append(f"Missing runtime dynamic libraries: {', '.join(missing_names)}.")
            remediation_steps.append("Install required Visual C++ / DirectX runtimes or place missing DLLs in application folder.")

        if dep_data.get("architecture_mismatches_count", 0) > 0:
            verdict = "ARCHITECTURE_MISMATCH_FAILURE"
            severity = "CRITICAL"
            hypotheses.append("Architecture mismatch: 32-bit/64-bit module loading conflict prevents execution.")
            root_cause_points.append("Incompatible CPU architecture between target binary and loaded dynamic libraries.")
            remediation_steps.append("Ensure all loaded dependency DLLs match the target executable architecture.")

        if crash_record:
            exc_code = crash_record.get("exception_code", "UNKNOWN")
            exc_name = crash_record.get("exception_name", "UNKNOWN")
            av_details = crash_record.get("access_violation_details")

            if is_internal_fault:
                verdict = f"INTERNAL_BINARY_CRASH: CRASH_TELEMETRY_RECORDED: {exc_name} ({exc_code})"
                severity = "CRITICAL"
                root_cause_points.append(f"Fatal crash inside '{bin_name}' at RVA {hex(fault_offset)} ({exc_name} {exc_code}).")
            elif raw_fault_module != "UNKNOWN_MODULE":
                verdict = f"EXTERNAL_MODULE_CRASH: {raw_fault_module} ({exc_name})"
                severity = "CRITICAL"
                root_cause_points.append(f"Fatal fault inside external module '{raw_fault_module}' at RVA {hex(fault_offset)}.")
                hypotheses.append(
                    f"External failure in '{raw_fault_module}'. Suspected incompatible graphics runtime or invalid pointer parameters passed across API boundary."
                )
                remediation_steps.append(f"Verify DirectX/graphics driver compatibility and audit API calls passed to '{raw_fault_module}'.")
            else:
                verdict = f"CRASH_TELEMETRY_RECORDED: {exc_name} (UNKNOWN_MODULE)"
                severity = "HIGH"
                root_cause_points.append(f"Fatal crash recorded without attributed module ({exc_name} {exc_code}).")

            if av_details:
                op = av_details.get("operation", "ACCESS")
                addr = av_details.get("target_virtual_address", "0x0")
                is_null = av_details.get("is_null_pointer_dereference", False)
                try:
                    t_int = int(addr, 16) if isinstance(addr, str) else int(addr)
                    if t_int < 0x10000:
                        is_null = True
                except Exception:
                    pass

                if is_null:
                    hyp_text = f"Probable Cause Hypothesis: High-probability NULL pointer dereference ({op} at virtual address {addr}). An uninitialized object or null struct pointer was accessed."
                    hypotheses.append(hyp_text)
                    root_cause_points.append(hyp_text)
                    remediation_steps.append("Inspect pointer validation preceding the faulting instruction or add a NULL safety guard.")
                else:
                    hyp_text = f"Probable Cause Hypothesis: Invalid memory access ({op} at protected/unmapped virtual address {addr}). Suspected buffer overread, dangling pointer, or DEP violation."
                    hypotheses.append(hyp_text)
                    root_cause_points.append(hyp_text)
                    remediation_steps.append("Validate buffer bounds and check for use-after-free or data execution prevention conflicts.")

        # 5. Build Evidence Graph & Extract Causal Chain
        graph = cls.build_evidence_graph(norm_path, crash_record=crash_record, ghidra_export=ghidra_export)
        target_node_id = f"TARGET:{bin_name}"
        causal_chain = []
        if "AV_ROOT_CAUSE" in graph.nodes and target_node_id in graph.nodes:
            causal_chain = graph.find_causal_path(target_node_id, "AV_ROOT_CAUSE")

        # 5. Compile Epistemic Unknowns Ledger
        unknowns = []
        if not crash_record:
            unknowns.append("Empirical crash telemetry is unavailable (no local MiniDump or Event 1000 record detected).")
        elif raw_fault_module == "UNKNOWN_MODULE":
            unknowns.append(f"Faulting module unmapped: exception occurred at unmapped virtual address {hex(fault_offset)}.")
        if is_internal_fault:
            if not ghidra_export:
                unknowns.append("Ghidra decompilation export unavailable: internal RVA cannot be resolved to AST/CFG.")
            elif binary_mapping and not binary_mapping.get("ghidra_function_name"):
                unknowns.append(f"Internal fault address {hex(va)} does not map to any exported Ghidra function.")
            elif binary_mapping and not binary_mapping.get("ghidra_basic_block"):
                unknowns.append(f"Internal fault address {hex(va)} does not map to any exported basic block boundary.")

        dossier = {
            "status": "success",
            "binary_path": norm_path,
            "verdict": verdict,
            "severity": severity,
            "epistemic_classification": {
                "facts": facts,
                "observations": observations,
                "hypotheses": hypotheses,
                "unknowns": unknowns
            },
            "unknowns": unknowns,
            "root_cause_summary": root_cause_points or ["No critical failure conditions detected in host Windows environment."],
            "remediation_advisory": remediation_steps or ["System and application dependencies are healthy."],
            "os_environment": os_data,
            "dependency_health": dep_data,
            "graphics_and_hardware": hw_data,
            "security_and_privileges": sec_data,
            "safety_kernel_audit": safety_kernel_report,
            "security_kernel_audit": safety_kernel_report,
            "resource_and_process_intelligence": resource_data,
            "crash_telemetry": crash_record,
            "binary_mapping": binary_mapping,
            "causal_chain": causal_chain,
            "synchronized_evidence_timeline": timeline,
            "evidence_graph": graph.to_dict(),
            "mermaid_diagram": graph.to_mermaid()
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
            "## 1. Epistemic Evidence Classification",
            "",
            "### Verified Facts (Empirical Ground Truth)",
        ]

        ep = dossier.get("epistemic_classification", {})
        for f in ep.get("facts", []):
            lines.append(f"- **[FACT]** {f}")
        if not ep.get("facts"):
            lines.append("- *(No direct crash telemetry facts recorded)*")

        lines.extend([
            "",
            "### Environmental Observations",
        ])
        for o in ep.get("observations", []):
            lines.append(f"- **[OBSERVATION]** {o}")

        lines.extend([
            "",
            "### Diagnostic Hypotheses & Inferences",
        ])
        for h in ep.get("hypotheses", []):
            lines.append(f"- **[HYPOTHESIS]** {h}")
        if not ep.get("hypotheses"):
            lines.append("- *(No failure hypotheses generated)*")

        lines.extend([
            "",
            "### Known Unknowns & Epistemic Boundaries",
        ])
        for u in ep.get("unknowns", []):
            lines.append(f"- **[UNKNOWN]** {u}")
        if not ep.get("unknowns"):
            lines.append("- *(All diagnostic variables empirically resolved)*")

        lines.extend([
            "",
            "## 2. Root Cause Summary",
        ])
        for rc in dossier.get("root_cause_summary", []):
            lines.append(f"- {rc}")

        lines.extend([
            "",
            "## 3. Engineering Remediation Advisory",
        ])
        for rem in dossier.get("remediation_advisory", []):
            lines.append(f"1. {rem}")

        # Timeline
        timeline = dossier.get("synchronized_evidence_timeline", [])
        if timeline:
            lines.extend([
                "",
                "## Synchronized Multi-Source Telemetry Timeline",
                "| Timestamp | Telemetry Source | Event Type | Description |",
                "| :--- | :--- | :--- | :--- |"
            ])
            for item in timeline[:10]:
                lines.append(f"| `{item.get('timestamp')}` | `{item.get('source')}` | `{item.get('event_type')}` | {item.get('summary')} |")

        # Crash Telemetry
        crash = dossier.get("crash_telemetry")
        if crash:
            lines.extend([
                "",
                "## 4. Crash Telemetry & Exception Details",
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
                "## 5. Static Binary & Ghidra IR Correlation"
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
            "## 6. Dependency Resolution Matrix",
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
            "## 7. Host Windows Environment & Hardware",
            f"- **OS:** {kernel.get('friendly_name', 'Windows')} (Build {kernel.get('build_number', 'Unknown')})",
            f"- **Architecture:** {os_env.get('architecture', {}).get('native_architecture', 'Unknown')}",
            f"- **Elevation:** Admin={dossier.get('security_and_privileges', {}).get('is_elevated_admin')}"
        ])

        mermaid = dossier.get("mermaid_diagram")
        if mermaid:
            lines.extend([
                "",
                "## 8. Evidence Causality Graph",
                "```mermaid",
                mermaid,
                "```"
            ])

        return "\n".join(lines)
