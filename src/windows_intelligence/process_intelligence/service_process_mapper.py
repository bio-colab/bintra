# -*- coding: utf-8 -*-
"""
Service-to-Process Cross-Correlation Mapper.
Maps Windows Service Control Manager (SCM) service definitions to active process instances (PIDs),
and resolves shared service host (svchost.exe) groups to identify which services run inside which processes.
"""

import os
from typing import Dict, Any, List, Optional
from ..system_introspection.service_inspector import ServiceManagerInspector
from .process_inventory import ProcessInventory


class ServiceProcessMapper:
    """
    Cross-references SCM service tables with active process tables to establish
    verified SERVICE_HOSTED and SERVICE_PROCESS relationships.
    """

    @classmethod
    def get_service_process_mapping(cls) -> Dict[str, Any]:
        """
        Builds a bidirectional map:
        1. PID -> List of services hosted in this process
        2. Service Name -> Process ID and executable image
        """
        # Query live services via ServiceManagerInspector
        services = ServiceManagerInspector.enumerate_services(max_services=512)
        processes = ProcessInventory.enumerate_processes(resolve_paths=True, max_processes=512)

        proc_by_pid = {p["process_id"]: p for p in processes}
        pid_to_services: Dict[int, List[Dict[str, Any]]] = {}
        service_to_proc: Dict[str, Dict[str, Any]] = {}

        for svc in services:
            pid = svc.get("process_id", svc.get("pid", 0))
            s_name = svc.get("service_name")
            if not s_name:
                continue

            svc_entry = {
                "service_name": s_name,
                "display_name": svc.get("display_name"),
                "state": svc.get("state"),
                "service_type": svc.get("service_type")
            }

            if pid and pid > 0:
                if pid not in pid_to_services:
                    pid_to_services[pid] = []
                pid_to_services[pid].append(svc_entry)

                proc_info = proc_by_pid.get(pid, {})
                service_to_proc[s_name] = {
                    "process_id": pid,
                    "executable_name": proc_info.get("executable_name"),
                    "image_path": proc_info.get("image_path")
                }

        # Identify svchost service groups
        svchost_groups = []
        for pid, svcs in pid_to_services.items():
            proc = proc_by_pid.get(pid, {})
            exe = (proc.get("executable_name") or "").lower()
            if "svchost" in exe or len(svcs) > 1:
                svchost_groups.append({
                    "process_id": pid,
                    "executable_name": proc.get("executable_name"),
                    "image_path": proc.get("image_path"),
                    "hosted_services_count": len(svcs),
                    "services": svcs
                })

        return {
            "status": "success",
            "total_services_analyzed": len(services),
            "running_services_with_pid": len(service_to_proc),
            "service_host_groups_count": len(svchost_groups),
            "pid_to_services": pid_to_services,
            "service_to_process": service_to_proc,
            "svchost_groups": svchost_groups
        }

    @classmethod
    def get_services_for_process(cls, pid: int) -> List[Dict[str, Any]]:
        """Returns all services hosted inside a specific process ID."""
        mapping = cls.get_service_process_mapping()
        return mapping.get("pid_to_services", {}).get(pid, [])
