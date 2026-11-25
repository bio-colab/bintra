"""MCP tool handlers: devices. Methods are bound into BintraMcpServer via mixin inheritance."""
from typing import Any, Dict




class DevicesToolsMixin:
    """Handlers for the devices MCP tools (signature: (self, name, args) -> result)."""

    def _tool_hardware_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_hardware_audit"""
        from windows_intelligence import NativeDeviceInspector
        report = NativeDeviceInspector.audit_hardware_health()
        if report.get("status") == "not_applicable":
            return report
        if args.get("problems_only", False):
            return {
                "is_hardware_healthy": report.get("is_hardware_healthy", True),
                "problem_devices_count": report.get("problem_devices_count", 0),
                "problem_devices": report.get("problem_devices", [])
            }
        return report

    def _tool_port_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_port_audit"""
        from windows_intelligence import PortInspector
        port_name = args.get("port_name")
        include_modem = args.get("include_modem_status", True)
        p_type = args.get("port_type", "all")
        if p_type == "parallel":
            return PortInspector.audit_parallel_ports()
        elif p_type == "serial":
            return PortInspector.audit_serial_ports(include_modem_status=include_modem, target_port=port_name)
        else:
            return PortInspector.audit_all_ports(include_modem_status=include_modem)

    def _tool_hardware_topology(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_hardware_topology"""
        from windows_intelligence import NativeDeviceInspector
        bus_filter = args.get("bus_filter")
        problems_only = args.get("problems_only", False)
        fmt = args.get("format", "tree")
        max_devs = args.get("max_devices", 300)
        return NativeDeviceInspector.build_device_topology(
            max_devices=max_devs,
            bus_filter=bus_filter,
            problems_only=problems_only,
            format=fmt
        )

    def _tool_network_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_network_audit"""
        from windows_intelligence import NetworkHardwareInspector
        inc_virt = args.get("include_virtual", True)
        return NetworkHardwareInspector.audit_network_adapters(include_virtual=inc_virt)

    def _tool_network_hardware_dissect(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_network_hardware_dissect"""
        from windows_intelligence import NetworkHardwareInspector
        target = args.get("target_query", "wifi")
        return NetworkHardwareInspector.deep_dissect_network_device(target_query=target)

    def _tool_network_connections(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_network_connections"""
        from windows_intelligence import NetworkHardwareInspector
        pid = args.get("pid")
        return NetworkHardwareInspector.audit_tcp_connections(pid=pid)

    def _tool_driver_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_driver_audit"""
        from windows_intelligence import KernelDriverInspector
        flt = args.get("driver_name_filter")
        if flt:
            matched = KernelDriverInspector.filter_drivers(flt)
            return {
                "status": "success",
                "filter": flt,
                "matched_count": len(matched),
                "drivers": matched
            }
        return KernelDriverInspector.audit_drivers()

    def _tool_service_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_service_audit"""
        from windows_intelligence import ServiceManagerInspector
        flt = args.get("service_name_filter")
        active_only = args.get("active_only", False)
        if flt or active_only:
            all_svcs = ServiceManagerInspector.enumerate_services()
            if active_only:
                all_svcs = [s for s in all_svcs if s.get("state") in ("RUNNING", "SERVICE_RUNNING")]
            if flt:
                flt_lower = flt.lower()
                all_svcs = [s for s in all_svcs if flt_lower in s.get("service_name", "").lower() or flt_lower in s.get("display_name", "").lower()]
            return {
                "status": "success",
                "total_matching_services": len(all_svcs),
                "services": all_svcs
            }
        return ServiceManagerInspector.audit_services()

    def _tool_device_driver_intelligence(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_device_driver_intelligence"""
        from windows_intelligence.device_intelligence import DriverMatcher, DriverPackageInventory, DeviceManagerInspector
        offline_infs = args.get("offline_inf_paths")
        if offline_infs and args.get("device_id"):
            parsed_infs = [DriverPackageInventory.parse_offline_inf(p) for p in offline_infs]
            return DriverMatcher.match_offline_device_to_infs(args["device_id"], parsed_infs)
        action = args.get("action", "audit")
        query = args.get("device_query")
        c_filter = args.get("class_filter")
        prob_only = args.get("problems_only", False)
        limit = int(args.get("limit", 200))

        if action == "find_packages":
            pkgs = DriverPackageInventory.find_driver_package_by_name(query or "")
            return {"status": "success", "query": query, "packages_count": len(pkgs), "packages": pkgs}
        elif action == "device_classes":
            return DeviceManagerInspector.get_device_classes()
        elif action == "list_devices":
            return DeviceManagerInspector.list_devices(class_filter=c_filter, problems_only=prob_only, limit=limit)
        elif action == "search_devices":
            return DeviceManagerInspector.search_devices(query=query or "", limit=limit if limit <= 50 else 50)
        elif action == "device_details":
            target = args.get("device_id_or_name") or query or ""
            return DeviceManagerInspector.get_device_details(target)

        return DriverMatcher.audit_device_driver_bindings(
            device_query=query,
            class_filter=c_filter,
            problems_only=prob_only,
            max_devices=int(args.get("max_devices", 64))
        )
