"""Bintra CLI commands: PnP hardware, drivers, services, ports and network adapter introspection."""
import argparse
import json
import sys


from windows_intelligence import (
    NativeDeviceInspector, KernelDriverInspector, ServiceManagerInspector
)


def cmd_hw_audit(cmd: str) -> None:
    """bintra hw-audit"""
    parser = argparse.ArgumentParser(description="Live hardware and PnP device audit via SetupAPI and CfgMgr32")
    parser.add_argument("command")
    parser.add_argument("--problems-only", action="store_true", help="Filter for devices with non-zero problem codes")
    parser.add_argument("--class-filter", default=None, help="Filter PnP devices by Setup class (e.g. MEDIA, Display, USB)")
    parser.add_argument("--storage", action="store_true", help="Include physical storage drives and volume partition inspection")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="hw-audit",
        target=args.class_filter or "AllDevices",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY",
    )
    if args.problems_only or args.class_filter:
        filtered = NativeDeviceInspector.enumerate_devices(
            filter_problems_only=args.problems_only,
            class_filter=args.class_filter,
        )
        report = NativeDeviceInspector.audit_hardware_health()
        report["filtered_devices"] = filtered
        report["filtered_count"] = len(filtered)
    else:
        report = NativeDeviceInspector.audit_hardware_health()

    if args.storage:
        report["storage_devices"] = NativeDeviceInspector.audit_storage_devices()

    if args.format == "md":
        if report.get("status") == "not_applicable" or "is_hardware_healthy" not in report:
            lines = [
                "# Native Hardware Subsystem Audit (SetupAPI / CfgMgr32)",
                f"- **Status:** `{report.get('status', 'unavailable')}`",
                f"- **Note:** {report.get('message', 'Hardware audit requires a Windows NT host.')}",
            ]
        else:
            lines = [
                "# Native Hardware Subsystem Audit (SetupAPI / CfgMgr32)",
                f"- **Hardware Status:** {'HEALTHY' if report.get('is_hardware_healthy') else 'DEGRADED_OR_PROBLEMS'}",
                f"- **Live PnP Devices:** {report.get('total_pnp_devices_enumerated', 0)}",
                f"- **Display Adapters:** {report.get('display_adapters_count', 0)}",
                f"- **Audio Devices:** {report.get('audio_devices_count', 0)}",
                f"- **Problem Devices:** {report.get('problem_devices_count', 0)}"
            ]
            if report.get("problem_devices"):
                lines.append("\n## Faulting Devices (CM_PROB_*):")
                for p in report["problem_devices"]:
                    lines.append(f"- **{p.get('name', 'Unknown')}**: `{p.get('problem_name', 'Unknown')}` (Service: `{p.get('service')}`)")
            if "storage_devices" in report and report["storage_devices"].get("status") == "success":
                st = report["storage_devices"]
                lines.append("\n## Physical Storage Drives:")
                for d in st.get("physical_drives", []):
                    lines.append(f"- **Drive {d.get('drive_index')}** (`{d.get('bus_type')}`): `{d.get('product_id')}` (Rev: `{d.get('product_revision')}`)")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_port_audit(cmd: str) -> None:
    """bintra port-audit"""
    parser = argparse.ArgumentParser(description="Live COM and LPT port audit via Windows kernel DEVICEMAP and PnP correlation")
    parser.add_argument("command")
    parser.add_argument("--port", default=None, help="Target specific port (e.g. COM1, COM3)")
    parser.add_argument("--type", choices=["all", "serial", "parallel"], default="all", help="Filter by port type")
    parser.add_argument("--no-modem-status", action="store_true", help="Disable non-disruptive DCB/modem control line queries")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="port-audit",
        target=args.port or "AllPorts",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY",
    )
    from windows_intelligence import PortInspector
    inc_modem = not args.no_modem_status
    if args.type == "serial":
        report = PortInspector.audit_serial_ports(include_modem_status=inc_modem, target_port=args.port)
    elif args.type == "parallel":
        report = PortInspector.audit_parallel_ports()
    else:
        report = PortInspector.audit_all_ports(include_modem_status=inc_modem)

    if args.format == "md":
        if report.get("status") == "not_applicable":
            print(f"# Port Audit\n- **Status:** `not_applicable`\n- **Note:** {report.get('message')}")
        else:
            lines = [
                "# Communication & Hardware Port Audit",
                f"- **Status:** `{report.get('status')}`",
                f"- **Active COM Ports:** {report.get('serial_ports_count', report.get('total_serial_ports', report.get('total_ports', 0)))}",
                f"- **Parallel Ports (LPT):** {report.get('parallel_ports_count', report.get('total_parallel_ports', 0))}",
            ]
            ports = report.get("ports") or report.get("serial_ports", [])
            if ports:
                lines.append("\n## Detected Communication Ports:")
                for p in ports:
                    p_name = p.get("port_name", "Unknown")
                    b_info = p.get("bridge_identity")
                    if isinstance(b_info, dict):
                        bridge_desc = f" ({b_info.get('controller_name', 'Standard')})"
                    elif isinstance(b_info, str) and b_info:
                        bridge_desc = f" ({b_info})"
                    else:
                        bridge_desc = ""
                    lines.append(f"- **`{p_name}`**{bridge_desc}: Type `{p.get('port_type')}`, Path `{p.get('device_map_path')}`")
                    cs = p.get("comm_state") or {}
                    if cs.get("accessible") or cs.get("status") == "active":
                        lc = cs.get("line_config", cs)
                        lines.append(f"  - Baud: {lc.get('baud_rate')}, DataBits: {lc.get('data_bits', lc.get('byte_size'))}, Parity: {lc.get('parity')}, StopBits: {lc.get('stop_bits')}")
            print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_hw_tree(cmd: str) -> None:
    """bintra hw-tree"""
    parser = argparse.ArgumentParser(description="Authoritative PnP bus topology tree and directed hardware graph")
    parser.add_argument("command")
    parser.add_argument("--bus", default=None, help="Filter by bus or subsystem (e.g. USB, PCI, ACPI)")
    parser.add_argument("--problems-only", action="store_true", help="Only render branches containing devices with error codes")
    parser.add_argument("--format", choices=["tree", "json", "mermaid"], default="tree", help="Output format")
    parser.add_argument("--max-devices", type=int, default=300, help="Maximum devices to query")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="hw-tree",
        target=args.bus or "AllBuses",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY",
    )
    from windows_intelligence import NativeDeviceInspector
    report = NativeDeviceInspector.build_device_topology(
        max_devices=args.max_devices,
        bus_filter=args.bus,
        problems_only=args.problems_only,
        format=args.format
    )
    if args.format in ("tree", "mermaid"):
        print(report.get("rendered", ""))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_hw_net(cmd: str) -> None:
    """bintra hw-net"""
    parser = argparse.ArgumentParser(description="Authoritative audit of live network adapters and NDIS miniports via iphlpapi")
    parser.add_argument("command")
    parser.add_argument("--virtual", action="store_true", help="Include virtual, loopback, and tunnel adapters")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="hw-net",
        target="NetworkAdapters",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY",
    )
    from windows_intelligence import NetworkHardwareInspector
    report = NetworkHardwareInspector.audit_network_adapters(include_virtual=args.virtual)
    if args.format == "md":
        lines = [
            "# Windows Network Adapters & NDIS Telemetry",
            f"- **Total Adapters:** {report.get('total_adapters', 0)}",
            f"- **Epistemic Classification:** `{report.get('epistemic_classification')}`",
            "",
            "| Friendly Name | Description | MAC Address | Status | Link Speed | IPv4 Address |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |"
        ]
        for a in report.get("adapters", []):
            ips = ", ".join(a.get("ipv4_addresses", [])) or "None"
            rx = a.get("receive_link_speed_mbps", 0.0)
            speed_str = f"{rx} Mbps" if rx > 0 else "Disconnected"
            lines.append(f"| {a.get('friendly_name')} | {a.get('description')} | `{a.get('physical_mac_address') or 'N/A'}` | {a.get('operational_status')} | {speed_str} | `{ips}` |")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_hw_dissect(cmd: str) -> None:
    """bintra hw-dissect"""
    parser = argparse.ArgumentParser(description="Multi-layer hardware-to-ring0 kernel driver reverse engineering dossier")
    parser.add_argument("command")
    parser.add_argument("target", nargs="?", default="wifi", help="Target hardware/driver keyword (e.g. 'wifi', 'intel', '8265', 'ethernet')")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="hw-dissect",
        target=args.target,
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY",
    )
    from windows_intelligence import NetworkHardwareInspector
    report = NetworkHardwareInspector.deep_dissect_network_device(target_query=args.target)
    if args.format == "md":
        l1 = report.get("layer_1_physical_bus", {})
        l2 = report.get("layer_2_ndis_telemetry", {})
        l3 = report.get("layer_3_driver_registry", {})
        l4 = report.get("layer_4_scm_service", {})
        l5 = report.get("layer_5_driver_binary_forensics", {})
        l6 = report.get("layer_6_runtime_kaslr", {})
        lines = [
            f"# Bintra Multi-Layer Hardware Reverse Engineering Dossier: {report.get('device_name')}",
            f"- **Target Query:** `{report.get('target_query')}` (Selection: `{report.get('selection_method')}`, Confidence: {report.get('match_confidence')})",
            f"- **Dossier Completeness:** `{report.get('dossier_completeness')}` (Status: `{report.get('status')}`)",
            f"- **Epistemic Classification:** `{report.get('epistemic_classification')}`",
            "",
            f"## Layer 1: Physical DevNode & PCIe Bus Topology [{l1.get('layer_status', 'UNKNOWN')}]",
            f"- **Device Instance ID:** `{l1.get('device_instance_id')}`",
            f"- **Hardware ID:** `{l1.get('hardware_id')}`",
            f"- **Parent Bus Node:** `{l1.get('parent_device_id')}`",
            f"- **Operational Status:** Started={l1.get('is_started')}, Problem={l1.get('problem_code')} ({l1.get('problem_description')})",
            "",
            f"## Layer 2: NDIS Stack & Link Layer Telemetry [{l2.get('layer_status', 'UNKNOWN')}]",
            f"- **Interface GUID:** `{l2.get('interface_guid')}`",
            f"- **Physical MAC Address:** `{l2.get('physical_mac_address')}`",
            f"- **Operational Status:** {l2.get('operational_status')}",
            f"- **Link Speed:** RX={l2.get('receive_link_speed_mbps')} Mbps, TX={l2.get('transmit_link_speed_mbps')} Mbps",
            f"- **IPv4 Addresses:** {', '.join(l2.get('ipv4_addresses', [])) or 'None'}",
            "",
            f"## Layer 3: PnP Driver Registry & INF Metadata [{l3.get('layer_status', 'UNKNOWN')}]",
            f"- **Driver Key:** `{l3.get('driver_key')}`",
            f"- **Driver Version:** `{l3.get('driver_version')}` (Provider: {l3.get('provider_name')}, Date: {l3.get('driver_date')})",
            f"- **INF File:** `{l3.get('inf_path')}`",
            "",
            f"## Layer 4: SCM Driver Service State [{l4.get('layer_status', 'UNKNOWN')}]",
            f"- **Service Name:** `{l4.get('service_name')}`",
            f"- **Display Name:** `{l4.get('display_name')}`",
            f"- **Service State:** `{l4.get('state')}`",
            f"- **Driver Binary Path:** `{l4.get('binary_path')}`",
            "",
            f"## Layer 5: Kernel Driver PE32+ Binary Forensics [{l5.get('layer_status', 'UNKNOWN')}]",
            f"- **Architecture:** `{l5.get('architecture')}`",
            f"- **Preferred Image Base:** `{l5.get('preferred_image_base')}`",
            f"- **Entry Point RVA:** `{l5.get('entry_point_rva')}`",
            f"- **PE Sections:** {l5.get('total_sections')} sections",
            f"- **Runtime Functions (.pdata):** {l5.get('total_pdata_functions')} functions",
            f"- **PDB RSDS GUID:** `{l5.get('pdb_correlation', {}).get('rsds_records', [{}])[0].get('guid') if l5.get('pdb_correlation', {}).get('rsds_records') else 'N/A'}`",
            "",
            f"## Layer 6: Ring-0 Kernel Runtime Memory & KASLR [{l6.get('layer_status', 'UNKNOWN')}]",
            f"- **Live Kernel Base:** `{l6.get('live_kernel_base_hex')}`",
            f"- **KASLR Slide:** `{l6.get('kaslr_slide_hex')}`",
            f"- **Live DriverEntry VA:** `{l6.get('live_driver_entry_va')}`",
            f"- **KASLR Active:** `{l6.get('aslr_mitigation_active')}`",
            f"- **Scope:** `{l6.get('kaslr_scope', 'STATIC_DYNAMIC_BASE_DISPLACEMENT')}`"
        ]
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_net_conns(cmd: str) -> None:
    """bintra net-conns"""
    parser = argparse.ArgumentParser(prog="bintra net-conns", description="Audit active TCP network connections via Win32 extended TCP table.")
    parser.add_argument("command")
    parser.add_argument("--pid", type=int, default=None, help="Filter by owning process PID")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="net-conns",
        target=str(args.pid) if args.pid else "all",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY",
    )
    from windows_intelligence import NetworkHardwareInspector
    report = NetworkHardwareInspector.audit_tcp_connections(pid=args.pid)
    if args.format == "md":
        lines = [
            "# Active TCP Network Connections",
            f"- **Filtered PID:** `{report.get('filter_pid')}`",
            f"- **Total Connections:** {report.get('total_connections')}",
            f"- **Epistemic Classification:** `{report.get('epistemic_classification')}`",
            "",
            "| PID | Local Endpoint | Remote Endpoint | State |",
            "| :--- | :--- | :--- | :--- |"
        ]
        for c in report.get("connections", []):
            lines.append(f"| {c.get('pid')} | `{c.get('local_address')}` | `{c.get('remote_address')}` | {c.get('state')} |")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_driver_audit(cmd: str) -> None:
    """bintra driver-audit"""
    parser = argparse.ArgumentParser(description="Kernel driver introspection via PSAPI")
    parser.add_argument("command")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    report = KernelDriverInspector.audit_drivers()
    if args.format == "md":
        if report.get("status") == "not_applicable" or "total_drivers_loaded" not in report:
            lines = [
                "# Kernel Drivers Introspection (PSAPI)",
                f"- **Status:** `{report.get('status', 'unavailable')}`",
                f"- **Note:** {report.get('message', 'Kernel driver audit requires a Windows NT host.')}",
            ]
        else:
            lines = [
                "# Kernel Drivers Introspection (PSAPI)",
                f"- **Total Drivers Loaded:** {report.get('total_drivers_loaded', 0)}",
                f"- **Graphics Drivers:** {len(report.get('graphics_drivers', []))}",
                f"- **Audio Drivers:** {len(report.get('audio_drivers', []))}",
                "",
                "## Critical Graphics & Display Driver Bases:"
            ]
            for g in report.get("graphics_drivers", []):
                lines.append(f"- **`{g.get('driver_name')}`**: Base `{g.get('kernel_image_base')}` (Path: `{g.get('file_path')}`)")
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_service_audit(cmd: str) -> None:
    """bintra service-audit"""
    parser = argparse.ArgumentParser(description="Windows Service Control Manager audit via Advapi32")
    parser.add_argument("command")
    parser.add_argument("--format", choices=["json", "md"], default="json", help="Output format")
    args = parser.parse_args()

    report = ServiceManagerInspector.audit_services()
    if args.format == "md":
        if report.get("status") == "not_applicable" or "total_services_enumerated" not in report:
            lines = [
                "# Service Control Manager Audit (Advapi32)",
                f"- **Status:** `{report.get('status', 'unavailable')}`",
                f"- **Note:** {report.get('message', 'Service control manager audit requires a Windows NT host.')}",
            ]
        else:
            lines = [
                "# Service Control Manager Audit (Advapi32)",
                f"- **Total Services Enumerated:** {report.get('total_services_enumerated', 0)}",
                f"- **Running Services:** {report.get('running_services_count', 0)}",
                f"- **Stopped Services:** {report.get('stopped_services_count', 0)}"
            ]
        print("\n".join(lines))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return


def cmd_dev_classes(cmd: str) -> None:
    """bintra dev-classes"""
    parser = argparse.ArgumentParser(prog="bintra dev-classes", description="Device Manager class hierarchy with friendly categories and error tallies")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dev-classes",
        target="DeviceClasses",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.device_intelligence import DeviceManagerInspector
    res = DeviceManagerInspector.get_device_classes()
    if args.format == "md":
        lines = [
            "# Windows Device Manager - Hardware Classes",
            f"- **Status:** `{res.get('status')}`",
            f"- **Total Hardware Classes:** {res.get('total_classes', 0)}",
            f"- **Total Active Devices:** {res.get('total_devices', 0)}",
            f"- **Devices with Problem Codes:** {res.get('total_problems', 0)}",
            f"- **Devices with Indeterminate/Unknown Status:** {res.get('total_unknown', 0)}",
            "",
            "| Class | Friendly Category | Devices | Problems | Unknown | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for c in res.get("classes", []):
            if c.get("problem_count", 0) > 0:
                c_status = f"⚠️ Error ({c['problem_count']})"
            elif c.get("unknown_count", 0) > 0:
                c_status = f"❓ Unknown ({c['unknown_count']})"
            else:
                c_status = "✅ Healthy"
            lines.append(
                f"| `{c.get('class_name')}` | {c.get('friendly_name')} | {c.get('device_count')} | {c.get('problem_count', 0)} | {c.get('unknown_count', 0)} | {c_status} |"
            )
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_dev_list(cmd: str) -> None:
    """bintra dev-list"""
    parser = argparse.ArgumentParser(prog="bintra dev-list", description="List active PnP devices enriched with driver store metadata and locations")
    parser.add_argument("--class-filter", default=None, help="Filter by device class (e.g. Display, Net, USB, Audio)")
    parser.add_argument("--problems-only", action="store_true", help="Filter to devices with active problem codes (CM_PROB_*)")
    parser.add_argument("--limit", type=int, default=50, help="Maximum devices to display (default: 50)")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dev-list",
        target=args.class_filter or "AllDevices",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.device_intelligence import DeviceManagerInspector
    res = DeviceManagerInspector.list_devices(
        class_filter=args.class_filter,
        problems_only=args.problems_only,
        limit=args.limit
    )
    if args.format == "md":
        lines = [
            f"# Windows Device Manager - Active Devices ({res.get('matched_count', len(res.get('devices', [])))} matches)",
            f"- **Total Enumerated:** {res.get('total_devices', 0)}",
            f"- **Class Filter:** `{args.class_filter}`" if args.class_filter else "- **Class Filter:** None",
            f"- **Problems Only:** {args.problems_only}",
            "",
            "| Device Name | Class | Driver Version | Provider | Bus / Location | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for d in res.get("devices", []):
            ver = d.get("driver_version") or "N/A"
            prov = d.get("driver_provider") or "N/A"
            loc = d.get("location") or d.get("bus_enumerator") or "Internal"
            prob_desc = d.get("problem_description") or "Healthy"
            stat_str = f"❌ {prob_desc}" if d.get("has_problem") else "✅ Healthy"
            lines.append(
                f"| {d.get('name')} | `{d.get('class')}` | {ver} | {prov} | {loc} | {stat_str} |"
            )
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_dev_search(cmd: str) -> None:
    """bintra dev-search"""
    parser = argparse.ArgumentParser(prog="bintra dev-search", description="Instant multi-field search across device names, hardware IDs, and vendors")
    parser.add_argument("query", nargs="?", default="", help="Search query (name, vendor, hardware ID, class, service, driver)")
    parser.add_argument("--query", dest="named_query", default=None, help="Alternative flag for query")
    parser.add_argument("--limit", type=int, default=50, help="Maximum results to return (default: 50)")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    query_val = args.named_query or args.query
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dev-search",
        target=query_val or "EmptyQuery",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.device_intelligence import DeviceManagerInspector
    res = DeviceManagerInspector.search_devices(query=query_val, limit=args.limit)
    if args.format == "md":
        lines = [
            f"# Windows Device Manager - Search Results for '{query_val}' ({res.get('matched_count', len(res.get('devices', [])))} matches)",
            "",
            "| Match Field | Device Name | Class | Driver Version | Provider | Location | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
        for d in res.get("devices", []):
            ver = d.get("driver_version") or "N/A"
            prov = d.get("driver_provider") or "N/A"
            loc = d.get("location") or d.get("bus_enumerator") or "Internal"
            prob_desc = d.get("problem_description") or "Healthy"
            stat_str = f"❌ {prob_desc}" if d.get("has_problem") else "✅ Healthy"
            lines.append(
                f"| `{d.get('match_field')}` | {d.get('name')} | `{d.get('class')}` | {ver} | {prov} | {loc} | {stat_str} |"
            )
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_dev_info(cmd: str) -> None:
    """bintra dev-info"""
    parser = argparse.ArgumentParser(prog="bintra dev-info", description="Complete Device Manager Properties dossier for a specific device")
    parser.add_argument("device", nargs="?", default="", help="Target device name or instance ID")
    parser.add_argument("--device", dest="named_device", default=None, help="Alternative flag for device target")
    parser.add_argument("--format", choices=["json", "md"], default="md", help="Output format")
    args = parser.parse_args(sys.argv[2:])
    target_dev = args.named_device or args.device
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dev-info",
        target=target_dev or "EmptyTarget",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.device_intelligence import DeviceManagerInspector
    res = DeviceManagerInspector.get_device_details(target_dev)
    if args.format == "md":
        if res.get("status") != "success":
            print(f"# Device Manager Dossier - Error\n- **Status:** `{res.get('status')}`\n- **Error:** {res.get('error', 'Unknown error')}")
            return
        dev = res.get("device", {})
        gen = dev.get("general", {})
        drv = dev.get("driver", {})
        diag = dev.get("status_diagnostics", {})
        hw = dev.get("hardware_ids", {})
        top = dev.get("topology", {})

        stat_badge = "✅ Healthy" if not diag.get("has_problem") else f"❌ {diag.get('problem_description')}"

        lines = [
            f"# Device Manager Properties - {gen.get('name')}",
            f"- **Status Badge:** {stat_badge}",
            "",
            "## 1. General Information",
            f"- **Friendly Name:** {gen.get('friendly_name') or 'N/A'}",
            f"- **Description:** {gen.get('description') or 'N/A'}",
            f"- **Class (Internal):** `{gen.get('class')}`",
            f"- **Class (Friendly):** {gen.get('class_friendly')}",
            f"- **Class GUID:** `{gen.get('class_guid')}`",
            f"- **Manufacturer:** {gen.get('manufacturer') or 'N/A'}",
            f"- **Location:** {gen.get('location') or 'N/A'}",
            f"- **Bus Enumerator:** `{gen.get('bus_enumerator')}`",
            f"- **PDO Name:** `{gen.get('pdo_name')}`",
            f"- **Kernel Service:** `{gen.get('service')}`",
            "",
            "## 2. Status & Diagnostics",
            f"- **Is Started (DN_STARTED):** {diag.get('is_started')}",
            f"- **Has Problem (DN_HAS_PROBLEM):** {diag.get('has_problem')}",
            f"- **Problem Code:** {diag.get('problem_code')} (`{diag.get('problem_name')}`)",
            f"- **Problem Description:** {diag.get('problem_description')}",
            "",
            "## 3. Driver Specification",
            f"- **Driver Version:** `{drv.get('driver_version') or 'N/A'}`",
            f"- **Driver Date:** `{drv.get('driver_date') or 'N/A'}`",
            f"- **Driver Provider:** {drv.get('provider_name') or 'N/A'}",
            f"- **INF File:** `{drv.get('inf_path') or 'N/A'}`",
            f"- **INF Section:** `{drv.get('inf_section') or 'N/A'}`",
            f"- **Matching Hardware ID:** `{drv.get('matching_device_id') or 'N/A'}`",
            f"- **Driver Registry Key:** `{drv.get('driver_key') or 'N/A'}`",
            "",
            "## 4. Hardware Identifiers",
            f"- **Primary Hardware ID:** `{hw.get('primary_hardware_id') or 'N/A'}`",
            "- **All Hardware IDs:**",
        ]
        for hid in hw.get("all_hardware_ids", []):
            lines.append(f"  - `{hid}`")
        if hw.get("compatible_ids"):
            lines.append("- **Compatible IDs:**")
            for cid in hw.get("compatible_ids", []):
                lines.append(f"  - `{cid}`")
        lines.extend([
            "",
            "## 5. Kernel PnP Topology",
            f"- **Device Instance ID:** `{top.get('device_instance_id')}`",
            f"- **DevNode Handle:** `0x{top.get('devnode_handle', 0):08X}`",
            f"- **Parent DevNode Handle:** `0x{top.get('parent_devnode', 0):08X}`" if top.get('parent_devnode') else "- **Parent DevNode Handle:** N/A",
            f"- **Parent Device Instance ID:** `{top.get('parent_device_id') or 'N/A'}`",
        ])
        print("\n".join(lines))
    else:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    return


def cmd_dev_match(cmd: str) -> None:
    """bintra dev-match"""
    parser = argparse.ArgumentParser(prog="bintra dev-match", description="Match PnP devices against Driver Store packages")
    parser.add_argument("--query", default=None, help="Device query name, instance ID, or hardware ID")
    parser.add_argument("--class-filter", default=None, help="Filter by device class")
    parser.add_argument("--problems-only", action="store_true", help="Filter to devices with active problem codes")
    args = parser.parse_args(sys.argv[2:])
    from security import ExecutionGuard, Capability
    ExecutionGuard.request_access(
        component="cli",
        operation="dev-match",
        target=args.query or "AllDevices",
        capability=Capability.DEVICE_QUERY,
        access_mode="QUERY"
    )
    from windows_intelligence.device_intelligence import DriverMatcher
    res = DriverMatcher.audit_device_driver_bindings(
        device_query=args.query,
        class_filter=args.class_filter,
        problems_only=args.problems_only
    )
    print(json.dumps(res, indent=2, ensure_ascii=False))
    return

