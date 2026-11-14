# -*- coding: utf-8 -*-
"""
Bintra Network Hardware Intelligence & Deep Driver Reverse Engineering Engine.
Provides authoritative read-only inspection of network adapters, NDIS miniports,
physical MAC layer, link characteristics, and performs end-to-end correlation:
PCIe Hardware -> SetupAPI DevNode -> SCM Driver Service -> Driver PE32+ Binary -> Live Ring-0 Memory (KASLR).
"""

import os
import sys
import ntpath
import socket
import struct
import ctypes
from ctypes import wintypes
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

try:
    import winreg
except ImportError:
    winreg = None


class NetworkHardwareInspector:
    """
    Authoritative read-only hardware intelligence engine for Windows network adapters
    and NDIS kernel driver reverse engineering.
    """

    IF_TYPE_NAMES = {
        1: "OTHER",
        6: "ETHERNET_CSMACD",
        9: "TOKEN_RING",
        23: "PPP",
        24: "SOFTWARE_LOOPBACK",
        71: "IEEE80211_WIRELESS",
        131: "TUNNEL",
        243: "WWAN_PP",
        244: "WWAN_PP2",
    }

    OPER_STATUS_NAMES = {
        1: "UP (Connected / Operational)",
        2: "DOWN (Disconnected / Media Disconnected)",
        3: "TESTING",
        4: "UNKNOWN",
        5: "DORMANT",
        6: "NOT_PRESENT",
        7: "LOWER_LAYER_DOWN",
    }

    @classmethod
    def audit_network_adapters(cls, include_virtual: bool = True) -> Dict[str, Any]:
        """
        Enumerates live network adapters using Win32 iphlpapi.GetAdaptersAddresses.
        Extracts interface GUID, friendly name, physical MAC address, operational status,
        link speed, MTU, IPv4 and IPv6 addresses.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "message": "Network adapter inspection requires a Windows NT host.",
                "total_adapters": 0,
                "adapters": []
            }

        try:
            iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to load iphlpapi.dll: {e}",
                "total_adapters": 0,
                "adapters": []
            }

        class SOCKET_ADDRESS(ctypes.Structure):
            _fields_ = [
                ("lpSockaddr", ctypes.c_void_p),
                ("iSockaddrLength", ctypes.c_int),
            ]

        class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
            pass

        IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
            ("Length", wintypes.ULONG),
            ("Flags", wintypes.DWORD),
            ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
            ("Address", SOCKET_ADDRESS),
            ("PrefixOrigin", ctypes.c_int),
            ("SuffixOrigin", ctypes.c_int),
            ("DadState", ctypes.c_int),
            ("ValidLifetime", wintypes.ULONG),
            ("PreferredLifetime", wintypes.ULONG),
            ("LeaseLifetime", wintypes.ULONG),
            ("OnLinkPrefixLength", ctypes.c_uint8),
        ]

        class IP_ADAPTER_ADDRESSES(ctypes.Structure):
            pass

        IP_ADAPTER_ADDRESSES._fields_ = [
            ("Length", wintypes.ULONG),
            ("IfIndex", wintypes.DWORD),
            ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
            ("AdapterName", ctypes.c_char_p),
            ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
            ("FirstAnycastAddress", ctypes.c_void_p),
            ("FirstMulticastAddress", ctypes.c_void_p),
            ("FirstDnsServerAddress", ctypes.c_void_p),
            ("DnsSuffix", wintypes.LPWSTR),
            ("Description", wintypes.LPWSTR),
            ("FriendlyName", wintypes.LPWSTR),
            ("PhysicalAddress", ctypes.c_ubyte * 8),
            ("PhysicalAddressLength", wintypes.DWORD),
            ("Flags", wintypes.DWORD),
            ("Mtu", wintypes.DWORD),
            ("IfType", wintypes.DWORD),
            ("OperStatus", ctypes.c_int),
            ("Ipv6IfIndex", wintypes.DWORD),
            ("ZoneIndices", wintypes.DWORD * 16),
            ("FirstPrefix", ctypes.c_void_p),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
        ]

        AF_UNSPEC = 0
        GAA_FLAG_INCLUDE_PREFIX = 0x0010
        size = wintypes.ULONG(16384)
        buf = ctypes.create_string_buffer(size.value)

        ret = iphlpapi.GetAdaptersAddresses(
            AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, None, ctypes.byref(buf), ctypes.byref(size)
        )
        if ret == 111:  # ERROR_BUFFER_OVERFLOW
            buf = ctypes.create_string_buffer(size.value)
            ret = iphlpapi.GetAdaptersAddresses(
                AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, None, ctypes.byref(buf), ctypes.byref(size)
            )

        if ret != 0:
            return {
                "status": "error",
                "win32_code": ret,
                "message": f"GetAdaptersAddresses failed with error {ret}",
                "total_adapters": 0,
                "adapters": []
            }

        adapters = []
        curr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
        while curr:
            addr = curr.contents
            name_guid = addr.AdapterName.decode("ascii", errors="ignore") if addr.AdapterName else ""
            friendly = addr.FriendlyName or ""
            desc = addr.Description or ""
            mac_len = min(addr.PhysicalAddressLength, 8)
            mac = "-".join(f"{b:02X}" for b in addr.PhysicalAddress[:mac_len]) if mac_len > 0 else ""

            rx_speed = addr.ReceiveLinkSpeed
            tx_speed = addr.TransmitLinkSpeed
            # When unplugged, Windows returns ~18.4 TB/s (0xFFFFFFFFFFFFFFFF // 1M)
            rx_mbps = round(rx_speed / 1_000_000, 1) if rx_speed < 10_000_000_000_000 else 0.0
            tx_mbps = round(tx_speed / 1_000_000, 1) if tx_speed < 10_000_000_000_000 else 0.0

            # Collect Unicast IP Addresses
            ipv4_list = []
            ipv6_list = []
            u_curr = addr.FirstUnicastAddress
            while u_curr:
                sa_ptr = u_curr.contents.Address.lpSockaddr
                sa_len = u_curr.contents.Address.iSockaddrLength
                if sa_ptr and sa_len >= 16:
                    sa_family = ctypes.cast(sa_ptr, ctypes.POINTER(ctypes.c_uint16)).contents.value
                    if sa_family == 2:  # AF_INET
                        ip_raw = ctypes.string_at(sa_ptr + 4, 4)
                        ipv4_list.append(socket.inet_ntoa(ip_raw))
                    elif sa_family == 23 and sa_len >= 28:  # AF_INET6
                        ip6_raw = ctypes.string_at(sa_ptr + 8, 16)
                        ipv6_list.append(socket.inet_ntop(socket.AF_INET6, ip6_raw))
                u_curr = u_curr.contents.Next

            if_type_name = cls.IF_TYPE_NAMES.get(addr.IfType, f"IF_TYPE_{addr.IfType}")
            oper_name = cls.OPER_STATUS_NAMES.get(addr.OperStatus, f"OPER_{addr.OperStatus}")
            is_wireless = (addr.IfType == 71)
            is_virtual = ("virtual" in desc.lower() or "loopback" in desc.lower() or "miniport" in desc.lower())

            if not include_virtual and is_virtual and not is_wireless:
                curr = curr.contents.Next
                continue

            adapters.append({
                "interface_guid": name_guid,
                "friendly_name": friendly,
                "description": desc,
                "physical_mac_address": mac,
                "interface_index": addr.IfIndex,
                "interface_type": if_type_name,
                "interface_type_code": addr.IfType,
                "is_wireless": is_wireless,
                "is_virtual": is_virtual,
                "operational_status": oper_name,
                "operational_status_code": addr.OperStatus,
                "is_connected": (addr.OperStatus == 1),
                "receive_link_speed_mbps": rx_mbps,
                "transmit_link_speed_mbps": tx_mbps,
                "mtu_bytes": addr.Mtu,
                "ipv4_addresses": ipv4_list,
                "ipv6_addresses": ipv6_list,
            })
            curr = curr.contents.Next

        return {
            "status": "success",
            "total_adapters": len(adapters),
            "adapters": adapters,
            "epistemic_classification": "WIN32_IPHLPAPI_ADAPTERS_ADDRESSES"
        }

    @classmethod
    def deep_dissect_network_device(cls, target_query: str = "wifi") -> Dict[str, Any]:
        """
        Conducts multi-layer hardware-to-ring0 reverse engineering for a specific network device:
        Layer 1: SetupAPI & CfgMgr32 PCIe Bus Topology
        Layer 2: NDIS & IP Stack Telemetry (MAC, Link Speed, Status)
        Layer 3: PnP Driver Registry & INF Metadata
        Layer 4: SCM Driver Service State
        Layer 5: Kernel Driver Binary Dissection (PE32+, Sections, Imports, PDB RSDS)
        Layer 6: Ring-0 Kernel Runtime Memory & KASLR Slide Calculation
        """
        from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
        from windows_intelligence.system_introspection.driver_inspector import KernelDriverInspector
        from windows_intelligence.system_introspection.service_inspector import ServiceManagerInspector
        from binary_neural_engine import BinaryFormatInspector
        from pe_deep_forensics import PeDeepForensicsInspector

        # 1. Enumerate PnP Net Devices and NDIS adapters upfront for holistic correlation
        pnp_devs = NativeDeviceInspector.enumerate_devices(class_filter="Net")
        all_net = cls.audit_network_adapters(include_virtual=True)
        ndis_adapters = all_net.get("adapters", [])

        # Build query keyword set with standard networking synonyms
        q_norm = (target_query or "").strip().lower()
        query_keywords = {q_norm}
        if q_norm in ("wifi", "wi-fi", "wireless", "wlan", "802.11", "wlan0"):
            query_keywords.update(["wifi", "wi-fi", "wireless", "wlan", "802.11"])
        elif q_norm in ("eth", "ethernet", "lan", "gigabit", "eth0"):
            query_keywords.update(["ethernet", "lan", "gigabit", "i219", "realtek", "broadcom"])

        # Candidate scoring across PnP devices
        scored_candidates = []
        for d in pnp_devs:
            name = str(d.get("name") or "").lower()
            inst_id = str(d.get("device_instance_id") or "").lower()
            svc = str(d.get("service") or "").lower()
            score = 0

            # Match against PnP attributes
            for kw in query_keywords:
                if kw in name:
                    score += 25
                if kw in inst_id:
                    score += 25
                if kw in svc:
                    score += 25

            # Physical bus preference (PCI / USB vs virtual SWD / ROOT)
            is_pci = "pci\\" in inst_id
            is_usb = "usb\\" in inst_id
            if is_pci:
                score += 30
            elif is_usb:
                score += 20

            # Non-virtual preference
            is_virt = ("virtual" in name or "vwifi" in inst_id or "root\\" in inst_id or "kdnic" in inst_id)
            if not is_virt:
                score += 15

            # Check correlated NDIS adapter friendly name / description
            for a in ndis_adapters:
                a_desc = str(a.get("description") or "").lower()
                a_name = str(a.get("friendly_name") or "").lower()
                if (name and name in a_desc) or (a_desc and a_desc in name):
                    for kw in query_keywords:
                        if kw in a_name:
                            score += 25
                    if a.get("is_connected"):
                        score += 10
                    break

            if score > 0:
                scored_candidates.append((score, d))

        # Select highest scored device, or fallback to first physical PCIe net adapter
        target_pnp = None
        if scored_candidates:
            scored_candidates.sort(key=lambda x: x[0], reverse=True)
            target_pnp = scored_candidates[0][1]
        else:
            for d in pnp_devs:
                if "PCI\\" in str(d.get("device_instance_id", "")).upper():
                    target_pnp = d
                    break

        if not target_pnp:
            return {
                "status": "error",
                "message": f"No network device matching query '{target_query}' found."
            }

        # 2. Match with IPHelper Adapter
        adapter_guid = None
        driver_reg_info = {}
        driver_key = target_pnp.get("driver_key")
        if driver_key and winreg:
            reg_full = rf"SYSTEM\CurrentControlSet\Control\Class\{driver_key}"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_full, 0, winreg.KEY_READ) as k:
                    sub_c, val_c, _ = winreg.QueryInfoKey(k)
                    for i in range(val_c):
                        try:
                            vname, vdata, _ = winreg.EnumValue(k, i)
                            if isinstance(vdata, (bytes, bytearray)):
                                vdata = vdata.hex()
                            driver_reg_info[vname] = vdata
                        except OSError:
                            break
                    adapter_guid = driver_reg_info.get("NetCfgInstanceId")
            except Exception:
                pass

        # Query live IP adapters (already cached in all_net)
        matched_ip_adapter = None
        for a in all_net.get("adapters", []):
            if adapter_guid and a.get("interface_guid", "").lower() == adapter_guid.lower():
                matched_ip_adapter = a
                break
            elif target_pnp.get("name") and a.get("description") and target_pnp.get("name") in a.get("description"):
                matched_ip_adapter = a
                break

        # 3. Query SCM Service State
        svc_name = target_pnp.get("service") or ""
        scm_config = ServiceManagerInspector.get_service_config(svc_name) if svc_name else None
        
        # Check running state in SCM
        running_services = ServiceManagerInspector.enumerate_services(include_drivers=True, max_services=2048)
        svc_state = None
        for s in running_services:
            if s.get("service_name", "").lower() == svc_name.lower():
                svc_state = s
                break

        # 4. Resolve Candidate Driver File Names and Locate Binary
        target_driver_names = set()
        if svc_name:
            target_driver_names.add(svc_name.lower())
            target_driver_names.add(f"{svc_name.lower()}.sys")

        driver_file_path = None
        if scm_config and scm_config.get("binary_path"):
            bpath = str(scm_config["binary_path"]).strip()
            # Extract raw sys filename (ntpath for cross-platform Linux CI safety)
            base_sys = ntpath.basename(bpath).lower()
            if base_sys:
                target_driver_names.add(base_sys)

            # Resolve full Windows path
            windir = os.environ.get("WINDIR", r"C:\Windows")
            b_lower = bpath.lower()
            if b_lower.startswith("\\systemroot\\"):
                rel = bpath[12:]
                candidate = ntpath.join(windir, rel)
            elif b_lower.startswith("\\??\\"):
                candidate = bpath[4:]
            elif b_lower.startswith("%systemroot%"):
                candidate = ntpath.join(windir, bpath[13:].lstrip("\\/"))
            else:
                candidate = bpath

            if os.path.isfile(candidate):
                driver_file_path = candidate

        # 5. Query Live Kernel Ring-0 Memory via PSAPI
        loaded_drivers = KernelDriverInspector.enumerate_loaded_drivers()
        matched_kernel_drv = None
        for kd in loaded_drivers:
            kd_name = kd.get("driver_name", "").lower()
            kd_path = kd.get("file_path", "").lower()
            if kd_name in target_driver_names:
                matched_kernel_drv = kd
                break
            if driver_file_path and kd_path and ntpath.normpath(driver_file_path).lower() == ntpath.normpath(kd_path).lower():
                matched_kernel_drv = kd
                break
            if any(t in kd_name for t in target_driver_names if len(t) >= 4):
                matched_kernel_drv = kd
                break

        if not driver_file_path and matched_kernel_drv and matched_kernel_drv.get("file_exists"):
            driver_file_path = matched_kernel_drv.get("file_path")

        # 6. Dissect Driver Binary File (PE32+)
        binary_dissection = {}
        kaslr_analysis = {}
        if driver_file_path and os.path.isfile(driver_file_path):
            pe_info = BinaryFormatInspector.inspect(driver_file_path)
            pe_forensics = PeDeepForensicsInspector().inspect(driver_file_path)

            preferred_image_base_str = pe_info.get("image_base", "0x0")
            preferred_image_base = int(preferred_image_base_str, 16) if isinstance(preferred_image_base_str, str) else preferred_image_base_str
            entry_rva_str = pe_info.get("entry_point_rva") or pe_info.get("entry_point") or "0x0"
            entry_rva = int(entry_rva_str, 16) if isinstance(entry_rva_str, str) else (entry_rva_str or 0)

            # KASLR Slide Calculation
            if matched_kernel_drv and matched_kernel_drv.get("kernel_base_int"):
                live_base = matched_kernel_drv["kernel_base_int"]
                kaslr_slide = live_base - preferred_image_base
                live_entry_va = live_base + entry_rva if entry_rva else live_base
                kaslr_analysis = {
                    "live_kernel_base_hex": matched_kernel_drv.get("kernel_image_base"),
                    "preferred_image_base_hex": hex(preferred_image_base),
                    "kaslr_slide_hex": hex(kaslr_slide),
                    "driver_entry_rva": hex(entry_rva) if entry_rva else None,
                    "live_driver_entry_va": hex(live_entry_va) if entry_rva else None,
                    "aslr_mitigation_active": (kaslr_slide != 0),
                }

            # Imports Breakdown
            imports_summary = {}
            for mod, funcs in pe_info.get("imports", {}).get("modules", {}).items():
                imports_summary[mod] = {
                    "total_functions": len(funcs),
                    "sample": funcs[:10]
                }

            binary_dissection = {
                "file_path": driver_file_path,
                "file_size_bytes": os.path.getsize(driver_file_path),
                "format": pe_info.get("format"),
                "architecture": pe_forensics.get("architecture"),
                "preferred_image_base": hex(preferred_image_base),
                "entry_point_rva": hex(entry_rva) if entry_rva else None,
                "total_sections": len(pe_info.get("sections", [])),
                "sections": pe_info.get("sections", []),
                "total_pdata_functions": pe_forensics.get("pdata_functions", {}).get("total_runtime_functions", 0),
                "pdb_correlation": pe_forensics.get("pdb_correlation", {}),
                "imported_modules_count": pe_info.get("imports", {}).get("imported_dlls_count", 0),
                "imported_modules": imports_summary,
            }

        return {
            "status": "success",
            "target_query": target_query,
            "device_name": target_pnp.get("name"),
            "layer_1_physical_bus": {
                "device_instance_id": target_pnp.get("device_instance_id"),
                "hardware_id": target_pnp.get("hardware_id"),
                "hardware_ids": target_pnp.get("hardware_ids"),
                "compatible_ids": target_pnp.get("compatible_ids"),
                "class": target_pnp.get("class"),
                "parent_device_id": target_pnp.get("parent_device_id"),
                "is_started": target_pnp.get("is_started"),
                "has_problem": target_pnp.get("has_problem"),
                "problem_code": target_pnp.get("problem_code"),
                "problem_description": target_pnp.get("problem_description"),
            },
            "layer_2_ndis_telemetry": matched_ip_adapter or {
                "status": "not_correlated",
                "message": "No matching active IP interface could be correlated."
            },
            "layer_3_driver_registry": {
                "driver_key": driver_key,
                "driver_description": driver_reg_info.get("DriverDesc"),
                "driver_version": driver_reg_info.get("DriverVersion"),
                "driver_date": driver_reg_info.get("DriverDate"),
                "provider_name": driver_reg_info.get("ProviderName"),
                "net_cfg_instance_id": driver_reg_info.get("NetCfgInstanceId"),
                "inf_path": driver_reg_info.get("InfPath"),
                "characteristics": driver_reg_info.get("Characteristics"),
                "bus_type": driver_reg_info.get("BusType"),
            },
            "layer_4_scm_service": {
                "service_name": svc_name,
                "display_name": scm_config.get("display_name") if scm_config else (svc_state.get("display_name") if svc_state else None),
                "state": svc_state.get("state") if svc_state else "UNKNOWN",
                "start_type": scm_config.get("start_type") if scm_config else None,
                "binary_path": scm_config.get("binary_path") if scm_config else None,
            },
            "layer_5_driver_binary_forensics": binary_dissection,
            "layer_6_runtime_kaslr": kaslr_analysis,
            "epistemic_scope": "MULTI_LAYER_HARDWARE_TO_KERNEL_CORRELATION",
            "epistemic_classification": "DETERMINISTIC_HARDWARE_REVERSE_ENGINEERING"
        }
