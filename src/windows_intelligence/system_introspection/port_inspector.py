"""
Bintra Port Inspector: Serial (COM), Parallel (LPT), and USB-to-UART Bridge Diagnostics.
Strictly read-only introspection of physical and virtual communication ports on Windows NT.

Capabilities:
1. Enumerates registered active COM ports via HKLM\\HARDWARE\\DEVICEMAP\\SERIALCOMM.
2. Enumerates legacy parallel printer ports via HKLM\\HARDWARE\\DEVICEMAP\\PARALLEL PORTS.
3. Correlates COM ports with PnP DevNodes to identify USB-to-UART bridge controllers (FTDI, CH340, CP210x, PL2303).
4. Passive non-disruptive DCB line configuration & modem status signal queries (CTS/DSR/RING/DCD).
5. Fail-closed ExecutionGuard mediation and zero-dependency ctypes/winreg execution.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any, Dict, List, Optional

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    import winreg
else:
    ctypes = None
    wintypes = None
    winreg = None


class PortInspector:
    """
    Diagnostic auditor for Windows serial communication ports, parallel ports,
    and USB bridge controllers.
    """

    # Win32 Modem Status Flags (GetCommModemStatus)
    MS_CTS_ON = 0x0010   # Clear To Send (CTS) status is on
    MS_DSR_ON = 0x0020   # Data Set Ready (DSR) status is on
    MS_RING_ON = 0x0040  # Ring Indicator (RI) status is on
    MS_RLSD_ON = 0x0080  # Receive Line Signal Detect (RLSD / Carrier Detect) is on

    # Parity names
    PARITY_MAP = {
        0: "NOPARITY",
        1: "ODDPARITY",
        2: "EVENPARITY",
        3: "MARKPARITY",
        4: "SPACEPARITY"
    }

    # Stop bits names
    STOPBITS_MAP = {
        0: "ONESTOPBIT (1.0)",
        1: "ONE5STOPBITS (1.5)",
        2: "TWOSTOPBITS (2.0)"
    }

    @classmethod
    def audit_serial_ports(
        cls,
        include_modem_status: bool = False,
        target_port: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enumerates all active COM ports registered in the Windows kernel device map.
        Correlates each port with its PnP device instance and USB bridge controller identity.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "message": "Serial port inspection requires a Windows NT host.",
                "total_ports": 0,
                "ports": []
            }

        ports_list = []
        try:
            # 1. Read kernel serial communication device map
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DEVICEMAP\SERIALCOMM",
                0,
                winreg.KEY_READ
            ) as key:
                idx = 0
                while True:
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, idx)
                        idx += 1
                        port_name = str(val_data).strip()
                        if target_port and port_name.upper() != target_port.upper():
                            continue

                        val_upper = str(val_name).upper()
                        port_info = {
                            "port_name": port_name,
                            "device_map_path": str(val_name),
                            "port_type": cls._classify_port_type(val_name, port_name),
                            "is_virtual_or_usb": any(tok in val_upper for tok in ("VCP", "USB", "FTDI", "SILABSER", "PROLIFIC", "CH34", "WCH", "BTH")),
                        }

                        if include_modem_status:
                            port_info["comm_state"] = cls.inspect_comm_status(port_name)

                        ports_list.append(port_info)
                    except OSError:
                        break
        except FileNotFoundError:
            # No serial ports registered on this machine
            pass
        except Exception as reg_err:
            return {
                "status": "error",
                "message": f"Failed to query SERIALCOMM registry map: {reg_err}",
                "total_ports": 0,
                "ports": []
            }

        # 2. Correlate with PnP Device Manager to enrich with bridge controller and hardware details
        pnp_error = None
        try:
            cls._enrich_with_pnp_hardware(ports_list)
        except Exception as pnp_exc:
            pnp_error = str(pnp_exc)

        res: Dict[str, Any] = {
            "status": "success",
            "total_ports": len(ports_list),
            "ports": ports_list,
            "epistemic_classification": "WINDOWS_KERNEL_DEVICEMAP_SERIALCOMM"
        }
        if pnp_error:
            res["pnp_enrichment_error"] = pnp_error
        return res

    @classmethod
    def audit_parallel_ports(cls) -> Dict[str, Any]:
        """
        Enumerates legacy IEEE 1284 parallel printer ports (LPT1, LPT2) registered on the host.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "message": "Parallel port inspection requires a Windows NT host.",
                "total_ports": 0,
                "ports": []
            }

        parallel_ports = []
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DEVICEMAP\PARALLEL PORTS",
                0,
                winreg.KEY_READ
            ) as key:
                idx = 0
                while True:
                    try:
                        val_name, val_data, _ = winreg.EnumValue(key, idx)
                        idx += 1
                        parallel_ports.append({
                            "port_name": str(val_data).strip(),
                            "device_map_path": str(val_name),
                        })
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as reg_err:
            return {
                "status": "error",
                "message": f"Failed to query PARALLEL PORTS registry map: {reg_err}",
                "total_ports": 0,
                "ports": []
            }

        return {
            "status": "success",
            "total_ports": len(parallel_ports),
            "ports": parallel_ports
        }

    @classmethod
    def inspect_comm_status(cls, port_name: str) -> Dict[str, Any]:
        """
        Passively queries the DCB line parameters (baud rate, parity, stop bits) and
        modem status pin voltages (CTS, DSR, RING, DCD) for a specific COM port.
        Uses GENERIC_READ and OPEN_EXISTING without altering hardware state.
        """
        if os.name != "nt":
            return {"status": "not_applicable"}

        clean_name = port_name.upper().strip()
        device_path = f"\\\\.\\{clean_name}"

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        OPEN_EXISTING = 3
        FILE_ATTRIBUTE_NORMAL = 0x00000080

        # Define Win32 DCB structure
        class _DCB(ctypes.Structure):
            _fields_ = [
                ("DCBlength", wintypes.DWORD),
                ("BaudRate", wintypes.DWORD),
                ("Flags", wintypes.DWORD),
                ("wReserved", wintypes.WORD),
                ("XonLim", wintypes.WORD),
                ("XoffLim", wintypes.WORD),
                ("ByteSize", ctypes.c_byte),
                ("Parity", ctypes.c_byte),
                ("StopBits", ctypes.c_byte),
                ("XonChar", ctypes.c_char),
                ("XoffChar", ctypes.c_char),
                ("ErrorChar", ctypes.c_char),
                ("EofChar", ctypes.c_char),
                ("EvtChar", ctypes.c_char),
                ("wReserved1", wintypes.WORD),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE
        ]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.GetCommState.restype = wintypes.BOOL
        k32.GetCommState.argtypes = [wintypes.HANDLE, ctypes.POINTER(_DCB)]
        k32.GetCommModemStatus.restype = wintypes.BOOL
        k32.GetCommModemStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

        INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

        handle = k32.CreateFileW(
            device_path,
            GENERIC_READ,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )

        if handle == INVALID_HANDLE_VALUE or handle is None or handle == 0:
            err = ctypes.get_last_error()
            is_busy = err in (5, 32)  # ERROR_ACCESS_DENIED or ERROR_SHARING_VIOLATION
            return {
                "accessible": False,
                "is_busy_or_locked": is_busy,
                "win32_error": err,
                "message": "Port is currently in-use by another application" if is_busy else f"CreateFileW failed with error {err}"
            }

        try:
            dcb = _DCB()
            dcb.DCBlength = ctypes.sizeof(_DCB)
            has_dcb = bool(k32.GetCommState(handle, ctypes.byref(dcb)))

            modem_stat = wintypes.DWORD(0)
            has_modem = bool(k32.GetCommModemStatus(handle, ctypes.byref(modem_stat)))

            res: Dict[str, Any] = {
                "accessible": True,
                "is_busy_or_locked": False,
            }

            if has_dcb:
                res["line_config"] = {
                    "baud_rate": int(dcb.BaudRate),
                    "data_bits": int(dcb.ByteSize),
                    "parity": cls.PARITY_MAP.get(int(dcb.Parity), f"UNKNOWN_{dcb.Parity}"),
                    "stop_bits": cls.STOPBITS_MAP.get(int(dcb.StopBits), f"UNKNOWN_{dcb.StopBits}"),
                }

            if has_modem:
                val = modem_stat.value
                res["modem_status_pins"] = {
                    "clear_to_send_cts": bool(val & cls.MS_CTS_ON),
                    "data_set_ready_dsr": bool(val & cls.MS_DSR_ON),
                    "ring_indicator_ri": bool(val & cls.MS_RING_ON),
                    "carrier_detect_dcd": bool(val & cls.MS_RLSD_ON),
                    "raw_modem_status": hex(val),
                }

            return res
        finally:
            k32.CloseHandle(handle)

    @classmethod
    def audit_all_ports(cls, include_modem_status: bool = False) -> Dict[str, Any]:
        """
        Unified audit combining serial COM ports, parallel ports, and detected hardware controllers.
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "host_os": sys.platform,
                "message": "Port inspection requires a Windows NT host.",
                "total_ports": 0,
                "serial_ports_count": 0,
                "serial_ports": [],
                "parallel_ports_count": 0,
                "parallel_ports": [],
            }

        ser = cls.audit_serial_ports(include_modem_status=include_modem_status)
        par = cls.audit_parallel_ports()

        return {
            "status": "success",
            "host_os": sys.platform,
            "serial_ports_count": ser.get("total_ports", 0),
            "serial_ports": ser.get("ports", []),
            "parallel_ports_count": par.get("total_ports", 0),
            "parallel_ports": par.get("ports", []),
        }

    # --- Private Helpers ---

    @staticmethod
    def _classify_port_type(device_map_path: str, port_name: str) -> str:
        d_lower = device_map_path.lower()
        if "vcp" in d_lower or "silabser" in d_lower:
            return "USB_VIRTUAL_COM_PORT"
        if "ftdi" in d_lower:
            return "FTDI_SERIAL_PORT"
        if "prolific" in d_lower:
            return "PROLIFIC_SERIAL_PORT"
        if "ch34" in d_lower or "wch" in d_lower:
            return "WCH_CH34X_SERIAL_PORT"
        if "bth" in d_lower:
            return "BLUETOOTH_SERIAL_PORT"
        if "usbser" in d_lower:
            return "USB_CDC_SERIAL_PORT"
        if "serial" in d_lower:
            return "STANDARD_PHYSICAL_UART"
        return "UNKNOWN_SERIAL_INTERFACE"

    @classmethod
    def _enrich_with_pnp_hardware(cls, ports_list: List[Dict[str, Any]]) -> None:
        """Enriches ports with vendor, bridge model, and PnP hardware IDs from device manager."""
        from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector
        from windows_intelligence.device_intelligence.device_identity import DeviceIdentity

        devices = NativeDeviceInspector.enumerate_devices(max_devices=2048)
        if not devices:
            return

        # Prioritize Ports/Modem PnP classes before falling back to general devices
        prioritized = sorted(
            devices,
            key=lambda d: 0 if str(d.get("class") or "").lower() in ("ports", "modem") else 1,
        )

        for p in ports_list:
            p_name = p.get("port_name", "").upper()
            if not p_name:
                continue

            token_re = re.compile(rf"(?:^|\b|\(){re.escape(p_name)}(?:\)|$|\b)")
            matched = None
            for d in prioritized:
                f_name = str(d.get("friendly_name") or d.get("name") or "").upper()
                d_desc = str(d.get("description") or "").upper()
                if token_re.search(f_name) or token_re.search(d_desc):
                    matched = d
                    break

            if matched:
                identity = DeviceIdentity.parse_device_instance(matched)
                p["hardware_details"] = {
                    "friendly_name": matched.get("friendly_name") or matched.get("name") or matched.get("description"),
                    "device_instance_id": matched.get("device_instance_id"),
                    "vendor_id": identity.get("vendor_id"),
                    "vendor_name": identity.get("vendor_name"),
                    "device_id": identity.get("device_id"),
                    "serial_bridge_model": identity.get("serial_bridge_model"),
                    "bound_driver_service": matched.get("service"),
                    "driver_key": matched.get("driver_key"),
                    "has_problem": matched.get("has_problem", False),
                    "problem_code": matched.get("problem_code", 0),
                    "problem_description": matched.get("problem_description", "Healthy"),
                    "problem_name": matched.get("problem_name", "CM_PROB_OK"),
                }
                if identity.get("serial_bridge_model"):
                    p["bridge_identity"] = identity.get("serial_bridge_model")
                    p["is_usb_serial_bridge"] = True
