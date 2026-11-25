#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bintra Native Model Context Protocol (MCP) Server.
Standard JSON-RPC 2.0 stdio server providing agent-native reverse engineering
tools for AI models (Antigravity, Claude Code, Codex, Cursor, Devin, etc.).

Zero external dependencies: runs on Python standard library + numpy.
Protocol Version: 2024-11-05
"""

import os
import sys
import json
import traceback
from token_telemetry import (
    TokenSessionTracker,
    compact_tool_schema,
    estimate_tokens,
    estimate_cost_usd,
    prune_payload,
)
from typing import Dict, Any, List, Optional
from pathlib import Path

# Add src to sys.path
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import numpy as np
    from binary_neural_engine import (
        BinaryFormatInspector,
        ContinuousDeobfuscator,
        SemanticFunctionMatcher,
        SurgicalBinaryPatcher,
        HybridBinaryDissector,
        SensoryCortex,
    )
    from bintra_engine import (
        SafetensorsHandler,
        SubspaceAnalyzer,
        CircuitDecompiler,
        WeightPatcher,
        WeightSecurityAuditor,
        CrossLayerCircuitAnalyzer,
        AmenabilityDiagnostic,
    )
    from ghidra_pcode_vectorizer import (
        PcodeVectorizer,
        PcodeFunctionMatcher,
        PcodeDeobfuscator,
        GhidraAnnotationPlanner,
    )
except ImportError as err:
    sys.stderr.write(f"[BINTRA-MCP] Error importing core engines: {err}\n")


SERVER_NAME = "bintra"
SERVER_VERSION = "1.1.0"
PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = [
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
]
LATEST_PROTOCOL_VERSION = "2026-07-28"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"


TOOLS_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "bintra_inspect_binary",
        "description": "Deep inspection of Windows PE32/PE32+ (or ELF) executable headers, mitigations (ASLR, DEP, CFG), section geometries, and Shannon byte entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute filesystem path to the target executable (.exe or .dll)"
                },
                "max_exports": {
                    "type": "integer",
                    "description": "Maximum exported functions to return in sample (default 64, pass 0 for all). Prevents token bloat on system DLLs."
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "bintra_deobfuscate_binary",
        "description": "Detects algebraic opaque predicates (e.g. xor r8,r8 with REX awareness) and control flow flattening (CFF) dispatcher loops in machine code or executable files.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code_hex": {
                    "type": "string",
                    "description": "Hexadecimal string of machine code (e.g. '55 48 89 e5 31 c0 74 05 ...')"
                },
                "file_path": {
                    "type": "string",
                    "description": "Optional path to executable file to deobfuscate (analyzes entry point if offset omitted)"
                },
                "offset": {
                    "type": ["integer", "string"],
                    "description": "Optional file offset (int or hex string) to start analysis at (defaults to entry point)"
                },
                "length": {
                    "type": "integer",
                    "description": "Number of bytes to analyze (default 4096)"
                }
            }
        }
    },
    {
        "name": "bintra_dump_bytes",
        "description": "Extracts and displays raw bytes/machine code hex and ASCII preview from a binary executable at a given offset.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to binary executable on disk"
                },
                "offset": {
                    "type": ["integer", "string"],
                    "description": "Byte offset in file to read from (int or hex string, e.g. '0x4e0778')"
                },
                "length": {
                    "type": "integer",
                    "description": "Number of bytes to read (default 64, max 65536)"
                }
            },
            "required": ["file_path", "offset"]
        }
    },
    {
        "name": "bintra_match_functions",
        "description": "Computes continuous behavioral vector embeddings to semantically match assembly routines across compilers and architectures (x86-64 vs ARM64).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "func1_hex": {
                    "type": "string",
                    "description": "Hex string of the first function's machine code"
                },
                "func2_hex": {
                    "type": "string",
                    "description": "Hex string of the second function's machine code"
                }
            },
            "required": ["func1_hex", "func2_hex"]
        }
    },
    {
        "name": "bintra_patch_binary",
        "description": "Surgically patches machine code bytes on disk with stack balance proprioception (RSP/RBP guard), PE integrity checksum sync, and atomic write replacement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to binary file to patch"
                },
                "offset": {
                    "type": ["integer", "string"],
                    "description": "0-based file byte offset where patch begins (int or hex string)"
                },
                "patch_hex": {
                    "type": "string",
                    "description": "Hexadecimal byte sequence to write (e.g. '90 90 90')"
                },
                "output_path": {
                    "type": "string",
                    "description": "Required destination path in workspace. In-place source modification is strictly forbidden."
                },
                "force": {
                    "type": "boolean",
                    "description": "Force overwrite even if stack-altering opcodes or DEP violations are flagged"
                }
            },
            "required": ["file_path", "output_path", "offset", "patch_hex"]
        }
    },
    {
        "name": "bintra_scan_hybrid",
        "description": "Scans Windows executables for embedded AI runtimes (DirectML, WinML, ONNX, GGUF, TFLite, Safetensors) and extracts tensor geometries and I/O bridge maps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to executable to scan for embedded neural assets"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "bintra_sensory_audit",
        "description": "Evaluates all 10 Metaphorical Senses (Analytical Vision, Temporal Hearing, Active Touch, Exploratory Smell, Discriminative Taste, Deep Proprioception, Spatial Sense, Vestibular Balance, Metaphorical Pain, Sense of Rhythm) on a binary or code sample.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to binary or safetensors file"
                },
                "code_hex": {
                    "type": "string",
                    "description": "Hexadecimal machine code string"
                }
            }
        }
    },
    {
        "name": "bintra_match_pcode",
        "description": "Semantically matches two routines using Ghidra High P-Code IR embeddings. Architecture- and compiler-invariant (proves semantic equivalence across x86-64 and ARM64).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "func1_pcode": {
                    "type": "array",
                    "description": "List of P-code op dicts for function 1 (each with 'opcode', 'inputs', 'output')"
                },
                "func2_pcode": {
                    "type": "array",
                    "description": "List of P-code op dicts for function 2 (each with 'opcode', 'inputs', 'output')"
                }
            },
            "required": ["func1_pcode", "func2_pcode"]
        }
    },
    {
        "name": "bintra_deobfuscate_pcode",
        "description": "Detects algebraic opaque predicates (e.g. INT_XOR(V, V) followed by CBRANCH) in Ghidra High P-Code to clean control flow before decompiler AST construction.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pcode_ops": {
                    "type": "array",
                    "description": "List of P-code op dicts (each with 'opcode', 'inputs', 'output')"
                }
            },
            "required": ["pcode_ops"]
        }
    },
    {
        "name": "bintra_ghidra_analyze",
        "description": "Batch-processes, queries, and searches Ghidra exported High P-Code program payloads (JSON, JSONL, SQLite .db). Detects opaque predicates, computes Roy-Vetterli spectral rank, synthesizes mutation plans, searches functions/opcodes/xrefs, and inspects decompiled C pseudocode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_file": {
                    "type": "string",
                    "description": "Recommended path to exported Ghidra JSON, JSONL, or SQLite (.db) file on disk (pass-by-reference avoids prompt token bloat)"
                },
                "payload": {
                    "type": "object",
                    "description": "Optional inline exported program payload containing 'functions' array of High P-Code ops"
                },
                "query": {
                    "type": "string",
                    "description": "Optional search query to filter functions by substring matching name, entry RVA, signature, or decompiled C text"
                },
                "opcode_filter": {
                    "type": "string",
                    "description": "Optional opcode filter (e.g. CALLIND, FLOAT_SQRT, INT_XOR) to find functions containing this P-Code mnemonic"
                },
                "xref_target": {
                    "type": "string",
                    "description": "Optional symbol, address, or string to find referencing functions"
                },
                "function_name": {
                    "type": "string",
                    "description": "Optional target function name or entry point to retrieve full architectural inspection and decompiled C pseudocode"
                },
                "sensitive_only": {
                    "type": "boolean",
                    "description": "Filter to functions invoking sensitive Win32 APIs (e.g. VirtualAlloc, CreateProcess, CryptDecrypt)"
                },
                "profile": {
                    "type": "boolean",
                    "description": "Synthesize global computational and architectural profile (12-category P-Code distribution, arithmetic/control ratio)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of search matches to return (default: 50)"
                },
                "offset": {
                    "type": "integer",
                    "description": "Offset for paginating search results (default: 0)"
                }
            }
        }
    },
    {
        "name": "bintra_ghidra_headless",
        "description": "Automates running Ghidra analyzeHeadless with Bintra bridge scripts on Windows/Linux. Decompiles functions, extracts High P-Code, analyzes semantics, and applies database mutations in one command with timeout protection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Absolute path to target executable (PE/ELF)"
                },
                "ghidra_path": {
                    "type": "string",
                    "description": "Optional Ghidra install path (defaults to C:\\ghidra or GHIDRA_INSTALL_DIR)"
                },
                "project_dir": {
                    "type": "string",
                    "description": "Optional directory for Ghidra project database (defaults to isolated temp)"
                },
                "project_name": {
                    "type": "string",
                    "description": "Optional Ghidra project name (defaults to auto-generated unique name)"
                },
                "post_script": {
                    "type": "string",
                    "description": "Bridge script to execute (default: 'BintraGhidraBridge.java' or 'bintra_extract_pcode.py')"
                },
                "script_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional arguments to pass to the post-script"
                },
                "apply": {
                    "type": "boolean",
                    "description": "Automatically commit function renames and plate comments to Ghidra database"
                },
                "delete_project": {
                    "type": "boolean",
                    "description": "Automatically delete temporary Ghidra project files after analysis completes (default: true)"
                },
                "timeout_seconds": {
                    "type": "integer",
                    "description": "Maximum execution time in seconds before aborting (default: 300)"
                },
                "max_cpu": {
                    "type": "integer",
                    "description": "Maximum CPU cores for Ghidra analysis threads"
                }
            },
            "required": ["binary_path"]
        }
    },
    {
        "name": "bintra_windows_env_audit",
        "description": "Interrogates the host Windows OS kernel version, architecture, graphics adapters, DirectX runtimes, and token integrity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Optional path to target executable to check for compatibility shims"
                }
            }
        }
    },
    {
        "name": "bintra_resolve_dependencies",
        "description": "Simulates the Windows dynamic library search order to identify missing DLLs, architecture mismatches (x86 vs x64), and unexported symbols.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to target PE executable on disk"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "bintra_inspect_crash_reports",
        "description": "Scans Windows Error Reporting (WER) archives, crash dumps, and Application Event Log errors for empirical fault data.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Optional target executable name filter"
                }
            }
        }
    },
    {
        "name": "bintra_correlate_failure_evidence",
        "description": "Cross-correlates Windows OS telemetry, crash records, and dependency health with static PE sections and Ghidra decompilation to produce an executive Failure Evidence Dossier.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to target PE executable"
                },
                "crash_record": {
                    "type": "object",
                    "description": "Optional empirical crash record containing exception_code and fault_offset"
                },
                "ghidra_export": {
                    "type": "object",
                    "description": "Optional exported Ghidra decompilation payload"
                }
            },
            "required": ["binary_path"]
        }
    },
    {
        "name": "bintra_win_catalog_cmd",
        "description": "Safely executes a registered read-only Windows diagnostic command from the immutable Command Catalog (e.g. 'os_ver', 'sys_info', 'whoami_privs', 'proc_list', 'service_list', 'driver_list', 'pnp_devices_problem', 'power_cfg') with argument whitelisting and typed JSON output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command_id": {
                    "type": "string",
                    "description": "Catalog command ID to execute (e.g. 'driver_list', 'proc_list', 'sys_info', 'whoami_privs')"
                },
                "extra_flags": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional whitelisted arguments"
                }
            },
            "required": ["command_id"]
        }
    },
    {
        "name": "bintra_registry_audit",
        "description": "Windows Registry Editor & Intelligence suite: audits 11 OS domains, reads keys in 64/32/dual views, searches keys/values/data (regedit Ctrl+F), parses and diffs .reg files, and exports live keys to Windows Registry Editor Version 5.00 format.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["audit", "read", "search", "parse_reg", "export_reg", "diff_reg"],
                    "description": "Action: 'audit' (11-domain policy audit), 'read' (read registry key/values), 'search' (search keys/values/data), 'parse_reg' (parse .reg file AST), 'export_reg' (export key to .reg format), 'diff_reg' (compare .reg file against live registry)",
                    "default": "audit"
                },
                "domain": {
                    "type": "string",
                    "description": "Functional domain for 'audit' (e.g. 'OPERATING_SYSTEM', 'SECURITY_POLICIES', 'DLL_SEARCH_CONFIGURATION', 'KNOWN_DLLS')"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Optional target executable path to check for compatibility shims"
                },
                "hive": {
                    "type": "string",
                    "description": "Registry hive for read/search/export (HKLM, HKCU, HKCR, HKU, HKCC)",
                    "default": "HKLM"
                },
                "key": {
                    "type": "string",
                    "description": "Registry subkey path for read or export (e.g. 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion')"
                },
                "subkey": {
                    "type": "string",
                    "description": "Alias for key parameter"
                },
                "query": {
                    "type": "string",
                    "description": "Search term for 'search' action"
                },
                "reg_content": {
                    "type": "string",
                    "description": "Raw string content of .reg file for parse_reg or diff_reg"
                },
                "reg_path": {
                    "type": "string",
                    "description": "Filesystem path to .reg file for parse_reg, diff_reg, or output of export_reg"
                },
                "view": {
                    "type": "string",
                    "enum": ["dual", "64", "32"],
                    "description": "Architecture view flag (dual, 64, or 32)",
                    "default": "dual"
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Recursively export subkeys for 'export_reg' action",
                    "default": False
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum traversal depth for search or export_reg",
                    "default": 3
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results to return for search",
                    "default": 50
                }
            }
        }
    },
    {
        "name": "bintra_hardware_audit",
        "description": "Inspects live Plug and Play (PnP) hardware devices, display adapters, audio endpoints, and queries CM_Get_DevNode_Status for hardware problem codes (CM_PROB_*) via SetupAPI and CfgMgr32.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "offline_inf_paths": {"type": "array", "items": {"type": "string"}, "description": "Optional .inf file paths for offline cross-platform driver matching"}, "device_id": {"type": "string", "description": "Optional device instance ID for offline matching"}, "problems_only": {
                    "type": "boolean",
                    "description": "If true, only returns devices that report non-zero CM_PROB_* error codes"
                }
            }
        }
    },
    {
        "name": "bintra_port_audit",
        "description": "Conducts authoritative read-only audit of Windows serial communication ports (COM), parallel printer ports (LPT), and USB-to-UART bridge controllers (FTDI, CH340, CP210x, PL2303) with passive DCB and modem control line inspection (CTS/DSR/RING/DCD).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port_name": {
                    "type": "string",
                    "description": "Optional specific COM port name to inspect (e.g. 'COM1', 'COM3')"
                },
                "include_modem_status": {
                    "type": "boolean",
                    "description": "If true, queries DCB line configuration and modem control signals non-disruptively (default: true)"
                },
                "port_type": {
                    "type": "string",
                    "enum": ["all", "serial", "parallel"],
                    "description": "Filter by port type: 'all' (default), 'serial', or 'parallel'"
                }
            }
        }
    },
    {
        "name": "bintra_hardware_topology",
        "description": "Generates an authoritative PnP bus topology tree and directed hardware graph from Windows Kernel DevNodes and SetupAPI. Supports nested JSON hierarchy, ASCII indented tree, or Mermaid diagram (graph TD), with optional bus filtering (USB, PCI, ACPI) and problem pruning (CM_PROB_*).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "bus_filter": {
                    "type": "string",
                    "description": "Optional substring filter on bus / root instance prefix (e.g. 'USB', 'PCI', 'ACPI')"
                },
                "problems_only": {
                    "type": "boolean",
                    "description": "If true, only renders branches containing devices with non-zero CM_PROB_* error codes"
                },
                "format": {
                    "type": "string",
                    "enum": ["tree", "json", "mermaid"],
                    "description": "Output representation: 'tree' (indented ASCII, default), 'json' (nested hierarchy), or 'mermaid' (graph TD)"
                },
                "max_devices": {
                    "type": "integer",
                    "description": "Upper bound on devices to interrogate (default 300)"
                }
            }
        }
    },
    {
        "name": "bintra_network_audit",
        "description": "Enumerates live Windows network adapters, NDIS miniports, physical MAC addresses, link speeds, operational statuses, and IPv4/IPv6 addresses via iphlpapi.GetAdaptersAddresses.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "include_virtual": {
                    "type": "boolean",
                    "description": "If true, includes virtual, tunnel, and loopback adapters (default: true)"
                }
            }
        }
    },
    {
        "name": "bintra_network_hardware_dissect",
        "description": "Executes authoritative multi-layer reverse engineering for a specific network hardware device: PCIe Bus Topology -> NDIS & IP Telemetry -> PnP Driver Registry -> SCM Driver Service -> Driver PE32+ Forensics -> Live Ring-0 Kernel KASLR Slide.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_query": {
                    "type": "string",
                    "description": "Target network hardware keyword or driver service (e.g. 'wifi', 'intel', '8265', 'ethernet')"
                }
            }
        }
    },
    {
        "name": "bintra_network_connections",
        "description": "Audits active TCP network connections, local/remote IP and port pairs, connection states, and owning process PIDs via Win32 GetExtendedTcpTable.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Optional owning process PID filter (e.g. 10324)"
                }
            }
        }
    },
    {
        "name": "bintra_driver_audit",
        "description": "Enumerates all currently loaded Windows kernel drivers, their kernel virtual base addresses, image filenames, and highlights display and audio drivers via PSAPI.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "driver_name_filter": {
                    "type": "string",
                    "description": "Optional substring filter for driver file or base name"
                }
            }
        }
    },
    {
        "name": "bintra_service_audit",
        "description": "Interrogates the Windows Service Control Manager (SCM) via Advapi32 to audit active, stopped, or win32 services, their binary paths, and startup configurations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service_name_filter": {
                    "type": "string",
                    "description": "Optional substring filter for service name or display name"
                },
                "active_only": {
                    "type": "boolean",
                    "description": "If true, only returns currently running services"
                }
            }
        }
    },
    {
        "name": "bintra_dmp_inspect",
        "description": "Multi-stream MiniDump (.dmp) inspection and crash telemetry extraction: parses ExceptionRecord, SystemInfo, Loaded Modules, ThreadList, and performs Access Violation parameter analysis (NULL-pointer dereference detection, DEP violation).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dmp_path": {
                    "type": "string",
                    "description": "Path to .dmp file (if omitted, audits recent crash dumps in standard dump locations)"
                },
                "app_name_filter": {
                    "type": "string",
                    "description": "Optional filter for target application name when scanning dumps"
                }
            }
        }
    },
    {
        "name": "bintra_etw_audit",
        "description": "Inspects host Event Tracing for Windows (ETW) infrastructure: queries active/system-protected trace sessions, dynamically enumerates all registered system providers via TDH, and interrogates kernel provider registration and hosting PIDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Inspection action: 'audit' (default health audit), 'providers' (dynamic TDH system provider enumeration), 'provider_info' (query live kernel instances/PIDs for a GUID), 'active_kernel' (enumerate active kernel-registered providers), 'session' (query specific trace session)",
                    "enum": ["audit", "providers", "provider_info", "active_kernel", "session"],
                    "default": "audit"
                },
                "session_name": {
                    "type": "string",
                    "description": "Optional trace session name to query specifically (e.g. 'Eventlog-Application', 'DiagLog')"
                },
                "query": {
                    "type": "string",
                    "description": "Keyword filter for provider enumeration (e.g. 'Direct3D', 'Kernel', 'Memory')"
                },
                "guid": {
                    "type": "string",
                    "description": "Provider GUID string for provider_info query"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 50)",
                    "default": 50
                }
            }
        }
    },
    {
        "name": "bintra_vad_inspect",
        "description": "Inspects passive virtual memory (VAD) layout and classifies pointer addresses for a target Windows process (identifies PE modules, private heaps, thread stacks, mapped views, and null-page dereference traps).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Target process ID (PID) to inspect"
                },
                "address": {
                    "type": "string",
                    "description": "Optional 64-bit or 32-bit virtual memory address to classify (e.g. '0x7fff12340000')"
                },
                "include_regions": {
                    "type": "boolean",
                    "description": "If true, includes full listing of contiguous memory regions"
                }
            },
            "required": ["pid"]
        }
    },
    {
        "name": "bintra_memory_scan",
        "description": "Performs read-only virtual memory scanning across a target Windows process (First Scan / Next Scan) to locate addresses matching specific values (int8..uint64, float, double, bytes, string) and conditions (exact, between, unknown, changed, unchanged, increased, decreased).",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Target process ID (PID) to scan"
                },
                "session_id": {
                    "type": "string",
                    "description": "Optional scan session ID returned by an initial First Scan to filter via Next Scan"
                },
                "value_type": {
                    "type": "string",
                    "enum": [
                        "int8", "uint8", "int16", "uint16",
                        "int32", "uint32", "int64", "uint64",
                        "float", "double", "bytes", "string"
                    ],
                    "description": "Value type: 'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64', 'float', 'double', 'bytes', 'string'",
                    "default": "int32"
                },
                "scan_mode": {
                    "type": "string",
                    "enum": [
                        "exact", "between", "unknown",
                        "increased", "decreased", "changed", "unchanged"
                    ],
                    "description": "Scan mode: 'exact', 'between', 'unknown', 'increased', 'decreased', 'changed', 'unchanged'",
                    "default": "exact"
                },
                "target_value": {
                    "description": "Target numeric value, hex string for bytes, or search string"
                },
                "high_value": {
                    "description": "Optional upper bound for 'between' scan mode"
                },
                "candidate_addresses": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Optional list of candidate integer addresses for stateless exact/between Next Scan filtering"
                },
                "alignment": {
                    "type": "integer",
                    "description": "Scan byte stride alignment (default: natural type size; use 1 for unaligned hits)"
                },
                "writable_only": {
                    "type": "boolean",
                    "description": "Restrict First Scan to writable committed regions (default: true)",
                    "default": True
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of candidate matches to return (default: 100)",
                    "default": 100
                }
            },
            "required": ["pid"]
        }
    },
    {
        "name": "bintra_pointer_scan",
        "description": "Resolves multi-level static module base pointer chains pointing to a target dynamic address ([Module.dll + RVA] + Offset1 + Offset2 -> Target).",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Target process ID (PID)"
                },
                "target_address": {
                    "type": "string",
                    "description": "Target dynamic memory address (e.g. '0x7fff12340000')"
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum pointer indirection depth (1 to 3, default: 2)",
                    "default": 2
                },
                "max_offset": {
                    "type": "integer",
                    "description": "Maximum struct offset (default: 4096)",
                    "default": 4096
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of pointer paths to return (default: 20)",
                    "default": 20
                },
                "alignment": {
                    "type": "integer",
                    "description": "Pointer slot byte alignment stride (default: 4)",
                    "default": 4
                }
            },
            "required": ["pid", "target_address"]
        }
    },
    {
        "name": "bintra_struct_dissect",
        "description": "Performs runtime object memory field analysis at a target address: classifies virtual method tables (vftables), heap/stack pointers, floats, and integers, and synthesizes a formal C struct definition.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {
                    "type": "integer",
                    "description": "Target process ID (PID)"
                },
                "address": {
                    "type": "string",
                    "description": "Target object base address (e.g. '0x7fff12340000')"
                },
                "size": {
                    "type": "integer",
                    "description": "Size in bytes to dissect (default: 64)",
                    "default": 64
                },
                "struct_name": {
                    "type": "string",
                    "description": "Name for the generated C struct (default: 'DissectedObject')",
                    "default": "DissectedObject"
                }
            },
            "required": ["pid", "address"]
        }
    },
    {
        "name": "bintra_crash_rca",
        "description": "Performs automated root cause analysis (RCA) on a Windows MiniDump (.dmp): extracts ExceptionRecord, classifies violated memory address (Null-trap, heap, unmapped), disassembles the faulting instruction window using Capstone, identifies the culprit register (e.g. RCX=0x0), and provides actionable developer remediation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dmp_path": {
                    "type": "string",
                    "description": "Path to MiniDump (.dmp) file on disk"
                },
                "binary_path": {
                    "type": "string",
                    "description": "Optional path to target executable for local instruction disassembly"
                }
            },
            "required": ["dmp_path"]
        }
    },
    {
        "name": "bintra_etw_capture",
        "description": "Establishes a passive real-time ETW capture session (or queries active telemetry stream), enables kernel/graphics diagnostic providers (Kernel-Process, Kernel-Memory, Direct3D11, DXGI), and synthesizes a chronological timeline of events leading up to faults.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_name": {
                    "type": "string",
                    "description": "Name for ETW trace session (default: 'Bintra_Diagnostic_Trace')"
                },
                "pid": {
                    "type": "integer",
                    "description": "Optional target PID to filter events"
                },
                "duration_seconds": {
                    "type": "number",
                    "description": "Duration in seconds to sample real-time events (default: 1.0)"
                }
            }
        }
    },
    {
        "name": "bintra_ghidra_live_bridge",
        "description": "Bidirectional localhost JSON-RPC 2.0 IPC bridge connecting Bintra to Ghidra. Enables starting/stopping the bridge server, querying client connection status, and injecting Phase 1 VAD memory maps, Phase 1.5 structure dissections and pointer scan paths, Phase 2 Crash RCA annotations, and Phase 3 ETW timelines directly into Ghidra's Program Database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action to perform: 'start', 'status', 'inject_crash_rca', 'inject_vad', 'inject_etw', 'inject_struct', 'inject_pointers', or 'stop'",
                    "enum": ["start", "status", "inject_crash_rca", "inject_vad", "inject_etw", "inject_struct", "inject_pointers", "stop"]
                },
                "port": {
                    "type": "integer",
                    "description": "Port number for bridge server (default: 41718)"
                },
                "auth_token": {
                    "type": "string",
                    "description": "Optional authentication token"
                },
                "crash_dmp_path": {
                    "type": "string",
                    "description": "Path to MiniDump (.dmp) file for 'inject_crash_rca'"
                },
                "pid": {
                    "type": "integer",
                    "description": "Target Process ID for 'inject_vad', 'inject_struct', or 'inject_pointers'"
                },
                "address": {
                    "type": "string",
                    "description": "Target memory address for 'inject_struct' or 'inject_pointers'"
                },
                "struct_report": {
                    "type": "object",
                    "description": "Optional structure dissection report dictionary for 'inject_struct'"
                },
                "pointer_report": {
                    "type": "object",
                    "description": "Optional pointer scan report dictionary for 'inject_pointers'"
                },
                "timeline_report": {
                    "type": "object",
                    "description": "Optional timeline report dictionary for 'inject_etw'"
                },
                "publish_temp_marker": {
                    "type": "boolean",
                    "description": "For 'start': whether to publish a discovery marker in the system temp dir (default: true; mediated by cap.tempdir.marker.write)"
                }
            },
            "required": ["action"]
        }
    },
    {
        "name": "bintra_evidence_graph",
        "description": "Generates a formal directed Evidence Graph G = (V, E) and Mermaid flowchart connecting target binary PE sections, imported DLLs, Ghidra AST functions/blocks, host OS build, PnP hardware devices, kernel drivers, and empirical crash telemetry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Path to target PE executable on disk"
                },
                "crash_dmp_path": {
                    "type": "string",
                    "description": "Optional path to MiniDump (.dmp) file"
                },
                "ghidra_export": {
                    "type": "object",
                    "description": "Optional exported Ghidra JSON payload with functions and basic blocks"
                }
            },
            "required": ["binary_path"]
        }
    },
    {
        "name": "bintra_wsp_audit",
        "description": "Audits neural weights embedded inside Windows executables without execution: computes Roy-Vetterli spectral effective rank, cross-layer induction composition, amenability diagnostic, and scans for dormant backdoor/trojan neurons (>4.5σ).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model_path": {
                    "type": "string",
                    "description": "Path to safetensors model file"
                },
                "tensor": {
                    "type": "string",
                    "description": "Optional tensor name to audit"
                }
            },
            "required": ["model_path"]
        }
    },
    {
        "name": "bintra_patch_weights",
        "description": "Surgically patches linear projection weights in a safetensors file without gradients, using selective column direction subtraction to eliminate pathological looping.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_path": {
                    "type": "string",
                    "description": "Input safetensors file path"
                },
                "output_path": {
                    "type": "string",
                    "description": "Output patched safetensors file path"
                },
                "tensor_name": {
                    "type": "string",
                    "description": "Name of weight tensor to patch"
                },
                "num_columns": {
                    "type": "integer",
                    "description": "Number of extreme columns to subtract (default: 64)"
                }
            },
            "required": ["source_path", "output_path", "tensor_name"]
        }
    },
    {
        "name": "bintra_device_driver_intelligence",
        "description": "Device Manager telemetry and deep driver intelligence: categorizes device classes, lists live devices with driver versions, searches devices by name/ID/vendor, inspects full Device Manager property sheets, and performs Driver Rank matching.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["audit", "match", "find_packages", "device_classes", "list_devices", "search_devices", "device_details"],
                    "description": "Action: 'audit' (Driver Rank audit), 'match' (match hardware IDs), 'find_packages' (search driver packages), 'device_classes' (hierarchical class summary), 'list_devices' (enumerate devices with driver metadata), 'search_devices' (instant multi-field search), 'device_details' (full Device Manager property sheet)",
                    "default": "audit"
                },
                "device_query": {
                    "type": "string",
                    "description": "Optional search term matching device name, instance ID, vendor, or hardware ID"
                },
                "device_id_or_name": {
                    "type": "string",
                    "description": "Target device name or instance ID for 'device_details' action"
                },
                "class_filter": {
                    "type": "string",
                    "description": "Optional device class filter (e.g. 'Display', 'Net', 'USB', 'Audio')"
                },
                "problems_only": {
                    "type": "boolean",
                    "description": "Filter to devices with active problem codes (CM_PROB_*)",
                    "default": False
                },
                "max_devices": {
                    "type": "integer",
                    "description": "Maximum number of devices to inspect",
                    "default": 64
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum items to return for list_devices and search_devices",
                    "default": 200
                }
            }
        }
    },
    {
        "name": "bintra_process_resource_audit",
        "description": "Inspects running processes, in-memory loaded modules, file lock handles via Windows Restart Manager, service-to-process hosting mappings, and Windows Task Manager telemetry (RAM, CPU, I/O, handles, threads, performance tab).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "find_file_locks",
                        "find_module_holders",
                        "process_tree",
                        "service_process_map",
                        "audit_process",
                        "list_processes",
                        "search_processes",
                        "system_performance"
                    ],
                    "description": "Action: 'find_file_locks', 'find_module_holders', 'process_tree', 'service_process_map', 'audit_process' (Task Manager deep dive on PID), 'list_processes' (live Task Manager process table), 'search_processes' (filter processes by query), 'system_performance' (Task Manager Performance tab)",
                    "default": "find_file_locks"
                },
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to file on disk to check for active lock handles or running image"
                },
                "module_query": {
                    "type": "string",
                    "description": "DLL name or keyword to search across loaded process modules"
                },
                "pid": {
                    "type": "integer",
                    "description": "Process ID for detailed inspection"
                },
                "query": {
                    "type": "string",
                    "description": "Search query (process name, PID, username, command line) for 'search_processes' or 'list_processes'"
                },
                "sort_by": {
                    "type": "string",
                    "enum": ["memory", "commit", "threads", "handles", "pid", "name"],
                    "description": "Sorting metric for 'list_processes' (default: memory)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum processes to return (default: 50)"
                }
            }
        }
    }
    ,
    {
        "name": "bintra_python_bytecode",
        "description": "Strictly read-only CPython bytecode and package architecture analyzer: inspects .py/.pyc or entire package directory to extract module topology, circular dependencies, McCabe/Cognitive complexity, and ReDoS/quadratic hazards.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to Python source file (.py), compiled bytecode (.pyc), or package directory"},
                "compare_with": {"type": "string", "description": "Optional second .py/.pyc path for WL-CFG bytecode diffing"},
                "limit": {"type": "integer", "description": "Maximum code objects to analyze (default 50)"},
                "complexity_threshold": {"type": "integer", "description": "Complexity threshold for hotspot detection in package mode (default 15)"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "bintra_cpython_memory_forensics",
        "description": "Strictly read-only CPython heap memory forensics using VirtualMemoryInspector and StructureDissector to inspect PyObject, PyASCIIObject, PyLongObject, and PyDictObject.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target Windows process ID"},
                "address": {"type": "string", "description": "Hex virtual address of the CPython object (e.g. 0x7ff612340000)"},
                "object_type": {"type": "string", "enum": ["pyobject", "pydict", "pyascii", "pylong"], "description": "CPython object layout to decode"}
            },
            "required": ["pid", "address"]
        }
    },
    {
        "name": "bintra_pe_deep_forensics",
        "description": "Strictly read-only deep PE32/PE32+ forensics: recovers x64 .pdata RUNTIME_FUNCTION boundaries, MSVC RTTI classes/vftables, and verifies local offline PDB/RSDS matches (zero network).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to PE executable or DLL"},
                "pdb_path": {"type": "string", "description": "Optional explicit local .pdb path for offline RSDS verification"},
                "limit": {"type": "integer", "description": "Maximum entries per section (default 25 to optimize token efficiency; pass higher for exhaustive dumps)"}
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "bintra_binary_diff",
        "description": "Strictly read-only semantic diffing across two PE binaries (.pdata/RTTI/SHA256) or two Ghidra P-Code JSON exports using WL-CFG hashing, 64-D P-Code cosine, and API/String anchor Jaccard.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_path": {"type": "string", "description": "Path to baseline PE binary or Ghidra export JSON"},
                "target_path": {"type": "string", "description": "Path to target PE binary or Ghidra export JSON"},
                "mode": {"type": "string", "enum": ["pe", "ghidra_export"], "description": "Diff mode: pe (default) or ghidra_export"}
            },
            "required": ["baseline_path", "target_path"]
        }
    },
    {
        "name": "bintra_ghidra_call_graph",
        "description": "Strictly read-only Call-Graph, XREF topology, indirect call, and sensitive Win32 API reachability analyzer for Ghidra JSON exports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "export_path": {"type": "string", "description": "Path to Ghidra JSON export file"},
                "target_function": {"type": "string", "description": "Optional root function name for BFS subgraph extraction"},
                "max_depth": {"type": "integer", "description": "BFS subgraph depth (default 4)"}
            },
            "required": ["export_path"]
        }
    },
    {
        "name": "bintra_ghidra_data_flow",
        "description": "Strictly read-only intra-procedural High P-Code SSA def-use backward/forward slice and Decompiler C AST/local variable correlator.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "export_path": {"type": "string", "description": "Path to Ghidra JSON export file"},
                "function_name": {"type": "string", "description": "Target function name or entry address"},
                "target_var": {"type": "string", "description": "Optional SSA varnode/variable name to slice backward from"}
            },
            "required": ["export_path", "function_name"]
        }
    },
    {
        "name": "bintra_ghidra_similar_functions",
        "description": "Behavioral nearest-routine search: ranks every function in a Ghidra export against a reference routine using the 64-D High P-Code semantic vectorizer (architecture- and optimization-invariant cosine similarity). Use it to locate clone routines, inlined variants, or ported logic inside one program.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "export_path": {
                    "type": "string",
                    "description": "Path to Ghidra export (.json, .jsonl, or .db) to search"
                },
                "reference_function": {
                    "type": "string",
                    "description": "Reference function name or entry address that exists in the export"
                },
                "reference_pcode": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "Externally supplied P-code operation stream (list of {opcode, inputs, output} objects) to search against, e.g. from another binary or a known-bad sample"
                },
                "threshold": {
                    "type": "number",
                    "description": "Minimum cosine similarity to report (default 0.75)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum matches to return (default 20)"
                },
                "min_pcode_ops": {
                    "type": "integer",
                    "description": "Minimum P-code operations for a function to be indexed (default 1; raise to skip thunks)"
                }
            },
            "required": ["export_path"]
        }
    },
    {
        "name": "bintra_fuse_evidence",
        "description": "Strictly read-only multi-signal causal fusion combining PE deep forensics (.pdata/RTTI/PDB), MiniDump Crash RCA, and Ghidra Call-Graph/Data-Flow into an EvidenceGraph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Optional path to target PE binary"},
                "dmp_path": {"type": "string", "description": "Optional path to MiniDump (.dmp) file"},
                "ghidra_export_path": {"type": "string", "description": "Optional path to Ghidra JSON export file"},
                "function_name": {"type": "string", "description": "Optional function name for data-flow slice fusion"}
            }
        }
    },
    {
        "name": "bintra_triage_binary",
        "description": "End-to-end read-only binary triage orchestrator combining PE inspection (mitigations/entropy), PE deep forensics (.pdata/RTTI/PDB), Authenticode/Catalog signature intelligence, obfuscation triage, optional MiniDump crash RCA, optional Ghidra call-graph/data-flow, and unified EvidenceGraph synthesis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute filesystem path to the target binary (.exe, .dll, or .sys)"
                },
                "dmp_path": {
                    "type": "string",
                    "description": "Optional MiniDump (.dmp) file path for crash RCA correlation"
                },
                "ghidra_export_path": {
                    "type": "string",
                    "description": "Optional Ghidra export (.json, .jsonl, or .db) for call-graph and data-flow fusion"
                },
                "function_name": {
                    "type": "string",
                    "description": "Optional target function name or address for focused Ghidra call-graph and data-flow slicing"
                },
                "include_deobfuscation": {
                    "type": "boolean",
                    "description": "Run entry-point obfuscation/CFF triage (default true)"
                },
                "include_sensory": {
                    "type": "boolean",
                    "description": "Run holistic 10-sense Sensory Cortex perception stage (default true)"
                },
                "include_hybrid_scan": {
                    "type": "boolean",
                    "description": "Scan for embedded neural inference assets (ONNX/TFLite/DirectML/GGUF) (default true)"
                },
                "max_exports": {
                    "type": "integer",
                    "description": "Maximum PE exports to include (default 32)"
                },
                "forensics_limit": {
                    "type": "integer",
                    "description": "Maximum .pdata/RTTI entries to extract (default 200)"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "bintra_list_capabilities",
        "description": "Self-describing capability manifest for AI agents: returns all registered Bintra MCP tools, environment requirements (cross_platform vs windows_native vs ghidra_required), security modes, and recommended decision workflows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "platform_filter": {"type": "string", "enum": ["all", "cross_platform", "windows_native", "ghidra_required"], "description": "Filter tools by execution environment"}
            }
        },
        "outputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["ok"]},
                "host_os": {"type": "string", "description": "Operating system family of the MCP host (e.g. Windows, Linux)"},
                "total_tools": {"type": "integer", "minimum": 0},
                "tools": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "environment": {"type": "string", "enum": ["cross_platform", "windows_native", "ghidra_required"]},
                            "capability": {"type": "string"},
                            "access_mode": {"type": "string"}
                        },
                        "required": ["name", "environment", "capability", "access_mode"]
                    }
                },
                "recommended_workflows": {"type": "object"}
            },
            "required": ["status", "host_os", "total_tools", "tools"]
        }
    },
    {
        "name": "bintra_profile_process",
        "description": "Passive longitudinal resource profiler and leak diagnosis engine for Windows processes. Collects Private Bytes (PagefileUsage), Working Set, Kernel Handles, and GDI/USER resources across multiple samples. Computes linear regression slopes and classifies behavior into STABLE, SATURATION_PLATEAU, or ACTIVE_LEAK.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Target Windows process ID (PID) to profile"},
                "samples_count": {"type": "integer", "default": 10, "description": "Number of consecutive samples to record"},
                "interval_seconds": {"type": "number", "default": 0.2, "description": "Sampling interval in seconds"}
            },
            "required": ["pid"]
        }
    },
    {
        "name": "bintra_inspect_slack_space",
        "description": "Audits binary slack space, PE overlays, and document EOF padding. Detects data beyond official boundaries: PE overlays (Authenticode certs, installer payloads, high-entropy packed data) and RTF/XML document trailing slack (such as MFC/WordPad trailing NUL 0x00 bytes).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Absolute filesystem path to target binary or document"}
            },
            "required": ["file_path"]
        }
    }
]


class BintraMcpServer:
    """Standard MCP Stdio JSON-RPC Server."""

    def __init__(
        self,
        workspace_root: Optional[str] = None,
        allowed_workspace_roots: Optional[List[str]] = None,
    ):
        self.handlers = {
            "initialize": self.handle_initialize,
            "notifications/initialized": self.handle_initialized_notification,
            "server/discover": self.handle_server_discover,
            "mcp/discover": self.handle_server_discover,
            "discovery": self.handle_server_discover,
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
            "resources/list": self.handle_resources_list,
            "resources/read": self.handle_resources_read,
            "prompts/list": self.handle_prompts_list,
            "prompts/get": self.handle_prompts_get,
            "ping": self.handle_ping,
        }
        self._tool_schemas = {
            t["name"]: t.get("inputSchema", {})
            for t in TOOLS_REGISTRY
        }
        self.token_tracker = TokenSessionTracker(model=os.environ.get("BINTRA_MODEL_PRICING", "claude-3.5-sonnet"))
        from security import PathIdentity, TargetScope, AuditLogger
        AuditLogger.ensure_chain_continuity(rotate_on_corrupt=True)
        default_ws = os.path.join(os.path.expanduser("~"), ".bintra", "workspace")
        chosen_ws = workspace_root or os.environ.get("BINTRA_MCP_WORKSPACE") or default_ws
        os.makedirs(chosen_ws, exist_ok=True)
        can_host_ws = PathIdentity.canonicalize(chosen_ws)
        unsafe_reason = TargetScope._is_unsafe_workspace_root(can_host_ws)
        if unsafe_reason:
            raise PermissionError(
                f"UNSAFE_WORKSPACE_ROOT ({unsafe_reason}): Host MCP workspace '{can_host_ws}' is unsafe."
            )
        self._host_workspace = can_host_ws

        raw_allowed = [can_host_ws]
        if allowed_workspace_roots:
            raw_allowed.extend(allowed_workspace_roots)
        env_allowed = os.environ.get("BINTRA_MCP_ALLOWED_WORKSPACES", "")
        if env_allowed:
            raw_allowed.extend([p.strip() for p in env_allowed.split(os.pathsep) if p.strip()])
        self._allowed_workspace_roots: List[str] = []
        for root in raw_allowed:
            if not root:
                continue
            can_root = PathIdentity.canonicalize(root)
            if not TargetScope._is_unsafe_workspace_root(can_root) and can_root not in self._allowed_workspace_roots:
                self._allowed_workspace_roots.append(can_root)

    def _resolve_server_workspace(self, args: Dict[str, Any]) -> str:
        """
        Derives the active workspace server-side.
        Rejects untrusted client-supplied workspace_dir overrides unless explicitly
        inside host-authorized workspace roots.
        """
        from security import PathIdentity, SecurityViolationError, AuditLogger, TargetScope
        client_ws = args.get("workspace_dir") or args.get("workspace")
        if not client_ws:
            return self._host_workspace
        try:
            can_client_ws = PathIdentity.canonicalize(str(client_ws))
        except Exception as exc:
            raise SecurityViolationError(f"UNTRUSTED_WORKSPACE_OVERRIDE: Invalid workspace '{client_ws}': {exc}")

        if not TargetScope._is_unsafe_workspace_root(can_client_ws):
            for allowed_root in self._allowed_workspace_roots:
                if PathIdentity.is_same_file(can_client_ws, allowed_root) or PathIdentity.is_within_directory(can_client_ws, allowed_root):
                    return can_client_ws

        AuditLogger.log_decision(
            component="mcp_server",
            operation="workspace_override",
            target=str(client_ws),
            decision="DENY",
            reason="UNTRUSTED_WORKSPACE_OVERRIDE",
            requested_capability="cap.workspace.write",
            result="DENIED",
        )
        raise SecurityViolationError(
            f"UNTRUSTED_WORKSPACE_OVERRIDE: Client-supplied workspace '{client_ws}' is not authorized by host MCP configuration."
        )

    @staticmethod
    def _matches_json_type(val: Any, json_type: Any) -> bool:
        types = json_type if isinstance(json_type, (list, tuple)) else [json_type]
        for t in types:
            if t == "string" and isinstance(val, str):
                return True
            if t == "integer" and isinstance(val, int) and not isinstance(val, bool):
                return True
            if t == "number" and isinstance(val, (int, float)) and not isinstance(val, bool):
                return True
            if t == "boolean" and isinstance(val, bool):
                return True
            if t == "array" and isinstance(val, list):
                return True
            if t == "object" and isinstance(val, dict):
                return True
            if t == "null" and val is None:
                return True
        return False

    def _validate_tool_arguments(self, tool_name: str, args: Any) -> None:
        """Validates tool arguments strictly against declared JSON inputSchema (required, types, enums, and no unknown fields)."""
        if args is None:
            args = {}
        if not isinstance(args, dict):
            raise ValueError(f"Invalid arguments for '{tool_name}': expected JSON object matching inputSchema.")
        schema = self._tool_schemas.get(tool_name)
        if not schema:
            return
        required = schema.get("required", [])
        missing = [req for req in required if req not in args or args[req] is None]
        if missing:
            raise ValueError(
                f"Missing required parameter(s) for '{tool_name}': {', '.join(missing)}."
            )
        props = schema.get("properties", {})
        unknown = [k for k in args.keys() if k not in props and k not in ("workspace_dir", "compact", "summary_only", "max_list_items")]
        if unknown:
            raise ValueError(
                f"Unknown parameter(s) for '{tool_name}': {', '.join(sorted(unknown))}."
            )
        for key, val in args.items():
            if key not in props or val is None:
                continue
            spec = props[key]
            expected_type = spec.get("type")
            if expected_type and not self._matches_json_type(val, expected_type):
                raise ValueError(
                    f"Invalid type for parameter '{key}' in '{tool_name}': "
                    f"expected {expected_type}, got {type(val).__name__}."
                )
            if expected_type == "array" and isinstance(spec.get("items"), dict) and spec["items"].get("type"):
                item_type = spec["items"]["type"]
                for idx, elem in enumerate(val):
                    if not self._matches_json_type(elem, item_type):
                        raise ValueError(
                            f"Invalid item type at '{key}[{idx}]' in '{tool_name}': "
                            f"expected {item_type}, got {type(elem).__name__}."
                        )
            allowed = spec.get("enum")
            if allowed and val not in allowed:
                raise ValueError(
                    f"Invalid value for parameter '{key}' in '{tool_name}': "
                    f"expected one of {allowed}, got {val!r}."
                )

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        req_ver = None
        if isinstance(params, dict):
            req_ver = params.get("io.modelcontextprotocol/protocolVersion") or params.get("protocolVersion")
        if req_ver is not None:
            if req_ver in SUPPORTED_PROTOCOL_VERSIONS:
                negotiated_version = req_ver
            else:
                # Per MCP 2026-07-28 specification: explicitly reject unsupported protocol versions!
                raise ValueError(
                    f"Unsupported protocol version: '{req_ver}'. "
                    f"Supported versions: {SUPPORTED_PROTOCOL_VERSIONS}"
                )
        else:
            negotiated_version = DEFAULT_PROTOCOL_VERSION

        return {
            "protocolVersion": negotiated_version,
            "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {
                    "listChanged": False
                },
                "resources": {
                    "subscribe": False,
                    "listChanged": False
                },
                "prompts": {
                    "listChanged": False
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            }
        }

    def handle_server_discover(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Stateless MCP 2026-07-28 server discovery handler."""
        return {
            "name": SERVER_NAME,
            "version": SERVER_VERSION,
            "protocolVersion": LATEST_PROTOCOL_VERSION,
            "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "capabilities": {
                "tools": {"listChanged": False},
                "resources": {"subscribe": False, "listChanged": False},
                "prompts": {"listChanged": False},
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION,
            },
        }

    def handle_initialized_notification(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def handle_ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    MCP_TOOL_PROFILES = {
        "core": {
            "bintra_triage_binary", "bintra_inspect_binary", "bintra_pe_deep_forensics",
            "bintra_sensory_audit", "bintra_deobfuscate_binary", "bintra_binary_diff",
            "bintra_list_capabilities",
        },
        "static": {
            "bintra_triage_binary", "bintra_inspect_binary", "bintra_pe_deep_forensics",
            "bintra_deobfuscate_binary", "bintra_dump_bytes", "bintra_match_functions",
            "bintra_scan_hybrid", "bintra_sensory_audit", "bintra_binary_diff",
            "bintra_patch_binary", "bintra_list_capabilities",
        },
        "ghidra": {
            "bintra_ghidra_analyze", "bintra_ghidra_headless", "bintra_ghidra_live_bridge",
            "bintra_ghidra_call_graph", "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions",
            "bintra_match_pcode", "bintra_deobfuscate_pcode", "bintra_fuse_evidence",
            "bintra_list_capabilities",
        },
        "neural": {
            "bintra_sensory_audit", "bintra_scan_hybrid", "bintra_wsp_audit",
            "bintra_patch_weights", "bintra_list_capabilities",
        },
    }

    TOOLS_LIST_PAGE_SIZE = 25

    def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        params = params or {}
        profile = (params.get("profile") or os.environ.get("BINTRA_MCP_PROFILE", "all")).lower()
        compact = (
            bool(params["compact"])
            if "compact" in params
            else (os.environ.get("BINTRA_MCP_COMPACT_SCHEMAS") == "1")
        )
        tools = TOOLS_REGISTRY
        if profile in self.MCP_TOOL_PROFILES:
            allowed = self.MCP_TOOL_PROFILES[profile]
            tools = [t for t in TOOLS_REGISTRY if t["name"] in allowed]
        elif profile == "windows":
            tools = [t for t in TOOLS_REGISTRY if t["name"] not in self.MCP_TOOL_PROFILES["neural"] or t["name"] == "bintra_list_capabilities"]

        # MCP 2025-06-18 pagination: when the client supplies an opaque cursor,
        # serve a fixed-size page and advertise nextCursor while more tools remain.
        # Without a cursor the full (possibly profile-filtered) list is returned in
        # one page for backward compatibility with older clients.
        offset = 0
        cursor = params.get("cursor")
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor.isdigit():
                raise ValueError(
                    f"Invalid tools/list cursor: {cursor!r}. Use the opaque nextCursor value returned by a previous page."
                )
            offset = int(cursor)
            if offset < 0 or offset >= len(tools):
                raise ValueError(f"tools/list cursor out of range: {cursor!r}")
        page = tools[offset : offset + self.TOOLS_LIST_PAGE_SIZE] if cursor is not None else tools
        next_offset = offset + self.TOOLS_LIST_PAGE_SIZE if cursor is not None else 0

        enriched_tools = []
        for t in page:
            item = compact_tool_schema(t) if compact else dict(t)
            item["annotations"] = self._derive_tool_annotations(item["name"])
            enriched_tools.append(item)

        base_tok = estimate_tokens(TOOLS_REGISTRY)
        act_tok = estimate_tokens(enriched_tools)
        self.token_tracker.record_schema_footprint(act_tok, base_tok)
        result: Dict[str, Any] = {
            "tools": enriched_tools
        }
        if cursor is not None and next_offset < len(tools):
            result["nextCursor"] = str(next_offset)
        return result

    @classmethod
    def _derive_tool_annotations(cls, tool_name: str) -> Dict[str, Any]:
        """Derives authoritative MCP Tool Annotations from TOOL_SECURITY_METADATA."""
        sec = cls.TOOL_SECURITY_METADATA.get(tool_name, ("cap.file.read", "READ", None))
        cap_val, mode, _ = sec
        is_read_only = mode in ("READ", "QUERY") and cap_val not in (
            "cap.workspace.write", "cap.ghidra.headless_exec", "cap.ghidra.project_mutate", "cap.binary.patch"
        )
        is_destructive = not is_read_only and (
            cap_val in ("cap.workspace.write", "cap.ghidra.project_mutate", "cap.binary.patch")
            or any(kw in tool_name for kw in ("patch", "modify", "mutate"))
        )
        return {
            "readOnlyHint": is_read_only,
            "destructiveHint": is_destructive,
            "idempotentHint": is_read_only,
            "openWorldHint": False,
        }

    MCP_RESOURCES: List[Dict[str, Any]] = [
        {
            "uri": "bintra://capabilities",
            "name": "Bintra Capability Catalog",
            "description": "Live platform-aware manifest of all registered Bintra MCP tools, capabilities, and workflows.",
            "mimeType": "application/json",
        },
        {
            "uri": "bintra://security/policy",
            "name": "Bintra Security Kernel Policy",
            "description": "Active workspace boundary, prohibited hazard capabilities, and component capability grants.",
            "mimeType": "application/json",
        },
        {
            "uri": "bintra://telemetry/session",
            "name": "Bintra Token Efficiency Telemetry",
            "description": "Current MCP session token footprint, call count, and token savings summary.",
            "mimeType": "application/json",
        },
        {
            "uri": "bintra://workflows/playbooks",
            "name": "Bintra Reverse Engineering Playbooks",
            "description": "Structured multi-tool workflows for PE triage, crash RCA, Ghidra analysis, and Windows auditing.",
            "mimeType": "application/json",
        },
    ]

    MCP_PROMPTS: List[Dict[str, Any]] = [
        {
            "name": "triage_pe_binary",
            "description": "Run a complete read-only triage of a Windows PE binary combining headers, .pdata/RTTI/PDB, digital signature trust, obfuscation, and optional crash/Ghidra correlation.",
            "arguments": [
                {"name": "file_path", "description": "Absolute path to the target binary (.exe, .dll, .sys)", "required": True},
                {"name": "dmp_path", "description": "Optional MiniDump (.dmp) file path", "required": False},
                {"name": "ghidra_export_path", "description": "Optional Ghidra export (.json/.jsonl/.db) path", "required": False},
            ],
        },
        {
            "name": "root_cause_crash",
            "description": "Correlate a Windows MiniDump (.dmp) crash with static PE forensics and Ghidra call-graph/data-flow evidence.",
            "arguments": [
                {"name": "dmp_path", "description": "Path to MiniDump (.dmp) file", "required": True},
                {"name": "binary_path", "description": "Optional faulting binary path", "required": False},
                {"name": "ghidra_export_path", "description": "Optional Ghidra export path", "required": False},
            ],
        },
        {
            "name": "audit_windows_host",
            "description": "Perform a read-only Windows host security, driver, service, and telemetry audit.",
            "arguments": [
                {"name": "focus", "description": "Audit domain: all, drivers, network, processes, or registry", "required": False},
            ],
        },
        {
            "name": "diff_binary_versions",
            "description": "Compare two versions of a binary semantically using WL-CFG hashing, P-Code behavior vectors, and API anchors.",
            "arguments": [
                {"name": "baseline_path", "description": "Path to baseline binary or Ghidra export", "required": True},
                {"name": "target_path", "description": "Path to target binary or Ghidra export", "required": True},
            ],
        },
        {
            "name": "audit_neural_weights",
            "description": "Zero-execution security audit of neural weights embedded in a binary or shipped as a Safetensors model: outlier-neuron trojan detection, spectral effective rank, and surgical amenability.",
            "arguments": [
                {"name": "target_path", "description": "Path to the hybrid binary or .safetensors model to audit", "required": True},
                {"name": "scan_embedded", "description": "First run hybrid embedded-AI scanning on a PE binary (default true)", "required": False},
            ],
        },
    ]

    def handle_resources_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"resources": list(self.MCP_RESOURCES)}

    def handle_resources_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = (params or {}).get("uri")
        if not uri or not isinstance(uri, str):
            raise ValueError("Missing required parameter 'uri' for resources/read.")

        if uri == "bintra://capabilities":
            payload = self.dispatch_tool("bintra_list_capabilities", {"platform_filter": "all"})
        elif uri == "bintra://security/policy":
            from security.capability_registry import PROHIBITED_HAZARDS, CapabilityRegistry
            payload = {
                "host_workspace": self._host_workspace,
                "allowed_workspace_roots": list(self._allowed_workspace_roots),
                "prohibited_hazards": sorted(h.value for h in PROHIBITED_HAZARDS),
                "registered_components_count": len(CapabilityRegistry.COMPONENT_CAPABILITIES),
                "target_immutability": True,
            }
        elif uri == "bintra://telemetry/session":
            payload = self.token_tracker.summary()
        elif uri == "bintra://workflows/playbooks":
            payload = {
                "playbooks": {
                    "unified_binary_triage": ["bintra_triage_binary"],
                    "static_pe_deep_audit": ["bintra_inspect_binary", "bintra_pe_deep_forensics", "bintra_deobfuscate_binary", "bintra_scan_hybrid", "bintra_sensory_audit"],
                    "ghidra_deep_re": ["bintra_ghidra_analyze", "bintra_ghidra_call_graph", "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions"],
                    "crash_root_cause_fusion": ["bintra_dmp_inspect", "bintra_crash_rca", "bintra_pe_deep_forensics", "bintra_fuse_evidence"],
                    "differential_binary_audit": ["bintra_binary_diff", "bintra_match_functions", "bintra_match_pcode", "bintra_ghidra_similar_functions"],
                    "windows_host_audit": ["bintra_windows_env_audit", "bintra_driver_audit", "bintra_service_audit", "bintra_network_connections"],
                }
            }
        else:
            raise ValueError(f"Unknown Bintra MCP resource URI: '{uri}'.")

        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": json.dumps(payload, indent=2, ensure_ascii=False),
                }
            ]
        }

    def handle_prompts_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {"prompts": list(self.MCP_PROMPTS)}

    def handle_prompts_get(self, params: Dict[str, Any]) -> Dict[str, Any]:
        params = params or {}
        name = params.get("name")
        p_args = params.get("arguments") or {}
        if not name or not isinstance(name, str):
            raise ValueError("Missing required parameter 'name' for prompts/get.")

        if name == "triage_pe_binary":
            fp = p_args.get("file_path")
            if not fp:
                raise ValueError("Prompt 'triage_pe_binary' requires argument 'file_path'.")
            extra = []
            if p_args.get("dmp_path"):
                extra.append(f"dmp_path='{p_args['dmp_path']}'")
            if p_args.get("ghidra_export_path"):
                extra.append(f"ghidra_export_path='{p_args['ghidra_export_path']}'")
            extra_str = (", " + ", ".join(extra)) if extra else ""
            text = (
                f"Perform a read-only Bintra binary triage on '{fp}'. "
                f"Start by calling bintra_triage_binary(file_path='{fp}'{extra_str}). "
                f"Report observed facts separately from heuristic indicators, include digital signature trust status, "
                f"and recommend concrete next tools if obfuscation or missing symbols are detected."
            )
        elif name == "root_cause_crash":
            dp = p_args.get("dmp_path")
            if not dp:
                raise ValueError("Prompt 'root_cause_crash' requires argument 'dmp_path'.")
            bp = p_args.get("binary_path", "")
            gp = p_args.get("ghidra_export_path", "")
            text = (
                f"Investigate the Windows crash dump at '{dp}'. "
                f"Run bintra_dmp_inspect and bintra_crash_rca on '{dp}', then fuse evidence with "
                f"bintra_fuse_evidence(dmp_path='{dp}', binary_path='{bp}', ghidra_export_path='{gp}'). "
                f"Distinguish confirmed faulting module/RVA facts from root-cause hypotheses."
            )
        elif name == "audit_windows_host":
            focus = p_args.get("focus", "all")
            text = (
                f"Run a read-only Windows host audit focused on '{focus}'. "
                f"Use bintra_windows_env_audit alongside relevant introspection tools "
                f"(bintra_driver_audit, bintra_service_audit, bintra_network_connections, bintra_registry_audit). "
                f"Flag any non-Windows degradation explicitly instead of guessing host state."
            )
        elif name == "diff_binary_versions":
            b_path = p_args.get("baseline_path")
            t_path = p_args.get("target_path")
            if not b_path or not t_path:
                raise ValueError("Prompt 'diff_binary_versions' requires 'baseline_path' and 'target_path'.")
            text = (
                f"Perform a semantic binary differential analysis between baseline '{b_path}' and target '{t_path}'. "
                f"Call bintra_binary_diff(baseline_path='{b_path}', target_path='{t_path}') and summarize added, "
                f"removed, and behaviorally modified routines."
            )
        elif name == "audit_neural_weights":
            tp = p_args.get("target_path")
            if not tp:
                raise ValueError("Prompt 'audit_neural_weights' requires argument 'target_path'.")
            text = (
                f"Audit the neural inference logic at '{tp}' without executing it. "
                f"If it is a PE binary, first call bintra_scan_hybrid(file_path='{tp}') to enumerate embedded AI "
                f"assets (ONNX, TFLite, DirectML, GGUF), then call bintra_wsp_audit(model_path='{tp}') when a "
                f"Safetensors-compatible tensor store is present. Report trojan/outlier-neuron indicators, "
                f"spectral effective rank, and whether selective column surgery (bintra_patch_weights) is "
                f"indicated. Separate measured facts from heuristic indicators."
            )
        else:
            raise ValueError(f"Unknown Bintra MCP prompt: '{name}'.")

        return {
            "description": next((p["description"] for p in self.MCP_PROMPTS if p["name"] == name), ""),
            "messages": [
                {
                    "role": "user",
                    "content": {"type": "text", "text": text},
                }
            ],
        }

    TOOL_SECURITY_METADATA = {
        "bintra_inspect_binary": ("cap.file.read", "READ", "file_path"),
        "bintra_deobfuscate_binary": ("cap.file.read", "READ", "file_path"),
        "bintra_dump_bytes": ("cap.file.read", "READ", "file_path"),
        "bintra_match_functions": ("cap.file.read", "READ", None),
        "bintra_patch_binary": ("cap.workspace.write", "WRITE", "output_path"),
        "bintra_scan_hybrid": ("cap.file.read", "READ", "file_path"),
        "bintra_sensory_audit": ("cap.file.read", "READ", "file_path"),
        "bintra_match_pcode": ("cap.file.read", "READ", None),
        "bintra_deobfuscate_pcode": ("cap.file.read", "READ", None),
        "bintra_ghidra_analyze": ("cap.file.read", "READ", "input_file"),
        "bintra_ghidra_headless": ("cap.ghidra.headless_exec", "EXECUTE", "binary_path"),
        "bintra_windows_env_audit": ("cap.registry.read", "READ", "file_path"),
        "bintra_resolve_dependencies": ("cap.file.read", "READ", "file_path"),
        "bintra_inspect_crash_reports": ("cap.minidump.read", "READ", "file_path"),
        "bintra_correlate_failure_evidence": ("cap.file.read", "READ", "binary_path"),
        "bintra_win_catalog_cmd": ("cap.subprocess.catalog_exec", "EXECUTE", "command_id"),
        "bintra_registry_audit": ("cap.registry.read", "READ", "domain"),
        "bintra_hardware_audit": ("cap.device.query", "QUERY", None),
        "bintra_port_audit": ("cap.device.query", "QUERY", "port_name"),
        "bintra_hardware_topology": ("cap.device.query", "QUERY", "bus_filter"),
        "bintra_network_audit": ("cap.device.query", "QUERY", None),
        "bintra_network_hardware_dissect": ("cap.device.query", "QUERY", "target_query"),
        "bintra_network_connections": ("cap.device.query", "QUERY", "pid"),
        "bintra_driver_audit": ("cap.driver.query", "QUERY", None),
        "bintra_service_audit": ("cap.service.query", "QUERY", None),
        "bintra_dmp_inspect": ("cap.minidump.read", "READ", "dmp_path"),
        "bintra_etw_audit": ("cap.event_log.read", "READ", "session_name"),
        "bintra_etw_capture": ("cap.event_log.read", "READ", "session_name"),
        "bintra_vad_inspect": ("cap.process.query", "QUERY", "pid"),
        "bintra_memory_scan": ("cap.process.query", "READ", "pid"),
        "bintra_pointer_scan": ("cap.process.query", "READ", "pid"),
        "bintra_struct_dissect": ("cap.process.query", "READ", "pid"),
        "bintra_crash_rca": ("cap.minidump.read", "READ", "dmp_path"),
        "bintra_ghidra_live_bridge": ("cap.file.read", "READ", None),
        "bintra_evidence_graph": ("cap.file.read", "READ", "binary_path"),
        "bintra_wsp_audit": ("cap.file.read", "READ", "model_path"),
        "bintra_patch_weights": ("cap.workspace.write", "WRITE", "output_path"),
        "bintra_device_driver_intelligence": ("cap.device.query", "QUERY", "device_query"),
        "bintra_process_resource_audit": ("cap.process.query", "QUERY", "file_path"),
        "bintra_python_bytecode": ("cap.file.read", "READ", "file_path"),
        "bintra_cpython_memory_forensics": ("cap.process.query", "READ", "pid"),
        "bintra_pe_deep_forensics": ("cap.file.read", "READ", "file_path"),
        "bintra_binary_diff": ("cap.file.read", "READ", "baseline_path"),
        "bintra_ghidra_call_graph": ("cap.file.read", "READ", "export_path"),
        "bintra_ghidra_data_flow": ("cap.file.read", "READ", "export_path"),
        "bintra_ghidra_similar_functions": ("cap.file.read", "READ", "export_path"),
        "bintra_fuse_evidence": ("cap.file.read", "READ", "binary_path"),
        "bintra_triage_binary": ("cap.file.read", "READ", "file_path"),
        "bintra_profile_process": ("cap.process.query", "QUERY", "pid"),
        "bintra_inspect_slack_space": ("cap.file.read", "READ", "file_path"),
        "bintra_list_capabilities": ("cap.file.read", "READ", None)
    }

    @staticmethod
    def _apply_token_diet(tool_name: str, result_data: Any, args: Dict[str, Any]) -> Any:
        """Prune verbose boilerplate and bound large arrays when compact/summary_only is enabled."""
        if not isinstance(result_data, dict):
            return result_data
        compact = bool(args.get("compact")) or (os.environ.get("BINTRA_COMPACT_OUTPUT") == "1")
        summary_only = bool(args.get("summary_only"))
        max_items = args.get("max_list_items")
        if max_items is None and (compact or summary_only):
            max_items = 20

        if not (compact or summary_only or max_items is not None):
            return result_data

        data = dict(result_data)
        if tool_name == "bintra_sensory_audit" and (compact or summary_only):
            data.pop("score_semantics", None)
            senses = data.get("senses")
            if isinstance(senses, dict) and summary_only:
                condensed = {}
                for s_name, s_val in senses.items():
                    if isinstance(s_val, dict):
                        condensed[s_name] = {
                            k: v for k, v in s_val.items()
                            if k in ("status", "score", "efficiency", "entropy", "anomalies_count", "is_safe", "recommendation")
                        }
                    else:
                        condensed[s_name] = s_val
                data["senses"] = condensed

        elif tool_name == "bintra_ghidra_call_graph" and (compact or summary_only):
            if summary_only:
                data.pop("callees_map", None)
                data.pop("callers_map", None)
            elif isinstance(max_items, int) and max_items > 0:
                for map_key in ("callees_map", "callers_map"):
                    m = data.get(map_key)
                    if isinstance(m, dict) and len(m) > max_items:
                        keys = list(m.keys())[:max_items]
                        data[map_key] = {k: m[k] for k in keys}
                        data[f"_{map_key}_truncated"] = {"total": len(m), "shown": max_items}

        if isinstance(max_items, int) and max_items > 0:
            data, _ = prune_payload(data, max_list_items=max_items, drop_empty=compact)
        elif compact:
            data, _ = prune_payload(data, max_list_items=0, drop_empty=True)
        return data

    def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        args = params.get("arguments", {})
        if tool_name not in self.TOOL_SECURITY_METADATA and f"bintra_{tool_name}" in self.TOOL_SECURITY_METADATA:
            tool_name = f"bintra_{tool_name}"

        try:
            from security import ExecutionGuard, Capability, SecurityViolationError, TargetMutationError, PathIdentity

            sec_meta = self.TOOL_SECURITY_METADATA.get(tool_name)
            if not sec_meta:
                raise SecurityViolationError(f"UNREGISTERED_TOOL: Tool '{tool_name}' has no registered security capability in PolicyEngine.")

            cap_val, mode, target_param = sec_meta
            cap = Capability(cap_val)

            # Extract target path and derive workspace strictly server-side
            target_path = (
                args.get("file_path") or args.get("binary_path") or
                args.get("model_path") or args.get("source_path") or
                args.get("target_path") or args.get("dump_path") or
                args.get("input_file") or args.get("dmp_path")
            )
            workspace_dir = self._resolve_server_workspace(args if isinstance(args, dict) else {})

            # Determine mediated target name
            effective_target = args.get(target_param) if target_param else (target_path or tool_name)
            if not effective_target:
                effective_target = tool_name

            req_metadata = {}
            if tool_name == "bintra_win_catalog_cmd":
                req_metadata["is_catalog_command"] = True

            self._validate_tool_arguments(tool_name, args)
            with ExecutionGuard.scoped_session(target_binary_path=target_path, workspace_dir=workspace_dir):
                # COMPLETE MEDIATION: All MCP tool invocations MUST be authorized by Reference Monitor
                ExecutionGuard.request_access(
                    component="mcp_server",
                    operation=tool_name,
                    target=str(effective_target),
                    capability=cap,
                    access_mode=mode,
                    metadata=req_metadata
                )
                raw_result_data = self.dispatch_tool(tool_name, args)
                pretty_print = (os.environ.get("BINTRA_PRETTY_PRINT") == "1")
                baseline_pretty_str = json.dumps(raw_result_data, indent=2, ensure_ascii=False)
                baseline_tok = estimate_tokens(baseline_pretty_str)
                result_data = self._apply_token_diet(tool_name, raw_result_data, args if isinstance(args, dict) else {})
                serialized_text = (
                    json.dumps(result_data, indent=2, ensure_ascii=False)
                    if pretty_print
                    else json.dumps(result_data, separators=(",", ":"), ensure_ascii=False)
                )
                call_stats = self.token_tracker.record_tool_call(
                    tool_name=tool_name,
                    args_text=json.dumps(args, separators=(",", ":"), ensure_ascii=False),
                    output_text=serialized_text,
                    baseline_output_tokens=baseline_tok,
                )
                if os.environ.get("BINTRA_TOKEN_TELEMETRY") == "1" and isinstance(result_data, dict):
                    result_data = dict(result_data)
                    result_data["_token_telemetry"] = {
                        "call": call_stats,
                        "session": self.token_tracker.summary(),
                    }
                    serialized_text = (
                        json.dumps(result_data, indent=2, ensure_ascii=False)
                        if pretty_print
                        else json.dumps(result_data, separators=(",", ":"), ensure_ascii=False)
                    )
                is_structured_error = (
                    isinstance(raw_result_data, dict)
                    and (
                        raw_result_data.get("status") == "error"
                        or raw_result_data.get("decision") == "DENY"
                    )
                )
                ret_obj = {
                    "content": [
                        {
                            "type": "text",
                            "text": serialized_text
                        }
                    ],
                    "isError": is_structured_error
                }
                if isinstance(result_data, dict):
                    ret_obj["structuredContent"] = result_data
                return ret_obj
        except Exception as exc:
            tb = traceback.format_exc()
            err_msg = f"Missing required parameter: {exc}" if isinstance(exc, KeyError) else str(exc)
            err_payload = {
                "status": "error",
                "tool": tool_name,
                "error": err_msg,
            }
            if os.environ.get("BINTRA_DEBUG") == "1":
                err_payload["traceback"] = tb
            err_text = (
                json.dumps(err_payload, indent=2)
                if os.environ.get("BINTRA_PRETTY_PRINT") == "1"
                else json.dumps(err_payload, separators=(",", ":"))
            )
            return {
                "content": [
                    {
                        "type": "text",
                        "text": err_text
                    }
                ],
                "structuredContent": err_payload,
                "isError": True
            }

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name not in self.TOOL_SECURITY_METADATA and f"bintra_{name}" in self.TOOL_SECURITY_METADATA:
            name = f"bintra_{name}"
        if name == "bintra_inspect_binary":
            path = args["file_path"]
            res = BinaryFormatInspector.inspect(path)
            # Enrich with Windows Signature Intelligence (Dual Authenticode & Catalog)
            try:
                from windows_intelligence import WindowsSignatureIntelligence
                sig_info = WindowsSignatureIntelligence.verify_file(path, check_catalog=True)
                res["security_authenticode"] = sig_info
            except Exception:
                pass
            max_exports = args.get("max_exports")
            if "exports" in res and "functions" in res["exports"]:
                all_funcs = res["exports"]["functions"]
                limit_val = 64 if max_exports is None else int(max_exports)
                if limit_val > 0 and len(all_funcs) > limit_val:
                    res["exports"]["functions_sample"] = all_funcs[:limit_val]
                    res["exports"]["functions_truncated"] = True
                    res["exports"]["functions_omitted_count"] = len(all_funcs) - limit_val
                    res["exports"]["functions"] = all_funcs[:limit_val]
            return res

        elif name == "bintra_deobfuscate_binary":
            code_hex = args.get("code_hex")
            file_path = args.get("file_path")
            raw_off = args.get("offset")
            offset = int(str(raw_off), 0) if raw_off is not None else None
            length = int(args.get("length", 4096))
            if code_hex:
                raw_bytes = bytes.fromhex(code_hex.replace(" ", "").replace("\n", ""))
                return ContinuousDeobfuscator.deobfuscate_cfg(raw_bytes)
            elif file_path and os.path.exists(file_path):
                return ContinuousDeobfuscator.deobfuscate_file(file_path, offset=offset, length=length)
            else:
                raise ValueError("Must provide 'code_hex' or valid 'file_path'")

        elif name == "bintra_dump_bytes":
            path = args["file_path"]
            offset = int(str(args["offset"]), 0)
            length = int(args.get("length", 64))
            return SurgicalBinaryPatcher.read_bytes(path, offset, length)

        elif name == "bintra_match_functions":
            f1_hex = args["func1_hex"]
            f2_hex = args["func2_hex"]
            return SemanticFunctionMatcher.match_functions(f1_hex, f2_hex)

        elif name == "bintra_patch_binary":
            path = args["file_path"]
            out_path = args.get("output_path")
            from security import PathIdentity, ExecutionGuard, Capability, TargetMutationError
            if not out_path or PathIdentity.is_same_file(path, out_path):
                raise TargetMutationError(
                    "TARGET_WRITE_FORBIDDEN: 'output_path' is required and cannot overwrite the source target binary. Analysis tools must write patched copies to an isolated workspace destination."
                )

            # Enforce that output_path is within authorized workspace
            ExecutionGuard.request_access(
                component="mcp_server",
                operation="patch_binary",
                target=out_path,
                capability=Capability.WORKSPACE_WRITE,
                access_mode="WRITE"
            )

            offset = int(str(args["offset"]), 0)
            patch_hex = args["patch_hex"]
            force = bool(args.get("force", False))
            return SurgicalBinaryPatcher.patch_file(
                source_path=path,
                output_path=out_path,
                file_offset=offset,
                patch_hex=patch_hex,
                enforce_nociception=not force
            )

        elif name == "bintra_scan_hybrid":
            path = args["file_path"]
            return HybridBinaryDissector.scan_for_embedded_logic(path)

        elif name == "bintra_sensory_audit":
            file_path = args.get("file_path")
            code_hex = args.get("code_hex")
            cortex = SensoryCortex()
            return cortex.evaluate_all_senses(file_path=file_path, code_hex=code_hex)

        elif name == "bintra_match_pcode":
            p1 = args["func1_pcode"]
            p2 = args["func2_pcode"]
            return PcodeFunctionMatcher.match(p1, p2)

        elif name == "bintra_deobfuscate_pcode":
            pcode_ops = args["pcode_ops"]
            return PcodeDeobfuscator.detect_opaque_predicates(pcode_ops)

        elif name == "bintra_ghidra_analyze":
            from security import ExecutionGuard, Capability
            from ghidra_export_store import GhidraExportStore
            payload = args.get("payload")
            input_file = args.get("input_file")
            if input_file:
                ExecutionGuard.request_access(
                    component="ghidra_analyzer",
                    operation="read_ghidra_export",
                    target=input_file,
                    capability=Capability.FILE_READ,
                    access_mode="READ",
                    metadata={"file_path": input_file}
                )
            if not payload and not input_file:
                raise ValueError("Must provide 'payload' object or valid 'input_file'")

            with GhidraExportStore.from_path(input_file if input_file else payload) as store:
                # 1. Targeted single-function deep architectural inspection
                fn_target = args.get("function_name")
                if fn_target:
                    res = store.inspect_function(fn_target)
                    if not res:
                        return {"status": "not_found", "function_name": fn_target}
                    return res

                # 2. Advanced search across functions, opcodes, xrefs, and decompiled C
                query = args.get("query")
                opcode_filter = args.get("opcode_filter")
                xref_target = args.get("xref_target")
                sensitive_only = bool(args.get("sensitive_only", False))
                if query or opcode_filter or xref_target or sensitive_only:
                    limit = int(args.get("limit", 50))
                    offset = int(args.get("offset", 0))
                    return store.search_functions(
                        query=query,
                        opcode=opcode_filter,
                        xref_target=xref_target,
                        sensitive_only=sensitive_only,
                        limit=limit,
                        offset=offset
                    )

                # 3. Global computational and architectural profile
                if args.get("profile"):
                    return store.query_computational_profile()

                # 4. Standard batch mutation plan generation (default)
                return GhidraAnnotationPlanner.analyze_program_export(store)

        elif name == "bintra_ghidra_headless":
            from security import ExecutionGuard, Capability
            from ghidra_headless_runner import GhidraHeadlessRunner
            bin_path = args["binary_path"]
            apply_flag = bool(args.get("apply", False))
            timeout_sec = int(args.get("timeout_seconds", 300))
            delete_proj = bool(args.get("delete_project", True))

            ExecutionGuard.request_access(
                component="ghidra_headless",
                operation="run_ghidra_headless",
                target=bin_path,
                capability=Capability.GHIDRA_HEADLESS_EXEC,
                access_mode="EXECUTE",
                metadata={"shell": False, "apply": apply_flag, "timeout": timeout_sec}
            )
            if apply_flag:
                ExecutionGuard.request_access(
                    component="ghidra_headless",
                    operation="apply_project_mutations",
                    target=bin_path,
                    capability=Capability.GHIDRA_PROJECT_MUTATE,
                    access_mode="WRITE",
                    metadata={"target": "ghidra_project_database"}
                )

            run_res = GhidraHeadlessRunner.run(
                binary_path=bin_path,
                apply=apply_flag,
                timeout_sec=timeout_sec,
                delete_project=delete_proj,
                ghidra_path=args.get("ghidra_path"),
                post_script=args.get("post_script") or "BintraGhidraBridge.java",
                project_name=args.get("project_name"),
                project_dir=args.get("project_dir"),
                max_cpu=args.get("max_cpu"),
                script_args=list(args.get("script_args", [])),
                guard_component="ghidra_headless",
            )

            return {
                "exit_code": run_res["exit_code"],
                "is_timeout": run_res["is_timeout"],
                "timeout_seconds": run_res["timeout_seconds"],
                "script_error_detected": run_res["script_error_detected"],
                "is_error": run_res["is_error"],
                "project_name": run_res["project_name"],
                "project_cleaned": run_res["project_cleaned"],
                "analyzed_functions_count": run_res["analyzed_functions_count"],
                "opaque_predicates_detected": run_res["opaque_predicates_detected"],
                "cff_backbones_detected": run_res["cff_backbones_detected"],
                "stdout_tail": run_res["stdout"][-3000:],
                "stderr_tail": run_res["stderr"][-2000:],
                "epistemic_classification": "GHIDRA_HEADLESS_BATCH_EXECUTION"
            }

        elif name == "bintra_windows_env_audit":
            from windows_intelligence import WindowsOSProfiler, WindowsDeviceInspector, WindowsSecurityInspector
            b = args.get("file_path") or args.get("binary_path")
            return {
                "os": WindowsOSProfiler.profile(b),
                "devices": WindowsDeviceInspector.audit(),
                "security": WindowsSecurityInspector.audit(b)
            }

        elif name == "bintra_resolve_dependencies":
            from windows_intelligence import WindowsDependencyResolver
            b = args.get("file_path") or args.get("binary_path")
            return WindowsDependencyResolver.audit_dependencies(b)

        elif name == "bintra_inspect_crash_reports":
            from windows_intelligence import WindowsCrashAnalyzer
            b = args.get("file_path") or args.get("binary_path")
            return WindowsCrashAnalyzer.collect_crash_evidence(b)

        elif name == "bintra_correlate_failure_evidence":
            from windows_intelligence import DiagnosticEvidenceCorrelator
            b = args.get("binary_path") or args.get("file_path")
            c = args.get("crash_record")
            g = args.get("ghidra_export")
            return DiagnosticEvidenceCorrelator.correlate(b, crash_record=c, ghidra_export=g)

        elif name == "bintra_win_catalog_cmd":
            from windows_intelligence import CommandCatalog, CommandExecutor
            cmd_id = str(args.get("command_id", "")).strip()
            if cmd_id.lower() in ("list", "__list__"):
                commands = CommandCatalog.list_available_commands()
                return {
                    "status": "success",
                    "action": "list",
                    "commands_count": len(commands),
                    "commands": commands,
                }
            flags = tuple(args.get("extra_flags", [])) if args.get("extra_flags") else None
            return CommandExecutor.execute(cmd_id, extra_flags=flags)

        elif name == "bintra_registry_audit":
            from windows_intelligence import WindowsRegistryAnalyzer, WindowsRegistryEditor
            action = args.get("action", "audit")
            if action == "read":
                hive = args.get("hive", "HKLM")
                subkey = args.get("subkey") or args.get("key", "")
                view = args.get("view", "dual")
                return WindowsRegistryEditor.read_key(hive=hive, subkey=subkey, view=view)
            elif action == "search":
                q = args.get("query") or args.get("search_query", "")
                hive = args.get("hive", "HKLM")
                root_k = args.get("root_key") or args.get("subkey") or args.get("key", "")
                limit = int(args.get("limit", 50))
                max_d = int(args.get("max_depth", 3))
                view = args.get("view", "64")
                return WindowsRegistryEditor.search(query=q, hive=hive, root_key=root_k, limit=limit, max_depth=max_d, view=view)
            elif action == "parse_reg":
                from security import ExecutionGuard, Capability
                target = args.get("reg_path") or args.get("reg_content") or ""
                if args.get("reg_path") or (isinstance(target, str) and len(target) < 1024 and os.path.isfile(target)):
                    ExecutionGuard.request_access(
                        component="mcp_server",
                        operation="parse_reg_file",
                        target=str(target),
                        capability=Capability.FILE_READ,
                        access_mode="READ"
                    )
                return WindowsRegistryEditor.parse_reg_file(target)
            elif action == "export_reg":
                from security import ExecutionGuard, Capability
                hive = args.get("hive", "HKLM")
                subkey = args.get("subkey") or args.get("key", "")
                out_path = args.get("output_path") or args.get("reg_path")
                rec = bool(args.get("recursive", False))
                max_d = int(args.get("max_depth", 1))
                view = args.get("view", "64")
                if out_path:
                    ExecutionGuard.request_access(
                        component="mcp_server",
                        operation="export_reg",
                        target=str(out_path),
                        capability=Capability.WORKSPACE_WRITE,
                        access_mode="WRITE"
                    )
                return WindowsRegistryEditor.export_key(hive=hive, subkey=subkey, output_path=out_path, recursive=rec, max_depth=max_d, view=view)
            elif action == "diff_reg":
                from security import ExecutionGuard, Capability
                target = args.get("reg_path") or args.get("reg_content") or ""
                if args.get("reg_path") or (isinstance(target, str) and len(target) < 1024 and os.path.isfile(target)):
                    ExecutionGuard.request_access(
                        component="mcp_server",
                        operation="diff_reg_file",
                        target=str(target),
                        capability=Capability.FILE_READ,
                        access_mode="READ"
                    )
                view = args.get("view", "64")
                return WindowsRegistryEditor.diff_reg_file(target, view=view)

            domain = args.get("domain")
            target_b = args.get("target_binary")
            if domain:
                return WindowsRegistryAnalyzer.audit_domain(domain)
            return WindowsRegistryAnalyzer.audit_all(target_binary_path=target_b)

        elif name == "bintra_hardware_audit":
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

        elif name == "bintra_port_audit":
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

        elif name == "bintra_hardware_topology":
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

        elif name == "bintra_network_audit":
            from windows_intelligence import NetworkHardwareInspector
            inc_virt = args.get("include_virtual", True)
            return NetworkHardwareInspector.audit_network_adapters(include_virtual=inc_virt)

        elif name == "bintra_network_hardware_dissect":
            from windows_intelligence import NetworkHardwareInspector
            target = args.get("target_query", "wifi")
            return NetworkHardwareInspector.deep_dissect_network_device(target_query=target)

        elif name == "bintra_network_connections":
            from windows_intelligence import NetworkHardwareInspector
            pid = args.get("pid")
            return NetworkHardwareInspector.audit_tcp_connections(pid=pid)

        elif name == "bintra_driver_audit":
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

        elif name == "bintra_service_audit":
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

        elif name == "bintra_dmp_inspect":
            from windows_intelligence import MiniDumpParser
            dmp_p = args.get("dmp_path")
            app_flt = args.get("app_name_filter")
            if dmp_p:
                return MiniDumpParser.parse_minidump(dmp_p)
            return MiniDumpParser.audit_dumps(app_name_filter=app_flt)

        elif name == "bintra_etw_audit":
            from windows_intelligence import EtwController
            act = args.get("action", "audit")
            sname = args.get("session_name")
            if sname or act == "session":
                return EtwController.query_trace_session(sname or "Eventlog-Application")
            if act == "providers":
                return EtwController.enumerate_registered_providers(query=args.get("query"), limit=int(args.get("limit", 50)))
            if act == "active_kernel":
                return EtwController.audit_active_kernel_providers(limit=int(args.get("limit", 50)))
            if act == "provider_info":
                guid = args.get("guid") or "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
                return EtwController.query_provider_instances(guid)
            return EtwController.audit_telemetry_system()

        elif name == "bintra_etw_capture":
            s_name = args.get("session_name", "Bintra_Diagnostic_Trace")
            t_pid = args.get("pid")
            dur = float(args.get("duration_seconds", 1.0))
            import time
            from windows_intelligence import EtwLiveCaptureSession, EtwTimelineCorrelator
            session = EtwLiveCaptureSession(session_name=s_name, target_pid=t_pid)
            s_info = session.start_session()
            time.sleep(min(dur, 5.0))
            stop_info = session.stop_session()
            timeline = session.get_timeline(pid=t_pid)
            report = EtwTimelineCorrelator.correlate_crash_timeline(timeline)
            report["session_info"] = s_info
            report["stop_info"] = stop_info
            return report

        elif name == "bintra_ghidra_live_bridge":
            from ghidra_live_bridge import (
                GhidraLiveBridgeServer, GhidraLiveBridgeClient,
                get_or_create_bridge, get_active_bridge, stop_active_bridge
            )
            act = args.get("action", "status")
            port = int(args.get("port", 41718))
            token = args.get("auth_token")

            if act == "start":
                server = get_or_create_bridge(
                    port=port,
                    auth_token=token,
                    publish_temp_marker=bool(args.get("publish_temp_marker", True)),
                )
                st = server.dispatch_rpc_method("get_status", {})
                st["marker_file"] = getattr(server, "_marker_path", None)
                return st
            elif act == "stop":
                return stop_active_bridge()
            elif act == "status":
                server = get_active_bridge()
                if server and server.is_running:
                    return server.dispatch_rpc_method("get_status", {})
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
                try:
                    return client.call_rpc("get_status")
                except Exception as e:
                    return {"is_running": False, "error": str(e)}
            elif act == "inject_crash_rca":
                dmp = args.get("crash_dmp_path")
                if not dmp:
                    raise ValueError("'crash_dmp_path' is required for action 'inject_crash_rca'")
                from windows_intelligence import CrashRootCauseAnalyzer
                rca = CrashRootCauseAnalyzer.analyze_crash(dmp)
                server = get_active_bridge()
                if server and server.is_running:
                    return server.inject_crash_rca(rca)
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
                return client.call_rpc("bintra.inject_crash_rca", {"rca_report": rca})
            elif act == "inject_vad":
                pid = int(args.get("pid", 0))
                if pid <= 0:
                    raise ValueError("Valid 'pid' (> 0) is required for action 'inject_vad'")
                from windows_intelligence import VirtualMemoryInspector
                snap = VirtualMemoryInspector.inspect_process(pid)
                server = get_active_bridge()
                if server and server.is_running:
                    return server.inject_vad_snapshot(snap.to_dict())
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
                return client.call_rpc("bintra.inject_vad_snapshot", {"vad_snapshot": snap.to_dict()})
            elif act == "inject_etw":
                tl = args.get("timeline_report")
                if not tl:
                    import time
                    from windows_intelligence import EtwLiveCaptureSession, EtwTimelineCorrelator
                    sess = EtwLiveCaptureSession(session_name="QuickProbe")
                    sess.start_session()
                    time.sleep(0.5)
                    sess.stop_session()
                    tl = EtwTimelineCorrelator.correlate_crash_timeline(sess.get_timeline())
                server = get_active_bridge()
                if server and server.is_running:
                    return server.inject_etw_timeline(tl)
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
                return client.call_rpc("bintra.inject_etw_timeline", {"timeline_report": tl})
            elif act == "inject_struct":
                s_rep = args.get("struct_report")
                if not s_rep:
                    pid = int(args.get("pid", 0))
                    addr_str = args.get("address")
                    if pid <= 0 or not addr_str:
                        raise ValueError("'struct_report' or both 'pid' and 'address' are required for 'inject_struct'")
                    base_addr = int(addr_str, 16) if addr_str.lower().startswith("0x") else int(addr_str)
                    from windows_intelligence import StructureDissector
                    s_rep = StructureDissector.dissect(pid, base_addr)
                server = get_active_bridge()
                if server and server.is_running:
                    return server.inject_structure_dissection(s_rep)
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
                return client.call_rpc("bintra.inject_structure_dissection", {"struct_report": s_rep})
            elif act == "inject_pointers":
                p_rep = args.get("pointer_report")
                if not p_rep:
                    pid = int(args.get("pid", 0))
                    addr_str = args.get("address")
                    if pid <= 0 or not addr_str:
                        raise ValueError("'pointer_report' or both 'pid' and 'address' are required for 'inject_pointers'")
                    target_addr = int(addr_str, 16) if addr_str.lower().startswith("0x") else int(addr_str)
                    from windows_intelligence import PointerScanner
                    p_rep = PointerScanner.find_pointer_paths(pid, target_addr)
                server = get_active_bridge()
                if server and server.is_running:
                    return server.inject_pointer_chains(p_rep)
                client = GhidraLiveBridgeClient(bridge_url=f"http://127.0.0.1:{port}", auth_token=token)
                return client.call_rpc("bintra.inject_pointer_chains", {"pointer_report": p_rep})
            else:
                raise ValueError(f"Unknown ghidra_live_bridge action: '{act}'")

        elif name == "bintra_vad_inspect":
            pid = int(args.get("pid", 0))
            if pid <= 0:
                raise ValueError("Valid 'pid' (> 0) is required.")
            from windows_intelligence import VirtualMemoryInspector
            snapshot = VirtualMemoryInspector.inspect_process(pid)
            addr_str = args.get("address")
            if addr_str:
                addr = int(addr_str, 0)
                return snapshot.classify_address(addr)
            return snapshot.to_dict(include_regions=bool(args.get("include_regions", False)))

        elif name == "bintra_memory_scan":
            pid = int(args.get("pid", 0))
            if pid <= 0:
                raise ValueError("Valid 'pid' (> 0) is required.")
            from windows_intelligence import ProcessMemoryScanner
            val_type = str(args.get("value_type", "int32")).lower()
            valid_types = {
                "int8", "uint8", "int16", "uint16",
                "int32", "uint32", "int64", "uint64",
                "float", "double", "bytes", "string",
            }
            if val_type not in valid_types:
                raise ValueError(f"Unsupported value_type '{val_type}'.")
            mode = str(args.get("scan_mode", "exact")).lower()
            mode_map = {
                "exact": "EXACT_VALUE",
                "between": "VALUE_BETWEEN",
                "unknown": "UNKNOWN_INITIAL_VALUE",
                "increased": "INCREASED_VALUE",
                "decreased": "DECREASED_VALUE",
                "changed": "CHANGED_VALUE",
                "unchanged": "UNCHANGED_VALUE",
            }
            if mode not in mode_map:
                raise ValueError(f"Unsupported scan_mode '{mode}'. Allowed: {sorted(mode_map.keys())}")
            scan_mode = mode_map[mode]
            val = args.get("target_value")
            high_val = args.get("high_value")
            int_types = ("int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64")
            if val is not None:
                if val_type in int_types and isinstance(val, str):
                    val = int(val, 0)
                elif val_type in ("float", "double") and isinstance(val, str):
                    val = float(val)
                elif val_type == "bytes" and isinstance(val, str):
                    val = bytes.fromhex(val.replace(" ", "").replace("0x", "").replace("0X", ""))
            if high_val is not None:
                if val_type in int_types and isinstance(high_val, str):
                    high_val = int(high_val, 0)
                elif val_type in ("float", "double") and isinstance(high_val, str):
                    high_val = float(high_val)

            sid = args.get("session_id")
            cand_addrs = args.get("candidate_addresses")
            if sid:
                return ProcessMemoryScanner.next_scan(
                    session_id=sid,
                    scan_type=scan_mode,
                    value=val,
                    min_val=val,
                    max_val=high_val,
                )
            elif cand_addrs is not None:
                return ProcessMemoryScanner.next_scan(
                    pid=pid,
                    data_type=val_type,
                    candidate_addresses=cand_addrs,
                    scan_type=scan_mode,
                    value=val,
                    min_val=val,
                    max_val=high_val,
                )
            else:
                alignment = args.get("alignment")
                return ProcessMemoryScanner.first_scan(
                    pid=pid,
                    data_type=val_type,
                    scan_type=scan_mode,
                    value=val,
                    min_val=val,
                    max_val=high_val,
                    writable_only=bool(args.get("writable_only", True)),
                    max_candidates=int(args.get("max_results", 50000)),
                    alignment=int(alignment) if alignment is not None else None,
                )

        elif name == "bintra_pointer_scan":
            pid = int(args.get("pid", 0))
            if pid <= 0:
                raise ValueError("Valid 'pid' (> 0) is required.")
            target_str = args.get("target_address")
            if not target_str:
                raise ValueError("'target_address' is required.")
            target_addr = int(target_str, 0) if isinstance(target_str, str) else int(target_str)
            from windows_intelligence import PointerScanner
            depth = int(args.get("max_depth", 2))
            offset = int(args.get("max_offset", 4096))
            max_r = int(args.get("max_results", 20))
            align = int(args.get("alignment", 4))
            return PointerScanner.find_pointer_paths(
                pid=pid,
                target_address=target_addr,
                max_depth=depth,
                max_offset=offset,
                max_results=max_r,
                alignment=align,
            )

        elif name == "bintra_struct_dissect":
            pid = int(args.get("pid", 0))
            if pid <= 0:
                raise ValueError("Valid 'pid' (> 0) is required.")
            addr_str = args.get("address")
            if not addr_str:
                raise ValueError("'address' is required.")
            addr = int(addr_str, 0) if isinstance(addr_str, str) else int(addr_str)
            size = min(4096, max(8, int(args.get("size", 64))))
            s_name = args.get("struct_name")
            from windows_intelligence import StructureDissector
            return StructureDissector.dissect(pid=pid, base_address=addr, size=size, struct_name=s_name)

        elif name == "bintra_crash_rca":
            dmp_p = args.get("dmp_path")
            if not dmp_p:
                raise ValueError("'dmp_path' is required.")
            b_path = args.get("binary_path")
            from windows_intelligence import CrashRootCauseAnalyzer
            return CrashRootCauseAnalyzer.analyze_crash(dump_target=dmp_p, binary_path=b_path)

        elif name == "bintra_evidence_graph":
            from windows_intelligence import CausalitySynthesizer, MiniDumpParser
            b = args.get("binary_path") or args.get("file_path")
            dmp_p = args.get("crash_dmp_path")
            g = args.get("ghidra_export")
            c_rec = None
            if dmp_p:
                parsed_dmp = MiniDumpParser.parse_minidump(dmp_p)
                if parsed_dmp.get("status") == "success":
                    exc = parsed_dmp.get("exception_info") or {}
                    c_rec = {
                        "source": "MINIDUMP",
                        "file_path": dmp_p,
                        "exception_code": exc.get("exception_code"),
                        "exception_name": exc.get("exception_name"),
                        "fault_module": exc.get("fault_module"),
                        "fault_offset": exc.get("fault_offset", "0x0"),
                        "access_violation_details": exc.get("access_violation_details")
                    }
            graph = CausalitySynthesizer.build_evidence_graph(b, crash_record=c_rec, ghidra_export=g)
            return {
                "status": "success",
                "binary_path": b,
                "total_nodes": len(graph.nodes),
                "total_edges": len(graph.edges),
                "graph": graph.to_dict(),
                "mermaid_diagram": graph.to_mermaid()
            }

        elif name == "bintra_wsp_audit":
            path = args["model_path"]
            hdr, _, hdr_sha = SafetensorsHandler.read_header(path)
            t_names = [k for k in hdr.keys() if k != "__metadata__"]
            if not t_names:
                raise ValueError("No tensor weights found in safetensors model file.")
            req_t = args.get("tensor")
            primary_t = req_t if (req_t and req_t in t_names) else t_names[0]
            arr, _ = SafetensorsHandler.read_tensor(path, primary_t)
            eff_rank = CrossLayerCircuitAnalyzer.compute_effective_rank(arr)
            amenability = AmenabilityDiagnostic.evaluate_surgical_amenability(arr)
            sec_audit = WeightSecurityAuditor.audit_weights_without_evaluation(arr)
            induction_report = None
            if len(t_names) >= 2:
                arr2, _ = SafetensorsHandler.read_tensor(path, t_names[1])
                induction_report = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(arr, arr2, num_heads=4)
            return {
                "status": "success",
                "model_path": path,
                "header_sha256": hdr_sha,
                "primary_tensor": primary_t,
                "tensor_count": len(t_names),
                "effective_rank_analysis": eff_rank,
                "surgical_amenability": amenability,
                "zero_eval_security_audit": sec_audit,
                "cross_layer_induction": induction_report,
            }

        elif name == "bintra_patch_weights":
            src = args["source_path"]
            out = args["output_path"]
            tname = args["tensor_name"]
            num_cols = int(args.get("num_columns", 64))
            tensor_arr, _ = SafetensorsHandler.read_tensor(src, tname)
            patched_arr, metrics = WeightPatcher.apply_patch(
                tensor_arr,
                patch_operation="column_direction_subtract",
                parameters={"num_columns": num_cols},
            )
            res = SafetensorsHandler.write_patched_safetensors(
                src, out, {tname: patched_arr}
            )
            res["status"] = res.get("status", "success")
            res["tensor_name"] = tname
            res["operation"] = "column_direction_subtract"
            res["metrics"] = metrics
            return res

        elif name == "bintra_device_driver_intelligence":
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

        elif name == "bintra_process_resource_audit":
            from windows_intelligence.process_intelligence import (
                FileUsageInspector,
                ModuleInventory,
                ProcessInventory,
                ServiceProcessMapper,
                TaskManagerInspector
            )
            action = args.get("action", "find_file_locks")
            f_path = args.get("file_path")
            pid = args.get("pid")
            mod_q = args.get("module_query")
            query = args.get("query")
            sort_by = args.get("sort_by", "memory")
            limit = int(args.get("limit", 50))

            if action == "find_file_locks":
                if not f_path:
                    return {"status": "error", "error": "file_path is required for action 'find_file_locks'"}
                return FileUsageInspector.inspect_file_locks(f_path)
            elif action == "find_module_holders":
                if not mod_q:
                    return {"status": "error", "error": "module_query is required for action 'find_module_holders'"}
                return ModuleInventory.find_processes_hosting_module(mod_q)
            elif action == "process_tree":
                return ProcessInventory.get_process_tree()
            elif action == "service_process_map":
                return ServiceProcessMapper.get_service_process_mapping()
            elif action == "list_processes":
                return TaskManagerInspector.list_processes(limit=limit, sort_by=sort_by, query=query)
            elif action == "search_processes":
                if not query:
                    return {"status": "error", "error": "query parameter is required for action 'search_processes'"}
                return TaskManagerInspector.search_processes(query=query, max_results=limit)
            elif action == "system_performance":
                return TaskManagerInspector.get_system_performance()
            elif action == "audit_process":
                target_pid = pid or os.getpid()
                return TaskManagerInspector.get_process_details(target_pid)
            else:
                return {"status": "error", "error": f"Unknown action: '{action}'"}

        elif name == "bintra_python_bytecode":
            from python_intelligence import PythonBytecodeAnalyzer, PythonPackageArchitect
            target_path = args["file_path"]
            if os.path.isdir(target_path) or bool(args.get("package_mode")):
                return PythonPackageArchitect.analyze_package(
                    target_path,
                    max_files=int(args.get("max_files", 500)),
                    complexity_threshold=int(args.get("complexity_threshold", 15))
                )
            if args.get("compare_with"):
                return PythonBytecodeAnalyzer.compare_bytecode(target_path, args["compare_with"])
            return PythonBytecodeAnalyzer.analyze_file(target_path, limit=int(args.get("limit", 50)))

        elif name == "bintra_cpython_memory_forensics":
            from windows_intelligence.runtime_telemetry.cpython_memory_forensics import CPythonMemoryForensics
            addr = int(str(args["address"]), 16) if str(args["address"]).startswith("0x") else int(args["address"])
            return CPythonMemoryForensics.inspect_live_process(
                pid=int(args["pid"]),
                address=addr,
                object_type=args.get("object_type", "pyobject"),
            )

        elif name == "bintra_pe_deep_forensics":
            from pe_deep_forensics import PeDeepForensicsInspector
            return PeDeepForensicsInspector().inspect(
                file_path=args["file_path"],
                pdb_path=args.get("pdb_path"),
                limit=int(args.get("limit", 25)),
            )

        elif name == "bintra_binary_diff":
            from pe_deep_forensics import SemanticBinaryDiffer
            from security import SafeFileAccess, TargetScope, ExecutionGuard, Capability
            mode_val = args.get("mode", "pe")
            b_path = args["baseline_path"]
            t_path = args["target_path"]
            if mode_val == "ghidra_export":
                from ghidra_export_store import GhidraExportStore
                ExecutionGuard.request_access(component="binary_diff", operation="diff_ghidra_baseline", target=b_path, capability=Capability.FILE_READ, access_mode="READ")
                ExecutionGuard.request_access(component="binary_diff", operation="diff_ghidra_target", target=t_path, capability=Capability.FILE_READ, access_mode="READ")
                with GhidraExportStore.from_path(b_path) as b_store, GhidraExportStore.from_path(t_path) as t_store:
                    b_funcs = list(b_store.iter_functions()) if b_store.is_sqlite else b_store.to_dict().get("functions", [])
                    t_funcs = list(t_store.iter_functions()) if t_store.is_sqlite else t_store.to_dict().get("functions", [])
                    return SemanticBinaryDiffer().diff_function_exports(b_funcs, t_funcs)
            return SemanticBinaryDiffer().diff_pe_binaries(b_path, t_path)

        elif name == "bintra_ghidra_call_graph":
            from security import ExecutionGuard, Capability
            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            from ghidra_export_store import GhidraExportStore
            ep = args["export_path"]
            ExecutionGuard.request_access(
                component="ghidra_analyzer",
                operation="read_ghidra_export_call_graph",
                target=ep,
                capability=Capability.FILE_READ,
                access_mode="READ",
                metadata={"file_path": ep}
            )
            with GhidraExportStore.from_path(ep) as store:
                return GhidraDeepAnalyzer().build_call_graph_and_xrefs(
                    store,
                    target_function=args.get("target_function"),
                    max_depth=int(args.get("max_depth", 4)),
                )

        elif name == "bintra_ghidra_data_flow":
            from security import ExecutionGuard, Capability
            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            from ghidra_export_store import GhidraExportStore
            ep = args["export_path"]
            fn_target = args["function_name"]
            ExecutionGuard.request_access(
                component="ghidra_analyzer",
                operation="read_ghidra_export_data_flow",
                target=ep,
                capability=Capability.FILE_READ,
                access_mode="READ",
                metadata={"file_path": ep, "function_name": fn_target}
            )
            with GhidraExportStore.from_path(ep) as store:
                matched_fn = store.get_function(fn_target)
                if not matched_fn:
                    return {"status": "not_found", "function_name": fn_target}
                return GhidraDeepAnalyzer().slice_data_flow(matched_fn, target_var=args.get("target_var"))

        elif name == "bintra_ghidra_similar_functions":
            from security import ExecutionGuard, Capability
            from ghidra_export_store import GhidraExportStore
            ep = args["export_path"]
            ExecutionGuard.request_access(
                component="ghidra_analyzer",
                operation="search_similar_functions",
                target=ep,
                capability=Capability.FILE_READ,
                access_mode="READ",
                metadata={"file_path": ep}
            )
            ref_fn = args.get("reference_function")
            ref_pcode = args.get("reference_pcode")
            if not ref_fn and not ref_pcode:
                raise ValueError(
                    "Must provide either 'reference_function' (name/entry in the export) "
                    "or 'reference_pcode' (external P-code operation stream)."
                )
            with GhidraExportStore.from_path(ep) as store:
                return store.search_similar_functions(
                    reference_function=ref_fn,
                    reference_pcode=ref_pcode,
                    threshold=float(args.get("threshold", 0.75)),
                    limit=int(args.get("limit", 20)),
                    min_pcode_ops=int(args.get("min_pcode_ops", 1)),
                )

        elif name == "bintra_fuse_evidence":
            from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
            pe_res = None
            sig_res = None
            rca_res = None
            cg_res = None
            df_res = None
            ghidra_provenance = {"status": "NOT_PROVIDED", "verified": False}
            if args.get("binary_path"):
                from pe_deep_forensics import PeDeepForensicsInspector
                from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence
                pe_res = PeDeepForensicsInspector().inspect(args["binary_path"], limit=200)
                try:
                    sig_res = WindowsSignatureIntelligence.verify_file(args["binary_path"], check_catalog=True)
                except Exception:
                    sig_res = None
            if args.get("dmp_path"):
                from windows_intelligence import CrashRootCauseAnalyzer
                rca_res = CrashRootCauseAnalyzer.analyze_crash(dump_target=args["dmp_path"], binary_path=args.get("binary_path"))
            if args.get("ghidra_export_path"):
                from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
                from ghidra_export_store import GhidraExportStore
                from analysis_orchestrator import BinaryTriageOrchestrator
                gp = args["ghidra_export_path"]
                with GhidraExportStore.from_path(gp) as store:
                    # Provenance quarantine parity with the triage orchestrator:
                    # an export whose hash/name does not match the target binary is
                    # NEVER fused into the evidence graph.
                    if args.get("binary_path"):
                        import hashlib
                        h = hashlib.sha256()
                        with open(args["binary_path"], "rb") as bf:
                            while chunk := bf.read(65536):
                                h.update(chunk)
                        ghidra_provenance, is_crypto, is_heuristic = (
                            BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                                store,
                                target_sha256=h.hexdigest().lower(),
                                target_filename=os.path.basename(args["binary_path"]),
                            )
                        )
                        if not (is_crypto or is_heuristic):
                            return {
                                "status": "provenance_mismatch",
                                "epistemic_classification": "MULTI_SIGNAL_EVIDENCE_FUSION",
                                "ghidra_provenance": ghidra_provenance,
                                "warning": ghidra_provenance.get("warning", "Ghidra export provenance verification failed."),
                            }
                    else:
                        ghidra_provenance = {
                            "status": "UNVERIFIED_NO_TARGET_FOR_PROVENANCE",
                            "verified": False,
                            "warning": "No binary_path provided; Ghidra export provenance could not be verified.",
                        }
                    analyzer = GhidraDeepAnalyzer()
                    cg_res = analyzer.build_call_graph_and_xrefs(store, target_function=args.get("function_name"))
                    if args.get("function_name"):
                        fn_match = store.get_function(args["function_name"])
                        if fn_match:
                            df_res = analyzer.slice_data_flow(fn_match)
            return fuse_static_dynamic_ghidra(
                pe_forensics=pe_res,
                crash_rca=rca_res,
                ghidra_call_graph=cg_res,
                ghidra_data_flow=df_res,
                signature_intel=sig_res,
                ghidra_provenance=ghidra_provenance,
            )

        elif name == "bintra_triage_binary":
            from analysis_orchestrator import BinaryTriageOrchestrator
            return BinaryTriageOrchestrator.triage_binary(
                file_path=args["file_path"],
                dmp_path=args.get("dmp_path"),
                ghidra_export_path=args.get("ghidra_export_path"),
                function_name=args.get("function_name"),
                include_deobfuscation=bool(args.get("include_deobfuscation", True)),
                include_sensory=bool(args.get("include_sensory", True)),
                include_hybrid_scan=bool(args.get("include_hybrid_scan", True)),
                max_exports=int(args.get("max_exports", 32)),
                forensics_limit=int(args.get("forensics_limit", 200)),
            )

        elif name == "bintra_profile_process":
            from windows_intelligence.process_intelligence import ProcessLongitudinalProfiler
            return ProcessLongitudinalProfiler.profile_pid_longitudinal(
                pid=int(args["pid"]),
                samples_count=int(args.get("samples_count", 10)),
                interval_seconds=float(args.get("interval_seconds", 0.2))
            )

        elif name == "bintra_inspect_slack_space":
            from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector
            return BinarySlackInspector.inspect_file(args["file_path"])

        elif name == "bintra_list_capabilities":
            import platform as _plat
            p_filter = args.get("platform_filter", "all")
            win_tools = {
                "bintra_windows_env_audit", "bintra_resolve_dependencies", "bintra_inspect_crash_reports",
                "bintra_win_catalog_cmd", "bintra_registry_audit", "bintra_hardware_audit",
                "bintra_port_audit", "bintra_hardware_topology", "bintra_network_audit", "bintra_network_hardware_dissect", "bintra_network_connections",
                "bintra_driver_audit", "bintra_service_audit", "bintra_etw_audit",
                "bintra_vad_inspect", "bintra_memory_scan", "bintra_pointer_scan",
                "bintra_struct_dissect", "bintra_etw_capture", "bintra_device_driver_intelligence",
                "bintra_process_resource_audit"
            }
            ghidra_tools = {
                "bintra_ghidra_headless", "bintra_ghidra_live_bridge", "bintra_match_pcode",
                "bintra_deobfuscate_pcode", "bintra_ghidra_analyze", "bintra_ghidra_call_graph",
                "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions"
            }
            entries = []
            for t in TOOLS_REGISTRY:
                t_name = t["name"]
                sec = self.TOOL_SECURITY_METADATA.get(t_name, ("unknown", "READ", None))
                env = "windows_native" if t_name in win_tools else ("ghidra_required" if t_name in ghidra_tools else "cross_platform")
                if p_filter != "all" and env != p_filter:
                    continue
                compact_caps = bool(args.get("compact")) or (os.environ.get("BINTRA_COMPACT_OUTPUT") == "1")
                entry = {
                    "name": t_name,
                    "environment": env,
                    "capability": sec[0],
                    "access_mode": sec[1],
                }
                if not compact_caps:
                    entry["description"] = t.get("description", "")
                entries.append(entry)
            return {
                "status": "ok",
                "host_os": _plat.system(),
                "total_tools": len(entries),
                "tools": entries,
                "recommended_workflows": {
                    "static_pe_deep_audit": ["bintra_inspect_binary", "bintra_pe_deep_forensics", "bintra_deobfuscate_binary", "bintra_scan_hybrid", "bintra_sensory_audit"],
                    "ghidra_deep_re": ["bintra_ghidra_analyze", "bintra_ghidra_call_graph", "bintra_ghidra_data_flow", "bintra_ghidra_similar_functions"],
                    "crash_root_cause_fusion": ["bintra_dmp_inspect", "bintra_crash_rca", "bintra_pe_deep_forensics", "bintra_fuse_evidence"],
                    "version_diff": ["bintra_binary_diff"]
                }
            }

        else:
            raise ValueError(f"Unknown tool name: '{name}'")

    def _handle_single_request(self, msg: Any) -> Optional[Dict[str, Any]]:
        """Processes a single JSON-RPC 2.0 request or notification according to specification."""
        if not isinstance(msg, dict):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: message must be a JSON object"
                }
            }

        is_notification = ("id" not in msg)
        msg_id = msg.get("id")
        method = msg.get("method")
        params = msg.get("params", {})

        if not isinstance(params, (dict, list)):
            params = {}

        # Stateless MCP 2026-07-28: per-request protocolVersion check via _meta
        meta = params.get("_meta") if isinstance(params, dict) else None
        if not meta and isinstance(msg, dict):
            meta = msg.get("_meta")
        if meta and isinstance(meta, dict):
            meta_ver = meta.get("io.modelcontextprotocol/protocolVersion") or meta.get("protocolVersion")
            client_caps = meta.get("io.modelcontextprotocol/clientCapabilities") or meta.get("clientCapabilities")
            if client_caps and isinstance(client_caps, dict):
                self.current_client_capabilities = client_caps
            if meta_ver is not None and meta_ver not in SUPPORTED_PROTOCOL_VERSIONS:
                if not is_notification:
                    return {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32022,
                            "message": f"Unsupported protocol version: '{meta_ver}'. Supported versions: {list(SUPPORTED_PROTOCOL_VERSIONS)}",
                            "data": {
                                "supported": list(SUPPORTED_PROTOCOL_VERSIONS),
                                "requested": meta_ver,
                                "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                                "latestProtocolVersion": LATEST_PROTOCOL_VERSION,
                            }
                        }
                    }
                return None

        if method not in self.handlers:
            if not is_notification:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: '{method}'"
                    }
                }
            return None

        try:
            handler = self.handlers[method]
            result = handler(params)
            if not is_notification:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": result
                }
        except ValueError as ve:
            if not is_notification:
                is_ver_err = "Unsupported protocol version" in str(ve)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32022 if is_ver_err else -32602,
                        "message": str(ve),
                        "data": {
                            "supported": list(SUPPORTED_PROTOCOL_VERSIONS),
                            "requested": params.get("io.modelcontextprotocol/protocolVersion") or params.get("protocolVersion") if isinstance(params, dict) else None,
                            "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                            "latestProtocolVersion": LATEST_PROTOCOL_VERSION,
                        }
                    }
                }
            return None
        except Exception as ex:
            if not is_notification:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {ex}"
                    }
                }
        return None

    def run_stdio(self):
        """Standard JSON-RPC 2.0 loop reading from stdin and writing to stdout."""
        # Ensure utf-8 stdio. stdin MUST be reconfigured too: on Windows a piped
        # stdin defaults to the ANSI code page (e.g. cp1252), which silently
        # mangles non-ASCII file paths sent by MCP clients (JSON-RPC is UTF-8).
        # stdout uses newline="\n" so frames are not rewritten to CRLF.
        for stream_name, extra in (("stdin", {}), ("stdout", {"newline": "\n"}), ("stderr", {})):
            s = getattr(sys, stream_name, None)
            if s and hasattr(s, "reconfigure"):
                try:
                    s.reconfigure(encoding="utf-8", errors="replace", **extra)
                except Exception:
                    pass

        while True:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue

                msg = json.loads(line)
                if isinstance(msg, list):
                    if len(msg) == 0:
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": None,
                            "error": {
                                "code": -32600,
                                "message": "Invalid Request: empty batch"
                            }
                        }
                        sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                        sys.stdout.flush()
                    else:
                        batch_resps = []
                        for item in msg:
                            r = self._handle_single_request(item)
                            if r is not None:
                                batch_resps.append(r)
                        if batch_resps:
                            sys.stdout.write(json.dumps(batch_resps, ensure_ascii=False) + "\n")
                            sys.stdout.flush()
                else:
                    r = self._handle_single_request(msg)
                    if r is not None:
                        sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
                        sys.stdout.flush()

            except json.JSONDecodeError as jde:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {jde}"
                    }
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
            except Exception as ex:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32603,
                        "message": f"Internal error: {ex}"
                    }
                }
                sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()


def main():
    server = BintraMcpServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
