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
        "description": "Batch-processes a full Ghidra exported High P-Code program payload. Scans all functions, detects opaque predicates, calculates spectral effective rank, and synthesizes a mutation plan (renames, plate comments).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "input_file": {
                    "type": "string",
                    "description": "Recommended token-efficient path to exported JSON file on disk (pass-by-reference avoids prompt token bloat)"
                },
                "payload": {
                    "type": "object",
                    "description": "Optional inline exported program payload containing 'functions' array of High P-Code ops (pass-by-reference via 'input_file' is strongly preferred for token efficiency)"
                }
            }
        }
    },
    {
        "name": "bintra_ghidra_headless",
        "description": "Automates running Ghidra analyzeHeadless with BintraGhidraBridge.java on Windows. Decompiles functions, extracts High P-Code, analyzes semantics, and applies database mutations in one command.",
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
                "apply": {
                    "type": "boolean",
                    "description": "Automatically commit function renames and plate comments to Ghidra database"
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
        "description": "Performs dual-view (64-bit and 32-bit WOW64) inspection across 11 Windows Registry functional domains, detecting redirection divergence and security/loader policy anomalies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Optional functional domain (e.g. 'OPERATING_SYSTEM', 'SECURITY_POLICIES', 'DLL_SEARCH_CONFIGURATION', 'KNOWN_DLLS')"
                },
                "target_binary": {
                    "type": "string",
                    "description": "Optional target executable path to check for compatibility shims"
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
        "description": "Audits PnP devices, CM_PROB_* codes, PCI/USB/HDAUDIO/HID/ACPI identities, and Driver Rank bindings; supports cross-platform offline .inf matching via offline_inf_paths.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["audit", "match", "find_packages"],
                    "description": "Action: 'audit' (default device driver audit), 'match' (match hardware IDs), 'find_packages' (search driver packages)",
                    "default": "audit"
                },
                "device_query": {
                    "type": "string",
                    "description": "Optional search term matching device name, instance ID, or hardware ID"
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
                }
            }
        }
    },
    {
        "name": "bintra_process_resource_audit",
        "description": "Inspects running processes, in-memory loaded modules, file lock handles via Windows Restart Manager, and service-to-process hosting mappings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["find_file_locks", "find_module_holders", "process_tree", "service_process_map", "audit_process"],
                    "description": "Action: 'find_file_locks' (discover processes locking a file), 'find_module_holders' (find processes with DLL loaded), 'process_tree' (parent-child tree), 'service_process_map' (services hosted in processes), 'audit_process' (inspect PID)",
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
                }
            }
        }
    }
    ,
    {
        "name": "bintra_python_bytecode",
        "description": "Strictly read-only CPython bytecode analyzer: disassembles .py/.pyc via dis & marshal into Control-Flow Basic Blocks and computes Weisfeiler-Lehman CFG hashes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to .py or .pyc file"},
                "compare_with": {"type": "string", "description": "Optional second .py/.pyc path for WL-CFG bytecode diffing"},
                "limit": {"type": "integer", "description": "Maximum code objects to analyze (default 50)"}
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
        "name": "bintra_list_capabilities",
        "description": "Self-describing capability manifest for AI agents: returns all registered Bintra MCP tools, environment requirements (cross_platform vs windows_native vs ghidra_required), security modes, and recommended decision workflows.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "platform_filter": {"type": "string", "enum": ["all", "cross_platform", "windows_native", "ghidra_required"], "description": "Filter tools by execution environment"}
            }
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
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
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
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": {
                    "listChanged": False
                }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            }
        }

    def handle_initialized_notification(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return None

    def handle_ping(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    MCP_TOOL_PROFILES = {
        "core": {
            "bintra_inspect_binary", "bintra_pe_deep_forensics", "bintra_sensory_audit",
            "bintra_deobfuscate_binary", "bintra_binary_diff", "bintra_list_capabilities",
        },
        "static": {
            "bintra_inspect_binary", "bintra_pe_deep_forensics", "bintra_deobfuscate_binary",
            "bintra_dump_bytes", "bintra_match_functions", "bintra_scan_hybrid",
            "bintra_sensory_audit", "bintra_binary_diff", "bintra_patch_binary",
            "bintra_list_capabilities",
        },
        "ghidra": {
            "bintra_ghidra_analyze", "bintra_ghidra_headless", "bintra_ghidra_live_bridge",
            "bintra_ghidra_call_graph", "bintra_ghidra_data_flow", "bintra_match_pcode",
            "bintra_deobfuscate_pcode", "bintra_fuse_evidence", "bintra_list_capabilities",
        },
        "neural": {
            "bintra_sensory_audit", "bintra_scan_hybrid", "bintra_wsp_audit",
            "bintra_patch_weights", "bintra_list_capabilities",
        },
    }

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
        if compact:
            tools = [compact_tool_schema(t) for t in tools]

        base_tok = estimate_tokens(TOOLS_REGISTRY)
        act_tok = estimate_tokens(tools)
        self.token_tracker.record_schema_footprint(act_tok, base_tok)
        return {
            "tools": tools
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
        "bintra_ghidra_headless": ("cap.file.read", "READ", "binary_path"),
        "bintra_windows_env_audit": ("cap.registry.read", "READ", "file_path"),
        "bintra_resolve_dependencies": ("cap.file.read", "READ", "file_path"),
        "bintra_inspect_crash_reports": ("cap.minidump.read", "READ", "file_path"),
        "bintra_correlate_failure_evidence": ("cap.file.read", "READ", "binary_path"),
        "bintra_win_catalog_cmd": ("cap.subprocess.catalog_exec", "EXECUTE", "command_id"),
        "bintra_registry_audit": ("cap.registry.read", "READ", "domain"),
        "bintra_hardware_audit": ("cap.device.query", "QUERY", None),
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
        "bintra_fuse_evidence": ("cap.file.read", "READ", "binary_path"),
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
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": serialized_text
                        }
                    ],
                    "isError": False
                }
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
                "isError": True
            }

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name not in self.TOOL_SECURITY_METADATA and f"bintra_{name}" in self.TOOL_SECURITY_METADATA:
            name = f"bintra_{name}"
        if name == "bintra_inspect_binary":
            path = args["file_path"]
            res = BinaryFormatInspector.inspect(path)
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
            payload = args.get("payload")
            input_file = args.get("input_file")
            if not payload and input_file and os.path.exists(input_file):
                with open(input_file, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            if not payload:
                raise ValueError("Must provide 'payload' object or valid 'input_file'")
            return GhidraAnnotationPlanner.analyze_program_export(payload)

        elif name == "bintra_ghidra_headless":
            import subprocess, tempfile
            bin_path = args["binary_path"]
            ghidra_path_val = args.get("ghidra_path") or os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
            headless_name = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
            alt_name = "analyzeHeadless" if os.name == "nt" else "analyzeHeadless.bat"

            headless_bat = None
            if ghidra_path_val:
                p = Path(ghidra_path_val)
                cand = p / "support" / headless_name
                if cand.exists():
                    headless_bat = cand
                elif (p / "support" / alt_name).exists():
                    headless_bat = p / "support" / alt_name

            if not headless_bat:
                candidates = [
                    Path.home() / "tools" / "ghidra",
                    Path.home() / "ghidra",
                    Path(r"C:\ghidra") if os.name == "nt" else Path("/opt/ghidra"),
                    Path(r"C:\tools\ghidra"),
                    Path(r"D:\ghidra"),
                ]
                for cand_dir in candidates:
                    cand = cand_dir / "support" / headless_name
                    if cand.exists():
                        headless_bat = cand
                        break
                    alt = cand_dir / "support" / alt_name
                    if alt.exists():
                        headless_bat = alt
                        break

            if not headless_bat or not headless_bat.exists():
                raise FileNotFoundError(f"analyzeHeadless executable not found. Configure GHIDRA_INSTALL_DIR or pass 'ghidra_path'.")

            script_dir = SRC_DIR.parent / "ghidra_scripts"
            script_args = ["apply"] if args.get("apply", False) else []
            cmd = [
                str(headless_bat),
                tempfile.gettempdir(),
                "BintraMcpHeadless",
                "-import", bin_path,
                "-scriptPath", str(script_dir),
                "-postScript", "BintraGhidraBridge.java"
            ] + script_args
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
            error_markers = [
                "SCRIPT ERROR:",
                "Analysis failed for file:",
                "GhidraScriptLoadException",
                "RuntimeException:",
                "ERROR (GhidraScript)",
            ]
            has_script_error = any(m in combined for m in error_markers)
            effective_exit = proc.returncode if proc.returncode != 0 else (1 if has_script_error else 0)
            return {
                "exit_code": effective_exit,
                "script_error_detected": has_script_error,
                "is_error": effective_exit != 0,
                "stdout_tail": proc.stdout[-3000:],
                "stderr_tail": proc.stderr[-2000:]
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
            from windows_intelligence import CommandExecutor
            cmd_id = args.get("command_id", "")
            flags = tuple(args.get("extra_flags", [])) if args.get("extra_flags") else None
            return CommandExecutor.execute(cmd_id, extra_flags=flags)

        elif name == "bintra_registry_audit":
            from windows_intelligence import WindowsRegistryAnalyzer
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
            from windows_intelligence.device_intelligence import DriverMatcher, DriverPackageInventory
            offline_infs = args.get("offline_inf_paths")
            if offline_infs and args.get("device_id"):
                parsed_infs = [DriverPackageInventory.parse_offline_inf(p) for p in offline_infs]
                return DriverMatcher.match_offline_device_to_infs(args["device_id"], parsed_infs)
            action = args.get("action", "audit")
            query = args.get("device_query")
            c_filter = args.get("class_filter")
            prob_only = args.get("problems_only", False)

            if action == "find_packages":
                pkgs = DriverPackageInventory.find_driver_package_by_name(query or "")
                return {"status": "success", "query": query, "packages_count": len(pkgs), "packages": pkgs}
            return DriverMatcher.audit_device_driver_bindings(
                device_query=query,
                class_filter=c_filter,
                problems_only=prob_only,
                max_devices=int(args.get("max_devices", 64))
            )

        elif name == "bintra_process_resource_audit":
            from windows_intelligence.process_intelligence import FileUsageInspector, ModuleInventory, ProcessInventory, ServiceProcessMapper
            action = args.get("action", "find_file_locks")
            f_path = args.get("file_path")
            pid = args.get("pid")
            mod_q = args.get("module_query")

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
            elif action == "audit_process":
                target_pid = pid or os.getpid()
                mod_res = ModuleInventory.get_modules_for_process(target_pid)
                svcs = ServiceProcessMapper.get_services_for_process(target_pid)
                img = ProcessInventory.get_process_image_path(target_pid)
                return {
                    "status": "success",
                    "process_id": target_pid,
                    "image_path": img,
                    "hosted_services": svcs,
                    "loaded_modules_count": mod_res.get("modules_count", 0),
                    "modules_sample": mod_res.get("modules", [])[:15]
                }
            else:
                return {"status": "error", "error": f"Unknown action: '{action}'"}

        elif name == "bintra_python_bytecode":
            from python_intelligence import PythonBytecodeAnalyzer
            if args.get("compare_with"):
                return PythonBytecodeAnalyzer.compare_bytecode(args["file_path"], args["compare_with"])
            return PythonBytecodeAnalyzer.analyze_file(args["file_path"], limit=int(args.get("limit", 50)))

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
            from security import SafeFileAccess, TargetScope
            mode_val = args.get("mode", "pe")
            b_path = args["baseline_path"]
            t_path = args["target_path"]
            if mode_val == "ghidra_export":
                b_data = json.loads(SafeFileAccess.read_bytes(b_path).decode("utf-8"))
                t_data = json.loads(SafeFileAccess.read_bytes(t_path).decode("utf-8"))
                return SemanticBinaryDiffer().diff_function_exports(b_data.get("functions", []), t_data.get("functions", []))
            return SemanticBinaryDiffer().diff_pe_binaries(b_path, t_path)

        elif name == "bintra_ghidra_call_graph":
            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            from security import SafeFileAccess, TargetScope
            ep = args["export_path"]
            raw = SafeFileAccess.read_bytes(ep).decode("utf-8")
            exp_data = json.loads(raw)
            return GhidraDeepAnalyzer().build_call_graph_and_xrefs(
                exp_data,
                target_function=args.get("target_function"),
                max_depth=int(args.get("max_depth", 4)),
            )

        elif name == "bintra_ghidra_data_flow":
            from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
            from security import SafeFileAccess, TargetScope
            ep = args["export_path"]
            fn_target = args["function_name"]
            raw = SafeFileAccess.read_bytes(ep).decode("utf-8")
            exp_data = json.loads(raw)
            matched_fn = None
            for fn in exp_data.get("functions", []):
                if fn.get("name") == fn_target or fn.get("entry_point") == fn_target or fn.get("address") == fn_target:
                    matched_fn = fn
                    break
            if not matched_fn:
                return {"status": "not_found", "function_name": fn_target}
            return GhidraDeepAnalyzer().slice_data_flow(matched_fn, target_var=args.get("target_var"))

        elif name == "bintra_fuse_evidence":
            from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
            pe_res = None
            rca_res = None
            cg_res = None
            df_res = None
            if args.get("binary_path"):
                from pe_deep_forensics import PeDeepForensicsInspector
                pe_res = PeDeepForensicsInspector().inspect(args["binary_path"], limit=200)
            if args.get("dmp_path"):
                from windows_intelligence import CrashRootCauseAnalyzer
                rca_res = CrashRootCauseAnalyzer.analyze_crash(dump_target=args["dmp_path"], binary_path=args.get("binary_path"))
            if args.get("ghidra_export_path"):
                from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
                from security import SafeFileAccess, TargetScope
                gp = args["ghidra_export_path"]
                g_data = json.loads(SafeFileAccess.read_bytes(gp).decode("utf-8"))
                analyzer = GhidraDeepAnalyzer()
                cg_res = analyzer.build_call_graph_and_xrefs(g_data, target_function=args.get("function_name"))
                if args.get("function_name"):
                    for fn in g_data.get("functions", []):
                        if fn.get("name") == args["function_name"]:
                            df_res = analyzer.slice_data_flow(fn)
                            break
            return fuse_static_dynamic_ghidra(pe_forensics=pe_res, crash_rca=rca_res, ghidra_call_graph=cg_res, ghidra_data_flow=df_res)

        elif name == "bintra_list_capabilities":
            import platform as _plat
            p_filter = args.get("platform_filter", "all")
            win_tools = {
                "bintra_windows_env_audit", "bintra_resolve_dependencies", "bintra_inspect_crash_reports",
                "bintra_win_catalog_cmd", "bintra_registry_audit", "bintra_hardware_audit",
                "bintra_driver_audit", "bintra_service_audit", "bintra_etw_audit",
                "bintra_vad_inspect", "bintra_memory_scan", "bintra_pointer_scan",
                "bintra_struct_dissect", "bintra_etw_capture", "bintra_device_driver_intelligence",
                "bintra_process_resource_audit"
            }
            ghidra_tools = {
                "bintra_ghidra_headless", "bintra_ghidra_live_bridge", "bintra_match_pcode",
                "bintra_deobfuscate_pcode", "bintra_ghidra_analyze", "bintra_ghidra_call_graph",
                "bintra_ghidra_data_flow"
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
                    "static_pe_deep_audit": ["bintra_inspect_binary", "bintra_pe_deep_forensics", "bintra_deobfuscate_binary", "bintra_scan_hybrid"],
                    "ghidra_deep_re": ["bintra_ghidra_analyze", "bintra_ghidra_call_graph", "bintra_ghidra_data_flow"],
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
        # Ensure utf-8 stdio
        for stream_name in ("stdout", "stderr"):
            s = getattr(sys, stream_name, None)
            if s and hasattr(s, "reconfigure"):
                try:
                    s.reconfigure(encoding="utf-8", errors="replace")
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
