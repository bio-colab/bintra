"""Static MCP tool definitions (JSON Schemas, descriptions) served by tools/list."""
from typing import Any, Dict, List

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
