#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Native Model Context Protocol (MCP) Server.
Standard JSON-RPC 2.0 stdio server providing agent-native reverse engineering
tools for AI models (Antigravity, Claude Code, Codex, Cursor, Devin, etc.).

Zero external dependencies: runs on Python standard library + numpy.
Protocol Version: 2024-11-05
"""

import os
import sys
import json
import traceback
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
    from rea_neural_engine import (
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
    sys.stderr.write(f"[REA-MCP] Error importing core engines: {err}\n")


SERVER_NAME = "rea-neural"
SERVER_VERSION = "7.4.0"
PROTOCOL_VERSION = "2024-11-05"


TOOLS_REGISTRY: List[Dict[str, Any]] = [
    {
        "name": "rea_inspect_binary",
        "description": "Deep inspection of Windows PE32/PE32+ (or ELF) executable headers, mitigations (ASLR, DEP, CFG), section geometries, and Shannon byte entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute filesystem path to the target executable (.exe or .dll)"
                }
            },
            "required": ["file_path"]
        }
    },
    {
        "name": "rea_deobfuscate_binary",
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
                    "type": "integer",
                    "description": "Optional file offset to start analysis at (defaults to entry point)"
                },
                "length": {
                    "type": "integer",
                    "description": "Number of bytes to analyze (default 4096)"
                }
            }
        }
    },
    {
        "name": "rea_dump_bytes",
        "description": "Extracts and displays raw bytes/machine code hex and ASCII preview from a binary executable at a given offset.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to binary executable on disk"
                },
                "offset": {
                    "type": "integer",
                    "description": "Byte offset in file to read from (e.g. 0x4e0778)"
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
        "name": "rea_match_functions",
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
        "name": "rea_patch_binary",
        "description": "Surgically patches machine code bytes on disk with stack balance proprioception (RSP/RBP guard), PE integrity checksum sync, and atomic write replacement.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to binary file to patch"
                },
                "offset": {
                    "type": "integer",
                    "description": "0-based file byte offset where patch begins"
                },
                "patch_hex": {
                    "type": "string",
                    "description": "Hexadecimal byte sequence to write (e.g. '90 90 90')"
                },
                "force": {
                    "type": "boolean",
                    "description": "Force overwrite even if stack-altering opcodes or DEP violations are flagged"
                }
            },
            "required": ["file_path", "offset", "patch_hex"]
        }
    },
    {
        "name": "rea_scan_hybrid",
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
        "name": "rea_sensory_audit",
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
        "name": "rea_match_pcode",
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
        "name": "rea_deobfuscate_pcode",
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
        "name": "rea_ghidra_analyze",
        "description": "Batch-processes a full Ghidra exported High P-Code program payload. Scans all functions, detects opaque predicates, calculates spectral effective rank, and synthesizes a mutation plan (renames, plate comments).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "object",
                    "description": "Exported program payload containing 'functions' array of High P-Code ops"
                },
                "input_file": {
                    "type": "string",
                    "description": "Optional path to exported JSON file on disk"
                }
            }
        }
    },
    {
        "name": "rea_ghidra_headless",
        "description": "Automates running Ghidra analyzeHeadless with ReaNeuralGhidraBridge.java on Windows. Decompiles functions, extracts High P-Code, analyzes semantics, and applies database mutations in one command.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {
                    "type": "string",
                    "description": "Absolute path to target executable (PE/ELF)"
                },
                "ghidra_path": {
                    "type": "string",
                    "description": "Optional Ghidra install path (defaults to C:\\Users\\Eylias\\tools\\ghidra or GHIDRA_INSTALL_DIR)"
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
        "name": "rea_windows_env_audit",
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
        "name": "rea_resolve_dependencies",
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
        "name": "rea_inspect_crash_reports",
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
        "name": "rea_correlate_failure_evidence",
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
        "name": "rea_win_catalog_cmd",
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
        "name": "rea_registry_audit",
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
        "name": "rea_wsp_audit",
        "description": "Audits neural weights embedded inside Windows executables without execution: computes Roy-Vetterli spectral effective rank, cross-layer induction composition, amenability diagnostic, and scans for dormant backdoor/trojan neurons (>4.5σ).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "model_path": {
                    "type": "string",
                    "description": "Path to safetensors model file"
                }
            },
            "required": ["model_path"]
        }
    },
    {
        "name": "rea_patch_weights",
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
    }
]


class ReaMcpServer:
    """Standard MCP Stdio JSON-RPC Server."""

    def __init__(self):
        self.handlers = {
            "initialize": self.handle_initialize,
            "notifications/initialized": self.handle_initialized_notification,
            "tools/list": self.handle_tools_list,
            "tools/call": self.handle_tools_call,
            "ping": self.handle_ping,
        }

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

    def handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "tools": TOOLS_REGISTRY
        }

    def handle_tools_call(self, params: Dict[str, Any]) -> Dict[str, Any]:
        tool_name = params.get("name")
        args = params.get("arguments", {})

        try:
            result_data = self.dispatch_tool(tool_name, args)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result_data, indent=2, ensure_ascii=False)
                    }
                ],
                "isError": False
            }
        except Exception as exc:
            tb = traceback.format_exc()
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps({
                            "status": "error",
                            "tool": tool_name,
                            "error": str(exc),
                            "traceback": tb
                        }, indent=2)
                    }
                ],
                "isError": True
            }

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name == "rea_inspect_binary":
            path = args["file_path"]
            return BinaryFormatInspector.inspect(path)

        elif name == "rea_deobfuscate_binary":
            code_hex = args.get("code_hex")
            file_path = args.get("file_path")
            offset = args.get("offset")
            length = int(args.get("length", 4096))
            if code_hex:
                raw_bytes = bytes.fromhex(code_hex.replace(" ", "").replace("\n", ""))
                return ContinuousDeobfuscator.deobfuscate_cfg(raw_bytes)
            elif file_path and os.path.exists(file_path):
                return ContinuousDeobfuscator.deobfuscate_file(file_path, offset=offset, length=length)
            else:
                raise ValueError("Must provide 'code_hex' or valid 'file_path'")

        elif name == "rea_dump_bytes":
            path = args["file_path"]
            offset = int(args["offset"])
            length = int(args.get("length", 64))
            return SurgicalBinaryPatcher.read_bytes(path, offset, length)

        elif name == "rea_match_functions":
            f1_hex = args["func1_hex"]
            f2_hex = args["func2_hex"]
            return SemanticFunctionMatcher.match_functions(f1_hex, f2_hex)

        elif name == "rea_patch_binary":
            path = args["file_path"]
            out_path = args.get("output_path", path)
            offset = int(args["offset"])
            patch_hex = args["patch_hex"]
            force = bool(args.get("force", False))
            return SurgicalBinaryPatcher.patch_file(
                source_path=path,
                output_path=out_path,
                file_offset=offset,
                patch_hex=patch_hex,
                enforce_nociception=not force
            )

        elif name == "rea_scan_hybrid":
            path = args["file_path"]
            return HybridBinaryDissector.scan_for_embedded_logic(path)

        elif name == "rea_sensory_audit":
            file_path = args.get("file_path")
            code_hex = args.get("code_hex")
            cortex = SensoryCortex()
            return cortex.evaluate_all_senses(file_path=file_path, code_hex=code_hex)

        elif name == "rea_match_pcode":
            p1 = args["func1_pcode"]
            p2 = args["func2_pcode"]
            return PcodeFunctionMatcher.match(p1, p2)

        elif name == "rea_deobfuscate_pcode":
            pcode_ops = args["pcode_ops"]
            return PcodeDeobfuscator.detect_opaque_predicates(pcode_ops)

        elif name == "rea_ghidra_analyze":
            payload = args.get("payload")
            input_file = args.get("input_file")
            if not payload and input_file and os.path.exists(input_file):
                with open(input_file, "r", encoding="utf-8") as f:
                    payload = json.load(f)
            if not payload:
                raise ValueError("Must provide 'payload' object or valid 'input_file'")
            return GhidraAnnotationPlanner.analyze_program_export(payload)

        elif name == "rea_ghidra_headless":
            import subprocess, tempfile
            bin_path = args["binary_path"]
            ghidra_dir = Path(args.get("ghidra_path") or os.environ.get("GHIDRA_INSTALL_DIR", r"C:\Users\Eylias\tools\ghidra"))
            headless_bat = ghidra_dir / "support" / "analyzeHeadless.bat"
            if not headless_bat.exists():
                raise FileNotFoundError(f"analyzeHeadless.bat not found at: {headless_bat}")
            script_dir = SRC_DIR.parent / "ghidra_scripts"
            script_args = ["apply"] if args.get("apply", False) else []
            cmd = [
                str(headless_bat),
                tempfile.gettempdir(),
                "REANeuralMcpHeadless",
                "-import", bin_path,
                "-scriptPath", str(script_dir),
                "-postScript", "ReaNeuralGhidraBridge.java"
            ] + script_args
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
            return {
                "exit_code": proc.returncode,
                "stdout_tail": proc.stdout[-3000:],
                "stderr_tail": proc.stderr[-2000:]
            }

        elif name == "rea_windows_env_audit":
            from windows_intelligence import WindowsOSProfiler, WindowsDeviceInspector, WindowsSecurityInspector
            b = args.get("file_path") or args.get("binary_path")
            return {
                "os": WindowsOSProfiler.profile(b),
                "devices": WindowsDeviceInspector.audit(),
                "security": WindowsSecurityInspector.audit(b)
            }

        elif name == "rea_resolve_dependencies":
            from windows_intelligence import WindowsDependencyResolver
            b = args.get("file_path") or args.get("binary_path")
            return WindowsDependencyResolver.audit_dependencies(b)

        elif name == "rea_inspect_crash_reports":
            from windows_intelligence import WindowsCrashAnalyzer
            b = args.get("file_path") or args.get("binary_path")
            return WindowsCrashAnalyzer.collect_crash_evidence(b)

        elif name == "rea_correlate_failure_evidence":
            from windows_intelligence import DiagnosticEvidenceCorrelator
            b = args.get("binary_path") or args.get("file_path")
            c = args.get("crash_record")
            g = args.get("ghidra_export")
            return DiagnosticEvidenceCorrelator.correlate(b, crash_record=c, ghidra_export=g)

        elif name == "rea_win_catalog_cmd":
            from windows_intelligence import CommandExecutor
            cmd_id = args.get("command_id", "")
            flags = tuple(args.get("extra_flags", [])) if args.get("extra_flags") else None
            return CommandExecutor.execute(cmd_id, extra_flags=flags)

        elif name == "rea_registry_audit":
            from windows_intelligence import WindowsRegistryAnalyzer
            domain = args.get("domain")
            target_b = args.get("target_binary")
            if domain:
                return WindowsRegistryAnalyzer.audit_domain(domain)
            return WindowsRegistryAnalyzer.audit_all()

        elif name == "rea_wsp_audit":
            path = args["model_path"]
            return WeightSecurityAuditor.audit_weights_without_evaluation(path)

        elif name == "rea_patch_weights":
            src = args["source_path"]
            out = args["output_path"]
            tname = args["tensor_name"]
            num_cols = int(args.get("num_columns", 64))
            return WeightPatcher.patch_safetensors_file(
                src_path=src,
                output_path=out,
                tensor_name=tname,
                operation="column_direction_subtract",
                num_columns=num_cols
            )

        else:
            raise ValueError(f"Unknown tool name: '{name}'")

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
                msg_id = msg.get("id")
                method = msg.get("method")
                params = msg.get("params", {})

                if method not in self.handlers:
                    if msg_id is not None:
                        err_resp = {
                            "jsonrpc": "2.0",
                            "id": msg_id,
                            "error": {
                                "code": -32601,
                                "message": f"Method not found: '{method}'"
                            }
                        }
                        sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
                        sys.stdout.flush()
                    continue

                handler = self.handlers[method]
                result = handler(params)

                # Notifications don't receive replies
                if msg_id is not None:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "result": result
                    }
                    sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
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
    server = ReaMcpServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
