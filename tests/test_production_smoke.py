#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fast baseline smoke tests covering public entrypoints and core contracts before refactoring."""

import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _make_minimal_pe32(path: Path) -> Path:
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x014C, 1, 0, 0, 0, 0xE0, 0x0102)
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x10B)
    struct.pack_into("<IIIIIII", buf, opt + 16, 0x1000, 0x1000, 0x2000, 0x00400000, 0x1000, 0x200, 0)
    struct.pack_into("<HHHH", buf, opt + 40, 4, 0, 0, 0)
    struct.pack_into("<IIIIII", buf, opt + 56, 0x3000, 0x400, 0, 3, 0x0140, 0)
    struct.pack_into("<I", buf, opt + 92, 16)
    sec_off = opt + 0xE0
    buf[sec_off:sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_off + 8, 0x100, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    # Benign x86 ret stub at file offset 0x400
    buf[0x400:0x406] = b"\x55\x8B\xEC\x31\xC0\xC3"
    path.write_bytes(buf)
    return path


def _make_minimal_minidump(path: Path) -> Path:
    # Header + 2 streams (Stream 7 SystemInfo, Stream 6 Exception, Stream 4 ModuleList)
    buf = bytearray(0x400)
    # MDMP header (32B): sig, ver, num_streams=3, stream_dir_rva=0x40
    struct.pack_into("<IIIIII", buf, 0, 0x504D444D, 0xA793, 3, 0x40, 0, 0)
    # Directory entries at 0x40 (3 * 12 = 36 bytes)
    # Stream 7 SystemInfo (size 56, rva 0x80)
    struct.pack_into("<III", buf, 0x40, 7, 56, 0x80)
    # Stream 6 Exception (size 168, rva 0x100)
    struct.pack_into("<III", buf, 0x50 - 4, 6, 168, 0x100)
    # Stream 4 ModuleList (size 112, rva 0x200)
    struct.pack_into("<III", buf, 0x58, 4, 112, 0x200)

    # Stream 7 SystemInfo (arch=0 x86, major=10, minor=0, build=19045)
    struct.pack_into("<HHHH", buf, 0x80, 0, 6, 0, 0)
    struct.pack_into("<III", buf, 0x80 + 8, 10, 0, 19045)
    # Stream 6 Exception (thread_id=101, exc_code=0xC0000005, exc_addr=0x401000)
    struct.pack_into("<IIIIQQ", buf, 0x100, 101, 0, 0xC0000005, 0, 0, 0x401000)
    # Stream 4 ModuleList (count=1, mod base=0x400000, size=0x20000, name_rva=0x280)
    struct.pack_into("<I", buf, 0x200, 1)
    struct.pack_into("<QIIII", buf, 0x204, 0x400000, 0x20000, 0, 0, 0x280)
    name_utf16 = "C:\\app\\mod.exe".encode("utf-16-le")
    struct.pack_into("<I", buf, 0x280, len(name_utf16))
    buf[0x284:0x284 + len(name_utf16)] = name_utf16
    path.write_bytes(buf)
    return path


class TestProductionBaselineSmoke(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bintra_smoke_"))
        self.pe_path = _make_minimal_pe32(self.tmp_dir / "sample.exe")
        self.dmp_path = _make_minimal_minidump(self.tmp_dir / "crash.dmp")

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_cli_registry_all_handlers_resolve_cleanly(self):
        from bintra_cli import registry

        self.assertGreaterEqual(len(registry.COMMANDS), 80)
        for cmd_name in registry.COMMANDS:
            handler = registry.resolve(cmd_name)
            self.assertTrue(callable(handler), f"Handler not callable for '{cmd_name}'")
        self.assertIsNone(registry.resolve("__definitely_unknown_cmd__"))

    def test_cli_subprocess_core_commands_smoke(self):
        cli_py = str(SRC_DIR / "cli.py")
        for args, expected_key in (
            (["inspect", "--file", str(self.pe_path)], "pe_type"),
            (["sense", "--hex", "55 48 89 e5 90 5d c3"], "active_senses_count"),
            (["deobfuscate", "--hex", "55 48 89 e5 31 c0 74 02 90 c3"], "opaque_predicates_detected"),
            (["ghidra-plan", "--address", "0x401000", "--name", "SmokeFn"], "method"),
        ):
            proc = subprocess.run(
                [sys.executable, cli_py, *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=True,
            )
            payload = json.loads(proc.stdout)
            self.assertIn(expected_key, payload, f"Missing {expected_key} for CLI args {args}")

    def test_mcp_server_protocol_and_registry_parity_smoke(self):
        from bintra_mcp.tools import TOOL_HANDLERS
        from mcp_server import BintraMcpServer, TOOLS_REGISTRY

        ws = self.tmp_dir / "mcp_ws"
        srv = BintraMcpServer(workspace_root=str(ws))

        tool_names = {t["name"] for t in TOOLS_REGISTRY}
        self.assertEqual(tool_names, set(srv.TOOL_SECURITY_METADATA.keys()))
        self.assertEqual(tool_names, set(TOOL_HANDLERS.keys()))

        init_res = srv.handle_initialize({"protocolVersion": "2025-06-18"})
        self.assertEqual(init_res["protocolVersion"], "2025-06-18")
        self.assertIn("serverInfo", init_res)

        disc = srv.handle_server_discover()
        self.assertEqual(disc["name"], "bintra")

        resources = srv.handle_resources_list({})["resources"]
        self.assertEqual(len(resources), 4)
        for res in resources:
            read_out = srv.handle_resources_read({"uri": res["uri"]})
            self.assertIn("contents", read_out)

        prompts = srv.handle_prompts_list({})["prompts"]
        self.assertEqual(len(prompts), 5)
        sample_args = {
            "triage_pe_binary": {"file_path": str(self.pe_path)},
            "root_cause_crash": {"dmp_path": str(self.dmp_path)},
            "audit_windows_host": {"focus": "all"},
            "diff_binary_versions": {"baseline_path": "a.exe", "target_path": "b.exe"},
            "audit_neural_weights": {"target_path": "m.safetensors"},
        }
        for pr in prompts:
            got = srv.handle_prompts_get({"name": pr["name"], "arguments": sample_args[pr["name"]]})
            self.assertEqual(got["messages"][0]["role"], "user")

        out_insp = srv.handle_tools_call({"name": "bintra_inspect_binary", "arguments": {"file_path": str(self.pe_path)}})
        self.assertFalse(out_insp["isError"])
        self.assertEqual(out_insp["structuredContent"]["format"], "PE")

        bad_args = srv.handle_tools_call({"name": "bintra_inspect_binary", "arguments": "not-a-dict"})
        self.assertTrue(bad_args["isError"])

        from bintra_mcp.tools._common import parse_int_arg
        self.assertEqual(parse_int_arg("0x401000", "address"), 0x401000)
        with self.assertRaises(ValueError):
            parse_int_arg(True, "address")
        with self.assertRaises(ValueError):
            parse_int_arg("", "address")

        export_file = self.tmp_dir / "sample_export.json"
        export_file.write_text(json.dumps({"functions": []}), encoding="utf-8")
        cg_res = srv.handle_tools_call({"name": "bintra_ghidra_call_graph", "arguments": {"export_path": str(export_file)}})
        self.assertFalse(cg_res["isError"])

    def test_core_engines_and_security_invariants_smoke(self):
        from binary_neural_engine import BinaryFormatInspector, ContinuousDeobfuscator
        from ghidra_export_store import GhidraExportStore
        from ghidra_pcode_vectorizer import GhidraDeepAnalyzer, PcodeFunctionMatcher
        from pe_deep_forensics import PeDeepForensicsInspector, SemanticBinaryDiffer
        from security import ExecutionGuard, SafeFileAccess, TargetMutationError
        from windows_intelligence.crash_analyzer import WindowsCrashAnalyzer
        from windows_intelligence.runtime_telemetry.minidump_parser import MiniDumpParser

        insp = BinaryFormatInspector.inspect(str(self.pe_path))
        self.assertEqual(insp["pe_type"], "PE32 (32-bit)")
        self.assertEqual(ContinuousDeobfuscator.deobfuscate_file(str(self.pe_path))["total_bytes_analyzed"] > 0, True)

        forensics = PeDeepForensicsInspector().inspect(str(self.pe_path))
        self.assertEqual(forensics["status"], "ok")
        self.assertTrue(SemanticBinaryDiffer().diff_pe_binaries(str(self.pe_path), str(self.pe_path))["identical_sha256"])

        pcode = [
            {"opcode": "INT_ADD", "inputs": ["R0", "R1"], "output": "T0"},
            {"opcode": "INT_XOR", "inputs": ["T1", "T1"], "output": "Z0"},
            {"opcode": "CBRANCH", "inputs": ["Z0", "0x401010"], "output": None},
            {"opcode": "CALL", "inputs": ["VirtualAlloc"], "output": "R0"},
            {"opcode": "RETURN", "inputs": ["R0"], "output": None},
        ]
        m = PcodeFunctionMatcher.match(pcode, pcode)
        self.assertAlmostEqual(m["pcode_cosine_similarity"], 1.0, places=4)

        export_payload = {
            "image_base": "0x400000",
            "functions": [{"name": "fn", "entry_point": "0x401000", "pcode_ops": pcode, "callees": ["VirtualAlloc"]}],
        }
        with GhidraExportStore.from_path(export_payload) as store:
            cg = GhidraDeepAnalyzer().build_call_graph_and_xrefs(store)
            self.assertEqual(cg["functions_indexed"], 1)

        ws_dir = self.tmp_dir / "sec_ws"
        with ExecutionGuard.scoped_session(target_binary_path=str(self.pe_path), workspace_dir=str(ws_dir)):
            with self.assertRaises(TargetMutationError):
                SafeFileAccess.write_workspace_file(str(self.pe_path), b"BAD")

        with ExecutionGuard.scoped_session(target_binary_path=str(self.dmp_path), workspace_dir=str(ws_dir)):
            dmp1 = MiniDumpParser.parse_minidump(str(self.dmp_path))
            dmp2 = WindowsCrashAnalyzer.parse_minidump(str(self.dmp_path))
            self.assertEqual(dmp1["status"], "success")
            self.assertEqual(dmp2["status"], "success")
            self.assertEqual(dmp1["exception_info"]["fault_module"], "mod.exe")
            self.assertEqual(dmp2["exception_info"]["fault_module"], "mod.exe")


if __name__ == "__main__":
    unittest.main()
