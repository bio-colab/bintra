# -*- coding: utf-8 -*-
"""
Audit Remediation & Regression Test Suite for Bintra (F1-F14).
Verifies:
- F1/F4/F9: Honest simulation flags and fail-loud memory read contracts.
- F2: Live Ghidra Bridge P-Code RPCs (bintra.deobfuscate_function, bintra.match_functions).
- F3/F8: Broken MCP tools fixed (bintra_memory_scan, bintra_wsp_audit, bintra_patch_binary hex offset, KeyError envelopes).
- F5: Bridge auth token file permission hardening (0o600 on POSIX / isolated permissions).
- F6: CausalitySynthesizer consistent binary_mapping schema across branches.
- F7: Clean JSON error envelopes in CLI on ordinary user errors (zero raw tracebacks).
- F11/F12/F13: Epistemic honesty bounds (probe-trace, amenability cols, deobfuscate truncation, fault_rva vs VA).
- Interface smoke audit across all 34 registered MCP tools.
"""

import os
import sys
import stat
import json
import struct
import urllib.request
import tempfile
import subprocess
import unittest
from pathlib import Path

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def _save_safetensors(path: str, tensor_name: str, arr) -> None:
    raw = arr.astype("float32").tobytes()
    hdr = json.dumps({
        tensor_name: {
            "dtype": "F32",
            "shape": list(arr.shape),
            "data_offsets": [0, len(raw)]
        }
    }).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hdr)))
        f.write(hdr)
        f.write(raw)


def _build_minimal_pe64() -> bytes:
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", buf, 0x98, 0x20B)  # PE32+ magic
    struct.pack_into("<I", buf, 0x98 + 16, 0x1000)  # EntryPoint RVA
    struct.pack_into("<Q", buf, 0x98 + 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", buf, 0x98 + 32, 0x1000)
    struct.pack_into("<I", buf, 0x98 + 36, 0x200)
    struct.pack_into("<I", buf, 0x98 + 56, 0x2000)  # SizeOfImage
    struct.pack_into("<I", buf, 0x98 + 60, 0x200)   # SizeOfHeaders
    sec_off = 0x188
    buf[sec_off:sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_off + 8, 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    buf[0x200:0x202] = b"\x90\xC3"
    return bytes(buf)


class TestAuditRemediations(unittest.TestCase):

    def test_f2_ghidra_bridge_pcode_rpcs_live_roundtrip(self):
        """F2: Verifies bintra.deobfuscate_function and bintra.match_functions work end-to-end via live bridge RPC."""
        from ghidra_live_bridge import GhidraLiveBridgeServer
        import random
        port = random.randint(43000, 46000)
        srv = GhidraLiveBridgeServer(port=port)
        with tempfile.TemporaryDirectory() as ws_dir:
            marker_path = os.path.join(ws_dir, ".bintra_bridge.json")
            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(workspace_dir=ws_dir):
                info = srv.start(marker_path=marker_path)
                try:
                    token = info["auth_token"]
                    url = info["bridge_url"]

                    # 1. Verify marker permissions (on POSIX mode must not be group/world readable)
                    if os.name != "nt":
                        mode = stat.S_IMODE(os.stat(marker_path).st_mode)
                        self.assertEqual(mode & 0o077, 0, f"Bridge marker overly permissive: {oct(mode)}")

                    pcode_ops = [
                        {"opcode": "INT_XOR", "inputs": ["RAX", "RAX"], "output": "TMP1"},
                        {"opcode": "CBRANCH", "inputs": ["TMP1"], "output": None},
                        {"opcode": "INT_ADD", "inputs": ["RBX", "RCX"], "output": "RBX"},
                        {"opcode": "INT_ADD", "inputs": ["RBX", "RCX"], "output": "RBX"},
                        {"opcode": "RETURN", "inputs": ["RBX"], "output": None},
                    ]

                    def rpc(method, params):
                        req_data = json.dumps({
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": method,
                            "params": params
                        }).encode("utf-8")
                        req = urllib.request.Request(
                            url,
                            data=req_data,
                            headers={"Content-Type": "application/json", "X-Bintra-Auth-Token": token},
                            method="POST"
                        )
                        with urllib.request.urlopen(req, timeout=5.0) as resp:
                            return json.loads(resp.read().decode("utf-8"))

                    # bintra.deobfuscate_function
                    res_deob = rpc("bintra.deobfuscate_function", {"pcode_ops": pcode_ops})
                    self.assertIn("result", res_deob, f"RPC failed: {res_deob}")
                    self.assertIn("is_obfuscated", res_deob["result"])
                    self.assertTrue(res_deob["result"]["is_obfuscated"])

                    # bintra.match_functions
                    res_match = rpc("bintra.match_functions", {
                        "func1": {"pcode_ops": pcode_ops},
                        "func2": {"pcode_ops": pcode_ops}
                    })
                    self.assertIn("result", res_match, f"RPC failed: {res_match}")
                    self.assertGreaterEqual(res_match["result"]["similarity"], 0.99)
                finally:
                    srv.stop()

    def test_f3_f8_mcp_broken_tools_and_keyerror_envelopes(self):
        """F3/F8: Verifies all 34 MCP tools schema, hex offsets, bintra_wsp_audit, bintra_memory_scan, and KeyError formatting."""
        from mcp_server import BintraMcpServer
        import numpy as np
        from bintra_engine import SafetensorsHandler

        srv = BintraMcpServer()
        tools = srv.handle_tools_list({})["tools"]
        self.assertEqual(len(tools), 34)
        for t in tools:
            self.assertIn(t["name"], srv.TOOL_SECURITY_METADATA)
            self.assertIn("inputSchema", t)

        # F8: Missing required arg returns structured schema validation message, not raw KeyError string
        err_resp = srv.handle_tools_call({"name": "bintra_inspect_binary", "arguments": {}})
        self.assertTrue(err_resp["isError"])
        err_json = json.loads(err_resp["content"][0]["text"])
        self.assertIn("Missing required parameter", err_json["error"])

        # F8b: Invalid enum value caught by inputSchema validator
        enum_err = srv.handle_tools_call({
            "name": "bintra_process_resource_audit",
            "arguments": {"action": "invalid_nonexistent_action"}
        })
        self.assertTrue(enum_err["isError"])
        enum_json = json.loads(enum_err["content"][0]["text"])
        self.assertIn("Invalid value for parameter 'action'", enum_json["error"])

        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir:
            pe_path = os.path.join(tgt_dir, "sample.exe")
            out_path = os.path.join(ws_dir, "patched.exe")
            with open(pe_path, "wb") as f:
                f.write(_build_minimal_pe64())

            # F3a: Default BintraMcpServer rejects untrusted client workspace_dir override;
            # host-configured BintraMcpServer(allowed_workspace_roots=[ws_dir]) authorizes ws_dir.
            srv_ws = BintraMcpServer(allowed_workspace_roots=[ws_dir])
            patch_resp = srv_ws.handle_tools_call({
                "name": "bintra_patch_binary",
                "arguments": {
                    "file_path": pe_path,
                    "output_path": out_path,
                    "offset": "0x200",
                    "patch_hex": "90",
                    "workspace_dir": ws_dir
                }
            })
            self.assertFalse(patch_resp["isError"], f"bintra_patch_binary failed: {patch_resp}")
            patch_data = json.loads(patch_resp["content"][0]["text"])
            self.assertEqual(patch_data["file_offset"], "0x200")
            self.assertTrue(patch_data["pe_checksum_recalculated"])
            self.assertTrue(patch_data["is_safe"])

            # F3b: bintra_dump_bytes with hex offset string "0x200"
            dump_resp = srv.handle_tools_call({
                "name": "bintra_dump_bytes",
                "arguments": {
                    "file_path": out_path,
                    "offset": "0x200",
                    "length": 4
                }
            })
            self.assertFalse(dump_resp["isError"], f"bintra_dump_bytes failed: {dump_resp}")

            # F3c: bintra_wsp_audit with valid safetensors file
            model_path = os.path.join(ws_dir, "test_model.safetensors")
            arr = np.random.randn(8, 8).astype(np.float32)
            _save_safetensors(model_path, "layer.weight", arr)
            wsp_resp = srv.handle_tools_call({
                "name": "bintra_wsp_audit",
                "arguments": {"model_path": model_path}
            })
            self.assertFalse(wsp_resp["isError"], f"bintra_wsp_audit failed: {wsp_resp}")
            wsp_data = json.loads(wsp_resp["content"][0]["text"])
            self.assertEqual(wsp_data["status"], "success")
            self.assertIn("effective_rank_analysis", wsp_data)
            self.assertIn("zero_eval_security_audit", wsp_data)

            # F3d: bintra_memory_scan does not raise TypeError(ProcessMemoryScanner() takes no arguments)
            scan_resp = srv.handle_tools_call({
                "name": "bintra_memory_scan",
                "arguments": {
                    "pid": os.getpid(),
                    "value_type": "int32",
                    "scan_mode": "exact",
                    "target_value": "12345"
                }
            })
            scan_data = json.loads(scan_resp["content"][0]["text"])
            self.assertNotIn("takes no arguments", str(scan_data))

    def test_f1_f4_snapshot_simulation_transparency(self):
        """F1/F4: Verifies ProcessMemoryMapSnapshot marks synthetic snapshots clearly and non-NT degrades cleanly."""
        from windows_intelligence.runtime_telemetry.virtual_memory_inspector import ProcessMemoryMapSnapshot
        sim_snap = ProcessMemoryMapSnapshot(pid=1, process_name="simulated_1.exe", is_simulated=True)
        d = sim_snap.to_dict()
        self.assertEqual(d["status"], "simulated")
        self.assertEqual(d["source"], "synthetic")
        self.assertTrue(d["is_simulated"])
        self.assertIn("notice", d)

        live_snap = ProcessMemoryMapSnapshot(pid=1, process_name="live.exe", is_simulated=False)
        d_live = live_snap.to_dict()
        self.assertEqual(d_live["status"], "live") if "live" == d_live["status"] else self.assertEqual(d_live["status"], "success")
        self.assertEqual(d_live["source"], "live")
        self.assertFalse(d_live["is_simulated"])

    def test_f7_cli_clean_json_error_envelopes(self):
        """F7: Verifies invoking cli.py main() on invalid inputs outputs JSON errors instead of raw Python tracebacks."""
        cli_path = os.path.join(SRC_DIR, "cli.py")

        # 1. Invalid hex to match command
        p1 = subprocess.run(
            [sys.executable, cli_path, "match", "--func1", "not_a_hex_file.bin", "--func2", "90"],
            capture_output=True, text=True, encoding="utf-8"
        )
        self.assertNotEqual(p1.returncode, 0)
        self.assertNotIn("Traceback (most recent call last):", p1.stderr)
        err1 = json.loads(p1.stdout)
        self.assertEqual(err1["status"], "error")
        self.assertIn("error_type", err1)

        # 2. Empty file inspect returns structured JSON (no traceback)
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            empty_path = tf.name
        try:
            p2 = subprocess.run(
                [sys.executable, cli_path, "inspect", "--file", empty_path],
                capture_output=True, text=True, encoding="utf-8"
            )
            self.assertEqual(p2.returncode, 0)
            res2 = json.loads(p2.stdout)
            self.assertEqual(res2["format"], "EMPTY_FILE")
            self.assertEqual(res2["size"], 0)
        finally:
            if os.path.exists(empty_path):
                os.unlink(empty_path)

        # 3. Corrupted MiniDump with invalid stream count yields non-empty explicit error message
        from windows_intelligence.runtime_telemetry.minidump_parser import MiniDumpParser
        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as df:
            df.write(struct.pack("<IIIIIIQ", 0x504D444D, 0x0000A793, 0xFFFFFFFF, 32, 0, 1600000000, 0))
            bad_dmp = df.name
        try:
            dmp_res = MiniDumpParser.parse_minidump(bad_dmp)
            self.assertEqual(dmp_res["status"], "error")
            self.assertTrue(bool(dmp_res["error"].strip()))
            self.assertIn("invalid stream", dmp_res["error"].lower())
        finally:
            if os.path.exists(bad_dmp):
                os.unlink(bad_dmp)

    def test_f11_f12_epistemic_honesty_and_truncation(self):
        """F11/F12: Verifies probe-trace steps>=1 + simulation label, amenability column clamping, and deobfuscation truncation."""
        import numpy as np
        from bintra_engine import ActivationTraceProber, AmenabilityDiagnostic, SafetensorsHandler
        from binary_neural_engine import ContinuousDeobfuscator

        with tempfile.TemporaryDirectory() as ws_dir:
            model_path = os.path.join(ws_dir, "tiny.safetensors")
            arr = np.arange(16, dtype=np.float32).reshape(4, 4)
            _save_safetensors(model_path, "proj.weight", arr)

            # F11a: max_tokens=3 should simulate 3 steps (not clamp silently to 4) and declare simulation
            probe = ActivationTraceProber.probe_trace(model_path, prompt="test prompt", max_tokens=3)
            self.assertEqual(probe["steps_simulated"], 3)
            self.assertEqual(probe["analysis_mode"], "SEEDED_SPECTRAL_OPERATOR_SIMULATION")
            self.assertIn("disclaimer", probe)

            # F11b: recommended_num_columns and advice never exceed tensor width (4)
            amen = AmenabilityDiagnostic.evaluate_surgical_amenability(arr)
            self.assertLessEqual(amen["recommended_num_columns"], 4)
            self.assertIn("num_columns=4", amen["surgery_scale_advice"])
            self.assertEqual(amen["analysis_mode"], "SPECTRAL_HEURISTIC_ESTIMATE")
            self.assertEqual(amen["loop_rate_source"], "spectral_heuristic_estimate")
            self.assertIn("estimated_loop_rate", amen)

            # F11c: CircuitDecompiler discloses single-metric spectral heuristic confidence
            from bintra_engine import CircuitDecompiler, SubspaceAnalyzer
            svd_m = SubspaceAnalyzer.analyze_svd(arr, top_k=4)
            dec = CircuitDecompiler.decompile_attention_head(svd_m, layer_idx=0, head_idx=0)
            self.assertEqual(dec["classification_confidence"], "HEURISTIC_SPECTRAL_RATIO")
            self.assertIn("heuristic_note", dec)

            # F12: deobfuscate_file marks truncation when file exceeds analysis window
            big_bin = os.path.join(ws_dir, "big.bin")
            with open(big_bin, "wb") as f:
                f.write(b"\x90" * 512)
            deob = ContinuousDeobfuscator.deobfuscate_file(big_bin, offset=0, length=64)
            self.assertTrue(deob["is_truncated"])
            self.assertEqual(deob["analysis_window_size"], 64)
            self.assertEqual(deob["total_file_size"], 512)

    def test_second_audit_security_and_math_remediations(self):
        """Second Audit S-1/S-2 & F-1..F-5: Workspace override block, bintra_patch_weights, fail-closed imports, small-layer backdoors."""
        import builtins
        import unittest.mock as mock
        import numpy as np
        from mcp_server import BintraMcpServer
        from security import ExecutionGuard, TargetScope, AuditLogger, SafeFileAccess, TargetMutationError
        from binary_neural_engine import SurgicalBinaryPatcher
        from bintra_engine import SafetensorsHandler, WeightSecurityAuditor

        # S-1 / F-1a: TargetScope rejects filesystem root & user home root
        root_dir = os.path.abspath(os.sep)
        with self.assertRaises(PermissionError):
            TargetScope(workspace_dir=root_dir)
        with self.assertRaises(PermissionError):
            TargetScope(workspace_dir=os.path.expanduser("~"))

        # S-1 / F-1b: Default BintraMcpServer rejects untrusted client workspace_dir overrides fail-closed
        default_srv = BintraMcpServer()
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir:
            pe_path = os.path.join(tgt_dir, "victim.exe")
            with open(pe_path, "wb") as f:
                f.write(_build_minimal_pe64())
            evil_out = os.path.join(ws_dir, "pwn.exe")
            for evil_ws in (root_dir, ws_dir):
                resp = default_srv.handle_tools_call({
                    "name": "bintra_patch_binary",
                    "arguments": {
                        "file_path": pe_path,
                        "output_path": evil_out,
                        "offset": "0x200",
                        "patch_hex": "90",
                        "workspace_dir": evil_ws,
                    },
                })
                self.assertTrue(resp["isError"])
                self.assertIn("UNTRUSTED_WORKSPACE_OVERRIDE", resp["content"][0]["text"])
                self.assertFalse(os.path.exists(evil_out))

            # SafeFileAccess.write_workspace_file raises TargetMutationError (fixed broken .policy_engine import)
            with ExecutionGuard.scoped_session(target_binary_path=pe_path, workspace_dir=ws_dir):
                with self.assertRaises(TargetMutationError):
                    SafeFileAccess.write_workspace_file(pe_path, b"overwrite")

        # F-2: bintra_patch_weights works end-to-end inside authorized workspace
        with tempfile.TemporaryDirectory() as src_dir, tempfile.TemporaryDirectory() as ws_dir:
            src_st = os.path.join(src_dir, "model.safetensors")
            out_st = os.path.join(ws_dir, "patched_model.safetensors")
            _save_safetensors(src_st, "attn.o_proj.weight", np.ones((16, 16), dtype=np.float32))
            auth_srv = BintraMcpServer(allowed_workspace_roots=[ws_dir])
            pw_resp = auth_srv.handle_tools_call({
                "name": "bintra_patch_weights",
                "arguments": {
                    "source_path": src_st,
                    "output_path": out_st,
                    "tensor_name": "attn.o_proj.weight",
                    "num_columns": 4,
                    "workspace_dir": ws_dir,
                },
            })
            self.assertFalse(pw_resp["isError"], f"bintra_patch_weights failed: {pw_resp}")
            pw_data = json.loads(pw_resp["content"][0]["text"])
            self.assertEqual(pw_data["status"], "success")
            self.assertTrue(os.path.isfile(out_st))

        # Every MCP tool metadata target parameter must exist in its inputSchema (or be None)
        for t in auth_srv.handle_tools_list({})["tools"]:
            t_name = t["name"]
            _, _, param = auth_srv.TOOL_SECURITY_METADATA[t_name]
            if param is not None:
                props = t.get("inputSchema", {}).get("properties", {})
                self.assertIn(param, props, f"TOOL_SECURITY_METADATA target '{param}' absent from {t_name} schema")

        # S-2 / F-4: SurgicalBinaryPatcher & SafetensorsHandler fail closed when security cannot be imported
        real_import = builtins.__import__

        def blocking_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "security" or name.startswith("security."):
                raise ImportError("Simulated missing security kernel")
            return real_import(name, globals, locals, fromlist, level)

        with tempfile.TemporaryDirectory() as tmp_d:
            pe_src = os.path.join(tmp_d, "a.exe")
            pe_out = os.path.join(tmp_d, "b.exe")
            with open(pe_src, "wb") as f:
                f.write(_build_minimal_pe64())
            st_src = os.path.join(tmp_d, "m.safetensors")
            st_out = os.path.join(tmp_d, "m2.safetensors")
            _save_safetensors(st_src, "w", np.ones((4, 4), dtype=np.float32))

            with mock.patch("builtins.__import__", side_effect=blocking_import):
                with self.assertRaises(RuntimeError) as cm1:
                    SurgicalBinaryPatcher.patch_file(pe_src, pe_out, 0x200, "90")
                self.assertIn("SECURITY_KERNEL_UNAVAILABLE", str(cm1.exception))
                self.assertFalse(os.path.exists(pe_out))

                with self.assertRaises(RuntimeError) as cm2:
                    SafetensorsHandler.write_patched_safetensors(st_src, st_out, {"w": np.zeros((4, 4), dtype=np.float32)})
                self.assertIn("SECURITY_KERNEL_UNAVAILABLE", str(cm2.exception))
                self.assertFalse(os.path.exists(st_out))

        # F-5: Small-layer 16x128 backdoor detection (1 or 2 spikes detected, normal noise not flagged)
        rng = np.random.default_rng(1234)
        clean_small = (rng.standard_normal((16, 128)) * 0.1).astype(np.float32)
        clean_res = WeightSecurityAuditor.audit_weights_without_evaluation(clean_small)
        self.assertFalse(clean_res["potential_backdoor_detected"])

        one_spike = clean_small.copy()
        one_spike[3, :] *= 80.0
        one_res = WeightSecurityAuditor.audit_weights_without_evaluation(one_spike)
        self.assertTrue(one_res["potential_backdoor_detected"])
        self.assertIn(3, one_res["suspect_trigger_neurons"])

        two_spikes = clean_small.copy()
        two_spikes[3, :] *= 80.0
        two_spikes[4, :] *= 80.0
        two_res = WeightSecurityAuditor.audit_weights_without_evaluation(two_spikes)
        self.assertTrue(two_res["potential_backdoor_detected"])
        self.assertIn(3, two_res["suspect_trigger_neurons"])
        self.assertIn(4, two_res["suspect_trigger_neurons"])

    def test_second_audit_telemetry_cli_and_bridge_remediations(self):
        """Second Audit F-3, F-8, F-10, F-11, F-13, F-14, F-18, F-20: x86 CONTEXT, RCA bounds, wevtutil, CLI & bridge hygiene."""
        import struct
        import subprocess
        import unittest.mock as mock
        import cli as cli_mod
        from security import AuditLogger, ExecutionGuard, SecurityViolationError, OutOfScopeError
        from windows_intelligence.runtime_telemetry import (
            MiniDumpParser,
            CrashRootCauseAnalyzer,
            EventLogCollector,
            EtwLiveCaptureSession,
        )
        import ghidra_live_bridge as glb

        # F-11: Verify WinNT x86 CONTEXT offsets (Edi=156, Esi=160, Ebx=164, Edx=168, Ecx=172, Eax=176, Ebp=180, Eip=184, Esp=196)
        ctx = bytearray(716)
        struct.pack_into("<I", ctx, 156, 0x77777777)  # EDI
        struct.pack_into("<I", ctx, 160, 0x55555555)  # ESI
        struct.pack_into("<I", ctx, 164, 0xBBBBBBBB)  # EBX
        struct.pack_into("<I", ctx, 168, 0xDDDDDDDD)  # EDX
        struct.pack_into("<I", ctx, 172, 0xCCCCCCCC)  # ECX
        struct.pack_into("<I", ctx, 176, 0xAAAAAAAA)  # EAX
        struct.pack_into("<I", ctx, 180, 0x0012FF50)  # EBP
        struct.pack_into("<I", ctx, 184, 0x00401050)  # EIP
        struct.pack_into("<I", ctx, 196, 0x0012FF00)  # ESP

        exc_rva = 32 + 12  # Header(32) + 1 directory entry(12)
        ctx_rva = exc_rva + 168
        exc_data = struct.pack(
            "<IIIIQQII15QII",
            1001, 0, 0xC0000005, 0, 0, 0x401050, 2, 0,
            *([0, 0x10] + [0] * 13), len(ctx), ctx_rva
        )
        dir_entry = struct.pack("<III", 6, len(exc_data), exc_rva)
        hdr = struct.pack("<IIIIII", 0x504D444D, 0xA793, 1, 32, 0, 0) + b"\x00" * 8
        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tf:
            tf.write(hdr + dir_entry + exc_data + bytes(ctx))
            dmp_path = tf.name
        try:
            with ExecutionGuard.scoped_session(target_binary_path=dmp_path):
                parsed = MiniDumpParser.parse_minidump(dmp_path)
            regs = parsed["exception_info"]["thread_registers"]
            self.assertEqual(regs["arch"], "x86")
            self.assertEqual(regs["ecx"], hex(0xCCCCCCCC))
            self.assertEqual(regs["edx"], hex(0xDDDDDDDD))
            self.assertEqual(regs["ebx"], hex(0xBBBBBBBB))
            self.assertEqual(regs["esi"], hex(0x55555555))
            self.assertEqual(regs["edi"], hex(0x77777777))
        finally:
            if os.path.exists(dmp_path):
                os.remove(dmp_path)

        # F-13: Missing target_virtual_address -> UNKNOWN_TARGET_ADDRESS (not NULL_PAGE_TRAP)
        no_av_dump = {
            "status": "success",
            "exception_info": {"exception_code": "0xc0000094", "exception_name": "INTEGER_DIVIDE_BY_ZERO"},
            "threads": [{"thread_id": 1, "stack_base": "0x00100000", "stack_size_bytes": 0x1000}],
            "modules": [],
        }
        no_av_rca = CrashRootCauseAnalyzer.analyze_crash(no_av_dump)
        self.assertEqual(no_av_rca["root_cause_classification"], "UNKNOWN_TARGET_ADDRESS")
        self.assertEqual(no_av_rca["target_address"], "UNAVAILABLE")

        # F-13: Thread stack bounds [st_base, st_base + st_size_bytes) must NOT include st_base - 0x100
        below_stack = CrashRootCauseAnalyzer._classify_target_memory(0x00100000 - 0x100, no_av_dump)
        self.assertNotEqual(below_stack.get("category"), "THREAD_STACK")
        inside_stack = CrashRootCauseAnalyzer._classify_target_memory(0x00100000 + 0x100, no_av_dump)
        self.assertEqual(inside_stack.get("category"), "THREAD_STACK")

        # F-18: EventLogCollector._execute_wevtutil_fallback must propagate SecurityViolationError (no raw subprocess bypass)
        with mock.patch.object(os, "name", "nt"):
            with mock.patch("security.safe_subprocess.SafeSubprocessBroker.execute_catalog_command", side_effect=SecurityViolationError("BROKER_DENY")):
                with mock.patch("subprocess.run") as raw_run:
                    with self.assertRaises(SecurityViolationError):
                        EventLogCollector._execute_wevtutil_fallback("Application", "*", 5)
                    raw_run.assert_not_called()

        # F-3: Non-NT ETW capture discloses synthetic simulation honestly
        with mock.patch.object(os, "name", "posix"):
            sess = EtwLiveCaptureSession(session_name="TestEtwHonesty")
            res = sess.start_session()
            self.assertTrue(res["is_simulated"])
            self.assertFalse(res["etw_native_consumer_active"])
            self.assertEqual(res["source"], "synthetic")

        # F-10: AuditLogger multi-process continuity via ensure_chain_continuity
        with tempfile.TemporaryDirectory() as log_dir:
            log_path = os.path.join(log_dir, "multi_proc_audit.jsonl")
            AuditLogger.clear()
            AuditLogger.set_log_file(log_path)
            AuditLogger.log_decision("cli", "op1", "tgt1", "ALLOW", "first")
            AuditLogger.clear()
            AuditLogger.set_log_file(log_path)
            rec = AuditLogger.ensure_chain_continuity(log_path)
            self.assertTrue(rec["recovered"])
            self.assertEqual(rec["records_count"], 1)
            AuditLogger.log_decision("cli", "op2", "tgt2", "ALLOW", "second")
            v = AuditLogger.verify_audit_chain(log_path)
            self.assertTrue(v["is_valid"])
            self.assertEqual(v["records_verified"], 2)
            AuditLogger.clear()

        # F-17: resolve_bridge_marker ignores untrusted CWD marker outside workspace
        with tempfile.TemporaryDirectory() as rogue_cwd, tempfile.TemporaryDirectory() as real_ws:
            cwd_marker = os.path.join(rogue_cwd, ".bintra_bridge.json")
            with open(cwd_marker, "w", encoding="utf-8") as f:
                json.dump({"port": 59999, "auth_token": "rogue"}, f)
            tmp_marker = os.path.join(tempfile.gettempdir(), ".bintra_bridge.json")
            if not os.path.exists(tmp_marker):
                with ExecutionGuard.scoped_session(workspace_dir=real_ws):
                    with mock.patch("os.getcwd", return_value=rogue_cwd):
                        resolved = glb.resolve_bridge_marker()
                self.assertNotEqual((resolved or {}).get("port"), 59999)

        # F-20 / F-16 / F-14: CLI --version, guarded ghidra-analyze --output, non-NT md formatters
        ver_proc = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "--version"],
            capture_output=True, text=True
        )
        self.assertEqual(ver_proc.returncode, 0)
        self.assertIn("1.0.0", ver_proc.stdout)

        # ghidra-analyze --output outside workspace is rejected fail-closed
        with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as foreign_dir:
            pcode_in = os.path.join(in_dir, "export.json")
            foreign_out = os.path.join(foreign_dir, "escaped_plan.json")
            with open(pcode_in, "w", encoding="utf-8") as f:
                json.dump({"program": "test.exe", "functions": []}, f)
            with ExecutionGuard.scoped_session(target_binary_path=pcode_in, workspace_dir=ws_dir):
                with mock.patch.object(sys, "argv", ["cli.py", "ghidra-analyze", "--input", pcode_in, "--output", foreign_out]):
                    with self.assertRaises(OutOfScopeError):
                        cli_mod._dispatch_cli()
            self.assertFalse(os.path.exists(foreign_out))

        # Non-NT --format md outputs for win-audit, hw-audit, driver-audit, service-audit must not raise KeyError
        for subcmd in ("win-audit", "hw-audit", "driver-audit", "service-audit"):
            with mock.patch.object(sys, "platform", "linux"), mock.patch.object(os, "name", "posix"):
                with mock.patch.object(sys, "argv", ["cli.py", subcmd, "--format", "md"]):
                    cli_mod._dispatch_cli()

        # F-14: binary_neural_engine.py standalone CLI defaults --enforce-nociception to True
        bne_help = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "binary_neural_engine.py"), "patch", "-h"],
            capture_output=True, text=True
        )
        self.assertEqual(bne_help.returncode, 0)
        bne_norm = " ".join(bne_help.stdout.split())
        self.assertIn("--force", bne_norm)
        self.assertIn("enabled by default", bne_norm)

        # F-8: update CLI exposes --yes confirmation and --ref flags
        upd_help = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "update", "-h"],
            capture_output=True, text=True
        )
        self.assertEqual(upd_help.returncode, 0)
        self.assertIn("--yes", upd_help.stdout)
        self.assertIn("--ref", upd_help.stdout)

        # F-16: mem-scan --session-file outside workspace is blocked fail-closed
        with tempfile.TemporaryDirectory() as ws_dir, tempfile.TemporaryDirectory() as foreign_dir:
            foreign_sess = os.path.join(foreign_dir, "sess.json")
            with ExecutionGuard.scoped_session(workspace_dir=ws_dir):
                with mock.patch.object(
                    sys, "argv",
                    ["cli.py", "mem-scan", "--pid", str(os.getpid()), "--value", "123456", "--session-file", foreign_sess]
                ):
                    with self.assertRaises(OutOfScopeError):
                        cli_mod._dispatch_cli()
            self.assertFalse(os.path.exists(foreign_sess))

    def test_mcp_all_34_tools_schema_strict_validation_and_memscan_parity(self):
        """Validates strict schema enforcement across all 34 MCP tools and bintra_memory_scan parity."""
        import inspect
        import numpy as np
        import mcp_server as mcp_mod

        self.assertEqual(len(mcp_mod.TOOLS_REGISTRY), 34)
        dispatch_src = inspect.getsource(mcp_mod.BintraMcpServer.dispatch_tool)

        with tempfile.TemporaryDirectory() as td:
            ws_dir = os.path.join(td, "ws")
            target_dir = os.path.join(td, "targets")
            os.makedirs(ws_dir, exist_ok=True)
            os.makedirs(target_dir, exist_ok=True)

            dummy_pe = os.path.join(target_dir, "target.exe")
            with open(dummy_pe, "wb") as f:
                f.write(_build_minimal_pe64())

            dummy_st = os.path.join(target_dir, "weights.safetensors")
            _save_safetensors(dummy_st, "w", np.eye(4, dtype=np.float32))

            dummy_dmp = os.path.join(target_dir, "crash.dmp")
            with open(dummy_dmp, "wb") as f:
                f.write(b"MDMP" + b"\x00" * 64)

            server = mcp_mod.BintraMcpServer(workspace_root=ws_dir)

            def _base_args_for(tool_name, schema):
                props = schema.get("properties", {})
                args = {}
                for req in schema.get("required", []):
                    spec = props.get(req, {})
                    if req in ("file_path", "binary_path", "input_file"):
                        args[req] = dummy_pe
                    elif req in ("model_path", "source_path"):
                        args[req] = dummy_st
                    elif req == "dmp_path":
                        args[req] = dummy_dmp
                    elif req == "output_path":
                        ext = "safetensors" if tool_name == "bintra_patch_weights" else "exe"
                        args[req] = os.path.join(ws_dir, f"out_{tool_name}.{ext}")
                    elif req == "offset":
                        args[req] = "0x10"
                    elif req == "patch_hex":
                        args[req] = "90"
                    elif req == "tensor_name":
                        args[req] = "w"
                    elif req in ("func1_hex", "func2_hex"):
                        args[req] = "90c3"
                    elif req in ("func1_pcode", "func2_pcode", "pcode_ops"):
                        args[req] = [{"mnemonic": "INT_ADD"}]
                    elif req == "command_id":
                        args[req] = "os_ver"
                    elif req == "pid":
                        args[req] = os.getpid()
                    elif req in ("address", "target_address"):
                        args[req] = "0x1000"
                    elif req == "action" and spec.get("enum"):
                        args[req] = spec["enum"][0]
                    elif spec.get("type") == "integer":
                        args[req] = 1
                    elif spec.get("type") == "boolean":
                        args[req] = False
                    elif spec.get("type") == "array":
                        args[req] = []
                    elif spec.get("type") == "object":
                        args[req] = {}
                    else:
                        args[req] = "val"
                # Populate target path needed by ExecutionGuard before _validate_tool_arguments
                if tool_name == "bintra_patch_binary":
                    args.setdefault("file_path", dummy_pe)
                elif tool_name == "bintra_patch_weights":
                    args.setdefault("source_path", dummy_st)
                elif tool_name == "bintra_win_catalog_cmd":
                    args["command_id"] = "os_ver"
                return args

            for tool in mcp_mod.TOOLS_REGISTRY:
                tname = tool["name"]
                schema = tool["inputSchema"]
                props = schema.get("properties", {})
                base = _base_args_for(tname, schema)

                # 1. Unknown parameter rejection
                res_unknown = server.handle_tools_call({
                    "name": tname,
                    "arguments": {**base, "__unknown_param__": 1}
                })
                self.assertTrue(res_unknown["isError"], f"{tname} should reject unknown param")
                err_unknown = json.loads(res_unknown["content"][0]["text"])["error"]
                self.assertIn("Unknown parameter", err_unknown, f"{tname}: {err_unknown}")

                # 2. Type & enum rejection across declared constrained fields
                for prop_name, spec in props.items():
                    ptype = spec.get("type")
                    if ptype == "integer":
                        bad_val = "bad_int"
                    elif ptype == "boolean":
                        bad_val = "yes"
                    elif ptype == "array":
                        bad_val = "not_a_list"
                    elif isinstance(spec.get("enum"), list):
                        bad_val = "__INVALID_ENUM__"
                    elif isinstance(ptype, list) and "integer" in ptype and "string" in ptype:
                        bad_val = True
                    else:
                        continue
                    bad_args = {**base, prop_name: bad_val}
                    res_bad = server.handle_tools_call({"name": tname, "arguments": bad_args})
                    self.assertTrue(res_bad["isError"], f"{tname}.{prop_name} should reject {bad_val!r}")
                    err_bad = json.loads(res_bad["content"][0]["text"])["error"]
                    self.assertTrue(
                        "Invalid type" in err_bad or "Invalid value" in err_bad,
                        f"{tname}.{prop_name} unexpected error: {err_bad}"
                    )

            # 3. Verify bintra_memory_scan schema-dispatch parity and optional parameter acceptance
            mem_schema = next(t["inputSchema"] for t in mcp_mod.TOOLS_REGISTRY if t["name"] == "bintra_memory_scan")
            for prop in mem_schema["properties"]:
                self.assertIn(prop, dispatch_src, f"bintra_memory_scan property '{prop}' missing from dispatch_tool")

            # Valid optional params pass _validate_tool_arguments without error
            server._validate_tool_arguments("bintra_memory_scan", {
                "pid": os.getpid(),
                "session_id": "scan_alpha",
                "value_type": "int32",
                "scan_mode": "changed",
                "target_value": 100,
                "candidate_addresses": [0x1000, 0x2000],
                "alignment": 4,
                "writable_only": True,
                "max_results": 10,
            })

            res_bad_items = server.handle_tools_call({
                "name": "bintra_memory_scan",
                "arguments": {"pid": os.getpid(), "candidate_addresses": ["bad_addr"]}
            })
            self.assertTrue(res_bad_items["isError"])
            self.assertIn("Invalid item type", json.loads(res_bad_items["content"][0]["text"])["error"])

            for bad_field, bad_val in [("value_type", "int128"), ("scan_mode", "fuzzy")]:
                res_mem_bad = server.handle_tools_call({
                    "name": "bintra_memory_scan",
                    "arguments": {"pid": os.getpid(), bad_field: bad_val}
                })
                self.assertTrue(res_mem_bad["isError"])
                self.assertIn("Invalid value", json.loads(res_mem_bad["content"][0]["text"])["error"])

    def test_cli_audit_init_fail_closed_and_degraded_signaling(self):
        """Mutating CLI commands fail-closed when audit dir cannot initialize; reads surface audit_degraded."""
        cli_path = os.path.join(SRC_DIR, "cli.py")
        with tempfile.TemporaryDirectory() as td:
            home_dir = os.path.join(td, "blocked_home")
            ws_dir = os.path.join(td, "ws")
            target_dir = os.path.join(td, "targets")
            os.makedirs(os.path.join(home_dir, ".bintra"), exist_ok=True)
            os.makedirs(ws_dir, exist_ok=True)
            os.makedirs(target_dir, exist_ok=True)

            # Regular file at ~/.bintra/logs blocks directory/log creation portably on Windows & POSIX
            with open(os.path.join(home_dir, ".bintra", "logs"), "w", encoding="utf-8") as f:
                f.write("unwritable_log_blocker")

            dummy_pe = os.path.join(target_dir, "sample.exe")
            with open(dummy_pe, "wb") as f:
                f.write(_build_minimal_pe64())

            env = os.environ.copy()
            env["HOME"] = home_dir
            env["USERPROFILE"] = home_dir

            out_bin = os.path.join(ws_dir, "patched.exe")
            mut_proc = subprocess.run(
                [
                    sys.executable, cli_path, "patch-binary",
                    "--file", dummy_pe, "--output", out_bin,
                    "--offset", "0x10", "--patch-hex", "90",
                    "--workspace", ws_dir,
                ],
                env=env, capture_output=True, text=True
            )
            self.assertNotEqual(mut_proc.returncode, 0, mut_proc.stdout + mut_proc.stderr)
            mut_payload = json.loads(mut_proc.stdout)
            self.assertTrue(mut_payload.get("audit_degraded"), mut_payload)
            self.assertIn("AUDIT_INIT_FAILED", mut_payload.get("error", ""))
            self.assertFalse(os.path.exists(out_bin))

            read_proc = subprocess.run(
                [
                    sys.executable, cli_path, "resolve-deps",
                    "--binary", dummy_pe, "--workspace", ws_dir,
                ],
                env=env, capture_output=True, text=True
            )
            self.assertEqual(read_proc.returncode, 0, read_proc.stdout + read_proc.stderr)
            read_payload = json.loads(read_proc.stdout)
            self.assertTrue(read_payload.get("audit_degraded"), read_payload)
            self.assertTrue(read_payload.get("audit_degraded_reason"), read_payload)

    def test_docs_and_skills_consistency_guards(self):
        """Enforces consistency between code counts, ETW categories, docs, and agent skills."""
        import mcp_server as mcp_mod

        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.assertEqual(len(mcp_mod.TOOLS_REGISTRY), 34)

        discovered_count = unittest.defaultTestLoader.discover(
            os.path.join(repo_root, "tests"), pattern="test_*.py"
        ).countTestCases()
        self.assertEqual(discovered_count, 209)

        doc_paths = [
            "README.md",
            "AGENTS.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
            "docs/RUNTIME_TELEMETRY_AND_CRASH_ANALYSIS.md",
            "docs/ROADMAP.md",
            "docs/architecture.md",
            "docs/releases/v1.0.0.md",
            "pyproject.toml",
        ]
        skills_dir = os.path.join(repo_root, "skills")
        for root, _, files in os.walk(skills_dir):
            for fname in sorted(files):
                if fname.endswith(".md"):
                    doc_paths.append(os.path.relpath(os.path.join(root, fname), repo_root))

        texts = {}
        for rel in doc_paths:
            with open(os.path.join(repo_root, rel), "r", encoding="utf-8") as f:
                texts[rel.replace("\\", "/")] = f.read()

        # 1. Zero foreign branding, fork/upstream lineage claims, or commercial game/anti-cheat mentions
        forbidden_tokens = [
            "diagnose --crash ",
            "original_file_intact",
            "output_location",
            "is_dep_violation",
            "dormant_backdoors_detected",
            "frobenius_norm_delta",
            "subspace_steer",
            "file:///D:/",
            "anti-cheat",
            "game.exe",
            '"is_loop_cured"',
        ]
        forbidden_lower_tokens = [
            "morluto",
            "forked from rea",
            "fork of rea",
            "upstream foundation",
            "traditional rea",
            "classicalrea",
            "الشوكة الدلالية",
            "في الشوكة",
            "rea-neural",
            "reverse-engineer-anything",
            "reamcpserver",
            "rea_inspect_binary",
            "7.4.0",
        ]
        for rel, body in texts.items():
            lower_body = body.lower()
            for ltok in forbidden_lower_tokens:
                self.assertNotIn(ltok, lower_body, f"Found lineage/attribution drift '{ltok}' in {rel}")
            for tok in forbidden_tokens:
                if tok == "anti-cheat" and rel == ".github/PULL_REQUEST_TEMPLATE.md":
                    continue
                self.assertNotIn(tok, body, f"Found stale/forbidden token '{tok}' in {rel}")

        # 2. 34 MCP tool count synchronized everywhere
        for rel in (
            "AGENTS.md",
            "README.md",
            "skills/bintra/SKILL.md",
            "docs/RUNTIME_TELEMETRY_AND_CRASH_ANALYSIS.md",
        ):
            self.assertIn("34", texts[rel], f"Expected '34' tool count in {rel}")
            self.assertNotIn("31 أداة", texts[rel])
            self.assertNotIn("31 MCP", texts[rel])

        # 3. 195 test count synchronized across primary docs & PR template
        for rel in (
            "README.md",
            "docs/RUNTIME_TELEMETRY_AND_CRASH_ANALYSIS.md",
            "docs/ROADMAP.md",
            "docs/releases/v1.0.0.md",
            ".github/PULL_REQUEST_TEMPLATE.md",
        ):
            self.assertIn("195", texts[rel], f"Expected '195' test count in {rel}")
            self.assertNotIn("160 Tests", texts[rel])

        # 4. EtwTimelineCorrelator canonical event categories exist in source
        etw_src_path = os.path.join(
            repo_root, "src", "windows_intelligence", "runtime_telemetry", "etw_capture_engine.py"
        )
        with open(etw_src_path, "r", encoding="utf-8") as f:
            etw_src = f.read()
        for cat in (
            "IMAGE_LOAD",
            "VIRTUAL_FREE",
            "APPLICATION_ERROR",
            "WER_REPORT",
            "APPLICATION_HANG",
            "KERNEL_POWER_OR_BUGCHECK",
            "RESTART_MANAGER_LOCK",
            "GRAPHICS_TDR_DEVICE_REMOVAL",
        ):
            self.assertIn(cat, etw_src, f"Missing ETW event category '{cat}' in etw_capture_engine.py")


if __name__ == "__main__":
    unittest.main()
