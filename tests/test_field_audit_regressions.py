#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for generic Bintra defects uncovered during real-world Win32 field auditing."""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _build_minimal_pe32(sections_spec=None, include_delay_import=False):
    """Builds a minimal valid PE32 binary with optional extra sections or delay-load descriptor."""
    buf = bytearray(0x800)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    sec_list = sections_spec or [(".text", 0x1000, 0x200, 0x400, 0x200, 0x60000020)]
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x014C, len(sec_list), 0, 0, 0, 0xE0, 0x0102)
    # PE32 optional header
    opt = 0x98
    struct.pack_into("<H", buf, opt, 0x10B)
    struct.pack_into("<IIIIIII", buf, opt + 16, 0x1000, 0x1000, 0x2000, 0x00400000, 0x1000, 0x200, 0)
    struct.pack_into("<HHHH", buf, opt + 40, 4, 0, 0, 0)
    struct.pack_into("<IIIIII", buf, opt + 56, 0x4000, 0x400, 0, 2, 0x0140, 0)
    struct.pack_into("<I", buf, opt + 92, 16)
    if include_delay_import:
        # DataDirectory[13] = DelayImportDescriptor at RVA 0x2000 (file off 0x600)
        dd_off = opt + 96 + 13 * 8
        struct.pack_into("<II", buf, dd_off, 0x2000, 32)
    sec_off = opt + 0xE0
    for idx, (nm, va, vsz, roff, rsz, chars) in enumerate(sec_list):
        base = sec_off + idx * 40
        buf[base:base + 8] = nm.encode("ascii")[:8].ljust(8, b"\x00")
        struct.pack_into("<IIIIIIHHI", buf, base + 8, vsz, va, rsz, roff, 0, 0, 0, 0, chars)
    return bytes(buf)


class TestFieldAuditRegressions(unittest.TestCase):
    def test_cli_ghidra_headless_argparse_accepts_flags_without_dummy_command(self):
        """`bintra ghidra-headless --binary ...` must not fail requiring a phantom positional `command` arg."""
        from cli import main as cli_main
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf_path = tf.name
            tf.write(_build_minimal_pe32())
        try:
            mock_res = {
                "command": ["analyzeHeadless"],
                "headless_binary": "analyzeHeadless.bat",
                "exit_code": 0,
                "raw_returncode": 0,
                "is_timeout": False,
                "timeout_seconds": 60,
                "script_error_detected": False,
                "is_error": False,
                "project_name": "tmp_proj",
                "project_dir": tempfile.gettempdir(),
                "project_cleaned": True,
                "stdout": "OK\n",
                "stderr": "",
                "epistemic_classification": "GHIDRA_HEADLESS_BATCH_EXECUTION",
                "analyzed_functions_count": 0,
                "opaque_predicates_detected": 0,
                "cff_backbones_detected": 0,
            }
            with mock.patch("ghidra_headless_runner.GhidraHeadlessRunner.run", return_value=mock_res) as m_run:
                with mock.patch("sys.argv", ["bintra", "ghidra-headless", "--binary", tf_path]):
                    with self.assertRaises(SystemExit) as cm:
                        cli_main()
            self.assertEqual(cm.exception.code, 0)
            m_run.assert_called_once()
            self.assertEqual(m_run.call_args.kwargs["binary_path"], tf_path)
        finally:
            if os.path.exists(tf_path):
                os.unlink(tf_path)

    def test_ghidra_headless_runner_detects_jdk_error_and_closes_stdin(self):
        """Headless runner must pass stdin=DEVNULL and flag missing JDK 21+ as script_error_detected."""
        from ghidra_headless_runner import GhidraHeadlessRunner

        with tempfile.TemporaryDirectory() as tmp:
            support_dir = Path(tmp) / "support"
            support_dir.mkdir(parents=True, exist_ok=True)
            (support_dir / "analyzeHeadless.bat").write_text("@echo off\n", encoding="utf-8")
            (support_dir / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
            fake_exe = Path(tmp) / "dummy.exe"
            fake_exe.write_bytes(_build_minimal_pe32())

            fake_proc = mock.Mock(
                returncode=1,
                stdout="JDK 21+ (64-bit) could not be found.\nERROR: Failed to find a supported JDK\n",
                stderr="",
            )
            with mock.patch("subprocess.run", return_value=fake_proc) as m_sub:
                res = GhidraHeadlessRunner.run(
                    binary_path=str(fake_exe),
                    ghidra_path=str(tmp),
                    project_name="test_jdk_err_proj",
                    delete_project=True,
                )
            self.assertTrue(res["is_error"])
            self.assertTrue(res["script_error_detected"])
            self.assertEqual(m_sub.call_args.kwargs.get("stdin"), __import__("subprocess").DEVNULL)

    def test_cpython_live_memory_forensics_accepts_success_and_partial_status(self):
        """CPythonMemoryForensics.inspect_live_process must work with VirtualMemoryInspector's 'success'/'partial' statuses."""
        from windows_intelligence.runtime_telemetry.cpython_memory_forensics import CPythonMemoryForensics
        from windows_intelligence.runtime_telemetry.virtual_memory_inspector import (
            VirtualMemoryInspector,
            StructureDissector,
        )

        # Build a valid 64-bit CPython PyDictObject + PyDictKeysObject raw payload
        dict_raw = struct.pack("<qQQQQQ", 2, 0x7FF800001234, 3, 0xCAFE, 0x10002000, 0) + b"\x00" * 16
        keys_raw = struct.pack("<qBBBBIqq", 1, 3, 0, 0, 0, 1, 2, 1) + b"\x00" * 8 + struct.pack("<qQQ", 12345, 0x10003000, 0x10004000)

        def fake_read(pid, address, size, allow_partial=True):
            if address == 0x10001000:
                return {"status": "success", "data": dict_raw, "bytes_read": len(dict_raw)}
            if address == 0x10002000:
                return {"status": "partial", "data": keys_raw, "bytes_read": len(keys_raw)}
            return {"status": "error", "data": None}

        with mock.patch.object(VirtualMemoryInspector, "_read_memory_internal", side_effect=fake_read):
            with mock.patch.object(StructureDissector, "dissect", return_value={"status": "success", "fields": []}):
                res = CPythonMemoryForensics.inspect_live_process(1234, 0x10001000, object_type="pydict")

        self.assertEqual(res["status"], "ok")
        obj = res["cpython_object"]
        self.assertEqual(obj["ma_used"], 3)
        self.assertIn("keys_table", obj)
        self.assertEqual(obj["keys_table"]["dk_nentries"], 1)

    def test_pe_diff_reports_real_entropy_raw_size_export_and_duplicate_section_deltas(self):
        """diff_pe_binaries must use shannon_entropy, raw_size, exports.functions, and disambiguate duplicate sections."""
        from pe_deep_forensics import SemanticBinaryDiffer

        base_pe = {
            "format": "PE",
            "pe_type": "PE32 (32-bit)",
            "sha256": "aaa",
            "sections": [
                {"name": ".text", "virtual_size": 0x100, "raw_size": 0x200, "shannon_entropy": 5.5, "is_executable": True},
                {"name": ".text", "virtual_size": 0x300, "raw_size": 0x400, "shannon_entropy": 6.0, "is_executable": True},
            ],
            "imports": {"modules": {"KERNEL32.dll": ["ExitProcess"]}},
            "exports": {"exported_functions_count": 2, "functions": [{"name": "FnA", "ordinal": 1}, {"name": "FnB", "ordinal": 2}]},
        }
        targ_pe = {
            "format": "PE",
            "pe_type": "PE32 (32-bit)",
            "sha256": "bbb",
            "sections": [
                {"name": ".text", "virtual_size": 0x100, "raw_size": 0x200, "shannon_entropy": 5.5, "is_executable": True},
                {"name": ".text", "virtual_size": 0x350, "raw_size": 0x600, "shannon_entropy": 6.75, "is_executable": True},
            ],
            "imports": {"modules": {"KERNEL32.dll": ["ExitProcess"]}},
            "exports": {"exported_functions_count": 2, "functions": [{"name": "FnA", "ordinal": 1}, {"name": "FnC", "ordinal": 3}]},
        }

        with tempfile.TemporaryDirectory() as tmp:
            p1 = os.path.join(tmp, "a.dll")
            p2 = os.path.join(tmp, "b.dll")
            raw = _build_minimal_pe32()
            Path(p1).write_bytes(raw)
            Path(p2).write_bytes(raw + b"\x90" * 16)

            with mock.patch("binary_neural_engine.BinaryFormatInspector.inspect", side_effect=[base_pe, targ_pe]):
                diff = SemanticBinaryDiffer().diff_pe_binaries(p1, p2)

        deltas = {g["section"]: g for g in diff["sections_diff"]["geometry_deltas"]}
        self.assertIn(".text", deltas)
        self.assertIn(".text#2", deltas)
        self.assertEqual(deltas[".text#2"]["raw_size_delta"], 0x200)
        self.assertEqual(deltas[".text#2"]["entropy_baseline"], 6.0)
        self.assertEqual(deltas[".text#2"]["entropy_target"], 6.75)
        self.assertEqual(diff["exports_diff"]["exports_added"], ["FnC"])
        self.assertEqual(diff["exports_diff"]["exports_removed"], ["FnB"])

    def test_signature_classifies_subject_form_unknown_cleanly(self):
        """0x800B0003 (TRUST_E_SUBJECT_FORM_UNKNOWN) must map to NOT_AUTHENTICODE_FORMAT & unsupported_format metric."""
        from windows_intelligence.signature_intelligence import (
            WindowsSignatureIntelligence,
            TRUST_E_SUBJECT_FORM_UNKNOWN,
        )

        self.assertEqual(
            WindowsSignatureIntelligence._classify_win32_trust_status(TRUST_E_SUBJECT_FORM_UNKNOWN),
            "NOT_AUTHENTICODE_FORMAT",
        )
        with tempfile.TemporaryDirectory() as tmp:
            plugin = Path(tmp) / "script.cleo"
            plugin.write_bytes(b"\x01\x02\x03DATA_PLUGIN")
            fake_rep = {
                "signature_present": False,
                "is_signed": False,
                "is_verified": False,
                "signature_type": "NONE",
                "trust_status": "NOT_AUTHENTICODE_FORMAT",
                "trust_classification": "NOT_AUTHENTICODE_FORMAT",
                "win32_status_code": hex(TRUST_E_SUBJECT_FORM_UNKNOWN),
                "is_microsoft_system_binary": False,
                "is_whql_certified": False,
            }
            with mock.patch("windows_intelligence.signature_intelligence.platform.system", return_value="Windows"):
                with mock.patch.object(WindowsSignatureIntelligence, "_verify_win32_signature", return_value=fake_rep):
                    audit = WindowsSignatureIntelligence.audit_directory(tmp, pattern="*.cleo")
            self.assertEqual(audit["metrics"]["unsupported_format"], 1)
            self.assertEqual(audit["metrics"]["untrusted_or_expired"], 0)
            self.assertIn("NON_AUTHENTICODE_FILE_FORMAT", audit["files"][0]["risk_flags"])

    def test_graph_model_and_orchestrator_populate_entropy_and_fault_address(self):
        """fuse_static_dynamic_ghidra and analysis_orchestrator must populate PE entropy & CRASH_EVENT fault fields."""
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
        from analysis_orchestrator import BinaryTriageOrchestrator

        pe_inspect = {
            "format": "PE",
            "sha256": "deadbeef12345678",
            "file_name": "mod.exe",
            "sections": [
                {"name": ".text", "raw_size": 0x400, "shannon_entropy": 6.4},
                {"name": ".rdata", "raw_size": 0x100, "shannon_entropy": 4.9},
            ],
        }
        crash_rca = {
            "exception_code": "0xC0000005",
            "root_cause_classification": "DETERMINISTIC_NULL_POINTER_DEREFERENCE",
            "confidence": "CONFIDENT_DETERMINISTIC",
            "culprit_register": "EAX",
            "fault_module": "d3d9.dll",
            "fault_rva": "0x5FEDB",
            "fault_virtual_address": "0x69E6FEDB",
            "target_address": "0x000000000000000C",
        }
        fused = fuse_static_dynamic_ghidra(binary_inspection=pe_inspect, crash_rca=crash_rca)
        nodes = {n["type"]: n for n in fused["fused_graph"]["nodes"]}
        self.assertAlmostEqual(nodes["PE_BINARY"]["properties"]["entropy"], 6.1)
        self.assertEqual(nodes["CRASH_EVENT"]["properties"]["fault_address"], "0x000000000000000C")
        self.assertEqual(nodes["CRASH_EVENT"]["properties"]["fault_module"], "d3d9.dll")
        self.assertEqual(nodes["CRASH_EVENT"]["properties"]["fault_rva"], "0x5FEDB")

        summary = BinaryTriageOrchestrator._synthesize_triage_summary(
            can_path="mod.exe",
            pe_inspect=pe_inspect,
            pe_forensics=None,
            sig_intel=None,
            deobf=None,
            crash_rca=None,
            ghidra_cg=None,
        )
        self.assertTrue(any("Observed Shannon entropy: 6.10" in x for x in summary["observed_facts"]))

    def test_crash_rca_remediation_cites_probable_caller_on_null_call(self):
        """NULL_FUNCTION_POINTER_CALL remediation must cite blame_details.probable_caller."""
        from windows_intelligence.runtime_telemetry.crash_rca_engine import CrashRootCauseAnalyzer

        tmp = tempfile.mkdtemp()
        try:
            dmp = os.path.join(tmp, "nullcall.dmp")
            with open(dmp, "wb") as f:
                f.write(b"\x00" * 0x40 + struct.pack("<I", 0x469EF7))
            dump = {
                "status": "success",
                "file_path": dmp,
                "exception_info": {
                    "exception_code": "0xc0000005",
                    "fault_module": "UNKNOWN_MODULE",
                    "fault_offset": "0x0",
                    "exception_address": "0x0",
                    "is_unloaded_or_unmapped": True,
                    "access_violation_details": {
                        "access_type": "EXECUTE (DEP / NX Violation)",
                        "target_virtual_address": "0x0",
                    },
                    "thread_registers": {"arch": "x86", "esp": "0x19f000", "eip": "0x0"},
                },
                "modules": [{"name": "mod.exe", "base_address": "0x400000", "size": 0x200000}],
                "memory_ranges": [{"start_va": 0x19F000, "end_va": 0x19F004, "file_rva": 0x40}],
            }
            rca = CrashRootCauseAnalyzer.analyze_crash(dump)
            self.assertIn("mod.exe+0x69EF7", rca["remediation_advice"])
            self.assertNotIn("UNKNOWN_MODULE+0x0", rca["remediation_advice"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    @unittest.skipUnless(sys.platform == "win32", "Requires Windows host")
    def test_dependency_resolver_audits_delay_imports(self):
        """WindowsDependencyResolver.audit_dependencies must inspect PE delay_imports."""
        from windows_intelligence import WindowsDependencyResolver
        from binary_neural_engine import BinaryFormatInspector

        fake_pe = {
            "format": "PE",
            "pe_type": "PE32 (32-bit)",
            "imports": {"modules": {"KERNEL32.dll": ["ExitProcess"]}},
            "delay_imports": {"modules": {"NON_EXISTENT_DELAY_MOD_777.dll": ["FakeDelayFn"]}},
        }
        orig_inspect = BinaryFormatInspector.inspect
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(_build_minimal_pe32())
            tf_path = tf.name
        try:
            def _selective_inspect(path, *a, **kw):
                if os.path.abspath(path) == os.path.abspath(tf_path):
                    return fake_pe
                return orig_inspect(path, *a, **kw)

            with mock.patch("windows_intelligence.dependency_resolver.BinaryFormatInspector.inspect", side_effect=_selective_inspect):
                with mock.patch.object(WindowsDependencyResolver, "extract_manifest_text", return_value=""):
                    res = WindowsDependencyResolver.audit_dependencies(tf_path)
            self.assertEqual(res["verdict"], "HEALTHY")
            self.assertEqual(res["delay_imported_dlls_count"], 1)
            self.assertEqual(res["delay_dependency_health"], "DELAY_DEPENDENCY_ISSUES_DETECTED")
            self.assertEqual(res["missing_delay_dlls"][0]["imported_name"], "NON_EXISTENT_DELAY_MOD_777.dll")
        finally:
            if os.path.exists(tf_path):
                os.unlink(tf_path)

    def test_mcp_win_catalog_cmd_list_action(self):
        """bintra_win_catalog_cmd with command_id='list' must return the catalog list cleanly."""
        from mcp_server import BintraMcpServer

        srv = BintraMcpServer()
        out = srv.dispatch_tool("bintra_win_catalog_cmd", {"command_id": "list"})
        self.assertEqual(out["status"], "success")
        self.assertGreater(out["commands_count"], 5)
        cmd_ids = {c["command_id"] for c in out["commands"]}
        self.assertIn("os_ver", cmd_ids)

    def test_cff_detector_rejects_normal_crt_comparisons_with_embedded_immediates(self):
        """Standard procedural register checks and rel32 immediate bytes must not falsely trigger CFF."""
        from binary_neural_engine import ContinuousDeobfuscator

        # Benign x86 CRT-like code: cmp ecx, 0/1/-1; call rel32 whose immediate contains B8..BF / 83 F8 bytes;
        # plus isolated pointer loads `mov ecx, 0x100261c0`.
        crt_stub = (
            b"\x55\x8B\xEC"
            b"\xB9\xC0\x61\x02\x10"      # mov ecx, 0x100261c0
            b"\x83\xF9\x00\x74\x05"      # cmp ecx, 0; je +5
            b"\xE8\x83\xF8\x01\xB8"      # call rel32 (embedded 83 F8 01 B8!)
            b"\xB9\xC0\x61\x02\x10"      # mov ecx, 0x100261c0
            b"\x83\xF9\x01\x74\x03"      # cmp ecx, 1; je +3
            b"\x83\xF9\xFF\x74\x02"      # cmp ecx, -1; je +2
            b"\x5D\xC3"
        )
        res = ContinuousDeobfuscator.detect_control_flow_flattening(crt_stub, is_64bit=False)
        self.assertFalse(res["has_control_flow_flattening"])

        # Positive register-based CFF state machine must still be detected cleanly.
        cff_reg = (
            b"\xB8\x11\x11\x00\x00"      # mov eax, 0x1111
            b"\x81\xF8\x11\x11\x00\x00"  # cmp eax, 0x1111
            b"\x81\xF8\x22\x22\x00\x00"  # cmp eax, 0x2222
            b"\x81\xF8\x33\x33\x00\x00"  # cmp eax, 0x3333
            b"\xB8\x22\x22\x00\x00"      # mov eax, 0x2222
            b"\xB8\x33\x33\x00\x00"      # mov eax, 0x3333
        )
        res_pos = ContinuousDeobfuscator.detect_control_flow_flattening(cff_reg, is_64bit=False)
        self.assertTrue(res_pos["has_control_flow_flattening"])

    def test_mcp_ghidra_analyze_closes_sqlite_handle(self):
        """bintra_ghidra_analyze must close SQLite handles so temp/workspace DB files are immediately removable on Windows."""
        from ghidra_export_store import GhidraExportStore
        from mcp_server import BintraMcpServer

        ws = Path(tempfile.mkdtemp(prefix="bintra_db_close_", dir=str(Path.home() / ".bintra" / "workspace")))
        try:
            src_json = ws / "exp.json"
            dst_db = ws / "exp.db"
            src_json.write_text(json.dumps({
                "image_base": "0x400000",
                "functions": [
                    {
                        "name": "SampleFn",
                        "entry_point": "0x401000",
                        "pcode_ops": [{"opcode": "INT_ADD", "inputs": ["R0", "R1"], "output": "T0"}],
                        "callees": ["VirtualAlloc"],
                    }
                ],
            }), encoding="utf-8")
            GhidraExportStore.ingest_to_sqlite(str(src_json), str(dst_db))
            srv = BintraMcpServer()
            prof = srv.dispatch_tool("bintra_ghidra_analyze", {"input_file": str(dst_db), "profile": True})
            self.assertEqual(prof["status"], "ok")
            self.assertEqual(prof["total_functions"], 1)
            # Must succeed immediately without WinError 32 file-in-use lock
            os.remove(dst_db)
            self.assertFalse(dst_db.exists())
        finally:
            shutil.rmtree(ws, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
