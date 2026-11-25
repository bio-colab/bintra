"""
Regression tests for defects found by the real-world Windows test campaign
(benchmarks/real_world_windows). Each test is hermetic (synthetic inputs), so it
runs on any OS, but reproduces the exact failure mode observed on real artifacts.
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

import numpy as np

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from windows_intelligence.runtime_telemetry.crash_rca_engine import CrashRootCauseAnalyzer  # noqa: E402


def _cli(args, cwd=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, os.path.join(SRC_DIR, "cli.py")] + args, capture_output=True,
                          text=True, encoding="utf-8", errors="replace", env=env, cwd=cwd, timeout=180)


class TestCrashRcaNeverFabricatesBlame(unittest.TestCase):
    """Real dumps: the engine disassembled the wrong module and blamed a NULL register
    whose value could not produce the faulting address."""

    def test_operand_mismatch_is_not_reported_as_null_dereference(self):
        disasm = {"available": True, "code_source": "ON_DISK_IMAGE", "image_identity": "UNVERIFIABLE",
                  "offending_instruction": {"mnemonic": "add", "op_str": "byte ptr [rdx], ah"}}
        regs = {"arch": "x64", "rdx": "0x0", "rax": "0x1f58085b690"}
        blame = CrashRootCauseAnalyzer._attribute_culprit_register(
            disasm, regs, target_vaddr=0x1F58085B698, access_type="WRITE",
            spatial_verdict={"category": "UNMAPPED_DYNAMIC_MEMORY"})
        self.assertEqual(blame["root_cause"], "OPERAND_CONTEXT_MISMATCH")
        self.assertNotIn("NULL", blame["root_cause"])

    def test_exact_operand_math_with_index_and_scale(self):
        disasm = {"available": True, "code_source": "DUMP_MEMORY",
                  "offending_instruction": {"mnemonic": "mov", "op_str": "eax, dword ptr [rdi + rsi*4 + 0x10]"}}
        regs = {"arch": "x64", "rdi": "0x1000", "rsi": "0x2"}
        blame = CrashRootCauseAnalyzer._attribute_culprit_register(
            disasm, regs, target_vaddr=0x1000 + 2 * 4 + 0x10, access_type="READ",
            spatial_verdict={"category": "UNMAPPED_DYNAMIC_MEMORY"})
        # Base register is RDI (not the index RSI, which a substring search used to pick).
        self.assertEqual(blame["culprit_register"], "RDI")
        self.assertEqual(blame["index_register"], "RSI")
        self.assertEqual(blame["confidence"], "CONFIDENT_DETERMINISTIC")

    def test_provided_binary_of_another_module_is_not_disassembled(self):
        tmp = tempfile.mkdtemp()
        try:
            other = os.path.join(tmp, "app.exe")
            with open(other, "wb") as f:
                f.write(b"MZ" + b"\x00" * 1022)
            dump = {"modules": [{"name": "ntdll.dll", "path": os.path.join(tmp, "missing", "ntdll.dll")}]}
            win = CrashRootCauseAnalyzer._disassemble_fault_window(other, "ntdll.dll", 0x649E6, "x64", dump)
            self.assertFalse(win["available"])
            self.assertTrue(any("not the faulting module" in n for n in win.get("notes", [])))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_stale_on_disk_image_is_refused(self):
        tmp = tempfile.mkdtemp()
        try:
            dll = os.path.join(tmp, "mod.dll")
            hdr = bytearray(0x400)
            hdr[0:2] = b"MZ"
            struct.pack_into("<I", hdr, 0x3C, 0x80)
            hdr[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<I", hdr, 0x80 + 8, 0x11111111)        # TimeDateStamp on disk
            struct.pack_into("<I", hdr, 0x80 + 24 + 56, 0x5000)      # SizeOfImage on disk
            struct.pack_into("<I", hdr, 0x80 + 24 + 64, 0xAABBCCDD)  # Non-zero PE CheckSum
            with open(dll, "wb") as f:
                f.write(hdr)
            verdict, _ = CrashRootCauseAnalyzer._verify_module_image(dll, {"timestamp": 0x22222222, "size": 0x5000})
            self.assertEqual(verdict, "MISMATCH")
            verdict, _ = CrashRootCauseAnalyzer._verify_module_image(dll, {"timestamp": 0x11111111, "size": 0x5000})
            self.assertEqual(verdict, "HEADER_MATCH_ONLY")
            verdict, _ = CrashRootCauseAnalyzer._verify_module_image(
                dll, {"timestamp": 0x11111111, "size": 0x5000, "checksum": "0x99999999"}
            )
            self.assertEqual(verdict, "MISMATCH")
            verdict, _ = CrashRootCauseAnalyzer._verify_module_image(
                dll, {"timestamp": 0x11111111, "size": 0x5000, "checksum": "0xAABBCCDD"}
            )
            self.assertEqual(verdict, "VERIFIED")
            # HEADER_MATCH_ONLY must not produce CONFIDENT_DETERMINISTIC blame
            blame = CrashRootCauseAnalyzer._attribute_culprit_register(
                {"available": True, "code_source": "ON_DISK_IMAGE", "image_identity": "HEADER_MATCH_ONLY",
                 "offending_instruction": {"mnemonic": "mov", "op_str": "eax, dword ptr [rcx]"}},
                {"arch": "x64", "rcx": "0x0"}, target_vaddr=0, access_type="READ",
                spatial_verdict={"category": "NULL_PAGE_TRAP"})
            self.assertNotEqual(blame["confidence"], "CONFIDENT_DETERMINISTIC")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_code_bytes_are_read_from_dump_memory(self):
        tmp = tempfile.mkdtemp()
        try:
            dmp = os.path.join(tmp, "x.dmp")
            code = bytes.fromhex("83600800") + b"\x90" * 60   # and dword ptr [rax+8], 0
            with open(dmp, "wb") as f:
                f.write(b"\x00" * 0x100 + code)
            parsed = {"file_path": dmp, "modules": [],
                      "memory_ranges": [{"start_va": 0x7FF000, "end_va": 0x7FF000 + len(code), "file_rva": 0x100}]}
            win = CrashRootCauseAnalyzer._disassemble_fault_window(None, "m.dll", 0xA354F, "x64", parsed, fault_va=0x7FF000)
            self.assertTrue(win["available"])
            self.assertEqual(win["code_source"], "DUMP_MEMORY")
            self.assertEqual(win["offending_instruction"]["mnemonic"], "and")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_null_function_pointer_call_reports_caller(self):
        tmp = tempfile.mkdtemp()
        try:
            dmp = os.path.join(tmp, "g.dmp")
            with open(dmp, "wb") as f:
                f.write(b"\x00" * 0x40 + struct.pack("<I", 0x469EF7))
            dump = {
                "status": "success", "file_path": dmp,
                "exception_info": {
                    "exception_code": "0xc0000005", "fault_module": "UNKNOWN_MODULE", "fault_offset": "0x0",
                    "exception_address": "0x0", "is_unloaded_or_unmapped": True,
                    "access_violation_details": {"access_type": "EXECUTE (DEP / NX Violation)", "target_virtual_address": "0x0"},
                    "thread_registers": {"arch": "x86", "esp": "0x19f000", "eip": "0x0"},
                },
                "modules": [{"name": "game.exe", "base_address": "0x400000", "size": 0x200000}],
                "memory_ranges": [{"start_va": 0x19F000, "end_va": 0x19F004, "file_rva": 0x40}],
            }
            rca = CrashRootCauseAnalyzer.analyze_crash(dump)
            self.assertEqual(rca["root_cause_classification"], "NULL_FUNCTION_POINTER_CALL")
            caller = rca["blame_details"]["probable_caller"]
            self.assertEqual(caller["module"], "game.exe")
            self.assertEqual(caller["module_rva"], "0x69EF7")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_non_access_violation_codes_are_classified(self):
        for code, expected in (("0xc000027b", "WINRT_STOWED_EXCEPTION"), ("0x40000015", "FATAL_APP_EXIT_ABORT"),
                               ("0xc0000409", "STACK_BUFFER_OVERRUN_OR_FAST_FAIL")):
            rca = CrashRootCauseAnalyzer.analyze_crash({
                "status": "success", "modules": [],
                "exception_info": {"exception_code": code, "parameters": ["0x2"]},
            })
            self.assertEqual(rca["root_cause_classification"], expected)
        rca = CrashRootCauseAnalyzer.analyze_crash({"status": "success", "modules": [],
                                                    "exception_info": {"exception_code": "0xc0000409", "parameters": ["0x2"]}})
        self.assertEqual(rca["blame_details"]["fast_fail_name"], "FAST_FAIL_STACK_COOKIE_CHECK_FAILURE")


class TestCliExitCodeContract(unittest.TestCase):
    def test_missing_file_exits_nonzero_for_every_static_command(self):
        tmp = tempfile.mkdtemp()
        try:
            missing = os.path.join(tmp, "nope.exe")
            for args in (["inspect", "--file", missing], ["slack-audit", "-f", missing], ["sense", "--file", missing]):
                proc = _cli(args)
                self.assertNotEqual(proc.returncode, 0, f"{args[0]} exited 0 for a missing file")
                json.loads(proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_sense_refuses_to_fabricate_report_for_missing_file(self):
        from binary_neural_engine import SensoryCortex
        with self.assertRaises(FileNotFoundError):
            SensoryCortex.evaluate_all_senses(file_path=os.path.join(tempfile.gettempdir(), "definitely_missing_bintra.exe"))


class TestCliWorkspaceFromExplicitOutput(unittest.TestCase):
    def test_documented_patch_into_workspace_dir_works_and_target_dir_is_refused(self):
        tmp = tempfile.mkdtemp()
        try:
            tgt_dir = os.path.join(tmp, "target")
            ws_dir = os.path.join(tmp, "workspace")
            os.makedirs(tgt_dir)
            os.makedirs(ws_dir)
            src = os.path.join(tgt_dir, "app.bin")
            with open(src, "wb") as f:
                f.write(b"\x90" * 4096)
            ok = _cli(["patch-binary", "--file", src, "--output", os.path.join(ws_dir, "app_patched.bin"),
                       "--offset", "0x100", "--patch-hex", "90 90"], cwd=tmp)
            self.assertEqual(ok.returncode, 0, ok.stdout[-600:])
            self.assertTrue(os.path.exists(os.path.join(ws_dir, "app_patched.bin")))
            bad = _cli(["patch-binary", "--file", src, "--output", os.path.join(tgt_dir, "sub", "x.bin"),
                        "--offset", "0x100", "--patch-hex", "90"], cwd=tmp)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("TARGET_DIRECTORY_WRITE_FORBIDDEN", bad.stdout)
            self.assertFalse(os.path.exists(os.path.join(tgt_dir, "sub", "x.bin")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestMemScanSessionPersistence(unittest.TestCase):
    def test_export_import_roundtrip(self):
        from windows_intelligence.runtime_telemetry.virtual_memory_inspector import ProcessMemoryScanner
        sid = "deadbeefcafef00d"
        with ProcessMemoryScanner._SESSION_LOCK:
            ProcessMemoryScanner._ACTIVE_SESSIONS[sid] = {
                "session_id": sid, "pid": 1234, "process_start_time": 99, "data_type": "int32", "alignment": 4,
                "candidates": [{"address": "0x10", "address_int": 16, "value": 7, "category": "HEAP"}],
                "created_at": 1.0, "last_accessed": 1.0,
            }
        state = ProcessMemoryScanner.export_session(sid)
        self.assertEqual(state["format"], ProcessMemoryScanner.SESSION_STATE_FORMAT)
        with ProcessMemoryScanner._SESSION_LOCK:
            ProcessMemoryScanner._ACTIVE_SESSIONS.pop(sid)
        restored = ProcessMemoryScanner.import_session(json.loads(json.dumps(state)))
        self.assertEqual(restored, sid)
        self.assertEqual(ProcessMemoryScanner._ACTIVE_SESSIONS[sid]["candidates"][0]["address_int"], 16)
        with self.assertRaises(ValueError):
            ProcessMemoryScanner.import_session({"format": "other"})


class TestWeightAuditColumnAxis(unittest.TestCase):
    def test_planted_column_neuron_is_detected_without_false_positive_on_clean(self):
        from bintra_engine import WeightSecurityAuditor
        rng = np.random.default_rng(7)
        clean = rng.normal(0, 0.02, size=(256, 128)).astype(np.float32)
        self.assertFalse(WeightSecurityAuditor.audit_weights_without_evaluation(clean)["potential_backdoor_detected"])
        planted = clean.copy()
        planted[:, 42] += 0.9
        res = WeightSecurityAuditor.audit_weights_without_evaluation(planted)
        self.assertTrue(res["potential_backdoor_detected"])
        self.assertIn(42, res["suspect_input_channel_neurons"])
        self.assertIn("columns", res["suspect_axes"])


class TestSlackInspectorTruncatedHeaders(unittest.TestCase):
    def _pe_header(self):
        b = bytearray(0x200)
        b[0:2] = b"MZ"
        struct.pack_into("<I", b, 0x3C, 0x80)
        b[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", b, 0x84, 0x8664, 7)       # 7 sections declared
        struct.pack_into("<H", b, 0x80 + 20, 0xF0)        # SizeOfOptionalHeader (PE32+)
        struct.pack_into("<H", b, 0x80 + 24, 0x20B)
        return b

    def test_truncated_section_table_is_reported_not_clean(self):
        from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector
        tmp = tempfile.mkdtemp()
        try:
            for cut in (0x80 + 24 + 100, 0x80 + 24 + 0xF0 + 20):   # inside data dirs / inside section table
                p = os.path.join(tmp, f"t{cut}.bin")
                with open(p, "wb") as f:
                    f.write(bytes(self._pe_header()[:cut]))
                res = BinarySlackInspector.inspect_pe_file(p)
                self.assertTrue(res.get("is_truncated"), res)
                self.assertNotEqual(res.get("slack_type"), "CLEAN_EXACT_EOF")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestAuditSegmentSealing(unittest.TestCase):
    def test_sealed_segment_keeps_one_continuous_chain(self):
        from security.audit_logger import AuditLogger
        tmp = tempfile.mkdtemp()
        prev = (AuditLogger._log_file, AuditLogger._log_dir, AuditLogger._segment_max_bytes)
        try:
            log = os.path.join(tmp, "audit.jsonl")
            AuditLogger.clear()
            AuditLogger.set_log_file(log)
            AuditLogger._segment_max_bytes = 2048
            for i in range(12):
                AuditLogger.log_decision("t", "op", f"target{i}", "ALLOW", "r")
            AuditLogger._journal.clear()
            AuditLogger._sequence = 0
            res = AuditLogger.ensure_chain_continuity()
            self.assertIn("sealed_segment", res)
            sealed_path = res["sealed_segment"]
            self.assertEqual(os.path.getsize(log) if os.path.exists(log) else 0, 0)
            # Chain verification right after sealing must still verify all 12 sealed records
            v_post_seal = AuditLogger.verify_audit_chain(log)
            self.assertTrue(v_post_seal["is_valid"], v_post_seal)
            self.assertEqual(v_post_seal["records_verified"], 12)

            AuditLogger.log_decision("t", "op", "after-seal", "ALLOW", "r")
            with open(log, encoding="utf-8") as f:
                first_new = json.loads(f.readline())
            self.assertEqual(first_new["sequence"], 12)
            v_after_append = AuditLogger.verify_audit_chain(log)
            self.assertTrue(v_after_append["is_valid"], v_after_append)
            self.assertEqual(v_after_append["records_verified"], 13)

            # Fresh process view: the active segment verifies against the sealed anchor.
            AuditLogger._journal.clear()
            AuditLogger._sequence = 0
            rec = AuditLogger.recover_chain_from_disk(log)
            self.assertEqual(rec["sealed_anchor_sequence"], 11)
            self.assertEqual(rec["records_count"], 1)

            # Tampering with a MIDDLE record inside the sealed segment must fail recovery and verify_audit_chain.
            with open(sealed_path, "r", encoding="utf-8") as f:
                sealed_orig = f.read()
            try:
                with open(sealed_path, "w", encoding="utf-8") as f:
                    f.write(sealed_orig.replace("target3", "forged3"))
                v_sealed_tamper = AuditLogger.verify_audit_chain(log)
                self.assertFalse(v_sealed_tamper["is_valid"])
                AuditLogger._journal.clear()
                AuditLogger._sequence = 0
                with self.assertRaises(Exception):
                    AuditLogger.recover_chain_from_disk(log)
            finally:
                with open(sealed_path, "w", encoding="utf-8") as f:
                    f.write(sealed_orig)

            # Tampering with the active segment is still detected.
            with open(log, "r+", encoding="utf-8") as f:
                data = f.read().replace("after-seal", "forged-target")
                f.seek(0)
                f.write(data)
                f.truncate()
            v_active_tamper = AuditLogger.verify_audit_chain(log)
            self.assertFalse(v_active_tamper["is_valid"])
            with self.assertRaises(Exception):
                AuditLogger.recover_chain_from_disk(log)

            # Deleting an older sealed segment (leaving non-zero start sequence) must be rejected.
            os.remove(sealed_path)
            v_missing_seg = AuditLogger.verify_audit_chain(log)
            self.assertFalse(v_missing_seg["is_valid"])
            with self.assertRaises(Exception):
                AuditLogger.recover_chain_from_disk(log)
        finally:
            AuditLogger.clear()
            AuditLogger._log_file, AuditLogger._log_dir, AuditLogger._segment_max_bytes = prev
            shutil.rmtree(tmp, ignore_errors=True)


class TestPeParserFastPathsAreEquivalent(unittest.TestCase):
    def test_cstring_reader_semantics(self):
        import io
        from binary_neural_engine import BinaryFormatInspector
        buf = io.BytesIO(b"kernel32.dll\x00junk" + b"A" * 300)
        self.assertEqual(bytes(BinaryFormatInspector._read_cstring_at_cursor(buf, len(buf.getvalue()))), b"kernel32.dll")
        buf.seek(17)
        self.assertEqual(len(BinaryFormatInspector._read_cstring_at_cursor(buf, len(buf.getvalue()))), 256)
        buf.seek(len(buf.getvalue()))
        self.assertEqual(bytes(BinaryFormatInspector._read_cstring_at_cursor(buf, len(buf.getvalue()))), b"")


if __name__ == "__main__":
    unittest.main()
