# -*- coding: utf-8 -*-
"""
Targeted regression tests covering the direct code audit of:
  1. BinarySlackInspector (XML Expat root parsing, BOM sniffing, COFF zero-size sections, overlay bounds)
  2. EvidenceGraph & evaluate_data_flow_crash_causality (per-sink binding, reg aliases, def-use lineage)
  3. ProcessLongitudinalProfiler (-1 handle sentinel exclusion, short-series leak checks, multi-leak signals)
  4-6-7. AuditLogger (atomic persistence vs memory chain state, forged cache rejection, tail/truncation checks)
  5. MCP 2026-07-28 DiscoverResult, clientInfo _meta, CacheableResult hints, JSON-RPC validation
"""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def _minimal_pe_with_bss_and_overlay(overlay: bytes = b"", add_sec_dir: int = 0) -> bytes:
    """Build valid PE32+ with .text (raw_size=0x200, raw_ptr=0x400) + .bss (raw_size=0, dummy raw_ptr=0x99999)."""
    pe = bytearray(0x600)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    opt = 0x80 + 24
    struct.pack_into("<H", pe, opt, 0x20B)
    struct.pack_into("<I", pe, opt + 108, 16)
    if add_sec_dir > 0:
        data_dirs = opt + 112
        struct.pack_into("<II", pe, data_dirs + 4 * 8, 0x600, add_sec_dir)
    sec0 = opt + 0xF0
    pe[sec0 : sec0 + 5] = b".text"
    struct.pack_into("<IIII", pe, sec0 + 8, 0x200, 0x1000, 0x200, 0x400)
    sec1 = sec0 + 40
    pe[sec1 : sec1 + 4] = b".bss"
    struct.pack_into("<IIII", pe, sec1 + 8, 0x1000, 0x2000, 0, 0x99999)
    return bytes(pe) + overlay


class TestBinarySlackAuditFixes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bintra_slack_audit_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_xml_appended_element_detected_by_expat(self):
        from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector

        bad_xml = os.path.join(self.tmp, "appended.xml")
        with open(bad_xml, "wb") as f:
            f.write(b'<?xml version="1.0"?><root><item/></root><injected>payload</injected>')
        res = BinarySlackInspector.inspect_file(bad_xml)
        self.assertEqual(res["format"], "XML")
        self.assertTrue(res["has_trailing_slack"])
        self.assertEqual(res["slack_type"], "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK")
        self.assertEqual(res["slack_bytes_count"], len(b"<injected>payload</injected>"))

        self_close = os.path.join(self.tmp, "clean_sc.xml")
        with open(self_close, "wb") as f:
            f.write(b"<root/>")
        res_clean = BinarySlackInspector.inspect_file(self_close)
        self.assertEqual(res_clean["format"], "XML")
        self.assertFalse(res_clean["has_trailing_slack"])
        self.assertEqual(res_clean["slack_type"], "CLEAN_EXACT_EOF")

    def test_utf8_bom_json_and_zero_padded_pe_overlay_payload(self):
        from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector

        bom_json = os.path.join(self.tmp, "bom.json")
        with open(bom_json, "wb") as f:
            f.write(b'\xef\xbb\xbf{"ok":true}TRAILING')
        rj = BinarySlackInspector.inspect_file(bom_json)
        self.assertEqual(rj["format"], "JSON")
        self.assertTrue(rj["has_trailing_slack"])
        self.assertEqual(rj["slack_type"], "SUSPICIOUS_UNMAPPED_DOCUMENT_SLACK")

        # 1KB zero padding + non-zero payload after must NOT be hidden as PE_ZERO_PADDING_SLACK
        pe_padded = os.path.join(self.tmp, "bss_and_padded_overlay.exe")
        with open(pe_padded, "wb") as f:
            f.write(_minimal_pe_with_bss_and_overlay(overlay=(b"\x00" * 1500 + b"SECRET_PAYLOAD")))
        rp = BinarySlackInspector.inspect_file(pe_padded)
        self.assertEqual(rp["status"], "ok")
        self.assertFalse(rp["is_truncated"])
        self.assertTrue(rp["has_trailing_slack"])
        self.assertNotEqual(rp["slack_type"], "PE_ZERO_PADDING_SLACK")

    def test_pe_certificate_with_trailing_slack(self):
        from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector

        pe_cert = os.path.join(self.tmp, "cert_extra.exe")
        cert = struct.pack("<IHH", 64, 0x0200, 0x0002) + b"\x11" * 56
        extra = b"APPENDED_POST_CERT_BYTES" * 4
        with open(pe_cert, "wb") as f:
            f.write(_minimal_pe_with_bss_and_overlay(overlay=cert + extra, add_sec_dir=64))
        rc = BinarySlackInspector.inspect_file(pe_cert)
        self.assertEqual(rc["slack_type"], "PE_CERTIFICATE_WITH_TRAILING_SLACK")
        self.assertEqual(rc["post_certificate_slack_bytes"], len(extra))


class TestEvidenceGraphAuditFixes(unittest.TestCase):
    def test_decoupled_multi_sink_and_missing_lineage_not_overclaimed(self):
        from windows_intelligence.evidence_engine.graph_model import evaluate_data_flow_crash_causality

        crash = {
            "fault_module": "mod.exe",
            "fault_rva": "0x1050",
            "fault_virtual_address": "0x140001050",
            "culprit_register": "RAX",
        }
        # Decoy: matching sink uses RDX only; distant unrelated sink uses RAX
        decoy_df = {
            "function": "Parse",
            "entry_point": "0x140001000",
            "sinks": [
                {"address": "0x140001050", "var": "RCX", "inputs": ["RDX"]},
                {"address": "0x140009000", "var": "RAX", "inputs": ["RBP"]},
            ],
            "sources": [{"address": "0x140001010", "var": "RAX"}],
            "backward_slice": [{"address": "0x140001020", "output": "RAX", "inputs": ["RCX"]}],
            "provenance": {"status": "VERIFIED_CRYPTOGRAPHIC_HASH"},
        }
        res_decoy = evaluate_data_flow_crash_causality(decoy_df, crash)
        self.assertNotEqual(res_decoy["level"], "CAUSALLY_VALIDATED")
        self.assertLess(res_decoy["epistemic_confidence"], 0.90)

        # Isolated co-located sink with zero sources and zero backward_slice -> CAUSAL_HYPOTHESIS (0.70)
        isolated_df = {
            "function": "Parse",
            "entry_point": "0x140001000",
            "sinks": [{"address": "0x140001050", "var": "RCX", "inputs": ["EAX"]}],
            "sources": [],
            "backward_slice": [],
            "provenance": {"status": "VERIFIED_CRYPTOGRAPHIC_HASH"},
        }
        res_iso = evaluate_data_flow_crash_causality(isolated_df, crash)
        self.assertEqual(res_iso["level"], "CAUSAL_HYPOTHESIS")
        self.assertEqual(res_iso["epistemic_confidence"], 0.70)
        # x64 RAX matched EAX in the sink via symmetric register family map
        self.assertTrue(res_iso["register_matched"])

    def test_fuse_quarantines_call_graph_and_mermaid_avoids_id_collision(self):
        from windows_intelligence.evidence_engine.graph_model import EvidenceGraph, fuse_static_dynamic_ghidra

        fused = fuse_static_dynamic_ghidra(
            binary_inspection={"format": "PE", "file_name": "a.exe", "sha256": "11" * 32},
            ghidra_call_graph={"status": "ok", "functions_indexed": 5, "call_edges_count": 3},
            ghidra_provenance={"status": "PROVENANCE_HASH_MISMATCH"},
        )
        cg_node = next(n for n in fused["fused_graph"]["nodes"] if n["id"] == "ghidra:call_graph")
        self.assertEqual(cg_node["properties"]["verification_level"], "UNVERIFIED_PROVENANCE_QUARANTINED")

        g = EvidenceGraph()
        g.add_node("node:a", "HOST_OS", "First")
        g.add_node("node_a", "HOST_OS", "Second")
        mmd = g.to_mermaid()
        self.assertIn("node_a[", mmd)
        self.assertIn("node_a_2[", mmd)


class TestProcessProfilerAuditFixes(unittest.TestCase):
    def test_negative_handle_sentinel_and_short_series_and_multi_leak(self):
        from windows_intelligence.process_intelligence.process_profiler import ProcessLongitudinalProfiler

        # Short 2-sample GDI + memory leak with unavailable (-1) kernel handles
        samples = [
            {
                "sample_index": 1, "timestamp_epoch": 100.0,
                "working_set_mb": 20.0, "private_bytes_mb": 10.0,
                "peak_working_set_mb": 20.0, "peak_private_bytes_mb": 10.0,
                "kernel_handles": -1, "gdi_handles": 100, "user_handles": 10,
            },
            {
                "sample_index": 2, "timestamp_epoch": 101.0,
                "working_set_mb": 30.0, "private_bytes_mb": 18.0,
                "peak_working_set_mb": 30.0, "peak_private_bytes_mb": 18.0,
                "kernel_handles": -1, "gdi_handles": 150, "user_handles": 10,
            },
        ]
        res = ProcessLongitudinalProfiler.analyze_telemetry_series(pid=100, telemetry_samples=samples)
        ms = res["metrics_summary"]
        self.assertFalse(ms["handle_telemetry_available"])
        self.assertIsNone(ms["initial_kernel_handles"])
        self.assertEqual(ms["delta_kernel_handles"], 0)
        self.assertEqual(res["behavior_classification"], "ACTIVE_GDI_LEAK_SUSPECTED")
        self.assertIn("ACTIVE_MEMORY_LEAK_SUSPECTED", ms["concurrent_leak_signals"])
        self.assertGreater(ms["slope_private_bytes_mb_per_second"], 0.0)


class TestAuditLoggerIntegrityAndAtomicity(unittest.TestCase):
    def setUp(self):
        from security.audit_logger import AuditLogger
        self.tmp = tempfile.mkdtemp(prefix="bintra_audit_int_")
        self.log = os.path.join(self.tmp, "audit.jsonl")
        self._prev = (
            AuditLogger._log_file,
            AuditLogger._log_dir,
            AuditLogger._segment_max_bytes,
            AuditLogger.get_strict_persistence(),
        )
        AuditLogger.clear()
        AuditLogger.set_strict_persistence(False)
        AuditLogger.set_log_file(self.log)

    def tearDown(self):
        from security.audit_logger import AuditLogger
        AuditLogger.clear()
        AuditLogger.set_strict_persistence(self._prev[3])
        AuditLogger._log_file, AuditLogger._log_dir, AuditLogger._segment_max_bytes, _ = self._prev
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_failure_does_not_corrupt_in_memory_sequence_or_hash(self):
        from security.audit_logger import AuditLogger, AuditPersistenceError

        r0 = AuditLogger.log_decision("t", "op", "ok0", "ALLOW", "init")
        self.assertEqual(r0["sequence"], 0)
        seq_before = AuditLogger._sequence
        hash_before = AuditLogger._last_hash
        count_before = len(AuditLogger._journal)

        with mock.patch.object(AuditLogger, "_persist_record", side_effect=AuditPersistenceError("disk full")):
            AuditLogger.set_strict_persistence(True)
            with self.assertRaises(AuditPersistenceError):
                AuditLogger.log_decision("t", "op", "fail_strict", "ALLOW", "err")
        self.assertEqual(AuditLogger._sequence, seq_before)
        self.assertEqual(AuditLogger._last_hash, hash_before)
        self.assertEqual(len(AuditLogger._journal), count_before)

        AuditLogger.set_strict_persistence(False)
        with mock.patch.object(AuditLogger, "_persist_record", return_value=False):
            r_fail = AuditLogger.log_decision("t", "op", "fail_soft", "ALLOW", "err")
            self.assertFalse(r_fail.get("persisted", True))
            self.assertIsNone(r_fail["sequence"])
        self.assertEqual(AuditLogger._sequence, seq_before)
        self.assertEqual(AuditLogger._last_hash, hash_before)
        self.assertEqual(len(AuditLogger._journal), count_before)

        r1 = AuditLogger.log_decision("t", "op", "ok1", "ALLOW", "recovered")
        self.assertEqual(r1["sequence"], 1)
        self.assertEqual(AuditLogger.verify_audit_chain(self.log)["records_verified"], 2)

    def test_forged_sealed_cache_and_large_tail_and_truncation_detected(self):
        from security.audit_logger import AuditLogger, AuditIntegrityError

        AuditLogger._segment_max_bytes = 512
        for i in range(6):
            AuditLogger.log_decision("t", "op", f"item_{i}", "ALLOW", "ok")
        AuditLogger._journal.clear()
        AuditLogger._sequence = 0
        AuditLogger._last_hash = "0" * 64
        res = AuditLogger.ensure_chain_continuity()
        sealed = res["sealed_segment"]
        # Build .sealedcache.json
        AuditLogger._journal.clear()
        AuditLogger._sequence = 0
        AuditLogger._last_hash = "0" * 64
        AuditLogger.ensure_chain_continuity()

        # Tamper sealed file AND forge matching sha256 inside .sealedcache.json!
        with open(sealed, "r", encoding="utf-8") as f:
            orig_sealed = f.read()
        forged_sealed = orig_sealed.replace("item_2", "hacked")
        with open(sealed, "w", encoding="utf-8") as f:
            f.write(forged_sealed)
        cache_path = AuditLogger._sealed_cache_path(self.log)
        with open(cache_path, "r", encoding="utf-8") as cf:
            cache_data = json.load(cf)
        cache_data[os.path.basename(sealed)]["sha256"] = AuditLogger._file_sha256(sealed)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache_data, f)

        AuditLogger._journal.clear()
        AuditLogger._sequence = 0
        AuditLogger._last_hash = "0" * 64
        with self.assertRaises(AuditIntegrityError):
            AuditLogger.recover_chain_from_disk(self.log)
        v_full = AuditLogger.verify_audit_chain(self.log, full_verify=True)
        self.assertFalse(v_full["is_valid"])
        self.assertFalse(v_full["bounded_cost"] if "bounded_cost" in v_full else False)

        # Restore intact archive, then verify >10KB record sync & active file truncation detection
        with open(sealed, "w", encoding="utf-8") as f:
            f.write(orig_sealed)
        AuditLogger.recover_chain_from_disk(self.log)
        big_rec = AuditLogger.log_decision("t", "op", "X" * 12000, "ALLOW", "big")
        seq_after_big = big_rec["sequence"]
        AuditLogger._journal.clear()
        AuditLogger._sequence = 0
        AuditLogger._last_hash = "0" * 64
        AuditLogger._known_disk_state = None
        next_rec = AuditLogger.log_decision("t", "op", "after_big", "ALLOW", "ok")
        self.assertEqual(next_rec["sequence"], seq_after_big + 1)
        self.assertTrue(AuditLogger.verify_audit_chain(self.log)["is_valid"])

        # Truncate active file while in-memory records exist -> verify_audit_chain must fail!
        with open(self.log, "wb") as f:
            pass
        os.remove(sealed)
        self.assertFalse(AuditLogger.verify_audit_chain(self.log)["is_valid"])

    def test_tampered_log_never_rotated_silently_and_fsync_enforced(self):
        """Tamper breaks must fail closed even with rotate_on_corrupt=True, and fsync runs on persist."""
        import subprocess
        from security.audit_logger import AuditLogger, AuditIntegrityError

        AuditLogger.set_strict_persistence(False)
        with mock.patch("security.audit_logger.os.fsync", wraps=os.fsync) as fsync_spy:
            AuditLogger.log_decision("t", "op", "fsync_target", "ALLOW", "ok")
        self.assertGreaterEqual(fsync_spy.call_count, 1)
        AuditLogger.log_decision("t", "op", "second_rec", "ALLOW", "ok")

        # Tamper record on disk
        with open(self.log, "r", encoding="utf-8") as f:
            raw = f.read()
        with open(self.log, "w", encoding="utf-8") as f:
            f.write(raw.replace("second_rec", "tampered_rec"))

        AuditLogger._journal.clear()
        AuditLogger._sequence = 0
        AuditLogger._last_hash = "0" * 64
        AuditLogger._known_disk_state = None
        with self.assertRaises(AuditIntegrityError):
            AuditLogger.ensure_chain_continuity(rotate_on_corrupt=True)
        self.assertTrue(AuditLogger.is_tamper_detected())
        self.assertTrue(AuditLogger.is_audit_degraded())
        # Tamper evidence file MUST still exist (not moved to .legacy!)
        self.assertTrue(os.path.exists(self.log))

        # Test sudden deletion of active file in-process
        AuditLogger.clear()
        del_log = os.path.join(self.tmp, "del_audit.jsonl")
        AuditLogger.set_log_file(del_log)
        AuditLogger.log_decision("t", "op", "x", "ALLOW", "ok")
        os.remove(del_log)
        with self.assertRaises(AuditIntegrityError):
            AuditLogger.ensure_chain_continuity(rotate_on_corrupt=True)
        self.assertTrue(AuditLogger.is_tamper_detected())

        # End-to-end CLI & MCP against a home directory whose active audit.jsonl is tampered
        home_dir = os.path.join(self.tmp, "tampered_home")
        log_dir = os.path.join(home_dir, ".bintra", "logs")
        ws_dir = os.path.join(self.tmp, "ws")
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(ws_dir, exist_ok=True)
        cli_log = os.path.join(log_dir, "audit.jsonl")
        AuditLogger.clear()
        AuditLogger.set_log_file(cli_log)
        AuditLogger.log_decision("cli", "inspect", "bin.exe", "ALLOW", "ok")
        AuditLogger.log_decision("cli", "patch", "bin.exe", "ALLOW", "ok2")
        with open(cli_log, "r", encoding="utf-8") as f:
            cli_raw = f.read()
        with open(cli_log, "w", encoding="utf-8") as f:
            f.write(cli_raw.replace("bin.exe", "tampered.exe"))

        target_bin = os.path.join(self.tmp, "sample.exe")
        with open(target_bin, "wb") as f:
            f.write(_minimal_pe_with_bss_and_overlay())
        env = os.environ.copy()
        env["HOME"] = home_dir
        env["USERPROFILE"] = home_dir

        cli_py = os.path.join(SRC_DIR, "cli.py")
        mut = subprocess.run(
            [sys.executable, cli_py, "patch-binary", "--file", target_bin, "--output", os.path.join(ws_dir, "out.bin"), "--offset", "0x40", "--patch-hex", "90", "--workspace", ws_dir],
            env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertNotEqual(mut.returncode, 0)
        mut_json = json.loads(mut.stdout)
        self.assertTrue(mut_json.get("audit_tamper_detected"))
        self.assertTrue(os.path.exists(cli_log))

        rd = subprocess.run(
            [sys.executable, cli_py, "slack-audit", "--file", target_bin],
            env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertEqual(rd.returncode, 0, rd.stderr)
        rd_json = json.loads(rd.stdout)
        self.assertTrue(rd_json.get("audit_degraded"))
        self.assertTrue(rd_json.get("audit_tamper_detected"))
        self.assertTrue(os.path.exists(cli_log))

        # MCP server on tampered audit log blocks mutating tools & keeps read tools flagged
        from mcp_server import BintraMcpServer
        AuditLogger.clear()
        AuditLogger.set_log_file(cli_log)
        srv = BintraMcpServer(workspace_root=ws_dir)
        self.assertTrue(AuditLogger.is_tamper_detected())
        self.assertTrue(os.path.exists(cli_log))
        mcp_mut = srv.handle_tools_call({
            "name": "bintra_patch_binary",
            "arguments": {"file_path": target_bin, "output_path": os.path.join(ws_dir, "mcp_out.bin"), "offset": 64, "patch_hex": "90"},
        })
        self.assertTrue(mcp_mut["isError"])
        self.assertIn("AUDIT_TAMPER_DETECTED", mcp_mut["structuredContent"]["error"])
        mcp_rd = srv.handle_tools_call({"name": "bintra_inspect_slack_space", "arguments": {"file_path": target_bin}})
        self.assertFalse(mcp_rd["isError"])
        self.assertTrue(mcp_rd["structuredContent"].get("audit_tamper_detected"))


class TestMcp20260728ComplianceFixes(unittest.TestCase):
    def test_discover_result_and_cache_hints_and_jsonrpc_checks(self):
        from mcp_server import BintraMcpServer

        srv = BintraMcpServer()
        disc = srv._handle_single_request({
            "jsonrpc": "2.0",
            "id": "d1",
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "TestClient", "version": "2.0"},
                    "io.modelcontextprotocol/clientCapabilities": {"roots": {"listChanged": True}},
                }
            },
        })
        res = disc["result"]
        self.assertEqual(res["resultType"], "complete")
        self.assertIn("2026-07-28", res["supportedVersions"])
        self.assertEqual(res["cacheScope"], "public")
        self.assertEqual(res["ttlMs"], 3600000)
        self.assertEqual(res["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "bintra")
        self.assertEqual(srv.current_client_info["name"], "TestClient")

        # Stateless capability isolation: subsequent 2026-07-28 request must not inherit prior capabilities
        ping_r = srv._handle_single_request({
            "jsonrpc": "2.0",
            "id": "p1",
            "method": "ping",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        })
        self.assertEqual(ping_r["result"]["resultType"], "complete")
        self.assertEqual(ping_r["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "bintra")
        self.assertEqual(srv.current_client_capabilities, {})

        # Paginated tools/list MUST keep resultType, ttlMs, and cacheScope per schema/2026-07-28
        tl = srv.handle_tools_list({})
        self.assertEqual(tl["resultType"], "complete")
        self.assertEqual(tl["cacheScope"], "public")
        self.assertIn("ttlMs", tl)
        tl_page = srv.handle_tools_list({"cursor": "0"})
        self.assertEqual(tl_page["resultType"], "complete")
        self.assertEqual(tl_page["cacheScope"], "public")
        self.assertEqual(tl_page["ttlMs"], 3600000)
        self.assertIn("nextCursor", tl_page)

        rl = srv.handle_resources_list({})
        self.assertEqual(rl["resultType"], "complete")
        self.assertEqual(rl["cacheScope"], "public")
        pl = srv.handle_prompts_list({})
        self.assertEqual(pl["resultType"], "complete")
        pg = srv.handle_prompts_get({"name": "audit_windows_host", "arguments": {"focus": "all"}})
        self.assertEqual(pg["resultType"], "complete")
        tc_err = srv.handle_tools_call({"name": "bintra_list_capabilities", "arguments": {"platform_filter": "invalid_choice"}})
        self.assertTrue(tc_err["isError"])
        self.assertEqual(tc_err["resultType"], "complete")

        priv_res = srv.handle_resources_read({"uri": "bintra://security/policy"})
        self.assertEqual(priv_res["resultType"], "complete")
        self.assertEqual(priv_res["cacheScope"], "private")
        self.assertEqual(priv_res["ttlMs"], 0)

        # JSON-RPC validation: missing jsonrpc, non-object params, invalid 2026 _meta, null id under 2026
        missing_jsonrpc = srv._handle_single_request({"id": 10, "method": "ping"})
        self.assertEqual(missing_jsonrpc["error"]["code"], -32600)
        bad_ver = srv._handle_single_request({"jsonrpc": "1.0", "id": 1, "method": "ping"})
        self.assertEqual(bad_ver["error"]["code"], -32600)
        bad_method = srv._handle_single_request({"jsonrpc": "2.0", "id": 2})
        self.assertEqual(bad_method["error"]["code"], -32600)
        bad_params = srv._handle_single_request({"jsonrpc": "2.0", "id": 3, "method": "ping", "params": "invalid"})
        self.assertEqual(bad_params["error"]["code"], -32602)
        missing_caps = srv._handle_single_request({
            "jsonrpc": "2.0", "id": 4, "method": "ping",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}},
        })
        self.assertEqual(missing_caps["error"]["code"], -32602)
        null_id_2026 = srv._handle_single_request({
            "jsonrpc": "2.0", "id": None, "method": "ping",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}}},
        })
        self.assertEqual(null_id_2026["error"]["code"], -32600)


class TestEndToEndGhidraProvenanceAndRcaSlack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bintra_e2e_audit_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ghidra_dict_varnodes_multi_sink_end_to_end_and_provenance_tamper(self):
        """Validates real Ghidra dict Varnodes from slice_data_flow through Orchestrator/MCP/Graph and sidecar manifest tampering."""
        import hashlib
        from analysis_orchestrator import BinaryTriageOrchestrator
        from ghidra_export_store import GhidraExportStore
        from windows_intelligence.evidence_engine.graph_model import evaluate_data_flow_crash_causality

        pe_bytes = _minimal_pe_with_bss_and_overlay()
        pe_path = os.path.join(self.tmp, "app.exe")
        with open(pe_path, "wb") as f:
            f.write(pe_bytes)
        target_sha = hashlib.sha256(pe_bytes).hexdigest()

        # Real Ghidra dict varnode style with TWO sinks: sinks[0] is unrelated; sinks[1] at 0x140001050 crashes on RAX!
        export_payload = {
            "program_name": "app.exe",
            "image_base": "0x140000000",
            "sha256": target_sha,
            "functions": [
                {
                    "name": "ProcessFrame",
                    "entry_point": "0x140001000",
                    "size": 0x100,
                    "pcode_ops": [
                        {
                            "opcode": "CALL",
                            "address": "0x140001010",
                            "inputs": [{"kind": "register", "name": "RCX", "repr": "reg:RCX"}],
                            "output": {"kind": "register", "name": "RDX", "repr": "reg:RDX", "def_id": "0x140001010:0"},
                        },
                        {
                            "opcode": "STORE",  # First sink: unrelated!
                            "address": "0x140001020",
                            "inputs": [
                                {"kind": "register", "name": "RDX", "repr": "reg:RDX", "def_id": "0x140001010:0"},
                                {"kind": "register", "name": "RBX", "repr": "reg:RBX"},
                            ],
                            "output": None,
                        },
                        {
                            "opcode": "LOAD",  # Source feeding the crashing RAX pointer
                            "address": "0x140001040",
                            "inputs": [{"kind": "register", "name": "RSI", "repr": "reg:RSI"}],
                            "output": {"kind": "register", "name": "RAX", "repr": "reg:RAX", "def_id": "0x140001040:0"},
                        },
                        {
                            "opcode": "STORE",  # Second sink: exact crash location!
                            "address": "0x140001050",
                            "inputs": [
                                {"kind": "register", "name": "RAX", "repr": "reg:RAX", "def_id": "0x140001040:0"},
                                {"kind": "constant", "repr": "const:0x0"},
                            ],
                            "output": None,
                        },
                    ],
                }
            ],
        }
        exp_path = os.path.join(self.tmp, "app_ghidra.json")
        with open(exp_path, "w", encoding="utf-8") as f:
            json.dump(export_payload, f)
        content_sha = BinaryTriageOrchestrator.compute_ghidra_export_content_sha256(export_payload)
        sidecar = exp_path + ".provenance.json"
        with open(sidecar, "w", encoding="utf-8") as sf:
            json.dump({"target_sha256": target_sha, "export_content_sha256": content_sha}, sf)

        # Build valid crash dump dict at 0x140001050 (fault_rva 0x1050) without explicitly naming function
        from mcp_server import BintraMcpServer
        dmp_stub = os.path.join(self.tmp, "crash.dmp")
        # Minimal valid MDMP triggering crash RCA at 0x140001050 (verified via dump memory bytes `48 c7 00 00 00 00 00`)
        code_mov = b"\x48\xc7\x00\x00\x00\x00\x00"  # mov qword ptr [rax], 0
        dmp_buf = bytearray(0x900)
        struct.pack_into("<IIIIII", dmp_buf, 0, 0x504D444D, 0xA793, 5, 0x40, 0, 0)
        struct.pack_into("<III", dmp_buf, 0x40, 7, 56, 0x80)    # SystemInfo
        struct.pack_into("<III", dmp_buf, 0x4C, 6, 168, 0xC0)   # Exception
        struct.pack_into("<III", dmp_buf, 0x58, 4, 112, 0x180)  # ModuleList
        struct.pack_into("<III", dmp_buf, 0x64, 5, 20, 0x240)   # MemoryList
        struct.pack_into("<III", dmp_buf, 0x70, 16, 64, 0x280)  # MemoryInfoList (Stream 16 VAD!)
        # SystemInfo arch=9 (x64)
        struct.pack_into("<HHHH", dmp_buf, 0x80, 9, 6, 0, 0)
        # Exception Stream (168B at 0xC0): "<IIIIQQII15QII" -> thread_id=1, code=C0000005, addr=0x140001050, num_params=2, params=[1, 0x200000000], ctx=(1232, 0x300)
        exc_params = [1, 0x200000000] + [0] * 13
        struct.pack_into("<IIIIQQII15QII", dmp_buf, 0xC0, 1, 0, 0xC0000005, 0, 0, 0x140001050, 2, 0, *exc_params, 1232, 0x300)
        # x64 ThreadContext at 0x300: rip at +248, rax=0x200000000 at +120
        struct.pack_into("<Q", dmp_buf, 0x300 + 248, 0x140001050)
        struct.pack_into("<Q", dmp_buf, 0x300 + 120, 0x200000000)
        # Module app.exe base=0x140000000 size=0x10000
        struct.pack_into("<I", dmp_buf, 0x180, 1)
        struct.pack_into("<QIIII", dmp_buf, 0x184, 0x140000000, 0x10000, 0, 0, 0x200)
        name_u = "C:\\t\\app.exe".encode("utf-16-le")
        struct.pack_into("<I", dmp_buf, 0x200, len(name_u))
        dmp_buf[0x204:0x204 + len(name_u)] = name_u
        # MemoryList: capture code bytes at 0x140001050 stored at rva 0x260
        struct.pack_into("<I", dmp_buf, 0x240, 1)
        struct.pack_into("<QII", dmp_buf, 0x244, 0x140001050, len(code_mov), 0x260)
        dmp_buf[0x260:0x260 + len(code_mov)] = code_mov
        # Stream 16 MemoryInfoList: 1 entry confirming 0x200000000 is MEM_FREE (0x10000)
        struct.pack_into("<IIQ", dmp_buf, 0x280, 16, 48, 1)
        struct.pack_into("<QQIIQIII", dmp_buf, 0x290, 0x200000000, 0, 0, 0, 0x1000, 0x10000, 0x1, 0)
        with open(dmp_stub, "wb") as df:
            df.write(dmp_buf)

        srv = BintraMcpServer(workspace_root=self.tmp)
        fused_resp = srv.handle_tools_call({
            "name": "bintra_fuse_evidence",
            "arguments": {"binary_path": pe_path, "dmp_path": dmp_stub, "ghidra_export_path": exp_path},
        })
        self.assertFalse(fused_resp["isError"], fused_resp)
        graph = fused_resp["structuredContent"]["fused_graph"]
        slice_edges = [e for e in graph["edges"] if e["relation"] == "EXPLAINS_DATA_PROVENANCE"]
        self.assertEqual(len(slice_edges), 1, graph["edges"])
        self.assertEqual(slice_edges[0]["metadata"]["verification_level"], "CAUSALLY_VALIDATED")
        self.assertGreaterEqual(slice_edges[0]["metadata"]["epistemic_confidence"], 0.90)

        # Verify BinaryTriageOrchestrator end-to-end auto-locates enclosing function and proves CAUSALLY_VALIDATED
        triage_res = BinaryTriageOrchestrator.triage_binary(
            file_path=pe_path, dmp_path=dmp_stub, ghidra_export_path=exp_path, include_deobfuscation=False
        )
        triage_edges = [e for e in triage_res["evidence_graph"]["edges"] if e["relation"] == "EXPLAINS_DATA_PROVENANCE"]
        self.assertEqual(len(triage_edges), 1, triage_res["evidence_graph"]["edges"])
        self.assertTrue(triage_res["artifacts"]["ghidra_data_flow"]["slice_anchor_matched"])
        self.assertEqual(triage_res["stage_statuses"]["ghidra_analysis"]["provenance"]["content_integrity"], "VERIFIED_INDEPENDENT_MANIFEST")

        # Direct check: provenance + slice_anchor_matched on wrong sink must NOT give CAUSALLY_VALIDATED
        bad_df = {
            "function": "ProcessFrame",
            "sinks_sample": [{"address": "0x140001050", "inputs": ["reg:RAX"]}],
            "sources_sample": [],
            "backward_slice": [{"address": "0x140001010", "output": "reg:RDX", "inputs": ["reg:RCX"]}],
            "sliced_from_address": "0x140001020",
        }
        bad_c = evaluate_data_flow_crash_causality(
            bad_df,
            {"fault_virtual_address": "0x140001050", "fault_rva": "0x1050", "culprit_register": "RAX"},
            provenance={"status": "VERIFIED_CRYPTOGRAPHIC_HASH"},
        )
        self.assertEqual(bad_c["level"], "CAUSAL_HYPOTHESIS")

        # Tamper function data in export while leaving target sha256 intact -> must be quarantined via sidecar!
        export_payload["functions"][0]["name"] = "EvilRenamed"
        with open(exp_path, "w", encoding="utf-8") as f:
            json.dump(export_payload, f)
        with GhidraExportStore.from_path(exp_path) as store:
            prov, is_crypto, is_heur = BinaryTriageOrchestrator.verify_ghidra_export_provenance(
                store, target_sha256=target_sha, target_filename="app.exe"
            )
        self.assertFalse(is_crypto)
        self.assertFalse(is_heur)
        self.assertEqual(prov["status"], "PROVENANCE_CONTENT_TAMPERED")

    def test_crash_rca_stream16_vs_partial_dump_and_truncated_slack(self):
        """Partial dumps must not claim UNMAPPED/WILD_OR_FREED_POINTER without Stream 16/VAD; truncated docs must not claim CLEAN_EXACT_EOF."""
        from windows_intelligence.runtime_telemetry.crash_rca_engine import CrashRootCauseAnalyzer
        from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector

        partial_dump = {
            "status": "success",
            "modules": [{"name": "m.exe", "base_address": "0x400000", "size": 0x1000}],
            "memory_ranges": [],
            "vad_regions": [],
            "exception_info": {
                "exception_code": "0xC0000005",
                "fault_module": "m.exe",
                "fault_offset": "0x100",
                "access_violation_details": {"access_type": "READ", "target_virtual_address": "0x55550000"},
                "thread_registers": {"arch": "x64"},
            },
        }
        rca_partial = CrashRootCauseAnalyzer.analyze_crash(partial_dump)
        self.assertEqual(rca_partial["memory_spatial_classification"]["status"], "NOT_CAPTURED_IN_PARTIAL_DUMP")
        self.assertNotEqual(rca_partial["memory_spatial_classification"]["category"], "UNMAPPED_DYNAMIC_MEMORY")

        # With Stream 16 MEM_FREE (0x10000), unmapped pointer IS confirmed!
        confirmed_free = dict(partial_dump, vad_regions=[{"base_int": 0x55550000, "size": 0x1000, "state": "0x10000", "protect": "0x1"}])
        rca_free = CrashRootCauseAnalyzer.analyze_crash(confirmed_free)
        self.assertEqual(rca_free["memory_spatial_classification"]["status"], "CONFIRMED_UNMAPPED_MEMORY")

        # Truncated JSON / XML / RTF / Generic must NEVER return CLEAN_EXACT_EOF
        j_path = os.path.join(self.tmp, "big.json")
        x_path = os.path.join(self.tmp, "big.xml")
        r_path = os.path.join(self.tmp, "big.rtf")
        g_path = os.path.join(self.tmp, "big.bin")
        with open(j_path, "wb") as f:
            f.write(b'{"a":1}' + b" " * 64)
        with open(x_path, "wb") as f:
            f.write(b"<root/>" + b" " * 64)
        with open(r_path, "wb") as f:
            f.write(b"{\\rtf1 hi}" + b" " * 64)
        with open(g_path, "wb") as f:
            f.write(b"\x01\x02" * 64)

        with mock.patch.object(BinarySlackInspector, "MAX_JSON_READ", 8), \
             mock.patch.object(BinarySlackInspector, "MAX_DOCUMENT_READ", 12), \
             mock.patch.object(BinarySlackInspector, "MAX_OVERLAY_SAMPLE", 16):
            for fp in (j_path, x_path, r_path, g_path):
                res = BinarySlackInspector.inspect_file(fp)
                self.assertTrue(res["sample_truncated"], (fp, res))
                self.assertEqual(res["status"], "partial", (fp, res))
                self.assertNotEqual(res["slack_type"], "CLEAN_EXACT_EOF", (fp, res))


if __name__ == "__main__":
    unittest.main()
