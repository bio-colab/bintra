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
                    "io.modelcontextprotocol/clientCapabilities": {"roots": {}},
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

        tl = srv.handle_tools_list({})
        self.assertEqual(tl["cacheScope"], "public")
        self.assertIn("ttlMs", tl)
        tl_page = srv.handle_tools_list({"cursor": "0"})
        self.assertNotIn("ttlMs", tl_page)

        priv_res = srv.handle_resources_read({"uri": "bintra://security/policy"})
        self.assertEqual(priv_res["cacheScope"], "private")
        self.assertEqual(priv_res["ttlMs"], 0)

        bad_ver = srv._handle_single_request({"jsonrpc": "1.0", "id": 1, "method": "ping"})
        self.assertEqual(bad_ver["error"]["code"], -32600)
        bad_method = srv._handle_single_request({"jsonrpc": "2.0", "id": 2})
        self.assertEqual(bad_method["error"]["code"], -32600)


if __name__ == "__main__":
    unittest.main()
