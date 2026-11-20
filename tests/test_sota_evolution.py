# -*- coding: utf-8 -*-
"""
NEON SOTA Architecture & Capability Evolution Test Suite.
Validates:
  1. MCP Protocol SOTA capabilities (resources/list, resources/read, prompts/list, prompts/get, tool annotations, isError semantics).
  2. Unified BinaryTriageOrchestrator (PE inspection + deep forensics + signature trust + deobfuscation + Ghidra + EvidenceGraph fusion).
  3. Shared CLI (`bintra triage`) and MCP (`bintra_triage_binary`) integration + fail-closed security mediation.
  4. Documentation & packaging consistency (`pyproject.toml`, `README.md`, `AGENTS.md`, `docs/architecture.md`).
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def _build_minimal_pe64() -> bytes:
    pe = bytearray(1024)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe, 0x84, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    struct.pack_into("<H", pe, 0x84 + 20, 0x20B)
    struct.pack_into("<I", pe, 0x84 + 20 + 108, 16)
    return bytes(pe)


class TestSotaMcpCapabilities(unittest.TestCase):
    """Validates MCP resources, prompts, tool annotations, and structured isError contract."""

    def setUp(self):
        from mcp_server import BintraMcpServer
        self.tmp_ws = tempfile.mkdtemp(prefix="bintra_sota_mcp_")
        self.srv = BintraMcpServer(workspace_root=self.tmp_ws)

    def tearDown(self):
        shutil.rmtree(self.tmp_ws, ignore_errors=True)

    def test_initialize_advertises_tools_resources_and_prompts(self):
        init = self.srv.handle_initialize({"protocolVersion": "2024-11-05"})
        caps = init["capabilities"]
        self.assertIn("tools", caps)
        self.assertIn("resources", caps)
        self.assertIn("prompts", caps)

    def test_all_50_tools_have_authoritative_mcp_annotations(self):
        res = self.srv.handle_tools_list({})
        tools = res["tools"]
        self.assertEqual(len(tools), 50)
        by_name = {t["name"]: t for t in tools}
        self.assertIn("bintra_triage_binary", by_name)

        for t in tools:
            ann = t.get("annotations")
            self.assertIsInstance(ann, dict, f"Missing annotations on {t['name']}")
            self.assertIn("readOnlyHint", ann)
            self.assertIn("destructiveHint", ann)
            if t["name"] in ("bintra_patch_binary", "bintra_patch_weights"):
                self.assertTrue(ann["destructiveHint"])
            else:
                self.assertFalse(ann["destructiveHint"])

        self.assertTrue(by_name["bintra_triage_binary"]["annotations"]["readOnlyHint"])
        self.assertTrue(by_name["bintra_inspect_binary"]["annotations"]["readOnlyHint"])
        self.assertFalse(by_name["bintra_patch_binary"]["annotations"]["readOnlyHint"])
        self.assertFalse(by_name["bintra_patch_weights"]["annotations"]["readOnlyHint"])

    def test_mcp_resources_list_and_read_all_uris(self):
        listed = self.srv.handle_resources_list({})["resources"]
        uris = [r["uri"] for r in listed]
        self.assertEqual(
            uris,
            [
                "bintra://capabilities",
                "bintra://security/policy",
                "bintra://telemetry/session",
                "bintra://workflows/playbooks",
            ],
        )
        for uri in uris:
            out = self.srv.handle_resources_read({"uri": uri})
            self.assertEqual(len(out["contents"]), 1)
            self.assertEqual(out["contents"][0]["uri"], uri)
            parsed = json.loads(out["contents"][0]["text"])
            self.assertIsInstance(parsed, dict)

        with self.assertRaises(ValueError):
            self.srv.handle_resources_read({"uri": "bintra://does-not-exist"})
        with self.assertRaises(ValueError):
            self.srv.handle_resources_read({})

    def test_mcp_prompts_list_and_get(self):
        prompts = self.srv.handle_prompts_list({})["prompts"]
        names = [p["name"] for p in prompts]
        self.assertEqual(
            names,
            ["triage_pe_binary", "root_cause_crash", "audit_windows_host", "diff_binary_versions"],
        )

        p1 = self.srv.handle_prompts_get({"name": "triage_pe_binary", "arguments": {"file_path": "/tmp/a.exe"}})
        self.assertIn("bintra_triage_binary", p1["messages"][0]["content"]["text"])

        p2 = self.srv.handle_prompts_get({"name": "root_cause_crash", "arguments": {"dmp_path": "/tmp/c.dmp"}})
        self.assertIn("bintra_fuse_evidence", p2["messages"][0]["content"]["text"])

        p3 = self.srv.handle_prompts_get({"name": "audit_windows_host", "arguments": {"focus": "drivers"}})
        self.assertIn("drivers", p3["messages"][0]["content"]["text"])

        p4 = self.srv.handle_prompts_get({
            "name": "diff_binary_versions",
            "arguments": {"baseline_path": "/tmp/v1.exe", "target_path": "/tmp/v2.exe"},
        })
        self.assertIn("bintra_binary_diff", p4["messages"][0]["content"]["text"])

        with self.assertRaises(ValueError):
            self.srv.handle_prompts_get({"name": "triage_pe_binary", "arguments": {}})
        with self.assertRaises(ValueError):
            self.srv.handle_prompts_get({"name": "unknown_prompt", "arguments": {}})

    def test_mcp_structured_error_sets_is_error_true(self):
        # Non-existent dump file returns structured status="error" from MiniDumpParser -> isError must be True
        missing_dmp = os.path.join(self.tmp_ws, "missing.dmp")
        resp = self.srv.handle_tools_call({"name": "bintra_dmp_inspect", "arguments": {"dmp_path": missing_dmp}})
        self.assertTrue(resp["isError"])
        payload = json.loads(resp["content"][0]["text"])
        self.assertEqual(payload["status"], "error")


class TestSotaBinaryTriageOrchestrator(unittest.TestCase):
    """Validates BinaryTriageOrchestrator, upgraded EvidenceGraph fusion, MCP, and CLI triage."""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_sota_triage_")
        self.pe_path = os.path.join(self.tmp_dir, "sample.exe")
        pe_bytes = _build_minimal_pe64()
        with open(self.pe_path, "wb") as f:
            f.write(pe_bytes)
        self.ghidra_json = os.path.join(self.tmp_dir, "ghidra.json")
        with open(self.ghidra_json, "w", encoding="utf-8") as f:
            json.dump({
                "program_name": "sample.exe",
                "sha256": hashlib.sha256(pe_bytes).hexdigest(),
                "functions": [
                    {
                        "name": "main",
                        "entry_point": "0x140001000",
                        "size": 64,
                        "callees": ["CreateFileW"],
                        "pcode_ops": [],
                    }
                ],
            }, f)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_orchestrator_triage_fuses_pe_signature_and_ghidra(self):
        from analysis_orchestrator import BinaryTriageOrchestrator
        from security import ExecutionGuard

        with ExecutionGuard.scoped_session(workspace_dir=self.tmp_dir):
            res = BinaryTriageOrchestrator.triage_binary(
                file_path=self.pe_path,
                ghidra_export_path=self.ghidra_json,
                include_deobfuscation=False,
            )

        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["epistemic_classification"], "UNIFIED_BINARY_TRIAGE")
        self.assertEqual(res["stage_statuses"]["signature_intelligence"]["status"], "ok")
        self.assertEqual(res["stage_statuses"]["ghidra_analysis"]["status"], "ok")
        self.assertEqual(res["stage_statuses"]["deobfuscation"]["status"], "skipped")

        # Verify unified EvidenceGraph includes PE_BINARY, SIGNATURE_TRUST, and GHIDRA_CALL_GRAPH nodes
        nodes = res["evidence_graph"].get("nodes", [])
        node_types = {(n.get("type") or n.get("node_type")) for n in (nodes.values() if isinstance(nodes, dict) else nodes)}
        self.assertIn("PE_BINARY", node_types)
        self.assertIn("SIGNATURE_TRUST", node_types)
        self.assertIn("GHIDRA_CALL_GRAPH", node_types)

        self.assertTrue(len(res["summary"]["observed_facts"]) >= 2)

    def test_orchestrator_fail_closed_blocks_forbidden_system_path(self):
        from analysis_orchestrator import BinaryTriageOrchestrator
        from security import SecurityViolationError

        with self.assertRaises(SecurityViolationError):
            BinaryTriageOrchestrator.triage_binary(r"\\?\C:\Windows\System32\config\SAM")

    def test_orchestrator_raises_file_not_found_for_missing_binary(self):
        from analysis_orchestrator import BinaryTriageOrchestrator

        with self.assertRaises(FileNotFoundError):
            BinaryTriageOrchestrator.triage_binary(os.path.join(self.tmp_dir, "nope.exe"))

    def test_mcp_and_cli_triage_integration(self):
        from mcp_server import BintraMcpServer

        srv = BintraMcpServer(workspace_root=self.tmp_dir)
        mcp_resp = srv.handle_tools_call({
            "name": "bintra_triage_binary",
            "arguments": {"file_path": self.pe_path, "include_deobfuscation": False},
        })
        self.assertFalse(mcp_resp["isError"])
        mcp_data = json.loads(mcp_resp["content"][0]["text"])
        self.assertEqual(mcp_data["status"], "ok")

        cli_proc = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "triage", "--file", self.pe_path, "--skip-deobf"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(cli_proc.returncode, 0, cli_proc.stderr)
        cli_data = json.loads(cli_proc.stdout)
        self.assertEqual(cli_data["status"], "ok")
        self.assertEqual(cli_data["file_name"], "sample.exe")


class TestSotaDocsAndPackagingSync(unittest.TestCase):
    """Validates documentation accuracy and pyproject.toml module completeness."""

    def test_docs_reflect_50_mcp_tools_and_no_stale_34_count(self):
        arch_txt = (Path(REPO_ROOT) / "docs" / "architecture.md").read_text(encoding="utf-8")
        self.assertNotIn("34 أداة", arch_txt)
        self.assertTrue(any(c in arch_txt for c in ("50 أداة", "48 أداة")))

        readme_txt = (Path(REPO_ROOT) / "README.md").read_text(encoding="utf-8")
        self.assertTrue(any(c in readme_txt for c in ("50 mediated reverse engineering", "48 mediated reverse engineering")))
        self.assertIn("analysis_orchestrator.py", readme_txt)

        agents_txt = (Path(REPO_ROOT) / "AGENTS.md").read_text(encoding="utf-8")
        self.assertTrue(any(c in agents_txt for c in ("50 type-safe tools", "48 type-safe tools")))
        self.assertIn("bintra_triage_binary", agents_txt)


if __name__ == "__main__":
    unittest.main()
