"""
Regression tests for Windows-specific defects:

1. MCP stdio server must decode stdin as UTF-8 (non-ASCII paths were mangled
   by the ANSI code page on Windows) and must not emit CRLF-framed output.
2. CLI branches must `return` after printing (falling through printed
   "Unknown command" and exited 1 after a valid JSON payload).
3. CLI glue must call existing APIs with valid signatures
   (process-mitigations, evidence-graph, driver/device correlation).
4. proc-profile must not route a "pid:N" target through filesystem path
   canonicalization (rejected as an Alternate Data Stream on Windows).
"""

import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


def _child_env():
    env = dict(os.environ)
    # Reproduce the default Windows console/pipe behaviour (no UTF-8 override).
    env.pop("PYTHONIOENCODING", None)
    env.pop("PYTHONUTF8", None)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return env


class TestMcpStdioUtf8(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bintra_utf8_")
        self.ar_dir = os.path.join(self.tmp, "مجلد_اختبار")
        os.makedirs(self.ar_dir)
        self.target = os.path.join(self.ar_dir, "sample.bin")
        with open(self.target, "wb") as f:
            f.write(b"MZ" + b"\x00" * 126)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_non_ascii_path_survives_stdio_roundtrip(self):
        reqs = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize",
             "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "bintra_dump_bytes",
                        "arguments": {"file_path": self.target, "offset": 0, "length": 2}}},
        ]
        payload = ("\n".join(json.dumps(r, ensure_ascii=False) for r in reqs) + "\n").encode("utf-8")
        proc = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "mcp_server.py")],
            input=payload, capture_output=True, env=_child_env(), timeout=60,
        )
        self.assertNotIn(b"\r\n", proc.stdout, "MCP frames must be LF-delimited")
        responses = [json.loads(l) for l in proc.stdout.decode("utf-8").splitlines() if l.strip()]
        call = next(r for r in responses if r.get("id") == 2)
        text = call["result"]["content"][0]["text"]
        self.assertNotIn("FILE_NOT_FOUND", text)
        self.assertNotIn("does not exist", text)


class TestCliDispatchFallthrough(unittest.TestCase):
    def test_every_win_intel_branch_terminates(self):
        """Each `cmd == ...` branch in the WIN_INTEL block must return/exit."""
        import re
        with open(os.path.join(SRC_DIR, "cli.py"), encoding="utf-8") as f:
            src = f.read().splitlines()
        start = next(i for i, l in enumerate(src) if l.startswith("    if cmd in WIN_INTEL_COMMANDS"))
        end = next(i for i, l in enumerate(src) if l.startswith("    if cmd in SENSORY_COMMANDS"))
        heads = [i for i in range(start, end) if re.match(r"        (el)?if cmd (==|in) ", src[i])] + [end]
        missing = []
        for a, b in zip(heads, heads[1:]):
            body = "\n".join(src[a:b])
            if not re.search(r"^\s+return\b|sys\.exit\(", body, re.M):
                missing.append(src[a].strip())
        self.assertEqual(missing, [], f"Branches fall through to 'Unknown command': {missing}")


class TestCliGlueSignatures(unittest.TestCase):
    def test_process_mitigation_inspector_api(self):
        from windows_intelligence import ProcessMitigationInspector
        self.assertTrue(hasattr(ProcessMitigationInspector, "inspect_process"))
        self.assertIn("pid", inspect.signature(ProcessMitigationInspector.inspect_process).parameters)

    def test_causality_synthesizer_accepts_binary_path(self):
        from windows_intelligence.evidence_engine import CausalitySynthesizer
        self.assertIn("binary_path", inspect.signature(CausalitySynthesizer.synthesize_dossier).parameters)

    def test_driver_device_correlation_uses_list_devices(self):
        from windows_intelligence.device_intelligence.device_manager import DeviceManagerInspector
        import windows_intelligence.signature_intelligence as si
        owner = next(getattr(si, n) for n in dir(si) if hasattr(getattr(si, n), "_correlate_driver_with_device"))
        fake = {"devices": [{"device_instance_id": "PCI\\X", "friendly_name": "Fake Disk",
                             "class": "DiskDrive", "service": "disk", "problem_name": "CM_PROB_OK"}]}
        with mock.patch.object(DeviceManagerInspector, "list_devices", return_value=fake) as m:
            res = owner._correlate_driver_with_device(r"C:\Windows\System32\drivers\disk.sys")
        m.assert_called_once()
        self.assertEqual(res["associated_devices_count"], 1)
        self.assertEqual(res["associated_devices"][0]["device_id"], "PCI\\X")
        self.assertEqual(res["associated_devices"][0]["device_class"], "DiskDrive")

    def test_evidence_graph_cli_exit_code_and_single_json(self):
        tmp = tempfile.mkdtemp(prefix="bintra_eg_")
        try:
            target = os.path.join(tmp, "x.bin")
            with open(target, "wb") as f:
                f.write(b"MZ" + b"\x00" * 126)
            proc = subprocess.run(
                [sys.executable, os.path.join(SRC_DIR, "cli.py"), "evidence-graph", "--target", target],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                env=_child_env(), timeout=180,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout[-500:] + proc.stderr[-500:])
            self.assertNotIn("Unknown command", proc.stdout)
            json.loads(proc.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestProcProfileGuard(unittest.TestCase):
    def test_proc_profile_uses_query_mode(self):
        from security import ExecutionGuard
        seen = []

        def fake_request(component, operation, target, capability, access_mode="READ", metadata=None, raise_on_deny=True):
            seen.append((operation, target, access_mode))
            raise SystemExit(0)

        with mock.patch.object(ExecutionGuard, "request_access", side_effect=fake_request), \
             mock.patch("sys.argv", ["cli.py", "proc-profile", "-p", "4", "-n", "2"]):
            from cli import _dispatch_cli
            with self.assertRaises(SystemExit):
                _dispatch_cli()
        self.assertEqual(seen[0][0], "proc-profile")
        self.assertEqual(seen[0][2], "QUERY")


if __name__ == "__main__":
    unittest.main()
