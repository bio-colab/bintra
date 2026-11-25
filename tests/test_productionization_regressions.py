"""
Regression tests for the productionization pass: static-analysis defects and
audit-journal concurrency/integrity hardening.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from security.audit_logger import AuditLogger, AuditIntegrityError  # noqa: E402
import security.audit_logger as audit_mod  # noqa: E402


class TestStaticDefects(unittest.TestCase):
    def test_ghidra_planner_accepts_json_path(self):
        """`os` was never imported: passing a .json export path raised NameError."""
        from ghidra_pcode_vectorizer import GhidraAnnotationPlanner
        tmp = tempfile.mkdtemp()
        try:
            p = os.path.join(tmp, "export.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"program_name": "x.exe", "functions": []}, f)
            res = GhidraAnnotationPlanner.analyze_program_export(p)
            self.assertEqual(res.get("analyzed_functions"), 0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class _IsolatedAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, "audit.jsonl")
        self._prev = (AuditLogger._log_file, AuditLogger._log_dir, AuditLogger._segment_max_bytes)
        AuditLogger.clear()
        AuditLogger.set_log_file(self.log)

    def tearDown(self):
        AuditLogger.clear()
        AuditLogger._log_file, AuditLogger._log_dir, AuditLogger._segment_max_bytes = self._prev
        AuditLogger._audit_degraded = False
        AuditLogger._degraded_reason = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _fresh_process_view(self):
        AuditLogger._journal.clear()
        AuditLogger._sequence = 0
        AuditLogger._last_hash = "0" * 64
        AuditLogger._known_disk_state = None


class TestAuditNeverWritesUnlocked(_IsolatedAudit):
    def test_lock_timeout_does_not_append_or_advance_chain(self):
        AuditLogger.log_decision("t", "op", "a", "ALLOW", "r")
        size_before = os.path.getsize(self.log)
        seq_before = AuditLogger._sequence

        class _NeverAcquired:
            def __init__(self, *a, **k):
                self.acquired = False

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        with mock.patch.object(audit_mod, "_ProcessFileLock", _NeverAcquired):
            rec = AuditLogger.log_decision("t", "op", "b", "ALLOW", "r")
        self.assertFalse(rec["persisted"])
        self.assertEqual(os.path.getsize(self.log), size_before)
        self.assertEqual(AuditLogger._sequence, seq_before)
        self.assertTrue(AuditLogger.is_audit_degraded())
        # The on-disk chain is still intact and continues normally once the lock is available.
        AuditLogger.log_decision("t", "op", "c", "ALLOW", "r")
        self._fresh_process_view()
        self.assertEqual(AuditLogger.recover_chain_from_disk(self.log)["records_count"], 2)


class TestAuditSealedSegments(_IsolatedAudit):
    def _fill_and_seal(self, n=10):
        AuditLogger._segment_max_bytes = 1024
        for i in range(n):
            AuditLogger.log_decision("t", "op", f"target{i}", "ALLOW", "r")
        self._fresh_process_view()
        res = AuditLogger.ensure_chain_continuity()
        self.assertIn("sealed_segment", res)
        return res["sealed_segment"]

    def test_verifying_an_archive_never_reseals_it(self):
        sealed = self._fill_and_seal()
        self._fresh_process_view()
        AuditLogger.recover_chain_from_disk(sealed)
        self.assertTrue(os.path.exists(sealed))
        self.assertEqual([p for p in os.listdir(self.tmp) if p.count(".sealed.") > 1], [])

    def test_sealed_cache_is_used_and_detects_tampering(self):
        sealed = self._fill_and_seal()
        self._fresh_process_view()
        AuditLogger.ensure_chain_continuity()
        self.assertTrue(os.path.exists(AuditLogger._sealed_cache_path(self.log)))
        with mock.patch.object(AuditLogger, "_verify_segment_file", wraps=AuditLogger._verify_segment_file) as spy:
            self._fresh_process_view()
            AuditLogger.ensure_chain_continuity()
            sealed_calls = [c for c in spy.call_args_list if c.args and c.args[0] == sealed]
            self.assertEqual(sealed_calls, [], "intact sealed segment should be validated by digest, not re-parsed")
        with open(sealed, "r+", encoding="utf-8") as f:
            data = f.read().replace("target3", "forged!")
            f.seek(0)
            f.write(data)
            f.truncate()
        self._fresh_process_view()
        with self.assertRaises(AuditIntegrityError):
            AuditLogger.recover_chain_from_disk(self.log)


if __name__ == "__main__":
    unittest.main()
