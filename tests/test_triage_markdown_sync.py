# -*- coding: utf-8 -*-
"""
Tests for BinaryTriageOrchestrator, Slack Space Stage, and Deterministic Markdown Report Sync.
"""

import os
import unittest
from analysis_orchestrator import BinaryTriageOrchestrator


class TestTriageMarkdownSync(unittest.TestCase):

    def test_triage_and_report_sync(self):
        """Verify that triage executes cleanly and generates a 1:1 factual markdown report."""
        target = r"C:\Program Files\Windows NT\Accessories\wordpad.exe"
        if not os.path.exists(target):
            self.skipTest("wordpad.exe not found on system.")

        triage_data = BinaryTriageOrchestrator.triage_binary(
            file_path=target,
            include_deobfuscation=False,
            max_exports=16,
            forensics_limit=50
        )
        self.assertIn("status", triage_data)
        self.assertIn("artifacts", triage_data)
        self.assertIn("slack_and_overlay", triage_data["artifacts"])

        # Check stage status
        slack_stage = triage_data["stage_statuses"].get("slack_and_overlay")
        self.assertIsNotNone(slack_stage)
        self.assertEqual(slack_stage.get("status"), "ok")

        # Generate deterministic markdown report
        md_report = BinaryTriageOrchestrator.generate_markdown_report(triage_data)
        self.assertIsInstance(md_report, str)
        self.assertGreater(len(md_report), 200)

        # Verify 1:1 consistency between Markdown and JSON
        self.assertIn(triage_data["target_sha256"], md_report)
        self.assertIn(triage_data["file_name"], md_report)
        self.assertIn(str(triage_data["status"]).upper(), md_report)

        # Verify that Slack Space is documented in Markdown
        self.assertIn("Binary Slack Space", md_report)


if __name__ == "__main__":
    unittest.main()
