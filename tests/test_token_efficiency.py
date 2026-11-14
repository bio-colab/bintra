import json
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
BENCH_DIR = os.path.join(REPO_ROOT, "benchmarks")
for p in (SRC_DIR, BENCH_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from mcp_server import BintraMcpServer
from token_telemetry import (
    TokenSessionTracker,
    compact_tool_schema,
    estimate_cost_usd,
    estimate_tokens,
    measure_serialization_waste,
    prune_payload,
)
from token_efficiency_benchmark import run_benchmark


class TestTokenEfficiency(unittest.TestCase):
    def test_token_estimation_and_cost_calculation(self):
        sample = {"status": "ok", "items": [1, 2, 3, 4, 5]}
        waste = measure_serialization_waste(sample)
        self.assertGreater(waste["pretty_tokens"], waste["compact_tokens"])
        cost = estimate_cost_usd(1_000_000, model="claude-3.5-sonnet", direction="input")
        self.assertAlmostEqual(cost, 3.0, places=4)

    def test_prune_payload_preserves_truncation_metadata(self):
        data = {"imports": [f"func_{i}" for i in range(50)], "empty_field": []}
        pruned, stats = prune_payload(data, max_list_items=10, drop_empty=True)
        self.assertEqual(len(pruned["imports"]), 10)
        self.assertEqual(pruned["_imports_truncated"]["total"], 50)
        self.assertEqual(pruned["_imports_truncated"]["omitted"], 40)
        self.assertNotIn("empty_field", pruned)
        self.assertEqual(stats["items_omitted"], 40)

    def test_mcp_compact_and_profile_schemas_reduce_tokens(self):
        srv = BintraMcpServer()
        full = srv.handle_tools_list({"compact": False, "profile": "all"})["tools"]
        compact_all = srv.handle_tools_list({"compact": True, "profile": "all"})["tools"]
        static_compact = srv.handle_tools_list({"compact": True, "profile": "static"})["tools"]

        self.assertEqual(len(full), 40)
        self.assertEqual(len(compact_all), 40)
        self.assertLess(len(static_compact), 15)

        full_tok = estimate_tokens(full)
        compact_tok = estimate_tokens(compact_all)
        static_tok = estimate_tokens(static_compact)
        self.assertLess(compact_tok, full_tok * 0.65)
        self.assertLess(static_tok, full_tok * 0.25)

    def test_cli_compact_and_token_report_flags(self):
        res_pretty = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "sense", "--hex", "554889e55dc3"],
            capture_output=True, text=True, check=True,
        )
        res_compact = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "sense", "--hex", "554889e55dc3", "--compact", "--token-report"],
            capture_output=True, text=True, check=True,
        )
        self.assertLess(len(res_compact.stdout), len(res_pretty.stdout))
        self.assertIn("[TOKEN TELEMETRY]", res_compact.stderr)
        self.assertEqual(
            json.loads(res_pretty.stdout)["overall_sensory_efficiency"],
            json.loads(res_compact.stdout)["overall_sensory_efficiency"],
        )

    def test_end_to_end_before_after_savings_and_parity(self):
        report = run_benchmark()
        self.assertTrue(report["quality_parity_passed"], f"Parity failed: {report['parity_checks']}")
        self.assertGreaterEqual(report["session_totals"]["savings_pct"], 50.0)


if __name__ == "__main__":
    unittest.main()
