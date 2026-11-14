# -*- coding: utf-8 -*-
"""
Field Test Validation for Legacy Win32 Game PE Benchmark (generals.exe).
Asserts that Bintra's static PE parsing, MSVC RTTI extraction, WOW64 dependency resolution,
and x86 heuristic prologue semantic diffing function reliably on legacy 32-bit binaries.
"""

import os
import sys
import json
import unittest

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)


class TestLegacyPeFieldValidation(unittest.TestCase):
    """Verifies results and privacy guarantees of the generals.exe benchmark."""

    def test_legacy_pe_benchmark_results_and_privacy_guarantees(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        json_path = os.path.join(repo_root, "benchmarks", "legacy_game_pe", "benchmark_results.json")
        report_path = os.path.join(repo_root, "benchmarks", "legacy_game_pe", "README.md")

        self.assertTrue(os.path.isfile(json_path), f"Missing benchmark json: {json_path}")
        self.assertTrue(os.path.isfile(report_path), f"Missing benchmark report: {report_path}")

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        with open(report_path, "r", encoding="utf-8") as f:
            report_text = f.read()

        # 1. Structural & Architecture Guarantees
        self.assertEqual(data["target_name"], "generals.exe")
        self.assertIn("PE32", data["pe_inspection"]["pe_type"])
        self.assertIn("x86", data["pe_inspection"]["machine"])
        self.assertGreaterEqual(data["file_size_bytes"], 6000000)

        # 2. Section Anatomy
        section_names = [s["name"] for s in data["pe_inspection"]["sections"]]
        self.assertIn(".text", section_names)
        self.assertIn(".rdata", section_names)
        self.assertIn(".data", section_names)
        self.assertIn(".rsrc", section_names)
        self.assertIn("Px7774", section_names)
        for sname in section_names:
            self.assertNotIn("\x00", sname)

        # 3. WOW64 Dependency Audit
        dep = data["dependency_resolution"]
        self.assertEqual(dep["verdict"], "HEALTHY")
        self.assertEqual(dep["loader_mode"], "WOW64 (32-on-64)")
        self.assertEqual(dep["missing_dlls_count"], 0)
        self.assertEqual(dep["architecture_mismatches_count"], 0)
        self.assertGreaterEqual(dep["resolved_dlls_count"], 15)

        # 4. MSVC RTTI Recovery
        rtti = data["deep_forensics"]
        self.assertGreaterEqual(rtti["rtti_type_descriptors_count"], 10)
        self.assertIn("class INIException", rtti["rtti_classes_sample"])
        self.assertGreaterEqual(rtti.get("rtti_class_hierarchy_descriptors_count", 0), 2)

        # 5. Semantic Diffing
        diff = data["semantic_binary_diff"]
        self.assertEqual(diff["functions_diff_mode"], "x86_prologue_heuristics")
        self.assertEqual(diff["pe_semantic_similarity"], 1.0)
        self.assertGreaterEqual(diff["identical_functions_count"], 100)

        # 6. Dossier & Extended Reports Verification
        dossier_path = os.path.join(repo_root, "benchmarks", "legacy_game_pe", "DEEP_FORENSICS_DOSSIER.md")
        cfg_path = os.path.join(repo_root, "benchmarks", "legacy_game_pe", "CFG_DEOBFUSCATION_REPORT.md")
        self.assertTrue(os.path.isfile(dossier_path), f"Missing dossier: {dossier_path}")
        self.assertTrue(os.path.isfile(cfg_path), f"Missing cfg report: {cfg_path}")

        with open(dossier_path, "r", encoding="utf-8") as f:
            dossier_text = f.read()
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg_text = f.read()

        # 7. Strict Privacy & Zero Path Leakage Assertions
        for text in (json.dumps(data), report_text, dossier_text, cfg_text):
            self.assertNotIn("R.G. Mechanics", text)
            self.assertNotIn("R.G.", text)
            self.assertNotIn("Mechanics", text)
            self.assertNotIn("D:\\Program Files", text)
            self.assertNotIn("D:/Program Files", text)
            self.assertNotIn("Command and Conquer Generals Zero Hour", text)


if __name__ == "__main__":
    unittest.main()
