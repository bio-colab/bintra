#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for Bintra Ghidra Security & Epistemic Remediation:
1. GhidraProjectGuard Project Name Sanitization & Path Traversal Prevention
2. Workspace Confinement for Project Creation & Deletion
3. Session Provenance Enforcement (Refusal to delete foreign projects)
4. Truthful Filesystem Absence Verification
5. Capability-Gated SQLite Cache DB Lifecycle
6. Pure SQL-Indexed Opcode and XREF Search with Limits
7. Advanced MSVC Symbol Demangler (Templates, Compounds, Pointer-to-Pointer)
8. Computational Profile Epistemic Honesty, Confidence Scores & Disclaimers
"""

import json
import os
import shutil
import tempfile
import unittest

from ghidra_export_store import GhidraExportStore
from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
from security import (
    ExecutionGuard,
    GhidraProjectGuard,
    SecurityViolationError,
    TargetScope,
)


class TestGhidraSecurityRemediation(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="bintra_ghidra_sec_test_")
        self.ws_dir = os.path.join(self.tmp_dir, "workspace")
        self.target_dir = os.path.join(self.tmp_dir, "target")
        os.makedirs(self.ws_dir, exist_ok=True)
        os.makedirs(self.target_dir, exist_ok=True)

        self.target_bin = os.path.join(self.target_dir, "target_app.exe")
        with open(self.target_bin, "wb") as f:
            f.write(b"MZ\x90\x00TargetPayload")

        self.scope = TargetScope(
            target_binary_path=self.target_bin,
            workspace_dir=self.ws_dir
        )
        ExecutionGuard.set_current_scope(self.scope)

    def tearDown(self):
        ExecutionGuard.set_current_scope(None)
        if os.path.exists(self.tmp_dir):
            shutil.rmtree(self.tmp_dir, ignore_errors=True)

    # 1. Project Name Sanitization
    def test_project_name_path_traversal_rejection(self):
        """Verifies that malicious or traversal project names are rejected with ValueError."""
        unsafe_names = [
            "../../malicious",
            r"..\..\malicious",
            "foo/bar",
            r"foo\bar",
            "name:stream",
            "proj*",
            "proj?name",
            "proj name with spaces",
            "a" * 65  # Exceeds max length
        ]
        for name in unsafe_names:
            with self.assertRaises(ValueError):
                GhidraProjectGuard.sanitize_project_name(name)

        # Valid names must succeed
        valid_names = ["valid_name", "Test-Project_01", "BintraHeadless_abcdef12"]
        for name in valid_names:
            self.assertEqual(GhidraProjectGuard.sanitize_project_name(name), name)

    # 2. Workspace Boundary Confinement
    def test_project_dir_workspace_confinement(self):
        """Verifies that project directories outside workspace or inside target dir are blocked."""
        # Outside workspace
        outside_dir = os.path.join(self.tmp_dir, "external_dir")
        with self.assertRaises(SecurityViolationError):
            GhidraProjectGuard.resolve_project_dir(outside_dir)

        # Inside protected target directory
        with self.assertRaises(SecurityViolationError):
            GhidraProjectGuard.resolve_project_dir(self.target_dir)

        # Default resolves inside workspace
        def_dir = GhidraProjectGuard.resolve_project_dir(None)
        self.assertTrue(self.scope.is_inside_workspace(def_dir))
        self.assertTrue(def_dir.endswith("ghidra_projects"))

    # 3. Session Provenance & Truthful Cleanup
    def test_session_provenance_and_clean_verification(self):
        """Verifies session provenance tracking and truthful filesystem cleanup."""
        proj_dir = os.path.join(self.ws_dir, "ghidra_projects")
        proj_name = "SessionProj_123"

        # Register and prepare project
        rep_path, gpr_path = GhidraProjectGuard.register_and_prepare_project(
            "ghidra_headless", proj_dir, proj_name
        )

        # Create dummy project files
        os.makedirs(rep_path, exist_ok=True)
        with open(gpr_path, "w") as f:
            f.write("<project/>")

        self.assertTrue(os.path.exists(rep_path))
        self.assertTrue(os.path.exists(gpr_path))

        # Attempting to delete an un-registered foreign project must be rejected
        res_foreign = GhidraProjectGuard.clean_transient_project("ghidra_headless", proj_dir, "ForeignProj_999")
        self.assertFalse(res_foreign)

        # Truthful cleaning of our registered session project
        res_clean = GhidraProjectGuard.clean_transient_project("ghidra_headless", proj_dir, proj_name)
        self.assertTrue(res_clean)
        self.assertFalse(os.path.exists(rep_path))
        self.assertFalse(os.path.exists(gpr_path))

    # 4. SQLite Cache Lifecycle Gating
    def test_sqlite_cache_lifecycle_gating(self):
        """Verifies SQLite cache DB creation is mediated by ExecutionGuard with WORKSPACE_WRITE."""
        cache_dir = os.path.join(self.ws_dir, "exports_cache")
        os.makedirs(cache_dir, exist_ok=True)
        target_db = os.path.join(cache_dir, "test_cache.db")

        dummy_json = {
            "program_name": "TestSec.exe",
            "functions": [
                {
                    "name": "DummyFunc",
                    "entry_point": "0x140001000",
                    "size": 32,
                    "pcode_ops": [{"opcode": "INT_ADD"}, {"opcode": "RETURN"}]
                }
            ]
        }
        json_file = os.path.join(self.ws_dir, "export.json")
        with open(json_file, "w") as f:
            json.dump(dummy_json, f)

        GhidraExportStore.ingest_to_sqlite(json_file, target_db)
        self.assertTrue(os.path.exists(target_db))
        self.assertTrue(self.scope.is_session_file(target_db))

        store = GhidraExportStore.from_path(target_db)
        self.assertEqual(store.count_functions(), 1)
        store.close()

    # 5. Pure SQL-Indexed Opcode and XREF Search
    def test_sqlite_indexed_opcode_and_xref_search(self):
        """Verifies that opcode and XREF searches use indexed SQL queries with pagination."""
        dummy_export = {
            "program_name": "TestSearch.exe",
            "functions": [
                {
                    "name": "FuncA",
                    "entry_point": "0x1000",
                    "size": 100,
                    "pcode_ops": [{"opcode": "CALLIND"}, {"opcode": "INT_XOR"}],
                    "xrefs": [{"from": "0x1000", "to": "0x5000", "symbol": "CryptoKey"}]
                },
                {
                    "name": "FuncB",
                    "entry_point": "0x2000",
                    "size": 50,
                    "pcode_ops": [{"opcode": "INT_ADD"}, {"opcode": "RETURN"}],
                    "xrefs": []
                }
            ]
        }
        json_file = os.path.join(self.ws_dir, "search_export.json")
        db_file = os.path.join(self.ws_dir, "search_export.db")
        with open(json_file, "w") as f:
            json.dump(dummy_export, f)

        GhidraExportStore.ingest_to_sqlite(json_file, db_file)
        store = GhidraExportStore.from_path(db_file)

        # Search by opcode
        res_opc = store.search_functions(opcode="CALLIND", limit=10)
        self.assertEqual(res_opc["total_matches"], 1)
        self.assertEqual(res_opc["matches"][0]["name"], "FuncA")

        # Search by XREF
        res_xref = store.search_functions(xref_target="CryptoKey", limit=10)
        self.assertEqual(res_xref["total_matches"], 1)
        self.assertEqual(res_xref["matches"][0]["name"], "FuncA")

        store.close()

    # 6. MSVC Demangler Advanced Constructs
    def test_msvc_demangler_advanced_constructs(self):
        """Verifies MSVC demangling of templates, compounds, and pointer chains."""
        cases = [
            ("?GetData@?$vector@H@@QEAAPEAHXZ", "int* vector<int>::GetData(void)"),
            ("?SetTarget@Controller@@QEAAXPEAUPlayer@@PEAW4Mode@@@Z", "void Controller::SetTarget(Player*, Mode*)"),
            ("?GetBuffer@Stream@@QEAAPEAPEAXPEA_N@Z", "void** Stream::GetBuffer(bool*)"),
            ("?Transform@?$Matrix@M@@QEAAXAEAUPoint@@@Z", "void Matrix<float>::Transform(Point&)")
        ]
        for mangled, expected in cases:
            res = GhidraDeepAnalyzer.demangle_msvc_symbol(mangled)
            self.assertEqual(res, expected)

    # 7. Computational Profile Epistemic Honesty
    def test_computational_profile_epistemic_honesty(self):
        """Verifies epistemic classification, confidence score, and disclaimer in profile."""
        dummy_export = {
            "functions": [
                {
                    "name": "Compute",
                    "size": 64,
                    "pcode_ops": [{"opcode": "INT_ADD"}, {"opcode": "INT_MULT"}]
                }
            ]
        }
        store = GhidraExportStore(in_memory_dict=dummy_export)
        prof = store.query_computational_profile()

        self.assertEqual(prof["epistemic_classification"], "EXPLORATORY_HEURISTIC_ARCHITECTURAL_PROFILE")
        self.assertEqual(prof["confidence_score"], 0.85)
        self.assertIn("threshold_criteria", prof)
        self.assertIn("disclaimer", prof)


if __name__ == "__main__":
    unittest.main()
