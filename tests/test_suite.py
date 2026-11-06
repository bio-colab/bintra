import unittest
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "src"))
sys.path.insert(0, SRC_DIR)

from binary_neural_engine import ContinuousDeobfuscator, SemanticFunctionMatcher, BinaryFormatInspector
from rea_neural_engine import SubspaceAnalyzer, CircuitDecompiler, WeightPatcher
import numpy as np

class TestWindowsBinaryNeuralEngine(unittest.TestCase):

    def test_windows_pe_parsing(self):
        """Verifies native Windows PE parsing on the current Python executable."""
        exe_path = sys.executable
        res = BinaryFormatInspector.inspect(exe_path)
        self.assertEqual(res["format"], "PE")
        self.assertTrue(res["sections_count"] > 0)
        self.assertTrue(any(s["name"] == ".text" for s in res["sections"]))

    def test_opaque_predicate_deobfuscation(self):
        """Tests continuous state-transition deobfuscation and dead-branch elimination."""
        code = bytes.fromhex("55 48 89 e5 31 c0 74 05 e8 11 22 33 44 90 c3")
        res = ContinuousDeobfuscator.deobfuscate_cfg(code)
        self.assertEqual(res["opaque_predicates_detected"], 1)
        self.assertEqual(res["dead_instruction_bytes"], 4)
        self.assertTrue(res["complexity_reduction_percentage"] > 20.0)

    def test_semantic_function_matching(self):
        """Tests continuous behavioral vector matching between unoptimized and optimized code."""
        func1 = "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3"
        func2 = "55 48 89 e5 8d 47 01 5d c3"
        res = SemanticFunctionMatcher.match_functions(func1, func2)
        self.assertTrue(res["is_semantic_match"])
        self.assertGreater(res["cosine_similarity"], 0.90)

    def test_subspace_svd_extraction(self):
        """Tests truncated SVD extraction for continuous weight projections."""
        matrix = np.random.randn(64, 64).astype(np.float32)
        res = SubspaceAnalyzer.analyze_svd(matrix, top_k=8)
        self.assertEqual(res["top_k"], 8)
        self.assertEqual(len(res["singular_values"]), 8)
        self.assertGreater(res["energy_retained_ratio"], 0.0)

if __name__ == "__main__":
    unittest.main()
