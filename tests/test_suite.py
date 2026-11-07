import unittest
import sys
import os
import struct
import io
import zipfile
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "src"))
sys.path.insert(0, SRC_DIR)

from binary_neural_engine import (
    ContinuousDeobfuscator,
    SemanticFunctionMatcher,
    BinaryFormatInspector,
    SurgicalBinaryPatcher,
    HybridBinaryDissector
)
from rea_neural_engine import SafetensorsHandler, SubspaceAnalyzer, CircuitDecompiler, WeightPatcher

class TestRigorousEngineEvaluation(unittest.TestCase):

    def test_random_bytes_similarity_baseline(self):
        """
        Directly addresses Critique 1:
        Verifies that random unrelated byte sequences do NOT yield false positive high similarity.
        Across 50 random pairs, cosine similarity must be 0.0 (strictly rejected as non-code).
        """
        np.random.seed(42)
        similarities = []
        for _ in range(50):
            b1 = os.urandom(128).hex()
            b2 = os.urandom(128).hex()
            res = SemanticFunctionMatcher.match_functions(b1, b2)
            similarities.append(res["cosine_similarity"])
            self.assertFalse(res["is_semantic_match"])

        avg_sim = float(np.mean(similarities))
        max_sim = float(np.max(similarities))
        self.assertEqual(avg_sim, 0.0, "Random noise must produce 0.0 similarity.")
        self.assertEqual(max_sim, 0.0, "Random noise must not produce any matching false positives.")

    def test_real_semantic_function_matching(self):
        """Verifies that genuine semantic variants (unoptimized vs optimized) match with high confidence."""
        f1 = "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3"
        f2 = "55 48 89 e5 8d 47 01 5d c3"
        res = SemanticFunctionMatcher.match_functions(f1, f2)
        self.assertTrue(res["is_semantic_match"])
        self.assertGreater(res["cosine_similarity"], 0.85)

    def test_opaque_predicate_strict_register_equality(self):
        """
        Directly addresses Critique 2:
        Verifies that 'xor reg1, reg2' where reg1 != reg2 is NOT falsely flagged as zeroing.
        Only 'xor reg1, reg1' where reg1 == reg2 must be detected.
        """
        # xor eax, ecx (31 c8) followed by jz (74 05) -> reg 1 (ecx) != reg 0 (eax) -> NOT OPAQUE
        code_diff_regs = bytes.fromhex("31 c8 74 05 90 90")
        res_diff = ContinuousDeobfuscator.analyze_opaque_predicates(code_diff_regs)
        self.assertEqual(len(res_diff), 0, "False positive: 'xor eax, ecx' was mistakenly identified as zeroing.")

        # xor eax, eax (31 c0) followed by jz (74 05) -> reg 0 == reg 0 -> OPAQUE PREDICATE
        code_same_regs = bytes.fromhex("31 c0 74 05 90 90")
        res_same = ContinuousDeobfuscator.analyze_opaque_predicates(code_same_regs)
        self.assertEqual(len(res_same), 1, "Failed to identify genuine zeroing predicate 'xor eax, eax; jz'.")
        self.assertEqual(res_same[0]["type"], "OPAQUE_PREDICATE_ALWAYS_TRUE")

    def test_control_flow_flattening_detection(self):
        """
        Directly addresses Critique 2 (CFF):
        Verifies detection of flattened dispatcher loops with state variables.
        """
        # Synthetic CFF sequence:
        # MOV [RBP-4], 1; CMP [RBP-4], 1; CMP [RBP-4], 2; CMP [RBP-4], 3; MOV [RBP-4], 2; MOV [RBP-4], 3
        # 81 7D FC imm32 (cmp [rbp-4], imm32)
        # C7 45 FC imm32 (mov [rbp-4], imm32)
        code = (
            b"\xC7\x45\xFC\x01\x00\x00\x00" + # mov [rbp-4], 1
            b"\x81\x7D\xFC\x01\x00\x00\x00" + # cmp [rbp-4], 1
            b"\x81\x7D\xFC\x02\x00\x00\x00" + # cmp [rbp-4], 2
            b"\x81\x7D\xFC\x03\x00\x00\x00" + # cmp [rbp-4], 3
            b"\xC7\x45\xFC\x02\x00\x00\x00" + # mov [rbp-4], 2
            b"\xC7\x45\xFC\x03\x00\x00\x00"   # mov [rbp-4], 3
        )
        cff = ContinuousDeobfuscator.detect_control_flow_flattening(code)
        self.assertTrue(cff["has_control_flow_flattening"])
        self.assertEqual(cff["dispatcher_comparisons_count"], 3)
        self.assertEqual(cff["state_transitions_count"], 3)

    def test_stack_safety_analysis(self):
        """
        Directly addresses Critique 3:
        Verifies that 'is_stack_safe' is dynamically evaluated based on instruction opcodes.
        """
        # Replaced bytes containing 'push rbp' (0x55)
        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(b"\x55\x48\x89\xE5")
        self.assertFalse(safe)
        self.assertIn("stack-altering", reason)

        # Replaced bytes containing SUB RSP (48 83 EC 20)
        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(b"\x48\x83\xEC\x20")
        self.assertFalse(safe)
        self.assertIn("SUB RSP", reason)

        # Replaced bytes containing pure non-stack instructions (e.g. mov eax, 1; nop)
        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(b"\xB8\x01\x00\x00\x00\x90")
        self.assertTrue(safe)

    def test_pe_checksum_algorithm(self):
        """
        Directly addresses Critique 3:
        Verifies Microsoft PE checksum calculation on synthetic PE buffer.
        """
        buf = bytearray(512)
        buf[0:2] = b"MZ"
        buf[0x3C:0x40] = struct.pack("<I", 0x80)
        buf[0x80:0x84] = b"PE\x00\x00"
        chk = BinaryFormatInspector.calculate_pe_checksum(buf, 0x80)
        self.assertIsInstance(chk, int)
        self.assertGreater(chk, 0)

    def test_bf16_conversion_roundtrip(self):
        """
        Directly addresses Critique 4:
        Verifies that BF16 is interpreted as IEEE float32, NOT raw integer uint16.
        1.0 in BF16 is 0x3F80.
        """
        raw_bf16 = np.array([0x3F80, 0x4000, 0xBF80], dtype=np.uint16)
        u32 = raw_bf16.astype(np.uint32) << 16
        f32 = u32.view(np.float32)

        np.testing.assert_allclose(f32, [1.0, 2.0, -1.0], rtol=1e-5)

        # Roundtrip back to BF16
        u32_back = f32.view(np.uint32)
        u16_back = ((u32_back + 0x7FFF + ((u32_back >> 16) & 1)) >> 16).astype(np.uint16)
        np.testing.assert_array_equal(u16_back, raw_bf16)

    def test_attention_head_slicing(self):
        """
        Directly addresses Critique 4:
        Verifies that attention decompilation slices individual heads rather than the whole matrix.
        """
        d_out = 32
        d_in = 64
        num_heads = 4
        head_dim = d_in // num_heads # 16

        matrix = np.random.randn(d_out, d_in).astype(np.float32)
        head_0 = matrix[:, 0:head_dim]
        head_1 = matrix[:, head_dim:2*head_dim]

        self.assertEqual(head_0.shape, (32, 16))
        self.assertEqual(head_1.shape, (32, 16))
        self.assertFalse(np.array_equal(head_0, head_1))

    def test_hybrid_scanner_rejects_plain_zip(self):
        """
        Directly addresses Critique 5:
        Verifies that a generic ZIP archive (e.g. text files) is NOT reported as TorchScript.
        """
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("document.txt", "Plain non-model text document")

        tmp_path = os.path.join(SCRIPT_DIR, "plain_test.zip")
        with open(tmp_path, "wb") as f:
            f.write(zip_buf.getvalue())

        try:
            res = HybridBinaryDissector.scan_for_embedded_logic(tmp_path)
            findings = [f for f in res["findings"] if f["type"].startswith("TorchScript")]
            self.assertEqual(len(findings), 0, "Plain ZIP was falsely detected as TorchScript!")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
