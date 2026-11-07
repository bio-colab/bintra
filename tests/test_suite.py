import unittest
import sys
import os
import struct
import io
import zipfile
import tempfile
import subprocess
import json
import numpy as np

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from binary_neural_engine import (
    ContinuousDeobfuscator,
    SemanticFunctionMatcher,
    BinaryFormatInspector,
    SurgicalBinaryPatcher,
    HybridBinaryDissector
)
from rea_neural_engine import (
    SafetensorsHandler,
    SubspaceAnalyzer,
    CircuitDecompiler,
    WeightPatcher,
    ActivationTraceProber,
    NeuralBehaviorVerifier,
)
from binary_neural_engine import SensoryCortex


def _create_synthetic_pe64() -> bytearray:
    """Builds a valid synthetic Windows PE32+ (64-bit) image with .text and .rdata sections."""
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    pe_offset = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_offset)
    buf[pe_offset : pe_offset + 4] = b"PE\x00\x00"

    # COFF Header: AMD64 (0x8664), 2 sections, opt_hdr_size = 240 (0xF0), chars = 0x0022
    struct.pack_into("<HHIIIHH", buf, pe_offset + 4, 0x8664, 2, 0x65000000, 0, 0, 0xF0, 0x0022)

    opt_offset = pe_offset + 24
    # PE32+ Magic = 0x20B, EntryPoint RVA = 0x1000, ImageBase = 0x140000000
    struct.pack_into("<H", buf, opt_offset, 0x20B)
    struct.pack_into("<I", buf, opt_offset + 16, 0x1000)
    struct.pack_into("<Q", buf, opt_offset + 24, 0x140000000)
    # Subsystem = 3 (CUI), DllCharacteristics = 0x4160 (HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | GUARD_CF)
    struct.pack_into("<HH", buf, opt_offset + 68, 3, 0x4160)
    struct.pack_into("<I", buf, opt_offset + 108, 16)  # NumberOfRvaAndSizes
    # Import Table Data Directory (index 1)
    struct.pack_into("<II", buf, opt_offset + 112 + 8, 0x2000, 0x40)

    sec_table = opt_offset + 0xF0
    # Section 1: .text at RVA 0x1000, RawOffset 0x200, RawSize 0x200, Executable (0x60000020)
    buf[sec_table : sec_table + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec_table + 8, 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    # Section 2: .rdata at RVA 0x2000, RawOffset 0x400, RawSize 0x200, Read-Only (0x40000040)
    sec2 = sec_table + 40
    buf[sec2 : sec2 + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIIIIIHHI", buf, sec2 + 8, 0x200, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0x40000040)

    # Put valid x64 function inside .text (0x200)
    code = bytes.fromhex("55 48 89 e5 48 31 c0 74 05 b8 55 00 00 00 5d c3")
    buf[0x200 : 0x200 + len(code)] = code
    # Put DirectML signature inside .rdata (0x400)
    sig = b"DirectML.dll\x00DMLCreateDevice\x00"
    buf[0x400 : 0x400 + len(sig)] = sig

    chk = BinaryFormatInspector.calculate_pe_checksum(buf, pe_offset)
    struct.pack_into("<I", buf, opt_offset + 64, chk)
    return buf


class TestRigorousEngineEvaluation(unittest.TestCase):

    # --- Original 9 Baseline Tests ---

    def test_random_bytes_similarity_baseline(self):
        np.random.seed(42)
        similarities = []
        for _ in range(50):
            b1 = os.urandom(128).hex()
            b2 = os.urandom(128).hex()
            res = SemanticFunctionMatcher.match_functions(b1, b2)
            similarities.append(res["cosine_similarity"])
            self.assertFalse(res["is_semantic_match"])

        self.assertEqual(float(np.mean(similarities)), 0.0)
        self.assertEqual(float(np.max(similarities)), 0.0)

    def test_real_semantic_function_matching(self):
        f1 = "55 48 89 e5 89 7d fc 8b 45 fc 83 c0 01 5d c3"
        f2 = "55 48 89 e5 8d 47 01 5d c3"
        res = SemanticFunctionMatcher.match_functions(f1, f2)
        self.assertTrue(res["is_semantic_match"])
        self.assertGreater(res["cosine_similarity"], 0.85)

    def test_opaque_predicate_strict_register_equality(self):
        code_diff_regs = bytes.fromhex("31 c8 74 05 90 90")
        res_diff = ContinuousDeobfuscator.analyze_opaque_predicates(code_diff_regs)
        self.assertEqual(len(res_diff), 0)

        code_same_regs = bytes.fromhex("31 c0 74 05 90 90")
        res_same = ContinuousDeobfuscator.analyze_opaque_predicates(code_same_regs)
        self.assertEqual(len(res_same), 1)
        self.assertEqual(res_same[0]["type"], "OPAQUE_PREDICATE_ALWAYS_TRUE")

    def test_control_flow_flattening_detection(self):
        code = (
            b"\xC7\x45\xFC\x01\x00\x00\x00" +
            b"\x81\x7D\xFC\x01\x00\x00\x00" +
            b"\x81\x7D\xFC\x02\x00\x00\x00" +
            b"\x81\x7D\xFC\x03\x00\x00\x00" +
            b"\xC7\x45\xFC\x02\x00\x00\x00" +
            b"\xC7\x45\xFC\x03\x00\x00\x00"
        )
        cff = ContinuousDeobfuscator.detect_control_flow_flattening(code)
        self.assertTrue(cff["has_control_flow_flattening"])
        self.assertEqual(cff["dispatcher_comparisons_count"], 3)
        self.assertEqual(cff["state_transitions_count"], 3)
        self.assertGreater(cff["dispatcher_cadence_regularity"], 0.5)

    def test_stack_safety_analysis(self):
        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(b"\x55\x48\x89\xE5")
        self.assertFalse(safe)
        self.assertIn("stack-altering", reason)

        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(b"\x48\x83\xEC\x20")
        self.assertFalse(safe)
        self.assertIn("SUB RSP", reason)

        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(b"\xB8\x01\x00\x00\x00\x90")
        self.assertTrue(safe)

    def test_pe_checksum_algorithm(self):
        buf = bytearray(512)
        buf[0:2] = b"MZ"
        buf[0x3C:0x40] = struct.pack("<I", 0x80)
        buf[0x80:0x84] = b"PE\x00\x00"
        chk = BinaryFormatInspector.calculate_pe_checksum(buf, 0x80)
        self.assertIsInstance(chk, int)
        self.assertGreater(chk, 0)

    def test_bf16_conversion_roundtrip(self):
        raw_bf16 = np.array([0x3F80, 0x4000, 0xBF80], dtype=np.uint16)
        u32 = raw_bf16.astype(np.uint32) << 16
        f32 = u32.view(np.float32)
        np.testing.assert_allclose(f32, [1.0, 2.0, -1.0], rtol=1e-5)

        u32_back = f32.view(np.uint32)
        u16_back = ((u32_back + 0x7FFF + ((u32_back >> 16) & 1)) >> 16).astype(np.uint16)
        np.testing.assert_array_equal(u16_back, raw_bf16)

    def test_attention_head_slicing(self):
        d_out, d_in, num_heads = 32, 64, 4
        head_dim = d_in // num_heads
        matrix = np.random.randn(d_out, d_in).astype(np.float32)
        head_0 = matrix[:, 0:head_dim]
        head_1 = matrix[:, head_dim:2*head_dim]
        self.assertEqual(head_0.shape, (32, 16))
        self.assertEqual(head_1.shape, (32, 16))
        self.assertFalse(np.array_equal(head_0, head_1))

    def test_hybrid_scanner_rejects_plain_zip(self):
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as z:
            z.writestr("document.txt", "Plain non-model text document")

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            tf.write(zip_buf.getvalue())
            tmp_path = tf.name

        try:
            res = HybridBinaryDissector.scan_for_embedded_logic(tmp_path)
            findings = [f for f in res["findings"] if f["type"].startswith("TorchScript")]
            self.assertEqual(len(findings), 0)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # --- 16 New Patch & 10-Sense Verification Tests ---

    def test_safetensors_read_and_in_place_write_f32_and_bf16(self):
        """Verifies Fix #1 & #2: SafetensorsHandler.read_tensor works via mmap and supports in-place writes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            st_path = os.path.join(tmpdir, "model.safetensors")
            arr_f32 = np.arange(16, dtype=np.float32).reshape(4, 4)
            arr_bf16_vals = np.array([[1.0, -2.0], [0.5, 4.0]], dtype=np.float32)
            bf16_bytes = SafetensorsHandler._float32_to_bf16_bytes(arr_bf16_vals)
            f32_bytes = arr_f32.tobytes()

            header = {
                "weight_f32": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, len(f32_bytes)]},
                "weight_bf16": {
                    "dtype": "BF16",
                    "shape": [2, 2],
                    "data_offsets": [len(f32_bytes), len(f32_bytes) + len(bf16_bytes)]
                }
            }
            hdr_json = json.dumps(header).encode("utf-8")
            with open(st_path, "wb") as f:
                f.write(struct.pack("<Q", len(hdr_json)))
                f.write(hdr_json)
                f.write(f32_bytes)
                f.write(bf16_bytes)

            loaded_f32, _ = SafetensorsHandler.read_tensor(st_path, "weight_f32")
            loaded_bf16, _ = SafetensorsHandler.read_tensor(st_path, "weight_bf16")
            np.testing.assert_allclose(loaded_f32, arr_f32)
            np.testing.assert_allclose(loaded_bf16, arr_bf16_vals, rtol=1e-2)

            # In-place write on the exact same path must not truncate or corrupt!
            patched_f32, _ = WeightPatcher.rank1_nullify(loaded_f32, mode_index=0, alpha=0.5)
            res = SafetensorsHandler.write_patched_safetensors(st_path, st_path, {"weight_f32": patched_f32})
            self.assertTrue(res["in_place_atomic_safe"])

            reloaded_f32, _ = SafetensorsHandler.read_tensor(st_path, "weight_f32")
            reloaded_bf16, _ = SafetensorsHandler.read_tensor(st_path, "weight_bf16")
            np.testing.assert_allclose(reloaded_f32, patched_f32)
            np.testing.assert_allclose(reloaded_bf16, arr_bf16_vals, rtol=1e-2)

    def test_rex_prefix_register_zeroing_discrimination(self):
        """Verifies Fix #3: 'xor r8, rax' (49 31 C0) is NOT register zeroing, whereas 'xor r8, r8' (4D 31 C0) IS."""
        # 49 31 c0 74 05 -> xor r8, rax; jz +5 (NOT opaque!)
        code_r8_rax = bytes.fromhex("49 31 c0 74 05 90")
        res1 = ContinuousDeobfuscator.analyze_opaque_predicates(code_r8_rax)
        self.assertEqual(len(res1), 0, "49 31 C0 (xor r8, rax) must not be flagged as zeroing!")

        # 4D 31 c0 74 05 -> xor r8, r8; jz +5 (OPAQUE!)
        code_r8_r8 = bytes.fromhex("4d 31 c0 74 05 90")
        res2 = ContinuousDeobfuscator.analyze_opaque_predicates(code_r8_r8)
        self.assertEqual(len(res2), 1)
        self.assertEqual(res2[0]["offset"], 0)
        self.assertEqual(res2[0]["length"], 5)
        self.assertIn("R8", res2[0]["zeroing_instruction"])

    def test_instruction_boundary_stack_proprioception_no_false_positive(self):
        """Verifies Fix #4: Immediate byte 0x55 inside 'mov eax, 0x55' (B8 55 00 00 00) is NOT flagged as PUSH RBP."""
        code_mov_imm_55 = bytes.fromhex("b8 55 00 00 00 90")
        safe, reason = SurgicalBinaryPatcher.verify_stack_safety(code_mov_imm_55)
        self.assertTrue(safe, f"Immediate 0x55 inside MOV EAX, 0x55 was falsely flagged: {reason}")

    def test_pe64_deep_inspection_and_rva_mapping(self):
        """Verifies Fix #5: PE32+ (64-bit) inspection, mitigations, and RVA <-> Offset spatial sense."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(pe_bytes)
            pe_path = tf.name

        try:
            info = BinaryFormatInspector.inspect(pe_path)
            self.assertEqual(info["format"], "PE")
            self.assertEqual(info["pe_type"], "PE32+ (64-bit)")
            self.assertEqual(info["entry_point_rva"], "0x1000")
            self.assertEqual(info["entry_point_file_offset"], "0x200")
            self.assertTrue(info["windows_security_mitigations"]["aslr_dynamic_base"])
            self.assertTrue(info["windows_security_mitigations"]["dep_nx_compat"])
            self.assertTrue(info["windows_security_mitigations"]["control_flow_guard_cfg"])
            self.assertIn("ImportTable", info["data_directories"])

            # Spatial RVA <-> File Offset roundtrip
            off = BinaryFormatInspector.rva_to_offset(info, 0x1010)
            self.assertEqual(off, 0x210)
            rva_back = BinaryFormatInspector.offset_to_rva(info, 0x210)
            self.assertEqual(rva_back, 0x1010)
        finally:
            if os.path.exists(pe_path):
                os.remove(pe_path)

    def test_directml_and_entropy_hybrid_detection(self):
        """Verifies Fix #6: HybridBinaryDissector detects Windows DirectML signatures and computes entropy."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(pe_bytes)
            pe_path = tf.name

        try:
            res = HybridBinaryDissector.scan_for_embedded_logic(pe_path)
            self.assertTrue(res["is_hybrid_binary"])
            ids = [f["identifier"] for f in res["findings"]]
            self.assertIn("DirectML_DLL", ids)
            self.assertIn("DirectML_API", ids)
            self.assertGreater(res["overall_shannon_entropy"], 0.0)
        finally:
            if os.path.exists(pe_path):
                os.remove(pe_path)

    def test_subspace_sparse_extremes_and_coordinate_slice(self):
        """Verifies Fix #7a: SubspaceAnalyzer supports sparse_extremes and coordinate_slice modes."""
        mat = np.zeros((8, 8), dtype=np.float32)
        mat[3, 5] = 42.0
        ext = SubspaceAnalyzer.inspect_subspace(mat, mode="sparse_extremes", top_k=2)
        self.assertEqual(ext["extremes"][0]["coordinates"], [3, 5])
        self.assertAlmostEqual(ext["extremes"][0]["value"], 42.0)

        slc = SubspaceAnalyzer.inspect_subspace(mat, mode="coordinate_slice", top_k=4)
        self.assertEqual(slc["slice_shape"], [4, 4])

    def test_circuit_decompiler_mlp_and_layernorm(self):
        """Verifies Fix #7b: CircuitDecompiler supports mlp_projection and layer_norm_drift."""
        mlp_mat = np.random.randn(16, 16).astype(np.float32)
        mlp_res = CircuitDecompiler.decompile_mlp_projection(mlp_mat, layer_idx=5)
        self.assertEqual(mlp_res["circuit_type"], "mlp_projection")
        self.assertIn("Layer_5_MLP", mlp_res["pseudocode"])

        ln_vec = np.ones(16, dtype=np.float32)
        ln_vec[2] = 12.0
        ln_res = CircuitDecompiler.decompile_layer_norm_drift(ln_vec, layer_idx=5)
        self.assertEqual(ln_res["circuit_type"], "layer_norm_drift")
        self.assertTrue(ln_res["is_anomaly"])

    def test_weight_patcher_all_schema_operations(self):
        """Verifies Fix #7c: WeightPatcher supports sparse_clamp, subspace_zero, and vector_add."""
        mat = np.random.randn(12, 12).astype(np.float32)
        mat[0, 0] = 100.0
        p1, m1 = WeightPatcher.apply_patch(mat, "sparse_clamp", {"threshold_z": 2.5, "clamp_value": 0.0})
        self.assertEqual(m1["operation"], "sparse_clamp")
        self.assertEqual(float(p1[0, 0]), 0.0)

        p2, m2 = WeightPatcher.apply_patch(mat, "subspace_zero", {"mode_indices": [0]})
        self.assertEqual(m2["operation"], "subspace_zero")
        self.assertLess(np.linalg.norm(p2), np.linalg.norm(mat))

        p3, m3 = WeightPatcher.apply_patch(mat, "vector_add", {"mode_index": 0, "beta": 0.1})
        self.assertEqual(m3["operation"], "vector_add")

    def test_temporal_hearing_activation_trace_prober(self):
        """Verifies Sense #2 (Temporal Hearing) & probe_activation_trace.json implementation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            st_path = os.path.join(tmpdir, "trace_model.safetensors")
            mat = np.diag([10.0, 1.0, 0.5, 0.2]).astype(np.float32)
            raw = mat.tobytes()
            hdr = json.dumps({"layers.0.attn.o_proj": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, len(raw)]}}).encode("utf-8")
            with open(st_path, "wb") as f:
                f.write(struct.pack("<Q", len(hdr)))
                f.write(hdr)
                f.write(raw)

            res = ActivationTraceProber.probe_trace(st_path, prompt="test loop prompt", max_tokens=10)
            self.assertEqual(res["steps_simulated"], 10)
            self.assertTrue(res["loop_attractor_detected"])

    def test_vestibular_balance_neural_behavior_verifier(self):
        """Verifies Sense #8 (Vestibular Balance) & verify_neural_behavior.json implementation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_p = os.path.join(tmpdir, "base.safetensors")
            patch_p = os.path.join(tmpdir, "patch.safetensors")
            mat = (np.eye(8, dtype=np.float32) * 10.0)
            raw = mat.tobytes()
            hdr = json.dumps({"w": {"dtype": "F32", "shape": [8, 8], "data_offsets": [0, len(raw)]}}).encode("utf-8")
            for p in (base_p, patch_p):
                with open(p, "wb") as f:
                    f.write(struct.pack("<Q", len(hdr)))
                    f.write(hdr)
                    f.write(raw)

            perturbed = mat.copy()
            perturbed[0, 0] += 0.01
            SafetensorsHandler.write_patched_safetensors(base_p, patch_p, {"w": perturbed})
            ver = NeuralBehaviorVerifier.verify_behavior(base_p, patch_p, tolerance=0.005)
            self.assertTrue(ver["is_equilibrium_preserved"])

    def test_nociceptive_pain_reflex_blocks_unsafe_patch(self):
        """Verifies Sense #9 (Metaphorical Pain): enforce_nociception blocks stack-destroying patches."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(pe_bytes)
            pe_path = tf.name

        try:
            with self.assertRaises(RuntimeError):
                SurgicalBinaryPatcher.patch_file(pe_path, pe_path, 0x200, "90", enforce_nociception=True)
        finally:
            if os.path.exists(pe_path):
                os.remove(pe_path)

    def test_sensory_cortex_all_10_senses_on_pe64(self):
        """Verifies that SensoryCortex evaluates all 10 Metaphorical Senses with high efficiency."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(pe_bytes)
            pe_path = tf.name

        try:
            report = SensoryCortex.evaluate_all_senses(file_path=pe_path)
            self.assertEqual(report["active_senses_count"], 10)
            self.assertGreaterEqual(report["overall_sensory_efficiency"], 0.90)
            expected_keys = {
                "analytical_vision", "temporal_hearing", "active_touch",
                "exploratory_smell", "discriminative_taste", "deep_proprioception",
                "spatial_sense", "vestibular_balance", "metaphorical_pain", "sense_of_rhythm"
            }
            self.assertEqual(set(report["senses"].keys()), expected_keys)
            for sense_data in report["senses"].values():
                self.assertTrue(sense_data["present"])
                self.assertGreaterEqual(sense_data["efficiency_score"], 0.90)
        finally:
            if os.path.exists(pe_path):
                os.remove(pe_path)

    def test_sensory_cortex_on_safetensors_model(self):
        """Verifies that SensoryCortex evaluates all 10 Metaphorical Senses on a Safetensors model."""
        with tempfile.TemporaryDirectory() as tmpdir:
            st_path = os.path.join(tmpdir, "cortex_model.safetensors")
            mat = np.eye(8, dtype=np.float32) * 2.0
            raw = mat.tobytes()
            hdr = json.dumps({"layers.0.attn.o_proj": {"dtype": "F32", "shape": [8, 8], "data_offsets": [0, len(raw)]}}).encode("utf-8")
            with open(st_path, "wb") as f:
                f.write(struct.pack("<Q", len(hdr)))
                f.write(hdr)
                f.write(raw)
            report = SensoryCortex.evaluate_all_senses(file_path=st_path)
            self.assertEqual(report["active_senses_count"], 10)
            self.assertEqual(report["senses"]["analytical_vision"]["telemetry"]["target_modality"], "SAFETENSORS_MODEL")

    def test_in_place_binary_patching_atomic_windows_safety(self):
        """Verifies that SurgicalBinaryPatcher safely patches a Windows PE64 binary in-place and maps RVA."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tf:
            tf.write(pe_bytes)
            pe_path = tf.name
        try:
            res = SurgicalBinaryPatcher.patch_file(pe_path, pe_path, 0x208, "90 90")
            self.assertTrue(res["is_stack_safe"])
            self.assertTrue(res["pe_checksum_recalculated"])
            self.assertEqual(res["virtual_rva"], "0x1008")
            self.assertEqual(res["target_section"], ".text")
        finally:
            if os.path.exists(pe_path):
                os.remove(pe_path)

    def test_arm64_instruction_decoding_and_vectorization(self):
        """Verifies ARM64 instruction decoding and behavioral vectorization."""
        arm64_hex = "ff 43 00 d1 00 04 00 11 ff 43 00 91 c0 03 5f d6"
        vec = SemanticFunctionMatcher.vectorize_function(arm64_hex)
        self.assertGreater(float(np.linalg.norm(vec)), 0.9)

    def test_cli_sense_command_end_to_end(self):
        """Verifies that 'python src/cli.py sense --hex ...' executes cleanly and outputs valid UTF-8 JSON."""
        cli_path = os.path.join(SRC_DIR, "cli.py")
        proc = subprocess.run(
            [sys.executable, cli_path, "sense", "--hex", "55 48 89 e5 48 31 c0 74 05 b8 55 00 00 00 5d c3"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True
        )
        data = json.loads(proc.stdout)
        self.assertEqual(data["active_senses_count"], 10)


if __name__ == "__main__":
    unittest.main()
