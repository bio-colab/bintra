import unittest
import sys
import os
import shutil
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
from bintra_engine import (
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

            # Policy enforcement: In-place write on same path is strictly forbidden
            from security.execution_guard import TargetMutationError
            patched_f32, _ = WeightPatcher.rank1_nullify(loaded_f32, mode_index=0, alpha=0.5)
            with self.assertRaises(TargetMutationError):
                SafetensorsHandler.write_patched_safetensors(st_path, st_path, {"weight_f32": patched_f32})

            # Out-of-place write succeeds to separate workspace and preserves original file
            from security import ExecutionGuard
            work_dir = tempfile.mkdtemp(prefix="bintra_ws_")
            try:
                out_st_path = os.path.join(work_dir, "patched_model.safetensors")
                with ExecutionGuard.scoped_session(target_binary_path=st_path, workspace_dir=work_dir):
                    res = SafetensorsHandler.write_patched_safetensors(st_path, out_st_path, {"weight_f32": patched_f32})
                self.assertEqual(res["output_path"], out_st_path)
                self.assertTrue(os.path.exists(out_st_path))

                reloaded_f32, _ = SafetensorsHandler.read_tensor(out_st_path, "weight_f32")
                reloaded_bf16, _ = SafetensorsHandler.read_tensor(out_st_path, "weight_bf16")
            finally:
                shutil.rmtree(work_dir, ignore_errors=True)
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

            from security import ExecutionGuard
            work_dir = tempfile.mkdtemp(prefix="bintra_ws_")
            try:
                out_patch_p = os.path.join(work_dir, "patch.safetensors")
                perturbed = mat.copy()
                perturbed[0, 0] += 0.01
                with ExecutionGuard.scoped_session(target_binary_path=base_p, workspace_dir=work_dir):
                    SafetensorsHandler.write_patched_safetensors(base_p, out_patch_p, {"w": perturbed})
                ver = NeuralBehaviorVerifier.verify_behavior(base_p, out_patch_p, tolerance=0.005)
                self.assertTrue(ver["is_equilibrium_preserved"])
            finally:
                shutil.rmtree(work_dir, ignore_errors=True)

    def test_nociceptive_pain_reflex_blocks_unsafe_patch(self):
        """Verifies Sense #9 (Metaphorical Pain): enforce_nociception blocks stack-destroying patches."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir:
            pe_path = os.path.join(tgt_dir, "test.exe")
            with open(pe_path, "wb") as f:
                f.write(pe_bytes)
            out_path = os.path.join(ws_dir, "out_patched.exe")

            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(target_binary_path=pe_path, workspace_dir=ws_dir):
                with self.assertRaises(RuntimeError):
                    SurgicalBinaryPatcher.patch_file(pe_path, out_path, 0x200, "90", enforce_nociception=True)

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
        """Verifies that SurgicalBinaryPatcher enforces target immutability on in-place calls and safely patches out-of-place."""
        pe_bytes = _create_synthetic_pe64()
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir:
            pe_path = os.path.join(tgt_dir, "test.exe")
            with open(pe_path, "wb") as f:
                f.write(pe_bytes)
            out_path = os.path.join(ws_dir, "out_patched.exe")

            from security.execution_guard import TargetMutationError
            with self.assertRaises(TargetMutationError):
                SurgicalBinaryPatcher.patch_file(pe_path, pe_path, 0x208, "90 90")

            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(target_binary_path=pe_path, workspace_dir=ws_dir):
                res = SurgicalBinaryPatcher.patch_file(pe_path, out_path, 0x208, "90 90")
            self.assertTrue(res["is_stack_safe"])
            self.assertTrue(res["pe_checksum_recalculated"])
            self.assertEqual(res["virtual_rva"], "0x1008")
            self.assertEqual(res["target_section"], ".text")
            self.assertTrue(os.path.exists(out_path))

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



    # --- 10 New MIT CSAIL WSP Paper Alignment Tests (Total: 35 Tests) ---

    def test_wsp_exp8_mlp_column_direction_subtract_exact_sparsity(self):
        """Verifies Exp 8 (Page 16): Subtracting loop direction from exactly K columns in MLP matrices."""
        mlp = np.random.randn(256, 512).astype(np.float32)
        patched, metrics = WeightPatcher.column_direction_subtract(mlp, mode_index=0, num_columns=64, alpha=1.0)
        self.assertEqual(metrics["operation"], "column_direction_subtract")
        self.assertEqual(metrics["num_columns_edited"], 64)
        col_diffs = np.linalg.norm(patched - mlp, axis=0)
        changed_cols = int(np.sum(col_diffs > 1e-6))
        self.assertEqual(changed_cols, 64, "Exactly 64 columns must be modified as in Exp 8!")

    def test_wsp_exp3_effective_rank_romaji_vs_code_discrimination(self):
        """Verifies Exp 3 (Page 8): Effective Rank distinguishes restricted-alphabet (Romaji) from full-rank code."""
        from bintra_engine import CrossLayerCircuitAnalyzer
        rng = np.random.default_rng(123)
        u_low = rng.standard_normal((32, 5)).astype(np.float32)
        v_low = rng.standard_normal((5, 32)).astype(np.float32)
        romaji_like = u_low @ v_low
        full_code_like = rng.standard_normal((32, 32)).astype(np.float32)

        res_romaji = CrossLayerCircuitAnalyzer.compute_effective_rank(romaji_like)
        res_code = CrossLayerCircuitAnalyzer.compute_effective_rank(full_code_like)
        self.assertLess(res_romaji["effective_rank"], res_code["effective_rank"] * 0.4)
        self.assertIn("RESTRICTED_ALPHABET", res_romaji["inferred_domain_profile"])

    def test_wsp_exp3_cross_layer_induction_head_matrix_multiplication(self):
        """Verifies Exp 3 (Page 7-8): Cross-layer W_QK @ W_OV composition detects copying heads without running text."""
        from bintra_engine import CrossLayerCircuitAnalyzer
        early_ov = np.zeros((32, 32), dtype=np.float32)
        late_qk = np.zeros((32, 32), dtype=np.float32)
        early_ov[8:16, 8:16] = np.eye(8, dtype=np.float32) * 5.0
        late_qk[8:16, 8:16] = np.eye(8, dtype=np.float32) * 5.0
        res = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(early_ov, late_qk, num_heads=4)
        self.assertIn(1, res["copying_heads_detected"])

    def test_wsp_exp7_sycophancy_attention_pattern_auditor(self):
        """Verifies Exp 7 (Page 14-15): AttentionPatternAuditor separates honest vs. sycophantic heads."""
        from bintra_engine import AttentionPatternAuditor
        d = 16
        q_ans = np.zeros(d, dtype=np.float32)
        q_ans[0] = 1.0  # Answer query probes dimension 0
        k_quest = np.zeros((2, d), dtype=np.float32)
        k_quest[:, 1] = 2.0  # Question numbers live on dim 1
        k_sugg = np.zeros((2, d), dtype=np.float32)
        k_sugg[:, 2] = 2.0   # User suggestion lives on dim 2

        # Honest head routes dim 0 -> dim 1 (question facts)
        qk_honest = np.zeros((d, d), dtype=np.float32)
        qk_honest[0, 1] = 5.0
        res_honest = AttentionPatternAuditor.audit_sycophancy_attention(qk_honest, k_quest, k_sugg, q_ans)
        self.assertFalse(res_honest["is_sycophantic_head"])
        self.assertGreater(res_honest["question_tokens_attention_share"], 0.90)

        # Sycophantic head routes dim 0 -> dim 2 (user's suggested answer)
        qk_syc = np.zeros((d, d), dtype=np.float32)
        qk_syc[0, 2] = 5.0
        res_syc = AttentionPatternAuditor.audit_sycophancy_attention(qk_syc, k_quest, k_sugg, q_ans)
        self.assertTrue(res_syc["is_sycophantic_head"])
        self.assertGreater(res_syc["user_suggestion_attention_share"], 0.85)

    def test_wsp_gemma_vs_qwen_amenability_diagnostic(self):
        """Verifies Page 17 boundary condition: distinguishes amenable loop obstacle from capability deficit."""
        from bintra_engine import AmenabilityDiagnostic
        u = np.ones((16, 1), dtype=np.float32)
        v = np.ones((1, 16), dtype=np.float32)
        qwen_mat = (u @ v) * 10.0 + np.eye(16, dtype=np.float32) * 0.2
        res_qwen = AmenabilityDiagnostic.evaluate_surgical_amenability(qwen_mat, observed_loop_rate=0.93)
        self.assertTrue(res_qwen["is_amenable_to_weight_surgery"])

        gemma_mat = np.eye(16, dtype=np.float32)
        res_gemma = AmenabilityDiagnostic.evaluate_surgical_amenability(gemma_mat, observed_loop_rate=0.085)
        self.assertFalse(res_gemma["is_amenable_to_weight_surgery"])
        self.assertIn("CAPABILITY_DEFICIT_WARNING", res_gemma["wsp_prognosis"])

    def test_wsp_exp5_zero_shot_breakout_weight_synthesis(self):
        """Verifies Exp 5 (Page 10-11): Compiling Breakout policy weights from scratch without training."""
        from bintra_engine import WeightSpaceCompiler
        tensors = WeightSpaceCompiler.compile_breakout_policy_network(input_dim=32, hidden_dim=16, action_dim=3)
        self.assertEqual(set(tensors.keys()), {
            "policy.layer1.weight", "policy.layer1.bias",
            "policy.layer2.weight", "policy.layer2.bias"
        })
        self.assertEqual(tensors["policy.layer1.weight"].shape, (16, 32))
        self.assertEqual(tensors["policy.layer2.weight"].shape, (3, 16))
        self.assertGreater(float(np.linalg.norm(tensors["policy.layer1.weight"])), 1.0)

    def test_wsp_exp4_conditional_subcircuit_grafting_within_3_5_percent(self):
        """Verifies Exp 4 (Page 9-10): Grafting a conditional bypass sub-circuit modifying <= 3.5% weights."""
        from bintra_engine import CircuitGrafter
        host = np.random.randn(64, 64).astype(np.float32)
        host[10, :] *= 0.001  # dormant row
        patched, info = CircuitGrafter.graft_conditional_subcircuit(
            host, sensor_indices=[0, 1, 2], actuator_index=3, gain=-3.0, max_graft_fraction=0.035
        )
        self.assertTrue(info["within_exp4_sparsity_budget"])
        self.assertLessEqual(info["modified_percentage"], 3.5)
        self.assertFalse(np.array_equal(host, patched))

    def test_wsp_page19_cross_architecture_circuit_transplantation(self):
        """Verifies Page 19 'True architectural and model merging': grafting modes across different shapes."""
        from bintra_engine import CircuitGrafter
        host = np.eye(24, 32, dtype=np.float32)
        donor = np.ones((16, 16), dtype=np.float32) * 2.0
        merged, info = CircuitGrafter.transplant_reasoning_subspace(host, donor, rank_k=2, blend=0.2)
        self.assertEqual(merged.shape, (24, 32))
        self.assertEqual(info["transplanted_modes"], 2)
        self.assertGreater(info["frobenius_graft_ratio"], 0.0)

    def test_wsp_exp6_exp8_forward_pass_budgeted_harness_monotonic_gain(self):
        """Verifies Exp 6 & 8 (Page 12-16): ForwardPassHarness keeps edits only when score improves."""
        from bintra_engine import ForwardPassHarness
        rng = np.random.default_rng(7)
        w_init = rng.standard_normal((12, 16)).astype(np.float32)
        x_probes = rng.standard_normal((8, 16)).astype(np.float32)
        y_targ = rng.standard_normal((8, 12)).astype(np.float32)
        _, metrics = ForwardPassHarness.run_budgeted_optimization(
            w_init, x_probes, y_targ, forward_pass_budget=10, num_columns=8
        )
        self.assertEqual(metrics["forward_passes_used"], 10)
        self.assertGreaterEqual(metrics["final_score"], metrics["initial_score"])

    def test_wsp_page19_zero_eval_backdoor_and_receptive_field_audit(self):
        """Verifies Exp 1 & Page 19: Static weight auditing detects Trojan spikes and bottom-row paddle weights."""
        from bintra_engine import WeightSecurityAuditor
        mat = np.random.randn(32, 100).astype(np.float32) * 0.1
        mat[7, :] = 15.0
        res = WeightSecurityAuditor.audit_weights_without_evaluation(mat, spatial_height=10, spatial_width=10)
        self.assertTrue(res["potential_backdoor_detected"])
        self.assertIn(7, res["suspect_trigger_neurons"])


    # --- 5 Ghidra P-Code Continuous Semantic Vectorizer Tests (Total: 40 Tests) ---

    def test_ghidra_pcode_opcode_classification_and_vectorization(self):
        """Verifies Ghidra P-code operations vectorization into a 64-D unit sphere vector."""
        from ghidra_pcode_vectorizer import PcodeVectorizer, PCODE_CATEGORIES
        ops = [
            {"opcode": "INT_ADD", "inputs": ["a", "b"], "output": "c"},
            {"opcode": "INT_SUB", "inputs": ["c", "1"], "output": "c"},
            {"opcode": "CBRANCH", "inputs": ["ram_target", "c"]},
            {"opcode": "RETURN", "inputs": ["c"]}
        ]
        res = PcodeVectorizer.vectorize_pcode_ops(ops)
        vec = np.array(res["vector"], dtype=np.float32)
        self.assertEqual(len(vec), 64)
        self.assertAlmostEqual(float(np.linalg.norm(vec)), 1.0, places=4)
        self.assertGreater(res["effective_rank"], 1.0)
        self.assertEqual(res["op_count"], 4)
        self.assertEqual(res["category_histogram"]["ALU_ARITH"], 2)
        self.assertEqual(res["category_histogram"]["CONTROL_BRANCH_COND"], 1)
        self.assertEqual(res["category_histogram"]["CONTROL_RETURN"], 1)

    def test_ghidra_pcode_cross_architecture_semantic_matching(self):
        """Verifies architecture-invariant semantic matching of identical logic routines via P-code."""
        from ghidra_pcode_vectorizer import PcodeFunctionMatcher
        # Simulate x86-64 loop vs ARM64 loop in Ghidra P-code (both reduce to same SSA sequence)
        x86_pcode = [
            {"opcode": "LOAD", "inputs": ["rsp", "8"], "output": "u1"},
            {"opcode": "INT_ADD", "inputs": ["u1", "10"], "output": "u2"},
            {"opcode": "STORE", "inputs": ["rsp", "8", "u2"]},
            {"opcode": "INT_LESS", "inputs": ["u2", "100"], "output": "b1"},
            {"opcode": "CBRANCH", "inputs": ["0x140001000", "b1"]},
            {"opcode": "RETURN"}
        ]
        arm64_pcode = [
            {"opcode": "LOAD", "inputs": ["sp", "8"], "output": "v1"},
            {"opcode": "INT_ADD", "inputs": ["v1", "10"], "output": "v2"},
            {"opcode": "STORE", "inputs": ["sp", "8", "v2"]},
            {"opcode": "INT_LESS", "inputs": ["v2", "100"], "output": "c1"},
            {"opcode": "CBRANCH", "inputs": ["0x00010000", "c1"]},
            {"opcode": "RETURN"}
        ]
        match_res = PcodeFunctionMatcher.match(x86_pcode, arm64_pcode)
        self.assertTrue(match_res["is_semantic_match"])
        self.assertGreaterEqual(match_res["pcode_cosine_similarity"], 0.95)
        self.assertEqual(match_res["confidence"], "HIGH")

    def test_ghidra_pcode_divergent_function_rejection(self):
        """Verifies that divergent P-code routines are rejected with low cosine similarity."""
        from ghidra_pcode_vectorizer import PcodeFunctionMatcher
        arith_routine = [
            {"opcode": "INT_ADD"}, {"opcode": "INT_SUB"}, {"opcode": "INT_MULT"},
            {"opcode": "INT_DIV"}, {"opcode": "RETURN"}
        ]
        float_call_routine = [
            {"opcode": "FLOAT_ADD"}, {"opcode": "FLOAT_MULT"}, {"opcode": "CALL"},
            {"opcode": "CALLIND"}, {"opcode": "RETURN"}
        ]
        match_res = PcodeFunctionMatcher.match(arith_routine, float_call_routine)
        self.assertFalse(match_res["is_semantic_match"])
        self.assertEqual(match_res["confidence"], "LOW")
        self.assertLess(match_res["pcode_cosine_similarity"], 0.85)

    def test_ghidra_pcode_opaque_predicate_detection(self):
        """Verifies algebraic dead code and opaque predicate detection in P-code stream."""
        from ghidra_pcode_vectorizer import PcodeDeobfuscator
        pcode_stream = [
            {"opcode": "INT_XOR", "inputs": ["rax", "rax"], "output": "u_zero"},
            {"opcode": "CBRANCH", "inputs": ["target_dead", "u_zero"]},
            {"opcode": "INT_ADD", "inputs": ["rcx", "1"], "output": "rcx"},
            {"opcode": "RETURN"}
        ]
        report = PcodeDeobfuscator.detect_opaque_predicates(pcode_stream)
        self.assertTrue(report["is_obfuscated"])
        self.assertEqual(report["opaque_predicates_count"], 1)
        self.assertEqual(report["detected_predicates"][0]["predicate_type"], "ALGEBRAIC_ZERO_CBRANCH_OPAQUE")
        self.assertIn(1, report["prunable_operations"])

    def test_ghidra_annotation_plan_and_c_struct_synthesis(self):
        """Verifies Ghidra database mutation planning and C header struct synthesis for hybrid binaries."""
        from ghidra_pcode_vectorizer import GhidraAnnotationPlanner
        rename_plan = GhidraAnnotationPlanner.build_rename_plan("0x140001000", "DeobfuscatedKeyCheck")
        self.assertEqual(rename_plan["method"], "set_address_name")
        self.assertEqual(rename_plan["params"]["name"], "DeobfuscatedKeyCheck")

        annot_plan = GhidraAnnotationPlanner.build_function_annotation_plan(
            "0x140001000", "DeobfuscatedKeyCheck", return_type="int", comment="Bypassed by Bintra"
        )
        self.assertEqual(annot_plan["method"], "annotate_native_function")
        self.assertEqual(annot_plan["params"]["return_type"], "int")

        c_struct = GhidraAnnotationPlanner.build_hybrid_c_struct(
            "DirectML_Detector", ["input_tensor", "output_probs"], [[1, 3, 224, 224], [1, 1000]]
        )
        self.assertIn("struct DirectML_Detector", c_struct)
        self.assertIn("tensor_input_tensor", c_struct)
        self.assertIn("[1x3x224x224]", c_struct)

    def test_arm64_tightened_detection(self):
        """Verifies that stray 5f d6 bytes in x86 are not misclassified as ARM64 in SemanticFunctionMatcher."""
        from binary_neural_engine import SemanticFunctionMatcher
        # x86 snippet with stray 5f d6 in operand/immediate
        x86_hex = "55 48 89 e5 b8 5f d6 00 00 5d c3"
        vec_x86 = SemanticFunctionMatcher.vectorize_function(x86_hex)
        self.assertEqual(len(vec_x86), 16)
        # Genuine ARM64 instruction sequence ending with RET
        arm64_hex = "00 00 80 d2 c0 03 5f d6"
        vec_arm = SemanticFunctionMatcher.vectorize_function(arm64_hex)
        self.assertEqual(len(vec_arm), 16)

    def test_sensory_score_semantics_presence(self):
        """Verifies that sensory evaluation includes explicit score_semantics disclosure."""
        from binary_neural_engine import SensoryCortex
        cortex = SensoryCortex()
        report = cortex.evaluate_all_senses(code_hex="90 90 c3")
        self.assertIn("score_semantics", report)
        self.assertIn("STATIC capability-presence", report["score_semantics"])
        self.assertEqual(report["active_senses_count"], 10)

    def test_ghidra_analyze_program_export(self):
        """Verifies batch analysis of exported Ghidra High P-Code program payload."""
        from ghidra_pcode_vectorizer import GhidraAnnotationPlanner
        payload = {
            "program_name": "target_crackme.exe",
            "image_base": "0x140000000",
            "functions": [
                {
                    "name": "FUN_140001000",
                    "entry_point": "0x140001000",
                    "basic_blocks": [
                        {"id": 0, "start": "0x140001000", "true_out": 1, "false_out": 2},
                        {"id": 1, "start": "0x140001050"},
                        {"id": 2, "start": "0x140001060"}
                    ],
                    "pcode_ops": [
                        {"opcode": "INT_XOR", "inputs": ["rax", "rax"], "output": "u_zero", "block_id": 0},
                        {"opcode": "CBRANCH", "inputs": ["0x140001050", "u_zero"], "block_id": 0},
                        {"opcode": "RETURN", "block_id": 0}
                    ]
                },
                {
                    "name": "FUN_140002000",
                    "entry_point": "0x140002000",
                    "pcode_ops": [
                        {"opcode": "INT_ADD", "inputs": ["rcx", "rdx"], "output": "rax"},
                        {"opcode": "RETURN"}
                    ]
                }
            ]
        }
        plan = GhidraAnnotationPlanner.analyze_program_export(payload)
        self.assertEqual(plan["analyzed_functions"], 2)
        self.assertEqual(plan["obfuscated_functions"], 1)
        self.assertEqual(plan["opaque_predicates_total"], 1)
        self.assertEqual(len(plan["rename_actions"]), 1)
        self.assertEqual(plan["rename_actions"][0]["name"], "Bintra_Deob_FUN_140001000")
        self.assertEqual(len(plan["comment_actions"]), 1)

    def test_ghidra_bridge_scripts_exist(self):
        """Verifies that Ghidra bridge scripts exist and are well-formed."""
        from pathlib import Path
        repo_root = Path(__file__).resolve().parent.parent
        java_script = repo_root / "ghidra_scripts" / "BintraGhidraBridge.java"
        py_script = repo_root / "ghidra_scripts" / "bintra_extract_pcode.py"
        self.assertTrue(java_script.exists())
        self.assertTrue(py_script.exists())

        java_content = java_script.read_text(encoding="utf-8")
        self.assertIn("public class BintraGhidraBridge extends GhidraScript", java_content)
        self.assertIn("startTransaction", java_content)
        self.assertIn("ghidra-analyze", java_content)

    def test_mcp_server_initialize_and_tools_list(self):
        """Verifies that native MCP server implements JSON-RPC 2.0 handshake and 27 tools."""
        from mcp_server import BintraMcpServer, TOOLS_REGISTRY
        server = BintraMcpServer()
        init_res = server.handle_initialize({})
        self.assertEqual(init_res["serverInfo"]["name"], "bintra")
        self.assertIn(init_res["serverInfo"]["version"], ("1.1.0", "1.0.0"))

        tools_res = server.handle_tools_list({})
        self.assertIn("tools", tools_res)
        self.assertEqual(len(tools_res["tools"]), 42)
        tool_names = [t["name"] for t in tools_res["tools"]]
        self.assertIn("bintra_memory_scan", tool_names)
        self.assertIn("bintra_pointer_scan", tool_names)
        self.assertIn("bintra_struct_dissect", tool_names)
        self.assertIn("bintra_ghidra_live_bridge", tool_names)
        self.assertIn("bintra_device_driver_intelligence", tool_names)
        self.assertIn("bintra_process_resource_audit", tool_names)
        self.assertIn("bintra_hardware_audit", tool_names)
        self.assertIn("bintra_driver_audit", tool_names)
        self.assertIn("bintra_service_audit", tool_names)
        self.assertIn("bintra_dmp_inspect", tool_names)
        self.assertIn("bintra_etw_audit", tool_names)
        self.assertIn("bintra_evidence_graph", tool_names)
        self.assertIn("bintra_dump_bytes", tool_names)
        self.assertIn("bintra_inspect_binary", tool_names)
        self.assertIn("bintra_sensory_audit", tool_names)
        self.assertIn("bintra_ghidra_headless", tool_names)
        self.assertIn("bintra_windows_env_audit", tool_names)
        self.assertIn("bintra_resolve_dependencies", tool_names)
        self.assertIn("bintra_inspect_crash_reports", tool_names)
        self.assertIn("bintra_correlate_failure_evidence", tool_names)
        self.assertIn("bintra_win_catalog_cmd", tool_names)
        self.assertIn("bintra_registry_audit", tool_names)

    def test_mcp_server_dispatch_tool_call(self):
        """Verifies dispatching tools directly through MCP server protocol."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()
        audit_res = server.dispatch_tool("bintra_sensory_audit", {"code_hex": "55 48 89 e5 31 c0 5d c3"})
        self.assertEqual(audit_res["active_senses_count"], 10)
        self.assertIn("score_semantics", audit_res)

        deob_res = server.dispatch_tool("bintra_deobfuscate_binary", {"code_hex": "31 c0 74 02 90 90 c3"})
        self.assertIn("opaque_predicates_detected", deob_res)


    def test_semantic_matcher_short_identical_functions(self):
        """Verifies that identical assembly blocks (even short straight-line sequences) achieve high match."""
        from binary_neural_engine import SemanticFunctionMatcher
        # push ebp; mov ebp, esp
        res = SemanticFunctionMatcher.match_functions("558bec", "558bec")
        self.assertTrue(res["is_semantic_match"])
        self.assertEqual(res["cosine_similarity"], 1.0)
        self.assertEqual(res["confidence"], "HIGH")

    def test_inspect_nonexistent_file_returns_error_dict(self):
        """Verifies that inspecting a non-existent file returns a structured dict rather than crashing."""
        from binary_neural_engine import BinaryFormatInspector
        res = BinaryFormatInspector.inspect("C:/non_existent_fake_binary_12345.exe")
        self.assertEqual(res["format"], "FILE_NOT_FOUND")
        self.assertIn("error", res)

    def test_read_bytes_dump(self):
        """Verifies dumping raw bytes from file."""
        import tempfile, os
        from binary_neural_engine import SurgicalBinaryPatcher
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x55\x89\xe5\x90\x90\xc3")
            tmp = f.name
        try:
            dump_res = SurgicalBinaryPatcher.read_bytes(tmp, 0, 4)
            self.assertEqual(dump_res["hex"], "5589e590")
            self.assertEqual(dump_res["length"], 4)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def test_agents_md_documentation_exists(self):
        """Verifies that AGENTS.md operating guide exists in repository root."""
        from pathlib import Path
        repo_root = Path(__file__).resolve().parent.parent
        agents_md = repo_root / "AGENTS.md"
        self.assertTrue(agents_md.exists())
        text = agents_md.read_text(encoding="utf-8")
        self.assertIn("Autonomous AI Coding Agents", text)
        self.assertIn("Model Context Protocol (MCP)", text)


    def test_cfg_analyzer_topology_and_cff(self):
        """Verifies CFG topology extraction, cyclomatic complexity, and CFF dispatcher loop detection."""
        from ghidra_pcode_vectorizer import ControlFlowGraphAnalyzer
        # Synthetic CFG with a central dispatcher block (Block 1) with in-degree 3, out-degree 2
        blocks = [
            {"id": 0, "start": "0x140001000", "predecessors": [], "successors": [1]},
            {"id": 1, "start": "0x140001010", "predecessors": [0, 2, 3], "successors": [2, 3]},
            {"id": 2, "start": "0x140001030", "predecessors": [1], "successors": [1]},
            {"id": 3, "start": "0x140001050", "predecessors": [1], "successors": [1, 4]},
            {"id": 4, "start": "0x140001070", "predecessors": [3], "successors": []}
        ]
        cfg = ControlFlowGraphAnalyzer.analyze_cfg(blocks)
        self.assertEqual(cfg["block_count"], 5)
        self.assertEqual(cfg["edge_count"], 6)
        self.assertEqual(cfg["cyclomatic_complexity"], 3) # 6 - 5 + 2 = 3
        self.assertTrue(cfg["has_cff_backbone"])
        self.assertEqual(cfg["topology"], "FLATTENED_DISPATCHER")
        self.assertEqual(len(cfg["dispatcher_blocks"]), 1)
        self.assertEqual(cfg["dispatcher_blocks"][0]["block_id"], 1)

    def test_pcode_ssa_analyzer_varnodes(self):
        """Verifies High P-Code SSA Def-Use analysis and mathematical invariant proof."""
        from ghidra_pcode_vectorizer import PcodeSSAAnalyzer
        pcode_ops = [
            {
                "seq": 10,
                "address": "0x140001000",
                "opcode": "INT_XOR",
                "inputs": [
                    {"kind": "register", "name": "EAX", "size": 4},
                    {"kind": "register", "name": "EAX", "size": 4}
                ],
                "output": {"kind": "unique", "unique_id": 501, "size": 4}
            },
            {
                "seq": 11,
                "address": "0x140001005",
                "opcode": "CBRANCH",
                "inputs": [
                    {"kind": "ram", "offset": "0x140001050"},
                    {"kind": "unique", "unique_id": 501, "def_seq": 10, "size": 4}
                ],
                "block_id": 0
            }
        ]
        blocks = [
            {"id": 0, "start": "0x140001000", "true_out": 2, "false_out": 1},
            {"id": 1, "start": "0x140001010"},
            {"id": 2, "start": "0x140001050"}
        ]
        res = PcodeSSAAnalyzer.analyze_ssa_invariants(pcode_ops, blocks)
        self.assertTrue(res["is_obfuscated"])
        self.assertEqual(res["evidence_dossiers_count"], 1)
        dossier = res["evidence_dossiers"][0]
        self.assertEqual(dossier["dead_block_id"], 2)
        self.assertEqual(dossier["dead_block_address"], "0x140001050")
        self.assertIn("determines condition=0 in SSA", dossier["algebraic_proof"])

    def test_scope_decoupling_synthesize_weights(self):
        """Verifies that synthesize-weights is decoupled from active CLI commands per SCOPE.md."""
        import subprocess, sys
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cli_path = os.path.join(repo_root, "src", "cli.py")
        res = subprocess.run([sys.executable, cli_path, "synthesize-weights"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("decoupled_from_active_scope", res.stdout)
        self.assertIn("SCOPE.md", res.stdout)


    def test_ssa_analyzer_negative_different_register_definitions(self):
        """Negative Test: Verifies that registers with same name but different def_seq are NOT evaluated as identical."""
        from ghidra_pcode_vectorizer import PcodeSSAAnalyzer
        # EAX version 10 vs EAX version 25
        pcode_stream = [
            {
                "seq": 30,
                "address": "0x140001000",
                "opcode": "INT_XOR",
                "inputs": [
                    {"kind": "register", "name": "EAX", "size": 4, "def_seq": 10},
                    {"kind": "register", "name": "EAX", "size": 4, "def_seq": 25}
                ],
                "output": {"kind": "unique", "unique_id": 999, "size": 4}
            },
            {
                "seq": 31,
                "address": "0x140001005",
                "opcode": "CBRANCH",
                "inputs": [
                    {"kind": "ram", "offset": "0x140001050"},
                    {"kind": "unique", "unique_id": 999, "def_seq": 30, "size": 4}
                ],
                "block_id": 0
            }
        ]
        blocks = [
            {"id": 0, "start": "0x140001000", "true_out": 1, "false_out": 2},
            {"id": 1, "start": "0x140001050"},
            {"id": 2, "start": "0x140001060"}
        ]
        res = PcodeSSAAnalyzer.analyze_ssa_invariants(pcode_stream, blocks)
        # MUST NOT evaluate as opaque predicate because EAX_10 != EAX_25!
        self.assertFalse(res["is_obfuscated"])
        self.assertEqual(res["evidence_dossiers_count"], 0)
        self.assertEqual(len(res["prunable_operations"]), 0)

    def test_ssa_analyzer_requires_resolved_dead_block_in_cfg(self):
        """Verifies that an Evidence Dossier is NEVER emitted if the branch target block is unresolved in CFG."""
        from ghidra_pcode_vectorizer import PcodeSSAAnalyzer
        pcode_stream = [
            {
                "seq": 40,
                "address": "0x140001000",
                "opcode": "INT_XOR",
                "inputs": [
                    {"kind": "register", "name": "ECX", "size": 4, "def_seq": 5},
                    {"kind": "register", "name": "ECX", "size": 4, "def_seq": 5}
                ],
                "output": {"kind": "unique", "unique_id": 777, "size": 4}
            },
            {
                "seq": 41,
                "address": "0x140001005",
                "opcode": "CBRANCH",
                "inputs": [
                    {"kind": "ram", "offset": "0x140009999"},
                    {"kind": "unique", "unique_id": 777, "def_seq": 40, "size": 4}
                ],
                "block_id": 0
            }
        ]
        # Basic blocks where block 0 has true_out = 999 (which does NOT exist in block_map)
        blocks = [
            {"id": 0, "start": "0x140001000", "true_out": 999, "false_out": 1},
            {"id": 1, "start": "0x140001020"}
        ]
        res = PcodeSSAAnalyzer.analyze_ssa_invariants(pcode_stream, blocks)
        # Unresolved dead block MUST result in 0 evidence dossiers
        self.assertEqual(res["evidence_dossiers_count"], 0)

    def test_cfg_dfs_cycle_detection_non_sequential_ids(self):
        """Verifies graph-theoretic DFS cycle detection on non-sequential / reversed block IDs."""
        from ghidra_pcode_vectorizer import ControlFlowGraphAnalyzer
        # Arbitrary block IDs: Block 50 -> Block 20 -> Block 99 -> Block 50
        blocks = [
            {"id": 50, "start": "0x140001000", "in_degree": 1, "out_degree": 1, "successors": [20], "predecessors": [99]},
            {"id": 20, "start": "0x140001020", "in_degree": 1, "out_degree": 1, "successors": [99], "predecessors": [50]},
            {"id": 99, "start": "0x140001040", "in_degree": 1, "out_degree": 1, "successors": [50], "predecessors": [20]}
        ]
        cfg = ControlFlowGraphAnalyzer.analyze_cfg(blocks)
        self.assertEqual(cfg["block_count"], 3)
        self.assertEqual(cfg["edge_count"], 3)
        self.assertEqual(cfg["cyclomatic_complexity"], 2) # 3 - 3 + 2 = 2
        self.assertEqual(cfg["back_edges_count"], 1)
        self.assertIn((99, 50), cfg["back_edges"])
        self.assertEqual(cfg["topology"], "CYCLIC_LOOP")

    def test_binary_patcher_negative_length_rejected(self):
        """Verifies that negative or zero lengths in read_bytes and deobfuscate_file raise ValueError."""
        import tempfile
        from binary_neural_engine import SurgicalBinaryPatcher, ContinuousDeobfuscator
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x90\x90\xc3")
            tmp = f.name
        try:
            with self.assertRaises(ValueError):
                SurgicalBinaryPatcher.read_bytes(tmp, 0, length=-5)
            with self.assertRaises(ValueError):
                SurgicalBinaryPatcher.read_bytes(tmp, 0, length=0)
            with self.assertRaises(ValueError):
                ContinuousDeobfuscator.deobfuscate_file(tmp, offset=0, length=-1)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def test_unified_version_consistency_v7_4_0(self):
        """Verifies that all project manifests, CLI, and MCP servers consistently declare v1.0.0."""
        import json
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        # pyproject.toml
        pyproj = os.path.join(repo_root, "pyproject.toml")
        with open(pyproj, "r", encoding="utf-8") as f:
            pyproj_text = f.read()
            self.assertTrue('version = "1.1.0"' in pyproj_text or 'version = "1.0.0"' in pyproj_text)
        # package.json
        pkg_json = os.path.join(repo_root, "package.json")
        with open(pkg_json, "r", encoding="utf-8") as f:
            self.assertIn(json.load(f)["version"], ("1.1.0", "1.0.0"))
        # mcp_server.py
        from mcp_server import SERVER_VERSION
        self.assertIn(SERVER_VERSION, ("1.1.0", "1.0.0"))
        # SKILL.md
        skill_file = os.path.join(repo_root, "skills", "bintra", "SKILL.md")
        if os.path.exists(skill_file):
            with open(skill_file, "r", encoding="utf-8") as sf:
                skill_content = sf.read()
                self.assertTrue('version: "1.1.0"' in skill_content or 'version: "1.0.0"' in skill_content)
                self.assertIn('tool_count: 42', skill_content)


    def test_ssa_analyzer_negative_same_seq_different_address(self):
        """Negative Test: Verifies that operations with identical seq time at DIFFERENT addresses are NOT matched."""
        from ghidra_pcode_vectorizer import PcodeSSAAnalyzer
        pcode_stream = [
            {
                "seq": 0,
                "address": "0x140001000",
                "opcode": "INT_XOR",
                "inputs": [
                    {"kind": "register", "name": "EAX", "size": 4, "def_id": "0x140001000:0"},
                    {"kind": "register", "name": "EAX", "size": 4, "def_id": "0x140001000:0"}
                ],
                "output": {"kind": "unique", "unique_id": 111, "size": 4}
            },
            {
                "seq": 1,
                "address": "0x140001005",
                "opcode": "CBRANCH",
                "inputs": [
                    {"kind": "ram", "offset": "0x140001050"},
                    # Condition defined at seq 0, but at DIFFERENT address 0x140002000!
                    {"kind": "unique", "unique_id": 111, "def_seq": 0, "def_addr": "0x140002000", "def_id": "0x140002000:0", "size": 4}
                ],
                "block_id": 0
            }
        ]
        blocks = [
            {"id": 0, "start": "0x140001000", "true_out": 1, "false_out": 2},
            {"id": 1, "start": "0x140001050"},
            {"id": 2, "start": "0x140001060"}
        ]
        res = PcodeSSAAnalyzer.analyze_ssa_invariants(pcode_stream, blocks)
        # MUST NOT evaluate as opaque predicate because generator address != condition def address!
        self.assertFalse(res["is_obfuscated"])
        self.assertEqual(res["evidence_dossiers_count"], 0)

    def test_patch_file_structural_pe_header_flagged_unsafe(self):
        """Verifies that arbitrary patches to PE headers are flagged as unsafe PE_STRUCTURAL_HEADER_MUTATION."""
        import tempfile
        from binary_neural_engine import SurgicalBinaryPatcher
        # Create minimal PE file
        dos_hdr = bytearray(0x80)
        dos_hdr[0:2] = b"MZ"
        dos_hdr[0x3C:0x40] = (0x40).to_bytes(4, "little") # pe_offset = 0x40
        pe_hdr = b"PE\x00\x00" + b"\x4c\x01" + (1).to_bytes(2, "little") + b"\x00"*12 + (0xe0).to_bytes(2, "little") + (0x102).to_bytes(2, "little")
        opt_hdr = b"\x0b\x01" + b"\x00"*222
        sec_hdr = b".text\x00\x00\x00" + (0x1000).to_bytes(4, "little") + (0x1000).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + b"\x00"*12 + (0x60000020).to_bytes(4, "little")
        padding = b"\x90" * 0x300
        full_pe = bytes(dos_hdr[:0x40] + pe_hdr + opt_hdr + sec_hdr + padding)

        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir:
            src_tmp = os.path.join(tgt_dir, "src.exe")
            with open(src_tmp, "wb") as f:
                f.write(full_pe)
            out_tmp = os.path.join(ws_dir, "out_patched.exe")

            from security import ExecutionGuard
            # Patching offset 0x3C (e_lfanew) should NOT be safe
            with ExecutionGuard.scoped_session(target_binary_path=src_tmp, workspace_dir=ws_dir):
                # Under default enforce_nociception=True, Nociceptive Reflex blocks PE header corruption
                with self.assertRaises(RuntimeError):
                    SurgicalBinaryPatcher.patch_file(src_tmp, out_tmp, 0x3C, "90909090", enforce_nociception=True)
                # When enforce_nociception=False, it is recorded as unsafe PE_STRUCTURAL_HEADER_MUTATION
                res = SurgicalBinaryPatcher.patch_file(src_tmp, out_tmp, 0x3C, "90909090", enforce_nociception=False)
            self.assertFalse(res["is_safe"])
            self.assertEqual(res["patch_type"], "PE_STRUCTURAL_HEADER_MUTATION")
            self.assertIn("PE_HEADER_CORRUPTION_HAZARD", res["pain_hazards"])



    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_windows_os_profiler(self):
        """Verifies Windows OS Profiler retrieves kernel build, arch, and WOW64 emulation status."""
        from windows_intelligence import WindowsOSProfiler
        profile = WindowsOSProfiler.profile()
        self.assertEqual(profile.get("status"), "success")
        self.assertIn("kernel", profile)
        self.assertIn("architecture", profile)
        self.assertIn("process_wow64", profile)
        self.assertIn("registry_info", profile)
        self.assertTrue(profile["kernel"].get("is_windows"))
        self.assertIn("major_version", profile["kernel"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_windows_dependency_resolver_synthetic(self):
        """Verifies Windows Dependency Resolver simulates Safe DLL Search, API Sets, and KnownDLLs."""
        from windows_intelligence import WindowsDependencyResolver
        synthetic_imports = {
            "KERNEL32.dll": ["ExitProcess", "CreateFileW"],
            "NON_EXISTENT_FAKE_MODULE_9999.dll": ["SomeFunc"]
        }
        res = WindowsDependencyResolver.audit_dependencies("dummy_target.exe", custom_imports=synthetic_imports)
        self.assertEqual(res.get("status"), "success")
        self.assertEqual(res.get("audit_scope"), "STATIC_HEURISTIC_AUDIT")
        self.assertIn("known_dlls_enforced", res)
        self.assertEqual(res["total_imported_dlls"], 2)
        self.assertEqual(res["resolved_dlls_count"], 1)
        self.assertEqual(res["missing_dlls_count"], 1)
        self.assertEqual(res["resolved_dlls"][0]["imported_name"], "KERNEL32.dll")
        self.assertEqual(res["missing_dlls"][0]["imported_name"], "NON_EXISTENT_FAKE_MODULE_9999.dll")

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_windows_device_inspector(self):
        """Verifies Windows Device Inspector scans display adapters and DirectX runtimes."""
        from windows_intelligence import WindowsDeviceInspector
        devices = WindowsDeviceInspector.audit()
        self.assertEqual(devices.get("status"), "success")
        self.assertIn("graphics_adapters", devices)
        self.assertIn("directx_runtimes", devices)
        subsystems = devices["directx_runtimes"].get("subsystems", {})
        self.assertIn("legacy_directdraw", subsystems)
        self.assertIn("legacy_direct3d9", subsystems)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_windows_security_inspector(self):
        """Verifies Windows Security Inspector evaluates token integrity and directory write access."""
        import tempfile
        import shutil
        from windows_intelligence import WindowsSecurityInspector
        temp_dir = tempfile.mkdtemp()
        try:
            sec = WindowsSecurityInspector.audit(temp_dir)
            self.assertEqual(sec.get("status"), "success")
            self.assertIn("is_elevated_admin", sec)
            self.assertIn("token_integrity", sec)
            self.assertIn("directory_write_permissions", sec)
            self.assertTrue(sec["directory_write_permissions"]["is_writable"])
            # Invariant: 100% read-only inspection - zero probe files created on disk
            self.assertEqual(len(os.listdir(temp_dir)), 0)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_windows_crash_analyzer_synthetic_wer_and_minidump(self):
        """Verifies Windows Crash Analyzer parses WER reports, Event 1000 XML, and correlated minidumps."""
        import tempfile
        import struct
        from windows_intelligence import WindowsCrashAnalyzer

        mock_wer = (
            "Version=1\n"
            "EventType=APPCRASH\n"
            "EventTime=133000000000000000\n"
            "ReportIdentifier=test-guid-1234\n"
            "Sig[0].Name=Application Name\n"
            "Sig[0].Value=target.exe\n"
            "Sig[1].Name=Application Version\n"
            "Sig[1].Value=1.0.0.0\n"
            "Sig[2].Name=Fault Module Name\n"
            "Sig[2].Value=target.exe\n"
            "Sig[3].Name=Fault Module Name (Real)\n"
            "Sig[3].Value=target.exe\n"
            "Sig[4].Name=Fault Module Version\n"
            "Sig[4].Value=1.0.0.0\n"
            "Sig[6].Name=Exception Code\n"
            "Sig[6].Value=c0000005\n"
            "Sig[7].Name=Fault Module Offset\n"
            "Sig[7].Value=00001050\n"
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix='.wer', mode='w', encoding='utf-8') as f:
            f.write(mock_wer)
            wer_file = f.name
        try:
            parsed = WindowsCrashAnalyzer._parse_wer_file(wer_file)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed["source"], "WER_REPORT")
            self.assertEqual(parsed["app_name"], "target.exe")
            self.assertEqual(parsed["fault_module"], "target.exe")
            self.assertEqual(parsed["fault_offset"], "0x00001050")
            self.assertEqual(parsed["exception_code"], "0xc0000005")
        finally:
            if os.path.exists(wer_file):
                os.remove(wer_file)

        # Minidump with Stream 6 (Exception) and Stream 4 (ModuleList)
        hdr = struct.pack('<4sIIIIII', b'MDMP', 42, 2, 0x20, 0, 123456, 0) + bytes([0]*4)
        dir_entries = struct.pack('<III', 6, 168, 0x40) + struct.pack('<III', 4, 112, 0xF0)
        pad0 = bytes([0] * (0x40 - 0x38))

        exc_data = struct.pack('<IIIIQQ', 1, 0, 0xC0000005, 0, 0, 0x140001050) + bytes([0] * 136)
        pad1 = bytes([0] * (0xF0 - 0xE8))

        mod_name_bytes = "my_target.exe".encode("utf-16-le")
        mod_str_rva = 0x180
        mod_record = struct.pack('<QIIII', 0x140000000, 0x10000, 0, 0, mod_str_rva) + bytes([0] * 84)
        mod_stream = struct.pack('<I', 1) + mod_record
        pad2 = bytes([0] * (0x180 - 0x160))

        str_data = struct.pack('<I', len(mod_name_bytes)) + mod_name_bytes

        full_dmp = hdr + dir_entries + pad0 + exc_data + pad1 + mod_stream + pad2 + str_data

        with tempfile.NamedTemporaryFile(delete=False, suffix='.dmp', mode='wb') as f:
            f.write(full_dmp)
            dmp_file = f.name
        try:
            mdmp_info = WindowsCrashAnalyzer.parse_minidump(dmp_file)
            self.assertEqual(mdmp_info["status"], "success")
            self.assertEqual(mdmp_info["format"], "MINIDUMP")
            self.assertEqual(mdmp_info["module_count"], 1)
            self.assertIsNotNone(mdmp_info["exception_info"])
            self.assertEqual(mdmp_info["exception_info"]["fault_module"], "my_target.exe")
            self.assertEqual(mdmp_info["exception_info"]["fault_offset"], "0x1050")
        finally:
            if os.path.exists(dmp_file):
                os.remove(dmp_file)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_windows_evidence_correlator_end_to_end(self):
        """Verifies cross-correlation of crash telemetry with strict RVA semantics and module attribution."""
        import tempfile
        from windows_intelligence import DiagnosticEvidenceCorrelator

        # Create minimal valid PE file with a .text section
        dos_hdr = bytearray(0x80)
        dos_hdr[0:2] = b"MZ"
        dos_hdr[0x3C:0x40] = (0x40).to_bytes(4, "little")
        pe_hdr = b"PE\x00\x00" + b"\x4c\x01" + (1).to_bytes(2, "little") + b"\x00"*12 + (0xe0).to_bytes(2, "little") + (0x102).to_bytes(2, "little")
        opt_hdr = bytearray(224)
        opt_hdr[0:2] = b"\x0b\x01"
        opt_hdr[28:32] = (0x00400000).to_bytes(4, "little") # ImageBase = 0x400000
        sec_hdr = b".text\x00\x00\x00" + (0x1000).to_bytes(4, "little") + (0x1000).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + (0x200).to_bytes(4, "little") + b"\x00"*12 + (0x60000020).to_bytes(4, "little")
        padding = b"\x90" * 0x300
        full_pe = bytes(dos_hdr[:0x40] + pe_hdr + bytes(opt_hdr) + sec_hdr + padding)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as f:
            f.write(full_pe)
            pe_path = f.name

        try:
            # Case 1: Internal fault matching the binary name
            crash_internal = {
                "source": "WER_REPORT",
                "fault_offset": "0x1050",  # FaultingOffset is the RVA!
                "exception_code": "0xc0000005",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "fault_module": os.path.basename(pe_path)
            }
            ghidra_export = {
                "functions": [
                    {
                        "name": "FUN_00401050",
                        "entry_point": "0x401050",
                        "pcode_ops": [{"address": "0x401050", "mnemonic": "MOV"}]
                    }
                ]
            }

            dossier1 = DiagnosticEvidenceCorrelator.correlate(
                binary_path=pe_path,
                crash_record=crash_internal,
                ghidra_export=ghidra_export
            )
            self.assertEqual(dossier1["status"], "success")
            self.assertIn("CRASH_TELEMETRY_RECORDED", dossier1["verdict"])
            self.assertTrue(dossier1["binary_mapping"]["is_internal_fault"])
            self.assertEqual(dossier1["binary_mapping"]["fault_rva"], "0x1050")
            self.assertEqual(dossier1["binary_mapping"]["fault_section"], ".text")
            self.assertEqual(dossier1["binary_mapping"]["fault_virtual_address"], "0x401050")
            self.assertEqual(dossier1["binary_mapping"]["ghidra_function_name"], "FUN_00401050")

            md1 = DiagnosticEvidenceCorrelator.format_markdown(dossier1)
            self.assertIn("# Bintra Failure Evidence Dossier", md1)
            self.assertIn("0xc0000005", md1)

            # Case 2: External runtime fault (e.g. crash in d3d9.dll)
            crash_external = {
                "source": "EVENT_LOG_1000",
                "fault_offset": "0x25000",
                "exception_code": "0xc0000005",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "fault_module": "d3d9.dll"
            }
            dossier2 = DiagnosticEvidenceCorrelator.correlate(
                binary_path=pe_path,
                crash_record=crash_external
            )
            self.assertEqual(dossier2["status"], "success")
            self.assertIn("EXTERNAL_MODULE_CRASH", dossier2["verdict"])
            self.assertFalse(dossier2["binary_mapping"]["is_internal_fault"])
            self.assertEqual(dossier2["binary_mapping"]["external_fault_module"], "d3d9.dll")
            self.assertEqual(dossier2["binary_mapping"]["attribution"], "EXTERNAL_DEPENDENCY_OR_SYSTEM_MODULE")

            md2 = DiagnosticEvidenceCorrelator.format_markdown(dossier2)
            self.assertIn("External Dependency / System Runtime", md2)
            self.assertIn("d3d9.dll", md2)

        finally:
            if os.path.exists(pe_path):
                os.remove(pe_path)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_mcp_server_windows_intelligence_dispatch(self):
        """Verifies that native MCP server can dispatch windows intelligence audit tools."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()
        audit_res = server.dispatch_tool("bintra_windows_env_audit", {})
        self.assertIn("os", audit_res)
        self.assertIn("devices", audit_res)
        self.assertIn("security", audit_res)
        self.assertEqual(audit_res["os"]["status"], "success")

    def test_command_catalog_specs_and_validation(self):
        """Verifies immutable CommandCatalog contracts, whitelisting, and query methods."""
        from windows_intelligence import CommandCatalog
        self.assertIn("os_ver", CommandCatalog.CATALOG)
        self.assertIn("driver_list", CommandCatalog.CATALOG)
        self.assertIn("pnp_devices_problem", CommandCatalog.CATALOG)

        spec = CommandCatalog.get_spec("os_ver")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.binary_name, "cmd.exe")
        self.assertEqual(spec.output_schema, "windows.ver.v1")

        # Non-existent command returns None
        self.assertIsNone(CommandCatalog.get_spec("non_existent_cmd_12345"))

        # List commands
        cmds = CommandCatalog.list_available_commands(current_build=19045)
        self.assertGreaterEqual(len(cmds), 10)
        os_ver_entry = next((c for c in cmds if c["command_id"] == "os_ver"), None)
        self.assertIsNotNone(os_ver_entry)
        self.assertTrue(os_ver_entry["supported"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_command_executor_safe_execution(self):
        """Verifies safe command execution without shell=True, timeout enforcement, and argument gating."""
        from windows_intelligence import CommandExecutor

        # Execute legitimate safe command
        res = CommandExecutor.execute("os_ver")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(res["schema"], "windows.ver.v1")
        self.assertIn("version", res["data"])

        # Rejection of unregistered command
        err_res = CommandExecutor.execute("malicious_rmdir_command")
        self.assertEqual(err_res["status"], "error")
        self.assertIn("not registered", err_res["error"])

        # Rejection of unwhitelisted argument
        flag_err = CommandExecutor.execute("os_ver", extra_flags=("/dangerous_arbitrary_flag",))
        self.assertEqual(flag_err["status"], "error")
        self.assertIn("not permitted", flag_err["error"])

    def test_output_parsers_csv_and_sc_query(self):
        """Verifies structured output parsing for CSV, sc query, pnputil, and whoami formats."""
        from windows_intelligence import OutputParsers

        # CSV Parsing
        mock_csv = '"Image Name","PID","Session Name","Session#","Mem Usage"\n"explorer.exe","1234","Console","1","50,000 K"\n'
        parsed_csv = OutputParsers.parse_csv_records(mock_csv)
        self.assertEqual(len(parsed_csv), 1)
        self.assertEqual(parsed_csv[0]["image_name"], "explorer.exe")
        self.assertEqual(parsed_csv[0]["pid"], "1234")

        # SC Query Parsing
        mock_sc = (
            "SERVICE_NAME: Spooler\n"
            "        TYPE               : 110  WIN32_OWN_PROCESS (interactive)\n"
            "        STATE              : 4  RUNNING\n"
            "        WIN32_EXIT_CODE    : 0  (0x0)\n"
            "        DISPLAY_NAME       : Print Spooler\n"
        )
        parsed_sc = OutputParsers.parse_sc_query(mock_sc)
        self.assertEqual(len(parsed_sc), 1)
        self.assertEqual(parsed_sc[0]["service_name"], "Spooler")
        self.assertEqual(parsed_sc[0]["display_name"], "Print Spooler")
        self.assertEqual(parsed_sc[0]["win32_exit_code"], "0  (0x0)")

        # PnPUtil Drivers Parsing
        mock_pnp = (
            "Published Name:     oem12.inf\n"
            "Original Name:      nvlddmkm.inf\n"
            "Provider Name:      NVIDIA\n"
            "Class Name:         Display\n"
            "Driver Version:     31.0.15.5222\n"
        )
        parsed_pnp = OutputParsers.parse_pnputil_drivers(mock_pnp)
        self.assertEqual(len(parsed_pnp), 1)
        self.assertEqual(parsed_pnp[0]["published_name"], "oem12.inf")
        self.assertEqual(parsed_pnp[0]["provider_name"], "NVIDIA")

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_registry_catalog_and_dual_view_reader(self):
        """Verifies 11-domain RegistryCatalog and dual-view (32/64-bit) reader."""
        from windows_intelligence import RegistryCatalog, WindowsRegistryReader

        self.assertEqual(len(RegistryCatalog.DOMAINS), 11)
        self.assertIn("OPERATING_SYSTEM", RegistryCatalog.DOMAINS)
        self.assertIn("SECURITY_POLICIES", RegistryCatalog.DOMAINS)
        self.assertIn("DLL_SEARCH_CONFIGURATION", RegistryCatalog.DOMAINS)

        # Query key under dual view
        res = WindowsRegistryReader.query_key_dual_view(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            target_values=("CurrentBuild", "ProductName")
        )
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["view_64"]["exists"])
        self.assertTrue(res["view_32"]["exists"])
        self.assertIn("CurrentBuild", res["view_64"]["values"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_registry_analyzer_critical_policies(self):
        """Verifies rule-based evaluation of SafeDllSearchMode, UAC, and KnownDLLs."""
        from windows_intelligence import WindowsRegistryAnalyzer

        policies = WindowsRegistryAnalyzer.evaluate_critical_policies()
        self.assertEqual(policies["status"], "success")
        self.assertIn("safedllsearch_mode", policies)
        self.assertIn("uac_enabled", policies)
        self.assertIn("known_dlls_count", policies)
        self.assertGreater(policies["findings_count"], 0)

        domain_res = WindowsRegistryAnalyzer.audit_domain("OPERATING_SYSTEM")
        self.assertEqual(domain_res["status"], "success")
        self.assertEqual(domain_res["domain"], "OPERATING_SYSTEM")
        self.assertGreater(domain_res["keys_inspected"], 0)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_mcp_server_catalog_and_registry_dispatch(self):
        """Verifies MCP server protocol dispatch for win_catalog_cmd and registry_audit."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        cmd_res = server.dispatch_tool("bintra_win_catalog_cmd", {"command_id": "os_ver"})
        self.assertEqual(cmd_res["status"], "success")
        self.assertEqual(cmd_res["schema"], "windows.ver.v1")

        reg_res = server.dispatch_tool("bintra_registry_audit", {"domain": "OPERATING_SYSTEM"})
        self.assertEqual(reg_res["status"], "success")
        self.assertEqual(reg_res["domain"], "OPERATING_SYSTEM")

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_native_device_inspector_live(self):
        """Verifies NativeDeviceInspector SetupAPI & CfgMgr32 device enumeration and health audit."""
        from windows_intelligence import NativeDeviceInspector
        report = NativeDeviceInspector.audit_hardware_health()
        self.assertEqual(report.get("status"), "success")
        self.assertIn("is_hardware_healthy", report)
        self.assertIn("total_pnp_devices_enumerated", report)
        self.assertGreater(report["total_pnp_devices_enumerated"], 0)
        self.assertIn("display_adapters_count", report)
        self.assertIn("problem_devices", report)
        desc = NativeDeviceInspector.get_problem_description(1)
        self.assertIn("CM_PROB_NOT_CONFIGURED", desc)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_kernel_driver_inspector_psapi(self):
        """Verifies KernelDriverInspector PSAPI driver enumeration and base mapping."""
        from windows_intelligence import KernelDriverInspector
        report = KernelDriverInspector.audit_drivers()
        self.assertEqual(report.get("status"), "success")
        self.assertIn("total_drivers_loaded", report)
        self.assertGreater(report["total_drivers_loaded"], 0)
        self.assertIn("drivers_sample", report)
        self.assertIn("graphics_drivers", report)
        all_drivers = KernelDriverInspector.enumerate_loaded_drivers()
        self.assertGreater(len(all_drivers), 0)
        first = all_drivers[0]
        self.assertIn("driver_name", first)
        self.assertIn("kernel_image_base", first)
        self.assertTrue(first["kernel_image_base"].startswith("0x"))

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_service_manager_inspector_advapi32(self):
        """Verifies ServiceManagerInspector SCM service interrogation via Advapi32."""
        from windows_intelligence import ServiceManagerInspector
        report = ServiceManagerInspector.audit_services()
        self.assertEqual(report.get("status"), "success")
        self.assertIn("total_services_enumerated", report)
        self.assertGreater(report["total_services_enumerated"], 0)
        self.assertIn("running_services_count", report)
        self.assertIn("services_sample", report)
        all_svcs = ServiceManagerInspector.enumerate_services()
        self.assertGreater(len(all_svcs), 0)
        svc = all_svcs[0]
        self.assertIn("service_name", svc)
        self.assertIn("display_name", svc)
        self.assertIn("state", svc)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_process_mitigation_inspector_live(self):
        """Verifies ProcessMitigationInspector DEP, ASLR, token integrity, and memory counters."""
        from windows_intelligence import ProcessMitigationInspector
        proc = ProcessMitigationInspector.inspect_process()
        self.assertEqual(proc.get("status"), "success")
        self.assertTrue(proc.get("is_current_process"))
        self.assertEqual(proc.get("pid"), os.getpid())
        self.assertIn("mitigations", proc)
        self.assertIn("dep", proc["mitigations"])
        self.assertTrue(proc["mitigations"]["dep"]["enabled"])
        self.assertIn("aslr", proc["mitigations"])
        self.assertIn("security_token", proc)
        self.assertIn("integrity_level", proc["security_token"])
        self.assertIn("memory", proc)
        self.assertIn("working_set_bytes", proc["memory"])
        self.assertGreater(proc["memory"]["working_set_bytes"], 0)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_mcp_server_system_introspection_dispatch(self):
        """Verifies MCP server dispatch for hardware_audit, driver_audit, and service_audit."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        hw_res = server.dispatch_tool("bintra_hardware_audit", {"problems_only": True})
        self.assertIn("is_hardware_healthy", hw_res)
        self.assertIn("problem_devices_count", hw_res)

        drv_res = server.dispatch_tool("bintra_driver_audit", {"driver_name_filter": "dxg"})
        self.assertEqual(drv_res.get("status"), "success")
        self.assertIn("drivers", drv_res)
        self.assertGreater(drv_res.get("matched_count", 0), 0)

        svc_res = server.dispatch_tool("bintra_service_audit", {"active_only": True})
        self.assertEqual(svc_res.get("status"), "success")
        self.assertIn("services", svc_res)
        self.assertGreater(len(svc_res["services"]), 0)
        for s in svc_res["services"]:
            self.assertIn(s["state"], ("RUNNING", "SERVICE_RUNNING"))

    def test_minidump_parser_multistream_synthetic(self):
        """Verifies MiniDumpParser multi-stream parsing (Streams 3, 4, 6, 7, 10) & AV diagnostics."""
        from windows_intelligence import MiniDumpParser

        fmt_sys = '<HHHBBIIIIIHH16s'
        sys_data = struct.pack(fmt_sys, 9, 6, 0x1234, 4, 1, 10, 0, 19045, 2, 0, 0x100, 0, bytes([0]*16))

        fmt_misc = '<IIIIII'
        misc_data = struct.pack(fmt_misc, 24, 0x3, 9999, 1000, 200, 150)

        fmt_thread = '<IIIIQQIIII'
        t1 = struct.pack(fmt_thread, 1001, 0, 32, 8, 0x7ff00000, 0x12ff00, 0x1000, 0, 0, 0)
        t2 = struct.pack(fmt_thread, 1002, 0, 32, 8, 0x7ff10000, 0x13ff00, 0x1000, 0, 0, 0)
        thread_data = struct.pack('<I', 2) + t1 + t2

        mod_name_utf16 = 'target_app.exe\x00'.encode('utf-16-le')
        mod_str_data = struct.pack('<I', len(mod_name_utf16)) + mod_name_utf16

        hdr_size = 32
        dir_size = 5 * 12
        sys_rva = hdr_size + dir_size
        misc_rva = sys_rva + len(sys_data)
        thread_rva = misc_rva + len(misc_data)
        mod_str_rva = thread_rva + len(thread_data)
        mod_list_rva = mod_str_rva + len(mod_str_data)

        mod_record = struct.pack('<QIIII', 0x400000, 0x20000, 0, 0, mod_str_rva) + bytes([0] * (108 - 24))
        mod_list_data = struct.pack('<I', 1) + mod_record
        exc_rva = mod_list_rva + len(mod_list_data)

        fmt_exc = '<IIIIQQII15QII'
        ctx_bytes = bytearray(716)
        ctx_bytes[184:188] = struct.pack('<I', 0x401050)  # EIP
        ctx_bytes[196:200] = struct.pack('<I', 0x12ff00)  # ESP
        ctx_bytes[180:184] = struct.pack('<I', 0x12ff50)  # EBP
        ctx_bytes[176:180] = struct.pack('<I', 0x1)       # EAX
        ctx_rva = exc_rva + 168  # context bytes immediately follow 168-byte exception stream
        exc_data = struct.pack(fmt_exc, 1001, 0, 0xC0000005, 0, 0, 0x401050, 2, 0, *( [1, 0x0] + [0]*13 ), len(ctx_bytes), ctx_rva)

        dir_entries = [
            struct.pack('<III', 7, len(sys_data), sys_rva),
            struct.pack('<III', 15, len(misc_data), misc_rva),  # Stream 15 is standard MiscInfoStream
            struct.pack('<III', 3, len(thread_data), thread_rva),
            struct.pack('<III', 4, len(mod_list_data), mod_list_rva),
            struct.pack('<III', 6, len(exc_data), exc_rva),
        ]
        dir_bytes = b''.join(dir_entries)
        hdr = struct.pack('<IIIIII', 0x504D444D, 0xA793, 5, 32, 0, 0x65000000) + bytes([0] * 8)
        payload = hdr + dir_bytes + sys_data + misc_data + thread_data + mod_str_data + mod_list_data + exc_data + bytes(ctx_bytes)

        with tempfile.NamedTemporaryFile(suffix='.dmp', delete=False) as tf:
            tf.write(payload)
            tpath = tf.name

        try:
            parsed = MiniDumpParser.parse_minidump(tpath)
            self.assertEqual(parsed['status'], 'success')
            self.assertEqual(parsed['stream_count'], 5)
            self.assertEqual(parsed['thread_count'], 2)
            self.assertEqual(parsed['module_count'], 1)
            # System info
            self.assertIn('system_info', parsed)
            self.assertEqual(parsed['system_info']['build_number'], 19045)
            self.assertEqual(parsed['system_info']['processor_architecture'], 'AMD64 (x64 64-bit)')
            # Misc info
            self.assertIn('misc_info', parsed)
            self.assertEqual(parsed['misc_info']['process_id'], 9999)
            # Exception info & correlation
            exc = parsed['exception_info']
            self.assertEqual(exc['exception_code'], '0xc0000005')
            self.assertEqual(exc['fault_module'], 'target_app.exe')
            self.assertEqual(exc['fault_offset'], '0x1050')
            self.assertIn('access_violation_details', exc)
            self.assertEqual(exc['access_violation_details']['operation'], 'WRITE')
            self.assertTrue(exc['access_violation_details']['is_null_pointer_dereference'])
            # Thread register extraction
            self.assertIn('thread_registers', exc)
            self.assertEqual(exc['thread_registers']['arch'], 'x86')
            self.assertEqual(exc['thread_registers']['eip'], '0x401050')
            self.assertEqual(exc['thread_registers']['esp'], '0x12ff00')
            self.assertEqual(exc['thread_registers']['ebp'], '0x12ff50')
        finally:
            if os.path.exists(tpath):
                os.unlink(tpath)

    def test_event_log_collector_live(self):
        """Verifies EventLogCollector queries Application Event Log for failure events."""
        from windows_intelligence import EventLogCollector
        telemetry = EventLogCollector.collect_all_telemetry()
        self.assertEqual(telemetry['status'], 'success')
        self.assertIn('counts', telemetry)
        self.assertIn('application_crashes_1000', telemetry['counts'])
        self.assertIn('wer_events_1001', telemetry['counts'])
        self.assertIn('application_hangs_1002', telemetry['counts'])
        self.assertIn('system_crashes', telemetry['counts'])
        if os.name == 'nt':
            self.assertEqual(telemetry.get('backend'), 'wevtapi.dll (native Win32 in-process)')

    def test_event_log_collector_native_backend(self):
        """Verifies EventLogCollector directly leverages in-process Win32 wevtapi bindings."""
        from windows_intelligence import EventLogCollector
        if os.name != 'nt':
            return
        native_nodes = EventLogCollector._execute_native_query("Application", "*[System[(EventID=1000)]]", 2)
        self.assertIsNotNone(native_nodes)
        self.assertIsInstance(native_nodes, list)
        self.assertFalse(EventLogCollector.LAST_QUERY_ERRORS)


    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_etw_controller_live_and_providers(self):
        """Verifies EtwController providers catalog and session query capabilities."""
        from windows_intelligence import EtwController
        provs = EtwController.audit_etw_providers()
        self.assertEqual(provs['status'], 'success')
        self.assertGreater(provs['total_providers'], 5)
        self.assertIn('Microsoft-Windows-Kernel-Process', provs['providers'])
        self.assertIn('Microsoft-Windows-Direct3D11', provs['providers'])
        self.assertIn('Microsoft-Windows-DXGI', provs['providers'])

        # Probe standard sessions
        audit = EtwController.audit_telemetry_system()
        self.assertEqual(audit['status'], 'success')
        self.assertTrue(audit.get('is_windows'))
        self.assertGreater(audit['standard_sessions_probed'], 0)
        self.assertIn('active_sessions', audit)

        # Query standard application event log trace session
        sess = EtwController.query_trace_session('Eventlog-Application')
        self.assertEqual(sess['session_name'], 'Eventlog-Application')
        self.assertTrue(sess['is_active'])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_etw_controller_bounded_session(self):
        """Verifies EtwController bounded trace session lifecycle with fail-closed elevation handling."""
        import tempfile
        import shutil
        from windows_intelligence import EtwController
        ws_tmp = tempfile.mkdtemp(prefix="bintra_etw_ws_")
        try:
            res = EtwController.capture_bounded_session(
                session_name="Bintra_Unit_Test_Trace",
                duration_sec=0.5,
                workspace_dir=ws_tmp
            )
            self.assertIn('status', res)
            self.assertIn(res['status'], ('elevation_required', 'success', 'already_active'))
            if res['status'] == 'elevation_required':
                self.assertEqual(res['error_code'], 5)
                self.assertIn('safe_alternatives', res)
        finally:
            shutil.rmtree(ws_tmp, ignore_errors=True)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_mcp_server_telemetry_dispatch(self):
        """Verifies MCP server protocol dispatch for bintra_dmp_inspect and bintra_etw_audit."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        # Audit dumps without explicit path
        dmp_res = server.dispatch_tool("bintra_dmp_inspect", {})
        self.assertEqual(dmp_res["status"], "success")
        self.assertIn("total_dumps_discovered", dmp_res)

        # ETW audit
        etw_res = server.dispatch_tool("bintra_etw_audit", {})
        self.assertEqual(etw_res["status"], "success")
        self.assertIn("registered_providers_count", etw_res)
        self.assertIn("active_sessions", etw_res)

    def test_evidence_graph_data_structures(self):
        """Verifies EvidenceGraph nodes, edges, BFS causal path, and Mermaid rendering."""
        from windows_intelligence.evidence_engine import EvidenceGraph

        g = EvidenceGraph()
        g.add_node("TARGET:app.exe", "BINARY_TARGET", "app.exe")
        g.add_node("SEC:.text", "PE_SECTION", ".text")
        g.add_node("CRASH", "CRASH_TELEMETRY", "STATUS_ACCESS_VIOLATION")
        g.add_node("ROOT", "ACCESS_VIOLATION_ROOT", "WRITE @ 0x0")

        g.add_edge("TARGET:app.exe", "SEC:.text", "HAS_SECTION")
        g.add_edge("TARGET:app.exe", "CRASH", "REPORTED_CRASH")
        g.add_edge("CRASH", "ROOT", "CAUSED_BY_VIOLATION")

        self.assertEqual(len(g.nodes), 4)
        self.assertEqual(len(g.edges), 3)

        # Causal path BFS
        path = g.find_causal_path("TARGET:app.exe", "ROOT")
        self.assertEqual(path, ["TARGET:app.exe", "CRASH", "ROOT"])

        # Dict and Mermaid serialization
        g_dict = g.to_dict()
        self.assertEqual(g_dict["total_nodes"], 4)
        self.assertEqual(g_dict["total_edges"], 3)

        mermaid = g.to_mermaid()
        self.assertTrue(mermaid.startswith("flowchart TD"))
        self.assertIn("CRASH: STATUS_ACCESS_VIOLATION", mermaid)
        self.assertIn("ROOT: WRITE @ 0x0", mermaid)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_causality_synthesizer_end_to_end(self):
        """Verifies CausalitySynthesizer builds complete graph and synthesizes dossier."""
        from windows_intelligence.evidence_engine import CausalitySynthesizer

        cmd_path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "cmd.exe")
        crash_rec = {
            "source": "MINIDUMP",
            "exception_code": "0xc0000005",
            "exception_name": "STATUS_ACCESS_VIOLATION",
            "fault_module": "cmd.exe",
            "fault_offset": "0x1050",
            "access_violation_details": {
                "operation": "WRITE",
                "target_virtual_address": "0x0",
                "is_null_pointer_dereference": True,
                "probable_cause": "NULL Pointer Dereference"
            }
        }
        ghidra_export = {
            "functions": [
                {
                    "name": "MainEntry",
                    "entry_point": "0x140001000",
                    "size": 100,
                    "basic_blocks": [{"start": "0x140001000", "end": "0x140001064"}]
                }
            ]
        }

        dossier = CausalitySynthesizer.synthesize_dossier(
            cmd_path,
            crash_record=crash_rec,
            ghidra_export=ghidra_export
        )

        self.assertEqual(dossier["status"], "success")
        self.assertIn("INTERNAL_BINARY_CRASH", dossier["verdict"])
        self.assertEqual(dossier["severity"], "CRITICAL")
        self.assertGreater(len(dossier["root_cause_summary"]), 0)
        self.assertIn("causal_chain", dossier)
        self.assertEqual(dossier["causal_chain"], ["TARGET:cmd.exe", "CRASH_TELEMETRY", "AV_ROOT_CAUSE"])
        self.assertIn("evidence_graph", dossier)
        self.assertGreater(dossier["evidence_graph"]["total_nodes"], 10)
        self.assertTrue(dossier["mermaid_diagram"].startswith("flowchart TD"))
        self.assertIn("epistemic_classification", dossier)
        self.assertIn("facts", dossier["epistemic_classification"])
        self.assertIn("observations", dossier["epistemic_classification"])
        self.assertIn("hypotheses", dossier["epistemic_classification"])
        self.assertGreater(len(dossier["epistemic_classification"]["facts"]), 0)
        self.assertGreater(len(dossier["epistemic_classification"]["hypotheses"]), 0)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_mcp_server_evidence_graph_dispatch(self):
        """Verifies MCP server protocol dispatch for bintra_evidence_graph."""
        from mcp_server import BintraMcpServer
        server = BintraMcpServer()

        cmd_path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "cmd.exe")
        res = server.dispatch_tool("bintra_evidence_graph", {"binary_path": cmd_path})
        self.assertEqual(res["status"], "success")
        self.assertGreater(res["total_nodes"], 10)
        self.assertGreater(res["total_edges"], 10)
        self.assertIn("graph", res)
        self.assertIn("mermaid_diagram", res)



    def test_causality_synthesizer_no_presumptive_fallback(self):
        """Verifies no presumptive fallback when fault_module is missing from crash record."""
        from windows_intelligence.evidence_engine import CausalitySynthesizer
        cmd_path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "cmd.exe")
        cleanup_path = None
        if not os.path.isfile(cmd_path):
            pe_bytes = _create_synthetic_pe64()
            tf = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
            tf.write(pe_bytes)
            tf.close()
            cmd_path = tf.name
            cleanup_path = tf.name
        try:
            crash_no_mod = {
                "source": "WER_REPORT",
                "exception_code": "0xc0000005",
                "exception_name": "STATUS_ACCESS_VIOLATION",
                "fault_offset": "0x1000"
                # fault_module explicitly omitted
            }
            dossier = CausalitySynthesizer.synthesize_dossier(cmd_path, crash_record=crash_no_mod)
            self.assertEqual(dossier["status"], "success")
            self.assertFalse(dossier["binary_mapping"]["is_internal_fault"])
            self.assertEqual(dossier["binary_mapping"]["external_fault_module"], "UNKNOWN_MODULE")
            self.assertEqual(dossier["binary_mapping"]["attribution"], "ATTRIBUTION_UNKNOWN")
        finally:
            if cleanup_path and os.path.exists(cleanup_path):
                os.unlink(cleanup_path)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_registry_subkeys_and_three_state_policies(self):
        """Verifies registry subkey enumeration and 3-state policy status (SafeDllSearchMode, EnableLUA)."""
        from windows_intelligence.registry_intelligence import WindowsRegistryReader, WindowsRegistryAnalyzer
        subkeys = WindowsRegistryReader.enumerate_subkeys(
            WindowsRegistryReader.HIVE_MAP["HKLM"],
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            max_subkeys=20
        )
        self.assertIsInstance(subkeys, list)
        self.assertGreater(len(subkeys), 0)

        policies = WindowsRegistryAnalyzer.evaluate_critical_policies()
        self.assertIn("safedllsearch_mode_status", policies)
        self.assertIn(policies["safedllsearch_mode_status"], (
            "EXPLICIT_ENABLED", "EXPLICIT_DISABLED", "NOT_CONFIGURED (OS_DEFAULT_ENABLED)"
        ))
        self.assertIn("uac_status", policies)
        self.assertIn(policies["uac_status"], (
            "EXPLICIT_ENABLED", "EXPLICIT_DISABLED", "NOT_CONFIGURED (OS_DEFAULT_ENABLED)"
        ))

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_command_executor_privilege_and_output_guards(self):
        """Verifies CommandExecutor administrative privilege gating and output limit."""
        from windows_intelligence.command_engine import CommandExecutor, CommandCatalog
        spec = CommandCatalog.get_spec("bcdedit_enum")
        if spec and spec.requires_admin:
            from windows_intelligence.security_inspector import WindowsSecurityInspector
            if not WindowsSecurityInspector.is_elevated():
                res = CommandExecutor.execute("bcdedit_enum")
                self.assertEqual(res["status"], "error")
                self.assertIn("requires elevated administrative privileges", res["error"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_command_executor_output_truncation_5mb(self):
        """Verifies 5MB output truncation guard in CommandExecutor."""
        from windows_intelligence.command_engine import CommandExecutor
        from unittest.mock import patch
        import subprocess

        large_output_str = "A" * (6 * 1024 * 1024)
        mock_proc = subprocess.CompletedProcess(
            args=["cmd.exe", "/c", "ver"],
            returncode=0,
            stdout=large_output_str,
            stderr=""
        )

        with patch("subprocess.run", return_value=mock_proc):
            res = CommandExecutor.execute("os_ver")
            self.assertEqual(res["status"], "success")
            self.assertTrue(res["is_truncated"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_command_executor_sc_query_arguments(self):
        """Verifies sc.exe query argument parsing with both separate and merged state= all flags."""
        from windows_intelligence.command_engine import CommandExecutor
        # 1. Separate tokens
        res1 = CommandExecutor.execute("service_list", extra_flags=["state=", "all"])
        self.assertEqual(res1["status"], "success")
        self.assertEqual(res1["exit_code"], 0)
        self.assertIsInstance(res1["data"], list)
        self.assertGreater(len(res1["data"]), 0)
        self.assertIn("service_name", res1["data"][0])

        # 2. Merged space token
        res2 = CommandExecutor.execute("service_list", extra_flags=["state= all"])
        self.assertEqual(res2["status"], "success")
        self.assertEqual(res2["exit_code"], 0)
        self.assertIsInstance(res2["data"], list)
        self.assertGreater(len(res2["data"]), 0)
        self.assertIn("service_name", res2["data"][0])

    def test_powershell_executor_depth_4(self):
        """Verifies PowerShellExecutor generates command scripts with -Depth 4."""
        from windows_intelligence.command_engine import PowerShellExecutor
        cmd = PowerShellExecutor.build_command("Get-Process")
        self.assertIn("-Depth 4", cmd)

    def test_zero_hardcoded_developer_paths(self):
        """Verifies zero occurrences of developer paths in source code, tests, and ghidra scripts."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        disallowed = ["c:" + "\\users\\eylias", "d:" + "\\rea-neural", "d:" + "\\bintra", "/users/eylias", "users/eylias"]
        scanned_exts = (".py", ".java", ".md", ".json")

        for root_dir in (os.path.join(repo_root, "src"), os.path.join(repo_root, "ghidra_scripts"), os.path.join(repo_root, "tests")):
            for root, _, files in os.walk(root_dir):
                for f in files:
                    if f.endswith(scanned_exts):
                        p = os.path.join(root, f)
                        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                            fc = fh.read().lower()
                            if f == "test_suite.py":
                                lines = [line for line in fc.splitlines() if "disallowed" not in line and "test_zero_hardcoded" not in line]
                                fc = "\n".join(lines)
                            for bad in disallowed:
                                self.assertNotIn(bad, fc, f"Leaked developer path in {p}")

    def test_minidump_parser_stream_bounds_and_miscinfo_stream_15(self):
        """Verifies MiniDumpParser bounds checking and strict Stream 15 MiscInfo mapping."""
        from windows_intelligence.runtime_telemetry import MiniDumpParser
        import tempfile
        import struct

        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as tf:
            dmp_path = tf.name
            # Construct synthetic dump: 1 stream with out-of-bounds RVA
            hdr = struct.pack("<IIIIII", 0x504D444D, 0x0000A793, 1, 32, 0, 1600000000)
            # Stream entry: Stream 15 (MiscInfo), size 24, RVA 999999 (far beyond file size)
            stream_entry = struct.pack("<III", 15, 24, 999999)
            tf.write(hdr)
            tf.write(stream_entry)

        try:
            res = MiniDumpParser.parse_minidump(dmp_path)
            self.assertEqual(res["status"], "success")
            # The out of bounds stream was skipped defensively
            self.assertIsNone(res["misc_info"])
        finally:
            if os.path.exists(dmp_path):
                os.remove(dmp_path)

    def test_minidump_thread_registers_and_context_keys(self):
        """Verifies both thread_registers and thread_context are populated in ExceptionStream."""
        from windows_intelligence.runtime_telemetry import MiniDumpParser
        import tempfile
        import struct

        fd, dmp_path = tempfile.mkstemp(suffix=".dmp")
        try:
            # Build valid minimal MDMP with ExceptionStream (6)
            ctx_bytes = b"\x00" * 1300
            ctx_mutable = bytearray(ctx_bytes)
            struct.pack_into("<Q", ctx_mutable, 248, 0x140001050)
            struct.pack_into("<Q", ctx_mutable, 152, 0x7FFFFFFF0000)

            exc_record = bytearray(168)
            # ctx_rva is at offset 32 (hdr) + 12 (stream entry) + 168 (exc_record) = 212
            struct.pack_into("<IIIIQQII15QII", exc_record, 0,
                             1, 0, 0xC0000005, 0, 0, 0x140001050, 2, 0,
                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                             len(ctx_mutable), 212)

            # Header is exactly 32 bytes: 6 uint32s (24 bytes) + 8 reserved bytes
            hdr = struct.pack("<IIIIIIQ", 0x504D444D, 0x0000A793, 1, 32, 0, 1600000000, 0)
            stream_entry = struct.pack("<III", 6, 168, 44)

            with os.fdopen(fd, "wb") as f:
                f.write(hdr)
                f.write(stream_entry)
                f.write(exc_record)
                f.write(ctx_mutable)

            res = MiniDumpParser.parse_minidump(dmp_path)
            self.assertEqual(res["status"], "success")
            exc_info = res["exception_info"]
            self.assertIsNotNone(exc_info)
            self.assertIn("thread_registers", exc_info)
            self.assertIn("thread_context", exc_info)
            self.assertEqual(exc_info["thread_registers"]["rip"], "0x140001050")
            self.assertEqual(exc_info["thread_context"]["rip"], "0x140001050")
            self.assertEqual(exc_info["fault_module"], "UNKNOWN_MODULE")
            self.assertTrue(exc_info["is_unloaded_or_unmapped"])
        finally:
            if os.path.exists(dmp_path):
                os.remove(dmp_path)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_security_inspector_policy_estimation(self):
        """Verifies WindowsSecurityInspector returns explicit POLICY_ESTIMATION semantics."""
        from windows_intelligence.security_inspector import WindowsSecurityInspector
        res = WindowsSecurityInspector.test_directory_write_access(r"C:\Windows")
        self.assertEqual(res["evaluation_type"], "POLICY_ESTIMATION")
        self.assertTrue(res["is_read_only_audit"])
        self.assertTrue(res["is_program_files_path"])
        self.assertIn("methodology", res)
        self.assertIn("notice", res)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_registry_reader_truncation_metadata_and_access_denied(self):
        """Verifies registry reader truncation metadata and ACCESS_DENIED preservation in analyzer."""
        from windows_intelligence.registry_intelligence import WindowsRegistryReader, WindowsRegistryAnalyzer
        from unittest.mock import patch

        # Test truncation metadata
        key_res = WindowsRegistryReader._read_single_view(
            WindowsRegistryReader.HIVE_MAP["HKLM"],
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
            0,
            include_subkeys=True,
            max_subkeys=2
        )
        self.assertTrue(key_res["exists"])
        self.assertEqual(key_res["subkeys_count"], 2)
        self.assertGreater(key_res["total_subkeys"], 2)
        self.assertTrue(key_res["is_truncated"])

        # Test ACCESS_DENIED preservation in analyzer
        mock_dual_view = {
            "view_64": {"exists": True, "access_denied": True, "error": "AccessDenied"},
            "view_32": {"exists": True, "access_denied": True, "error": "AccessDenied"}
        }
        with patch.object(WindowsRegistryReader, "query_key_dual_view", return_value=mock_dual_view):
            pol = WindowsRegistryAnalyzer.evaluate_critical_policies()
            self.assertIn("ACCESS_DENIED", pol["safedllsearch_mode_status"])
            self.assertIn("ACCESS_DENIED", pol["uac_status"])

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_causality_synthesizer_exact_block_containment_and_unknowns(self):
        """Verifies exact basic block containment matching and unknowns ledger generation."""
        from windows_intelligence.evidence_engine import CausalitySynthesizer
        cmd_path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "cmd.exe")

        # Non-contiguous blocks: Block A [0x140001000 - 0x140001020], Block B [0x140001080 - 0x1400010A0]
        # Fault VA is at 0x140001050 (in the gap between blocks!)
        ghidra_export = {
            "functions": [
                {
                    "name": "GapFunc",
                    "entry_point": "0x140001000",
                    "size": 0x200,
                    "basic_blocks": [
                        {"start": "0x140001000", "end": "0x140001020"},
                        {"start": "0x140001080", "end": "0x1400010A0"}
                    ]
                }
            ]
        }
        crash_rec = {
            "source": "MINIDUMP",
            "exception_code": "0xc0000005",
            "exception_name": "STATUS_ACCESS_VIOLATION",
            "fault_module": "cmd.exe",
            "fault_offset": "0x1050"
        }

        dossier = CausalitySynthesizer.synthesize_dossier(cmd_path, crash_record=crash_rec, ghidra_export=ghidra_export)
        self.assertEqual(dossier["status"], "success")
        # Notice: It does NOT match any block because 0x140001050 is not in Block A or Block B
        self.assertNotIn("ghidra_basic_block", dossier["binary_mapping"])
        # Unknowns ledger captures the unmapped block boundary
        self.assertIn("unknowns", dossier)
        self.assertTrue(any("does not map to any exported basic block boundary" in u for u in dossier["unknowns"]))


    def test_nociceptive_pain_reflex_blocks_replacement_stack_corruption(self):
        """Verifies Fix for Audit 5.2: Guard inspects replacement bytes and blocks sub rsp over neutral code."""
        from binary_neural_engine import SurgicalBinaryPatcher
        import tempfile

        pe_bytes = _create_synthetic_pe64()
        with tempfile.TemporaryDirectory() as tgt_dir, tempfile.TemporaryDirectory() as ws_dir:
            pe_path = os.path.join(tgt_dir, "test.exe")
            with open(pe_path, "wb") as f:
                f.write(pe_bytes)
            out_path = os.path.join(ws_dir, "out_patched.exe")

            from security import ExecutionGuard
            with ExecutionGuard.scoped_session(target_binary_path=pe_path, workspace_dir=ws_dir):
                # At offset 0x240 in .text section, inject destructive 'sub rsp, 0x28' (48 83 ec 28)
                # over previously neutral bytes. With enforce_nociception=True, this MUST raise RuntimeError!
                with self.assertRaises(RuntimeError) as ctx:
                    SurgicalBinaryPatcher.patch_file(
                        pe_path,
                        out_path,
                        0x240,
                        "4883ec28",
                        enforce_nociception=True
                    )
                self.assertIn("Nociceptive Reflex blocked destructive binary patch", str(ctx.exception))
                self.assertIn("Stack frame balance violated", str(ctx.exception))

                # When enforce_nociception=False, it should record the STACK_FRAME_IMBALANCE_HAZARD
                res = SurgicalBinaryPatcher.patch_file(
                    pe_path,
                    out_path,
                    0x240,
                    "4883ec28",
                    enforce_nociception=False
                )
            self.assertFalse(res["is_safe"])
            self.assertIn("STACK_FRAME_IMBALANCE_HAZARD", res["pain_hazards"])
            self.assertGreaterEqual(res["pain_score"], 0.65)

    def test_semantic_function_matcher_real_gcc_x86_vs_arm64(self):
        """Verifies Fix for Audit 5.1: Real compiler instructions are disassembled via Capstone without collapse."""
        from binary_neural_engine import SemanticFunctionMatcher

        # Real compiled arithmetic function:
        # x86-64 (add edi, esi; mov eax, edi; ret)
        x86_hex = "01f789f8c3"
        # ARM64 (add w0, w0, w1; ret)
        arm_hex = "0000010bc0035fd6"

        res = SemanticFunctionMatcher.match_functions(x86_hex, arm_hex)
        self.assertGreater(res["cosine_similarity"], 0.85)
        self.assertTrue(res["is_semantic_match"])
        self.assertIn(res["confidence"], ("HIGH", "MODERATE"))
        self.assertNotEqual(res["cosine_similarity"], 0.0)

    def test_control_flow_flattening_x64_rsp_dispatcher(self):
        """Verifies Fix for Audit 5.1/Table 3: Detects 64-bit RSP-based dispatcher loops."""
        from binary_neural_engine import ContinuousDeobfuscator
        import struct

        # Construct synthetic x64 CFF block:
        # 3 comparisons against [rsp+8] (81 7C 24 08 imm32)
        # 3 assignments to [rsp+8] (C7 44 24 08 imm32)
        cff_stream = bytearray()
        for state in (0x10, 0x20, 0x30):
            # CMP [rsp+8], state
            cff_stream.extend(b"\x81\x7C\x24\x08" + struct.pack("<I", state))
            # NOP padding
            cff_stream.extend(b"\x90\x90\x90\x90")
            # MOV [rsp+8], state + 1
            cff_stream.extend(b"\xC7\x44\x24\x08" + struct.pack("<I", state + 1))
            cff_stream.extend(b"\x90\x90\x90\x90")

        res = ContinuousDeobfuscator.detect_control_flow_flattening(bytes(cff_stream))
        self.assertTrue(res["has_control_flow_flattening"])
        self.assertEqual(res["dispatcher_comparisons_count"], 3)
        self.assertEqual(res["state_transitions_count"], 3)
        self.assertGreater(res["dispatcher_cadence_regularity"], 0.0)


    @unittest.skipUnless(sys.platform == 'win32', "Windows SetupAPI & Device Inspector tests require Windows host")
    def test_native_device_inspector_instance_id_and_multi_sz(self):
        """Verifies Track 1: SetupDiGetDeviceInstanceIdW string IDs and REG_MULTI_SZ hardware IDs."""
        from windows_intelligence.system_introspection import NativeDeviceInspector
        from windows_intelligence.device_intelligence import DeviceIdentity, DriverMatcher

        devs = NativeDeviceInspector.enumerate_devices(max_devices=32)
        self.assertIsInstance(devs, list)
        self.assertGreater(len(devs), 0)

        # Inspect first valid device with instance_id
        valid_devs = [d for d in devs if d.get("device_instance_id")]
        self.assertGreater(len(valid_devs), 0)
        sample = valid_devs[0]

        # Ensure instance_id is real string (e.g. PCI\VEN_... or ROOT\... or USB\...)
        self.assertIsInstance(sample["device_instance_id"], str)
        self.assertGreater(len(sample["device_instance_id"]), 3)

        # Ensure hardware_ids is list
        self.assertIsInstance(sample["hardware_ids"], list)

        # Ensure problem status is properly parsed
        self.assertIn("has_problem", sample)
        self.assertIn("problem_name", sample)

        # Test DeviceIdentity parser
        parsed = DeviceIdentity.parse_device_instance(sample)
        self.assertIn("bus_type", parsed)

    @unittest.skipUnless(sys.platform == 'win32', "Windows Restart Manager tests require Windows host")
    def test_file_usage_inspector_restart_manager(self):
        """Verifies Track 2: Native Windows Restart Manager discovers file lock holders."""
        from windows_intelligence.process_intelligence import FileUsageInspector

        # Create temporary locked file
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"lock_test_payload_bintra")
            tf.flush()
            temp_path = tf.name

        try:
            # Open file with exclusive lock in current process
            with open(temp_path, "r+b") as locked_f:
                res = FileUsageInspector.inspect_file_locks(temp_path)
                self.assertTrue(res["is_locked"])
                self.assertGreater(res["locking_processes_count"], 0)
                pids = [p["process_id"] for p in res["locking_processes"]]
                self.assertIn(os.getpid(), pids)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    @unittest.skipUnless(sys.platform == 'win32', "Windows Toolhelp32 & Process Inventory require Windows host")
    def test_process_inventory_and_service_mapper(self):
        """Verifies Track 2: Process inventory, process tree, and SCM service mapping."""
        from windows_intelligence.process_intelligence import ProcessInventory, ServiceProcessMapper

        # Test process enumeration
        procs = ProcessInventory.enumerate_processes(resolve_paths=False)
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0)
        cur_pid = os.getpid()
        self.assertTrue(any(p["process_id"] == cur_pid for p in procs))

        # Test process tree
        tree = ProcessInventory.get_process_tree()
        self.assertIn("total_processes", tree)
        self.assertIn("process_tree", tree)
        self.assertGreater(tree["total_processes"], 0)

        # Test service-to-process mapper
        svc_map = ServiceProcessMapper.get_service_process_mapping()
        self.assertIn("running_services_with_pid", svc_map)
        self.assertIn("service_host_groups_count", svc_map)

    @unittest.skipUnless(sys.platform == 'win32', "Driver Matcher requires Windows host")
    def test_driver_matcher_audit(self):
        """Verifies Track 1: Driver matcher correlates devices with driver rank."""
        from windows_intelligence.device_intelligence import DriverMatcher

        audit_res = DriverMatcher.audit_device_driver_bindings(max_devices=10)
        self.assertEqual(audit_res["status"], "success")
        self.assertIn("devices_audited", audit_res)
        self.assertIn("driver_packages_cataloged", audit_res)
        self.assertIn("device_reports", audit_res)

    @unittest.skipUnless(sys.platform == 'win32', "CLI Windows Intelligence subcommands require Windows host")
    def test_cli_parallel_tracks_subcommands(self):
        """Verifies that file-locks, proc-modules, and dev-match CLI subcommands execute cleanly."""
        cli_path = os.path.join(SRC_DIR, "cli.py")

        # Test help outputs
        for subcmd in ("file-locks", "proc-modules", "dev-match"):
            p = subprocess.run([sys.executable, cli_path, subcmd, "--help"], capture_output=True, text=True, check=True)
            self.assertEqual(p.returncode, 0)
            self.assertIn(subcmd, p.stdout)

        # Test dev-match live output
        p_match = subprocess.run(
            [sys.executable, cli_path, "dev-match", "--query", "Intel"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True
        )
        data = json.loads(p_match.stdout)
        self.assertEqual(data["status"], "success")
        self.assertIn("device_reports", data)


    # --- Safety Kernel & Non-Destructive Execution Tests ---

    def test_safety_kernel_path_identity_and_anti_traversal(self):
        """Verifies PathIdentity rejects Alternate Data Streams, null bytes, and raw device paths."""
        from security import PathIdentity

        with self.assertRaises(ValueError):
            PathIdentity.canonicalize(r"C:\test\target.exe:stream")

        with self.assertRaises(ValueError):
            PathIdentity.canonicalize(r"\\.\PhysicalDrive0")

        with self.assertRaises(ValueError):
            PathIdentity.canonicalize("test\x00file.exe")

    def test_safety_kernel_target_scope_baseline_and_tamper_detection(self):
        """Verifies TargetScope computes baseline SHA-256 and detects any single-byte mutation."""
        from security import TargetScope

        target_dir = tempfile.mkdtemp(prefix="bintra_tgt_")
        target_path = os.path.join(target_dir, "test_binary.exe")
        with open(target_path, "wb") as f:
            f.write(b"immutable_pe_bytes_version_1")

        try:
            scope = TargetScope(target_binary_path=target_path)
            self.assertTrue(scope.is_target_file(target_path))
            self.assertTrue(scope.is_target_directory(target_dir))

            # Initial integrity verification
            check1 = scope.verify_target_integrity(target_path)
            self.assertTrue(check1["is_intact"])
            self.assertFalse(check1["tamper_detected"])

            # Mutate target by 1 byte
            with open(target_path, "wb") as f:
                f.write(b"immutable_pe_bytes_version_2")

            check2 = scope.verify_target_integrity(target_path)
            self.assertFalse(check2["is_intact"])
            self.assertTrue(check2["tamper_detected"])
        finally:
            if os.path.exists(target_path):
                os.remove(target_path)
            if os.path.exists(target_dir):
                os.rmdir(target_dir)

    def test_safety_kernel_execution_guard_target_immutability(self):
        """Verifies ExecutionGuard blocks writes to target files and shields target directories."""
        from security import (
            ExecutionGuard, SafeFileAccess, TargetMutationError,
            SecurityViolationError, OutOfScopeError
        )

        target_dir = tempfile.mkdtemp(prefix="bintra_tgt_")
        target_path = os.path.join(target_dir, "protected.exe")
        with open(target_path, "wb") as f:
            f.write(b"protected_pe_content_safe")

        ws_dir = tempfile.mkdtemp(prefix="bintra_ws_")

        try:
            with ExecutionGuard.scoped_session(target_binary_path=target_path, workspace_dir=ws_dir):
                # 1. Attempting to write directly to target file must raise TargetMutationError
                with self.assertRaises(TargetMutationError):
                    SafeFileAccess.write_workspace_file(target_path, b"destructive_patch")

                # Verify target was untouched
                with open(target_path, "rb") as f:
                    self.assertEqual(f.read(), b"protected_pe_content_safe")

                # 2. Attempting to write in target directory must raise TargetMutationError
                sibling_file = os.path.join(target_dir, "sibling_leak.txt")
                with self.assertRaises(TargetMutationError):
                    SafeFileAccess.write_workspace_file(sibling_file, "forbidden sibling write")

                # 3. Attempting to write outside workspace must raise OutOfScopeError
                with self.assertRaises(OutOfScopeError):
                    SafeFileAccess.write_workspace_file(r"C:\Windows\temp_exploit.txt", "exploit")

                # 4. Writing inside designated workspace must succeed
                ws_file = os.path.join(ws_dir, "dossier.json")
                out_path = SafeFileAccess.write_workspace_file(ws_file, '{"dossier": "healthy"}')
                self.assertTrue(os.path.exists(out_path))

                # 5. Deleting session-created workspace file must succeed
                self.assertTrue(SafeFileAccess.delete_workspace_file(ws_file))

                # 6. Deleting target file must be blocked
                with self.assertRaises(SecurityViolationError):
                    SafeFileAccess.delete_workspace_file(target_path)
        finally:
            if os.path.exists(target_path):
                os.remove(target_path)
            if os.path.exists(target_dir):
                os.rmdir(target_dir)
            if os.path.exists(ws_dir):
                os.rmdir(ws_dir)

    def test_safety_kernel_prohibited_hazards_rejection(self):
        """Verifies that all hazardous mutation capabilities are unconditionally rejected by PolicyEngine."""
        from security import PolicyEngine, AccessRequest, Capability, TargetScope

        scope = TargetScope()
        prohibited = [
            Capability.TARGET_MUTATE,
            Capability.REGISTRY_MUTATE,
            Capability.PROCESS_MUTATE,
            Capability.SERVICE_MUTATE,
            Capability.DRIVER_MUTATE,
            Capability.SHELL_FREE_EXEC,
            Capability.PRIVILEGE_ELEVATE,
        ]

        for hazard in prohibited:
            req = AccessRequest(
                component="malicious_tool",
                operation="mutate_system",
                target="system_resource",
                requested_capability=hazard,
                access_mode="WRITE"
            )
            decision = PolicyEngine.evaluate(req, scope)
            self.assertFalse(decision.is_allowed)
            self.assertEqual(decision.verdict, "DENY")
            self.assertIn("forbidden by Bintra Safety Policy", decision.reason)

    def test_safety_kernel_audit_logger_complete_mediation_and_redaction(self):
        """Verifies AuditLogger captures decisions, redacts secrets, and computes summary statistics."""
        from security import AuditLogger

        AuditLogger.clear()
        AuditLogger.log_decision(
            component="sec_test",
            operation="auth_probe",
            target="svc --password UserSecretPassword123 --token API_KEY_9999",
            decision="ALLOW",
            reason="testing",
            requested_capability="cap.test"
        )
        trail = AuditLogger.get_audit_trail()
        self.assertEqual(len(trail), 1)
        logged_str = trail[0]["target"]
        self.assertNotIn("UserSecretPassword123", logged_str)
        self.assertNotIn("API_KEY_9999", logged_str)
        self.assertIn("***REDACTED***", logged_str)

        summary = AuditLogger.summarize()
        self.assertEqual(summary["total_mediated_operations"], 1)
        self.assertEqual(summary["allowed_count"], 1)
        self.assertEqual(summary["denied_count"], 0)

    @unittest.skipUnless(sys.platform == 'win32', "Safe Subprocess Broker requires Windows host")
    def test_safety_kernel_safe_subprocess_broker(self):
        """Verifies SafeSubprocessBroker executes cataloged commands safely without shell=True."""
        from security import SafeSubprocessBroker, SecurityViolationError

        # Rejection of uncataloged command
        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker.execute_catalog_command("dangerous_tool")

        # Rejection of unpermitted argument
        with self.assertRaises(SecurityViolationError):
            SafeSubprocessBroker.execute_catalog_command("os_ver", extra_flags=["/dangerous_flag"])

        # Legitimate execution of catalog command
        res = SafeSubprocessBroker.execute_catalog_command("os_ver")
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["exit_code"], 0)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_safety_kernel_target_binary_zero_mutation_post_analysis(self):
        """Verifies that full end-to-end binary and diagnostic analysis causes ZERO mutations to target PE."""
        from binary_neural_engine import BinaryFormatInspector
        from windows_intelligence.evidence_engine import CausalitySynthesizer
        from security import TargetScope

        pe_bytes = _create_synthetic_pe64()
        target_dir = tempfile.mkdtemp(prefix="bintra_audit_")
        target_path = os.path.join(target_dir, "clean_target.exe")
        with open(target_path, "wb") as f:
            f.write(pe_bytes)

        try:
            scope = TargetScope(target_binary_path=target_path)
            pre_hash = scope.compute_sha256(target_path)

            # Execute full binary inspection
            pe_info = BinaryFormatInspector.inspect(target_path)
            self.assertEqual(pe_info["format"], "PE")

            # Execute full evidence synthesis dossier
            dossier = CausalitySynthesizer.synthesize_dossier(target_path)
            self.assertEqual(dossier["status"], "success")
            self.assertIn("security_kernel_audit", dossier)

            # Verify target hash post-analysis is 100% IDENTICAL
            post_hash = scope.compute_sha256(target_path)
            self.assertEqual(pre_hash, post_hash, "Target executable MUST NOT be modified by analysis!")

            integrity = scope.verify_target_integrity(target_path)
            self.assertTrue(integrity["is_intact"])
            self.assertFalse(integrity["tamper_detected"])
        finally:
            if os.path.exists(target_path):
                os.remove(target_path)
            if os.path.exists(target_dir):
                os.rmdir(target_dir)

    @unittest.skipUnless(sys.platform == 'win32', "Requires Windows NT host")
    def test_safety_kernel_cmd_executor_fails_closed_on_denial(self):
        """Verifies that CommandExecutor fails closed with DENY decision when Safety Kernel denies execution."""
        from windows_intelligence.command_engine import CommandExecutor
        from security import CapabilityRegistry, Capability, SecurityViolationError

        # 1. Unregistered command fails
        res_unreg = CommandExecutor.execute("unknown_malicious_command")
        self.assertEqual(res_unreg["status"], "error")
        self.assertIn("not registered", res_unreg["error"])

        # 2. Unwhitelisted flag fails
        res_flag = CommandExecutor.execute("os_ver", extra_flags=("/evil_flag_99",))
        self.assertEqual(res_flag["status"], "error")
        self.assertIn("not permitted", res_flag["error"])

        # 3. Safety Kernel fail-closed mediation test
        orig_caps = set(CapabilityRegistry.get_capabilities("cmd_executor"))
        try:
            CapabilityRegistry.COMPONENT_CAPABILITIES["cmd_executor"] = set()
            res_denied = CommandExecutor.execute("os_ver")
            self.assertEqual(res_denied["status"], "error")
            self.assertEqual(res_denied.get("decision"), "DENY")
            self.assertIn("Execution blocked by Safety Kernel", res_denied["error"])
        finally:
            CapabilityRegistry.COMPONENT_CAPABILITIES["cmd_executor"] = orig_caps

    def test_safety_kernel_mcp_patch_binary_blocks_in_place_overwrite(self):
        """Verifies that MCP bintra_patch_binary strictly forbids in-place modification of target binaries."""
        from mcp_server import BintraMcpServer
        from security import TargetMutationError, ExecutionGuard

        pe_bytes = _create_synthetic_pe64()
        target_dir = tempfile.mkdtemp(prefix="bintra_target_")
        target_path = os.path.join(target_dir, "victim_binary.exe")
        with open(target_path, "wb") as f:
            f.write(pe_bytes)

        server = BintraMcpServer()
        try:
            # 1. dispatch_tool: Omitting output_path raises TargetMutationError
            with self.assertRaises(TargetMutationError):
                server.dispatch_tool("bintra_patch_binary", {
                    "file_path": target_path,
                    "offset": 0,
                    "patch_hex": "90"
                })

            # 2. dispatch_tool: Same output_path as target_path raises TargetMutationError
            with self.assertRaises(TargetMutationError):
                server.dispatch_tool("bintra_patch_binary", {
                    "file_path": target_path,
                    "output_path": target_path,
                    "offset": 0,
                    "patch_hex": "90"
                })

            # 3. handle_tools_call: Same output_path returns isError=True with TARGET_WRITE_FORBIDDEN
            call_res = server.handle_tools_call({
                "name": "bintra_patch_binary",
                "arguments": {
                    "file_path": target_path,
                    "output_path": target_path,
                    "offset": 0,
                    "patch_hex": "90"
                }
            })
            self.assertTrue(call_res["isError"])
            err_json = json.loads(call_res["content"][0]["text"])
            self.assertIn("TARGET_WRITE_FORBIDDEN", err_json["error"])

            # 4. Engine level: when target_path is registered in active scope, SurgicalBinaryPatcher.patch_file blocks mutation
            from binary_neural_engine import SurgicalBinaryPatcher
            with ExecutionGuard.scoped_session(target_binary_path=target_path):
                with self.assertRaises(TargetMutationError):
                    SurgicalBinaryPatcher.patch_file(target_path, target_path, 0, "90")

            # 5. Legitimate out-of-place patch to workspace succeeds and preserves original target intact
            workspace_dir = tempfile.mkdtemp(prefix="bintra_work_")
            out_path = os.path.join(workspace_dir, "patched_target.exe")
            try:
                with ExecutionGuard.scoped_session(target_binary_path=target_path, workspace_dir=workspace_dir):
                    patch_res = server.dispatch_tool("bintra_patch_binary", {
                        "file_path": target_path,
                        "output_path": out_path,
                        "offset": 0,
                        "patch_hex": "4D5A",
                        "force": True
                    })
                    self.assertEqual(patch_res["output_file"], out_path)
                    self.assertTrue(os.path.exists(out_path))
                    # Original target is completely untouched
                    with open(target_path, "rb") as f:
                        self.assertEqual(f.read(), pe_bytes)
            finally:
                if os.path.exists(out_path):
                    os.remove(out_path)
                if os.path.exists(workspace_dir):
                    os.rmdir(workspace_dir)
        finally:
            if os.path.exists(target_path):
                os.remove(target_path)
            if os.path.exists(target_dir):
                os.rmdir(target_dir)

    def test_safety_kernel_capability_registry_enforcement_in_policy_engine(self):
        """Verifies that PolicyEngine enforces CapabilityRegistry grants and mode matching."""
        from security.policy_engine import PolicyEngine, AccessRequest
        from security import CapabilityRegistry, Capability, TargetScope

        scope = TargetScope(target_binary_path="C:\\dummy\\target.exe")

        # 1. Component with no granted capability is DENIED
        req1 = AccessRequest(
            component="unauthorized_subsystem",
            operation="read_file",
            target="C:\\dummy\\target.exe",
            requested_capability=Capability.FILE_READ,
            access_mode="READ"
        )
        dec1 = PolicyEngine.evaluate(req1, scope=scope)
        self.assertEqual(dec1.verdict, "DENY")
        self.assertIn("CAPABILITY_NOT_GRANTED", dec1.reason)

        # 2. Mode mismatch: Requesting WRITE mode with FILE_READ capability is DENIED
        req2 = AccessRequest(
            component="safe_file_access",
            operation="modify_file",
            target="C:\\dummy\\target.exe",
            requested_capability=Capability.FILE_READ,
            access_mode="WRITE"
        )
        dec2 = PolicyEngine.evaluate(req2, scope=scope)
        self.assertEqual(dec2.verdict, "DENY")
        self.assertIn("CAPABILITY_MISMATCH", dec2.reason)

        # 3. Mode mismatch: Requesting DELETE mode with FILE_READ capability is DENIED
        req3 = AccessRequest(
            component="safe_file_access",
            operation="delete_file",
            target="C:\\dummy\\target.exe",
            requested_capability=Capability.FILE_READ,
            access_mode="DELETE"
        )
        dec3 = PolicyEngine.evaluate(req3, scope=scope)
        self.assertEqual(dec3.verdict, "DENY")
        self.assertIn("CAPABILITY_MISMATCH", dec3.reason)

        # 4. Legitimate granted capability with valid mode is ALLOWED
        req4 = AccessRequest(
            component="safe_file_access",
            operation="read_target_binary",
            target="C:\\dummy\\target.exe",
            requested_capability=Capability.FILE_READ,
            access_mode="READ"
        )
        dec4 = PolicyEngine.evaluate(req4, scope=scope)
        self.assertEqual(dec4.verdict, "ALLOW")

    def test_safety_kernel_audit_logger_hash_chain_tamper_verification(self):
        """Verifies that AuditLogger creates a cryptographic SHA-256 hash chain and detects tampering."""
        from security import AuditLogger

        AuditLogger.clear()
        AuditLogger.log_decision(
            component="test_comp_1",
            operation="op_read",
            target="C:\\safe\\file1.txt",
            decision="ALLOW",
            reason="valid_read",
            requested_capability="cap.read"
        )
        AuditLogger.log_decision(
            component="test_comp_2",
            operation="op_exec",
            target="whoami",
            decision="ALLOW",
            reason="catalog_command",
            requested_capability="cap.exec"
        )
        AuditLogger.log_decision(
            component="test_comp_3",
            operation="op_write",
            target="C:\\target.exe",
            decision="DENY",
            reason="TARGET_WRITE_FORBIDDEN",
            requested_capability="cap.write"
        )

        # Hash chain must be completely valid initially
        chain_status = AuditLogger.verify_audit_chain()
        self.assertTrue(chain_status["is_valid"])
        self.assertEqual(chain_status["records_verified"], 3)

        trail = AuditLogger.get_audit_trail()
        self.assertEqual(len(trail), 3)
        self.assertEqual(trail[0]["sequence"], 0)
        self.assertEqual(trail[1]["sequence"], 1)
        self.assertEqual(trail[2]["sequence"], 2)
        # Sequence 0 has zero initial prev_hash
        self.assertEqual(trail[0]["prev_hash"], "0" * 64)
        # Sequence 1 prev_hash matches sequence 0 record_hash
        self.assertEqual(trail[1]["prev_hash"], trail[0]["record_hash"])
        # Sequence 2 prev_hash matches sequence 1 record_hash
        self.assertEqual(trail[2]["prev_hash"], trail[1]["record_hash"])

        # Tampering with record in-memory breaks cryptographic integrity
        AuditLogger._journal[1]["target"] = "tampered_arbitrary_cmd"
        tamper_status = AuditLogger.verify_audit_chain()
        self.assertFalse(tamper_status["is_valid"])
        self.assertIn("Tamper detected", tamper_status["error"])
        self.assertEqual(tamper_status["failed_sequence"], 1)

    def test_hardlink_target_immutability_enforcement(self):
        """Verifies Audit §2.1: Hard-link aliases of registered targets inside workspaces are strictly blocked."""
        from security import ExecutionGuard, SafeFileAccess, TargetMutationError, TargetScope
        target_dir = tempfile.mkdtemp(prefix="bintra_tgt_hl_")
        ws_dir = tempfile.mkdtemp(prefix="bintra_ws_hl_")
        tgt_file = os.path.join(target_dir, "original_target.bin")
        with open(tgt_file, "w") as f:
            f.write("PROTECTED_TARGET_DATA")

        link_file = os.path.join(ws_dir, "hardlink_alias.bin")
        try:
            os.link(tgt_file, link_file)
            scope = TargetScope(target_binary_path=tgt_file, workspace_dir=ws_dir)
            self.assertTrue(scope.is_target_file(link_file), "TargetScope must identify hard-link alias as target file")

            with ExecutionGuard.scoped_session(target_binary_path=tgt_file, workspace_dir=ws_dir):
                with self.assertRaises(TargetMutationError):
                    SafeFileAccess.write_workspace_file(link_file, "MUTATED_VIA_HARDLINK")
            # Verify target content remains byte-identical
            with open(tgt_file, "r") as f:
                self.assertEqual(f.read(), "PROTECTED_TARGET_DATA")
        finally:
            shutil.rmtree(target_dir, ignore_errors=True)
            shutil.rmtree(ws_dir, ignore_errors=True)

    def test_stack_proprioception_clobber_instructions(self):
        """Verifies Audit §2.2: compute_stack_proprioception flags all RSP-altering instructions."""
        from binary_neural_engine import SurgicalBinaryPatcher
        adversarial_cases = [
            ("4889c4", "mov rsp, rax"),
            ("488d20", "lea rsp, [rax]"),
            ("4889cc", "mov rsp, rcx"),
            ("488d642408", "lea rsp, [rsp+8]"),
            ("ff30", "push qword ptr [rax]"),
            ("8f00", "pop qword ptr [rax]"),
            ("4894", "xchg rsp, rax"),
        ]
        for hex_code, desc in adversarial_cases:
            code_bytes = bytes.fromhex(hex_code)
            prop = SurgicalBinaryPatcher.compute_stack_proprioception(code_bytes)
            self.assertFalse(prop["is_frame_invariant"], f"Failed to flag {desc} ({hex_code}) as frame variant")
            self.assertGreater(len(prop["violating_instructions"]), 0, f"No violations recorded for {desc}")
            is_safe, reason = SurgicalBinaryPatcher.verify_stack_safety(code_bytes)
            self.assertFalse(is_safe, f"verify_stack_safety falsely approved {desc}")

    def test_safetensors_validation_schema_and_boundaries(self):
        """Verifies Audit §3.1: SafetensorsHandler strictly validates dtype, offsets, shapes, and overlaps."""
        from bintra_engine import SafetensorsHandler

        def make_st(header_dict: dict, data_bytes: bytes, target_dir: str = None) -> str:
            hdr_json = json.dumps(header_dict, separators=(",", ":")).encode("utf-8")
            tf = tempfile.NamedTemporaryFile(suffix=".safetensors", dir=target_dir, delete=False)
            tf.write(struct.pack("<Q", len(hdr_json)) + hdr_json + data_bytes)
            tf.close()
            return tf.name

        # Case 1: Unknown dtype
        p1 = make_st({"x": {"dtype": "INVALID", "shape": [1], "data_offsets": [0, 4]}}, b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError):
            SafetensorsHandler.read_header(p1)
        os.remove(p1)

        # Case 2: Negative data_offsets
        p2 = make_st({"x": {"dtype": "F32", "shape": [1], "data_offsets": [-4, 0]}}, b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError):
            SafetensorsHandler.read_header(p2)
        os.remove(p2)

        # Case 3: Overlapping data offsets
        p3 = make_st({
            "x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
            "y": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}
        }, b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError):
            SafetensorsHandler.read_header(p3)
        os.remove(p3)

        # Case 4: Negative shape dimension
        p4 = make_st({"x": {"dtype": "F32", "shape": [-1], "data_offsets": [0, 4]}}, b"\x00\x00\x00\x00")
        with self.assertRaises(ValueError):
            SafetensorsHandler.read_header(p4)
        os.remove(p4)

        # Case 5: Missing tensor in write_patched_safetensors
        tgt_dir = tempfile.mkdtemp(prefix="bintra_tgt_dir_")
        ws_dir = tempfile.mkdtemp(prefix="bintra_ws_dir_")
        p5 = make_st({"x": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}, b"\x00\x00\x00\x00", target_dir=tgt_dir)
        out_p = os.path.join(ws_dir, "patched.safetensors")
        from security import ExecutionGuard
        try:
            with ExecutionGuard.scoped_session(target_binary_path=p5, workspace_dir=ws_dir):
                with self.assertRaises(KeyError):
                    SafetensorsHandler.write_patched_safetensors(p5, out_p, {"does_not_exist": np.array([1.0], dtype=np.float32)})
        finally:
            shutil.rmtree(tgt_dir, ignore_errors=True)
            shutil.rmtree(ws_dir, ignore_errors=True)

    def test_svd_non_finite_resilience(self):
        """Verifies Audit §3.2: SubspaceAnalyzer returns structured error dict on NaN or Inf input."""
        from bintra_engine import SubspaceAnalyzer
        m_nan = np.array([[np.nan, 1.0], [0.0, 2.0]], dtype=np.float32)
        res_nan = SubspaceAnalyzer.analyze_svd(m_nan)
        self.assertEqual(res_nan["status"], "error")
        self.assertIn("non-finite", res_nan["error"])

        m_inf = np.array([[np.inf, 1.0], [0.0, 2.0]], dtype=np.float32)
        res_inf = SubspaceAnalyzer.analyze_svd(m_inf)
        self.assertEqual(res_inf["status"], "error")
        self.assertIn("non-finite", res_inf["error"])

    def test_hybrid_dissector_tflite_and_zip_dos_protection(self):
        """Verifies Audit §3.4 & §4: TFLite requires valid vtable structure, and dense ZIP markers avoid DoS."""
        from binary_neural_engine import HybridBinaryDissector
        # Test 13-byte raw TFL3
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(b"XXXXTFL3YYYYY")
            p_tfl = tf.name
        try:
            res_tfl = HybridBinaryDissector.scan_for_embedded_logic(p_tfl)
            self.assertEqual(len(res_tfl["findings"]), 1)
            self.assertEqual(res_tfl["findings"][0]["confidence"], "LOW")
            self.assertIn("Unverified", res_tfl["findings"][0]["type"])
        finally:
            os.remove(p_tfl)

        # Test dense PK0304 non-PyTorch buffer (must be sub-second, non-hanging)
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write((b"PK\x03\x04" + b"\x00" * 28) * 10000)
            p_zip = tf.name
        try:
            res_zip = HybridBinaryDissector.scan_for_embedded_logic(p_zip)
            self.assertEqual(len(res_zip["findings"]), 0)
        finally:
            os.remove(p_zip)

if __name__ == "__main__":
    unittest.main()
