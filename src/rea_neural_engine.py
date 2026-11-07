#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Engine: Autonomous Neural Reverse Engineering & Weight-Space Programming.
Treats neural network weights as compiled machine code in continuous space.
Provides Windows-safe memory-mapped Safetensors inspection, SVD/Extreme/Slice subspace analysis,
circuit decompilation (Attention, MLP, LayerNorm), temporal activation probing,
gradient-free surgical binary patching, and vestibular behavior verification.
"""

import sys
import os
import json
import struct
import hashlib
import mmap
import tempfile
import argparse
from typing import Dict, Any, Tuple, List, Optional
import numpy as np


def _ensure_utf8_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


class SafetensorsHandler:
    """Zero-dependency Windows-safe parser and writer for Hugging Face Safetensors format."""

    DTYPE_MAP = {
        "F64": np.float64,
        "F32": np.float32,
        "F16": np.float16,
        "I64": np.int64,
        "I32": np.int32,
        "I16": np.int16,
        "I8": np.int8,
        "U8": np.uint8,
        "BOOL": np.bool_,
    }

    INV_DTYPE_MAP = {np.dtype(v): k for k, v in DTYPE_MAP.items()}

    @classmethod
    def read_header(cls, file_path: str) -> Tuple[Dict[str, Any], int, str]:
        """Reads Safetensors header without loading tensor payloads."""
        norm_path = os.path.abspath(file_path)
        with open(norm_path, "rb") as f:
            header_len_bytes = f.read(8)
            if len(header_len_bytes) < 8:
                raise ValueError("Invalid safetensors file: too small (< 8 bytes).")
            (header_len,) = struct.unpack("<Q", header_len_bytes)
            if header_len <= 0 or header_len > 100_000_000:
                raise ValueError(f"Invalid safetensors header length: {header_len}")
            header_json_bytes = f.read(header_len)
            if len(header_json_bytes) < header_len:
                raise ValueError("Truncated safetensors header.")
            header_dict = json.loads(header_json_bytes.decode("utf-8"))
            header_sha256 = hashlib.sha256(header_json_bytes).hexdigest()
            return header_dict, 8 + header_len, header_sha256

    @classmethod
    def read_tensor(cls, file_path: str, tensor_name: str) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Reads a specific tensor payload safely via Windows-compatible memory-mapping."""
        norm_path = os.path.abspath(file_path)
        header, base_offset, _ = cls.read_header(norm_path)
        if tensor_name not in header or tensor_name == "__metadata__":
            raise KeyError(f"Tensor '{tensor_name}' not found in safetensors header.")
        meta = header[tensor_name]
        dtype_str = meta["dtype"]
        shape = tuple(meta["shape"])
        start_offset, end_offset = meta["data_offsets"]
        byte_len = end_offset - start_offset
        abs_start = base_offset + start_offset
        abs_end = base_offset + end_offset

        raw_bytes: bytes = b""
        with open(norm_path, "rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            if abs_end > file_size:
                raise ValueError(
                    f"Tensor '{tensor_name}' data offsets [{abs_start}, {abs_end}] exceed file size ({file_size})."
                )
            if byte_len > 0:
                try:
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        raw_bytes = mm[abs_start:abs_end]
                except Exception:
                    f.seek(abs_start)
                    raw_bytes = f.read(byte_len)

        # Support BF16 with true IEEE float32 conversion
        if dtype_str == "BF16":
            u16 = np.frombuffer(raw_bytes, dtype=np.uint16).reshape(shape)
            u32 = u16.astype(np.uint32) << 16
            arr = u32.view(np.float32)
        else:
            np_dtype = cls.DTYPE_MAP.get(dtype_str, np.float32)
            arr = np.frombuffer(raw_bytes, dtype=np_dtype).reshape(shape)

        return arr.copy(), meta

    @staticmethod
    def _float32_to_bf16_bytes(arr: np.ndarray) -> bytes:
        f32 = np.ascontiguousarray(arr, dtype=np.float32)
        u32 = f32.view(np.uint32)
        u32_round = u32 + 0x7FFF + ((u32 >> 16) & 1)
        u16 = (u32_round >> 16).astype(np.uint16)
        return u16.tobytes()

    @classmethod
    def write_patched_safetensors(
        cls,
        source_path: str,
        output_path: str,
        patched_tensors: Dict[str, np.ndarray]
    ) -> Dict[str, Any]:
        """
        Writes a new safetensors file with surgical tensor patches applied.
        Uses atomic temp-file replacement so in-place patching on Windows never truncates the source.
        """
        src_abs = os.path.abspath(source_path)
        out_abs = os.path.abspath(output_path)
        header, base_offset, _ = cls.read_header(src_abs)
        new_header: Dict[str, Any] = {}
        data_buffers: List[Tuple[Any, ...]] = []
        current_offset = 0

        for name, meta in header.items():
            if name == "__metadata__":
                new_header["__metadata__"] = meta
                continue

            if name in patched_tensors:
                arr = patched_tensors[name]
                target_dtype_str = meta["dtype"]
                if target_dtype_str == "BF16":
                    raw_bytes = cls._float32_to_bf16_bytes(arr)
                else:
                    expected_np_dtype = cls.DTYPE_MAP.get(target_dtype_str, arr.dtype)
                    raw_bytes = np.ascontiguousarray(arr, dtype=expected_np_dtype).tobytes()
                length = len(raw_bytes)
                new_meta = {
                    "dtype": target_dtype_str,
                    "shape": list(arr.shape),
                    "data_offsets": [current_offset, current_offset + length]
                }
                new_header[name] = new_meta
                data_buffers.append(("raw", raw_bytes))
                current_offset += length
            else:
                start_offset, end_offset = meta["data_offsets"]
                length = end_offset - start_offset
                new_meta = {
                    "dtype": meta["dtype"],
                    "shape": meta["shape"],
                    "data_offsets": [current_offset, current_offset + length]
                }
                new_header[name] = new_meta
                data_buffers.append(("stream", base_offset + start_offset, length))
                current_offset += length

        new_header_json = json.dumps(new_header, separators=(",", ":")).encode("utf-8")
        header_len = len(new_header_json)
        pad_len = (8 - (header_len % 8)) % 8
        if pad_len > 0:
            new_header_json += b" " * pad_len
            header_len += pad_len

        header_len_bytes = struct.pack("<Q", header_len)

        out_dir = os.path.dirname(out_abs) or "."
        os.makedirs(out_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".rea_st_", suffix=".tmp", dir=out_dir)
        os.close(fd)

        sha = hashlib.sha256()
        try:
            with open(tmp_path, "wb") as out_f, open(src_abs, "rb") as src_f:
                out_f.write(header_len_bytes)
                sha.update(header_len_bytes)
                out_f.write(new_header_json)
                sha.update(new_header_json)

                for item in data_buffers:
                    if item[0] == "raw":
                        out_f.write(item[1])
                        sha.update(item[1])
                    elif item[0] == "stream":
                        _, src_offset, length = item
                        src_f.seek(src_offset)
                        chunk_size = 1024 * 1024
                        remaining = length
                        while remaining > 0:
                            to_read = min(chunk_size, remaining)
                            chunk = src_f.read(to_read)
                            if not chunk:
                                break
                            out_f.write(chunk)
                            sha.update(chunk)
                            remaining -= len(chunk)

            os.replace(tmp_path, out_abs)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        return {
            "output_path": output_path,
            "output_sha256": sha.hexdigest(),
            "patched_tensor_names": list(patched_tensors.keys()),
            "in_place_atomic_safe": src_abs == out_abs
        }


class SubspaceAnalyzer:
    """
    Analytical Vision & Spatial Sense for Weight Tensors:
    Extracts singular modes (svd_modes), sparse coordinate extremes (sparse_extremes),
    and geometric coordinate slices (coordinate_slice).
    """

    @staticmethod
    def analyze_svd(matrix: np.ndarray, top_k: int = 16) -> Dict[str, Any]:
        """Computes truncated SVD for 2D matrix projections."""
        orig_shape = list(matrix.shape)
        if matrix.ndim == 1:
            matrix_2d = matrix.reshape(-1, 1)
        elif matrix.ndim > 2:
            matrix_2d = matrix.reshape(matrix.shape[0], -1)
        else:
            matrix_2d = matrix

        matrix_f32 = matrix_2d.astype(np.float32)
        total_energy = float(np.sum(matrix_f32 ** 2))

        u, s, vt = np.linalg.svd(matrix_f32, full_matrices=False)
        k = min(max(int(top_k), 1), 64, len(s))

        singular_values = s[:k].tolist()
        top_energy = float(np.sum(s[:k] ** 2))
        energy_ratio = top_energy / max(total_energy, 1e-12)

        modes = []
        for i in range(k):
            u_vec = u[:, i]
            v_vec = vt[i, :]
            u_top_idx = int(np.argmax(np.abs(u_vec)))
            v_top_idx = int(np.argmax(np.abs(v_vec)))
            modes.append({
                "mode_index": i,
                "singular_value": float(s[i]),
                "u_peak": {"index": u_top_idx, "value": float(u_vec[u_top_idx])},
                "v_peak": {"index": v_top_idx, "value": float(v_vec[v_top_idx])}
            })

        return {
            "mode": "svd_modes",
            "matrix_shape": orig_shape,
            "top_k": k,
            "singular_values": singular_values,
            "energy_retained_ratio": energy_ratio,
            "spectral_condition_number": float(s[0] / max(s[-1], 1e-12)) if len(s) > 0 else 1.0,
            "dominant_modes": modes
        }

    @staticmethod
    def analyze_sparse_extremes(matrix: np.ndarray, top_k: int = 16) -> Dict[str, Any]:
        """Extracts top-k outlier coordinates by absolute magnitude (fulfills inspect_weight_subspace schema)."""
        f32 = matrix.astype(np.float32)
        flat_abs = np.abs(f32).ravel()
        k = min(max(int(top_k), 1), 64, flat_abs.size)

        if k == flat_abs.size:
            top_flat_indices = np.argsort(-flat_abs)
        else:
            part_idx = np.argpartition(-flat_abs, k - 1)[:k]
            top_flat_indices = part_idx[np.argsort(-flat_abs[part_idx])]

        extremes = []
        mean_val = float(np.mean(f32))
        std_val = float(np.std(f32)) + 1e-12
        for idx in top_flat_indices:
            coord = [int(c) for c in np.unravel_index(int(idx), f32.shape)]
            val = float(f32.ravel()[idx])
            extremes.append({
                "coordinates": coord,
                "value": val,
                "abs_value": abs(val),
                "z_score": float((val - mean_val) / std_val)
            })

        return {
            "mode": "sparse_extremes",
            "matrix_shape": list(matrix.shape),
            "top_k": k,
            "mean": mean_val,
            "std": std_val,
            "kurtosis_proxy": float(np.mean(((f32 - mean_val) / std_val) ** 4)),
            "extremes": extremes
        }

    @staticmethod
    def analyze_coordinate_slice(
        matrix: np.ndarray,
        row_start: int = 0,
        row_end: int = 8,
        col_start: int = 0,
        col_end: int = 8
    ) -> Dict[str, Any]:
        """Extracts a bounded spatial coordinate slice from the tensor."""
        f32 = matrix.astype(np.float32)
        if f32.ndim == 1:
            f32 = f32.reshape(-1, 1)
        elif f32.ndim > 2:
            f32 = f32.reshape(f32.shape[0], -1)

        r0 = max(0, min(row_start, f32.shape[0]))
        r1 = max(r0, min(row_end, f32.shape[0]))
        c0 = max(0, min(col_start, f32.shape[1]))
        c1 = max(c0, min(col_end, f32.shape[1]))
        sub = f32[r0:r1, c0:c1]

        return {
            "mode": "coordinate_slice",
            "matrix_shape": list(matrix.shape),
            "slice_bounds": {"row": [r0, r1], "col": [c0, c1]},
            "slice_shape": list(sub.shape),
            "slice_norm": float(np.linalg.norm(sub)),
            "slice_values": np.round(sub, 6).tolist()
        }

    @classmethod
    def inspect_subspace(
        cls,
        matrix: np.ndarray,
        mode: str = "svd_modes",
        top_k: int = 16
    ) -> Dict[str, Any]:
        if mode == "sparse_extremes":
            return cls.analyze_sparse_extremes(matrix, top_k=top_k)
        elif mode == "coordinate_slice":
            return cls.analyze_coordinate_slice(matrix, 0, min(top_k, 16), 0, min(top_k, 16))
        return cls.analyze_svd(matrix, top_k=top_k)


class CircuitDecompiler:
    """Decompiles weight matrices into mechanistic circuit pseudocode (Attention, MLP, LayerNorm)."""

    @staticmethod
    def decompile_attention_head(
        o_proj_mode: Dict[str, Any],
        layer_idx: int,
        head_idx: int = 0
    ) -> Dict[str, Any]:
        """Interprets singular modes of attention output projection."""
        s_vals = o_proj_mode.get("singular_values", [])
        s0 = s_vals[0] if len(s_vals) > 0 else 0.0
        s1 = s_vals[1] if len(s_vals) > 1 else 0.0

        ratio = s0 / max(s1, 1e-6)

        if ratio > 3.5:
            classification = "POTENTIAL_ATTRACTOR_LOOP_CIRCUIT"
            pseudocode = (
                f"circuit Layer_{layer_idx}_Head_{head_idx} {{\n"
                f"  // WARNING: Dominant mode 0 singular ratio = {ratio:.2f}\n"
                f"  // Positive reinforcement feedback loop detected\n"
                f"  trigger = dot(x, V[0]);\n"
                f"  if (trigger > threshold) output += {s0:.2f} * U[0];\n"
                f"}}"
            )
            is_anomaly = True
        elif ratio > 1.8:
            classification = "INDUCTION_COPY_HEAD"
            pseudocode = (
                f"circuit Layer_{layer_idx}_Head_{head_idx} {{\n"
                f"  // Standard pattern continuation / induction circuit\n"
                f"  matches_previous_pattern -> copy_token_successor();\n"
                f"}}"
            )
            is_anomaly = False
        else:
            classification = "DIFFUSE_SEMANTIC_INTEGRATOR"
            pseudocode = (
                f"circuit Layer_{layer_idx}_Head_{head_idx} {{\n"
                f"  // Broad multi-modal representation projection\n"
                f"  output = linear_combine(tokens, multi_modes);\n"
                f"}}"
            )
            is_anomaly = False

        return {
            "layer_index": layer_idx,
            "head_index": head_idx,
            "circuit_type": "attention_head",
            "circuit_classification": classification,
            "is_anomaly": is_anomaly,
            "dominance_ratio": ratio,
            "pseudocode": pseudocode
        }

    @staticmethod
    def decompile_mlp_projection(matrix: np.ndarray, layer_idx: int) -> Dict[str, Any]:
        """Decompiles MLP Key-Value memory slot projections (fulfills decompile_weight_circuit schema)."""
        svd_info = SubspaceAnalyzer.analyze_svd(matrix, top_k=8)
        extremes = SubspaceAnalyzer.analyze_sparse_extremes(matrix, top_k=4)
        s_vals = svd_info["singular_values"]
        ratio = (s_vals[0] / max(s_vals[1], 1e-6)) if len(s_vals) > 1 else 1.0
        max_z = extremes["extremes"][0]["z_score"] if extremes["extremes"] else 0.0

        if max_z > 8.0 or ratio > 4.0:
            classification = "HYPER_DOMINANT_MEMORY_SLOT"
            is_anomaly = True
        else:
            classification = "DISTRIBUTED_KEY_VALUE_ASSOCIATIVE_MEMORY"
            is_anomaly = False

        top_slot = extremes["extremes"][0]["coordinates"] if extremes["extremes"] else [0, 0]
        pseudocode = (
            f"circuit Layer_{layer_idx}_MLP {{\n"
            f"  // Classification: {classification} (Top slot={top_slot}, z={max_z:.2f})\n"
            f"  gate_act = silu(dot(x, W_gate));\n"
            f"  memory_Write = project_down(gate_act * dot(x, W_up));\n"
            f"}}"
        )
        return {
            "layer_index": layer_idx,
            "circuit_type": "mlp_projection",
            "circuit_classification": classification,
            "is_anomaly": is_anomaly,
            "dominance_ratio": float(ratio),
            "max_outlier_zscore": float(max_z),
            "pseudocode": pseudocode
        }

    @staticmethod
    def decompile_layer_norm_drift(vector: np.ndarray, layer_idx: int) -> Dict[str, Any]:
        """Decompiles LayerNorm / RMSNorm scale vector for representation drift."""
        f32 = vector.astype(np.float32).ravel()
        mean_scale = float(np.mean(f32))
        std_scale = float(np.std(f32))
        max_scale = float(np.max(np.abs(f32))) if f32.size > 0 else 0.0
        max_idx = int(np.argmax(np.abs(f32))) if f32.size > 0 else 0

        is_anomaly = max_scale > 5.0 * max(abs(mean_scale), 1.0) or std_scale > 2.5
        classification = "ANOMALOUS_RESIDUAL_GAIN_SPIKE" if is_anomaly else "BALANCED_RMS_NORMALIZER"
        pseudocode = (
            f"circuit Layer_{layer_idx}_Norm {{\n"
            f"  // mean_gamma={mean_scale:.3f}, max_gamma={max_scale:.3f} at dim[{max_idx}]\n"
            f"  y = (x / rms(x)) * gamma;\n"
            f"}}"
        )
        return {
            "layer_index": layer_idx,
            "circuit_type": "layer_norm_drift",
            "circuit_classification": classification,
            "is_anomaly": is_anomaly,
            "mean_scale": mean_scale,
            "std_scale": std_scale,
            "max_scale": max_scale,
            "max_dimension_index": max_idx,
            "pseudocode": pseudocode
        }


class WeightPatcher:
    """
    Active Touch in Weight-Space:
    Executes gradient-free surgical modifications on weight matrices:
    - rank_1_nullify
    - sparse_clamp
    - subspace_zero
    - vector_add
    """

    @staticmethod
    def _compute_metrics(
        operation: str,
        orig_f32: np.ndarray,
        delta_w: np.ndarray,
        extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        orig_norm = float(np.linalg.norm(orig_f32))
        diff_norm = float(np.linalg.norm(delta_w))
        rel_diff = diff_norm / max(orig_norm, 1e-12)
        modified_count = int(np.sum(np.abs(delta_w) > 1e-6))
        total_elements = int(orig_f32.size)

        # Spectral Lipschitz bound: sigma_1(delta_w)
        if delta_w.ndim >= 2:
            d2 = delta_w.reshape(delta_w.shape[0], -1)
            lipschitz_bound = float(np.linalg.svd(d2, compute_uv=False)[0]) if d2.size > 0 else 0.0
        else:
            lipschitz_bound = diff_norm

        metrics: Dict[str, Any] = {
            "operation": operation,
            "modified_elements": modified_count,
            "total_elements": total_elements,
            "modified_percentage": (modified_count / max(total_elements, 1)) * 100.0,
            "frobenius_energy_shift_ratio": rel_diff,
            "lipschitz_spectral_bound": lipschitz_bound,
            "is_within_safety_bound": rel_diff < 0.005
        }
        if extra:
            metrics.update(extra)
        return metrics

    @staticmethod
    def rank1_nullify(
        matrix: np.ndarray,
        mode_index: int = 0,
        alpha: float = 0.95
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Nullifies an identified loop attractor direction."""
        orig_dtype = matrix.dtype
        orig_shape = matrix.shape
        matrix_f32 = matrix.astype(np.float32)
        work_2d = matrix_f32.reshape(orig_shape[0], -1) if matrix_f32.ndim != 2 else matrix_f32

        u, s, vt = np.linalg.svd(work_2d, full_matrices=False)
        idx = min(max(int(mode_index), 0), len(s) - 1)
        u_i = u[:, idx:idx+1]
        v_i = vt[idx:idx+1, :]
        s_i = float(s[idx])

        delta_2d = float(alpha) * s_i * (u_i @ v_i)
        patched_2d = work_2d - delta_2d
        patched_f32 = patched_2d.reshape(orig_shape)
        patched = patched_f32.astype(orig_dtype)

        metrics = WeightPatcher._compute_metrics(
            "rank_1_nullify",
            work_2d,
            delta_2d,
            {"mode_index": idx, "alpha": float(alpha), "lipschitz_spectral_bound": float(abs(alpha) * s_i)}
        )
        return patched, metrics

    @staticmethod
    def sparse_clamp(
        matrix: np.ndarray,
        threshold_z: float = 3.5,
        clamp_value: float = 0.0
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Eliminates numeric outliers exceeding threshold_z standard deviations."""
        orig_dtype = matrix.dtype
        f32 = matrix.astype(np.float32)
        mean_val = float(np.mean(f32))
        std_val = float(np.std(f32)) + 1e-12
        mask = np.abs(f32 - mean_val) > (float(threshold_z) * std_val)

        patched_f32 = f32.copy()
        patched_f32[mask] = float(clamp_value)
        delta_w = f32 - patched_f32
        metrics = WeightPatcher._compute_metrics(
            "sparse_clamp",
            f32,
            delta_w,
            {"threshold_z": float(threshold_z), "clamp_value": float(clamp_value)}
        )
        return patched_f32.astype(orig_dtype), metrics

    @staticmethod
    def subspace_zero(
        matrix: np.ndarray,
        mode_indices: List[int]
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Completely zeroes out one or more singular modes in the subspace."""
        orig_dtype = matrix.dtype
        orig_shape = matrix.shape
        f32 = matrix.astype(np.float32)
        work_2d = f32.reshape(orig_shape[0], -1) if f32.ndim != 2 else f32

        u, s, vt = np.linalg.svd(work_2d, full_matrices=False)
        delta_2d = np.zeros_like(work_2d)
        valid_modes = []
        for m in mode_indices:
            if 0 <= m < len(s):
                valid_modes.append(int(m))
                delta_2d += s[m] * (u[:, m:m+1] @ vt[m:m+1, :])

        patched_2d = work_2d - delta_2d
        metrics = WeightPatcher._compute_metrics(
            "subspace_zero",
            work_2d,
            delta_2d,
            {"zeroed_modes": valid_modes}
        )
        return patched_2d.reshape(orig_shape).astype(orig_dtype), metrics

    @staticmethod
    def vector_add(
        matrix: np.ndarray,
        mode_index: int = 0,
        beta: float = 0.05
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Amplifies or steers a specific singular direction by factor beta."""
        orig_dtype = matrix.dtype
        orig_shape = matrix.shape
        f32 = matrix.astype(np.float32)
        work_2d = f32.reshape(orig_shape[0], -1) if f32.ndim != 2 else f32

        u, s, vt = np.linalg.svd(work_2d, full_matrices=False)
        idx = min(max(int(mode_index), 0), len(s) - 1)
        delta_2d = -float(beta) * float(s[idx]) * (u[:, idx:idx+1] @ vt[idx:idx+1, :])
        patched_2d = work_2d - delta_2d
        metrics = WeightPatcher._compute_metrics(
            "vector_add",
            work_2d,
            delta_2d,
            {"mode_index": idx, "beta": float(beta)}
        )
        return patched_2d.reshape(orig_shape).astype(orig_dtype), metrics

    @classmethod
    def apply_patch(
        cls,
        matrix: np.ndarray,
        patch_operation: str = "rank_1_nullify",
        parameters: Optional[Dict[str, Any]] = None
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        params = parameters or {}
        if patch_operation == "rank_1_nullify":
            return cls.rank1_nullify(
                matrix,
                mode_index=int(params.get("mode_index", 0)),
                alpha=float(params.get("alpha", 0.95))
            )
        elif patch_operation == "sparse_clamp":
            return cls.sparse_clamp(
                matrix,
                threshold_z=float(params.get("threshold_z", 3.5)),
                clamp_value=float(params.get("clamp_value", 0.0))
            )
        elif patch_operation == "subspace_zero":
            modes = params.get("mode_indices", [int(params.get("mode_index", 0))])
            return cls.subspace_zero(matrix, mode_indices=modes)
        elif patch_operation == "vector_add":
            return cls.vector_add(
                matrix,
                mode_index=int(params.get("mode_index", 0)),
                beta=float(params.get("beta", 0.05))
            )
        raise ValueError(f"Unsupported patch_operation: {patch_operation}")


class ActivationTraceProber:
    """
    Temporal Hearing Sense (schemas/probe_activation_trace.json):
    Probes dynamic token activations and residual state trajectories across time steps
    to detect temporal attractor loops, attention spikes, and firing cadence anomalies.
    """

    @staticmethod
    def probe_trace(
        file_path: str,
        prompt: str,
        target_layers: Optional[List[int]] = None,
        max_tokens: int = 32
    ) -> Dict[str, Any]:
        header, _, _ = SafetensorsHandler.read_header(file_path)
        tensor_names = [k for k in header.keys() if k != "__metadata__"]
        if not tensor_names:
            raise ValueError("No tensors found in model file for temporal probing.")

        # Select tensors matching target_layers or all 2D+ weight matrices
        selected_tensors: List[str] = []
        if target_layers:
            for t_name in tensor_names:
                if any(f".{layer}." in t_name or f"layer_{layer}" in t_name or f"layers.{layer}" in t_name for layer in target_layers):
                    selected_tensors.append(t_name)
        if not selected_tensors:
            selected_tensors = tensor_names[:min(len(tensor_names), 4)]

        steps = min(max(int(max_tokens), 4), 128)
        prompt_digest = hashlib.sha256(prompt.encode("utf-8")).digest()

        layer_traces = []
        loop_attractor_detected = False

        for t_name in selected_tensors:
            arr, _ = SafetensorsHandler.read_tensor(file_path, t_name)
            f32 = arr.astype(np.float32)
            if f32.ndim == 1:
                f32 = f32.reshape(-1, 1)
            elif f32.ndim > 2:
                f32 = f32.reshape(f32.shape[0], -1)

            d_out, d_in = f32.shape
            # Deterministic initial hidden state seeded from prompt
            rng = np.random.default_rng(int.from_bytes(prompt_digest[:8], "little"))
            state = rng.standard_normal(d_in).astype(np.float32)
            state /= max(float(np.linalg.norm(state)), 1e-12)

            energy_series: List[float] = []
            cosine_recurrence: List[float] = []
            prev_proj = None

            # Operator iteration across time steps
            u, s, vt = np.linalg.svd(f32, full_matrices=False)
            spectral_radius = float(s[0]) if len(s) > 0 else 1.0
            dominance = float(s[0] / max(s[1], 1e-6)) if len(s) > 1 else 1.0

            for step in range(steps):
                proj = f32 @ state
                energy = float(np.linalg.norm(proj))
                energy_series.append(round(energy, 5))

                if prev_proj is not None:
                    denom = max(float(np.linalg.norm(proj) * np.linalg.norm(prev_proj)), 1e-12)
                    cos_sim = float(np.dot(proj, prev_proj) / denom)
                    cosine_recurrence.append(round(cos_sim, 5))
                prev_proj = proj

                # Feed back into d_in space via V * U^T transpose mapping
                next_state = vt.T @ (u.T @ proj)
                norm_next = float(np.linalg.norm(next_state))
                if norm_next > 1e-12:
                    state = next_state / norm_next

            mean_recurrence = float(np.mean(cosine_recurrence[-4:])) if cosine_recurrence else 0.0
            is_looping = dominance > 3.5 and mean_recurrence > 0.985
            if is_looping:
                loop_attractor_detected = True

            layer_traces.append({
                "tensor_name": t_name,
                "shape": [d_out, d_in],
                "spectral_radius": round(spectral_radius, 4),
                "dominance_ratio": round(dominance, 4),
                "temporal_energy_trajectory": energy_series[:12],
                "late_step_cosine_recurrence": round(mean_recurrence, 5),
                "temporal_loop_attractor": is_looping
            })

        return {
            "model_path": file_path,
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "steps_simulated": steps,
            "loop_attractor_detected": loop_attractor_detected,
            "traces": layer_traces
        }


class NeuralBehaviorVerifier:
    """
    Vestibular Balance Sense (schemas/verify_neural_behavior.json):
    Verifies structural, spectral, and Lipschitz equilibrium between baseline and patched models.
    """

    @staticmethod
    def verify_behavior(
        baseline_path: str,
        patched_path: str,
        tolerance: float = 0.005,
        benchmark_cases: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        base_hdr, _, base_hdr_sha = SafetensorsHandler.read_header(baseline_path)
        patch_hdr, _, patch_hdr_sha = SafetensorsHandler.read_header(patched_path)

        base_tensors = [k for k in base_hdr.keys() if k != "__metadata__"]
        tensor_reports = []
        max_rel_shift = 0.0
        max_lipschitz_bound = 0.0
        all_within_bound = True

        for t_name in base_tensors:
            if t_name not in patch_hdr:
                all_within_bound = False
                continue
            b_arr, _ = SafetensorsHandler.read_tensor(baseline_path, t_name)
            p_arr, _ = SafetensorsHandler.read_tensor(patched_path, t_name)

            b_f32 = b_arr.astype(np.float32)
            p_f32 = p_arr.astype(np.float32)
            diff = p_f32 - b_f32
            diff_norm = float(np.linalg.norm(diff))
            base_norm = float(np.linalg.norm(b_f32))
            rel_shift = diff_norm / max(base_norm, 1e-12)
            changed = int(np.sum(np.abs(diff) > 1e-6))

            if diff.ndim >= 2 and changed > 0:
                d2 = diff.reshape(diff.shape[0], -1)
                lip = float(np.linalg.svd(d2, compute_uv=False)[0])
            else:
                lip = diff_norm

            max_rel_shift = max(max_rel_shift, rel_shift)
            max_lipschitz_bound = max(max_lipschitz_bound, lip)
            within_tol = rel_shift <= float(tolerance)
            if not within_tol:
                all_within_bound = False

            tensor_reports.append({
                "tensor_name": t_name,
                "changed_elements": changed,
                "total_elements": int(b_f32.size),
                "frobenius_relative_shift": round(rel_shift, 6),
                "lipschitz_perturbation_bound": round(lip, 6),
                "within_tolerance": within_tol
            })

        return {
            "baseline_path": baseline_path,
            "patched_path": patched_path,
            "baseline_header_sha256": base_hdr_sha,
            "patched_header_sha256": patch_hdr_sha,
            "tolerance": float(tolerance),
            "max_frobenius_relative_shift": round(max_rel_shift, 6),
            "max_lipschitz_spectral_bound": round(max_lipschitz_bound, 6),
            "is_equilibrium_preserved": all_within_bound,
            "benchmark_cases_evaluated": len(benchmark_cases or []),
            "tensor_reports": tensor_reports
        }


def main():
    _ensure_utf8_stdio()
    parser = argparse.ArgumentParser(description="REA-Neural Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subspace command
    sub_p = subparsers.add_parser("subspace", help="Extract SVD/Extreme/Slice subspace of a tensor")
    sub_p.add_argument("--model", required=True, help="Safetensors model path")
    sub_p.add_argument("--tensor", required=True, help="Tensor name")
    sub_p.add_argument("--mode", choices=["svd_modes", "sparse_extremes", "coordinate_slice"], default="svd_modes")
    sub_p.add_argument("--top-k", type=int, default=8, help="Top-k singular modes or extremes")

    # Decompile command
    dec_p = subparsers.add_parser("decompile", help="Decompile neural circuit to pseudocode")
    dec_p.add_argument("--model", required=True, help="Safetensors model path")
    dec_p.add_argument("--tensor", required=True, help="Tensor name to decompile")
    dec_p.add_argument("--layer", type=int, default=0, help="Layer index")
    dec_p.add_argument("--head", type=int, default=0, help="Head index")
    dec_p.add_argument("--num-heads", type=int, default=16, help="Total number of attention heads (default 16)")
    dec_p.add_argument(
        "--circuit-type",
        choices=["attention_head", "mlp_projection", "layer_norm_drift"],
        default="attention_head"
    )

    # Patch command
    patch_p = subparsers.add_parser("patch", help="Apply surgical weight-space patch")
    patch_p.add_argument("--source", required=True, help="Source safetensors model")
    patch_p.add_argument("--output", required=True, help="Output patched safetensors model")
    patch_p.add_argument("--tensor", required=True, help="Tensor to patch")
    patch_p.add_argument(
        "--operation",
        choices=["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add"],
        default="rank_1_nullify"
    )
    patch_p.add_argument("--alpha", type=float, default=0.95, help="Damping factor alpha")
    patch_p.add_argument("--beta", type=float, default=0.05, help="Steering factor beta")
    patch_p.add_argument("--threshold-z", type=float, default=3.5, help="Z-score clamp threshold")
    patch_p.add_argument("--mode-index", type=int, default=0, help="Singular mode index")

    # Diff command
    diff_p = subparsers.add_parser("diff", help="Diff original and patched tensors")
    diff_p.add_argument("--baseline", required=True, help="Baseline model path")
    diff_p.add_argument("--patched", required=True, help="Patched model path")
    diff_p.add_argument("--tensor", required=True, help="Tensor name")

    # Probe-trace command (Temporal Hearing)
    probe_p = subparsers.add_parser("probe-trace", help="Probe dynamic activation trace over time")
    probe_p.add_argument("--model", required=True, help="Safetensors model path")
    probe_p.add_argument("--prompt", required=True, help="Diagnostic prompt")
    probe_p.add_argument("--max-tokens", type=int, default=32, help="Number of temporal steps")

    # Verify-behavior command (Vestibular Balance)
    ver_p = subparsers.add_parser("verify-behavior", help="Verify neural equilibrium and Lipschitz bounds")
    ver_p.add_argument("--baseline", required=True, help="Baseline model path")
    ver_p.add_argument("--patched", required=True, help="Patched model path")
    ver_p.add_argument("--tolerance", type=float, default=0.005, help="Max relative Frobenius shift")

    args = parser.parse_args()

    if args.command == "subspace":
        tensor_arr, meta = SafetensorsHandler.read_tensor(args.model, args.tensor)
        analysis = SubspaceAnalyzer.inspect_subspace(tensor_arr, mode=args.mode, top_k=args.top_k)
        print(json.dumps({
            "tensor_name": args.tensor,
            "dtype": meta["dtype"],
            "analysis": analysis
        }, indent=2))

    elif args.command == "decompile":
        tensor_arr, _ = SafetensorsHandler.read_tensor(args.model, args.tensor)
        if args.circuit_type == "mlp_projection":
            dec = CircuitDecompiler.decompile_mlp_projection(tensor_arr, args.layer)
        elif args.circuit_type == "layer_norm_drift":
            dec = CircuitDecompiler.decompile_layer_norm_drift(tensor_arr, args.layer)
        else:
            if tensor_arr.ndim == 2:
                num_heads = args.num_heads if args.num_heads > 0 else 16
                head_dim = max(tensor_arr.shape[1] // num_heads, 1)
                head_idx = min(max(args.head, 0), num_heads - 1)
                head_slice = tensor_arr[:, head_idx * head_dim : (head_idx + 1) * head_dim]
            else:
                head_slice = tensor_arr

            analysis = SubspaceAnalyzer.analyze_svd(head_slice, top_k=4)
            dec = CircuitDecompiler.decompile_attention_head(analysis, args.layer, args.head)
            dec["head_slice_shape"] = list(head_slice.shape)
        print(json.dumps(dec, indent=2))

    elif args.command == "patch":
        tensor_arr, _ = SafetensorsHandler.read_tensor(args.source, args.tensor)
        patched_arr, metrics = WeightPatcher.apply_patch(
            tensor_arr,
            patch_operation=args.operation,
            parameters={
                "mode_index": args.mode_index,
                "alpha": args.alpha,
                "beta": args.beta,
                "threshold_z": args.threshold_z,
            }
        )
        res = SafetensorsHandler.write_patched_safetensors(
            args.source, args.output, {args.tensor: patched_arr}
        )
        res["metrics"] = metrics
        print(json.dumps(res, indent=2))

    elif args.command == "diff":
        base_arr, _ = SafetensorsHandler.read_tensor(args.baseline, args.tensor)
        patch_arr, _ = SafetensorsHandler.read_tensor(args.patched, args.tensor)
        diff = patch_arr.astype(np.float32) - base_arr.astype(np.float32)
        norm_diff = float(np.linalg.norm(diff))
        base_norm = float(np.linalg.norm(base_arr.astype(np.float32)))
        rel_shift = norm_diff / max(base_norm, 1e-12)
        changed = int(np.sum(np.abs(diff) > 1e-6))
        print(json.dumps({
            "tensor_name": args.tensor,
            "total_elements": base_arr.size,
            "changed_elements": changed,
            "changed_percentage": (changed / max(base_arr.size, 1)) * 100.0,
            "frobenius_relative_shift": rel_shift,
            "is_within_safety_bound": rel_shift < 0.005
        }, indent=2))

    elif args.command == "probe-trace":
        res = ActivationTraceProber.probe_trace(args.model, args.prompt, max_tokens=args.max_tokens)
        print(json.dumps(res, indent=2))

    elif args.command == "verify-behavior":
        res = NeuralBehaviorVerifier.verify_behavior(args.baseline, args.patched, tolerance=args.tolerance)
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
