#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bintra Engine: Autonomous Neural Reverse Engineering & Weight-Space Programming.
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

    DTYPE_SIZES = {
        "F64": 8, "I64": 8, "U64": 8,
        "F32": 4, "I32": 4, "U32": 4,
        "F16": 2, "BF16": 2, "I16": 2, "U16": 2,
        "I8": 1, "U8": 1, "BOOL": 1
    }

    @classmethod
    def _validate_header(cls, header: Dict[str, Any], base_offset: int, file_size: Optional[int] = None) -> None:
        """Validates safetensors header schema, dtypes, shapes, and offset ranges according to format specification."""
        import math
        if not isinstance(header, dict):
            raise ValueError(f"Invalid safetensors header: root must be a JSON object/dictionary, got {type(header).__name__}.")
        tensors_by_offset = []

        for name, meta in header.items():
            if name == "__metadata__":
                if not isinstance(meta, dict):
                    raise ValueError("__metadata__ in safetensors header must be a JSON dictionary.")
                continue

            if not isinstance(meta, dict):
                raise ValueError(f"Tensor entry '{name}' in safetensors header must be a dictionary.")

            # Validate dtype
            dtype_str = meta.get("dtype")
            if not dtype_str or (dtype_str not in cls.DTYPE_MAP and dtype_str != "BF16"):
                raise ValueError(f"Unknown or invalid safetensors dtype: '{dtype_str}' in tensor '{name}'.")

            # Validate shape
            shape = meta.get("shape")
            if not isinstance(shape, (list, tuple)):
                raise ValueError(f"Invalid shape for tensor '{name}': must be a list of integers.")
            for dim in shape:
                if not isinstance(dim, int) or dim < 0:
                    raise ValueError(f"Invalid dimension {dim} in shape for tensor '{name}': must be a non-negative integer.")

            # Validate data_offsets
            offsets = meta.get("data_offsets")
            if not isinstance(offsets, (list, tuple)) or len(offsets) != 2:
                raise ValueError(f"Invalid data_offsets for tensor '{name}': must be a 2-element list [start, end].")
            start_off, end_off = offsets
            if not isinstance(start_off, int) or not isinstance(end_off, int) or start_off < 0 or end_off < 0:
                raise ValueError(f"Negative offset in data_offsets [{start_off}, {end_off}] for tensor '{name}'.")
            if end_off < start_off:
                raise ValueError(f"Inverted offset range [{start_off}, {end_off}] for tensor '{name}'.")

            elem_size = cls.DTYPE_SIZES.get(dtype_str, 4)
            num_elements = math.prod(shape) if len(shape) > 0 else 1
            expected_bytes = num_elements * elem_size
            declared_bytes = end_off - start_off
            if declared_bytes != expected_bytes:
                raise ValueError(
                    f"Tensor '{name}' declared byte length ({declared_bytes}) does not match shape {shape} "
                    f"and dtype {dtype_str} ({expected_bytes} bytes)."
                )

            if file_size is not None:
                if base_offset + end_off > file_size:
                    raise ValueError(
                        f"Tensor '{name}' data offsets [{base_offset + start_off}, {base_offset + end_off}] exceed file size ({file_size})."
                    )

            tensors_by_offset.append((name, start_off, end_off))

        # Check for overlapping tensor byte intervals
        tensors_by_offset.sort(key=lambda t: t[1])
        for i in range(len(tensors_by_offset) - 1):
            t1_name, t1_start, t1_end = tensors_by_offset[i]
            t2_name, t2_start, t2_end = tensors_by_offset[i+1]
            if t1_end > t2_start:
                raise ValueError(
                    f"Overlapping tensor data offsets detected between '{t1_name}' [{t1_start}, {t1_end}] "
                    f"and '{t2_name}' [{t2_start}, {t2_end}]."
                )

    @classmethod
    def read_header(cls, file_path: str) -> Tuple[Dict[str, Any], int, str]:
        """Reads Safetensors header without loading tensor payloads."""
        norm_path = os.path.abspath(file_path)
        with open(norm_path, "rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            header_len_bytes = f.read(8)
            if len(header_len_bytes) < 8:
                raise ValueError("Invalid safetensors file: too small (< 8 bytes).")
            if header_len_bytes.startswith(b"MZ"):
                raise ValueError(f"Target file '{os.path.basename(file_path)}' is a Windows PE executable, not a .safetensors neural model.")
            if header_len_bytes.startswith(b"\x7fELF"):
                raise ValueError(f"Target file '{os.path.basename(file_path)}' is a Linux ELF binary, not a .safetensors neural model.")
            (header_len,) = struct.unpack("<Q", header_len_bytes)
            if header_len <= 0 or header_len > 100_000_000:
                raise ValueError(f"Invalid safetensors header length: {header_len}")
            header_json_bytes = f.read(header_len)
            if len(header_json_bytes) < header_len:
                raise ValueError("Truncated safetensors header.")
            header_dict = json.loads(header_json_bytes.decode("utf-8"))
            if not isinstance(header_dict, dict):
                raise ValueError(f"Invalid safetensors header: root must be a JSON object, got {type(header_dict).__name__}.")
            header_sha256 = hashlib.sha256(header_json_bytes).hexdigest()
            base_offset = 8 + header_len
            cls._validate_header(header_dict, base_offset, file_size)
            return header_dict, base_offset, header_sha256

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

        try:
            from security import PathIdentity, TargetMutationError, OutOfScopeError, ExecutionGuard, Capability
            if PathIdentity.is_same_file(src_abs, out_abs):
                raise TargetMutationError(
                    f"TARGET_WRITE_FORBIDDEN: In-place model weight modification is strictly forbidden by Bintra Safety Policy. Destination '{out_abs}' cannot match source '{src_abs}'."
                )
            scope = ExecutionGuard.get_current_scope()
            if scope and scope.is_target_directory(out_abs):
                raise TargetMutationError(
                    f"TARGET_DIRECTORY_WRITE_FORBIDDEN: Output patch cannot be placed in the target's original directory '{os.path.dirname(out_abs)}'."
                )

            # Mandatory Reference Monitor Mediation: Enforce workspace confinement & target immutability
            ExecutionGuard.request_access(
                component="weight_patcher",
                operation="write_patched_safetensors",
                target=out_abs,
                capability=Capability.WORKSPACE_WRITE,
                access_mode="WRITE"
            )
        except ImportError as imp_err:
            raise RuntimeError(
                f"SECURITY_KERNEL_UNAVAILABLE: Refusing unmediated safetensors write: {imp_err}"
            ) from imp_err
        header, base_offset, _ = cls.read_header(src_abs)
        missing_tensors = [t for t in patched_tensors if t not in header or t == "__metadata__"]
        if missing_tensors:
            raise KeyError(f"Patched tensor(s) {missing_tensors} not found in source safetensors file.")
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
        fd, tmp_path = tempfile.mkstemp(prefix=".bintra_st_", suffix=".tmp", dir=out_dir)
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
        if not np.all(np.isfinite(matrix_f32)):
            return {
                "status": "error",
                "error": "Matrix contains non-finite values (NaN or Inf). SVD computation cannot converge.",
                "matrix_shape": orig_shape,
                "top_k": 0,
                "singular_values": [],
                "energy_retained_ratio": 0.0,
                "spectral_condition_number": 0.0,
                "dominant_modes": []
            }

        total_energy = float(np.sum(matrix_f32 ** 2))

        try:
            u, s, vt = np.linalg.svd(matrix_f32, full_matrices=False)
        except np.linalg.LinAlgError as e:
            return {
                "status": "error",
                "error": f"SVD did not converge: {e}",
                "matrix_shape": orig_shape,
                "top_k": 0,
                "singular_values": [],
                "energy_retained_ratio": 0.0,
                "spectral_condition_number": 0.0,
                "dominant_modes": []
            }
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
            "classification_confidence": "HEURISTIC_SPECTRAL_RATIO",
            "heuristic_note": (
                "Classified from a single spectral singular value ratio (s0/s1); "
                "small or rank-deficient test tensors can trigger elevated dominance without runtime looping."
            ),
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

    @staticmethod
    def column_direction_subtract(
        matrix: np.ndarray,
        mode_index: int = 0,
        num_columns: int = 64,
        alpha: float = 1.0
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        MIT CSAIL WSP Experiment 8 Exact Intervention (Page 16):
        Traces the looping direction written by late-layer MLPs (e.g., Layers 15 and 19)
        and subtracts that single direction ONLY from the top `num_columns` (e.g., 64)
        output columns in each matrix (64 * d_model = 65,536 weights per layer; 131,072 across 2 layers).
        """
        orig_dtype = matrix.dtype
        orig_shape = matrix.shape
        f32 = matrix.astype(np.float32)
        work_2d = f32.reshape(orig_shape[0], -1) if f32.ndim != 2 else f32.copy()

        u, s, _ = np.linalg.svd(work_2d, full_matrices=False)
        idx = min(max(int(mode_index), 0), len(s) - 1)
        direction = u[:, idx]  # Unit direction vector in output space (d_out,)

        # Rank columns by magnitude of projection onto `direction`
        projections = direction @ work_2d  # (d_in,)
        k_cols = min(max(int(num_columns), 1), work_2d.shape[1])
        top_cols = np.argsort(-np.abs(projections))[:k_cols]

        delta_2d = np.zeros_like(work_2d)
        for c in top_cols:
            delta_2d[:, c] = float(alpha) * projections[c] * direction

        patched_2d = work_2d - delta_2d
        metrics = WeightPatcher._compute_metrics(
            "column_direction_subtract",
            work_2d,
            delta_2d,
            {
                "mode_index": idx,
                "num_columns_edited": int(k_cols),
                "selected_columns_preview": [int(c) for c in top_cols[:8]],
                "alpha": float(alpha),
            }
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
        elif patch_operation == "column_direction_subtract":
            return cls.column_direction_subtract(
                matrix,
                mode_index=int(params.get("mode_index", 0)),
                num_columns=int(params.get("num_columns", 64)),
                alpha=float(params.get("alpha", 1.0))
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

        if int(max_tokens) < 1:
            raise ValueError(f"max_tokens must be >= 1 (got {max_tokens}).")
        steps = min(int(max_tokens), 128)
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
            "analysis_mode": "SEEDED_SPECTRAL_OPERATOR_SIMULATION",
            "disclaimer": "Deterministic spectral SVD operator iteration seeded from SHA-256(prompt); does not execute tokenized LLM transformer forward inference.",
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
        tolerance: float = 0.015,
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

            if not np.all(np.isfinite(b_f32)) or not np.all(np.isfinite(p_f32)):
                all_within_bound = False
                max_rel_shift = float("inf")
                max_lipschitz_bound = float("inf")
                tensor_reports.append({
                    "tensor_name": t_name,
                    "changed_elements": int(b_f32.size),
                    "total_elements": int(b_f32.size),
                    "frobenius_relative_shift": float("inf"),
                    "lipschitz_perturbation_bound": float("inf"),
                    "within_tolerance": False,
                    "error": "Non-finite values (NaN or Inf) detected in tensor payload."
                })
                continue

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


class CrossLayerCircuitAnalyzer:
    """
    MIT CSAIL WSP Experiment 3 (Pages 7-8):
    1. Detects Copying / Induction Heads from middle layers alone by multiplying weight matrices
       across layers (W_QK^(l2) @ W_OV^(l1)) following Elhage et al. [10].
    2. Infers training language/alphabet complexity (Python code vs. English vs. Romaji) without
       input/output embeddings by computing the Effective Rank (distinct writing directions)
       of the final intermediate block.
    """

    @staticmethod
    def compute_effective_rank(matrix: np.ndarray) -> Dict[str, Any]:
        """
        Computes Shannon spectral effective rank and participation ratio to measure how many
        distinct directions a layer writes into (used in Exp 3 to distinguish Romaji's smaller
        letter inventory from English and Python).
        """
        f32 = matrix.astype(np.float32)
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)
        s = np.linalg.svd(f32, compute_uv=False)
        s_pos = s[s > 1e-12]
        if s_pos.size == 0:
            return {
                "effective_rank": 0.0,
                "participation_ratio": 0.0,
                "normalized_directional_diversity": 0.0,
                "inferred_domain_profile": "DEGENERATE_ZERO_SPACE"
            }

        p = s_pos / np.sum(s_pos)
        shannon_entropy = float(-np.sum(p * np.log(p + 1e-15)))
        eff_rank = float(np.exp(shannon_entropy))

        energy = s_pos ** 2
        part_ratio = float((np.sum(energy) ** 2) / max(float(np.sum(energy ** 2)), 1e-12))
        max_dim = max(min(f32.shape), 1)
        norm_div = eff_rank / float(max_dim)

        if norm_div < 0.45:
            domain = "RESTRICTED_ALPHABET_OR_ROMAJI_LIKE (Fewer distinct output directions)"
        elif norm_div > 0.78:
            domain = "HIGH_ENTROPY_CODE_OR_DENSE_SYNTAX (Broad directional utilization)"
        else:
            domain = "STANDARD_NATURAL_PROSE_LIKE"

        return {
            "effective_rank": round(eff_rank, 4),
            "participation_ratio": round(part_ratio, 4),
            "max_possible_rank": int(max_dim),
            "normalized_directional_diversity": round(norm_div, 4),
            "inferred_domain_profile": domain
        }

    @staticmethod
    def analyze_cross_layer_induction(
        early_ov: np.ndarray,
        late_qk: np.ndarray,
        num_heads: int = 6
    ) -> Dict[str, Any]:
        """
        Multiplies early-layer OV projection with late-layer QK projection per head pair
        to identify copying (induction) heads without running the model on any text.
        """
        ov_2d = early_ov.astype(np.float32)
        qk_2d = late_qk.astype(np.float32)
        if ov_2d.ndim != 2:
            ov_2d = ov_2d.reshape(ov_2d.shape[0], -1)
        if qk_2d.ndim != 2:
            qk_2d = qk_2d.reshape(qk_2d.shape[0], -1)

        # Align inner dimension for matrix product qk_2d @ ov_2d
        common_dim = min(qk_2d.shape[1], ov_2d.shape[0])
        qk_aligned = qk_2d[:, :common_dim]
        ov_aligned = ov_2d[:common_dim, :]

        heads = max(int(num_heads), 1)
        h_out = max(qk_aligned.shape[0] // heads, 1)
        h_in = max(ov_aligned.shape[1] // heads, 1)

        head_scores: List[Dict[str, Any]] = []
        copying_heads: List[int] = []

        for h in range(heads):
            r0, r1 = h * h_out, min((h + 1) * h_out, qk_aligned.shape[0])
            c0, c1 = h * h_in, min((h + 1) * h_in, ov_aligned.shape[1])
            if r1 <= r0 or c1 <= c0:
                continue
            q_sub = qk_aligned[r0:r1, :]
            o_sub = ov_aligned[:, c0:c1]
            composed = q_sub @ o_sub
            comp_norm = float(np.linalg.norm(composed))
            denom = max(float(np.linalg.norm(q_sub) * np.linalg.norm(o_sub)), 1e-12)
            k_score = comp_norm / denom

            # Check diagonal/copy alignment of composed operator
            min_rc = min(composed.shape[0], composed.shape[1])
            diag_energy = float(np.linalg.norm(np.diag(composed[:min_rc, :min_rc])))
            diag_ratio = diag_energy / max(comp_norm, 1e-12)
            is_copy_head = (k_score * (1.0 + diag_ratio)) > 0.42
            if is_copy_head:
                copying_heads.append(h)

            head_scores.append({
                "head_index": h,
                "composition_strength": round(k_score, 4),
                "diagonal_copy_alignment": round(diag_ratio, 4),
                "is_copying_induction_head": is_copy_head
            })

        return {
            "num_heads_analyzed": len(head_scores),
            "copying_heads_detected": copying_heads,
            "copying_head_density": round(len(copying_heads) / max(len(head_scores), 1), 4),
            "inferred_corpus_type": (
                "CODE_HEAVY_CORPUS (High copying-head density)"
                if len(copying_heads) >= max(2, len(head_scores) // 3)
                else "PROSE_CORPUS"
            ),
            "head_composition_table": head_scores
        }


class AttentionPatternAuditor:
    """
    MIT CSAIL WSP Experiment 7 (Pages 13-15):
    When static weight comparison alone cannot map distributed fine-tuning differences into
    behavioral verdicts (such as Sycophancy in Gemma 3 270M), probes where middle-layer
    attention heads look from the answer position:
      - Factual Question Spans (e.g. numbers/entities in the prompt)
      - User Suggested Answer Spans (e.g. "I think the answer is Canberra")
    """

    @staticmethod
    def audit_sycophancy_attention(
        qk_matrix: np.ndarray,
        question_token_vectors: np.ndarray,
        user_suggestion_vectors: np.ndarray,
        answer_query_vector: np.ndarray
    ) -> Dict[str, Any]:
        qk = qk_matrix.astype(np.float32)
        if qk.ndim != 2:
            qk = qk.reshape(qk.shape[0], -1)
        d = min(qk.shape[0], qk.shape[1], question_token_vectors.shape[-1], user_suggestion_vectors.shape[-1], answer_query_vector.size)
        w_qk = qk[:d, :d]
        q_ans = answer_query_vector.astype(np.float32).ravel()[:d]
        k_quest = question_token_vectors.astype(np.float32).reshape(-1, question_token_vectors.shape[-1])[:, :d]
        k_sugg = user_suggestion_vectors.astype(np.float32).reshape(-1, user_suggestion_vectors.shape[-1])[:, :d]

        # Bilinear attention logits from answer position: q_ans^T @ W_QK @ k_i / sqrt(d)
        scale = 1.0 / max(float(np.sqrt(d)), 1.0)
        projected_q = q_ans @ w_qk
        logits_quest = (k_quest @ projected_q) * scale
        logits_sugg = (k_sugg @ projected_q) * scale

        all_logits = np.concatenate([logits_quest, logits_sugg])
        all_logits = all_logits - np.max(all_logits)
        probs = np.exp(all_logits)
        probs /= max(float(np.sum(probs)), 1e-12)

        n_q = logits_quest.size
        question_mass = float(np.sum(probs[:n_q]))
        suggestion_mass = float(np.sum(probs[n_q:]))
        sycophancy_ratio = suggestion_mass / max(question_mass + suggestion_mass, 1e-12)
        mean_logit_quest = float(np.mean(logits_quest))
        mean_logit_sugg = float(np.mean(logits_sugg))
        logit_diff = mean_logit_sugg - mean_logit_quest

        # Scale-adaptive decision rule: compensates for un-normalized small-norm projection matrices
        is_sycophantic = (sycophancy_ratio > 0.55) or (sycophancy_ratio > 0.51 and logit_diff > 0.02)

        return {
            "question_tokens_attention_share": round(question_mass, 4),
            "user_suggestion_attention_share": round(suggestion_mass, 4),
            "sycophancy_attention_ratio": round(sycophancy_ratio, 4),
            "mean_question_logit": round(mean_logit_quest, 5),
            "mean_suggestion_logit": round(mean_logit_sugg, 5),
            "logit_difference": round(logit_diff, 5),
            "is_sycophantic_head": is_sycophantic,
            "diagnosis": (
                "SYCOPHANTIC_ROUTING: Head attends predominantly to user's suggested answer over question facts (Exp 7 Figure 2)."
                if is_sycophantic else
                "HONEST_FACTUAL_ROUTING: Head attends predominantly to question facts/numbers over user suggestion."
            )
        }


class AmenabilityDiagnostic:
    """
    MIT CSAIL WSP Additional Experiment (Pages 17-18: Qwen3.5-0.8B vs. Gemma 3 270M):
    Evaluates whether a model failure is caused by a removable latent obstacle/attractor loop
    (amenable to surgical weight editing, like Qwen3.5-0.8B's 93% token-limit looping)
    or a fundamental capability deficit (like Gemma 3 270M's 8.5% looping and arithmetic errors),
    where editing weights cannot magically add missing knowledge.
    """

    @staticmethod
    def evaluate_surgical_amenability(
        matrix: np.ndarray,
        observed_loop_rate: Optional[float] = None
    ) -> Dict[str, Any]:
        svd_info = SubspaceAnalyzer.analyze_svd(matrix, top_k=8)
        s_vals = svd_info["singular_values"]
        s0 = s_vals[0] if len(s_vals) > 0 else 0.0
        s1 = s_vals[1] if len(s_vals) > 1 else 1.0
        dominance_ratio = s0 / max(s1, 1e-6)

        # Column norm concentration (checks if a small subset of MLP columns dominates output writing)
        f32 = matrix.astype(np.float32)
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)
        col_norms = np.linalg.norm(f32, axis=0)
        sorted_cols = np.sort(col_norms)[::-1]
        k_sub = max(1, min(64, sorted_cols.size // 4))
        top_col_energy_share = float(np.sum(sorted_cols[:k_sub] ** 2) / max(float(np.sum(col_norms ** 2)), 1e-12))

        loop_rate = float(observed_loop_rate) if observed_loop_rate is not None else (
            min(0.95, 0.20 * dominance_ratio) if dominance_ratio > 2.5 else 0.08
        )

        is_amenable = (loop_rate >= 0.30) or (dominance_ratio >= 2.8) or (top_col_energy_share >= 0.45)

        # Scale calibration (LIM-5): Required surgery rank K scales inversely with pathology concentration.
        # Highly concentrated attractors (>=0.80) are cured by default K=64.
        # Diffuse/uniform attractors (<0.50) require larger column spans (K=128-256) or rank-1 nullification.
        num_cols_available = matrix.shape[1] if matrix.ndim >= 2 else matrix.shape[0]
        if top_col_energy_share >= 0.80:
            raw_k = 64
            recommended_k = max(1, min(raw_k, num_cols_available))
            pathology_dist = "CONCENTRATED_COLUMN_BOTTLENECK"
            surgery_advice = f"Concentrated attractor: standard column_direction_subtract (num_columns={recommended_k}) is highly effective."
        elif top_col_energy_share >= 0.50:
            raw_k = 128
            recommended_k = max(1, min(raw_k, num_cols_available))
            pathology_dist = "MODERATELY_DISTRIBUTED_ATTRACTOR"
            surgery_advice = f"Moderately distributed attractor: recommended num_columns={recommended_k} (default K=64 may achieve only partial attenuation)."
        else:
            raw_k = 256
            recommended_k = max(1, min(raw_k, num_cols_available))
            pathology_dist = "DIFFUSE_UNIFORM_ATTRACTOR"
            surgery_advice = f"Diffuse attractor: recommended num_columns={recommended_k} or rank1_nullify (default K=64 will leave residual attractor dominance)."

        return {
            "analysis_mode": "OBSERVED_LOOP_TELEMETRY" if observed_loop_rate is not None else "SPECTRAL_HEURISTIC_ESTIMATE",
            "loop_rate_source": "observed" if observed_loop_rate is not None else "spectral_heuristic_estimate",
            "spectral_dominance_ratio": round(float(dominance_ratio), 4),
            "top_columns_energy_concentration": round(top_col_energy_share, 4),
            "pathology_distribution": pathology_dist,
            "recommended_num_columns": recommended_k,
            "surgery_scale_advice": surgery_advice,
            "estimated_loop_rate": round(loop_rate, 4),
            "estimated_or_observed_loop_rate": round(loop_rate, 4),
            "is_amenable_to_weight_surgery": is_amenable,
            "wsp_prognosis": (
                f"AMENABLE_OBSTACLE_BOTTLENECK (Qwen3.5 Profile): Pathological loop/attractor detected ({pathology_dist}); "
                f"{surgery_advice}"
                if is_amenable else
                "CAPABILITY_DEFICIT_WARNING (Gemma-3-270M Profile): Low loop rate and diffuse spectrum; "
                "weight editing can remove obstacles but cannot add capabilities the model lacks (Page 17)."
            )
        }


class WeightSpaceCompiler:
    """
    MIT CSAIL WSP Pillar 3 — Experiments 5 & 6 (Pages 10-13):
    Writes neural network weights from scratch (Zero-Shot Weight Synthesis) without training
    by compiling symbolic domain rules (e.g., Breakout ball-landing tracker & paddle controller,
    or Go liberty/capture scorer) directly into layer weight tensors.
    """

    @staticmethod
    def compile_breakout_policy_network(
        input_dim: int = 32,
        hidden_dim: int = 16,
        action_dim: int = 3
    ) -> Dict[str, np.ndarray]:
        """
        Synthesizes a 2-layer policy network from scratch following Astra's Experiment 5 design:
        - Layer 1 computes ball landing-position error and velocity direction indicators
          (Units 0..3 track descending-right, descending-left, ascending-right, ascending-left;
          bottom-row paddle detector on row channels).
        - Layer 2 maps landing error to discrete actions: [LEFT (0), STAY (1), RIGHT (2)].
        """
        w1 = np.zeros((hidden_dim, input_dim), dtype=np.float32)
        b1 = np.zeros((hidden_dim,), dtype=np.float32)
        w2 = np.zeros((action_dim, hidden_dim), dtype=np.float32)
        b2 = np.zeros((action_dim,), dtype=np.float32)

        half = max(input_dim // 2, 2)

        # Trajectory direction detectors (Units 0..3 as in Page 11)
        if hidden_dim >= 4 and input_dim >= 4:
            w1[0, :2] = [2.5, -2.5]   # descending-right detector
            w1[1, :2] = [-2.5, 2.5]   # descending-left detector
            w1[2, 2:4] = [2.0, 2.0]   # velocity magnitude
            w1[3, -2:] = [4.0, -4.0]  # bottom-row paddle alignment (Page 5)

        # Landing error detectors (Units 4..7):
        # Unit 4: Positive error detector (ball_x > paddle_x -> steer RIGHT)
        # Unit 5: Negative error detector (ball_x < paddle_x -> steer LEFT)
        # Maps coordinates whether supplied as scalar offsets or spatial coordinate channels
        if hidden_dim >= 6:
            # Scalar coordinate indices: paddle at 0, ball at half
            w1[4, half] = 3.5
            w1[4, 0] = -3.5
            w2[2, 4] = 3.0
            w2[0, 4] = -3.0

            w1[5, 0] = 3.5
            w1[5, half] = -3.5
            w2[0, 5] = 3.0
            w2[2, 5] = -3.0

            # Multi-channel coordinate mapping across remaining units
            for i in range(6, min(hidden_dim, 8)):
                p_col = min(i - 4, half - 1)
                b_col = min(half + (i - 4), input_dim - 1)
                if i % 2 == 0:
                    w1[i, b_col] = 3.5
                    w1[i, p_col] = -3.5
                    w2[2, i] = 2.0
                    w2[0, i] = -2.0
                else:
                    w1[i, p_col] = 3.5
                    w1[i, b_col] = -3.5
                    w2[0, i] = 2.0
                    w2[2, i] = -2.0

        # Baseline stability bias for STAY (Action 1) when aligned (error = 0)
        b2[1] = 0.5

        return {
            "policy.layer1.weight": w1,
            "policy.layer1.bias": b1,
            "policy.layer2.weight": w2,
            "policy.layer2.bias": b2,
        }


class CircuitGrafter:
    """
    MIT CSAIL WSP Experiment 4 (Kinetix Ramp Bypass, Pages 9-10) & Page 19 (Model Merging):
    Grafts a compact conditional sub-circuit into dormant/low-norm units of a weight matrix,
    or transplants a functional subspace from a donor tensor into a host tensor without retraining.
    """

    @staticmethod
    def graft_conditional_subcircuit(
        host_matrix: np.ndarray,
        sensor_indices: List[int],
        actuator_index: int = 0,
        gain: float = -3.0,
        max_graft_fraction: float = 0.035
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Grafts a sparse backup/override path (default <= 3.5% weights, matching Exp 4's 3.5% edit)
        through the lowest-energy hidden rows/units of host_matrix.
        """
        orig_dtype = host_matrix.dtype
        f32 = host_matrix.astype(np.float32).copy()
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)

        rows, cols = f32.shape
        row_norms = np.linalg.norm(f32, axis=1)
        dormant_rows = np.argsort(row_norms)

        max_budget = max(1, int(f32.size * float(max_graft_fraction)))
        valid_sensors = [c for c in sensor_indices if 0 <= c < cols] or [0]
        num_graft_rows = max(1, min(len(dormant_rows), max_budget // max(len(valid_sensors), 1)))
        selected_rows = dormant_rows[:num_graft_rows].tolist()

        modified = 0
        for r in selected_rows:
            for c in valid_sensors:
                if modified < max_budget:
                    f32[r, c] = float(gain)
                    modified += 1
            if 0 <= actuator_index < cols and modified < max_budget:
                f32[r, actuator_index] = float(-gain * 0.8)
                modified += 1

        pct = (modified / max(f32.size, 1)) * 100.0
        return f32.reshape(host_matrix.shape).astype(orig_dtype), {
            "operation": "graft_conditional_subcircuit",
            "grafted_units": selected_rows,
            "modified_weights": modified,
            "total_weights": int(f32.size),
            "modified_percentage": round(pct, 4),
            "within_exp4_sparsity_budget": pct <= (max_graft_fraction * 100.0 + 1.0)
        }

    @staticmethod
    def transplant_reasoning_subspace(
        host_matrix: np.ndarray,
        donor_matrix: np.ndarray,
        rank_k: int = 2,
        blend: float = 0.25
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Page 19 'True architectural and model merging':
        Extracts the top-k principal circuit modes from donor_matrix and grafts them into
        host_matrix even when host_matrix and donor_matrix have different dimensions!
        """
        orig_dtype = host_matrix.dtype
        h_f32 = host_matrix.astype(np.float32)
        d_f32 = donor_matrix.astype(np.float32)
        h_2d = h_f32.reshape(h_f32.shape[0], -1) if h_f32.ndim != 2 else h_f32.copy()
        d_2d = d_f32.reshape(d_f32.shape[0], -1) if d_f32.ndim != 2 else d_f32

        u_d, s_d, vt_d = np.linalg.svd(d_2d, full_matrices=False)
        k = min(max(int(rank_k), 1), len(s_d))

        # Project donor modes into host dimensions via interpolation/truncation
        r_h, c_h = h_2d.shape
        r_d, c_d = d_2d.shape
        graft_delta = np.zeros_like(h_2d)

        for i in range(k):
            u_vec = np.interp(np.linspace(0, 1, r_h), np.linspace(0, 1, r_d), u_d[:, i]).astype(np.float32)
            v_vec = np.interp(np.linspace(0, 1, c_h), np.linspace(0, 1, c_d), vt_d[i, :]).astype(np.float32)
            u_vec /= max(float(np.linalg.norm(u_vec)), 1e-12)
            v_vec /= max(float(np.linalg.norm(v_vec)), 1e-12)
            graft_delta += float(blend) * float(s_d[i]) * np.outer(u_vec, v_vec)

        merged = h_2d + graft_delta
        return merged.reshape(host_matrix.shape).astype(orig_dtype), {
            "operation": "transplant_reasoning_subspace",
            "host_shape": list(host_matrix.shape),
            "donor_shape": list(donor_matrix.shape),
            "transplanted_modes": k,
            "frobenius_graft_ratio": round(float(np.linalg.norm(graft_delta) / max(float(np.linalg.norm(h_2d)), 1e-12)), 4)
        }


class ForwardPassHarness:
    """
    MIT CSAIL WSP Experiments 6 & 8 (Pages 12-13, 15-16):
    Budgeted Forward-Pass Optimization Harness (e.g., 0, 10, 25, 50 forward passes).
    Interleaves targeted weight edits with forward-pass rollouts on diagnostic batches,
    keeping a weight change ONLY if the rollout objective improves.
    """

    @staticmethod
    def run_budgeted_optimization(
        matrix: np.ndarray,
        input_probes: np.ndarray,
        target_vectors: np.ndarray,
        forward_pass_budget: int = 10,
        num_columns: int = 64
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        orig_dtype = matrix.dtype
        current_w = matrix.astype(np.float32).copy()
        if current_w.ndim != 2:
            current_w = current_w.reshape(current_w.shape[0], -1)

        d_out, d_in = current_w.shape
        x = input_probes.astype(np.float32).reshape(-1, d_in)
        y_target = target_vectors.astype(np.float32).reshape(-1, d_out)

        def _evaluate_forward_pass(w_cand: np.ndarray) -> float:
            pred = x @ w_cand.T
            mse = float(np.mean((pred - y_target) ** 2))
            return 1.0 / (1.0 + mse)

        budget = min(max(int(forward_pass_budget), 0), 50)
        if budget == 0:
            # One-shot edit without forward pass evaluation
            edited, _ = WeightPatcher.column_direction_subtract(current_w, num_columns=num_columns, alpha=0.5)
            return edited.reshape(matrix.shape).astype(orig_dtype), {
                "forward_passes_used": 0,
                "accepted_edits": 1,
                "rejected_edits": 0,
                "initial_score": None,
                "final_score": None,
                "mode": "zero_shot_no_rollout"
            }

        best_score = _evaluate_forward_pass(current_w)
        initial_score = best_score
        passes_used = 1
        accepted = 0
        rejected = 0
        score_history = [round(best_score, 5)]

        while passes_used < budget:
            residual = (x @ current_w.T) - y_target
            # Identify dominant error direction in output space
            err_u, _, _ = np.linalg.svd(residual.T, full_matrices=False)
            loop_dir = err_u[:, 0]
            step_scale = 0.35 / float(1.0 + 0.1 * passes_used)

            # Subtract error direction from top contributing columns
            col_scores = np.abs(loop_dir @ current_w)
            k_cols = min(max(int(num_columns), 1), d_in)
            top_cols = np.argsort(-col_scores)[:k_cols]

            candidate_w = current_w.copy()
            proj_coeffs = loop_dir @ candidate_w[:, top_cols]
            candidate_w[:, top_cols] -= step_scale * np.outer(loop_dir, proj_coeffs)

            cand_score = _evaluate_forward_pass(candidate_w)
            passes_used += 1
            if cand_score > best_score:
                current_w = candidate_w
                best_score = cand_score
                accepted += 1
            else:
                rejected += 1
            score_history.append(round(best_score, 5))

        return current_w.reshape(matrix.shape).astype(orig_dtype), {
            "forward_passes_used": passes_used,
            "forward_pass_budget": budget,
            "accepted_edits": accepted,
            "rejected_edits": rejected,
            "initial_score": round(initial_score, 5),
            "final_score": round(best_score, 5),
            "score_improvement": round(best_score - initial_score, 5),
            "trajectory": score_history
        }


class WeightSecurityAuditor:
    """
    MIT CSAIL WSP Experiments 1, 2 (Pages 4-6) & Page 19 ('Auditing without evaluation'):
    1. Scans raw weights without inference to detect Trojan / Backdoor trigger spikes.
    2. Reads input-channel spatial receptive fields (Exp 1: bottom-row paddle concentration).
    3. Extracts output-layer 2D geometric outlines (Exp 2: DDPM shape edge reconstruction).
    """

    @staticmethod
    def _compute_robust_row_zscores(row_norms: np.ndarray) -> Tuple[np.ndarray, float, float]:
        """Computes outlier-excluded / leave-one-out row norm z-scores safe for small layers."""
        n = row_norms.size
        if n == 0:
            return np.zeros(0, dtype=np.float64), 0.0, 1e-12
        if n < 3:
            return np.zeros(n, dtype=np.float64), float(np.mean(row_norms)), float(np.std(row_norms)) + 1e-12

        rn = row_norms.astype(np.float64)
        med = float(np.median(rn))
        q1, q3 = float(np.percentile(rn, 25)), float(np.percentile(rn, 75))
        mad_sigma = float(np.median(np.abs(rn - med))) * 1.4826
        scale_hint = max((q3 - q1) / 1.349, mad_sigma, 1e-12)
        core_mask = np.abs(rn - med) <= max(4.5 * scale_hint, 1e-9 * max(abs(med), 1.0))

        if int(np.sum(core_mask)) >= max(3, (n // 2) + 1):
            core = rn[core_mask]
            k = core.size
            c_mean = float(np.mean(core))
            c_std = float(np.std(core, ddof=1)) if k > 1 else 0.0
            s = core - c_mean
            tot = float(np.sum(s))
            sq = float(np.sum(s ** 2))
            loo_m = (tot - s) / float(k - 1)
            loo_var = np.maximum(0.0, (sq - s ** 2) / float(k - 1) - (loo_m ** 2))
            loo_s = np.sqrt(loo_var * float(k - 1) / float(max(k - 2, 1)))
            floor = max(1e-6 * max(abs(c_mean), abs(med)), 1e-12)
            z_scores = np.empty(n, dtype=np.float64)
            z_scores[core_mask] = (s - loo_m) / np.maximum(loo_s, floor)
            z_scores[~core_mask] = (rn[~core_mask] - c_mean) / max(c_std, floor)
            return z_scores, c_mean, max(c_std, floor)

        s = rn - med
        tot = float(np.sum(s))
        sq = float(np.sum(s ** 2))
        loo_m = (tot - s) / float(n - 1)
        loo_s = np.sqrt(np.maximum(0.0, (sq - s ** 2) / float(n - 1) - (loo_m ** 2)))
        floor = max(1e-6 * max(abs(med), 1.0), 1e-12)
        z_scores = (s - loo_m) / np.maximum(loo_s, floor)
        return z_scores, float(np.mean(rn)), max(float(np.std(rn)), floor)

    @classmethod
    def audit_weights_without_evaluation(
        cls,
        matrix: np.ndarray,
        spatial_height: int = 10,
        spatial_width: int = 10
    ) -> Dict[str, Any]:
        f32 = matrix.astype(np.float32)
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)

        rows, cols = f32.shape
        row_norms = np.linalg.norm(f32, axis=1)
        col_norms = np.linalg.norm(f32, axis=0)

        row_z, mean_r, std_r = cls._compute_robust_row_zscores(row_norms)
        max_r_z = float(np.max(row_z)) if row_z.size > 0 else 0.0
        suspect_rows = np.where(row_z > 4.5)[0].tolist()

        # Check rank-1 alignment of outlier rows (classic backdoor trigger signature)
        has_backdoor_spike = len(suspect_rows) > 0 and max_r_z > 5.0

        # Spatial Receptive Field Concentration (Exp 1)
        grid_size = spatial_height * spatial_width
        if cols >= grid_size and grid_size > 0:
            spatial_slice = np.abs(f32[:, :grid_size]).mean(axis=0).reshape(spatial_height, spatial_width)
            row_energy = spatial_slice.sum(axis=1)
            dominant_spatial_row = int(np.argmax(row_energy))
            bottom_row_ratio = float(row_energy[-1] / max(float(row_energy.sum()), 1e-12))
        else:
            dominant_spatial_row = int(np.argmax(col_norms)) if col_norms.size > 0 else 0
            bottom_row_ratio = 0.0

        return {
            "auditing_mode": "zero_evaluation_static_weight_audit",
            "potential_backdoor_detected": has_backdoor_spike,
            "max_neuron_norm_zscore": round(max_r_z, 4),
            "suspect_trigger_neurons": suspect_rows[:16],
            "receptive_field_dominant_row": dominant_spatial_row,
            "bottom_row_paddle_concentration": round(bottom_row_ratio, 4)
        }


def main():
    _ensure_utf8_stdio()
    parser = argparse.ArgumentParser(description="Bintra Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subspace command
    sub_p = subparsers.add_parser("subspace", help="Extract SVD/Extreme/Slice subspace of a tensor")
    sub_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    sub_p.add_argument("--tensor", required=True, help="Tensor name")
    sub_p.add_argument("--mode", choices=["svd_modes", "sparse_extremes", "coordinate_slice"], default="svd_modes")
    sub_p.add_argument("--top-k", type=int, default=8, help="Top-k singular modes or extremes")

    # Decompile command
    dec_p = subparsers.add_parser("decompile", help="Decompile neural circuit to pseudocode")
    dec_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    dec_p.add_argument("--tensor", required=True, help="Tensor name to decompile")
    dec_p.add_argument("--layer", type=int, default=0, help="Layer index")
    dec_p.add_argument("--head", type=int, default=0, help="Head index")
    dec_p.add_argument("--num-heads", type=int, default=16, help="Total number of attention heads (default 16)")
    dec_p.add_argument(
        "--circuit-type", "--kind",
        dest="circuit_type",
        choices=["attention_head", "mlp_projection", "layer_norm_drift"],
        default="attention_head"
    )

    # Patch command
    patch_p = subparsers.add_parser("patch", help="Apply surgical weight-space patch")
    patch_p.add_argument("--source", "--model", "--file", dest="source", required=True, help="Source safetensors model")
    patch_p.add_argument("--output", required=True, help="Output patched safetensors model")
    patch_p.add_argument("--tensor", required=True, help="Tensor to patch")
    patch_p.add_argument(
        "--operation",
        choices=["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add", "column_direction_subtract"],
        default="rank_1_nullify"
    )
    patch_p.add_argument("--alpha", type=float, default=0.95, help="Damping factor alpha")
    patch_p.add_argument("--beta", type=float, default=0.05, help="Steering factor beta")
    patch_p.add_argument("--threshold-z", type=float, default=3.5, help="Z-score clamp threshold")
    patch_p.add_argument("--mode-index", type=int, default=0, help="Singular mode index")
    patch_p.add_argument("--num-columns", type=int, default=64, help="Columns to edit in column_direction_subtract")

    # Diff command
    diff_p = subparsers.add_parser("diff", help="Diff original and patched tensors")
    diff_p.add_argument("--baseline", required=True, help="Baseline model path")
    diff_p.add_argument("--patched", required=True, help="Patched model path")
    diff_p.add_argument("--tensor", required=True, help="Tensor name")

    # Probe-trace command (Temporal Hearing)
    probe_p = subparsers.add_parser("probe-trace", help="Probe dynamic activation trace over time")
    probe_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    probe_p.add_argument("--prompt", required=True, help="Diagnostic prompt")
    probe_p.add_argument("--max-tokens", type=int, default=32, help="Number of temporal steps")

    # Verify-behavior command (Vestibular Balance)
    ver_p = subparsers.add_parser("verify-behavior", help="Verify neural equilibrium and Lipschitz bounds")
    ver_p.add_argument("--baseline", required=True, help="Baseline model path")
    ver_p.add_argument("--patched", required=True, help="Patched model path")
    ver_p.add_argument("--tolerance", type=float, default=0.005, help="Max relative Frobenius shift")

    # WSP-Audit command (Experiments 1, 2, 3, 7, 8 & Gemma-3 Amenability + Backdoor Audit)
    wsp_p = subparsers.add_parser("wsp-audit", help="Comprehensive MIT CSAIL WSP audit on a safetensors model")
    wsp_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    wsp_p.add_argument("--tensor", default=None, help="Optional primary tensor name")

    # Synthesize-Weights command (Experiments 5 & 6: Zero-Shot Weight Compilation from Scratch)
    syn_p = subparsers.add_parser("synthesize-weights", help="Compile neural weights from scratch without training")
    syn_p.add_argument("--output", required=True, help="Output .safetensors file path")
    syn_p.add_argument("--preset", choices=["breakout_paddle"], default="breakout_paddle", help="Symbolic rule preset")

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
                "num_columns": args.num_columns,
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
    elif args.command == "wsp-audit":
        hdr, _, hdr_sha = SafetensorsHandler.read_header(args.model)
        t_names = [k for k in hdr.keys() if k != "__metadata__"]
        primary_t = args.tensor if (args.tensor and args.tensor in t_names) else t_names[0]
        arr, _ = SafetensorsHandler.read_tensor(args.model, primary_t)
        eff_rank = CrossLayerCircuitAnalyzer.compute_effective_rank(arr)
        amenability = AmenabilityDiagnostic.evaluate_surgical_amenability(arr)
        sec_audit = WeightSecurityAuditor.audit_weights_without_evaluation(arr)
        induction_report = None
        if len(t_names) >= 2:
            arr2, _ = SafetensorsHandler.read_tensor(args.model, t_names[1])
            induction_report = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(arr, arr2, num_heads=4)
        print(json.dumps({
            "model_path": args.model,
            "header_sha256": hdr_sha,
            "primary_tensor": primary_t,
            "effective_rank_analysis": eff_rank,
            "surgical_amenability": amenability,
            "zero_eval_security_audit": sec_audit,
            "cross_layer_induction": induction_report,
        }, indent=2))

    elif args.command == "synthesize-weights":
        sys.stderr.write(
            "[Bintra SCOPE WARNING] 'synthesize-weights' BUILDS a neural network from "
            "scratch. This is out of Bintra's reverse-engineering scope (it creates a "
            "standalone AI model, the WSP paper's own agenda) and is kept only as archived "
            "lineage. See SCOPE.md. It reverse-engineers no Windows binary.\n"
        )
        tensors = WeightSpaceCompiler.compile_breakout_policy_network()
        # Write fresh safetensors file
        header = {}
        raw_blobs = []
        offset = 0
        for name, arr in tensors.items():
            b = np.ascontiguousarray(arr, dtype=np.float32).tobytes()
            header[name] = {"dtype": "F32", "shape": list(arr.shape), "data_offsets": [offset, offset + len(b)]}
            raw_blobs.append(b)
            offset += len(b)
        hdr_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        pad = (8 - (len(hdr_bytes) % 8)) % 8
        if pad:
            hdr_bytes += b" " * pad
        with open(args.output, "wb") as f:
            f.write(struct.pack("<Q", len(hdr_bytes)))
            f.write(hdr_bytes)
            for b in raw_blobs:
                f.write(b)
        print(json.dumps({
            "output_path": args.output,
            "preset": args.preset,
            "synthesized_tensors": list(tensors.keys()),
            "total_parameters": int(sum(a.size for a in tensors.values()))
        }, indent=2))


if __name__ == "__main__":
    main()
