#!/usr/bin/env python3
"""
REA-Neural Engine: Autonomous Neural Reverse Engineering & Weight-Space Programming.
Treats neural network weights as compiled machine code in continuous space.
Provides memory-mapped Safetensors inspection, SVD subspace analysis,
circuit decompilation, and gradient-free surgical binary patching.
"""

import sys
import os
import json
import struct
import hashlib
import argparse
from typing import Dict, Any, Tuple, List, Optional
import numpy as np


class SafetensorsHandler:
    """Zero-dependency parser and writer for Hugging Face Safetensors format."""

    DTYPE_MAP = {
        "F32": np.float32,
        "F16": np.float16,
        "I32": np.int32,
        "I64": np.int64,
        "I16": np.int16,
        "I8": np.int8,
        "U8": np.uint8,
        "BOOL": np.bool_,
    }

    INV_DTYPE_MAP = {v: k for k, v in DTYPE_MAP.items()}

    @classmethod
    def read_header(cls, file_path: str) -> Tuple[Dict[str, Any], int, str]:
        """Reads Safetensors header without loading tensor payloads."""
        with open(file_path, "rb") as f:
            header_len_bytes = f.read(8)
            if len(header_len_bytes) < 8:
                raise ValueError("Invalid safetensors file: too small.")
            (header_len,) = struct.unpack("<Q", header_len_bytes)
            header_json_bytes = f.read(header_len)
            header_dict = json.loads(header_json_bytes.decode("utf-8"))
            header_sha256 = hashlib.sha256(header_json_bytes).hexdigest()
            return header_dict, 8 + header_len, header_sha256

    @classmethod
    def read_tensor(cls, file_path: str, tensor_name: str) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Reads a specific tensor payload via memory-mapping."""
        header, base_offset, _ = cls.read_header(file_path)
        if tensor_name not in header:
            raise KeyError(f"Tensor '{tensor_name}' not found in safetensors header.")
        meta = header[tensor_name]
        dtype_str = meta["dtype"]
        shape = meta["shape"]
        start_offset, end_offset = meta["data_offsets"]

        # Support BF16 as uint16 for raw viewing
        if dtype_str == "BF16":
            np_dtype = np.uint16
        else:
            np_dtype = cls.DTYPE_MAP.get(dtype_str, np.float32)

        file_size = os.path.getsize(file_path)
        abs_start = base_offset + start_offset
        abs_end = base_offset + end_offset

        if abs_end > file_size:
            raise ValueError("Corrupt safetensors offsets exceed file boundaries.")

        with open(file_path, "rb") as f:
            f.seek(abs_start)
            raw_bytes = f.read(end_offset - start_offset)
            arr = np.frombuffer(raw_bytes, dtype=np_dtype).reshape(shape)
            return arr.copy(), meta

    @classmethod
    def write_patched_safetensors(
        cls,
        source_path: str,
        output_path: str,
        patched_tensors: Dict[str, np.ndarray]
    ) -> Dict[str, Any]:
        """Writes a new safetensors file with surgical tensor patches applied."""
        header, base_offset, _ = cls.read_header(source_path)
        new_header = {}
        data_buffers = []
        current_offset = 0

        # Build new header and collect buffers
        for name, meta in header.items():
            if name == "__metadata__":
                new_header["__metadata__"] = meta
                continue

            if name in patched_tensors:
                arr = patched_tensors[name]
                raw_bytes = arr.tobytes()
                length = len(raw_bytes)
                new_meta = {
                    "dtype": meta["dtype"],
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
        # Align header length to 8-byte boundary if needed
        header_len = len(new_header_json)
        pad_len = (8 - (header_len % 8)) % 8
        if pad_len > 0:
            new_header_json += b" " * pad_len
            header_len += pad_len

        header_len_bytes = struct.pack("<Q", header_len)

        sha = hashlib.sha256()
        with open(output_path, "wb") as out_f, open(source_path, "rb") as src_f:
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
                    # Stream in 1 MB chunks
                    chunk_size = 1024 * 1024
                    remaining = length
                    while remaining > 0:
                        to_read = min(chunk_size, remaining)
                        chunk = src_f.read(to_read)
                        out_f.write(chunk)
                        sha.update(chunk)
                        remaining -= to_read

        full_sha256 = sha.hexdigest()
        return {
            "output_path": output_path,
            "output_sha256": full_sha256,
            "patched_tensor_names": list(patched_tensors.keys())
        }


class SubspaceAnalyzer:
    """Extracts singular modes, SVD projections, and coordinate extremes."""

    @staticmethod
    def analyze_svd(matrix: np.ndarray, top_k: int = 16) -> Dict[str, Any]:
        """Computes truncated SVD for 2D matrix projections."""
        if matrix.ndim > 2:
            matrix = matrix.reshape(matrix.shape[0], -1)

        matrix_f32 = matrix.astype(np.float32)
        total_energy = float(np.sum(matrix_f32 ** 2))

        # Truncated SVD
        u, s, vt = np.linalg.svd(matrix_f32, full_matrices=False)
        k = min(top_k, len(s))

        singular_values = s[:k].tolist()
        top_energy = float(np.sum(s[:k] ** 2))
        energy_ratio = top_energy / max(total_energy, 1e-12)

        # Extract top directional coordinate peaks
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
            "matrix_shape": list(matrix.shape),
            "top_k": k,
            "singular_values": singular_values,
            "energy_retained_ratio": energy_ratio,
            "dominant_modes": modes
        }


class CircuitDecompiler:
    """Decompiles weight matrices into mechanistic circuit pseudocode."""

    @staticmethod
    def decompile_attention_head(
        o_proj_mode: Dict[str, Any],
        layer_idx: int,
        head_idx: int = 0
    ) -> Dict[str, Any]:
        """Interprets singular modes of attention output projection."""
        s0 = o_proj_mode["singular_values"][0] if o_proj_mode["singular_values"] else 0.0
        s1 = o_proj_mode["singular_values"][1] if len(o_proj_mode["singular_values"]) > 1 else 0.0

        ratio = s0 / max(s1, 1e-6)

        # High dominance of mode 0 often indicates an attractor or copy circuit
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
            "circuit_classification": classification,
            "is_anomaly": is_anomaly,
            "dominance_ratio": ratio,
            "pseudocode": pseudocode
        }


class WeightPatcher:
    """Executes gradient-free surgical modifications on weight matrices."""

    @staticmethod
    def rank1_nullify(
        matrix: np.ndarray,
        mode_index: int = 0,
        alpha: float = 0.95
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """Nullifies an identified loop attractor direction."""
        orig_dtype = matrix.dtype
        matrix_f32 = matrix.astype(np.float32)
        orig_norm = float(np.linalg.norm(matrix_f32))

        u, s, vt = np.linalg.svd(matrix_f32, full_matrices=False)
        u_i = u[:, mode_index:mode_index+1]
        v_i = vt[mode_index:mode_index+1, :]
        s_i = s[mode_index]

        # Delta W = - alpha * sigma_i * u_i * v_i
        delta_w = alpha * s_i * (u_i @ v_i)
        patched_f32 = matrix_f32 - delta_w
        patched = patched_f32.astype(orig_dtype)

        diff_norm = float(np.linalg.norm(delta_w))
        rel_diff = diff_norm / max(orig_norm, 1e-12)
        modified_count = int(np.sum(np.abs(delta_w) > 1e-6))
        total_elements = matrix.size

        metrics = {
            "operation": "rank_1_nullify",
            "mode_index": mode_index,
            "alpha": alpha,
            "modified_elements": modified_count,
            "total_elements": total_elements,
            "modified_percentage": (modified_count / total_elements) * 100.0,
            "frobenius_energy_shift_ratio": rel_diff
        }
        return patched, metrics


def main():
    parser = argparse.ArgumentParser(description="REA-Neural Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subspace command
    sub_p = subparsers.add_parser("subspace", help="Extract SVD subspace of a tensor")
    sub_p.add_argument("--model", required=True, help="Safetensors model path")
    sub_p.add_argument("--tensor", required=True, help="Tensor name")
    sub_p.add_argument("--top-k", type=int, default=8, help="Top-k singular modes")

    # Decompile command
    dec_p = subparsers.add_parser("decompile", help="Decompile attention circuit to pseudocode")
    dec_p.add_argument("--model", required=True, help="Safetensors model path")
    dec_p.add_argument("--tensor", required=True, help="Tensor name to decompile")
    dec_p.add_argument("--layer", type=int, default=0, help="Layer index")
    dec_p.add_argument("--head", type=int, default=0, help="Head index")

    # Patch command
    patch_p = subparsers.add_parser("patch", help="Apply surgical binary patch")
    patch_p.add_argument("--source", required=True, help="Source safetensors model")
    patch_p.add_argument("--output", required=True, help="Output patched safetensors model")
    patch_p.add_argument("--tensor", required=True, help="Tensor to patch")
    patch_p.add_argument("--alpha", type=float, default=0.95, help="Damping factor alpha")
    patch_p.add_argument("--mode-index", type=int, default=0, help="Singular mode index to nullify")

    # Diff command
    diff_p = subparsers.add_parser("diff", help="Diff original and patched tensors")
    diff_p.add_argument("--baseline", required=True, help="Baseline model path")
    diff_p.add_argument("--patched", required=True, help="Patched model path")
    diff_p.add_argument("--tensor", required=True, help="Tensor name")

    args = parser.parse_args()

    if args.command == "subspace":
        tensor_arr, meta = SafetensorsHandler.read_tensor(args.model, args.tensor)
        analysis = SubspaceAnalyzer.analyze_svd(tensor_arr, top_k=args.top_k)
        print(json.dumps({
            "tensor_name": args.tensor,
            "dtype": meta["dtype"],
            "analysis": analysis
        }, indent=2))

    elif args.command == "decompile":
        tensor_arr, _ = SafetensorsHandler.read_tensor(args.model, args.tensor)
        analysis = SubspaceAnalyzer.analyze_svd(tensor_arr, top_k=4)
        dec = CircuitDecompiler.decompile_attention_head(analysis, args.layer, args.head)
        print(json.dumps(dec, indent=2))

    elif args.command == "patch":
        tensor_arr, _ = SafetensorsHandler.read_tensor(args.source, args.tensor)
        patched_arr, metrics = WeightPatcher.rank1_nullify(
            tensor_arr, mode_index=args.mode_index, alpha=args.alpha
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
            "changed_percentage": (changed / base_arr.size) * 100.0,
            "frobenius_relative_shift": rel_shift,
            "is_within_safety_bound": rel_shift < 0.005
        }, indent=2))


if __name__ == "__main__":
    main()
