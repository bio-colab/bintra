"""Bintra CLI commands: Safetensors weight-space commands (audit, patch, diff, decompile) and archived lineage."""
import argparse
import json
import struct
import sys
from typing import List

import numpy as np

from bintra_engine import (
    ActivationTraceProber,
    AmenabilityDiagnostic,
    CircuitDecompiler,
    CrossLayerCircuitAnalyzer,
    NeuralBehaviorVerifier,
    SafetensorsHandler,
    SubspaceAnalyzer,
    WeightPatcher,
    WeightSecurityAuditor,
    WeightSpaceCompiler,
    _ensure_utf8_stdio,
)

from bintra_cli.commands._common import flag_value, guard_output_path, rename_flag

_IN_PLACE_WEIGHTS = (
    "TARGET_WRITE_FORBIDDEN: Direct in-place modification of model weights is strictly forbidden by "
    "Bintra Safety Policy. Specify a distinct --output file in the workspace."
)

# Public command name -> weight-engine sub-command.
_ENGINE_SUBCOMMAND = {"patch-weights": "patch", "decompile-circuit": "decompile", "diff-weights": "diff"}


def _build_weight_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bintra Engine")
    subparsers = parser.add_subparsers(dest="command", required=True)

    sub_p = subparsers.add_parser("subspace", help="Extract SVD/Extreme/Slice subspace of a tensor")
    sub_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    sub_p.add_argument("--tensor", required=True, help="Tensor name")
    sub_p.add_argument("--mode", choices=["svd_modes", "sparse_extremes", "coordinate_slice"], default="svd_modes")
    sub_p.add_argument("--top-k", type=int, default=8, help="Top-k singular modes or extremes")

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

    diff_p = subparsers.add_parser("diff", help="Diff original and patched tensors")
    diff_p.add_argument("--baseline", required=True, help="Baseline model path")
    diff_p.add_argument("--patched", required=True, help="Patched model path")
    diff_p.add_argument("--tensor", required=True, help="Tensor name")

    probe_p = subparsers.add_parser("probe-trace", help="Probe dynamic activation trace over time")
    probe_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    probe_p.add_argument("--prompt", required=True, help="Diagnostic prompt")
    probe_p.add_argument("--max-tokens", type=int, default=32, help="Number of temporal steps")

    ver_p = subparsers.add_parser("verify-behavior", help="Verify neural equilibrium and Lipschitz bounds")
    ver_p.add_argument("--baseline", required=True, help="Baseline model path")
    ver_p.add_argument("--patched", required=True, help="Patched model path")
    ver_p.add_argument("--tolerance", type=float, default=0.005, help="Max relative Frobenius shift")

    wsp_p = subparsers.add_parser("wsp-audit", help="Comprehensive MIT CSAIL WSP audit on a safetensors model")
    wsp_p.add_argument("--model", "--source", "--file", dest="model", required=True, help="Safetensors model path")
    wsp_p.add_argument("--tensor", default=None, help="Optional primary tensor name")

    syn_p = subparsers.add_parser("synthesize-weights", help="Compile neural weights from scratch without training")
    syn_p.add_argument("--output", required=True, help="Output .safetensors file path")
    syn_p.add_argument("--preset", choices=["breakout_paddle"], default="breakout_paddle", help="Symbolic rule preset")
    return parser


def _decompile(args) -> dict:
    tensor_arr, _ = SafetensorsHandler.read_tensor(args.model, args.tensor)
    if args.circuit_type == "mlp_projection":
        return CircuitDecompiler.decompile_mlp_projection(tensor_arr, args.layer)
    if args.circuit_type == "layer_norm_drift":
        return CircuitDecompiler.decompile_layer_norm_drift(tensor_arr, args.layer)
    if tensor_arr.ndim == 2:
        num_heads = args.num_heads if args.num_heads > 0 else 16
        head_dim = max(tensor_arr.shape[1] // num_heads, 1)
        head_idx = min(max(args.head, 0), num_heads - 1)
        head_slice = tensor_arr[:, head_idx * head_dim: (head_idx + 1) * head_dim]
    else:
        head_slice = tensor_arr
    analysis = SubspaceAnalyzer.analyze_svd(head_slice, top_k=4)
    dec = CircuitDecompiler.decompile_attention_head(analysis, args.layer, args.head)
    dec["head_slice_shape"] = list(head_slice.shape)
    return dec


def _patch(args) -> dict:
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
    res = SafetensorsHandler.write_patched_safetensors(args.source, args.output, {args.tensor: patched_arr})
    res["metrics"] = metrics
    return res


def _diff(args) -> dict:
    base_arr, _ = SafetensorsHandler.read_tensor(args.baseline, args.tensor)
    patch_arr, _ = SafetensorsHandler.read_tensor(args.patched, args.tensor)
    diff = patch_arr.astype(np.float32) - base_arr.astype(np.float32)
    norm_diff = float(np.linalg.norm(diff))
    base_norm = float(np.linalg.norm(base_arr.astype(np.float32)))
    rel_shift = norm_diff / max(base_norm, 1e-12)
    changed = int(np.sum(np.abs(diff) > 1e-6))
    return {
        "tensor_name": args.tensor,
        "total_elements": base_arr.size,
        "changed_elements": changed,
        "changed_percentage": (changed / max(base_arr.size, 1)) * 100.0,
        "frobenius_relative_shift": rel_shift,
        "is_within_safety_bound": rel_shift < 0.005
    }


def _wsp_audit(args) -> dict:
    hdr, _, hdr_sha = SafetensorsHandler.read_header(args.model)
    t_names = [k for k in hdr.keys() if k != "__metadata__"]
    primary_t = args.tensor if (args.tensor and args.tensor in t_names) else t_names[0]
    arr, _ = SafetensorsHandler.read_tensor(args.model, primary_t)
    induction_report = None
    if len(t_names) >= 2:
        arr2, _ = SafetensorsHandler.read_tensor(args.model, t_names[1])
        induction_report = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(arr, arr2, num_heads=4)
    return {
        "model_path": args.model,
        "header_sha256": hdr_sha,
        "primary_tensor": primary_t,
        "effective_rank_analysis": CrossLayerCircuitAnalyzer.compute_effective_rank(arr),
        "surgical_amenability": AmenabilityDiagnostic.evaluate_surgical_amenability(arr),
        "zero_eval_security_audit": WeightSecurityAuditor.audit_weights_without_evaluation(arr),
        "cross_layer_induction": induction_report,
    }


def _synthesize(args) -> dict:
    sys.stderr.write(
        "[Bintra SCOPE WARNING] 'synthesize-weights' BUILDS a neural network from "
        "scratch. This is out of Bintra's reverse-engineering scope (it creates a "
        "standalone AI model, the WSP paper's own agenda) and is kept only as archived "
        "lineage. See SCOPE.md. It reverse-engineers no Windows binary.\n"
    )
    # Archived lineage still obeys the workspace write policy like every other writer.
    guard_output_path(None, args.output, "synthesize-weights", _IN_PLACE_WEIGHTS)
    tensors = WeightSpaceCompiler.compile_breakout_policy_network()
    header = {}
    raw_blobs = []
    offset = 0
    for name, arr in tensors.items():
        b = np.ascontiguousarray(arr, dtype=np.float32).tobytes()
        header[name] = {"dtype": "F32", "shape": list(arr.shape), "data_offsets": [offset, offset + len(b)]}
        raw_blobs.append(b)
        offset += len(b)
    hdr_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    hdr_bytes += b" " * ((8 - (len(hdr_bytes) % 8)) % 8)
    payload_bytes = b"".join([struct.pack("<Q", len(hdr_bytes)), hdr_bytes, *raw_blobs])
    from security import SafeFileAccess

    written_path = SafeFileAccess.write_workspace_file(args.output, payload_bytes)
    return {
        "output_path": written_path,
        "preset": args.preset,
        "synthesized_tensors": list(tensors.keys()),
        "total_parameters": int(sum(a.size for a in tensors.values()))
    }


def run_weight_engine(argv: List[str]) -> None:
    """Weight engine sub-CLI (`<prog> subspace|decompile|patch|diff|probe-trace|verify-behavior|wsp-audit ...`)."""
    _ensure_utf8_stdio()
    args = _build_weight_parser().parse_args(argv[1:])
    if args.command == "subspace":
        tensor_arr, meta = SafetensorsHandler.read_tensor(args.model, args.tensor)
        res = {
            "tensor_name": args.tensor,
            "dtype": meta["dtype"],
            "analysis": SubspaceAnalyzer.inspect_subspace(tensor_arr, mode=args.mode, top_k=args.top_k),
        }
    elif args.command == "decompile":
        res = _decompile(args)
    elif args.command == "patch":
        res = _patch(args)
    elif args.command == "diff":
        res = _diff(args)
    elif args.command == "probe-trace":
        res = ActivationTraceProber.probe_trace(args.model, args.prompt, max_tokens=args.max_tokens)
    elif args.command == "verify-behavior":
        res = NeuralBehaviorVerifier.verify_behavior(args.baseline, args.patched, tolerance=args.tolerance)
    elif args.command == "wsp-audit":
        res = _wsp_audit(args)
    else:  # synthesize-weights
        res = _synthesize(args)
    print(json.dumps(res, indent=2))


def cmd_weight_engine(cmd: str) -> None:
    """bintra subspace, decompile, decompile-circuit, diff, diff-weights, probe-trace, verify-behavior, wsp-audit"""
    argv = list(sys.argv)
    if cmd in _ENGINE_SUBCOMMAND:
        argv[1] = _ENGINE_SUBCOMMAND[cmd]
    rename_flag(argv, ("--file", "--input", "--binary"), "--model")
    run_weight_engine(argv)


def cmd_patch_weights(cmd: str) -> None:
    """bintra patch-weights"""
    argv = list(sys.argv)
    argv[1] = "patch"
    source, output = flag_value(argv, "--source"), flag_value(argv, "--output")
    if source is not None and output is not None:
        guard_output_path(source, output, "patch-weights", _IN_PLACE_WEIGHTS)
    rename_flag(argv, ("--file", "--input", "--binary"), "--model")
    run_weight_engine(argv)


def cmd_synthesize_weights(cmd: str) -> None:
    """bintra synthesize-weights (archived lineage; requires --archived-lineage)"""
    if "--archived-lineage" in sys.argv:
        print(f"[SCOPE WARNING] Running {cmd} under historical research lineage (--archived-lineage).")
        run_weight_engine([a for a in sys.argv if a != "--archived-lineage"])
        return
    print(json.dumps({
        "status": "decoupled_from_active_scope",
        "command": cmd,
        "message": (
            "Command 'synthesize-weights' has been decoupled from Bintra's active reverse-engineering interface. "
            "Per SCOPE.md, Bintra focuses on continuous semantic reverse engineering, decompilation, "
            "and embedded neural tensor auditing. Standalone neural model synthesis is preserved only as historical lineage."
        ),
        "reference": "SCOPE.md",
        "hint": "To invoke for paper reproduction, provide flag: --archived-lineage",
    }, indent=2))
    sys.exit(0)
