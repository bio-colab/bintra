"""MCP tool handlers: weights. Methods are bound into BintraMcpServer via mixin inheritance."""
from typing import Any, Dict

from bintra_engine import (
    AmenabilityDiagnostic, CrossLayerCircuitAnalyzer, SafetensorsHandler, WeightPatcher, WeightSecurityAuditor,
)



class WeightsToolsMixin:
    """Handlers for the weights MCP tools (signature: (self, name, args) -> result)."""

    def _tool_wsp_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_wsp_audit"""
        path = args["model_path"]
        hdr, _, hdr_sha = SafetensorsHandler.read_header(path)
        t_names = [k for k in hdr.keys() if k != "__metadata__"]
        if not t_names:
            raise ValueError("No tensor weights found in safetensors model file.")
        req_t = args.get("tensor")
        primary_t = req_t if (req_t and req_t in t_names) else t_names[0]
        arr, _ = SafetensorsHandler.read_tensor(path, primary_t)
        eff_rank = CrossLayerCircuitAnalyzer.compute_effective_rank(arr)
        amenability = AmenabilityDiagnostic.evaluate_surgical_amenability(arr)
        sec_audit = WeightSecurityAuditor.audit_weights_without_evaluation(arr)
        induction_report = None
        if len(t_names) >= 2:
            arr2, _ = SafetensorsHandler.read_tensor(path, t_names[1])
            induction_report = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(arr, arr2, num_heads=4)
        return {
            "status": "success",
            "model_path": path,
            "header_sha256": hdr_sha,
            "primary_tensor": primary_t,
            "tensor_count": len(t_names),
            "effective_rank_analysis": eff_rank,
            "surgical_amenability": amenability,
            "zero_eval_security_audit": sec_audit,
            "cross_layer_induction": induction_report,
        }

    def _tool_patch_weights(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_patch_weights"""
        src = args["source_path"]
        out = args["output_path"]
        tname = args["tensor_name"]
        num_cols = int(args.get("num_columns", 64))
        tensor_arr, _ = SafetensorsHandler.read_tensor(src, tname)
        patched_arr, metrics = WeightPatcher.apply_patch(
            tensor_arr,
            patch_operation="column_direction_subtract",
            parameters={"num_columns": num_cols},
        )
        res = SafetensorsHandler.write_patched_safetensors(
            src, out, {tname: patched_arr}
        )
        res["status"] = res.get("status", "success")
        res["tensor_name"] = tname
        res["operation"] = "column_direction_subtract"
        res["metrics"] = metrics
        return res
