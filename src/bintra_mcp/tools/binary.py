"""MCP tool handlers: binary. Methods are bound into BintraMcpServer via mixin inheritance."""
import os
import sys
from typing import Any, Dict

from binary_neural_engine import (
    BinaryFormatInspector, ContinuousDeobfuscator, HybridBinaryDissector, SemanticFunctionMatcher,
    SensoryCortex, SurgicalBinaryPatcher,
)



class BinaryToolsMixin:
    """Handlers for the binary MCP tools (signature: (self, name, args) -> result)."""

    def _tool_inspect_binary(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_inspect_binary"""
        path = args["file_path"]
        res = BinaryFormatInspector.inspect(path)
        # Enrich with Windows Signature Intelligence (Dual Authenticode & Catalog)
        try:
            from windows_intelligence import WindowsSignatureIntelligence
            sig_info = WindowsSignatureIntelligence.verify_file(path, check_catalog=True)
            res["security_authenticode"] = sig_info
        except Exception as sig_err:
            res["security_authenticode_error"] = str(sig_err)
            sys.stderr.write(f"[Bintra] Signature verification skipped for '{path}': {sig_err}\n")
        max_exports = args.get("max_exports")
        if "exports" in res and "functions" in res["exports"]:
            all_funcs = res["exports"]["functions"]
            limit_val = 64 if max_exports is None else int(max_exports)
            if limit_val > 0 and len(all_funcs) > limit_val:
                res["exports"]["functions_sample"] = all_funcs[:limit_val]
                res["exports"]["functions_truncated"] = True
                res["exports"]["functions_omitted_count"] = len(all_funcs) - limit_val
                res["exports"]["functions"] = all_funcs[:limit_val]
        return res

    def _tool_deobfuscate_binary(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_deobfuscate_binary"""
        code_hex = args.get("code_hex")
        file_path = args.get("file_path")
        raw_off = args.get("offset")
        offset = int(str(raw_off), 0) if raw_off is not None else None
        length = int(args.get("length", 4096))
        if code_hex:
            raw_bytes = bytes.fromhex(code_hex.replace(" ", "").replace("\n", ""))
            return ContinuousDeobfuscator.deobfuscate_cfg(raw_bytes)
        elif file_path and os.path.exists(file_path):
            return ContinuousDeobfuscator.deobfuscate_file(file_path, offset=offset, length=length)
        else:
            raise ValueError("Must provide 'code_hex' or valid 'file_path'")

    def _tool_dump_bytes(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_dump_bytes"""
        path = args["file_path"]
        offset = int(str(args["offset"]), 0)
        length = int(args.get("length", 64))
        return SurgicalBinaryPatcher.read_bytes(path, offset, length)

    def _tool_match_functions(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_match_functions"""
        f1_hex = args["func1_hex"]
        f2_hex = args["func2_hex"]
        return SemanticFunctionMatcher.match_functions(f1_hex, f2_hex)

    def _tool_patch_binary(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_patch_binary"""
        path = args["file_path"]
        out_path = args.get("output_path")
        from security import PathIdentity, ExecutionGuard, Capability, TargetMutationError
        if not out_path or PathIdentity.is_same_file(path, out_path):
            raise TargetMutationError(
                "TARGET_WRITE_FORBIDDEN: 'output_path' is required and cannot overwrite the source target binary. Analysis tools must write patched copies to an isolated workspace destination."
            )

        # Enforce that output_path is within authorized workspace
        ExecutionGuard.request_access(
            component="mcp_server",
            operation="patch_binary",
            target=out_path,
            capability=Capability.WORKSPACE_WRITE,
            access_mode="WRITE"
        )

        offset = int(str(args["offset"]), 0)
        patch_hex = args["patch_hex"]
        force = bool(args.get("force", False))
        return SurgicalBinaryPatcher.patch_file(
            source_path=path,
            output_path=out_path,
            file_offset=offset,
            patch_hex=patch_hex,
            enforce_nociception=not force
        )

    def _tool_scan_hybrid(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_scan_hybrid"""
        path = args["file_path"]
        return HybridBinaryDissector.scan_for_embedded_logic(path)

    def _tool_sensory_audit(self, name: str, args: Dict[str, Any]) -> Any:
        """bintra_sensory_audit"""
        file_path = args.get("file_path")
        code_hex = args.get("code_hex")
        cortex = SensoryCortex()
        return cortex.evaluate_all_senses(file_path=file_path, code_hex=code_hex)
