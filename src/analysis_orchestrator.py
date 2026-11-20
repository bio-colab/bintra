# -*- coding: utf-8 -*-
"""
Bintra Unified Binary Triage & Cross-Domain Evidence Orchestrator.

Connects Bintra's isolated static, digital-trust, obfuscation, crash-RCA,
and Ghidra analysis engines into one reusable, fail-closed, evidence-honest
pipeline shared by both the CLI (`bintra triage`) and MCP (`bintra_triage_binary`).

Design invariants:
  - Strictly read-only on target binaries (mediated via ExecutionGuard).
  - Explicit per-stage status reporting (never hides stage failures as empty data).
  - Epistemic separation between observed facts, heuristic indicators, and unknowns.
  - Zero external dependencies beyond Bintra's existing core modules.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from security import Capability, ExecutionGuard, PathIdentity, SecurityViolationError


class BinaryTriageOrchestrator:
    """
    Coordinates PE inspection, PE deep forensics (.pdata/RTTI/PDB),
    Authenticode/Catalog signature intelligence, obfuscation triage,
    optional MiniDump crash RCA, optional Ghidra call-graph/data-flow,
    and unified EvidenceGraph fusion.
    """

    @classmethod
    def triage_binary(
        cls,
        file_path: str,
        dmp_path: Optional[str] = None,
        ghidra_export_path: Optional[str] = None,
        function_name: Optional[str] = None,
        include_deobfuscation: bool = True,
        max_exports: int = 32,
        forensics_limit: int = 200,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end, read-only multi-engine triage of a binary file
        and synthesizes a unified cross-domain evidence graph and risk assessment.
        """
        ExecutionGuard.request_access(
            component="analysis_orchestrator",
            operation="triage_binary",
            target=file_path,
            capability=Capability.FILE_READ,
            access_mode="READ",
        )
        can_path = PathIdentity.canonicalize(file_path)
        if not os.path.isfile(can_path):
            raise FileNotFoundError(f"Target binary not found: {file_path}")

        # Compute target binary hash and metadata for provenance verification
        sha256_hasher = hashlib.sha256()
        with open(can_path, "rb") as bf:
            while chunk := bf.read(65536):
                sha256_hasher.update(chunk)
        target_sha256 = sha256_hasher.hexdigest().lower()
        target_filename = os.path.basename(can_path)

        stages: Dict[str, Dict[str, Any]] = {}
        pe_inspect_res: Optional[Dict[str, Any]] = None
        pe_forensics_res: Optional[Dict[str, Any]] = None
        sig_res: Optional[Dict[str, Any]] = None
        deobf_res: Optional[Dict[str, Any]] = None
        crash_rca_res: Optional[Dict[str, Any]] = None
        ghidra_cg_res: Optional[Dict[str, Any]] = None
        ghidra_df_res: Optional[Dict[str, Any]] = None
        ghidra_provenance: Dict[str, Any] = {"status": "NOT_PROVIDED", "verified": False}

        # Stage 1: PE Structure, Mitigations (ASLR/DEP/CFG), Imports/Exports, Entropy
        try:
            from binary_neural_engine import BinaryFormatInspector
            pe_inspect_res = BinaryFormatInspector.inspect(can_path)
            if isinstance(pe_inspect_res, dict) and max_exports > 0:
                exports = pe_inspect_res.get("exports")
                if isinstance(exports, dict):
                    funcs = exports.get("functions")
                    if isinstance(funcs, list) and len(funcs) > max_exports:
                        exports_copy = dict(exports)
                        exports_copy["functions"] = funcs[:max_exports]
                        exports_copy["functions_truncated"] = True
                        exports_copy["truncated_from"] = len(funcs)
                        pe_inspect_res = dict(pe_inspect_res)
                        pe_inspect_res["exports"] = exports_copy
                        pe_inspect_res["exports_truncated"] = True
                elif isinstance(exports, list) and len(exports) > max_exports:
                    pe_inspect_res = dict(pe_inspect_res)
                    pe_inspect_res["exports"] = exports[:max_exports]
                    pe_inspect_res["exports_truncated"] = True
            st_inspect = pe_inspect_res.get("status", "ok") if isinstance(pe_inspect_res, dict) else "ok"
            stages["binary_inspection"] = {"status": st_inspect}
        except SecurityViolationError:
            raise
        except Exception as exc:
            stages["binary_inspection"] = {"status": "error", "error": str(exc)}

        # Stage 2: PE Deep Forensics (.pdata unwind functions, MSVC RTTI, offline PDB/RSDS)
        try:
            from pe_deep_forensics import PeDeepForensicsInspector
            pe_forensics_res = PeDeepForensicsInspector().inspect(can_path, limit=forensics_limit)
            st_forensics = pe_forensics_res.get("status", "ok") if isinstance(pe_forensics_res, dict) else "ok"
            stages["pe_deep_forensics"] = {"status": st_forensics}
        except SecurityViolationError:
            raise
        except Exception as exc:
            stages["pe_deep_forensics"] = {"status": "error", "error": str(exc)}

        # Stage 3: Digital Trust & Authenticode / Security Catalog Intelligence
        try:
            from windows_intelligence.signature_intelligence import WindowsSignatureIntelligence
            sig_res = WindowsSignatureIntelligence.verify_file(can_path, check_catalog=True)
            trust_stat = sig_res.get("trust_status", "UNKNOWN")
            st_sig = "ok"
            if trust_stat == "VERIFICATION_ERROR":
                st_sig = "verification_error"
            elif trust_stat == "REVOKED":
                st_sig = "untrusted_revoked"
            elif trust_stat in ("EXPIRED", "UNTRUSTED_ROOT"):
                st_sig = "untrusted"
            stages["signature_intelligence"] = {
                "status": st_sig,
                "trust_status": trust_stat,
                "is_verified": bool(sig_res.get("is_verified", False)),
            }
        except SecurityViolationError:
            raise
        except Exception as exc:
            stages["signature_intelligence"] = {"status": "error", "error": str(exc)}

        # Stage 4: Obfuscation / CFF / Opaque Predicate Triage (optional, read-only sample)
        if include_deobfuscation:
            try:
                from binary_neural_engine import ContinuousDeobfuscator
                deobf_res = ContinuousDeobfuscator.analyze_file(can_path, length=4096)
                st_deobf = deobf_res.get("status", "ok") if isinstance(deobf_res, dict) else "ok"
                stages["deobfuscation"] = {"status": st_deobf}
            except SecurityViolationError:
                raise
            except Exception as exc:
                stages["deobfuscation"] = {"status": "error", "error": str(exc)}
        else:
            stages["deobfuscation"] = {"status": "skipped", "reason": "disabled_by_caller"}

        # Stage 5: Optional Crash MiniDump RCA
        if dmp_path:
            try:
                from windows_intelligence import CrashRootCauseAnalyzer
                crash_rca_res = CrashRootCauseAnalyzer.analyze_crash(
                    dump_target=dmp_path, binary_path=can_path
                )
                stages["crash_rca"] = {"status": crash_rca_res.get("status", "ok") if isinstance(crash_rca_res, dict) else "ok"}
            except SecurityViolationError:
                raise
            except Exception as exc:
                stages["crash_rca"] = {"status": "error", "error": str(exc)}
        else:
            stages["crash_rca"] = {"status": "skipped", "reason": "no_dmp_path_provided"}

        # Stage 6: Optional Ghidra Export Call-Graph & Data-Flow Slicing with Provenance Check
        if ghidra_export_path:
            try:
                from ghidra_export_store import GhidraExportStore
                from ghidra_pcode_vectorizer import GhidraDeepAnalyzer
                with GhidraExportStore.from_path(ghidra_export_path) as store:
                    # Provenance verification against target binary
                    gh_prog_name = str(store.get("program_name") or "")
                    gh_sha256 = str(store.get("sha256") or "").lower()
                    gh_md5 = str(store.get("md5") or "").lower()

                    if gh_sha256:
                        if gh_sha256 == target_sha256:
                            ghidra_provenance = {
                                "status": "VERIFIED_CRYPTOGRAPHIC_HASH",
                                "verified": True,
                                "matched_sha256": gh_sha256,
                                "program_name": gh_prog_name,
                            }
                        else:
                            ghidra_provenance = {
                                "status": "PROVENANCE_HASH_MISMATCH",
                                "verified": False,
                                "export_sha256": gh_sha256,
                                "target_sha256": target_sha256,
                                "warning": f"Ghidra export SHA-256 ({gh_sha256}) does not match target ({target_sha256})."
                            }
                    elif gh_prog_name:
                        target_stem = Path(target_filename).stem.lower()
                        gh_stem = Path(gh_prog_name).stem.lower()
                        if target_stem in gh_stem or gh_stem in target_stem:
                            ghidra_provenance = {
                                "status": "VERIFIED_PROGRAM_NAME_MATCH",
                                "verified": True,
                                "program_name": gh_prog_name,
                            }
                        else:
                            ghidra_provenance = {
                                "status": "PROVENANCE_NAME_MISMATCH",
                                "verified": False,
                                "export_program_name": gh_prog_name,
                                "target_filename": target_filename,
                                "warning": f"Ghidra export program '{gh_prog_name}' does not match target filename '{target_filename}'."
                            }
                    else:
                        ghidra_provenance = {
                            "status": "UNVERIFIED_NO_METADATA",
                            "verified": False,
                            "warning": "Ghidra export lacks program_name or sha256 metadata."
                        }

                    analyzer = GhidraDeepAnalyzer()
                    ghidra_cg_res = analyzer.build_call_graph_and_xrefs(
                        store, target_function=function_name
                    )
                    if function_name:
                        fn_match = store.get_function(function_name)
                        if fn_match:
                            ghidra_df_res = analyzer.slice_data_flow(fn_match)

                cg_stat = ghidra_cg_res.get("status", "ok") if isinstance(ghidra_cg_res, dict) else "ok"
                stages["ghidra_analysis"] = {
                    "status": cg_stat,
                    "provenance": ghidra_provenance,
                }
            except SecurityViolationError:
                raise
            except Exception as exc:
                stages["ghidra_analysis"] = {"status": "error", "error": str(exc)}
        else:
            stages["ghidra_analysis"] = {"status": "skipped", "reason": "no_ghidra_export_provided"}

        # Stage 7: Unified Cross-Domain Evidence Graph Fusion
        from windows_intelligence.evidence_engine.graph_model import fuse_static_dynamic_ghidra
        fused = fuse_static_dynamic_ghidra(
            pe_forensics=pe_forensics_res,
            crash_rca=crash_rca_res,
            ghidra_call_graph=ghidra_cg_res,
            ghidra_data_flow=ghidra_df_res,
            binary_inspection=pe_inspect_res,
            signature_intel=sig_res,
            deobfuscation=deobf_res,
        )

        # Stage 8: Epistemic Summary (Observed Facts vs Heuristic Indicators vs Recommendations)
        synthesis = cls._synthesize_triage_summary(
            can_path=can_path,
            pe_inspect=pe_inspect_res,
            pe_forensics=pe_forensics_res,
            sig_intel=sig_res,
            deobf=deobf_res,
            crash_rca=crash_rca_res,
            ghidra_cg=ghidra_cg_res,
            ghidra_prov=ghidra_provenance,
        )

        failed_stages = [name for name, st in stages.items() if st.get("status") in ("error", "failed")]
        partial_stages = [name for name, st in stages.items() if st.get("status") in ("partial", "partial_success", "verification_error", "untrusted", "untrusted_revoked")]
        active_stages = [name for name, st in stages.items() if st.get("status") != "skipped"]

        if failed_stages and len(failed_stages) == len(active_stages):
            overall_status = "error"
        elif failed_stages or partial_stages:
            overall_status = "partial_success"
        else:
            overall_status = "ok"

        return {
            "status": overall_status,
            "epistemic_classification": "UNIFIED_BINARY_TRIAGE",
            "target_file": can_path,
            "file_name": os.path.basename(can_path),
            "target_sha256": target_sha256,
            "stage_statuses": stages,
            "failed_stages": failed_stages,
            "partial_stages": partial_stages,
            "summary": synthesis,
            "evidence_graph": fused.get("fused_graph", {}),
            "artifacts": {
                "binary_inspection": pe_inspect_res,
                "pe_deep_forensics": pe_forensics_res,
                "signature_intelligence": sig_res,
                "deobfuscation": deobf_res,
                "crash_rca": crash_rca_res,
                "ghidra_call_graph": ghidra_cg_res,
                "ghidra_data_flow": ghidra_df_res,
            },
        }

    @staticmethod
    def _synthesize_triage_summary(
        can_path: str,
        pe_inspect: Optional[Dict[str, Any]],
        pe_forensics: Optional[Dict[str, Any]],
        sig_intel: Optional[Dict[str, Any]],
        deobf: Optional[Dict[str, Any]],
        crash_rca: Optional[Dict[str, Any]],
        ghidra_cg: Optional[Dict[str, Any]],
        ghidra_prov: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Separates observed facts from heuristic indicators and proposes next steps."""
        observed_facts: List[str] = []
        heuristic_indicators: List[str] = []
        recommended_next_tools: List[str] = []

        if pe_inspect and isinstance(pe_inspect, dict):
            fmt = pe_inspect.get("format") or pe_inspect.get("architecture")
            if fmt:
                observed_facts.append(f"Binary format/architecture: {fmt}")
            mit = pe_inspect.get("mitigations") or pe_inspect.get("security_mitigations") or {}
            if isinstance(mit, dict) and mit:
                disabled = [k for k, v in mit.items() if v is False]
                if disabled:
                    observed_facts.append(f"Disabled PE mitigations: {', '.join(sorted(disabled))}")
            entropy = pe_inspect.get("overall_entropy") or pe_inspect.get("shannon_entropy")
            if isinstance(entropy, (int, float)):
                observed_facts.append(f"Observed Shannon entropy: {entropy:.2f}")
                if entropy >= 7.2:
                    heuristic_indicators.append("HIGH_ENTROPY_PACKED_OR_ENCRYPTED_SUSPECTED")
                    recommended_next_tools.append("bintra_deobfuscate_binary")

        if pe_forensics and pe_forensics.get("status") == "ok":
            pdata_cnt = pe_forensics.get("pdata_functions", {}).get("total_runtime_functions", 0)
            rtti_cnt = pe_forensics.get("msvc_rtti", {}).get("vftables_count", 0)
            observed_facts.append(f"Recovered {pdata_cnt} .pdata runtime functions and {rtti_cnt} MSVC RTTI vftables")

        if sig_intel and isinstance(sig_intel, dict):
            t_stat = sig_intel.get("trust_status", "UNKNOWN")
            is_ver = bool(sig_intel.get("is_verified", False))
            observed_facts.append(f"Signature trust_status={t_stat} (cryptographically_verified={is_ver})")
            for rf in sig_intel.get("risk_flags", []):
                heuristic_indicators.append(rf)
            if t_stat == "SIGNATURE_PRESENT_UNVERIFIED":
                recommended_next_tools.append("verify_on_windows_host_with_WinVerifyTrust")

        if deobf and isinstance(deobf, dict):
            cff = deobf.get("control_flow_flattening") or {}
            if cff.get("has_control_flow_flattening"):
                heuristic_indicators.append("CONTROL_FLOW_FLATTENING_DETECTED")
                recommended_next_tools.append("bintra_ghidra_headless")
            op_cnt = deobf.get("opaque_predicates_detected", 0)
            if isinstance(op_cnt, int) and op_cnt > 0:
                heuristic_indicators.append(f"OPAQUE_PREDICATES_DETECTED:{op_cnt}")

        if crash_rca and isinstance(crash_rca, dict):
            exc = crash_rca.get("exception_code")
            if exc:
                observed_facts.append(f"Correlated crash exception: {exc}")

        if ghidra_cg and ghidra_cg.get("status") == "ok":
            fn_cnt = ghidra_cg.get("functions_indexed", 0)
            observed_facts.append(f"Ghidra call graph indexed {fn_cnt} functions")
            if ghidra_prov and isinstance(ghidra_prov, dict):
                p_stat = ghidra_prov.get("status", "UNVERIFIED")
                if ghidra_prov.get("verified"):
                    observed_facts.append(f"Ghidra export provenance verified: {p_stat}")
                else:
                    heuristic_indicators.append(f"GHIDRA_PROVENANCE_ALERT:{p_stat}")
        else:
            recommended_next_tools.append("bintra_ghidra_analyze")

        # Deduplicate preserving order
        dedup_tools = list(dict.fromkeys(recommended_next_tools))

        return {
            "observed_facts": observed_facts,
            "heuristic_indicators": heuristic_indicators,
            "recommended_next_steps": dedup_tools,
        }
