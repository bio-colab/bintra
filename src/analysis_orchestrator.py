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
        include_sensory: bool = True,
        include_hybrid_scan: bool = True,
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
        sensory_res: Optional[Dict[str, Any]] = None
        hybrid_res: Optional[Dict[str, Any]] = None
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

        # Stage 4.5: Holistic 10-Sense Sensory Cortex Perception
        if include_sensory:
            try:
                from binary_neural_engine import SensoryCortex
                sensory_res = SensoryCortex().evaluate_all_senses(file_path=can_path)
                stages["sensory_perception"] = {
                    "status": "ok" if isinstance(sensory_res, dict) and sensory_res.get("senses") else "partial",
                    "active_senses_count": sensory_res.get("active_senses_count", 0) if isinstance(sensory_res, dict) else 0,
                    "overall_sensory_efficiency": sensory_res.get("overall_sensory_efficiency") if isinstance(sensory_res, dict) else None,
                }
            except SecurityViolationError:
                raise
            except Exception as exc:
                stages["sensory_perception"] = {"status": "error", "error": str(exc)}
        else:
            stages["sensory_perception"] = {"status": "skipped", "reason": "disabled_by_caller"}

        # Stage 4.7: Embedded Neural Inference Asset Scan (hybrid native-neural binaries)
        if include_hybrid_scan:
            try:
                from binary_neural_engine import HybridBinaryDissector
                hybrid_res = HybridBinaryDissector.scan_for_embedded_logic(can_path)
                st_hybrid = "ok" if isinstance(hybrid_res, dict) else "error"
                stages["embedded_ai_scan"] = {
                    "status": st_hybrid,
                    "is_hybrid_binary": bool(hybrid_res.get("is_hybrid_binary", False)) if isinstance(hybrid_res, dict) else False,
                    "embedded_logic_assets_count": hybrid_res.get("embedded_logic_assets_count", 0) if isinstance(hybrid_res, dict) else 0,
                }
            except SecurityViolationError:
                raise
            except Exception as exc:
                stages["embedded_ai_scan"] = {"status": "error", "error": str(exc)}
        else:
            stages["embedded_ai_scan"] = {"status": "skipped", "reason": "disabled_by_caller"}

        # Stage 5: Binary Slack Space & Overlay Forensics
        slack_res: Optional[Dict[str, Any]] = None
        try:
            from windows_intelligence.evidence_engine.binary_slack_inspector import BinarySlackInspector
            slack_res = BinarySlackInspector.inspect_file(can_path)
            st_slack = slack_res.get("status", "ok") if isinstance(slack_res, dict) else "ok"
            stages["slack_and_overlay"] = {
                "status": st_slack,
                "has_trailing_slack": slack_res.get("has_trailing_slack", False),
                "slack_bytes_count": slack_res.get("slack_bytes_count", 0),
                "slack_type": slack_res.get("slack_type", "CLEAN_EXACT_EOF"),
            }
        except SecurityViolationError:
            raise
        except Exception as exc:
            stages["slack_and_overlay"] = {"status": "error", "error": str(exc)}

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
                    ghidra_provenance, is_cryptographically_proven, is_heuristic_match = (
                        cls.verify_ghidra_export_provenance(
                            store, target_sha256=target_sha256, target_filename=target_filename
                        )
                    )

                    if is_cryptographically_proven or is_heuristic_match:
                        analyzer = GhidraDeepAnalyzer()
                        ghidra_cg_res = analyzer.build_call_graph_and_xrefs(
                            store, target_function=function_name
                        )
                        if function_name:
                            fn_match = store.get_function(function_name)
                            if fn_match:
                                ghidra_df_res = analyzer.slice_data_flow(fn_match)
                    else:
                        # STRICT ENFORCEMENT: Mismatched or alien export is quarantined from evidence fusion
                        ghidra_cg_res = None
                        ghidra_df_res = None

                if not is_cryptographically_proven and not is_heuristic_match:
                    stages["ghidra_analysis"] = {
                        "status": "provenance_mismatch",
                        "provenance": ghidra_provenance,
                        "error": ghidra_provenance.get("warning", "Ghidra export provenance verification failed.")
                    }
                elif is_heuristic_match:
                    cg_stat = ghidra_cg_res.get("status", "ok") if isinstance(ghidra_cg_res, dict) else "ok"
                    stages["ghidra_analysis"] = {
                        "status": "heuristic_unverified",
                        "provenance": ghidra_provenance,
                        "warning": ghidra_provenance.get("warning")
                    }
                else:
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
            ghidra_provenance=ghidra_provenance,
            sensory_audit=sensory_res,
            embedded_ai_scan=hybrid_res,
            slack_forensics=slack_res,
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
            slack_res=slack_res,
            sensory_res=sensory_res,
            hybrid_res=hybrid_res,
        )

        failed_stages = [name for name, st in stages.items() if st.get("status") in ("error", "failed", "provenance_mismatch")]
        partial_stages = [name for name, st in stages.items() if st.get("status") in ("partial", "partial_success", "verification_error", "untrusted", "untrusted_revoked", "heuristic_unverified")]
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
                "sensory_perception": sensory_res,
                "embedded_ai_scan": hybrid_res,
                "slack_and_overlay": slack_res,
                "crash_rca": crash_rca_res,
                "ghidra_call_graph": ghidra_cg_res,
                "ghidra_data_flow": ghidra_df_res,
            },
        }

    @staticmethod
    def verify_ghidra_export_provenance(
        store: Any,
        target_sha256: str,
        target_filename: str,
    ) -> tuple:
        """Verifies that a Ghidra export truly belongs to the analyzed target binary.

        Single authoritative implementation shared by the triage orchestrator and
        the MCP ``bintra_fuse_evidence`` tool so that provenance quarantine rules
        cannot drift between entry points.

        Returns ``(provenance_dict, is_cryptographically_proven, is_heuristic_match)``.
        """
        gh_prog_name = str(store.get("program_name") or "")
        gh_sha256 = str(store.get("sha256") or "").lower()

        is_cryptographically_proven = False
        is_heuristic_match = False

        if gh_sha256:
            if gh_sha256 == target_sha256:
                provenance = {
                    "status": "VERIFIED_CRYPTOGRAPHIC_HASH",
                    "verified": True,
                    "matched_sha256": gh_sha256,
                    "program_name": gh_prog_name,
                }
                is_cryptographically_proven = True
            else:
                provenance = {
                    "status": "PROVENANCE_HASH_MISMATCH",
                    "verified": False,
                    "export_sha256": gh_sha256,
                    "target_sha256": target_sha256,
                    "warning": f"Ghidra export SHA-256 ({gh_sha256}) does not match target ({target_sha256}). Quarantined."
                }
        elif gh_prog_name:
            target_stem = Path(target_filename).stem.lower()
            gh_stem = Path(gh_prog_name).stem.lower()
            if target_stem in gh_stem or gh_stem in target_stem:
                provenance = {
                    "status": "HEURISTIC_NAME_MATCH",
                    "verified": False,
                    "is_heuristic": True,
                    "program_name": gh_prog_name,
                    "warning": f"Matched by filename heuristic '{gh_prog_name}' only; cryptographic hash unavailable."
                }
                is_heuristic_match = True
            else:
                provenance = {
                    "status": "PROVENANCE_NAME_MISMATCH",
                    "verified": False,
                    "export_program_name": gh_prog_name,
                    "target_filename": target_filename,
                    "warning": f"Ghidra export program '{gh_prog_name}' does not match target filename '{target_filename}'. Quarantined."
                }
        else:
            provenance = {
                "status": "UNVERIFIED_NO_METADATA",
                "verified": False,
                "warning": "Ghidra export lacks program_name or sha256 metadata. Quarantined."
            }
        return provenance, is_cryptographically_proven, is_heuristic_match

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
        slack_res: Optional[Dict[str, Any]] = None,
        sensory_res: Optional[Dict[str, Any]] = None,
        hybrid_res: Optional[Dict[str, Any]] = None,
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
            entropy = (
                pe_inspect.get("overall_entropy")
                or pe_inspect.get("overall_shannon_entropy")
                or pe_inspect.get("shannon_entropy")
                or (pe_inspect.get("embedded_ai_scan") or {}).get("overall_shannon_entropy")
            )
            if not isinstance(entropy, (int, float)):
                secs = [s for s in (pe_inspect.get("sections") or []) if isinstance(s, dict) and isinstance(s.get("shannon_entropy"), (int, float))]
                if secs:
                    total_raw = sum(max(1, int(s.get("raw_size", 0))) for s in secs)
                    entropy = round(sum(float(s["shannon_entropy"]) * max(1, int(s.get("raw_size", 0))) for s in secs) / total_raw, 4)
            if isinstance(entropy, (int, float)):
                observed_facts.append(f"Observed Shannon entropy: {entropy:.2f}")
                if entropy >= 7.2:
                    heuristic_indicators.append("HIGH_ENTROPY_PACKED_OR_ENCRYPTED_SUSPECTED")
                    recommended_next_tools.append("bintra_deobfuscate_binary")

        if slack_res and isinstance(slack_res, dict):
            if slack_res.get("has_trailing_slack"):
                stype = slack_res.get("slack_type", "UNMAPPED_SLACK")
                scnt = slack_res.get("slack_bytes_count", 0)
                observed_facts.append(f"Binary slack space detected: {scnt} bytes ({stype})")
                if "SUSPICIOUS" in stype:
                    heuristic_indicators.append(f"SUSPICIOUS_TRAILING_OVERLAY:{stype}")

        if sensory_res and isinstance(sensory_res, dict) and sensory_res.get("senses"):
            active_cnt = sensory_res.get("active_senses_count", 0)
            efficiency = sensory_res.get("overall_sensory_efficiency")
            observed_facts.append(
                f"Sensory Cortex perception active on {active_cnt}/10 metaphorical senses "
                + (f"(overall efficiency {efficiency})" if isinstance(efficiency, (int, float)) else "")
            )
            for s_key, s_val in sensory_res.get("senses", {}).items():
                if not isinstance(s_val, dict):
                    continue
                anomalies = s_val.get("telemetry", {}).get("anomalies") if isinstance(s_val.get("telemetry"), dict) else None
                if anomalies:
                    heuristic_indicators.append(f"SENSE_ANOMALY:{s_key}:{anomalies}")

        if hybrid_res and isinstance(hybrid_res, dict):
            ai_cnt = hybrid_res.get("embedded_logic_assets_count", 0)
            if hybrid_res.get("is_hybrid_binary") or ai_cnt:
                frameworks = sorted({
                    str(f.get("kind") or f.get("type") or "ASSET")
                    for f in (hybrid_res.get("findings") or []) if isinstance(f, dict)
                })
                observed_facts.append(
                    f"Embedded neural inference assets detected: {ai_cnt}"
                    + (f" (kinds: {', '.join(frameworks)})" if frameworks else "")
                )
                heuristic_indicators.append("EMBEDDED_NEURAL_INFERENCE_LOGIC_PRESENT")
                recommended_next_tools.append("bintra_wsp_audit")
                recommended_next_tools.append("bintra_dump_bytes")

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

        if ghidra_prov and isinstance(ghidra_prov, dict):
            p_stat = ghidra_prov.get("status", "UNVERIFIED")
            if p_stat == "VERIFIED_CRYPTOGRAPHIC_HASH":
                observed_facts.append(f"Ghidra export provenance cryptographically verified: {p_stat}")
            elif p_stat == "HEURISTIC_NAME_MATCH":
                heuristic_indicators.append("GHIDRA_EXPORT_MATCHED_BY_HEURISTIC_FILENAME_ONLY")
            elif p_stat in ("PROVENANCE_HASH_MISMATCH", "PROVENANCE_NAME_MISMATCH", "UNVERIFIED_NO_METADATA"):
                heuristic_indicators.append(f"GHIDRA_PROVENANCE_MISMATCH_QUARANTINED:{p_stat}")

        if ghidra_cg and ghidra_cg.get("status") == "ok":
            fn_cnt = ghidra_cg.get("functions_indexed", 0)
            observed_facts.append(f"Ghidra call graph indexed {fn_cnt} functions")
        else:
            recommended_next_tools.append("bintra_ghidra_analyze")

        # Deduplicate preserving order
        dedup_tools = list(dict.fromkeys(recommended_next_tools))

        return {
            "observed_facts": observed_facts,
            "heuristic_indicators": heuristic_indicators,
            "recommended_next_steps": dedup_tools,
        }

    @classmethod
    def generate_markdown_report(cls, triage_data: Dict[str, Any]) -> str:
        """
        Generates an authoritative, deterministic GitHub-flavored Markdown dossier
        directly from the unified triage dictionary. Guarantees 1:1 factual
        consistency with JSON evidence without human divergence.
        """
        target_file = triage_data.get("target_file", "UNKNOWN")
        target_sha256 = triage_data.get("target_sha256", "UNKNOWN")
        file_name = triage_data.get("file_name", os.path.basename(str(target_file)))
        overall_status = triage_data.get("status", "UNKNOWN")
        artifacts = triage_data.get("artifacts", {})
        summary = triage_data.get("summary", {})

        pe_inspect = artifacts.get("binary_inspection") or {}
        sig_res = artifacts.get("signature_intelligence") or {}
        slack_res = artifacts.get("slack_and_overlay") or {}
        pe_forensics = artifacts.get("pe_deep_forensics") or {}
        deobf_res = artifacts.get("deobfuscation") or {}
        sensory_res = artifacts.get("sensory_perception") or {}
        hybrid_res = artifacts.get("embedded_ai_scan") or {}

        lines = []
        lines.append(f"# Bintra Binary Triage Forensic Dossier: `{file_name}`\n")
        lines.append("> [!IMPORTANT]")
        lines.append("> Generated deterministically by Bintra BinaryTriageOrchestrator.")
        lines.append(f"> Epistemic Classification: `{triage_data.get('epistemic_classification', 'UNIFIED_BINARY_TRIAGE')}`\n")
        
        lines.append("## 1. Target Inventory & Hashing\n")
        lines.append("| Property | Forensic Value |")
        lines.append("| :--- | :--- |")
        lines.append(f"| **Target Path** | `{target_file}` |")
        lines.append(f"| **SHA-256** | `{target_sha256}` |")
        lines.append(f"| **Triage Status** | `{str(overall_status).upper()}` |")
        arch = pe_inspect.get("format") or pe_inspect.get("pe_type") or pe_inspect.get("architecture") or "N/A"
        lines.append(f"| **Architecture / Format** | `{arch}` |\n")

        # Mitigations
        mit = pe_inspect.get("windows_security_mitigations") or pe_inspect.get("mitigations") or {}
        if isinstance(mit, dict) and mit:
            lines.append("## 2. Windows Exploit Mitigations\n")
            lines.append("| Mitigation | State |")
            lines.append("| :--- | :---: |")
            for k, v in mit.items():
                state = "ENABLED (Protected)" if v else "DISABLED (Exposed)"
                lines.append(f"| `{k}` | {state} |")
            lines.append("")

        # Digital Trust
        if sig_res and isinstance(sig_res, dict):
            lines.append("## 3. Digital Signature & Authenticode Verification\n")
            lines.append("| Attribute | State |")
            lines.append("| :--- | :--- |")
            lines.append(f"| **Trust Status** | `{sig_res.get('trust_status', 'UNKNOWN')}` |")
            lines.append(f"| **Is Verified** | `{bool(sig_res.get('is_verified', False))}` |")
            lines.append(f"| **Signer Subject** | `{sig_res.get('signer_subject', 'N/A')}` |")
            lines.append(f"| **Catalog Verified** | `{sig_res.get('is_catalog_signed', False)}` |\n")

        # Slack & Overlay
        if slack_res and isinstance(slack_res, dict):
            lines.append("## 4. Binary Slack Space & Overlay Forensics\n")
            lines.append("| Property | Value |")
            lines.append("| :--- | :--- |")
            lines.append(f"| **Has Trailing Slack** | `{slack_res.get('has_trailing_slack', False)}` |")
            lines.append(f"| **Slack Bytes Count** | `{slack_res.get('slack_bytes_count', 0)}` bytes |")
            lines.append(f"| **Slack Classification** | `{slack_res.get('slack_type', 'N/A')}` |")
            lines.append(f"| **Diagnostic Note** | {slack_res.get('diagnostic_note', 'N/A')} |\n")

        # Sensory Cortex Perception
        if sensory_res and isinstance(sensory_res, dict) and sensory_res.get("senses"):
            lines.append("## 5. Sensory Cortex Perception (10 Metaphorical Senses)\n")
            lines.append("| Sense | Status | Telemetry Highlights |")
            lines.append("| :--- | :--- | :--- |")
            for s_key, s_val in sensory_res.get("senses", {}).items():
                if not isinstance(s_val, dict):
                    continue
                tele = s_val.get("telemetry") if isinstance(s_val.get("telemetry"), dict) else {}
                highlights = "; ".join(
                    f"{tk}={tv}" for tk, tv in list(tele.items())[:3]
                ) if tele else "N/A"
                lines.append(f"| {s_val.get('name_en', s_key)} | `{'ACTIVE' if s_val.get('present') else 'INACTIVE'}` | {highlights} |")
            lines.append("")

        # Embedded Neural Inference Assets
        if hybrid_res and isinstance(hybrid_res, dict) and (
            hybrid_res.get("is_hybrid_binary") or hybrid_res.get("embedded_logic_assets_count")
        ):
            lines.append("## 6. Embedded Neural Inference Assets (Hybrid Dissection)\n")
            lines.append("| Asset | Kind | Offset |")
            lines.append("| :--- | :--- | :--- |")
            for f_item in hybrid_res.get("findings", []) or []:
                if not isinstance(f_item, dict):
                    continue
                lines.append(
                    f"| {f_item.get('description', f_item.get('framework', 'AI asset'))} "
                    f"| `{f_item.get('kind', f_item.get('type', 'ASSET'))}` "
                    f"| `{f_item.get('offset', f_item.get('file_offset', 'N/A'))}` |"
                )
            lines.append("")

        # Observed Facts & Recommendations
        facts = summary.get("observed_facts", [])
        if facts:
            lines.append("## 7. Authoritative Observed Facts\n")
            for f in facts:
                lines.append(f"* {f}")
            lines.append("")

        heuristics = summary.get("heuristic_indicators", [])
        if heuristics:
            lines.append("## 8. Heuristic Indicators & Anomalies\n")
            for h in heuristics:
                lines.append(f"* `{h}`")
            lines.append("")

        recs = summary.get("recommended_next_steps", [])
        if recs:
            lines.append("## 9. Recommended Next Diagnostic Actions\n")
            for r in recs:
                lines.append(f"* `{r}`")
            lines.append("")

        return "\n".join(lines)
