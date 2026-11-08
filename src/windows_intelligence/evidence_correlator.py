# -*- coding: utf-8 -*-
"""
Failure Evidence Correlation Engine.
Delegates to the unified CausalitySynthesizer engine to ensure a single, authoritative
source of truth for root-cause diagnosis, evidence graph construction, and failure dossiers.
Maintains full backward-compatibility for all existing CLI, MCP, and test call-sites.
"""

from typing import Dict, Any, Optional
from .evidence_engine.causality_synthesizer import CausalitySynthesizer


class DiagnosticEvidenceCorrelator:
    """
    Unified Failure Evidence Correlation Gateway.
    Delegates directly to CausalitySynthesizer, providing a single consolidated
    diagnostic engine across REA-Neural.
    """

    @classmethod
    def correlate(
        cls,
        binary_path: str,
        crash_record: Optional[Dict[str, Any]] = None,
        ghidra_export: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Delegates failure evidence correlation directly to CausalitySynthesizer."""
        return CausalitySynthesizer.synthesize_dossier(
            binary_path=binary_path,
            crash_record=crash_record,
            ghidra_export=ghidra_export
        )

    @classmethod
    def format_markdown(cls, dossier: Dict[str, Any]) -> str:
        """Delegates executive Markdown formatting directly to CausalitySynthesizer."""
        return CausalitySynthesizer.format_markdown(dossier)


# Backward compatibility alias
WindowsEvidenceCorrelator = DiagnosticEvidenceCorrelator
