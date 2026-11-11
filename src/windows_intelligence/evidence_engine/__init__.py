# -*- coding: utf-8 -*-
"""
Bintra Evidence Graph & Causality Synthesis Engine.
Binds static binary structures (sections, RVAs, imports, mitigations),
Ghidra High P-Code AST & CFG topologies, host OS & registry policies,
PnP hardware health, and empirical crash telemetry into a unified causality graph:
G = (V, E)
"""

from .graph_model import EvidenceGraph, EvidenceNode, EvidenceEdge
from .causality_synthesizer import CausalitySynthesizer

__all__ = [
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceEdge",
    "CausalitySynthesizer",
]
