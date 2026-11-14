import re
# -*- coding: utf-8 -*-
"""
Formal Evidence Graph Data Structures for Bintra.
Models the system and binary diagnostic space as a directed multigraph G = (V, E)
and provides Mermaid diagram rendering and causal path resolution.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from collections import deque


@dataclass
class EvidenceNode:
    """A diagnostic entity within the Evidence Graph."""
    id: str
    node_type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.node_type,
            "label": self.label,
            "properties": self.properties
        }


@dataclass
class EvidenceEdge:
    """A causal or structural relationship between two diagnostic entities."""
    source: str
    target: str
    relation: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "metadata": self.metadata
        }


class EvidenceGraph:
    """
    Directed Causality Graph G = (V, E).
    Represents relationships between target executable, sections, imports,
    Ghidra AST functions/blocks, host OS, PnP devices, drivers, and crash telemetry.
    """

    def __init__(self):
        self.nodes: Dict[str, EvidenceNode] = {}
        self.edges: List[EvidenceEdge] = []
        self._adj: Dict[str, List[EvidenceEdge]] = {}
        self._rev_adj: Dict[str, List[EvidenceEdge]] = {}

    def add_node(self, node_id: str, node_type: str, label: str, **properties) -> EvidenceNode:
        """Adds or updates a node in the graph."""
        node = EvidenceNode(id=node_id, node_type=node_type, label=label, properties=properties)
        self.nodes[node_id] = node
        if node_id not in self._adj:
            self._adj[node_id] = []
        if node_id not in self._rev_adj:
            self._rev_adj[node_id] = []
        return node

    def add_edge(self, source_id: str, target_id: str, relation: str, **metadata) -> Optional[EvidenceEdge]:
        """Creates a directed causal relationship edge."""
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        edge = EvidenceEdge(source=source_id, target=target_id, relation=relation, metadata=metadata)
        self.edges.append(edge)
        self._adj[source_id].append(edge)
        self._rev_adj[target_id].append(edge)
        return edge

    def get_node(self, node_id: str) -> Optional[EvidenceNode]:
        return self.nodes.get(node_id)

    def get_edges_from(self, source_id: str) -> List[EvidenceEdge]:
        return self._adj.get(source_id, [])

    def get_edges_to(self, target_id: str) -> List[EvidenceEdge]:
        return self._rev_adj.get(target_id, [])

    def find_causal_path(self, start_id: str, end_id: str) -> List[str]:
        """Finds the shortest directed path from start_id to end_id via BFS."""
        if start_id not in self.nodes or end_id not in self.nodes:
            return []

        queue = deque([[start_id]])
        visited: Set[str] = {start_id}

        while queue:
            path = queue.popleft()
            curr = path[-1]
            if curr == end_id:
                return path

            for edge in self._adj.get(curr, []):
                nxt = edge.target
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(path + [nxt])

        return []

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the graph into a JSON-serializable dictionary."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges]
        }

    def to_mermaid(self) -> str:
        """
        Renders the Evidence Graph as a Mermaid flowchart diagram.
        Applies distinctive shapes and styling for crash nodes, Ghidra functions, and hardware.
        """
        lines = ["flowchart TD"]

        # 1. Define nodes with clean sanitized IDs and shapes
        def _sanitize(nid: str) -> str:
            return re.sub(r"[^A-Za-z0-9_]", "_", nid)

        for n in self.nodes.values():
            s_id = _sanitize(n.id)
            clean_label = n.label.replace('"', "'")

            if n.node_type == "CRASH_TELEMETRY":
                lines.append(f'    {s_id}{{"CRASH: {clean_label}"}}:::crashClass')
            elif n.node_type == "ACCESS_VIOLATION_ROOT":
                lines.append(f'    {s_id}["ROOT: {clean_label}"]:::rootClass')
            elif n.node_type == "GHIDRA_FUNCTION":
                lines.append(f'    {s_id}(["FUNC: {clean_label}"]):::funcClass')
            elif n.node_type == "PE_SECTION":
                lines.append(f'    {s_id}[["SEC: {clean_label}"]]:::secClass')
            elif n.node_type == "HARDWARE_DEVICE":
                lines.append(f'    {s_id}[/"HW: {clean_label}"/]:::hwClass')
            elif n.node_type == "KERNEL_DRIVER":
                lines.append(f'    {s_id}[/"DRV: {clean_label}"/]:::drvClass')
            else:
                lines.append(f'    {s_id}["{clean_label}"]')

        # 2. Define edges
        for e in self.edges:
            s_src = _sanitize(e.source)
            s_tgt = _sanitize(e.target)
            rel_label = e.relation.replace("_", " ")
            lines.append(f'    {s_src} -->|"{rel_label}"| {s_tgt}')

        # 3. Class definitions for styling
        lines.append("")
        lines.append("    classDef crashClass fill:#f87171,stroke:#b91c1c,stroke-width:2px,color:#fff;")
        lines.append("    classDef rootClass fill:#fbbf24,stroke:#d97706,stroke-width:2px,color:#000;")
        lines.append("    classDef funcClass fill:#60a5fa,stroke:#1d4ed8,stroke-width:2px,color:#fff;")
        lines.append("    classDef secClass fill:#a78bfa,stroke:#6d28d9,stroke-width:1px,color:#fff;")
        lines.append("    classDef hwClass fill:#34d399,stroke:#047857,stroke-width:1px,color:#fff;")
        lines.append("    classDef drvClass fill:#38bdf8,stroke:#0284c7,stroke-width:1px,color:#fff;")

        return "\n".join(lines)


def fuse_static_dynamic_ghidra(
    pe_forensics: Optional[Dict[str, Any]] = None,
    crash_rca: Optional[Dict[str, Any]] = None,
    ghidra_call_graph: Optional[Dict[str, Any]] = None,
    ghidra_data_flow: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Fuses static PE deep forensics (.pdata, RTTI, PDB), MiniDump/Crash RCA,
    and Ghidra Call-Graph / Data-Flow slices into a unified EvidenceGraph.
    """
    graph = EvidenceGraph()
    if pe_forensics and pe_forensics.get("status") == "ok":
        bin_id = f"pe:{pe_forensics.get('sha256', 'unknown')[:12]}"
        graph.add_node(
            bin_id,
            "PE_BINARY",
            pe_forensics.get("file", "target.exe"),
            properties={
                "pdata_functions": pe_forensics.get("pdata_functions", {}).get("total_runtime_functions", 0),
                "rtti_vftables": pe_forensics.get("msvc_rtti", {}).get("vftables_count", 0),
                "pdb_matched": pe_forensics.get("pdb_correlation", {}).get("pdb_verification", {}).get("guid_match", False),
            },
        )
    else:
        bin_id = "pe:unknown"

    if crash_rca:
        exc_code = crash_rca.get("exception_code", "UNKNOWN_EXCEPTION")
        crash_id = f"crash:{exc_code}"
        graph.add_node(
            crash_id,
            "CRASH_EVENT",
            f"{exc_code} ({crash_rca.get('root_cause_classification', 'UNKNOWN')})",
            properties={
                "culprit_register": crash_rca.get("culprit_register"),
                "fault_address": crash_rca.get("fault_address"),
                "confidence": crash_rca.get("confidence"),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(bin_id, crash_id, "EXHIBITED_FAULT", metadata={"weight": 0.95})

    if ghidra_call_graph and ghidra_call_graph.get("status") == "ok":
        cg_id = "ghidra:call_graph"
        graph.add_node(
            cg_id,
            "GHIDRA_CALL_GRAPH",
            f"CallGraph ({ghidra_call_graph.get('functions_indexed', 0)} funcs)",
            properties={
                "call_edges": ghidra_call_graph.get("call_edges_count", 0),
                "indirect_calls": ghidra_call_graph.get("indirect_calls_count", 0),
                "sensitive_apis": len(ghidra_call_graph.get("sensitive_api_reachability", [])),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(bin_id, cg_id, "DECOMPILED_TOPOLOGY", metadata={"weight": 0.9})

    if ghidra_data_flow and ghidra_data_flow.get("status") == "ok":
        fn_name = ghidra_data_flow.get("function", "unknown")
        df_id = f"ghidra:slice:{fn_name}"
        graph.add_node(
            df_id,
            "DATA_FLOW_SLICE",
            f"DataFlow Slice: {fn_name}",
            properties={
                "sources_count": ghidra_data_flow.get("sources_count", 0),
                "sinks_count": ghidra_data_flow.get("sinks_count", 0),
                "slice_depth": len(ghidra_data_flow.get("backward_slice", [])),
            },
        )
        if "ghidra:call_graph" in graph.nodes:
            graph.add_edge("ghidra:call_graph", df_id, "CONTAINS_SLICE", metadata={"weight": 0.9})
        if crash_rca:
            exc_code = crash_rca.get("exception_code", "UNKNOWN_EXCEPTION")
            graph.add_edge(df_id, f"crash:{exc_code}", "EXPLAINS_DATA_PROVENANCE", metadata={"weight": 0.85})

    return {
        "status": "ok",
        "fused_graph": graph.to_dict(),
        "epistemic_classification": "MULTI_SIGNAL_EVIDENCE_FUSION",
    }
