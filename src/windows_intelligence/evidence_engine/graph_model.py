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
        props = properties.copy()
        if "properties" in props and isinstance(props["properties"], dict):
            inner_props = props.pop("properties")
            props.update(inner_props)
        node = EvidenceNode(id=node_id, node_type=node_type, label=label, properties=props)
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
        meta = metadata.copy()
        if "metadata" in meta and isinstance(meta["metadata"], dict):
            inner_meta = meta.pop("metadata")
            meta.update(inner_meta)
        edge = EvidenceEdge(source=source_id, target=target_id, relation=relation, metadata=meta)
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


def evaluate_data_flow_crash_causality(
    ghidra_data_flow: Dict[str, Any],
    crash_rca: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Rigorously evaluates the epistemic relationship between Ghidra High P-Code
    data flow slice and Crash RCA telemetry.
    Returns:
        level: 'CAUSALLY_VALIDATED' | 'CAUSAL_HYPOTHESIS' | 'CORRELATED' | 'CO_OCCURRENCE'
        relation: edge relation type
        relation_semantic: semantic classification
        epistemic_confidence: epistemic confidence (0.0 - 1.0)
        weight: graph edge weight
        confidence_rationale: textual explanation of the match or lack thereof
    """
    def _parse_addr(val: Any) -> Optional[int]:
        if val is None:
            return None
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            v = val.strip().lower()
            if v.startswith("0x"):
                try:
                    return int(v, 16)
                except ValueError:
                    return None
            try:
                return int(v)
            except ValueError:
                return None
        return None

    slice_addrs = set()
    slice_tokens = set()

    for s in ghidra_data_flow.get("sinks", []):
        if isinstance(s, dict):
            a = _parse_addr(s.get("address"))
            if a is not None:
                slice_addrs.add(a)
            if s.get("var"):
                slice_tokens.add(str(s["var"]).upper())
            for inp in s.get("inputs", []):
                slice_tokens.add(str(inp).upper())
        elif isinstance(s, str):
            slice_tokens.add(s.upper())

    for s in ghidra_data_flow.get("sources", []):
        if isinstance(s, dict):
            a = _parse_addr(s.get("address"))
            if a is not None:
                slice_addrs.add(a)
            if s.get("var"):
                slice_tokens.add(str(s["var"]).upper())
        elif isinstance(s, str):
            slice_tokens.add(s.upper())

    for op in ghidra_data_flow.get("backward_slice", []):
        if isinstance(op, dict):
            a = _parse_addr(op.get("address"))
            if a is not None:
                slice_addrs.add(a)
            if op.get("output"):
                slice_tokens.add(str(op["output"]).upper())
            for inp in op.get("inputs", []):
                slice_tokens.add(str(inp).upper())
        elif isinstance(op, str):
            slice_tokens.add(op.upper())

    fault_rva = _parse_addr(crash_rca.get("fault_rva") or crash_rca.get("fault_address"))
    fault_va = _parse_addr(crash_rca.get("fault_virtual_address"))
    culprit_reg = str(crash_rca.get("culprit_register") or "").upper().strip()

    reg_families = {
        "EAX": {"EAX", "RAX", "AX", "AL", "AH"},
        "EBX": {"EBX", "RBX", "BX", "BL", "BH"},
        "ECX": {"ECX", "RCX", "CX", "CL", "CH"},
        "EDX": {"EDX", "RDX", "DX", "DL", "DH"},
        "ESI": {"ESI", "RSI", "SI", "SIL"},
        "EDI": {"EDI", "RDI", "DI", "DIL"},
        "ESP": {"ESP", "RSP", "SP", "SPL"},
        "EBP": {"EBP", "RBP", "BP", "BPL"},
        "R8": {"R8", "R8D", "R8W", "R8B"},
        "R9": {"R9", "R9D", "R9W", "R9B"},
        "R10": {"R10", "R10D", "R10W", "R10B"},
        "R11": {"R11", "R11D", "R11W", "R11B"},
        "R12": {"R12", "R12D", "R12W", "R12B"},
        "R13": {"R13", "R13D", "R13W", "R13B"},
        "R14": {"R14", "R14D", "R14W", "R14B"},
        "R15": {"R15", "R15D", "R15W", "R15B"},
    }
    target_reg_set = reg_families.get(culprit_reg, {culprit_reg}) if culprit_reg else set()

    has_exact_address = (
        (fault_rva is not None and fault_rva in slice_addrs) or
        (fault_va is not None and fault_va in slice_addrs)
    )

    has_adjacent_address = False
    if not has_exact_address:
        for a in slice_addrs:
            if (fault_rva is not None and abs(a - fault_rva) <= 64) or (fault_va is not None and abs(a - fault_va) <= 64):
                has_adjacent_address = True
                break

    has_register_overlap = bool(target_reg_set and any(any(r in tok for r in target_reg_set) for tok in slice_tokens))

    fn_name = str(ghidra_data_flow.get("function") or "").lower()
    fault_mod = str(crash_rca.get("fault_module") or "").lower()
    fn_entry = _parse_addr(ghidra_data_flow.get("entry_point"))
    has_function_match = False
    if fn_entry is not None:
        if fault_rva is not None and abs(fault_rva - fn_entry) < 0x2000:
            has_function_match = True
        elif fault_va is not None and abs(fault_va - fn_entry) < 0x2000:
            has_function_match = True
    elif fn_name and fault_mod and (fn_name in fault_mod or fault_mod in fn_name):
        has_function_match = True

    if has_exact_address and has_register_overlap:
        addr_str = hex(fault_rva) if fault_rva is not None else hex(fault_va)
        return {
            "level": "CAUSALLY_VALIDATED",
            "relation": "EXPLAINS_DATA_PROVENANCE",
            "relation_semantic": "CAUSALLY_VALIDATED_FAULT_PATHWAY",
            "epistemic_confidence": 0.95,
            "weight": 0.95,
            "confidence_rationale": (
                f"Deterministic causality: data flow slice sink at {addr_str} directly manipulates "
                f"culprit register {culprit_reg} that caused crash exception."
            ),
        }
    elif has_exact_address or (has_adjacent_address and has_register_overlap):
        return {
            "level": "CAUSAL_HYPOTHESIS",
            "relation": "HYPOTHESIZES_FAULT_INPUT",
            "relation_semantic": "CAUSAL_HYPOTHESIS",
            "epistemic_confidence": 0.75,
            "weight": 0.75,
            "confidence_rationale": (
                f"Causal hypothesis: data flow slice terminates near faulting address or directly touches "
                f"culprit register {culprit_reg} in execution path."
            ),
        }
    elif has_function_match or has_register_overlap:
        return {
            "level": "CORRELATED",
            "relation": "CORRELATES_WITH_FAULT",
            "relation_semantic": "CORRELATED_FUNCTION_CONTEXT",
            "epistemic_confidence": 0.55,
            "weight": 0.55,
            "confidence_rationale": (
                "Correlated context: data flow slice resides in faulting function context, but specific "
                "instruction sink address did not match crash telemetry."
            ),
        }
    else:
        return {
            "level": "CO_OCCURRENCE",
            "relation": "CO_OCCURS_IN_INCIDENT",
            "relation_semantic": "CO_OCCURRENCE",
            "epistemic_confidence": 0.25,
            "weight": 0.25,
            "confidence_rationale": (
                "Co-occurrence only: Ghidra static slice and crash telemetry were both recorded in incident, "
                "but do not share instruction addresses or register operands."
            ),
        }


def fuse_static_dynamic_ghidra(
    pe_forensics: Optional[Dict[str, Any]] = None,
    crash_rca: Optional[Dict[str, Any]] = None,
    ghidra_call_graph: Optional[Dict[str, Any]] = None,
    ghidra_data_flow: Optional[Dict[str, Any]] = None,
    binary_inspection: Optional[Dict[str, Any]] = None,
    signature_intel: Optional[Dict[str, Any]] = None,
    deobfuscation: Optional[Dict[str, Any]] = None,
    ghidra_provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Fuses static PE inspection, PE deep forensics (.pdata, RTTI, PDB),
    digital signature trust intelligence, deobfuscation telemetry,
    MiniDump/Crash RCA, and Ghidra Call-Graph / Data-Flow slices into a
    unified EvidenceGraph.
    """
    graph = EvidenceGraph()
    bin_props: Dict[str, Any] = {}
    bin_label = "target.exe"
    bin_id = "pe:unknown"

    if pe_forensics and pe_forensics.get("status") == "ok":
        bin_id = f"pe:{pe_forensics.get('sha256', 'unknown')[:12]}"
        bin_label = pe_forensics.get("file", bin_label)
        bin_props.update({
            "pdata_functions": pe_forensics.get("pdata_functions", {}).get("total_runtime_functions", 0),
            "rtti_vftables": pe_forensics.get("msvc_rtti", {}).get("vftables_count", 0),
            "pdb_matched": pe_forensics.get("pdb_correlation", {}).get("pdb_verification", {}).get("guid_match", False),
        })

    if binary_inspection and isinstance(binary_inspection, dict):
        if bin_id == "pe:unknown":
            sha = str(binary_inspection.get("sha256") or binary_inspection.get("file_hash") or "inspected")
            bin_id = f"pe:{sha[:12]}"
            bin_label = binary_inspection.get("file_name") or binary_inspection.get("file_path") or bin_label
        bin_props["format"] = binary_inspection.get("format")
        bin_props["entropy"] = binary_inspection.get("overall_entropy") or binary_inspection.get("shannon_entropy")

    if bin_id != "pe:unknown":
        graph.add_node(bin_id, "PE_BINARY", bin_label, properties=bin_props)

    if signature_intel and isinstance(signature_intel, dict):
        trust_stat = signature_intel.get("trust_status", "UNKNOWN")
        sig_id = f"sig:{trust_stat}"
        is_ver = bool(signature_intel.get("is_verified", False))
        graph.add_node(
            sig_id,
            "SIGNATURE_TRUST",
            f"Signature: {trust_stat}",
            properties={
                "evidence_source": "WINDOWS_SIGNATURE_INTELLIGENCE",
                "verification_level": "CRYPTOGRAPHIC_VALIDATION" if is_ver else "CRYPTOGRAPHIC_STRUCTURE_PARSE",
                "signature_present": bool(signature_intel.get("signature_present", False)),
                "is_verified": is_ver,
                "signature_type": signature_intel.get("signature_type", "NONE"),
                "is_whql_certified": bool(signature_intel.get("is_whql_certified", False)),
                "timestamp_status": signature_intel.get("timestamp_status", "UNKNOWN"),
                "expiration_status": signature_intel.get("expiration_status", "UNKNOWN"),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(
                bin_id,
                sig_id,
                "HAS_TRUST_POSTURE",
                metadata={
                    "weight": 0.95 if is_ver else 0.80,
                    "evidence_source": "WINDOWS_SIGNATURE_INTELLIGENCE",
                    "verification_level": "CRYPTOGRAPHIC_VALIDATION" if is_ver else "CRYPTOGRAPHIC_STRUCTURE_PARSE",
                    "relation_semantic": "AUTHENTICODE_TRUST_POSTURE",
                    "epistemic_confidence": 0.95 if is_ver else 0.80,
                    "confidence_rationale": "Direct WinVerifyTrust or ASN.1 structural certificate chain validation.",
                },
            )

    if deobfuscation and isinstance(deobfuscation, dict):
        cff = deobfuscation.get("control_flow_flattening") or {}
        has_cff = bool(cff.get("has_control_flow_flattening", False))
        op_cnt = int(deobfuscation.get("opaque_predicates_detected", 0) or 0)
        if has_cff or op_cnt > 0:
            obf_id = "obf:signals"
            graph.add_node(
                obf_id,
                "OBFUSCATION_SIGNAL",
                f"Obfuscation (CFF={has_cff}, OpaquePreds={op_cnt})",
                properties={
                    "evidence_source": "CONTINUOUS_DEOBFUSCATOR",
                    "verification_level": "HEURISTIC_DISASSEMBLY_PATTERN",
                    "has_control_flow_flattening": has_cff,
                    "opaque_predicates_detected": op_cnt,
                    "dead_instruction_bytes": deobfuscation.get("dead_instruction_bytes", 0),
                },
            )
            if bin_id in graph.nodes:
                graph.add_edge(
                    bin_id,
                    obf_id,
                    "EXHIBITS_OBFUSCATION",
                    metadata={
                        "weight": 0.85,
                        "evidence_source": "CONTINUOUS_DEOBFUSCATOR",
                        "verification_level": "HEURISTIC_DISASSEMBLY_PATTERN",
                        "relation_semantic": "DETECTED_ANTI_ANALYSIS_STRUCTURES",
                        "epistemic_confidence": 0.85,
                        "confidence_rationale": "Algebraic invariant elimination and control-flow flattening dispatcher detection.",
                    },
                )

    if crash_rca:
        exc_code = crash_rca.get("exception_code", "UNKNOWN_EXCEPTION")
        crash_id = f"crash:{exc_code}"
        graph.add_node(
            crash_id,
            "CRASH_EVENT",
            f"{exc_code} ({crash_rca.get('root_cause_classification', 'UNKNOWN')})",
            properties={
                "evidence_source": "CRASH_ROOT_CAUSE_ANALYZER",
                "verification_level": "OBSERVED_CRASH_TELEMETRY",
                "culprit_register": crash_rca.get("culprit_register"),
                "fault_address": crash_rca.get("fault_address"),
                "confidence": crash_rca.get("confidence"),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(
                bin_id,
                crash_id,
                "EXHIBITED_FAULT",
                metadata={
                    "weight": 0.95,
                    "evidence_source": "CRASH_ROOT_CAUSE_ANALYZER",
                    "verification_level": "OBSERVED_CRASH_TELEMETRY",
                    "relation_semantic": "MINIDUMP_EXCEPTION_FAULT",
                    "epistemic_confidence": 0.95,
                    "confidence_rationale": "Hardware exception record and process memory layout at crash instant.",
                },
            )

    if ghidra_call_graph and ghidra_call_graph.get("status") == "ok":
        cg_id = "ghidra:call_graph"
        cg_vlevel = "STATIC_TOPOLOGY_EXTRACTION"
        cg_confidence = 0.90
        cg_rationale = "High P-Code call graph and sensitive Win32 API reachability paths."
        if ghidra_provenance and isinstance(ghidra_provenance, dict):
            if ghidra_provenance.get("status") == "HEURISTIC_NAME_MATCH":
                cg_confidence = 0.60
                cg_vlevel = "HEURISTIC_FILENAME_MATCH"
                cg_rationale = "Call graph loaded under unverified filename heuristic; cryptographic hash missing."
            elif ghidra_provenance.get("status") == "VERIFIED_CRYPTOGRAPHIC_HASH":
                cg_confidence = 0.95
                cg_vlevel = "CRYPTOGRAPHIC_PROVENANCE_VERIFIED"
                cg_rationale = "Cryptographically verified SHA-256 match against target binary."

        graph.add_node(
            cg_id,
            "GHIDRA_CALL_GRAPH",
            f"CallGraph ({ghidra_call_graph.get('functions_indexed', 0)} funcs)",
            properties={
                "evidence_source": "GHIDRA_STATIC_ANALYZER",
                "verification_level": cg_vlevel,
                "call_edges": ghidra_call_graph.get("call_edges_count", 0),
                "indirect_calls": ghidra_call_graph.get("indirect_calls_count", 0),
                "sensitive_apis": len(ghidra_call_graph.get("sensitive_api_reachability", [])),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(
                bin_id,
                cg_id,
                "DECOMPILED_TOPOLOGY",
                metadata={
                    "weight": cg_confidence,
                    "evidence_source": "GHIDRA_STATIC_ANALYZER",
                    "verification_level": cg_vlevel,
                    "relation_semantic": "DISASSEMBLED_CALL_TOPOLOGY",
                    "epistemic_confidence": cg_confidence,
                    "confidence_rationale": cg_rationale,
                },
            )

    if ghidra_data_flow and ghidra_data_flow.get("status") == "ok":
        fn_name = ghidra_data_flow.get("function", "unknown")
        df_id = f"ghidra:slice:{fn_name}"
        graph.add_node(
            df_id,
            "DATA_FLOW_SLICE",
            f"DataFlow Slice: {fn_name}",
            properties={
                "evidence_source": "GHIDRA_STATIC_ANALYZER",
                "verification_level": "STATIC_SSA_SLICE",
                "sources_count": ghidra_data_flow.get("sources_count", 0),
                "sinks_count": ghidra_data_flow.get("sinks_count", 0),
                "slice_depth": len(ghidra_data_flow.get("backward_slice", [])),
            },
        )
        if "ghidra:call_graph" in graph.nodes:
            graph.add_edge(
                "ghidra:call_graph",
                df_id,
                "CONTAINS_SLICE",
                metadata={
                    "weight": 0.90,
                    "evidence_source": "GHIDRA_STATIC_ANALYZER",
                    "verification_level": "STATIC_SSA_SLICE",
                    "relation_semantic": "INTRA_PROCEDURAL_DATA_FLOW",
                    "epistemic_confidence": 0.90,
                    "confidence_rationale": "High P-Code SSA def-use intra-procedural slice.",
                },
            )
        if crash_rca:
            exc_code = crash_rca.get("exception_code", "UNKNOWN_EXCEPTION")
            causality = evaluate_data_flow_crash_causality(ghidra_data_flow, crash_rca)
            graph.add_edge(
                df_id,
                f"crash:{exc_code}",
                causality["relation"],
                metadata={
                    "weight": causality["weight"],
                    "evidence_source": "EVIDENCE_FUSION_ENGINE",
                    "verification_level": causality["level"],
                    "relation_semantic": causality["relation_semantic"],
                    "epistemic_confidence": causality["epistemic_confidence"],
                    "confidence_rationale": causality["confidence_rationale"],
                },
            )

    return {
        "status": "ok",
        "fused_graph": graph.to_dict(),
        "epistemic_classification": "MULTI_SIGNAL_EVIDENCE_FUSION",
    }
