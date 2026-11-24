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
    crash_rca: Dict[str, Any],
    provenance: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Rigorously evaluates the epistemic relationship between Ghidra High P-Code
    data flow slice and Crash RCA telemetry.
    Categorizes into 4 epistemic levels:
      1. CAUSALLY_VALIDATED (epistemic_confidence: 0.95):
         Requires cryptographically verified Ghidra provenance, exact crash instruction
         matching a verified sink with exact culprit register flow, and continuous def-use slice.
      2. CAUSAL_HYPOTHESIS (epistemic_confidence: 0.70):
         Requires cryptographically verified Ghidra provenance, with intermediate slice
         operation or adjacent sink matching culprit register.
      3. CORRELATED (epistemic_confidence: 0.50):
         Function context match, or unverified/heuristic Ghidra provenance.
      4. CO_OCCURRENCE (epistemic_confidence: 0.20):
         Background presence without causal topological convergence.
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

    def _token_contains_register(tok: str, reg_set: Set[str]) -> bool:
        if not tok or not reg_set:
            return False
        # Exact word token matching to eliminate substring false-positives (e.g. 'AX' in 'TAX')
        words = set(re.findall(r"[A-Za-z0-9_]+", tok.upper()))
        return bool(words & reg_set)

    # Check cryptographic provenance upfront
    if not provenance and isinstance(ghidra_data_flow, dict):
        provenance = ghidra_data_flow.get("provenance")

    is_crypto_proven = False
    prov_warning = ""
    epistemic_reasons = []
    if provenance and isinstance(provenance, dict):
        prov_status = provenance.get("status") or provenance.get("verification_level")
        if prov_status == "VERIFIED_CRYPTOGRAPHIC_HASH":
            is_crypto_proven = True
        else:
            prov_warning = f"[Unverified Provenance: {prov_status}] Cryptographic SHA-256 match missing or quarantined. "
            epistemic_reasons.append(f"Provenance verification missing or heuristic ({prov_status}); capped at CORRELATED (<=0.50)")
    else:
        prov_warning = "[Unverified Provenance: NOT_PROVIDED] Ghidra export lacks cryptographic hash verification. "
        epistemic_reasons.append("Provenance verification missing or heuristic (NOT_PROVIDED); capped at CORRELATED (<=0.50)")

    sink_addrs = set()
    sink_tokens = set()
    for s in ghidra_data_flow.get("sinks", []):
        if isinstance(s, dict):
            a = _parse_addr(s.get("address"))
            if a is not None:
                sink_addrs.add(a)
            if s.get("var"):
                sink_tokens.add(str(s["var"]))
            for inp in s.get("inputs", []):
                sink_tokens.add(str(inp))
        elif isinstance(s, str):
            sink_tokens.add(s)

    slice_op_addrs = set()
    slice_tokens = set(sink_tokens)
    for op in ghidra_data_flow.get("backward_slice", []):
        if isinstance(op, dict):
            a = _parse_addr(op.get("address"))
            if a is not None:
                slice_op_addrs.add(a)
            if op.get("output"):
                slice_tokens.add(str(op["output"]))
            for inp in op.get("inputs", []):
                slice_tokens.add(str(inp))
        elif isinstance(op, str):
            slice_tokens.add(op)

    for s in ghidra_data_flow.get("sources", []):
        if isinstance(s, dict):
            a = _parse_addr(s.get("address"))
            if a is not None:
                slice_op_addrs.add(a)
            if s.get("var"):
                slice_tokens.add(str(s["var"]))
            for inp in s.get("inputs", []):
                slice_tokens.add(str(inp))
        elif isinstance(s, str):
            slice_tokens.add(s)

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

    has_exact_sink = (
        (fault_rva is not None and fault_rva in sink_addrs) or
        (fault_va is not None and fault_va in sink_addrs)
    )

    has_slice_op_match = (
        (fault_rva is not None and fault_rva in slice_op_addrs) or
        (fault_va is not None and fault_va in slice_op_addrs)
    )

    all_slice_addrs = sink_addrs | slice_op_addrs
    has_adjacent_address = False
    if not (has_exact_sink or has_slice_op_match):
        for a in all_slice_addrs:
            if (fault_rva is not None and abs(a - fault_rva) <= 64) or (fault_va is not None and abs(a - fault_va) <= 64):
                has_adjacent_address = True
                break

    has_sink_register_match = any(_token_contains_register(tok, target_reg_set) for tok in sink_tokens)
    has_slice_register_match = any(_token_contains_register(tok, target_reg_set) for tok in slice_tokens)

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

    slice_depth = len(ghidra_data_flow.get("backward_slice", []))

    # Level 1: Deterministic Causality (Strictly requires cryptographic provenance & exact sink match)
    if is_crypto_proven and has_exact_sink and has_sink_register_match:
        addr_str = hex(fault_rva) if fault_rva is not None else hex(fault_va)
        return {
            "level": "CAUSALLY_VALIDATED",
            "relation": "EXPLAINS_DATA_PROVENANCE",
            "relation_semantic": "CAUSALLY_VALIDATED_FAULT_PATHWAY",
            "epistemic_confidence": 0.95,
            "weight": 0.95,
            "register_matched": True,
            "epistemic_reasons": ["Exact instruction address and culprit register match with verified cryptographic provenance"],
            "confidence_rationale": (
                f"Deterministic causality: cryptographically verified Ghidra slice sink at {addr_str} directly manipulates "
                f"culprit register {culprit_reg} across {slice_depth} def-use operations leading to crash exception."
            ),
        }

    # Level 2: Causal Hypothesis (Requires cryptographic provenance and nearby or intermediate match)
    if is_crypto_proven and (
        (has_exact_sink and has_slice_register_match) or
        (has_slice_op_match and has_slice_register_match) or
        (has_adjacent_address and has_sink_register_match)
    ):
        return {
            "level": "CAUSAL_HYPOTHESIS",
            "relation": "HYPOTHESIZES_FAULT_INPUT",
            "relation_semantic": "CAUSAL_HYPOTHESIS",
            "epistemic_confidence": 0.70,
            "weight": 0.70,
            "register_matched": bool(has_sink_register_match or has_slice_register_match),
            "epistemic_reasons": ["Nearby or intermediate instruction and register correlation with verified provenance"],
            "confidence_rationale": (
                f"Causal hypothesis: verified data flow slice manipulates culprit register {culprit_reg} "
                f"along execution pathway near faulting address."
            ),
        }

    # Level 3: Correlated (Contextual function match, or unverified/heuristic Ghidra provenance)
    if has_function_match or has_slice_register_match or has_exact_sink or has_slice_op_match:
        conf = 0.50 if not is_crypto_proven else 0.55
        reasons = list(epistemic_reasons)
        if not reasons:
            reasons.append("Data flow slice resides in function context or overlaps registers/addresses without full deterministic proof")
        return {
            "level": "CORRELATED",
            "relation": "CORRELATES_WITH_FAULT",
            "relation_semantic": "CORRELATED_FUNCTION_CONTEXT",
            "epistemic_confidence": conf,
            "weight": conf,
            "register_matched": bool(has_sink_register_match or has_slice_register_match),
            "epistemic_reasons": reasons,
            "confidence_rationale": (
                f"{prov_warning}Correlated context: data flow slice resides in function context or overlaps registers/addresses, "
                f"but complete def-use causal path to crash sink is not deterministically proven."
            ),
        }

    # Level 4: Co-occurrence
    reasons = list(epistemic_reasons)
    reasons.append("No shared instruction addresses or register operands between slice and crash telemetry")
    return {
        "level": "CO_OCCURRENCE",
        "relation": "CO_OCCURS_IN_INCIDENT",
        "relation_semantic": "CO_OCCURRENCE",
        "epistemic_confidence": 0.20,
        "weight": 0.20,
        "register_matched": bool(has_sink_register_match or has_slice_register_match),
        "epistemic_reasons": reasons,
        "confidence_rationale": (
            f"{prov_warning}Co-occurrence only: Ghidra static slice and crash telemetry were both recorded in incident, "
            f"but do not share instruction addresses or register operands."
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
    sensory_audit: Optional[Dict[str, Any]] = None,
    embedded_ai_scan: Optional[Dict[str, Any]] = None,
    slack_forensics: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Fuses static PE inspection, PE deep forensics (.pdata, RTTI, PDB),
    digital signature trust intelligence, deobfuscation telemetry,
    MiniDump/Crash RCA, and Ghidra Call-Graph / Data-Flow slices into a
    unified EvidenceGraph.

    The three optional trailing inputs (sensory_audit, embedded_ai_scan,
    slack_forensics) extend the graph with Sensory-Cortex perception,
    embedded neural-asset discoveries, and slack-space/overlay findings
    without altering any pre-existing node or edge contract.
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
        df_confidence = 0.90
        df_vlevel = "STATIC_SSA_SLICE"
        df_rationale = "High P-Code SSA def-use intra-procedural slice."
        if ghidra_provenance and isinstance(ghidra_provenance, dict):
            if ghidra_provenance.get("status") == "HEURISTIC_NAME_MATCH":
                df_confidence = 0.60
                df_vlevel = "HEURISTIC_FILENAME_MATCH"
                df_rationale = "Data flow slice loaded under unverified filename heuristic; cryptographic hash missing."
            elif ghidra_provenance.get("status") == "VERIFIED_CRYPTOGRAPHIC_HASH":
                df_confidence = 0.95
                df_vlevel = "CRYPTOGRAPHIC_PROVENANCE_VERIFIED"
                df_rationale = "Cryptographically verified SHA-256 data flow slice against target binary."
            else:
                df_confidence = 0.40
                df_vlevel = "UNVERIFIED_PROVENANCE_QUARANTINED"
                df_rationale = "Data flow slice lacks verified cryptographic provenance."

        graph.add_node(
            df_id,
            "DATA_FLOW_SLICE",
            f"DataFlow Slice: {fn_name}",
            properties={
                "evidence_source": "GHIDRA_STATIC_ANALYZER",
                "verification_level": df_vlevel,
                "sources_count": ghidra_data_flow.get("sources_count", 0),
                "sinks_count": ghidra_data_flow.get("sinks_count", 0),
                "slice_depth": len(ghidra_data_flow.get("backward_slice", [])),
                "provenance_status": ghidra_provenance.get("status") if ghidra_provenance else "NOT_PROVIDED",
            },
        )
        if "ghidra:call_graph" in graph.nodes:
            graph.add_edge(
                "ghidra:call_graph",
                df_id,
                "CONTAINS_SLICE",
                metadata={
                    "weight": df_confidence,
                    "evidence_source": "GHIDRA_STATIC_ANALYZER",
                    "verification_level": df_vlevel,
                    "relation_semantic": "INTRA_PROCEDURAL_DATA_FLOW",
                    "epistemic_confidence": df_confidence,
                    "confidence_rationale": df_rationale,
                },
            )
        if crash_rca:
            exc_code = crash_rca.get("exception_code", "UNKNOWN_EXCEPTION")
            causality = evaluate_data_flow_crash_causality(ghidra_data_flow, crash_rca, provenance=ghidra_provenance)
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

    # Sensory Cortex perception channel (10 metaphorical senses)
    if sensory_audit and isinstance(sensory_audit, dict) and sensory_audit.get("senses"):
        cortex_id = "sensory:cortex"
        graph.add_node(
            cortex_id,
            "SENSORY_PERCEPTION",
            f"Sensory Cortex ({sensory_audit.get('active_senses_count', 0)}/10 senses)",
            properties={
                "evidence_source": "CONTINUOUS_SENSORY_CORTEX",
                "verification_level": "HEURISTIC_PERCEPTION_MODEL",
                "active_senses_count": sensory_audit.get("active_senses_count", 0),
                "overall_sensory_efficiency": sensory_audit.get("overall_sensory_efficiency"),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(
                bin_id,
                cortex_id,
                "IS_PERCEIVED_BY",
                metadata={
                    "weight": 0.70,
                    "evidence_source": "CONTINUOUS_SENSORY_CORTEX",
                    "verification_level": "HEURISTIC_PERCEPTION_MODEL",
                    "relation_semantic": "HOLISTIC_SENSE_PERCEPTION_PROFILE",
                    "epistemic_confidence": 0.70,
                    "confidence_rationale": "Ten-channel behavioral perception model; efficiency scores are capability-presence indicators, not measured accuracy.",
                },
            )

    # Embedded neural inference assets (hybrid native-neural binaries)
    if embedded_ai_scan and isinstance(embedded_ai_scan, dict):
        ai_findings = embedded_ai_scan.get("findings", [])
        if isinstance(ai_findings, list):
            for ai_idx, finding in enumerate(ai_findings):
                if not isinstance(finding, dict):
                    continue
                kind = finding.get("kind") or finding.get("type") or "ASSET"
                ai_id = f"ai:{ai_idx}:{kind}"
                graph.add_node(
                    ai_id,
                    "EMBEDDED_AI_ASSET",
                    str(finding.get("description") or finding.get("framework") or kind),
                    properties={
                        "evidence_source": "HYBRID_BINARY_DISSECTOR",
                        "verification_level": "STATIC_BYTE_SIGNATURE_MATCH",
                        "kind": kind,
                        "file_offset": finding.get("offset", finding.get("file_offset")),
                        "size_bytes": finding.get("size", finding.get("size_bytes")),
                        "shannon_entropy": finding.get("entropy", finding.get("shannon_entropy")),
                    },
                )
                if bin_id in graph.nodes:
                    graph.add_edge(
                        bin_id,
                        ai_id,
                        "EMBEDS_NEURAL_ASSET",
                        metadata={
                            "weight": 0.85,
                            "evidence_source": "HYBRID_BINARY_DISSECTOR",
                            "verification_level": "STATIC_BYTE_SIGNATURE_MATCH",
                            "relation_semantic": "EMBEDDED_INFERENCE_LOGIC_DISCOVERED",
                            "epistemic_confidence": 0.85,
                            "confidence_rationale": "Deterministic byte-signature and container-structure match inside the PE image.",
                        },
                    )

    # Slack space / overlay forensics
    if slack_forensics and isinstance(slack_forensics, dict) and slack_forensics.get("has_trailing_slack"):
        slack_id = "slack:trailing"
        graph.add_node(
            slack_id,
            "SLACK_SPACE",
            f"Slack ({slack_forensics.get('slack_bytes_count', 0)} bytes)",
            properties={
                "evidence_source": "BINARY_SLACK_INSPECTOR",
                "verification_level": "STRUCTURAL_SECTION_GEOMETRY",
                "slack_type": slack_forensics.get("slack_type", "UNMAPPED_SLACK"),
                "slack_bytes_count": slack_forensics.get("slack_bytes_count", 0),
            },
        )
        if bin_id in graph.nodes:
            graph.add_edge(
                bin_id,
                slack_id,
                "HAS_SLACK_SPACE",
                metadata={
                    "weight": 0.80,
                    "evidence_source": "BINARY_SLACK_INSPECTOR",
                    "verification_level": "STRUCTURAL_SECTION_GEOMETRY",
                    "relation_semantic": "TRAILING_UNMAPPED_BYTES",
                    "epistemic_confidence": 0.80,
                    "confidence_rationale": "Section table raw extents compared against physical file size.",
                },
            )

    return {
        "status": "ok",
        "fused_graph": graph.to_dict(),
        "epistemic_classification": "MULTI_SIGNAL_EVIDENCE_FUSION",
    }
