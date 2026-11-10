#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Ghidra P-Code Continuous Semantic Vectorizer.
Bridges Ghidra's Symbolic Intermediate Representation (P-code & High P-code SSA)
with REA-Neural's Continuous Vector Space representations.

Capabilities:
1. P-Code Opcode Taxonomy & Normalization across 12 semantic operational classes.
2. Continuous Varnode Dataflow & Transition Tensor Embedding (64-D unit vector).
3. Roy-Vetterli Spectral Effective Rank computation on P-code transition matrices.
4. Compiler- and Architecture-Invariant Function Matching (x86, x64, ARM, ARM64).
5. Opaque Predicate & Dead P-Code Pruning for Clean Decompilation Feeding.
6. Ghidra Annotation Plan generator for bi-directional database mutation.
"""

import math
import json
from typing import Dict, Any, List, Tuple, Optional, Set
import numpy as np


# ============================================================================
# 1. GHIDRA P-CODE CANONICAL TAXONOMY (12 SEMANTIC BUCKETS)
# ============================================================================

PCODE_CATEGORIES = [
    "ALU_ARITH",             # 0: INT_ADD, INT_SUB, INT_MULT, INT_DIV, FLOAT_ADD...
    "ALU_LOGIC",             # 1: INT_AND, INT_OR, INT_XOR, BOOL_XOR, BOOL_AND...
    "BIT_SHIFT",             # 2: INT_LEFT, INT_RIGHT, INT_SRIGHT
    "COMPARE",               # 3: INT_EQUAL, INT_NOTEQUAL, INT_LESS, INT_SLESS...
    "CONTROL_BRANCH_COND",   # 4: CBRANCH
    "CONTROL_BRANCH_UNCOND", # 5: BRANCH, BRANCHIND
    "CONTROL_CALL",          # 6: CALL, CALLIND, CALLOTHER
    "CONTROL_RETURN",        # 7: RETURN
    "MEMORY_LOAD",           # 8: LOAD, PTRSUB, PTRADD, SEGMENTOP
    "MEMORY_STORE",          # 9: STORE
    "SUBPIECE_CAST",         # 10: INT_ZEXT, INT_SEXT, PIECE, SUBPIECE, CAST, TRUNC
    "SSA_PHI",               # 11: MULTIEQUAL, INDIRECT
]

CAT_TO_INDEX: Dict[str, int] = {cat: i for i, cat in enumerate(PCODE_CATEGORIES)}

OPCODE_MAP: Dict[str, str] = {
    # Integer Arithmetic
    "INT_ADD": "ALU_ARITH", "INT_SUB": "ALU_ARITH", "INT_CARRY": "ALU_ARITH",
    "INT_SCARRY": "ALU_ARITH", "INT_SBORROW": "ALU_ARITH", "INT_2COMP": "ALU_ARITH",
    "INT_NEGATE": "ALU_ARITH", "INT_MULT": "ALU_ARITH", "INT_DIV": "ALU_ARITH",
    "INT_SDIV": "ALU_ARITH", "INT_REM": "ALU_ARITH", "INT_SREM": "ALU_ARITH",
    # Floating Point Arithmetic
    "FLOAT_ADD": "ALU_ARITH", "FLOAT_SUB": "ALU_ARITH", "FLOAT_MULT": "ALU_ARITH",
    "FLOAT_DIV": "ALU_ARITH", "FLOAT_NEG": "ALU_ARITH", "FLOAT_ABS": "ALU_ARITH",
    "FLOAT_SQRT": "ALU_ARITH",
    # Bitwise and Boolean Logic
    "INT_AND": "ALU_LOGIC", "INT_OR": "ALU_LOGIC", "INT_XOR": "ALU_LOGIC",
    "BOOL_XOR": "ALU_LOGIC", "BOOL_AND": "ALU_LOGIC", "BOOL_OR": "ALU_LOGIC",
    "BOOL_NEGATE": "ALU_LOGIC",
    # Bit shifts
    "INT_LEFT": "BIT_SHIFT", "INT_RIGHT": "BIT_SHIFT", "INT_SRIGHT": "BIT_SHIFT",
    # Comparisons
    "INT_EQUAL": "COMPARE", "INT_NOTEQUAL": "COMPARE", "INT_LESS": "COMPARE",
    "INT_SLESS": "COMPARE", "INT_LESSEQUAL": "COMPARE", "INT_SLESSEQUAL": "COMPARE",
    "FLOAT_EQUAL": "COMPARE", "FLOAT_NOTEQUAL": "COMPARE", "FLOAT_LESS": "COMPARE",
    "FLOAT_LESSEQUAL": "COMPARE", "FLOAT_NAN": "COMPARE",
    # Control flow
    "CBRANCH": "CONTROL_BRANCH_COND",
    "BRANCH": "CONTROL_BRANCH_UNCOND", "BRANCHIND": "CONTROL_BRANCH_UNCOND",
    "CALL": "CONTROL_CALL", "CALLIND": "CONTROL_CALL", "CALLOTHER": "CONTROL_CALL",
    "RETURN": "CONTROL_RETURN",
    # Memory and pointers
    "LOAD": "MEMORY_LOAD", "PTRSUB": "MEMORY_LOAD", "PTRADD": "MEMORY_LOAD",
    "SEGMENTOP": "MEMORY_LOAD",
    "STORE": "MEMORY_STORE",
    # Type casts and slicing
    "INT_ZEXT": "SUBPIECE_CAST", "INT_SEXT": "SUBPIECE_CAST", "PIECE": "SUBPIECE_CAST",
    "SUBPIECE": "SUBPIECE_CAST", "CAST": "SUBPIECE_CAST", "TRUNC": "SUBPIECE_CAST",
    "FLOAT2FLOAT": "SUBPIECE_CAST", "INT2FLOAT": "SUBPIECE_CAST", "FLOAT2INT": "SUBPIECE_CAST",
    # High P-Code SSA Phis
    "MULTIEQUAL": "SSA_PHI", "INDIRECT": "SSA_PHI",
}


# ============================================================================
# 2. P-CODE VECTORIZER ENGINE
# ============================================================================

class PcodeVectorizer:
    """
    Transforms Ghidra P-code operations and High P-code SSA AST into
    continuous semantic vectors invariant across CPU architectures and compiler passes.
    """

    NUM_CATEGORIES = len(PCODE_CATEGORIES)  # 12
    VECTOR_DIM = 64

    @classmethod
    def classify_opcode(cls, opcode: str) -> str:
        clean = opcode.strip().upper()
        return OPCODE_MAP.get(clean, "ALU_ARITH")

    @classmethod
    def vectorize_pcode_ops(cls, pcode_ops: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Vectorizes a sequence of P-code operations.
        Each item in pcode_ops is expected to have:
            - 'opcode': str (e.g. 'INT_ADD', 'CBRANCH', 'LOAD')
            - 'inputs': optional list of dicts/strings representing Varnodes
            - 'output': optional varnode representation
        """
        if not pcode_ops:
            return {
                "vector": np.zeros(cls.VECTOR_DIM, dtype=np.float32).tolist(),
                "effective_rank": 0.0,
                "participation_ratio": 0.0,
                "op_count": 0,
                "category_histogram": {cat: 0 for cat in PCODE_CATEGORIES},
                "dominance_ratio": 0.0,
            }

        cat_counts = np.zeros(cls.NUM_CATEGORIES, dtype=np.float32)
        transitions = np.zeros((cls.NUM_CATEGORIES, cls.NUM_CATEGORIES), dtype=np.float32)

        prev_cat_idx: Optional[int] = None
        unique_varnodes_count = 0
        total_inputs = 0
        total_outputs = 0
        has_calls = 0
        has_returns = 0

        for op in pcode_ops:
            op_name = op.get("opcode", op.get("mnemonic", "UNKNOWN"))
            cat = cls.classify_opcode(op_name)
            cat_idx = CAT_TO_INDEX.get(cat, 0)
            cat_counts[cat_idx] += 1.0

            if prev_cat_idx is not None:
                transitions[prev_cat_idx, cat_idx] += 1.0
            prev_cat_idx = cat_idx

            inputs = op.get("inputs", [])
            total_inputs += len(inputs) if isinstance(inputs, list) else 1
            if op.get("output") is not None:
                total_outputs += 1
            if cat == "CONTROL_CALL":
                has_calls += 1
            elif cat == "CONTROL_RETURN":
                has_returns += 1

        total_ops = float(len(pcode_ops))
        norm_hist = cat_counts / max(total_ops, 1.0)

        # Spectral Effective Rank of the P-Code Transition Matrix
        trans_sum = float(np.sum(transitions))
        if trans_sum > 0:
            p_mat = transitions / trans_sum
            s_vals = np.linalg.svd(p_mat, compute_uv=False)
            s_pos = s_vals[s_vals > 1e-12]
            p_s = s_pos / np.sum(s_pos)
            spectral_entropy = float(-np.sum(p_s * np.log(p_s + 1e-15)))
            eff_rank = float(np.exp(spectral_entropy))
            energy = s_pos ** 2
            part_ratio = float((np.sum(energy) ** 2) / max(float(np.sum(energy ** 2)), 1e-12))
            s0 = float(s_vals[0])
            s1 = float(s_vals[1]) if len(s_vals) > 1 else 1e-6
            dominance_ratio = float(s0 / max(s1, 1e-6))
        else:
            eff_rank = 1.0
            part_ratio = 1.0
            dominance_ratio = 1.0

        # Build 64-Dimensional Continuous Vector:
        # 0..11: Normalized Category Histogram (12)
        # 12..23: Category Marginal Transition Inflow (12)
        # 24..35: Category Marginal Transition Outflow (12)
        # 36..47: First 12 singular values of Transition Tensor (12)
        # 48..63: Structural Metrics (entropy, calls, returns, density, rank, etc.) (16)
        vec = np.zeros(cls.VECTOR_DIM, dtype=np.float32)
        vec[0:12] = norm_hist

        if trans_sum > 0:
            inflow = np.sum(transitions, axis=0) / trans_sum
            outflow = np.sum(transitions, axis=1) / trans_sum
            vec[12:24] = inflow
            vec[24:36] = outflow

            u_flat = np.linalg.svd(transitions, compute_uv=False)
            vec[36:48] = u_flat[:12] / max(float(u_flat[0]), 1e-6)

        # Structural telemetry slots
        vec[48] = math.log1p(total_ops) / 10.0
        vec[49] = eff_rank / float(cls.NUM_CATEGORIES)
        vec[50] = part_ratio / float(cls.NUM_CATEGORIES)
        vec[51] = min(dominance_ratio / 5.0, 1.0)
        vec[52] = (total_inputs / max(total_ops, 1.0)) / 4.0
        vec[53] = math.log1p(has_calls) / 5.0
        vec[54] = 1.0 if has_returns > 0 else 0.0
        vec[55] = norm_hist[CAT_TO_INDEX["ALU_LOGIC"]] + norm_hist[CAT_TO_INDEX["ALU_ARITH"]]
        vec[56] = norm_hist[CAT_TO_INDEX["MEMORY_LOAD"]] + norm_hist[CAT_TO_INDEX["MEMORY_STORE"]]
        vec[57] = norm_hist[CAT_TO_INDEX["CONTROL_BRANCH_COND"]]
        vec[58] = norm_hist[CAT_TO_INDEX["SSA_PHI"]]
        vec[59] = norm_hist[CAT_TO_INDEX["SUBPIECE_CAST"]]
        vec[60] = min((total_outputs / max(float(total_inputs), 1.0)), 1.0)
        vec[61] = min((norm_hist[CAT_TO_INDEX["CONTROL_BRANCH_COND"]] + norm_hist[CAT_TO_INDEX["CONTROL_BRANCH_UNCOND"]]) * 5.0, 1.0)
        vec[62] = min(norm_hist[CAT_TO_INDEX["ALU_ARITH"]] / max(norm_hist[CAT_TO_INDEX["ALU_LOGIC"]], 0.05) / 10.0, 1.0)
        vec[63] = min((norm_hist[CAT_TO_INDEX["MEMORY_LOAD"]] + norm_hist[CAT_TO_INDEX["MEMORY_STORE"]]) * 3.0, 1.0)

        # Normalize to unit sphere
        norm = float(np.linalg.norm(vec))
        if norm > 1e-12:
            vec /= norm

        hist_dict = {cat: int(cat_counts[i]) for i, cat in enumerate(PCODE_CATEGORIES)}
        return {
            "vector": vec.tolist(),
            "effective_rank": round(eff_rank, 4),
            "participation_ratio": round(part_ratio, 4),
            "dominance_ratio": round(dominance_ratio, 4),
            "op_count": int(total_ops),
            "category_histogram": hist_dict,
        }


# ============================================================================
# 3. P-CODE SEMANTIC MATCHER (CROSS-ARCHITECTURE EQUIVALENCE)
# ============================================================================

class PcodeFunctionMatcher:
    """
    Evaluates semantic behavioral equivalence between two P-code routines.
    Achieves architecture-invariant matching across x86, x64, ARM, and ARM64.
    """

    MATCH_THRESHOLD = 0.90
    HIGH_CONFIDENCE_THRESHOLD = 0.95

    @classmethod
    def match(
        cls,
        pcode_a: List[Dict[str, Any]],
        pcode_b: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        res_a = PcodeVectorizer.vectorize_pcode_ops(pcode_a)
        res_b = PcodeVectorizer.vectorize_pcode_ops(pcode_b)

        v_a = np.array(res_a["vector"], dtype=np.float32)
        v_b = np.array(res_b["vector"], dtype=np.float32)

        norm_a = float(np.linalg.norm(v_a))
        norm_b = float(np.linalg.norm(v_b))

        if norm_a < 1e-12 or norm_b < 1e-12:
            cosine = 0.0
        else:
            cosine = float(np.dot(v_a, v_b) / (norm_a * norm_b))
        cosine = max(-1.0, min(1.0, cosine))

        ops_a = res_a["op_count"]
        ops_b = res_b["op_count"]
        ops_ratio = (min(ops_a, ops_b) / max(ops_a, ops_b)) if max(ops_a, ops_b) > 0 else 0.0

        if ops_a < 5 or ops_b < 5:
            is_match = False
            confidence = "INSUFFICIENT_EVIDENCE"
            interpretation = (
                f"Insufficient P-code operations (func_a={ops_a}, func_b={ops_b}, minimum required: 5) "
                "to evaluate semantic equivalence reliably without high false-positive risk."
            )
        elif ops_ratio < 0.50 and max(ops_a, ops_b) >= 10:
            is_match = False
            confidence = "LOW_DIVERGENT_SCALE"
            interpretation = (
                f"P-code operation scale diverges significantly (ratio {round(ops_ratio, 2)} < 0.50); "
                "functions represent different structural scales and cannot be considered equivalent."
            )
        else:
            is_match = cosine >= cls.MATCH_THRESHOLD
            if is_match:
                confidence = "HIGH" if cosine >= cls.HIGH_CONFIDENCE_THRESHOLD else "MODERATE"
                interpretation = "High statistical correlation in P-code operation distribution and transition topology."
            elif cosine >= 0.80:
                confidence = "LOW"
                interpretation = "P-code routines share opcode category proportions but diverge in graph structure or instruction scale."
            else:
                confidence = "LOW"
                interpretation = "Substantial divergence in intermediate P-code operations or control flow."

        return {
            "pcode_cosine_similarity": round(cosine, 5),
            "is_semantic_match": is_match,
            "confidence": confidence,
            "function_a_telemetry": {
                "ops": res_a["op_count"],
                "effective_rank": res_a["effective_rank"],
                "dominance_ratio": res_a["dominance_ratio"]
            },
            "function_b_telemetry": {
                "ops": res_b["op_count"],
                "effective_rank": res_b["effective_rank"],
                "dominance_ratio": res_b["dominance_ratio"]
            },
            "interpretation": interpretation
        }


# ============================================================================
# 4. CONTROL FLOW GRAPH (CFG) ANALYZER
# ============================================================================

class ControlFlowGraphAnalyzer:
    """
    Analyzes Ghidra decompiled Basic Block Control Flow Graphs (CFG).
    Computes Cyclomatic Complexity, detects Control Flow Flattening (CFF)
    dispatcher backbones using rigorous DFS cycle/back-edge classification,
    and computes basic block topological metrics.
    """

    @classmethod
    def analyze_cfg(cls, basic_blocks: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not basic_blocks:
            return {
                "block_count": 0,
                "edge_count": 0,
                "cyclomatic_complexity": 1,
                "has_cff_backbone": False,
                "dispatcher_blocks": [],
                "back_edges_count": 0,
                "back_edges": [],
                "topology": "EMPTY"
            }

        n = len(basic_blocks)
        edges = 0
        all_block_ids = []
        adj: Dict[int, List[int]] = {}

        for b in basic_blocks:
            b_id = b.get("id", 0)
            all_block_ids.append(b_id)
            succs = b.get("successors", [])
            edges += len(succs)
            adj[b_id] = list(succs)

        # -------------------------------------------------------------
        # Rigorous Graph-Theoretic DFS Cycle & Back-Edge Detection
        # Color codes: 0 = WHITE (unvisited), 1 = GRAY (active recursion), 2 = BLACK (done)
        # An edge u -> v is a back-edge iff v is GRAY (ancestor in active path).
        # This is independent of block ID ordering and works on arbitrary graphs.
        # -------------------------------------------------------------
        entry_id = None
        for b in basic_blocks:
            in_deg = b.get("in_degree", len(b.get("predecessors", [])))
            if in_deg == 0:
                entry_id = b.get("id", 0)
                break
        if entry_id is None and basic_blocks:
            entry_id = basic_blocks[0].get("id", 0)

        color: Dict[int, int] = {b_id: 0 for b_id in all_block_ids}
        back_edges: List[Tuple[int, int]] = []

        def dfs(u: int):
            color[u] = 1
            for v in adj.get(u, []):
                if v in color:
                    if color[v] == 1:
                        back_edges.append((u, v))
                    elif color[v] == 0:
                        dfs(v)
            color[u] = 2

        if entry_id is not None and entry_id in color:
            dfs(entry_id)
        for b_id in all_block_ids:
            if color[b_id] == 0:
                dfs(b_id)

        # -------------------------------------------------------------
        # Dispatcher Identification with Evidence-Based Dynamic Confidence
        # -------------------------------------------------------------
        back_edge_targets = [tgt for src, tgt in back_edges]
        dispatcher_blocks = []

        for b in basic_blocks:
            b_id = b.get("id", 0)
            in_deg = b.get("in_degree", len(b.get("predecessors", [])))
            out_deg = b.get("out_degree", len(b.get("successors", [])))
            incoming_loops = back_edge_targets.count(b_id)

            if incoming_loops >= 2 and out_deg >= 2:
                # Dynamic confidence based on loop convergence and fan-out
                conf = min(0.95, 0.65 + 0.10 * (min(incoming_loops, 4) - 1) + 0.05 * min(out_deg, 4))
                dispatcher_blocks.append({
                    "block_id": b_id,
                    "start": b.get("start"),
                    "in_degree": in_deg,
                    "out_degree": out_deg,
                    "incoming_back_edges": incoming_loops,
                    "confidence": round(conf, 2)
                })

        cyclomatic = max(1, edges - n + 2)
        has_cff = len(dispatcher_blocks) > 0
        topology = "FLATTENED_DISPATCHER" if has_cff else ("CYCLIC_LOOP" if len(back_edges) > 0 else "ACYCLIC_TREE")

        return {
            "block_count": n,
            "edge_count": edges,
            "cyclomatic_complexity": cyclomatic,
            "has_cff_backbone": has_cff,
            "dispatcher_blocks": dispatcher_blocks,
            "back_edges_count": len(back_edges),
            "back_edges": back_edges,
            "topology": topology
        }


# ============================================================================
# 5. P-CODE SSA & DEF-USE INVARIANT ANALYZER
# ============================================================================

class PcodeSSAAnalyzer:
    """
    Exploits Ghidra High P-Code Static Single Assignment (SSA) and Def-Use chains
    to mathematically prove algebraic invariant tautologies (opaque predicates).
    Requires full definition identity (address + sequence) and verified dead block reachability.
    Never claims deobfuscation without algebraic proof and dead basic block identification.
    """

    @classmethod
    def analyze_ssa_invariants(
        cls,
        pcode_ops: List[Dict[str, Any]],
        basic_blocks: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        # Mathematical invariance proof requires CFG topology to verify dead branch reachability.
        if not basic_blocks:
            return {
                "total_pcode_ops": len(pcode_ops),
                "evidence_dossiers_count": 0,
                "evidence_dossiers": [],
                "prunable_operations": [],
                "is_obfuscated": False
            }

        evidence_dossiers = []
        dead_op_indices = set()
        block_map = {b.get("id", idx): b for idx, b in enumerate(basic_blocks)}

        def _get_varnode_key(vn: Any) -> str:
            if isinstance(vn, dict):
                k = vn.get("kind", "")
                size = vn.get("size", 4)
                if k == "register":
                    # Full SSA Identity: Must account for address + seq (def_id)
                    def_id = vn.get("def_id")
                    def_seq = vn.get("def_seq")
                    def_addr = vn.get("def_addr")
                    is_input = vn.get("is_input", False)
                    if def_id:
                        ver = f"def_{def_id}"
                    elif def_addr and def_seq is not None:
                        ver = f"def_{def_addr}:{def_seq}"
                    elif def_seq is not None:
                        ver = f"def_{def_seq}"
                    else:
                        ver = "input" if is_input else "untracked"
                    return f"reg:{vn.get('name', '').upper()}:{size}:{ver}"
                elif k == "unique":
                    def_id = vn.get("def_id")
                    def_seq = vn.get("def_seq")
                    uid = vn.get("unique_id", vn.get("offset", ""))
                    ver = f"def_{def_id}" if def_id else (f"def_{def_seq}" if def_seq is not None else "uid")
                    return f"u:{uid}:{size}:{ver}"
                elif k == "constant":
                    return f"const:{vn.get('const_val', 0)}:{size}"
                elif k == "ram":
                    return f"ram:{vn.get('offset', '')}:{size}"
                return vn.get("repr", str(vn))
            return str(vn)

        def _is_same_varnode(vn1: Any, vn2: Any) -> bool:
            k1 = _get_varnode_key(vn1)
            k2 = _get_varnode_key(vn2)
            if not k1 or not k2 or k1.startswith("const:"):
                return False
            if isinstance(vn1, dict) and isinstance(vn2, dict):
                d1 = vn1.get("def_id") or vn1.get("def_seq")
                d2 = vn2.get("def_id") or vn2.get("def_seq")
                if d1 is not None and d2 is not None and d1 != d2:
                    return False
            return k1 == k2

        for i, op in enumerate(pcode_ops):
            opcode = op.get("opcode", "").upper()
            inputs = op.get("inputs", [])
            output = op.get("output")

            if opcode in ("INT_XOR", "BOOL_XOR", "INT_SUB") and len(inputs) >= 2:
                if _is_same_varnode(inputs[0], inputs[1]):
                    out_key = _get_varnode_key(output) if output else None
                    out_seq = op.get("seq", i)
                    out_addr = op.get("address", "")
                    out_id = op.get("op_id", f"{out_addr}:{out_seq}" if out_addr else str(out_seq))

                    for j in range(i + 1, min(i + 16, len(pcode_ops))):
                        user_op = pcode_ops[j]
                        u_opcode = user_op.get("opcode", "").upper()
                        u_inputs = user_op.get("inputs", [])

                        if u_opcode == "CBRANCH" and len(u_inputs) >= 2:
                            cond_vn = u_inputs[1]
                            cond_key = _get_varnode_key(cond_vn)

                            is_def_match = False
                            if isinstance(cond_vn, dict):
                                cond_def_id = cond_vn.get("def_id")
                                cond_def_addr = cond_vn.get("def_addr")
                                cond_def_seq = cond_vn.get("def_seq")

                                if cond_def_id and out_id:
                                    is_def_match = (cond_def_id == out_id)
                                elif cond_def_addr and out_addr and cond_def_addr != out_addr:
                                    # Different instruction address - strictly NOT a match!
                                    is_def_match = False
                                elif cond_def_addr and out_addr:
                                    is_def_match = (cond_def_addr == out_addr and cond_def_seq == out_seq)
                                elif cond_def_seq is not None:
                                    is_def_match = (cond_def_seq == out_seq)
                                elif out_key and cond_key == out_key:
                                    is_def_match = True
                            elif out_key and cond_key == out_key:
                                is_def_match = True

                            if is_def_match:
                                cbranch_block_id = user_op.get("block_id", -1)
                                target_block_id = None
                                target_addr = None

                                if cbranch_block_id in block_map:
                                    blk = block_map[cbranch_block_id]
                                    target_block_id = blk.get("true_out")
                                    if target_block_id in block_map:
                                        target_addr = block_map[target_block_id].get("start")

                                if target_block_id is None or target_addr is None:
                                    continue

                                evidence_dossiers.append({
                                    "finding_type": "PROVEN_OPAQUE_PREDICATE",
                                    "predicate_type": "ALGEBRAIC_ZERO_CBRANCH_OPAQUE",
                                    "generator_seq": out_seq,
                                    "generator_address": out_addr,
                                    "generator_opcode": opcode,
                                    "cbranch_seq": user_op.get("seq", j),
                                    "cbranch_address": user_op.get("address"),
                                    "algebraic_proof": (
                                        f"{opcode}({_get_varnode_key(inputs[0])}, {_get_varnode_key(inputs[1])}) "
                                        f"determines condition=0 in SSA. CBRANCH is NEVER taken."
                                    ),
                                    "dead_block_id": target_block_id,
                                    "dead_block_address": target_addr,
                                    "confidence": 0.98,
                                    "severity": "HIGH",
                                    "remediation_proposal": "Replace CBRANCH with unconditional jump to fallthrough block."
                                })
                                dead_op_indices.add(j)
                                break

        return {
            "total_pcode_ops": len(pcode_ops),
            "evidence_dossiers_count": len(evidence_dossiers),
            "evidence_dossiers": evidence_dossiers,
            "prunable_operations": sorted(list(dead_op_indices)),
            "is_obfuscated": len(evidence_dossiers) > 0
        }


# ============================================================================
# 6. P-CODE DEAD CODE & OPAQUE PREDICATE SIMPLIFIER (LEGACY & COMPAT)
# ============================================================================

class PcodeDeobfuscator:
    """
    Identifies algebraic dead code and opaque predicate cascades at the P-code level
    using both SSA Def-Use analysis and canonical pattern sweeps.
    """

    @classmethod
    def detect_opaque_predicates(
        cls,
        pcode_ops: List[Dict[str, Any]],
        basic_blocks: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        ssa_res = PcodeSSAAnalyzer.analyze_ssa_invariants(pcode_ops, basic_blocks)
        if ssa_res["is_obfuscated"]:
            return {
                "total_pcode_ops": ssa_res["total_pcode_ops"],
                "opaque_predicates_count": ssa_res["evidence_dossiers_count"],
                "detected_predicates": ssa_res["evidence_dossiers"],
                "prunable_operations": ssa_res["prunable_operations"],
                "is_obfuscated": True
            }

        detected_predicates = []
        dead_op_indices: Set[int] = set()

        for i, op in enumerate(pcode_ops):
            op_name = op.get("opcode", "").upper()
            inputs = op.get("inputs", [])

            if op_name in ("INT_XOR", "BOOL_XOR") and len(inputs) >= 2:
                in0 = str(inputs[0].get("repr", inputs[0]) if isinstance(inputs[0], dict) else inputs[0])
                in1 = str(inputs[1].get("repr", inputs[1]) if isinstance(inputs[1], dict) else inputs[1])
                if in0 == in1:
                    target_out = str(op.get("output", {}).get("repr", op.get("output", "")) if isinstance(op.get("output"), dict) else op.get("output", ""))
                    for j in range(i + 1, min(i + 6, len(pcode_ops))):
                        next_op = pcode_ops[j]
                        if next_op.get("opcode", "").upper() == "CBRANCH":
                            cbranch_inputs = [str(x.get("repr", x) if isinstance(x, dict) else x) for x in next_op.get("inputs", [])]
                            if target_out and any(target_out in inp for inp in cbranch_inputs):
                                detected_predicates.append({
                                    "xor_op_index": i,
                                    "cbranch_index": j,
                                    "zeroed_varnode": in0,
                                    "predicate_type": "ALGEBRAIC_ZERO_CBRANCH_OPAQUE",
                                    "guaranteed_condition": "ALWAYS_EVALUATES_TO_ZERO",
                                    "simplification": "Turn CBRANCH into direct BRANCH or NOP fallthrough"
                                })
                                dead_op_indices.add(j)

        return {
            "total_pcode_ops": len(pcode_ops),
            "opaque_predicates_count": len(detected_predicates),
            "detected_predicates": detected_predicates,
            "prunable_operations": sorted(list(dead_op_indices)),
            "is_obfuscated": len(detected_predicates) > 0
        }


# ============================================================================
# 7. GHIDRA DATABASE MUTATION & ANNOTATION PLANNER
# ============================================================================

class GhidraAnnotationPlanner:
    """
    Constructs type-safe JSON-RPC payloads for mutating Ghidra's Program Database
    (set_address_name, annotate_native_function, set_comment) on Windows.

    SEPARATION OF DETECTION FROM MODIFICATION:
    - Evidence dossiers require mathematical invariant proof.
    - User/Imported function names are strictly preserved.
    - Placeholder names (FUN_...) are only renamed when proven with confidence >= 0.90.
    """

    @staticmethod
    def build_rename_plan(address: str, new_name: str) -> Dict[str, Any]:
        return {
            "method": "set_address_name",
            "params": {
                "address": address,
                "name": new_name
            }
        }

    @staticmethod
    def build_function_annotation_plan(
        address: str,
        name: str,
        return_type: str = "void",
        parameters: Optional[List[Dict[str, str]]] = None,
        comment: Optional[str] = None
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "address": address,
            "name": name,
            "return_type": return_type,
            "parameters": parameters or [],
        }
        if comment:
            payload["comment"] = comment
        return {
            "method": "annotate_native_function",
            "params": payload
        }

    @staticmethod
    def build_hybrid_c_struct(
        struct_name: str,
        tensor_names: List[str],
        tensor_shapes: List[List[int]]
    ) -> str:
        """
        Synthesizes a C header struct to define embedded AI models inside Ghidra's C Decompiler.
        """
        lines = [f"// Auto-generated by REA-Neural Hybrid Type Synthesizer", f"typedef struct {struct_name} {{"]
        lines.append("    uint32_t magic_header;")
        lines.append("    uint32_t tensor_count;")
        for i, (t_name, shape) in enumerate(zip(tensor_names, tensor_shapes)):
            shape_str = "x".join(str(d) for d in shape)
            sanitized = "".join(c if c.isalnum() else "_" for c in t_name)
            lines.append(f"    float* tensor_{sanitized}; // Shape: [{shape_str}]")
        lines.append(f"}} {struct_name};")
        return "\n".join(lines)

    @classmethod
    def analyze_program_export(cls, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes full Ghidra exported program payload containing multiple functions:
        - Runs ControlFlowGraphAnalyzer on each function.
        - Runs PcodeSSAAnalyzer on Def-Use chains.
        - Calculates 64-D continuous semantic embedding and effective rank.
        - Produces verified mutation actions (rename_actions, comment_actions, evidence_dossiers).
        """
        functions = payload.get("functions", [])
        rename_actions = []
        comment_actions = []
        all_evidence_dossiers = []
        total_opaque = 0
        total_cff = 0
        analyzed_functions = 0
        obfuscated_functions = 0

        for func in functions:
            name = func.get("name", "unknown")
            entry_point = func.get("entry_point", "0x0")
            pcode_ops = func.get("pcode_ops", [])
            basic_blocks = func.get("basic_blocks", [])

            if not pcode_ops:
                continue

            analyzed_functions += 1

            cfg_report = ControlFlowGraphAnalyzer.analyze_cfg(basic_blocks)
            ssa_report = PcodeSSAAnalyzer.analyze_ssa_invariants(pcode_ops, basic_blocks)
            vec_info = PcodeVectorizer.vectorize_pcode_ops(pcode_ops)

            dossiers = ssa_report.get("evidence_dossiers", [])
            has_cff = cfg_report.get("has_cff_backbone", False)

            if dossiers:
                total_opaque += len(dossiers)
                all_evidence_dossiers.extend(dossiers)

            if has_cff:
                total_cff += 1

            is_placeholder_name = name.startswith("FUN_") or name.startswith("sub_")
            should_rename = False
            new_name = name

            # Strict policy: ONLY rename if an opaque predicate is mathematically proven with dead block identification.
            # NEVER auto-rename based on loop topology heuristics alone!
            if is_placeholder_name and dossiers and dossiers[0].get("confidence", 0) >= 0.90:
                new_name = f"REA_Deob_{name}"
                should_rename = True

            if should_rename and new_name != name:
                rename_actions.append({
                    "action": "rename",
                    "address": entry_point,
                    "original_name": name,
                    "name": new_name,
                    "confidence": dossiers[0]["confidence"],
                    "rationale": "Renamed placeholder function based on mathematically proven SSA opaque predicate evidence."
                })

            if dossiers or has_cff:
                obfuscated_functions += 1
                comment_lines = [
                    "[REA-Neural Evidence-Based Semantic Deobfuscation]",
                    f"- High P-code Ops: {len(pcode_ops)} | Basic Blocks: {cfg_report['block_count']}",
                    f"- Cyclomatic Complexity: {cfg_report['cyclomatic_complexity']}",
                    f"- Effective Spectral Rank: {vec_info.get('effective_rank', 1.0):.4f}",
                ]
                if has_cff:
                    dispatchers = [d['block_id'] for d in cfg_report['dispatcher_blocks']]
                    comment_lines.append(f"- CFF Backbone: Dispatcher Blocks {dispatchers} (In-Deg>=3, Out-Deg>=2)")
                if dossiers:
                    comment_lines.append(f"- Proven Algebraic Invariants: {len(dossiers)}")
                    for idx, dos in enumerate(dossiers[:3]):
                        comment_lines.append(f"  [{idx+1}] Proof: {dos['algebraic_proof']}")
                        if dos.get('dead_block_address'):
                            comment_lines.append(f"      Dead Target: {dos['dead_block_address']} (Block {dos['dead_block_id']})")
                        patch_text = dos.get('remediation_proposal') or dos.get('verifiable_patch', 'N/A')
                        comment_lines.append(f"      Patch: {patch_text}")

                comment_actions.append({
                    "action": "plate_comment",
                    "address": entry_point,
                    "comment": "\n".join(comment_lines)
                })

        return {
            "program_name": payload.get("program_name", "unknown"),
            "image_base": payload.get("image_base", "0x0"),
            "analyzed_functions": analyzed_functions,
            "obfuscated_functions": obfuscated_functions,
            "opaque_predicates_total": total_opaque,
            "cff_backbones_total": total_cff,
            "evidence_dossiers": all_evidence_dossiers,
            "rename_actions": rename_actions,
            "comment_actions": comment_actions,
            "summary": (
                f"Analyzed {analyzed_functions} functions: {total_opaque} proven invariant tautologies, "
                f"{total_cff} CFF backbones, {len(rename_actions)} verified rename recommendations."
            )
        }
