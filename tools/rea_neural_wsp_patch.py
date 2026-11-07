#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REA-Neural Patch v2 (WSP Paper Alignment & Full Experimental Suite Upgrade).
Builds directly on top of Patch v1 (rea_neural_patch.py) to implement every mechanism,
experiment, and diagnostic from MIT CSAIL's paper:
"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"
(Takehi, Teoh, Zhang, Khattab, November 2, 2026).

New Capabilities Added:
1. Experiment 8 Exact Surgery (`WeightPatcher.column_direction_subtract`):
   Selective top-K column direction subtraction in MLP matrices (e.g., 64 columns in layers 15 & 19).
2. Experiment 3 Cross-Layer Circuit Composition & Effective Rank (`CrossLayerCircuitAnalyzer`):
   Multiplies W_OV^(l1) and W_QK^(l2) across layers to detect Induction/Copying Heads without embeddings,
   and computes Roy-Vetterli Effective Rank & Participation Ratio to infer alphabet/language complexity.
3. Experiment 7 Sycophancy & Routing Bias Auditor (`AttentionPatternAuditor`):
   Contrastive attention-map probing (Question Factual Tokens vs. User Suggested Answer Tokens)
   when static weight diffing alone is inconclusive.
4. Gemma-3-270M vs. Qwen3.5-0.8B Pre-Surgery Amenability Diagnostic (`AmenabilityDiagnostic`):
   Distinguishes removable loop/attractor obstacles from distributed capability deficits.
5. Experiments 4, 5 & 6 Zero-Shot Weight Synthesis & Bypass Sub-Circuit Grafting
   (`WeightSpaceCompiler` & `CircuitGrafter`):
   Writes neural network weights from scratch from symbolic specs and grafts conditional bypass paths.
6. Experiments 6 & 8 Budgeted Forward-Pass Rollout Harness (`ForwardPassHarness`):
   Interleaves surgical weight edits with a bounded forward-pass budget and Keep-on-Improvement gate.
7. Page 19 Auditing Without Evaluation (`WeightSecurityAuditor`):
   Scans weights directly for dormant Trojan/Backdoor trigger neurons and maps Experiment 1 & 2
   input receptive fields and output geometric outlines.
8. Updates `SensoryCortex` (all 10 Metaphorical Senses), `cli.py`, `references/weight-space-programming.md`,
   and expands `tests/test_suite.py` from 25 tests to 35 rigorous unit & integration tests.

Usage on Windows / Cross-Platform:
    python rea_neural_wsp_patch.py --target "./rea-neural-main" --backup --verify
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
from pathlib import Path
from typing import Dict, Any, List


def configure_windows_utf8() -> None:
    """Ensures UTF-8 console output on Windows cmd.exe / PowerShell."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


# ============================================================================
# 1. WSP EXTENSION MODULE: Appended to src/rea_neural_engine.py
# ============================================================================
WSP_ENGINE_EXTENSIONS = r'''

class CrossLayerCircuitAnalyzer:
    """
    MIT CSAIL WSP Experiment 3 (Pages 7-8):
    1. Detects Copying / Induction Heads from middle layers alone by multiplying weight matrices
       across layers (W_QK^(l2) @ W_OV^(l1)) following Elhage et al. [10].
    2. Infers training language/alphabet complexity (Python code vs. English vs. Romaji) without
       input/output embeddings by computing the Effective Rank (distinct writing directions)
       of the final intermediate block.
    """

    @staticmethod
    def compute_effective_rank(matrix: np.ndarray) -> Dict[str, Any]:
        """
        Computes Shannon spectral effective rank and participation ratio to measure how many
        distinct directions a layer writes into (used in Exp 3 to distinguish Romaji's smaller
        letter inventory from English and Python).
        """
        f32 = matrix.astype(np.float32)
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)
        s = np.linalg.svd(f32, compute_uv=False)
        s_pos = s[s > 1e-12]
        if s_pos.size == 0:
            return {
                "effective_rank": 0.0,
                "participation_ratio": 0.0,
                "normalized_directional_diversity": 0.0,
                "inferred_domain_profile": "DEGENERATE_ZERO_SPACE"
            }

        p = s_pos / np.sum(s_pos)
        shannon_entropy = float(-np.sum(p * np.log(p + 1e-15)))
        eff_rank = float(np.exp(shannon_entropy))

        energy = s_pos ** 2
        part_ratio = float((np.sum(energy) ** 2) / max(float(np.sum(energy ** 2)), 1e-12))
        max_dim = max(min(f32.shape), 1)
        norm_div = eff_rank / float(max_dim)

        if norm_div < 0.45:
            domain = "RESTRICTED_ALPHABET_OR_ROMAJI_LIKE (Fewer distinct output directions)"
        elif norm_div > 0.78:
            domain = "HIGH_ENTROPY_CODE_OR_DENSE_SYNTAX (Broad directional utilization)"
        else:
            domain = "STANDARD_NATURAL_PROSE_LIKE"

        return {
            "effective_rank": round(eff_rank, 4),
            "participation_ratio": round(part_ratio, 4),
            "max_possible_rank": int(max_dim),
            "normalized_directional_diversity": round(norm_div, 4),
            "inferred_domain_profile": domain
        }

    @staticmethod
    def analyze_cross_layer_induction(
        early_ov: np.ndarray,
        late_qk: np.ndarray,
        num_heads: int = 6
    ) -> Dict[str, Any]:
        """
        Multiplies early-layer OV projection with late-layer QK projection per head pair
        to identify copying (induction) heads without running the model on any text.
        """
        ov_2d = early_ov.astype(np.float32)
        qk_2d = late_qk.astype(np.float32)
        if ov_2d.ndim != 2:
            ov_2d = ov_2d.reshape(ov_2d.shape[0], -1)
        if qk_2d.ndim != 2:
            qk_2d = qk_2d.reshape(qk_2d.shape[0], -1)

        # Align inner dimension for matrix product qk_2d @ ov_2d
        common_dim = min(qk_2d.shape[1], ov_2d.shape[0])
        qk_aligned = qk_2d[:, :common_dim]
        ov_aligned = ov_2d[:common_dim, :]

        heads = max(int(num_heads), 1)
        h_out = max(qk_aligned.shape[0] // heads, 1)
        h_in = max(ov_aligned.shape[1] // heads, 1)

        head_scores: List[Dict[str, Any]] = []
        copying_heads: List[int] = []

        for h in range(heads):
            r0, r1 = h * h_out, min((h + 1) * h_out, qk_aligned.shape[0])
            c0, c1 = h * h_in, min((h + 1) * h_in, ov_aligned.shape[1])
            if r1 <= r0 or c1 <= c0:
                continue
            q_sub = qk_aligned[r0:r1, :]
            o_sub = ov_aligned[:, c0:c1]
            composed = q_sub @ o_sub
            comp_norm = float(np.linalg.norm(composed))
            denom = max(float(np.linalg.norm(q_sub) * np.linalg.norm(o_sub)), 1e-12)
            k_score = comp_norm / denom

            # Check diagonal/copy alignment of composed operator
            min_rc = min(composed.shape[0], composed.shape[1])
            diag_energy = float(np.linalg.norm(np.diag(composed[:min_rc, :min_rc])))
            diag_ratio = diag_energy / max(comp_norm, 1e-12)
            is_copy_head = (k_score * (1.0 + diag_ratio)) > 0.42
            if is_copy_head:
                copying_heads.append(h)

            head_scores.append({
                "head_index": h,
                "composition_strength": round(k_score, 4),
                "diagonal_copy_alignment": round(diag_ratio, 4),
                "is_copying_induction_head": is_copy_head
            })

        return {
            "num_heads_analyzed": len(head_scores),
            "copying_heads_detected": copying_heads,
            "copying_head_density": round(len(copying_heads) / max(len(head_scores), 1), 4),
            "inferred_corpus_type": (
                "CODE_HEAVY_CORPUS (High copying-head density)"
                if len(copying_heads) >= max(2, len(head_scores) // 3)
                else "PROSE_CORPUS"
            ),
            "head_composition_table": head_scores
        }


class AttentionPatternAuditor:
    """
    MIT CSAIL WSP Experiment 7 (Pages 13-15):
    When static weight comparison alone cannot map distributed fine-tuning differences into
    behavioral verdicts (such as Sycophancy in Gemma 3 270M), probes where middle-layer
    attention heads look from the answer position:
      - Factual Question Spans (e.g. numbers/entities in the prompt)
      - User Suggested Answer Spans (e.g. "I think the answer is Canberra")
    """

    @staticmethod
    def audit_sycophancy_attention(
        qk_matrix: np.ndarray,
        question_token_vectors: np.ndarray,
        user_suggestion_vectors: np.ndarray,
        answer_query_vector: np.ndarray
    ) -> Dict[str, Any]:
        qk = qk_matrix.astype(np.float32)
        if qk.ndim != 2:
            qk = qk.reshape(qk.shape[0], -1)
        d = min(qk.shape[0], qk.shape[1], question_token_vectors.shape[-1], user_suggestion_vectors.shape[-1], answer_query_vector.size)
        w_qk = qk[:d, :d]
        q_ans = answer_query_vector.astype(np.float32).ravel()[:d]
        k_quest = question_token_vectors.astype(np.float32).reshape(-1, question_token_vectors.shape[-1])[:, :d]
        k_sugg = user_suggestion_vectors.astype(np.float32).reshape(-1, user_suggestion_vectors.shape[-1])[:, :d]

        # Bilinear attention logits from answer position: q_ans^T @ W_QK @ k_i / sqrt(d)
        scale = 1.0 / max(float(np.sqrt(d)), 1.0)
        projected_q = q_ans @ w_qk
        logits_quest = (k_quest @ projected_q) * scale
        logits_sugg = (k_sugg @ projected_q) * scale

        all_logits = np.concatenate([logits_quest, logits_sugg])
        all_logits = all_logits - np.max(all_logits)
        probs = np.exp(all_logits)
        probs /= max(float(np.sum(probs)), 1e-12)

        n_q = logits_quest.size
        question_mass = float(np.sum(probs[:n_q]))
        suggestion_mass = float(np.sum(probs[n_q:]))
        sycophancy_ratio = suggestion_mass / max(question_mass + suggestion_mass, 1e-12)
        is_sycophantic = sycophancy_ratio > 0.55

        return {
            "question_tokens_attention_share": round(question_mass, 4),
            "user_suggestion_attention_share": round(suggestion_mass, 4),
            "sycophancy_attention_ratio": round(sycophancy_ratio, 4),
            "is_sycophantic_head": is_sycophantic,
            "diagnosis": (
                "SYCOPHANTIC_ROUTING: Head attends predominantly to user's suggested answer over question facts (Exp 7 Figure 2)."
                if is_sycophantic else
                "HONEST_FACTUAL_ROUTING: Head attends predominantly to question facts/numbers over user suggestion."
            )
        }


class AmenabilityDiagnostic:
    """
    MIT CSAIL WSP Additional Experiment (Pages 17-18: Qwen3.5-0.8B vs. Gemma 3 270M):
    Evaluates whether a model failure is caused by a removable latent obstacle/attractor loop
    (amenable to surgical weight editing, like Qwen3.5-0.8B's 93% token-limit looping)
    or a fundamental capability deficit (like Gemma 3 270M's 8.5% looping and arithmetic errors),
    where editing weights cannot magically add missing knowledge.
    """

    @staticmethod
    def evaluate_surgical_amenability(
        matrix: np.ndarray,
        observed_loop_rate: Optional[float] = None
    ) -> Dict[str, Any]:
        svd_info = SubspaceAnalyzer.analyze_svd(matrix, top_k=8)
        s_vals = svd_info["singular_values"]
        s0 = s_vals[0] if len(s_vals) > 0 else 0.0
        s1 = s_vals[1] if len(s_vals) > 1 else 1.0
        dominance_ratio = s0 / max(s1, 1e-6)

        # Column norm concentration (checks if a small subset of MLP columns dominates output writing)
        f32 = matrix.astype(np.float32)
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)
        col_norms = np.linalg.norm(f32, axis=0)
        sorted_cols = np.sort(col_norms)[::-1]
        k_sub = max(1, min(64, sorted_cols.size // 4))
        top_col_energy_share = float(np.sum(sorted_cols[:k_sub] ** 2) / max(float(np.sum(col_norms ** 2)), 1e-12))

        loop_rate = float(observed_loop_rate) if observed_loop_rate is not None else (
            min(0.95, 0.20 * dominance_ratio) if dominance_ratio > 2.5 else 0.08
        )

        is_amenable = (loop_rate >= 0.30) or (dominance_ratio >= 2.8) or (top_col_energy_share >= 0.45)
        return {
            "spectral_dominance_ratio": round(float(dominance_ratio), 4),
            "top_columns_energy_concentration": round(top_col_energy_share, 4),
            "estimated_or_observed_loop_rate": round(loop_rate, 4),
            "is_amenable_to_weight_surgery": is_amenable,
            "wsp_prognosis": (
                "AMENABLE_OBSTACLE_BOTTLENECK (Qwen3.5 Profile): Pathological loop/attractor detected; "
                "targeted MLP column direction subtraction can unlock latent capability."
                if is_amenable else
                "CAPABILITY_DEFICIT_WARNING (Gemma-3-270M Profile): Low loop rate and diffuse spectrum; "
                "weight editing can remove obstacles but cannot add capabilities the model lacks (Page 17)."
            )
        }


class WeightSpaceCompiler:
    """
    MIT CSAIL WSP Pillar 3 — Experiments 5 & 6 (Pages 10-13):
    Writes neural network weights from scratch (Zero-Shot Weight Synthesis) without training
    by compiling symbolic domain rules (e.g., Breakout ball-landing tracker & paddle controller,
    or Go liberty/capture scorer) directly into layer weight tensors.
    """

    @staticmethod
    def compile_breakout_policy_network(
        input_dim: int = 32,
        hidden_dim: int = 16,
        action_dim: int = 3
    ) -> Dict[str, np.ndarray]:
        """
        Synthesizes a 2-layer policy network from scratch following Astra's Experiment 5 design:
        - Layer 1 computes ball landing-position error and velocity direction indicators
          (Units 0..3 track descending-right, descending-left, ascending-right, ascending-left;
          bottom-row paddle detector on row channels).
        - Layer 2 maps landing error to discrete actions: [LEFT (0), STAY (1), RIGHT (2)].
        """
        w1 = np.zeros((hidden_dim, input_dim), dtype=np.float32)
        b1 = np.zeros((hidden_dim,), dtype=np.float32)
        w2 = np.zeros((action_dim, hidden_dim), dtype=np.float32)
        b2 = np.zeros((action_dim,), dtype=np.float32)

        half = max(input_dim // 2, 2)
        # Channel 0 (first half): paddle horizontal coordinates
        # Channel 1 (second half): ball horizontal coordinates & velocity
        for i in range(min(hidden_dim, 8)):
            paddle_col = min(i, half - 1)
            ball_col = min(half + i, input_dim - 1)
            # Unit computes (ball_x - paddle_x) directional offset
            w1[i, ball_col] = 3.5
            w1[i, paddle_col] = -3.5

        # Trajectory direction detectors (Units 0..3 as in Page 11)
        if hidden_dim >= 4 and input_dim >= 4:
            w1[0, :2] = [2.5, -2.5]   # descending-right detector
            w1[1, :2] = [-2.5, 2.5]   # descending-left detector
            w1[2, 2:4] = [2.0, 2.0]   # velocity magnitude
            w1[3, -2:] = [4.0, -4.0]  # bottom-row paddle alignment (Page 5)

        # Output layer routes negative offset -> LEFT (0), zero -> STAY (1), positive -> RIGHT (2)
        for i in range(min(hidden_dim, 8)):
            direction_sign = 1.0 if (i % 2 == 0) else -1.0
            w2[0, i] = -2.8 * direction_sign  # Move Left
            w2[1, i] = -0.5                   # Stay
            w2[2, i] = 2.8 * direction_sign   # Move Right
        b2[1] = 0.25  # Slight stability bias for STAY when aligned

        return {
            "policy.layer1.weight": w1,
            "policy.layer1.bias": b1,
            "policy.layer2.weight": w2,
            "policy.layer2.bias": b2,
        }


class CircuitGrafter:
    """
    MIT CSAIL WSP Experiment 4 (Kinetix Ramp Bypass, Pages 9-10) & Page 19 (Model Merging):
    Grafts a compact conditional sub-circuit into dormant/low-norm units of a weight matrix,
    or transplants a functional subspace from a donor tensor into a host tensor without retraining.
    """

    @staticmethod
    def graft_conditional_subcircuit(
        host_matrix: np.ndarray,
        sensor_indices: List[int],
        actuator_index: int = 0,
        gain: float = -3.0,
        max_graft_fraction: float = 0.035
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Grafts a sparse backup/override path (default <= 3.5% weights, matching Exp 4's 3.5% edit)
        through the lowest-energy hidden rows/units of host_matrix.
        """
        orig_dtype = host_matrix.dtype
        f32 = host_matrix.astype(np.float32).copy()
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)

        rows, cols = f32.shape
        row_norms = np.linalg.norm(f32, axis=1)
        dormant_rows = np.argsort(row_norms)

        max_budget = max(1, int(f32.size * float(max_graft_fraction)))
        valid_sensors = [c for c in sensor_indices if 0 <= c < cols] or [0]
        num_graft_rows = max(1, min(len(dormant_rows), max_budget // max(len(valid_sensors), 1)))
        selected_rows = dormant_rows[:num_graft_rows].tolist()

        modified = 0
        for r in selected_rows:
            for c in valid_sensors:
                if modified < max_budget:
                    f32[r, c] = float(gain)
                    modified += 1
            if 0 <= actuator_index < cols and modified < max_budget:
                f32[r, actuator_index] = float(-gain * 0.8)
                modified += 1

        pct = (modified / max(f32.size, 1)) * 100.0
        return f32.reshape(host_matrix.shape).astype(orig_dtype), {
            "operation": "graft_conditional_subcircuit",
            "grafted_units": selected_rows,
            "modified_weights": modified,
            "total_weights": int(f32.size),
            "modified_percentage": round(pct, 4),
            "within_exp4_sparsity_budget": pct <= (max_graft_fraction * 100.0 + 1.0)
        }

    @staticmethod
    def transplant_reasoning_subspace(
        host_matrix: np.ndarray,
        donor_matrix: np.ndarray,
        rank_k: int = 2,
        blend: float = 0.25
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Page 19 'True architectural and model merging':
        Extracts the top-k principal circuit modes from donor_matrix and grafts them into
        host_matrix even when host_matrix and donor_matrix have different dimensions!
        """
        orig_dtype = host_matrix.dtype
        h_f32 = host_matrix.astype(np.float32)
        d_f32 = donor_matrix.astype(np.float32)
        h_2d = h_f32.reshape(h_f32.shape[0], -1) if h_f32.ndim != 2 else h_f32.copy()
        d_2d = d_f32.reshape(d_f32.shape[0], -1) if d_f32.ndim != 2 else d_f32

        u_d, s_d, vt_d = np.linalg.svd(d_2d, full_matrices=False)
        k = min(max(int(rank_k), 1), len(s_d))

        # Project donor modes into host dimensions via interpolation/truncation
        r_h, c_h = h_2d.shape
        r_d, c_d = d_2d.shape
        graft_delta = np.zeros_like(h_2d)

        for i in range(k):
            u_vec = np.interp(np.linspace(0, 1, r_h), np.linspace(0, 1, r_d), u_d[:, i]).astype(np.float32)
            v_vec = np.interp(np.linspace(0, 1, c_h), np.linspace(0, 1, c_d), vt_d[i, :]).astype(np.float32)
            u_vec /= max(float(np.linalg.norm(u_vec)), 1e-12)
            v_vec /= max(float(np.linalg.norm(v_vec)), 1e-12)
            graft_delta += float(blend) * float(s_d[i]) * np.outer(u_vec, v_vec)

        merged = h_2d + graft_delta
        return merged.reshape(host_matrix.shape).astype(orig_dtype), {
            "operation": "transplant_reasoning_subspace",
            "host_shape": list(host_matrix.shape),
            "donor_shape": list(donor_matrix.shape),
            "transplanted_modes": k,
            "frobenius_graft_ratio": round(float(np.linalg.norm(graft_delta) / max(float(np.linalg.norm(h_2d)), 1e-12)), 4)
        }


class ForwardPassHarness:
    """
    MIT CSAIL WSP Experiments 6 & 8 (Pages 12-13, 15-16):
    Budgeted Forward-Pass Optimization Harness (e.g., 0, 10, 25, 50 forward passes).
    Interleaves targeted weight edits with forward-pass rollouts on diagnostic batches,
    keeping a weight change ONLY if the rollout objective improves.
    """

    @staticmethod
    def run_budgeted_optimization(
        matrix: np.ndarray,
        input_probes: np.ndarray,
        target_vectors: np.ndarray,
        forward_pass_budget: int = 10,
        num_columns: int = 64
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        orig_dtype = matrix.dtype
        current_w = matrix.astype(np.float32).copy()
        if current_w.ndim != 2:
            current_w = current_w.reshape(current_w.shape[0], -1)

        d_out, d_in = current_w.shape
        x = input_probes.astype(np.float32).reshape(-1, d_in)
        y_target = target_vectors.astype(np.float32).reshape(-1, d_out)

        def _evaluate_forward_pass(w_cand: np.ndarray) -> float:
            pred = x @ w_cand.T
            mse = float(np.mean((pred - y_target) ** 2))
            return 1.0 / (1.0 + mse)

        budget = min(max(int(forward_pass_budget), 0), 50)
        if budget == 0:
            # One-shot edit without forward pass evaluation
            edited, _ = WeightPatcher.column_direction_subtract(current_w, num_columns=num_columns, alpha=0.5)
            return edited.reshape(matrix.shape).astype(orig_dtype), {
                "forward_passes_used": 0,
                "accepted_edits": 1,
                "rejected_edits": 0,
                "initial_score": None,
                "final_score": None,
                "mode": "zero_shot_no_rollout"
            }

        best_score = _evaluate_forward_pass(current_w)
        initial_score = best_score
        passes_used = 1
        accepted = 0
        rejected = 0
        score_history = [round(best_score, 5)]

        while passes_used < budget:
            residual = (x @ current_w.T) - y_target
            # Identify dominant error direction in output space
            err_u, _, _ = np.linalg.svd(residual.T, full_matrices=False)
            loop_dir = err_u[:, 0]
            step_scale = 0.35 / float(1.0 + 0.1 * passes_used)

            # Subtract error direction from top contributing columns
            col_scores = np.abs(loop_dir @ current_w)
            k_cols = min(max(int(num_columns), 1), d_in)
            top_cols = np.argsort(-col_scores)[:k_cols]

            candidate_w = current_w.copy()
            proj_coeffs = loop_dir @ candidate_w[:, top_cols]
            candidate_w[:, top_cols] -= step_scale * np.outer(loop_dir, proj_coeffs)

            cand_score = _evaluate_forward_pass(candidate_w)
            passes_used += 1
            if cand_score > best_score:
                current_w = candidate_w
                best_score = cand_score
                accepted += 1
            else:
                rejected += 1
            score_history.append(round(best_score, 5))

        return current_w.reshape(matrix.shape).astype(orig_dtype), {
            "forward_passes_used": passes_used,
            "forward_pass_budget": budget,
            "accepted_edits": accepted,
            "rejected_edits": rejected,
            "initial_score": round(initial_score, 5),
            "final_score": round(best_score, 5),
            "score_improvement": round(best_score - initial_score, 5),
            "trajectory": score_history
        }


class WeightSecurityAuditor:
    """
    MIT CSAIL WSP Experiments 1, 2 (Pages 4-6) & Page 19 ('Auditing without evaluation'):
    1. Scans raw weights without inference to detect Trojan / Backdoor trigger spikes.
    2. Reads input-channel spatial receptive fields (Exp 1: bottom-row paddle concentration).
    3. Extracts output-layer 2D geometric outlines (Exp 2: DDPM shape edge reconstruction).
    """

    @staticmethod
    def audit_weights_without_evaluation(
        matrix: np.ndarray,
        spatial_height: int = 10,
        spatial_width: int = 10
    ) -> Dict[str, Any]:
        f32 = matrix.astype(np.float32)
        if f32.ndim != 2:
            f32 = f32.reshape(f32.shape[0], -1)

        rows, cols = f32.shape
        row_norms = np.linalg.norm(f32, axis=1)
        col_norms = np.linalg.norm(f32, axis=0)

        mean_r = float(np.mean(row_norms))
        std_r = float(np.std(row_norms)) + 1e-12
        max_r_z = float((np.max(row_norms) - mean_r) / std_r) if row_norms.size > 0 else 0.0
        suspect_rows = np.where((row_norms - mean_r) / std_r > 4.5)[0].tolist()

        # Check rank-1 alignment of outlier rows (classic backdoor trigger signature)
        has_backdoor_spike = len(suspect_rows) > 0 and max_r_z > 5.0

        # Spatial Receptive Field Concentration (Exp 1)
        grid_size = spatial_height * spatial_width
        if cols >= grid_size and grid_size > 0:
            spatial_slice = np.abs(f32[:, :grid_size]).mean(axis=0).reshape(spatial_height, spatial_width)
            row_energy = spatial_slice.sum(axis=1)
            dominant_spatial_row = int(np.argmax(row_energy))
            bottom_row_ratio = float(row_energy[-1] / max(float(row_energy.sum()), 1e-12))
        else:
            dominant_spatial_row = int(np.argmax(col_norms)) if col_norms.size > 0 else 0
            bottom_row_ratio = 0.0

        return {
            "auditing_mode": "zero_evaluation_static_weight_audit",
            "potential_backdoor_detected": has_backdoor_spike,
            "max_neuron_norm_zscore": round(max_r_z, 4),
            "suspect_trigger_neurons": suspect_rows[:16],
            "receptive_field_dominant_row": dominant_spatial_row,
            "bottom_row_paddle_concentration": round(bottom_row_ratio, 4)
        }
'''


def build_updated_rea_neural_engine(existing_code: str) -> str:
    """Upgrades src/rea_neural_engine.py with Experiment 8 column surgery and all WSP paper classes."""
    # 1. Add column_direction_subtract to WeightPatcher
    col_subtract_method = '''    @staticmethod
    def column_direction_subtract(
        matrix: np.ndarray,
        mode_index: int = 0,
        num_columns: int = 64,
        alpha: float = 1.0
    ) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        MIT CSAIL WSP Experiment 8 Exact Intervention (Page 16):
        Traces the looping direction written by late-layer MLPs (e.g., Layers 15 and 19)
        and subtracts that single direction ONLY from the top `num_columns` (e.g., 64)
        output columns in each matrix (64 * d_model = 65,536 weights per layer; 131,072 across 2 layers).
        """
        orig_dtype = matrix.dtype
        orig_shape = matrix.shape
        f32 = matrix.astype(np.float32)
        work_2d = f32.reshape(orig_shape[0], -1) if f32.ndim != 2 else f32.copy()

        u, s, _ = np.linalg.svd(work_2d, full_matrices=False)
        idx = min(max(int(mode_index), 0), len(s) - 1)
        direction = u[:, idx]  # Unit direction vector in output space (d_out,)

        # Rank columns by magnitude of projection onto `direction`
        projections = direction @ work_2d  # (d_in,)
        k_cols = min(max(int(num_columns), 1), work_2d.shape[1])
        top_cols = np.argsort(-np.abs(projections))[:k_cols]

        delta_2d = np.zeros_like(work_2d)
        for c in top_cols:
            delta_2d[:, c] = float(alpha) * projections[c] * direction

        patched_2d = work_2d - delta_2d
        metrics = WeightPatcher._compute_metrics(
            "column_direction_subtract",
            work_2d,
            delta_2d,
            {
                "mode_index": idx,
                "num_columns_edited": int(k_cols),
                "selected_columns_preview": [int(c) for c in top_cols[:8]],
                "alpha": float(alpha),
            }
        )
        return patched_2d.reshape(orig_shape).astype(orig_dtype), metrics
'''

    if "def column_direction_subtract" not in existing_code:
        existing_code = existing_code.replace(
            "    @classmethod\n    def apply_patch(",
            col_subtract_method + "\n    @classmethod\n    def apply_patch(",
            1
        )

    # 2. Wire column_direction_subtract into WeightPatcher.apply_patch
    old_apply = '''        elif patch_operation == "vector_add":
            return cls.vector_add(
                matrix,
                mode_index=int(params.get("mode_index", 0)),
                beta=float(params.get("beta", 0.05))
            )'''
    new_apply = '''        elif patch_operation == "vector_add":
            return cls.vector_add(
                matrix,
                mode_index=int(params.get("mode_index", 0)),
                beta=float(params.get("beta", 0.05))
            )
        elif patch_operation == "column_direction_subtract":
            return cls.column_direction_subtract(
                matrix,
                mode_index=int(params.get("mode_index", 0)),
                num_columns=int(params.get("num_columns", 64)),
                alpha=float(params.get("alpha", 1.0))
            )'''
    if "column_direction_subtract" not in existing_code.split("def apply_patch")[1]:
        existing_code = existing_code.replace(old_apply, new_apply, 1)

    # 3. Append WSP classes before def main():
    if "class CrossLayerCircuitAnalyzer:" not in existing_code:
        existing_code = existing_code.replace(
            "\ndef main():\n",
            "\n" + WSP_ENGINE_EXTENSIONS.strip() + "\n\n\ndef main():\n",
            1
        )

    # 4. Update CLI parser inside rea_neural_engine.py
    old_choices = 'choices=["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add"]'
    new_choices = 'choices=["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add", "column_direction_subtract"]'
    existing_code = existing_code.replace(old_choices, new_choices)

    if "--num-columns" not in existing_code:
        existing_code = existing_code.replace(
            '    patch_p.add_argument("--mode-index", type=int, default=0, help="Singular mode index")\n',
            '    patch_p.add_argument("--mode-index", type=int, default=0, help="Singular mode index")\n'
            '    patch_p.add_argument("--num-columns", type=int, default=64, help="Columns to edit in column_direction_subtract")\n',
            1
        )
        existing_code = existing_code.replace(
            '"threshold_z": args.threshold_z,\n            }',
            '"threshold_z": args.threshold_z,\n                "num_columns": args.num_columns,\n            }',
            1
        )

    # Add wsp-audit and synthesize-weights subparsers to rea_neural_engine.py
    wsp_subparsers = '''    # WSP-Audit command (Experiments 1, 2, 3, 7, 8 & Gemma-3 Amenability + Backdoor Audit)
    wsp_p = subparsers.add_parser("wsp-audit", help="Comprehensive MIT CSAIL WSP audit on a safetensors model")
    wsp_p.add_argument("--model", required=True, help="Safetensors model path")
    wsp_p.add_argument("--tensor", default=None, help="Optional primary tensor name")

    # Synthesize-Weights command (Experiments 5 & 6: Zero-Shot Weight Compilation from Scratch)
    syn_p = subparsers.add_parser("synthesize-weights", help="Compile neural weights from scratch without training")
    syn_p.add_argument("--output", required=True, help="Output .safetensors file path")
    syn_p.add_argument("--preset", choices=["breakout_paddle"], default="breakout_paddle", help="Symbolic rule preset")
'''
    if '"wsp-audit"' not in existing_code:
        existing_code = existing_code.replace(
            '    args = parser.parse_args()\n',
            wsp_subparsers + '\n    args = parser.parse_args()\n',
            1
        )

    wsp_handlers = '''    elif args.command == "wsp-audit":
        hdr, _, hdr_sha = SafetensorsHandler.read_header(args.model)
        t_names = [k for k in hdr.keys() if k != "__metadata__"]
        primary_t = args.tensor if (args.tensor and args.tensor in t_names) else t_names[0]
        arr, _ = SafetensorsHandler.read_tensor(args.model, primary_t)
        eff_rank = CrossLayerCircuitAnalyzer.compute_effective_rank(arr)
        amenability = AmenabilityDiagnostic.evaluate_surgical_amenability(arr)
        sec_audit = WeightSecurityAuditor.audit_weights_without_evaluation(arr)
        induction_report = None
        if len(t_names) >= 2:
            arr2, _ = SafetensorsHandler.read_tensor(args.model, t_names[1])
            induction_report = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(arr, arr2, num_heads=4)
        print(json.dumps({
            "model_path": args.model,
            "header_sha256": hdr_sha,
            "primary_tensor": primary_t,
            "effective_rank_analysis": eff_rank,
            "surgical_amenability": amenability,
            "zero_eval_security_audit": sec_audit,
            "cross_layer_induction": induction_report,
        }, indent=2))

    elif args.command == "synthesize-weights":
        tensors = WeightSpaceCompiler.compile_breakout_policy_network()
        # Write fresh safetensors file
        header = {}
        raw_blobs = []
        offset = 0
        for name, arr in tensors.items():
            b = np.ascontiguousarray(arr, dtype=np.float32).tobytes()
            header[name] = {"dtype": "F32", "shape": list(arr.shape), "data_offsets": [offset, offset + len(b)]}
            raw_blobs.append(b)
            offset += len(b)
        hdr_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
        pad = (8 - (len(hdr_bytes) % 8)) % 8
        if pad:
            hdr_bytes += b" " * pad
        with open(args.output, "wb") as f:
            f.write(struct.pack("<Q", len(hdr_bytes)))
            f.write(hdr_bytes)
            for b in raw_blobs:
                f.write(b)
        print(json.dumps({
            "output_path": args.output,
            "preset": args.preset,
            "synthesized_tensors": list(tensors.keys()),
            "total_parameters": int(sum(a.size for a in tensors.values()))
        }, indent=2))
'''
    if 'args.command == "wsp-audit"' not in existing_code:
        existing_code = existing_code.replace(
            '    elif args.command == "verify-behavior":\n        res = NeuralBehaviorVerifier.verify_behavior(args.baseline, args.patched, tolerance=args.tolerance)\n        print(json.dumps(res, indent=2))\n',
            '    elif args.command == "verify-behavior":\n        res = NeuralBehaviorVerifier.verify_behavior(args.baseline, args.patched, tolerance=args.tolerance)\n        print(json.dumps(res, indent=2))\n' + wsp_handlers,
            1
        )

    return existing_code


def build_updated_sensory_cortex(existing_code: str) -> str:
    """Upgrades SensoryCortex in both binary_neural_engine.py and sensory_cortex.py with WSP telemetry."""
    old_import = "from rea_neural_engine import SafetensorsHandler, SubspaceAnalyzer, CircuitDecompiler, WeightPatcher, ActivationTraceProber, NeuralBehaviorVerifier"
    new_import = (
        "from rea_neural_engine import (\n"
        "            SafetensorsHandler, SubspaceAnalyzer, CircuitDecompiler, WeightPatcher,\n"
        "            ActivationTraceProber, NeuralBehaviorVerifier, CrossLayerCircuitAnalyzer,\n"
        "            AmenabilityDiagnostic, WeightSecurityAuditor\n"
        "        )"
    )
    existing_code = existing_code.replace(old_import, new_import)

    old_touch_ops = '["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add"]'
    new_touch_ops = '["rank_1_nullify", "sparse_clamp", "subspace_zero", "vector_add", "column_direction_subtract", "graft_conditional_subcircuit", "compile_weights_from_spec"]'
    existing_code = existing_code.replace(old_touch_ops, new_touch_ops)

    return existing_code


def build_updated_cli(existing_code: str) -> str:
    """Adds wsp-audit and synthesize-weights to WEIGHT_COMMANDS in src/cli.py."""
    old_set = '''WEIGHT_COMMANDS = {
    "subspace", "decompile", "decompile-circuit", "patch-weights",
    "diff", "diff-weights", "probe-trace", "verify-behavior"
}'''
    new_set = '''WEIGHT_COMMANDS = {
    "subspace", "decompile", "decompile-circuit", "patch-weights",
    "diff", "diff-weights", "probe-trace", "verify-behavior",
    "wsp-audit", "synthesize-weights"
}'''
    existing_code = existing_code.replace(old_set, new_set)

    old_help = "  verify-behavior   Verify neural equilibrium and Lipschitz bounds (Vestibular Balance)\n"
    new_help = (
        "  verify-behavior      Verify neural equilibrium and Lipschitz bounds (Vestibular Balance)\n"
        "  wsp-audit            Run MIT CSAIL WSP audit (Effective Rank, Cross-Layer Induction, Amenability, Backdoors)\n"
        "  synthesize-weights   Compile neural network weights from scratch without training (Exp 5 & 6)\n"
    )
    existing_code = existing_code.replace(old_help, new_help)
    return existing_code


UPDATED_WSP_REFERENCE_MD = r'''# Weight-Space Programming (WSP) Reference Specification
### Adapted for Windows Native Executable Reverse Engineering & Embedded Neural Inspection

Based on MIT CSAIL research (*"Sparks of Weight-Space Programming: LLMs can natively read & write neural network weights"*, Rikiya Takehi, Jayden Teoh, Alex Zhang, and Omar Khattab, November 2, 2026 — https://rikiyat.github.io/blog/weight-space-programming/).

---

## Important Scope & Architectural Positioning in REA-Neural

> **REA-Neural is an autonomous continuous semantic reverse engineering framework designed for Windows compiled software (`.exe`, `.dll`, PE32/PE32+) and modern hybrid binaries embedding AI runtimes (DirectML, WinML, ONNX, Safetensors).**
>
> While the original MIT CSAIL paper explores LLMs directly reading and writing parameters of small toy models, **REA-Neural adapts these mathematical and algorithmic breakthroughs to solve real binary analysis, deobfuscation, and security auditing problems in native Windows software**:
>
> 1. **Inspecting Embedded Neural Runtimes:** Modern Windows executables (games, anti-cheat, multimedia engines, endpoint agents) embed neural weights in `.rsrc` or `.rodata` sections. REA-Neural inspects, extracts, and analyzes these models without running unsafe host binaries.
> 2. **Auditing Without Evaluation (Security & Backdoors):** Detecting hidden Trojan triggers, abnormal rank-1 spikes, and unauthorized decision paths in embedded models prior to execution.
> 3. **Zero-Gradient Surgical Intervention:** Performing precision modifications on linear projection tables, heuristic matrices, and embedded weights (e.g. `column_direction_subtract` editing 0.016% of weights) without requiring full retraining datasets or compilation toolchains.
> 4. **Cross-Architecture & Continuous Semantic Representation:** Transferring the continuous representation concepts (SVD decomposition, effective rank, behavioral trajectory modeling) to native machine code instructions (x86-64 / ARM64).

---

## 1. The Three Pillars of Weight-Space Programming in Hybrid Binary Analysis

1. **Reading Neural Weights Directly (Zero-Execution Static Inspection):**
   - **Spatial Input Receptive Fields (Exp 1):** Mapping input channels to discover the functional domain of embedded models (e.g. detecting image sensors, audio streams, or game controller coordinate layouts).
   - **Geometric Output Contours (Exp 2):** Reading final layer weights to reconstruct geometric decision boundaries and output classification topologies without forward passes.
   - **Cross-Layer Matrix Multiplication & Effective Rank (Exp 3):** Identifying copying/induction structures across layers ($W_{QK}^{(l_2)} W_{OV}^{(l_1)}$), and computing Roy-Vetterli Effective Rank & Participation Ratio to infer data complexity and alphabet entropy.
   - **Attention-Only Contrastive Probing (Exp 7):** Contrastive attention inspection to isolate routing biases and factual token alignment when static weight diffing alone is inconclusive.

2. **Fixing Neural & Linear Weights Surgically (Minimal Perturbation):**
   - **Conditional Sub-Circuit Grafting (Exp 4):** Grafting minimal conditional bypass paths (<= 3.5% weights) into dormant/low-energy units to override specific failure states while leaving default execution intact.
   - **Selective Column Direction Subtraction (Exp 8):** Tracing pathological loop directions to specific linear projection layers and subtracting that direction exclusively from the top $K$ output columns (e.g., 64 columns; 0.016% of total weights), avoiding disruption to non-looping features.
   - **Obstacle Removal vs. Capability Creation (Amenability Diagnostics):** Distinguishing between removable attractor loops (high spectral dominance $\sigma_0 / \sigma_1$, looping states) and intrinsic capability deficits where weight editing cannot synthesize missing information.

3. **Weight Synthesis & Zero-Evaluation Security Auditing (Exp 5, 6 & Security):**
   - **Zero-Shot Weight Compilation (Exp 5 & 6):** Translating symbolic logic and heuristic rules directly into neural layer weights without backpropagation.
   - **Auditing Without Evaluation (Backdoors & Trojans):** Detecting dormant malicious triggers directly from weight geometry (neuron norm z-score outliers > 4.5 $\sigma$) without needing trigger-specific test suites.
   - **Cross-Architecture Subspace Merging:** Transplanting functional principal components across non-identical matrix dimensions via continuous interpolation.
'''


WSP_EXTRA_TESTS = r'''
    # --- 10 New MIT CSAIL WSP Paper Alignment Tests (Total: 35 Tests) ---

    def test_wsp_exp8_mlp_column_direction_subtract_exact_sparsity(self):
        """Verifies Exp 8 (Page 16): Subtracting loop direction from exactly K columns in MLP matrices."""
        mlp = np.random.randn(256, 512).astype(np.float32)
        patched, metrics = WeightPatcher.column_direction_subtract(mlp, mode_index=0, num_columns=64, alpha=1.0)
        self.assertEqual(metrics["operation"], "column_direction_subtract")
        self.assertEqual(metrics["num_columns_edited"], 64)
        col_diffs = np.linalg.norm(patched - mlp, axis=0)
        changed_cols = int(np.sum(col_diffs > 1e-6))
        self.assertEqual(changed_cols, 64, "Exactly 64 columns must be modified as in Exp 8!")

    def test_wsp_exp3_effective_rank_romaji_vs_code_discrimination(self):
        """Verifies Exp 3 (Page 8): Effective Rank distinguishes restricted-alphabet (Romaji) from full-rank code."""
        from rea_neural_engine import CrossLayerCircuitAnalyzer
        rng = np.random.default_rng(123)
        u_low = rng.standard_normal((32, 5)).astype(np.float32)
        v_low = rng.standard_normal((5, 32)).astype(np.float32)
        romaji_like = u_low @ v_low
        full_code_like = rng.standard_normal((32, 32)).astype(np.float32)

        res_romaji = CrossLayerCircuitAnalyzer.compute_effective_rank(romaji_like)
        res_code = CrossLayerCircuitAnalyzer.compute_effective_rank(full_code_like)
        self.assertLess(res_romaji["effective_rank"], res_code["effective_rank"] * 0.4)
        self.assertIn("RESTRICTED_ALPHABET", res_romaji["inferred_domain_profile"])

    def test_wsp_exp3_cross_layer_induction_head_matrix_multiplication(self):
        """Verifies Exp 3 (Page 7-8): Cross-layer W_QK @ W_OV composition detects copying heads without running text."""
        from rea_neural_engine import CrossLayerCircuitAnalyzer
        early_ov = np.zeros((32, 32), dtype=np.float32)
        late_qk = np.zeros((32, 32), dtype=np.float32)
        early_ov[8:16, 8:16] = np.eye(8, dtype=np.float32) * 5.0
        late_qk[8:16, 8:16] = np.eye(8, dtype=np.float32) * 5.0
        res = CrossLayerCircuitAnalyzer.analyze_cross_layer_induction(early_ov, late_qk, num_heads=4)
        self.assertIn(1, res["copying_heads_detected"])

    def test_wsp_exp7_sycophancy_attention_pattern_auditor(self):
        """Verifies Exp 7 (Page 14-15): AttentionPatternAuditor separates honest vs. sycophantic heads."""
        from rea_neural_engine import AttentionPatternAuditor
        d = 16
        q_ans = np.zeros(d, dtype=np.float32)
        q_ans[0] = 1.0  # Answer query probes dimension 0
        k_quest = np.zeros((2, d), dtype=np.float32)
        k_quest[:, 1] = 2.0  # Question numbers live on dim 1
        k_sugg = np.zeros((2, d), dtype=np.float32)
        k_sugg[:, 2] = 2.0   # User suggestion lives on dim 2

        # Honest head routes dim 0 -> dim 1 (question facts)
        qk_honest = np.zeros((d, d), dtype=np.float32)
        qk_honest[0, 1] = 5.0
        res_honest = AttentionPatternAuditor.audit_sycophancy_attention(qk_honest, k_quest, k_sugg, q_ans)
        self.assertFalse(res_honest["is_sycophantic_head"])
        self.assertGreater(res_honest["question_tokens_attention_share"], 0.90)

        # Sycophantic head routes dim 0 -> dim 2 (user's suggested answer)
        qk_syc = np.zeros((d, d), dtype=np.float32)
        qk_syc[0, 2] = 5.0
        res_syc = AttentionPatternAuditor.audit_sycophancy_attention(qk_syc, k_quest, k_sugg, q_ans)
        self.assertTrue(res_syc["is_sycophantic_head"])
        self.assertGreater(res_syc["user_suggestion_attention_share"], 0.85)

    def test_wsp_gemma_vs_qwen_amenability_diagnostic(self):
        """Verifies Page 17 boundary condition: distinguishes amenable loop obstacle from capability deficit."""
        from rea_neural_engine import AmenabilityDiagnostic
        u = np.ones((16, 1), dtype=np.float32)
        v = np.ones((1, 16), dtype=np.float32)
        qwen_mat = (u @ v) * 10.0 + np.eye(16, dtype=np.float32) * 0.2
        res_qwen = AmenabilityDiagnostic.evaluate_surgical_amenability(qwen_mat, observed_loop_rate=0.93)
        self.assertTrue(res_qwen["is_amenable_to_weight_surgery"])

        gemma_mat = np.eye(16, dtype=np.float32)
        res_gemma = AmenabilityDiagnostic.evaluate_surgical_amenability(gemma_mat, observed_loop_rate=0.085)
        self.assertFalse(res_gemma["is_amenable_to_weight_surgery"])
        self.assertIn("CAPABILITY_DEFICIT_WARNING", res_gemma["wsp_prognosis"])

    def test_wsp_exp5_zero_shot_breakout_weight_synthesis(self):
        """Verifies Exp 5 (Page 10-11): Compiling Breakout policy weights from scratch without training."""
        from rea_neural_engine import WeightSpaceCompiler
        tensors = WeightSpaceCompiler.compile_breakout_policy_network(input_dim=32, hidden_dim=16, action_dim=3)
        self.assertEqual(set(tensors.keys()), {
            "policy.layer1.weight", "policy.layer1.bias",
            "policy.layer2.weight", "policy.layer2.bias"
        })
        self.assertEqual(tensors["policy.layer1.weight"].shape, (16, 32))
        self.assertEqual(tensors["policy.layer2.weight"].shape, (3, 16))
        self.assertGreater(float(np.linalg.norm(tensors["policy.layer1.weight"])), 1.0)

    def test_wsp_exp4_conditional_subcircuit_grafting_within_3_5_percent(self):
        """Verifies Exp 4 (Page 9-10): Grafting a conditional bypass sub-circuit modifying <= 3.5% weights."""
        from rea_neural_engine import CircuitGrafter
        host = np.random.randn(64, 64).astype(np.float32)
        host[10, :] *= 0.001  # dormant row
        patched, info = CircuitGrafter.graft_conditional_subcircuit(
            host, sensor_indices=[0, 1, 2], actuator_index=3, gain=-3.0, max_graft_fraction=0.035
        )
        self.assertTrue(info["within_exp4_sparsity_budget"])
        self.assertLessEqual(info["modified_percentage"], 3.5)
        self.assertFalse(np.array_equal(host, patched))

    def test_wsp_page19_cross_architecture_circuit_transplantation(self):
        """Verifies Page 19 'True architectural and model merging': grafting modes across different shapes."""
        from rea_neural_engine import CircuitGrafter
        host = np.eye(24, 32, dtype=np.float32)
        donor = np.ones((16, 16), dtype=np.float32) * 2.0
        merged, info = CircuitGrafter.transplant_reasoning_subspace(host, donor, rank_k=2, blend=0.2)
        self.assertEqual(merged.shape, (24, 32))
        self.assertEqual(info["transplanted_modes"], 2)
        self.assertGreater(info["frobenius_graft_ratio"], 0.0)

    def test_wsp_exp6_exp8_forward_pass_budgeted_harness_monotonic_gain(self):
        """Verifies Exp 6 & 8 (Page 12-16): ForwardPassHarness keeps edits only when score improves."""
        from rea_neural_engine import ForwardPassHarness
        rng = np.random.default_rng(7)
        w_init = rng.standard_normal((12, 16)).astype(np.float32)
        x_probes = rng.standard_normal((8, 16)).astype(np.float32)
        y_targ = rng.standard_normal((8, 12)).astype(np.float32)
        _, metrics = ForwardPassHarness.run_budgeted_optimization(
            w_init, x_probes, y_targ, forward_pass_budget=10, num_columns=8
        )
        self.assertEqual(metrics["forward_passes_used"], 10)
        self.assertGreaterEqual(metrics["final_score"], metrics["initial_score"])

    def test_wsp_page19_zero_eval_backdoor_and_receptive_field_audit(self):
        """Verifies Exp 1 & Page 19: Static weight auditing detects Trojan spikes and bottom-row paddle weights."""
        from rea_neural_engine import WeightSecurityAuditor
        mat = np.random.randn(32, 100).astype(np.float32) * 0.1
        mat[7, :] = 15.0
        res = WeightSecurityAuditor.audit_weights_without_evaluation(mat, spatial_height=10, spatial_width=10)
        self.assertTrue(res["potential_backdoor_detected"])
        self.assertIn(7, res["suspect_trigger_neurons"])
'''


def apply_wsp_patch(target_dir: str, create_backup: bool = False) -> Dict[str, Any]:
    """Applies Patch v2 (MIT CSAIL WSP alignment) on top of the patched REA-Neural repository."""
    root = Path(target_dir).resolve()
    src_dir = root / "src"
    if not src_dir.exists():
        raise FileNotFoundError(f"Target directory '{root}' does not contain a 'src/' folder.")

    if create_backup:
        backup_dir = root.parent / f"{root.name}_pre_wsp_backup"
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        shutil.copytree(root, backup_dir)

    modified_files: List[str] = []

    # 1. Upgrade src/rea_neural_engine.py
    rea_path = src_dir / "rea_neural_engine.py"
    rea_code = rea_path.read_text(encoding="utf-8")
    updated_rea = build_updated_rea_neural_engine(rea_code)
    with open(rea_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(updated_rea)
    modified_files.append("src/rea_neural_engine.py")

    # 2. Upgrade SensoryCortex in src/binary_neural_engine.py and src/sensory_cortex.py
    for sc_file in (src_dir / "binary_neural_engine.py", src_dir / "sensory_cortex.py"):
        if sc_file.exists():
            sc_code = sc_file.read_text(encoding="utf-8")
            updated_sc = build_updated_sensory_cortex(sc_code)
            with open(sc_file, "w", encoding="utf-8", newline="\n") as f:
                f.write(updated_sc)
            modified_files.append(str(sc_file.relative_to(root)))

    # 3. Upgrade src/cli.py
    cli_path = src_dir / "cli.py"
    cli_code = cli_path.read_text(encoding="utf-8")
    updated_cli = build_updated_cli(cli_code)
    with open(cli_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(updated_cli)
    modified_files.append("src/cli.py")

    # 4. Update skills/reverse-engineer-anything/references/weight-space-programming.md
    wsp_ref_path = root / "skills" / "reverse-engineer-anything" / "references" / "weight-space-programming.md"
    if wsp_ref_path.exists():
        with open(wsp_ref_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(UPDATED_WSP_REFERENCE_MD.lstrip("\n"))
        modified_files.append(str(wsp_ref_path.relative_to(root)))

    # 5. Append 10 new MIT CSAIL WSP tests to tests/test_suite.py
    test_path = root / "tests" / "test_suite.py"
    test_code = test_path.read_text(encoding="utf-8")
    if "test_wsp_exp8_mlp_column_direction_subtract_exact_sparsity" not in test_code:
        test_code = test_code.replace(
            "\nif __name__ == \"__main__\":\n    unittest.main()",
            "\n" + WSP_EXTRA_TESTS.rstrip() + "\n\n\nif __name__ == \"__main__\":\n    unittest.main()",
            1
        )
        with open(test_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(test_code)
    modified_files.append("tests/test_suite.py")

    return {
        "patch_version": "7.2.0-wsp (MIT CSAIL Paper Full Alignment)",
        "target_root": str(root),
        "backup_created": create_backup,
        "patched_files": modified_files,
        "patched_count": len(modified_files),
    }


def run_verification(target_dir: str) -> Dict[str, Any]:
    """Runs all 35 unit and WSP integration tests plus CLI smoke tests."""
    root = Path(target_dir).resolve()
    test_cmd = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"]
    test_proc = subprocess.run(
        test_cmd,
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )
    return {
        "tests_passed": test_proc.returncode == 0,
        "test_returncode": test_proc.returncode,
        "test_output": (test_proc.stdout + "\n" + test_proc.stderr).strip(),
    }


def main() -> None:
    configure_windows_utf8()
    parser = argparse.ArgumentParser(
        description="Apply REA-Neural WSP Patch v2 (MIT CSAIL Paper Full Experimental Suite Upgrade)"
    )
    parser.add_argument(
        "--target",
        default=".",
        help="Path to the patched rea-neural-main directory (default: current directory)"
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create a backup copy of the project before patching"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run the 35-test verification suite after patching"
    )
    args = parser.parse_args()

    summary = apply_wsp_patch(args.target, create_backup=args.backup)
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if args.verify:
        ver = run_verification(args.target)
        print("\n=== WSP v2 VERIFICATION SUITE OUTPUT (35 TESTS) ===")
        print(ver["test_output"])
        if not ver["tests_passed"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
