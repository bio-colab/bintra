"""Token & Cost Telemetry for Bintra AI Agent Operations.

Provides deterministic token estimation, multi-model USD cost calculation,
JSON serialization waste measurement, and session-level budget tracking.
"""

from __future__ import annotations

import json
import math
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


# Pricing in USD per 1,000,000 tokens (input, output)
MODEL_PRICING_PER_1M: Dict[str, Tuple[float, float]] = {
    "claude-3.5-sonnet": (3.00, 15.00),
    "claude-3.7-sonnet": (3.00, 15.00),
    "claude-opus-4": (15.00, 75.00),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "gemini-2.5-flash": (0.15, 0.60),
}

DEFAULT_MODEL = "claude-3.5-sonnet"

_TOKEN_SPLIT_RE = re.compile(r"\w+|[^\w\s]|\n+", re.UNICODE)


def estimate_tokens(data: Any) -> int:
    """Estimate BPE token count for text or JSON-serializable objects.

    Uses tiktoken (cl100k_base) when installed; otherwise falls back to a
    calibrated structural estimator (~3.7 chars/token for JSON/code, counting
    punctuation and whitespace clusters accurately).
    """
    if data is None:
        return 0
    if isinstance(data, str):
        text = data
    else:
        text = json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)
    if not text:
        return 0

    try:
        import tiktoken  # type: ignore

        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        pass

    # Calibrated fallback: split words/punctuation/newlines and account for long identifiers/hex
    chunks = _TOKEN_SPLIT_RE.findall(text)
    est = 0.0
    for ch in chunks:
        if ch.startswith("\n"):
            est += 0.5
        elif len(ch) <= 4:
            est += 1.0
        else:
            est += math.ceil(len(ch) / 3.8)
    # Leading/trailing spaces inside indent=2 lines add ~1 token per 4 spaces
    space_runs = len(text) - len(text.replace("  ", " "))
    est += space_runs * 0.25
    return max(1, int(round(est)))


def estimate_cost_usd(
    tokens: int,
    model: str = DEFAULT_MODEL,
    direction: str = "input",
) -> float:
    """Calculate estimated USD cost for a given token count and model."""
    in_rate, out_rate = MODEL_PRICING_PER_1M.get(model, MODEL_PRICING_PER_1M[DEFAULT_MODEL])
    rate = out_rate if direction == "output" else in_rate
    return round((max(0, tokens) / 1_000_000.0) * rate, 8)


def compact_json(data: Any) -> str:
    """Serialize data as minimal-token compact JSON."""
    return json.dumps(data, separators=(",", ":"), ensure_ascii=False, default=str)


def pretty_json(data: Any) -> str:
    """Serialize data as pretty-printed JSON (indent=2)."""
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def measure_serialization_waste(data: Any) -> Dict[str, Any]:
    """Compare pretty-printed vs compact JSON byte and token footprint."""
    pretty_str = pretty_json(data)
    compact_str = compact_json(data)
    pretty_tok = estimate_tokens(pretty_str)
    compact_tok = estimate_tokens(compact_str)
    saved_tok = max(0, pretty_tok - compact_tok)
    pct = round((saved_tok / pretty_tok) * 100.0, 2) if pretty_tok > 0 else 0.0
    return {
        "pretty_chars": len(pretty_str),
        "compact_chars": len(compact_str),
        "pretty_tokens": pretty_tok,
        "compact_tokens": compact_tok,
        "whitespace_waste_tokens": saved_tok,
        "whitespace_waste_pct": pct,
    }


def compact_tool_schema(tool_def: Dict[str, Any]) -> Dict[str, Any]:
    """Return a token-optimized MCP tool definition preserving full type/enum/required fidelity."""
    desc = tool_def.get("description", "").strip()
    # Keep first sentence (up to 110 chars) for crisp intent without repetitive prose
    first_sentence = desc.split(". ")[0].rstrip(".")
    if len(first_sentence) > 110:
        first_sentence = first_sentence[:107].rstrip() + "..."

    schema = tool_def.get("inputSchema", {})
    compact_props: Dict[str, Any] = {}
    for pname, pspec in schema.get("properties", {}).items():
        entry: Dict[str, Any] = {}
        for keep_key in ("type", "enum", "default", "items"):
            if keep_key in pspec:
                entry[keep_key] = pspec[keep_key]
        compact_props[pname] = entry

    compact_schema: Dict[str, Any] = {
        "type": schema.get("type", "object"),
        "properties": compact_props,
    }
    if "required" in schema:
        compact_schema["required"] = list(schema["required"])
    if "additionalProperties" in schema:
        compact_schema["additionalProperties"] = schema["additionalProperties"]

    return {
        "name": tool_def["name"],
        "description": first_sentence,
        "inputSchema": compact_schema,
    }


def prune_payload(
    data: Any,
    max_list_items: int = 25,
    drop_empty: bool = False,
    max_str_len: int = 0,
) -> Tuple[Any, Dict[str, int]]:
    """Bound large lists/strings in tool outputs while recording truncation metadata.

    Returns (pruned_data, truncation_stats) so callers/agents always know exact
    original counts when lists are capped.
    """
    stats: Dict[str, int] = {"lists_truncated": 0, "items_omitted": 0, "strings_truncated": 0}

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: Dict[str, Any] = {}
            for k, v in node.items():
                if drop_empty and (v is None or v == [] or v == {} or v == ""):
                    continue
                if isinstance(v, list) and max_list_items > 0 and len(v) > max_list_items:
                    omitted = len(v) - max_list_items
                    stats["lists_truncated"] += 1
                    stats["items_omitted"] += omitted
                    out[k] = [_walk(item) for item in v[:max_list_items]]
                    out[f"_{k}_truncated"] = {
                        "total": len(v),
                        "shown": max_list_items,
                        "omitted": omitted,
                    }
                else:
                    out[k] = _walk(v)
            return out
        elif isinstance(node, list):
            if max_list_items > 0 and len(node) > max_list_items:
                stats["lists_truncated"] += 1
                stats["items_omitted"] += len(node) - max_list_items
                return [_walk(item) for item in node[:max_list_items]]
            return [_walk(item) for item in node]
        elif isinstance(node, str) and max_str_len > 0 and len(node) > max_str_len:
            stats["strings_truncated"] += 1
            return node[:max_str_len] + f"...[+{len(node) - max_str_len} chars]"
        return node

    return _walk(data), stats


class TokenSessionTracker:
    """Tracks per-call and cumulative token & USD cost across an agent session."""

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = model if model in MODEL_PRICING_PER_1M else DEFAULT_MODEL
        self.schema_tokens_per_turn: int = 0
        self.baseline_schema_tokens_per_turn: int = 0
        self.calls: List[Dict[str, Any]] = []

    def record_schema_footprint(self, actual_tokens: int, baseline_tokens: Optional[int] = None) -> None:
        self.schema_tokens_per_turn = max(0, int(actual_tokens))
        self.baseline_schema_tokens_per_turn = max(
            self.schema_tokens_per_turn,
            int(baseline_tokens if baseline_tokens is not None else actual_tokens),
        )

    def record_tool_call(
        self,
        tool_name: str,
        args_text: str,
        output_text: str,
        baseline_output_tokens: Optional[int] = None,
    ) -> Dict[str, Any]:
        in_tok = estimate_tokens(args_text)
        out_tok = estimate_tokens(output_text)
        base_out = max(out_tok, int(baseline_output_tokens)) if baseline_output_tokens is not None else out_tok
        saved_out = max(0, base_out - out_tok)
        cost_usd = estimate_cost_usd(in_tok + out_tok, model=self.model, direction="input")
        entry = {
            "tool": tool_name,
            "args_tokens": in_tok,
            "output_tokens": out_tok,
            "baseline_output_tokens": base_out,
            "saved_output_tokens": saved_out,
            "estimated_context_cost_usd": cost_usd,
        }
        self.calls.append(entry)
        return entry

    def summary(self, turns: Optional[int] = None) -> Dict[str, Any]:
        n_turns = turns if turns is not None else max(1, len(self.calls))
        total_args = sum(c["args_tokens"] for c in self.calls)
        total_out = sum(c["output_tokens"] for c in self.calls)
        total_base_out = sum(c["baseline_output_tokens"] for c in self.calls)
        schema_actual = self.schema_tokens_per_turn * n_turns
        schema_base = self.baseline_schema_tokens_per_turn * n_turns
        total_actual = schema_actual + total_args + total_out
        total_baseline = schema_base + total_args + total_base_out
        saved_tokens = max(0, total_baseline - total_actual)
        savings_pct = round((saved_tokens / total_baseline) * 100.0, 2) if total_baseline > 0 else 0.0

        actual_cost = estimate_cost_usd(total_actual, model=self.model, direction="input")
        baseline_cost = estimate_cost_usd(total_baseline, model=self.model, direction="input")
        saved_cost = round(max(0.0, baseline_cost - actual_cost), 8)

        return {
            "model": self.model,
            "calls_count": len(self.calls),
            "turns_counted": n_turns,
            "schema_tokens_per_turn": self.schema_tokens_per_turn,
            "baseline_schema_tokens_per_turn": self.baseline_schema_tokens_per_turn,
            "tool_args_tokens": total_args,
            "tool_output_tokens": total_out,
            "baseline_tool_output_tokens": total_base_out,
            "total_tokens": total_actual,
            "baseline_total_tokens": total_baseline,
            "saved_tokens": saved_tokens,
            "savings_pct": savings_pct,
            "estimated_cost_usd": actual_cost,
            "baseline_cost_usd": baseline_cost,
            "saved_cost_usd": saved_cost,
        }
