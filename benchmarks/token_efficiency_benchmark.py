"""Before-vs-After Token Efficiency & Quality Parity Benchmark for Bintra.

Measures actual token consumption, USD cost, and analytical quality parity
before and after the two-step token optimization patch across a realistic
multi-turn AI agent reverse-engineering session.
"""

from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
from typing import Any, Dict

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(REPO_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mcp_server import BintraMcpServer
from token_telemetry import estimate_cost_usd, estimate_tokens, MODEL_PRICING_PER_1M


def _build_sample_pe(path: str) -> None:
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 240, 0x22)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    struct.pack_into("<I", opt, 16, 0x1000)
    struct.pack_into("<Q", opt, 24, 0x140000000)
    struct.pack_into("<I", opt, 32, 0x1000)
    struct.pack_into("<I", opt, 36, 0x200)
    struct.pack_into("<I", opt, 56, 0x2000)
    struct.pack_into("<I", opt, 60, 0x200)
    struct.pack_into("<H", opt, 68, 3)
    struct.pack_into("<I", opt, 108, 16)
    sec = bytearray(40)
    sec[0:5] = b".text"
    struct.pack_into("<IIIIIIHHI", sec, 8, 0x100, 0x1000, 0x400, 0x200, 0, 0, 0, 0, 0x60000020)
    code = (b"\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x83\xc4\x20\x5d\xc3" * 40)[:0x400]
    with open(path, "wb") as f:
        f.write(dos + pe_sig + coff + opt + sec + b"\x00" * (0x200 - (64 + 4 + 20 + 240 + 40)) + code)


def _build_sample_ghidra_export(path: str, num_funcs: int = 45) -> None:
    funcs = []
    for fi in range(num_funcs):
        blocks = []
        for bi in range(6):
            ops = []
            for oi in range(6):
                ops.append({
                    "mnemonic": ["COPY", "INT_ADD", "LOAD", "STORE", "CALL", "RETURN"][oi % 6],
                    "address": hex(0x140001000 + fi * 0x200 + bi * 0x20 + oi * 4),
                    "seq": oi,
                    "inputs": [{"space": "register", "offset": 0, "size": 8, "def_seq": max(0, oi - 1)}],
                    "output": {"space": "register", "offset": 8, "size": 8, "def_seq": oi},
                })
            blocks.append({"id": f"bb_{bi}", "start": hex(0x140001000 + fi * 0x200 + bi * 0x20), "succs": [f"bb_{(bi + 1) % 6}"], "ops": ops})
        funcs.append({
            "name": f"FUN_{0x140001000 + fi * 0x200:x}",
            "entry": hex(0x140001000 + fi * 0x200),
            "calls": [f"FUN_{0x140001000 + ((fi + 1) % num_funcs) * 0x200:x}"],
            "blocks": blocks,
            "pcode_ops": [op for b in blocks for op in b["ops"]],
        })
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"program": "target.exe", "arch": "x86:LE:64:default", "functions": funcs}, f)


def run_benchmark(model: str = "claude-3.5-sonnet") -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        pe_path = os.path.join(td, "sample.exe")
        ghidra_path = os.path.join(td, "ghidra_export.json")
        _build_sample_pe(pe_path)
        _build_sample_ghidra_export(ghidra_path, num_funcs=45)

        # --- BASELINE (Pre-Patch: pretty tools/list, all 40 schemas, full capabilities, unpruned payloads, CLI indent=2) ---
        srv_base = BintraMcpServer(workspace_root=td)
        base_tools = srv_base.handle_tools_list({"compact": False, "profile": "all"})["tools"]
        base_schema_tok = estimate_tokens(json.dumps(base_tools, indent=2))

        base_calls = {}
        for tname, targs in [
            ("bintra_list_capabilities", {}),
            ("bintra_inspect_binary", {"file_path": pe_path}),
            ("bintra_pe_deep_forensics", {"file_path": pe_path}),
            ("bintra_sensory_audit", {"file_path": pe_path}),
            ("bintra_ghidra_analyze", {"input_file": ghidra_path}),
            ("bintra_ghidra_call_graph", {"export_path": ghidra_path}),
        ]:
            raw = srv_base.dispatch_tool(tname, targs)
            pretty_txt = json.dumps(raw, indent=2, ensure_ascii=False)
            base_calls[tname] = {"data": raw, "tokens": estimate_tokens(pretty_txt)}

        env = dict(os.environ, PYTHONUTF8="1")
        cli_base = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "sense", "--hex", "554889e54883ec205dc3"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, check=True,
        )
        cli_base_tok = estimate_tokens(cli_base.stdout)

        # --- PATCHED (Step 1 + Step 2: compact static/ghidra profile schemas, compact capabilities, pruned/summary payloads, CLI --compact) ---
        srv_opt = BintraMcpServer(workspace_root=td)
        opt_tools = srv_opt.handle_tools_list({"compact": True, "profile": "static"})["tools"]
        opt_schema_tok = estimate_tokens(json.dumps(opt_tools, separators=(",", ":")))

        opt_calls = {}
        for tname, targs in [
            ("bintra_list_capabilities", {"compact": True}),
            ("bintra_inspect_binary", {"file_path": pe_path, "compact": True}),
            ("bintra_pe_deep_forensics", {"file_path": pe_path, "compact": True}),
            ("bintra_sensory_audit", {"file_path": pe_path, "compact": True, "summary_only": True}),
            ("bintra_ghidra_analyze", {"input_file": ghidra_path, "compact": True}),
            ("bintra_ghidra_call_graph", {"export_path": ghidra_path, "compact": True, "summary_only": True}),
        ]:
            res = srv_opt.handle_tools_call({"name": tname, "arguments": targs})
            txt = res["content"][0]["text"]
            opt_calls[tname] = {"data": json.loads(txt), "tokens": estimate_tokens(txt)}

        cli_opt = subprocess.run(
            [sys.executable, os.path.join(SRC_DIR, "cli.py"), "sense", "--hex", "554889e54883ec205dc3", "--compact"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, check=True,
        )
        cli_opt_tok = estimate_tokens(cli_opt.stdout)

        # --- QUALITY PARITY ASSERTIONS ---
        parity_checks = {
            "pe_arch_match": base_calls["bintra_inspect_binary"]["data"].get("architecture") == opt_calls["bintra_inspect_binary"]["data"].get("architecture"),
            "sensory_efficiency_match": base_calls["bintra_sensory_audit"]["data"].get("overall_sensory_efficiency") == opt_calls["bintra_sensory_audit"]["data"].get("overall_sensory_efficiency"),
            "sensory_count_match": base_calls["bintra_sensory_audit"]["data"].get("active_senses_count") == opt_calls["bintra_sensory_audit"]["data"].get("active_senses_count"),
            "ghidra_funcs_match": base_calls["bintra_ghidra_call_graph"]["data"].get("functions_indexed") == opt_calls["bintra_ghidra_call_graph"]["data"].get("functions_indexed"),
            "ghidra_edges_match": base_calls["bintra_ghidra_call_graph"]["data"].get("call_edges_count") == opt_calls["bintra_ghidra_call_graph"]["data"].get("call_edges_count"),
            "cli_sense_score_match": json.loads(cli_base.stdout).get("overall_sensory_efficiency") == json.loads(cli_opt.stdout).get("overall_sensory_efficiency"),
        }
        all_parity_ok = all(parity_checks.values())

        turns = 6
        base_total_tokens = (base_schema_tok * turns) + sum(v["tokens"] for v in base_calls.values()) + cli_base_tok
        opt_total_tokens = (opt_schema_tok * turns) + sum(v["tokens"] for v in opt_calls.values()) + cli_opt_tok
        saved_tokens = base_total_tokens - opt_total_tokens
        savings_pct = round((saved_tokens / base_total_tokens) * 100.0, 2) if base_total_tokens > 0 else 0.0

        pricing_comparison = {}
        for m in ("claude-3.5-sonnet", "gpt-4o", "gemini-2.5-pro"):
            b_usd = estimate_cost_usd(base_total_tokens, model=m, direction="input")
            o_usd = estimate_cost_usd(opt_total_tokens, model=m, direction="input")
            pricing_comparison[m] = {
                "baseline_session_usd": b_usd,
                "patched_session_usd": o_usd,
                "saved_per_1000_sessions_usd": round((b_usd - o_usd) * 1000.0, 2),
            }

        return {
            "status": "ok",
            "quality_parity_passed": all_parity_ok,
            "parity_checks": parity_checks,
            "session_turns": turns,
            "schema_tokens_per_turn": {"before": base_schema_tok, "after": opt_schema_tok, "saved_pct": round((1 - opt_schema_tok / base_schema_tok) * 100, 2)},
            "per_operation_tokens": {
                k: {"before": base_calls[k]["tokens"], "after": opt_calls[k]["tokens"], "saved_pct": round((1 - opt_calls[k]["tokens"] / max(1, base_calls[k]["tokens"])) * 100, 2)}
                for k in base_calls
            } | {"cli_sense": {"before": cli_base_tok, "after": cli_opt_tok, "saved_pct": round((1 - cli_opt_tok / max(1, cli_base_tok)) * 100, 2)}},
            "session_totals": {
                "before_tokens": base_total_tokens,
                "after_tokens": opt_total_tokens,
                "saved_tokens": saved_tokens,
                "savings_pct": savings_pct,
            },
            "cost_comparison_usd": pricing_comparison,
        }


if __name__ == "__main__":
    report = run_benchmark()
    print(json.dumps(report, indent=2, ensure_ascii=False))
