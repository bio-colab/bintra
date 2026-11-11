"""Bintra vs OBS Studio — Axis A2 Ghidra Integration & High P-Code Runner.

Executes BINTRA-OBS-003 (Headless + Live Bridge Integration) and
BINTRA-OBS-004 (High P-Code Extraction: Level 1 Blind vs Level 2 PDB)
using real Ghidra analyzeHeadless and real Bintra Live Bridge JSON-RPC 2.0.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import pefile
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
GHIDRA_SCRIPTS_DIR = REPO_ROOT / "ghidra_scripts"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ghidra_live_bridge import GhidraLiveBridgeClient, GhidraLiveBridgeServer  # noqa: E402
from ghidra_pcode_vectorizer import (  # noqa: E402
    GhidraAnnotationPlanner,
    PcodeFunctionMatcher,
    PcodeVectorizer,
)

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
OBS_ROOT = PROGRAM_FILES / "obs-studio"
OBS_BIN_DIR = OBS_ROOT / "bin" / "64bit"
HOME_DIR = Path.home()


def locate_ghidra_dir() -> Optional[Path]:
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR") or os.environ.get("GHIDRA_HOME")
    candidates = []
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.extend([HOME_DIR / "tools" / "ghidra", Path(r"C:\ghidra")])
    for cand in candidates:
        if (cand / "support" / "analyzeHeadless.bat").exists():
            return cand
    return None


def sanitize_text(value: str) -> str:
    if not value:
        return value
    out = value
    for src, dst in [
        (str(REPO_ROOT), "<REPO_ROOT>"),
        (str(REPO_ROOT).lower(), "<REPO_ROOT>"),
        (str(OBS_ROOT), "%ProgramFiles%\\obs-studio"),
        (str(OBS_ROOT).lower(), "%ProgramFiles%\\obs-studio"),
        (str(HOME_DIR), "%USERPROFILE%"),
        (str(HOME_DIR).lower(), "%USERPROFILE%"),
    ]:
        out = out.replace(src, dst)
        out = out.replace(src.replace("\\", "/"), dst.replace("/", "/").replace("\\", "/"))
        out = out.replace(src.replace("\\", "\\\\"), dst.replace("\\", "\\\\"))
    return out


def sanitize_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, list):
        return [sanitize_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {sanitize_text(str(k)): sanitize_obj(v) for k, v in obj.items()}
    return obj


def write_evidence(filename: str, payload: Dict[str, Any]) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / filename
    out_path.write_text(
        json.dumps(sanitize_obj(payload), indent=2, default=str),
        encoding="utf-8",
    )
    return out_path


def _extract_entry_hex(binary_path: Path, length: int = 128) -> str:
    pe = pefile.PE(str(binary_path), fast_load=True)
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        off = pe.get_offset_from_rva(ep)
        return pe.__data__[off : off + length].hex()
    finally:
        pe.close()


def run_ghidra_pcode_extraction(
    ghidra_dir: Path,
    binary_src: Path,
    with_pdb: bool,
    project_name: str,
    script_name: str = "BintraGhidraBridge.java",
) -> Dict[str, Any]:
    """Run analyzeHeadless with Bintra Ghidra bridge script in isolated dirs."""
    headless_bat = ghidra_dir / "support" / "analyzeHeadless.bat"
    with tempfile.TemporaryDirectory(prefix=f"bintra_ghidra_{project_name}_") as work_str:
        work_dir = Path(work_str)
        bin_dir = work_dir / "target"
        proj_dir = work_dir / "proj"
        tmp_dir = work_dir / "tmp"
        bin_dir.mkdir(parents=True, exist_ok=True)
        proj_dir.mkdir(parents=True, exist_ok=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        copied_bin = bin_dir / binary_src.name
        shutil.copy2(binary_src, copied_bin)
        if with_pdb:
            pdb_src = binary_src.with_suffix(".pdb")
            if pdb_src.exists():
                shutil.copy2(pdb_src, bin_dir / pdb_src.name)

        env = os.environ.copy()
        env["TMP"] = str(tmp_dir)
        env["TEMP"] = str(tmp_dir)
        env["BINTRA_ROOT"] = str(REPO_ROOT)
        env["PYTHON_EXE"] = sys.executable

        cmd = [
            str(headless_bat),
            str(proj_dir),
            project_name,
            "-import",
            str(copied_bin),
            "-overwrite",
            "-scriptPath",
            str(GHIDRA_SCRIPTS_DIR),
            "-postScript",
            script_name,
        ]

        t0 = time.perf_counter()
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=240,
            env=env,
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        exp_files = sorted(tmp_dir.glob("bintra_*exp*.json")) or sorted(tmp_dir.glob("bintra_ghidra_export_*.json"))
        plan_files = sorted(tmp_dir.glob("bintra_*plan*.json"))

        exp_summary: Dict[str, Any] = {}
        raw_functions: List[Dict[str, Any]] = []
        planner_summary: Dict[str, Any] = {}
        if exp_files:
            exp_data = json.loads(exp_files[0].read_text(encoding="utf-8"))
            funcs = exp_data.get("functions", [])
            raw_functions = funcs
            unnamed = sum(1 for fn in funcs if str(fn.get("name", "")).startswith("FUN_"))
            thunks = sum(1 for fn in funcs if "thunk" in str(fn.get("name", "")).lower())
            named_non_fun = len(funcs) - unnamed
            total_ops = sum(len(fn.get("pcode_ops", [])) for fn in funcs)
            total_cfg_blocks = sum(len(fn.get("cfg_blocks", fn.get("blocks", []))) for fn in funcs)
            exp_summary = {
                "export_keys": list(exp_data.keys()),
                "program_name": exp_data.get("program_name"),
                "image_base": exp_data.get("image_base"),
                "functions_count": len(funcs),
                "named_or_exported_count": named_non_fun,
                "unnamed_fun_prefix_count": unnamed,
                "thunk_named_count": thunks,
                "total_high_pcode_ops": total_ops,
                "total_cfg_blocks": total_cfg_blocks,
                "sample_functions": [
                    {
                        "name": fn.get("name"),
                        "entry_point": fn.get("entry_point"),
                        "size": fn.get("size"),
                        "pcode_ops_count": len(fn.get("pcode_ops", [])),
                    }
                    for fn in funcs[:12]
                ],
            }

            # Evaluate offline analyzer + CLI ghidra-analyze into authorized ~/.bintra/workspace
            in_mem_plan = GhidraAnnotationPlanner.analyze_program_export(exp_data)
            ws_dir = HOME_DIR / ".bintra" / "workspace"
            ws_dir.mkdir(parents=True, exist_ok=True)
            ws_plan_path = ws_dir / f"obs_bench_plan_{project_name}.json"
            try:
                cli_an = subprocess.run(
                    ["bintra", "ghidra-analyze", "--input", str(exp_files[0]), "--output", str(ws_plan_path)],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                planner_summary = {
                    "in_memory_keys": list(in_mem_plan.keys()),
                    "rename_actions_count": len(in_mem_plan.get("rename_actions", [])),
                    "comment_actions_count": len(in_mem_plan.get("comment_actions", [])),
                    "deobfuscation_findings": in_mem_plan.get("deobfuscation_summary") or len(in_mem_plan.get("obfuscated_functions", [])),
                    "cli_ghidra_analyze_with_ws_output_rc": cli_an.returncode,
                    "ws_plan_written": ws_plan_path.exists(),
                    "rename_actions_sample": in_mem_plan.get("rename_actions", [])[:6],
                    "comment_actions_sample": in_mem_plan.get("comment_actions", [])[:6],
                }
            finally:
                if ws_plan_path.exists():
                    ws_plan_path.unlink()

        plan_summary: Dict[str, Any] = {}
        if plan_files:
            plan_text = plan_files[0].read_text(encoding="utf-8")
            try:
                plan_data = json.loads(plan_text)
                plan_summary = {
                    "keys": list(plan_data.keys()),
                    "rename_actions_count": len(plan_data.get("rename_actions", [])),
                    "comment_actions_count": len(plan_data.get("comment_actions", [])),
                }
            except Exception:
                plan_summary = {"raw_non_json_head": plan_text[:200]}

        return {
            "binary": binary_src.name,
            "script": script_name,
            "mode": "Level2_SymbolAssisted_PDB" if with_pdb else "Level1_Blind_NoPDB",
            "returncode": proc.returncode,
            "elapsed_ms": elapsed_ms,
            "export_found": bool(exp_files),
            "internal_java_subprocess_plan_created": bool(plan_files),
            "export_summary": exp_summary,
            "downstream_planner_summary": planner_summary,
            "internal_plan_summary": plan_summary,
            "stdout_tail": "\n".join(proc.stdout.splitlines()[-35:]),
            "stderr_tail": "\n".join(proc.stderr.splitlines()[-20:]),
            "functions_raw_for_matching": raw_functions,
        }


def run_poc_003(ghidra_dir: Path) -> Dict[str, Any]:
    obs_frontend = OBS_BIN_DIR / "obs-frontend-api.dll"

    # 1. Auto-discovery check without GHIDRA_INSTALL_DIR
    with tempfile.TemporaryDirectory(prefix="bintra_ghidra_autodisc_") as tmp_str:
        blind_copy = Path(tmp_str) / obs_frontend.name
        shutil.copy2(obs_frontend, blind_copy)
        clean_env = os.environ.copy()
        clean_env.pop("GHIDRA_INSTALL_DIR", None)
        clean_env.pop("GHIDRA_HOME", None)
        auto_proc = subprocess.run(
            ["bintra", "ghidra-headless", "--file", str(blind_copy)],
            capture_output=True,
            text=True,
            timeout=20,
            env=clean_env,
        )

        # 2. Real CLI `bintra ghidra-headless` executing BintraGhidraBridge.java (Level 1 Blind)
        proj_dir = Path(tmp_str) / "ghidra_proj"
        proj_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.perf_counter()
        java_proc = subprocess.run(
            [
                "bintra",
                "ghidra-headless",
                "--file",
                str(blind_copy),
                "--ghidra-path",
                str(ghidra_dir),
                "--project-dir",
                str(proj_dir),
                "--project-name",
                "BintraObsFrontendJava",
            ],
            capture_output=True,
            text=True,
            timeout=240,
        )
        java_ms = round((time.perf_counter() - t0) * 1000, 2)
        gpr_exists = (proj_dir / "BintraObsFrontendJava.gpr").exists()

    # 3. Real GhidraLiveBridgeServer + GhidraLiveBridgeClient JSON-RPC 2.0 round-trip
    ep_hex = _extract_entry_hex(obs_frontend, 64)
    server = GhidraLiveBridgeServer(port=0)
    bridge_started = server.start(publish_temp_marker=False)
    redacted_start = {k: ("<REDACTED>" if k == "auth_token" else v) for k, v in bridge_started.items()}
    live_bridge_checks: Dict[str, Any] = {"bridge_started": redacted_start}
    try:
        url = bridge_started["bridge_url"]
        token = bridge_started["auth_token"]

        # Auth fail-closed test on protected RPC method (ghidra.poll_commands with wrong token)
        req_poll = urllib.request.Request(
            url,
            data=json.dumps({"jsonrpc": "2.0", "method": "ghidra.poll_commands", "params": {}, "id": 1}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Bintra-Auth-Token": "wrong-token"},
        )
        unauth_poll_rpc = json.loads(urllib.request.urlopen(req_poll, timeout=3.0).read().decode("utf-8"))
        live_bridge_checks["unauthorized_protected_rpc_response"] = unauth_poll_rpc

        client = GhidraLiveBridgeClient(bridge_url=url, auth_token=token)
        reg = client.register_client(
            program_name="obs-frontend-api.dll",
            image_base="0x180000000",
            architecture="x86_64",
            ghidra_version="12.1.4",
        )
        deob_rpc = client.call_rpc("bintra.deobfuscate_function", {"hex_bytes": ep_hex})
        match_rpc = client.call_rpc("bintra.match_functions", {"hex1": ep_hex, "hex2": ep_hex})

        # Queue annotations using explicit RVA vs VA address spaces
        vad_inj = client.inject_vad_snapshot(
            {
                "pid": 99999,
                "regions": [
                    {
                        "base_address": "0x180001000",
                        "size": 4096,
                        "classification": "IMAGE",
                        "protection": "PAGE_EXECUTE_READ",
                        "rva": "0x1000",
                        "module_name": "obs-frontend-api.dll",
                    }
                ],
                "summary": {"total_regions": 1, "wx_anomalies": 0},
            }
        )
        struct_inj = client.inject_structure_dissection(
            {
                "base_address": "0x1000",
                "address_space": "rva",
                "structure_name": "ObsFrontendCallbacks",
                "size_analyzed": 16,
                "c_declaration": "struct ObsFrontendCallbacks { void* vptr; uint32 flags; };",
                "fields": [
                    {"offset": 0, "inferred_type": "void* / Pointer", "value": "0x180002000", "confidence": 0.9},
                    {"offset": 8, "inferred_type": "uint32", "value": 32, "confidence": 0.8},
                ],
            }
        )
        ptr_inj = client.inject_pointer_chains(
            {
                "target_address": "0x180003000",
                "address_space": "va",
                "paths": [
                    {
                        "base_module": "obs-frontend-api.dll",
                        "base_rva": "0x1234",
                        "depth": 2,
                        "offsets": [16],
                        "expression": '"obs-frontend-api.dll"+0x1234 -> [+0x10]',
                    }
                ],
            }
        )
        polled = client.poll_commands()
        polled_after_drain = client.poll_commands()

        live_bridge_checks.update(
            {
                "register_client": reg,
                "rpc_deobfuscate_keys": list(deob_rpc.keys()) if isinstance(deob_rpc, dict) else None,
                "rpc_match_similarity": match_rpc.get("cosine_similarity") if isinstance(match_rpc, dict) else None,
                "vad_inject": vad_inj,
                "struct_inject": struct_inj,
                "pointer_inject": ptr_inj,
                "polled_commands_count": len(polled.get("commands", [])),
                "polled_actions": [
                    {
                        "action": c.get("action"),
                        "address": c.get("details", {}).get("address"),
                        "address_space": c.get("details", {}).get("address_space"),
                    }
                    for c in polled.get("commands", [])
                ],
                "queue_drained_count": len(polled_after_drain.get("commands", [])),
            }
        )
    finally:
        server.stop()

    # 4. Syntax check on BintraLiveBridgeService.py for Jython 2.7 compatibility note
    live_service_path = GHIDRA_SCRIPTS_DIR / "BintraLiveBridgeService.py"
    live_service_text = live_service_path.read_text(encoding="utf-8")
    uses_fstrings = 'f"' in live_service_text or "f'" in live_service_text
    py3_compiles = True
    try:
        py_compile.compile(str(live_service_path), doraise=True)
    except Exception:
        py3_compiles = False

    payload = {
        "test_id": "BINTRA-OBS-003",
        "ghidra_version_dir": ghidra_dir.name,
        "autodiscovery_without_env": {
            "command": "bintra ghidra-headless --file obs-frontend-api.dll",
            "returncode": auto_proc.returncode,
            "stdout": auto_proc.stdout.strip(),
            "stderr": auto_proc.stderr.strip(),
        },
        "cli_ghidra_headless_java": {
            "returncode": java_proc.returncode,
            "elapsed_ms": java_ms,
            "project_gpr_created": gpr_exists,
            "stdout_tail": "\n".join(java_proc.stdout.splitlines()[-40:]),
            "stderr_tail": "\n".join(java_proc.stderr.splitlines()[-20:]),
        },
        "live_bridge_jsonrpc": live_bridge_checks,
        "live_bridge_service_script_audit": {
            "py3_compile_ok": py3_compiles,
            "uses_python3_fstrings_incompatible_with_jython27": uses_fstrings,
        },
    }
    write_evidence("obs_003.json", payload)
    return payload


def run_poc_004(ghidra_dir: Path) -> Dict[str, Any]:
    targets = [
        OBS_BIN_DIR / "obs-frontend-api.dll",
        OBS_BIN_DIR / "libobs-d3d11.dll",
    ]
    comparisons: List[Dict[str, Any]] = []
    matcher = PcodeFunctionMatcher()
    vectorizer = PcodeVectorizer()

    pyghidra_probe = run_ghidra_pcode_extraction(
        ghidra_dir,
        OBS_BIN_DIR / "obs-frontend-api.dll",
        with_pdb=False,
        project_name="PyGhidraProbe_ObsFrontend",
        script_name="bintra_extract_pcode.py",
    )
    pyghidra_probe.pop("functions_raw_for_matching", None)

    for target in targets:
        if not target.exists():
            continue
        blind_res = run_ghidra_pcode_extraction(
            ghidra_dir, target, with_pdb=False, project_name=f"PcodeBlind_{target.stem}", script_name="BintraGhidraBridge.java"
        )
        pdb_res = run_ghidra_pcode_extraction(
            ghidra_dir, target, with_pdb=True, project_name=f"PcodePdb_{target.stem}", script_name="BintraGhidraBridge.java"
        )

        blind_funcs = blind_res.pop("functions_raw_for_matching", [])
        pdb_funcs = pdb_res.pop("functions_raw_for_matching", [])

        # Level 2 function-level P-Code match check on largest matching entry_point function
        pcode_match_samples = []
        pdb_by_ep = {f.get("entry_point"): f for f in pdb_funcs if f.get("pcode_ops")}
        for bf in blind_funcs:
            ep = bf.get("entry_point")
            if ep in pdb_by_ep and len(bf.get("pcode_ops", [])) >= 15:
                pf = pdb_by_ep[ep]
                if bf.get("name") != pf.get("name"):
                    res = matcher.match(bf["pcode_ops"], pf["pcode_ops"])
                    pcode_match_samples.append(
                        {
                            "entry_point": ep,
                            "blind_name": bf.get("name"),
                            "pdb_name": pf.get("name"),
                            "pcode_ops_blind": len(bf["pcode_ops"]),
                            "pcode_ops_pdb": len(pf["pcode_ops"]),
                            "similarity": res.get("similarity") or res.get("cosine_similarity"),
                            "result": res,
                        }
                    )
                    if len(pcode_match_samples) >= 3:
                        break

        # Also test vectorization on a real extracted function
        vec_dim = None
        if blind_funcs:
            longest = max(blind_funcs, key=lambda fn: len(fn.get("pcode_ops", [])))
            vec_res = vectorizer.vectorize_pcode_ops(longest.get("pcode_ops", []))
            vec_dim = len(vec_res.get("vector", [])) if isinstance(vec_res, dict) else None

        comparisons.append(
            {
                "binary": target.name,
                "level1_blind": blind_res,
                "level2_pdb": pdb_res,
                "blind_vs_pdb_same_ep_pcode_match": pcode_match_samples,
                "pcode_vector_dim": vec_dim,
            }
        )

    payload = {
        "test_id": "BINTRA-OBS-004",
        "ghidra_version_dir": ghidra_dir.name,
        "pyghidra_script_probe": pyghidra_probe,
        "targets": comparisons,
    }
    write_evidence("obs_004.json", payload)
    return payload


def main() -> None:
    ghidra_dir = locate_ghidra_dir()
    if not ghidra_dir:
        raise RuntimeError("Ghidra installation not found on host.")
    print(f"Using Ghidra at {sanitize_text(str(ghidra_dir))}")
    r3 = run_poc_003(ghidra_dir)
    print(
        f"[003] headless rc={r3['cli_ghidra_headless_java']['returncode']}, "
        f"bridge polled={r3['live_bridge_jsonrpc'].get('polled_commands_count')}"
    )
    r4 = run_poc_004(ghidra_dir)
    print(f"[004] Completed Blind vs PDB P-code extraction for {len(r4['targets'])} binaries.")


if __name__ == "__main__":
    main()
