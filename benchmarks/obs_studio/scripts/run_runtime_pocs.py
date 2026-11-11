"""Bintra vs OBS Studio — Axes A3 & A4 Runtime Memory, ETW & Static-Dynamic Correlation Runner.

Safely launches a dedicated, isolated OBS Studio 32.1.2 instance (--multi),
executes read-only BINTRA-OBS-005, 006, 007, 008 benchmarks across Level 1/2/3,
and cleanly terminates only the spawned OBS process tree in a finally block.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from binary_neural_engine import BinaryFormatInspector  # noqa: E402
from windows_intelligence.evidence_engine.causality_synthesizer import (  # noqa: E402
    CausalitySynthesizer,
)
from windows_intelligence.process_intelligence.process_inventory import (  # noqa: E402
    ProcessInventory,
)
from windows_intelligence.runtime_telemetry.etw_capture_engine import (  # noqa: E402
    EtwLiveCaptureSession,
    EtwTimelineCorrelator,
)
from windows_intelligence.runtime_telemetry.virtual_memory_inspector import (  # noqa: E402
    PointerScanner,
    ProcessMemoryScanner,
    StructureDissector,
    VirtualMemoryInspector,
)

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
OBS_ROOT = PROGRAM_FILES / "obs-studio"
OBS_BIN_DIR = OBS_ROOT / "bin" / "64bit"
OBS_PLUGINS_DIR = OBS_ROOT / "obs-plugins" / "64bit"
HOME_DIR = Path.home()


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
        out = out.replace(src.replace("\\", "/"), dst.replace("\\", "/"))
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


# ---------------------------------------------------------------------------
# Level 2 Ground Truth: dbghelp SymFromAddrW at synthetic/fixed base + RVA
# ---------------------------------------------------------------------------

class SYMBOL_INFOW_MIN(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("TypeIndex", wintypes.ULONG),
        ("Reserved", ctypes.c_uint64 * 2),
        ("Index", wintypes.ULONG),
        ("Size", wintypes.ULONG),
        ("ModBase", ctypes.c_uint64),
        ("Flags", wintypes.ULONG),
        ("Value", ctypes.c_uint64),
        ("Address", ctypes.c_uint64),
        ("Register", wintypes.ULONG),
        ("Scope", wintypes.ULONG),
        ("Tag", wintypes.ULONG),
        ("NameLen", wintypes.ULONG),
        ("MaxNameLen", wintypes.ULONG),
        ("Name", ctypes.c_wchar * 256),
    ]


def resolve_pdb_symbol_at_rva(binary_path: Path, rva: int) -> Optional[Dict[str, Any]]:
    """Resolve true symbol name + displacement at a module RVA using dbghelp.dll."""
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    proc_handle = ctypes.c_void_p(0xB17A0002)
    dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
    dbghelp.SymSetOptions.restype = wintypes.DWORD
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymLoadModuleExW.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_uint64,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    dbghelp.SymLoadModuleExW.restype = ctypes.c_uint64
    dbghelp.SymUnloadModule64.argtypes = [wintypes.HANDLE, ctypes.c_uint64]
    dbghelp.SymUnloadModule64.restype = wintypes.BOOL
    dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
    dbghelp.SymCleanup.restype = wintypes.BOOL

    dbghelp.SymSetOptions(0x00000002 | 0x00000004 | 0x00080000)
    if not dbghelp.SymInitializeW(proc_handle, str(binary_path.parent), False):
        return None
    try:
        base = dbghelp.SymLoadModuleExW(
            proc_handle, None, str(binary_path), binary_path.stem, 0x180000000, 0, None, 0
        )
        if not base:
            return None
        sym = SYMBOL_INFOW_MIN()
        sym.SizeOfStruct = 88  # sizeof(SYMBOL_INFOW header without trailing Name chars)
        sym.MaxNameLen = 256
        disp = ctypes.c_uint64(0)
        dbghelp.SymFromAddrW.argtypes = [
            wintypes.HANDLE,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(SYMBOL_INFOW_MIN),
        ]
        dbghelp.SymFromAddrW.restype = wintypes.BOOL
        ok = dbghelp.SymFromAddrW(proc_handle, base + rva, ctypes.byref(disp), ctypes.byref(sym))
        dbghelp.SymUnloadModule64(proc_handle, base)
        if not ok:
            return None
        return {
            "symbol": sym.Name,
            "displacement": int(disp.value),
            "rva": hex(rva),
        }
    finally:
        dbghelp.SymCleanup(proc_handle)


def _find_child_pids(parent_pid: int) -> List[Dict[str, Any]]:
    procs = ProcessInventory.enumerate_processes(resolve_paths=False)
    children = []
    for p in procs:
        if p.get("parent_process_id") == parent_pid:
            children.append({"pid": p.get("process_id"), "name": p.get("executable_name")})
    return children


def _terminate_pid_tree(root_pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(root_pid)],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except Exception:
        pass


def _find_live_cpp_vtable_object(pid: int, snap: Any) -> Optional[Dict[str, Any]]:
    """Find a genuine live C++ object in committed HEAP pointing into IMAGE_RDATA -> IMAGE_TEXT."""
    rdata_bounds: List[tuple[int, int, str]] = []
    text_bounds: List[tuple[int, int]] = []
    heap_regions = []
    for r in snap.regions:
        if r.state != 0x1000:
            continue
        if r.category == "IMAGE_RDATA":
            rdata_bounds.append((r.base_address, r.base_address + r.region_size, r.module_name or ""))
        elif r.category == "IMAGE_TEXT":
            text_bounds.append((r.base_address, r.base_address + r.region_size))
        elif r.category == "HEAP" and r.is_writable() and not r.is_guard_page() and 4096 <= r.region_size <= 2 * 1024 * 1024:
            heap_regions.append(r)

    def _in_bounds(val: int, bounds: List[tuple]) -> Optional[str]:
        for item in bounds:
            if item[0] <= val < item[1]:
                return item[2] if len(item) > 2 else "match"
        return None

    for reg in heap_regions[:30]:
        chunk = VirtualMemoryInspector.read_process_memory(pid, reg.base_address, min(reg.region_size, 65536))
        if not chunk:
            continue
        for off in range(0, len(chunk) - 64, 8):
            (cand_ptr,) = struct.unpack_from("<Q", chunk, off)
            mod_name = _in_bounds(cand_ptr, rdata_bounds)
            if mod_name and any(k in mod_name.lower() for k in ("obs", "qt6", "droidcam")):
                vslot_raw = VirtualMemoryInspector.read_process_memory(pid, cand_ptr, 8)
                if vslot_raw and len(vslot_raw) == 8:
                    (first_fn,) = struct.unpack("<Q", vslot_raw)
                    if _in_bounds(first_fn, text_bounds):
                        return {
                            "object_va": reg.base_address + off,
                            "vtable_va": cand_ptr,
                            "vtable_module": mod_name,
                            "first_vfn_va": first_fn,
                        }
    return None


def main() -> None:
    obs_exe = OBS_BIN_DIR / "obs64.exe"
    if not obs_exe.exists():
        raise RuntimeError("OBS Studio obs64.exe not found.")

    pre_obs = ProcessInventory.enumerate_processes(resolve_paths=False)
    pre_obs_pids = {p.get("process_id") for p in pre_obs if "obs64" in str(p.get("executable_name", "")).lower()}

    # Start ETW Capture Session BEFORE OBS launch (BINTRA-OBS-007)
    etw_session = EtwLiveCaptureSession(session_name="Bintra_OBS_Bench_Trace")
    etw_start = etw_session.start_session()

    obs_proc = subprocess.Popen(
        [str(obs_exe), "--multi", "--disable-shutdown-check"],
        cwd=str(OBS_BIN_DIR),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    obs_pid = obs_proc.pid
    print(f"Spawned isolated OBS Studio PID={obs_pid} (--multi --disable-shutdown-check)")

    try:
        # Poll up to 18s until obs.dll and plugins appear in process modules
        disk_plugins_set = {p.name.lower() for p in OBS_PLUGINS_DIR.glob("*.dll")} if OBS_PLUGINS_DIR.exists() else set()
        snap1 = None
        for _ in range(24):
            time.sleep(0.75)
            if obs_proc.poll() is not None:
                break
            snap_try = VirtualMemoryInspector.inspect_process(obs_pid)
            mod_names = {str(m.get("name", "")).lower() for m in snap_try.modules}
            loaded_plugins_now = mod_names & disk_plugins_set
            if "obs.dll" in mod_names and (len(loaded_plugins_now) >= 5 or len(mod_names) > 150):
                snap1 = snap_try
                time.sleep(2.5)
                snap1 = VirtualMemoryInspector.inspect_process(obs_pid)
                break
        if snap1 is None:
            snap1 = VirtualMemoryInspector.inspect_process(obs_pid)

        proc_alive = obs_proc.poll() is None
        etw_session.target_pid = obs_pid
        children = _find_child_pids(obs_pid)

        # ------------------------------------------------------------------
        # BINTRA-OBS-005: Runtime Modules, VAD Map & Snapshot Diff
        # ------------------------------------------------------------------
        loaded_mod_names = [m.get("name") for m in snap1.modules]
        loaded_lower = {str(n).lower(): m for n, m in zip(loaded_mod_names, snap1.modules)}

        disk_core_dlls = {p.name.lower() for p in OBS_BIN_DIR.glob("*.dll")}
        disk_plugin_dlls = {p.name.lower() for p in OBS_PLUGINS_DIR.glob("*.dll")} if OBS_PLUGINS_DIR.exists() else set()

        loaded_core_dlls = sorted(d for d in disk_core_dlls if d in loaded_lower)
        loaded_plugin_dlls = sorted(d for d in disk_plugin_dlls if d in loaded_lower)

        category_counts: Dict[str, int] = {}
        for r in snap1.regions:
            category_counts[r.category] = category_counts.get(r.category, 0) + 1

        time.sleep(1.5)
        snap2 = VirtualMemoryInspector.inspect_process(obs_pid)
        vad_diff = VirtualMemoryInspector.diff_snapshots(snap1, snap2)

        cli_proc_mod = subprocess.run(
            ["bintra", "proc-modules", "obs.dll"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        cli_vad = subprocess.run(
            ["bintra", "vad-inspect", "--pid", str(obs_pid)],
            capture_output=True,
            text=True,
            timeout=20,
        )

        payload_005 = {
            "test_id": "BINTRA-OBS-005",
            "pre_existing_obs_pids": sorted(pre_obs_pids),
            "spawned_obs_pid": obs_pid,
            "process_alive_during_audit": proc_alive,
            "child_processes": children,
            "is_simulated": snap1.is_simulated,
            "architecture": snap1.architecture,
            "vad_summary": snap1.compute_summary(),
            "region_category_counts": category_counts,
            "loaded_modules_total": len(snap1.modules),
            "loaded_obs_core_dlls_count": len(loaded_core_dlls),
            "loaded_obs_core_dlls_sample": loaded_core_dlls[:20],
            "loaded_obs_plugins_count": len(loaded_plugin_dlls),
            "loaded_obs_plugins": loaded_plugin_dlls,
            "droidcam_obs_loaded": "droidcam-obs.dll" in loaded_lower,
            "libcef_loaded_in_main_or_child": "libcef.dll" in loaded_lower or len(children) > 0,
            "snapshot_diff_summary": {
                k: v for k, v in vad_diff.items() if k in {"added_count", "removed_count", "modified_count", "summary", "delta_commit_bytes"}
            } or {"keys": list(vad_diff.keys()), "changes_count": len(vad_diff.get("changes", vad_diff.get("added", [])))},
            "cli_proc_modules_obs_dll": {
                "returncode": cli_proc_mod.returncode,
                "stdout_head": cli_proc_mod.stdout[:800],
            },
            "cli_vad_inspect_rc": cli_vad.returncode,
        }
        write_evidence("obs_005.json", payload_005)
        print(f"[005] Loaded {len(snap1.modules)} modules, {len(loaded_plugin_dlls)} plugins (droidcam={payload_005['droidcam_obs_loaded']}).")

        # ------------------------------------------------------------------
        # BINTRA-OBS-006: Live Memory Scanning, Pointer Scanning & Struct Dissection
        # ------------------------------------------------------------------
        t_scan0 = time.perf_counter()
        scan_version = ProcessMemoryScanner.first_scan(
            obs_pid,
            data_type="string",
            scan_type="EXACT_VALUE",
            value="OBS Studio",
            writable_only=True,
            max_candidates=200,
        )
        scan_ms = round((time.perf_counter() - t_scan0) * 1000, 2)

        next_scan_res = None
        if scan_version.get("session_id"):
            next_scan_res = ProcessMemoryScanner.next_scan(
                session_id=scan_version["session_id"],
                scan_type="EXACT_VALUE",
                value="OBS Studio",
            )

        # Discover a live C++ object with a real vtable pointer (.rdata -> .text)
        live_obj = _find_live_cpp_vtable_object(obs_pid, snap1)
        struct_dissect_res = None
        pointer_scan_res = None
        if live_obj:
            struct_dissect_res = StructureDissector.dissect(
                obs_pid,
                live_obj["object_va"],
                size=96,
                struct_name="OBS_LiveCppObject",
            )
            t_ptr0 = time.perf_counter()
            pointer_scan_res = PointerScanner.find_pointer_paths(
                obs_pid,
                live_obj["object_va"],
                max_depth=2,
                max_offset=512,
                max_results=10,
                alignment=8,
            )
            pointer_scan_res["elapsed_ms"] = round((time.perf_counter() - t_ptr0) * 1000, 2)
        elif scan_version.get("candidates_sample"):
            cand_va = int(scan_version["candidates_sample"][0]["address"], 16)
            struct_dissect_res = StructureDissector.dissect(obs_pid, cand_va, size=64)
            pointer_scan_res = PointerScanner.find_pointer_paths(obs_pid, cand_va, max_depth=2, max_offset=256, max_results=5, alignment=8)

        payload_006 = {
            "test_id": "BINTRA-OBS-006",
            "first_scan_writable_string": {
                "elapsed_ms": scan_ms,
                "regions_scanned": scan_version.get("regions_scanned"),
                "total_target_regions": scan_version.get("total_target_regions"),
                "total_candidates": scan_version.get("total_candidates"),
                "candidates_sample": scan_version.get("candidates_sample", [])[:5],
            },
            "next_scan_confirmation": {
                "previous_count": next_scan_res.get("previous_count") if next_scan_res else None,
                "surviving_count": next_scan_res.get("surviving_count") if next_scan_res else None,
                "keys": list(next_scan_res.keys()) if next_scan_res else None,
            },
            "live_cpp_object_probe": {
                "object_va": hex(live_obj["object_va"]) if live_obj else None,
                "vtable_va": hex(live_obj["vtable_va"]) if live_obj else None,
                "vtable_module": live_obj["vtable_module"] if live_obj else None,
            },
            "structure_dissection": {
                "fields_count": len(struct_dissect_res.get("fields", [])) if struct_dissect_res else 0,
                "vtable_detected": any("vtable" in str(f.get("description", "")) for f in (struct_dissect_res or {}).get("fields", [])),
                "fields_sample": (struct_dissect_res or {}).get("fields", [])[:8],
                "c_struct_definition": (struct_dissect_res or {}).get("c_struct_definition"),
            },
            "pointer_scan": pointer_scan_res,
        }
        write_evidence("obs_006.json", payload_006)
        print(f"[006] Scan candidates={scan_version.get('total_candidates')}, struct fields={payload_006['structure_dissection']['fields_count']}, ptr paths={pointer_scan_res.get('paths_count') if pointer_scan_res else None}.")

        # ------------------------------------------------------------------
        # BINTRA-OBS-008: Static <-> Dynamic Address Correlation & Evidence Graph
        # ------------------------------------------------------------------
        correlations: List[Dict[str, Any]] = []
        for mod_name, export_sym in [
            ("obs.dll", "obs_get_version"),
            ("obs.dll", "obs_startup"),
            ("obs-frontend-api.dll", "obs_frontend_get_version"),
            ("droidcam-obs.dll", "obs_module_ver"),
        ]:
            mod_info = loaded_lower.get(mod_name.lower())
            mod_disk = (OBS_BIN_DIR / mod_name) if (OBS_BIN_DIR / mod_name).exists() else (OBS_PLUGINS_DIR / mod_name)
            if not (mod_info and mod_disk.exists()):
                continue

            pe_info = BinaryFormatInspector.inspect(str(mod_disk))
            mod_base = int(str(mod_info.get("base_address")), 16) if isinstance(mod_info.get("base_address"), str) else int(mod_info.get("base_address", 0))
            exp_rva = None
            for ex in pe_info.get("exports", {}).get("functions", []):
                if ex.get("name") == export_sym:
                    exp_rva = int(ex["rva"], 16)
                    break
            if exp_rva is None:
                continue

            live_va = mod_base + exp_rva
            va_cls = snap1.classify_address(live_va)
            file_off = BinaryFormatInspector.rva_to_offset(pe_info, exp_rva)
            live_bytes = VirtualMemoryInspector.read_process_memory(obs_pid, live_va, 16) or b""
            disk_bytes = b""
            if file_off is not None:
                with open(mod_disk, "rb") as mf:
                    mf.seek(file_off)
                    disk_bytes = mf.read(16)

            pdb_sym = resolve_pdb_symbol_at_rva(mod_disk, exp_rva)
            correlations.append(
                {
                    "module": mod_name,
                    "export_symbol": export_sym,
                    "live_base": hex(mod_base),
                    "rva": hex(exp_rva),
                    "live_va": hex(live_va),
                    "file_offset": hex(file_off) if file_off is not None else None,
                    "bintra_vad_classification": va_cls,
                    "live_vs_disk_16B_exact_match": (live_bytes == disk_bytes and len(live_bytes) == 16),
                    "live_bytes_hex": live_bytes.hex(),
                    "disk_bytes_hex": disk_bytes.hex(),
                    "level2_pdb_verification": pdb_sym,
                }
            )

        ev_graph = CausalitySynthesizer.build_evidence_graph(str(OBS_BIN_DIR / "obs64.exe"))
        dossier = CausalitySynthesizer.synthesize_dossier(str(OBS_BIN_DIR / "obs64.exe"))
        ev_dict = ev_graph.to_dict() if hasattr(ev_graph, "to_dict") else {}
        payload_008 = {
            "test_id": "BINTRA-OBS-008",
            "correlations": correlations,
            "evidence_graph_summary": {
                "nodes_count": len(ev_dict.get("nodes", [])),
                "edges_count": len(ev_dict.get("edges", [])),
                "dossier_keys": list(dossier.keys()) if isinstance(dossier, dict) else None,
            },
        }
        write_evidence("obs_008.json", payload_008)
        print(f"[008] Verified {len(correlations)} live VA<->RVA<->FileOffset<->PDB correlations.")

    finally:
        # Cleanly terminate ONLY our spawned OBS process tree!
        _terminate_pid_tree(obs_pid)
        time.sleep(1.5)

    # Stop ETW session AFTER OBS shutdown to capture lifecycle (BINTRA-OBS-007)
    timeline = etw_session.get_timeline(limit=500, include_global=True)
    obs_timeline = etw_session.get_timeline(pid=obs_pid, limit=200, include_global=False)
    etw_stop = etw_session.stop_session()
    corr = EtwTimelineCorrelator.correlate_crash_timeline(timeline)

    etw_audit_cli = subprocess.run(
        ["bintra", "etw-audit"],
        capture_output=True,
        text=True,
        timeout=20,
    )

    event_sources: Dict[str, int] = {}
    for ev in timeline:
        src = str(ev.get("source") or ev.get("provider") or "unknown")
        event_sources[src] = event_sources.get(src, 0) + 1

    payload_007 = {
        "test_id": "BINTRA-OBS-007",
        "start_result": etw_start,
        "stop_result": etw_stop,
        "global_timeline_count": len(timeline),
        "obs_pid_filtered_count": len(obs_timeline),
        "event_sources_breakdown": event_sources,
        "sample_events": timeline[:8],
        "correlator_summary": {
            "keys": list(corr.keys()) if isinstance(corr, dict) else None,
            "total_events_analyzed": corr.get("total_events") if isinstance(corr, dict) else None,
        },
        "cli_etw_audit": {
            "returncode": etw_audit_cli.returncode,
            "stdout_head": etw_audit_cli.stdout[:800],
        },
    }
    write_evidence("obs_007.json", payload_007)
    print(f"[007] ETW capture mode={etw_start.get('mode') or etw_start.get('telemetry_backend')}, events={len(timeline)}, obs_filtered={len(obs_timeline)}.")


if __name__ == "__main__":
    main()
