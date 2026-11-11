"""Bintra vs OBS Studio — Axis A1 Static Analysis & Architecture Runner.

Executes BINTRA-OBS-001, BINTRA-OBS-002, BINTRA-OBS-009, and BINTRA-OBS-011
across Level 1 (Blind / no PDB), Level 2 (PDB via dbghelp.dll), and
Level 3 (PE spec validation via pefile) without modifying Bintra sources or
the installed OBS directory, and without persisting hardcoded local paths.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import pefile

REPO_ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = REPO_ROOT / "src"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from binary_neural_engine import (  # noqa: E402
    BinaryFormatInspector,
    ContinuousDeobfuscator,
    SemanticFunctionMatcher,
    SensoryCortex,
)
from windows_intelligence.dependency_resolver import (  # noqa: E402
    WindowsDependencyResolver,
)


EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence"
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
OBS_ROOT = PROGRAM_FILES / "obs-studio"
OBS_BIN_DIR = OBS_ROOT / "bin" / "64bit"
OBS_PLUGINS_DIR = OBS_ROOT / "obs-plugins" / "64bit"
WIN_CAPTURE_DATA_DIR = OBS_ROOT / "data" / "obs-plugins" / "win-capture"

HOME_DIR = Path.home()


def sanitize_text(value: str) -> str:
    """Redact user profile, repo root, and install root prefixes."""
    if not value:
        return value
    out = value
    replacements = [
        (str(REPO_ROOT), "<REPO_ROOT>"),
        (str(REPO_ROOT).lower(), "<REPO_ROOT>"),
        (str(OBS_ROOT), "%ProgramFiles%\\obs-studio"),
        (str(OBS_ROOT).lower(), "%ProgramFiles%\\obs-studio"),
        (str(HOME_DIR), "%USERPROFILE%"),
        (str(HOME_DIR).lower(), "%USERPROFILE%"),
    ]
    for src, dst in replacements:
        out = out.replace(src, dst)
        out = out.replace(src.replace("\\", "/"), dst.replace("\\", "/"))
    return out


def sanitize_obj(obj: Any) -> Any:
    """Recursively sanitize paths in JSON-serializable payloads."""
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
    clean_payload = sanitize_obj(payload)
    out_path.write_text(json.dumps(clean_payload, indent=2, default=str), encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# Level 2 Ground Truth: Windows dbghelp.dll PDB symbol enumeration
# ---------------------------------------------------------------------------

class SYMBOL_INFOW(ctypes.Structure):
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
        ("Name", ctypes.c_wchar * 512),
    ]


class IMAGEHLP_MODULEW64(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wintypes.ULONG),
        ("BaseOfImage", ctypes.c_uint64),
        ("ImageSize", wintypes.ULONG),
        ("TimeDateStamp", wintypes.ULONG),
        ("CheckSum", wintypes.ULONG),
        ("NumSyms", wintypes.ULONG),
        ("SymType", ctypes.c_int),
        ("ModuleName", ctypes.c_wchar * 32),
        ("ImageName", ctypes.c_wchar * 256),
        ("LoadedImageName", ctypes.c_wchar * 256),
        ("LoadedPdbName", ctypes.c_wchar * 256),
        ("CVSig", wintypes.ULONG),
        ("CVData", ctypes.c_wchar * 780),
        ("PdbSig", wintypes.ULONG),
        ("PdbSig70", ctypes.c_byte * 16),
        ("PdbAge", wintypes.ULONG),
        ("PdbUnmatched", wintypes.BOOL),
        ("DbgUnmatched", wintypes.BOOL),
        ("LineNumbers", wintypes.BOOL),
        ("GlobalSymbols", wintypes.BOOL),
        ("TypeInfo", wintypes.BOOL),
        ("SourceIndexed", wintypes.BOOL),
        ("Publics", wintypes.BOOL),
        ("MachineType", wintypes.ULONG),
        ("Reserved", wintypes.ULONG),
    ]


SYM_ENUM_CALLBACK = ctypes.WINFUNCTYPE(
    wintypes.BOOL,
    ctypes.POINTER(SYMBOL_INFOW),
    wintypes.ULONG,
    ctypes.c_void_p,
)


def enumerate_pdb_symbols(binary_path: Path, pdb_search_dir: Path) -> Dict[str, Any]:
    """Enumerate true symbols from shipped OBS PDB using dbghelp.dll (Level 2)."""
    dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    SYMOPT_UNDNAME = 0x00000002
    SYMOPT_DEFERRED_LOADS = 0x00000004
    SYMOPT_LOAD_LINES = 0x00000010
    SYMOPT_NO_PROMPTS = 0x00080000
    SymTagFunction = 5

    dbghelp.SymSetOptions.argtypes = [wintypes.DWORD]
    dbghelp.SymSetOptions.restype = wintypes.DWORD
    dbghelp.SymInitializeW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.BOOL]
    dbghelp.SymInitializeW.restype = wintypes.BOOL
    dbghelp.SymCleanup.argtypes = [wintypes.HANDLE]
    dbghelp.SymCleanup.restype = wintypes.BOOL
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
    dbghelp.SymGetModuleInfoW64.argtypes = [
        wintypes.HANDLE,
        ctypes.c_uint64,
        ctypes.POINTER(IMAGEHLP_MODULEW64),
    ]
    dbghelp.SymGetModuleInfoW64.restype = wintypes.BOOL
    dbghelp.SymEnumSymbolsW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_uint64,
        wintypes.LPCWSTR,
        SYM_ENUM_CALLBACK,
        ctypes.c_void_p,
    ]
    dbghelp.SymEnumSymbolsW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE

    proc_handle = ctypes.c_void_p(0xB17A0001)
    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_NO_PROMPTS | SYMOPT_LOAD_LINES)
    if not dbghelp.SymInitializeW(proc_handle, str(pdb_search_dir), False):
        return {"error": f"SymInitializeW failed: {ctypes.get_last_error()}"}

    counts = {"total_symbols": 0, "function_symbols": 0, "sample_functions": []}
    try:
        mod_base = dbghelp.SymLoadModuleExW(
            proc_handle,
            None,
            str(binary_path),
            binary_path.stem,
            0x140000000,
            0,
            None,
            0,
        )
        if not mod_base:
            return {"error": f"SymLoadModuleExW failed: {ctypes.get_last_error()}"}

        mod_info = IMAGEHLP_MODULEW64()
        mod_info.SizeOfStruct = ctypes.sizeof(IMAGEHLP_MODULEW64)
        loaded_pdb = ""
        sym_type = -1
        num_syms = 0
        if dbghelp.SymGetModuleInfoW64(proc_handle, mod_base, ctypes.byref(mod_info)):
            loaded_pdb = mod_info.LoadedPdbName
            sym_type = mod_info.SymType
            num_syms = mod_info.NumSyms

        @SYM_ENUM_CALLBACK
        def _cb(sym_ptr, sym_size, ctx):
            sym = sym_ptr.contents
            counts["total_symbols"] += 1
            if sym.Tag == SymTagFunction:
                counts["function_symbols"] += 1
                if len(counts["sample_functions"]) < 15:
                    counts["sample_functions"].append(
                        {
                            "name": sym.Name,
                            "rva": hex(sym.Address - mod_base) if sym.Address >= mod_base else hex(sym.Address),
                            "size": sym.Size,
                        }
                    )
            return True

        dbghelp.SymEnumSymbolsW(proc_handle, mod_base, "*", _cb, None)
        dbghelp.SymUnloadModule64(proc_handle, mod_base)
        return {
            "loaded_pdb": Path(loaded_pdb).name if loaded_pdb else None,
            "sym_type": sym_type,
            "num_syms_header": num_syms,
            "enumerated_total_symbols": counts["total_symbols"],
            "enumerated_function_symbols": counts["function_symbols"],
            "sample_functions": counts["sample_functions"],
        }
    finally:
        dbghelp.SymCleanup(proc_handle)


# ---------------------------------------------------------------------------
# Level 3 PE Ground Truth via pefile
# ---------------------------------------------------------------------------

def extract_pefile_spec(binary_path: Path) -> Dict[str, Any]:
    """Independent PE ground truth parser via pefile (Level 3)."""
    pe = pefile.PE(str(binary_path), fast_load=False)
    try:
        delay_dlls: List[str] = []
        delay_symbol_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                delay_dlls.append(entry.dll.decode("utf-8", errors="ignore"))
                delay_symbol_count += len(entry.imports)

        normal_dlls: Dict[str, int] = {}
        normal_symbol_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                name = entry.dll.decode("utf-8", errors="ignore")
                normal_dlls[name] = len(entry.imports)
                normal_symbol_count += len(entry.imports)

        export_count = 0
        forwarded_exports = 0
        export_names: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_count += 1
                if sym.forwarder:
                    forwarded_exports += 1
                if sym.name:
                    export_names.append(sym.name.decode("utf-8", errors="ignore"))

        version_info: Dict[str, str] = {}
        if hasattr(pe, "FileInfo"):
            for fi_list in pe.FileInfo:
                for fi in fi_list:
                    if hasattr(fi, "StringTable"):
                        for st in fi.StringTable:
                            for k, v in st.entries.items():
                                dk = k.decode("utf-8", errors="ignore")
                                dv = v.decode("utf-8", errors="ignore")
                                if dk in {"FileVersion", "ProductVersion", "CompanyName", "ProductName", "OriginalFilename", "FileDescription"}:
                                    version_info[dk] = dv

        debug_pdb_path = None
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                if getattr(dbg.entry, "PdbFileName", None):
                    debug_pdb_path = dbg.entry.PdbFileName.rstrip(b"\x00").decode("utf-8", errors="ignore")
                    break

        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ]
        has_authenticode_dir = security_dir.VirtualAddress != 0 and security_dir.Size > 0
        has_rich_header = getattr(pe, "RICH_HEADER", None) is not None
        subsystem = pe.OPTIONAL_HEADER.Subsystem

        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "size_bytes": binary_path.stat().st_size,
            "sections_count": len(pe.sections),
            "section_names": [s.Name.rstrip(b"\x00").decode("utf-8", errors="ignore") for s in pe.sections],
            "entrypoint_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "normal_import_dlls": len(normal_dlls),
            "normal_import_symbols": normal_symbol_count,
            "normal_import_map": normal_dlls,
            "delay_import_dlls": delay_dlls,
            "delay_import_symbols": delay_symbol_count,
            "export_total_symbols": export_count,
            "export_named_count": len(export_names),
            "forwarded_exports": forwarded_exports,
            "export_names_sample": export_names[:20],
            "all_export_names": export_names,
            "version_info": version_info,
            "has_debug_pdb_codeview": debug_pdb_path is not None,
            "debug_pdb_basename": Path(debug_pdb_path).name if debug_pdb_path else None,
            "has_authenticode_dir": has_authenticode_dir,
            "has_rich_header": has_rich_header,
            "subsystem": subsystem,
        }
    finally:
        pe.close()


# ---------------------------------------------------------------------------
# PoC 001: Static Binary Inspection & Sensory Audit
# ---------------------------------------------------------------------------

def run_poc_001() -> Dict[str, Any]:
    inspector = BinaryFormatInspector()
    deobfuscator = ContinuousDeobfuscator()
    cortex = SensoryCortex()

    targets: List[Tuple[str, Path, bool]] = [
        ("obs64.exe", OBS_BIN_DIR / "obs64.exe", True),
        ("obs.dll", OBS_BIN_DIR / "obs.dll", True),
        ("libobs-d3d11.dll", OBS_BIN_DIR / "libobs-d3d11.dll", True),
        ("obs-frontend-api.dll", OBS_BIN_DIR / "obs-frontend-api.dll", True),
        ("droidcam-obs.dll", OBS_PLUGINS_DIR / "droidcam-obs.dll", True),
        ("obs-browser.dll", OBS_PLUGINS_DIR / "obs-browser.dll", True),
        ("avcodec-61.dll", OBS_BIN_DIR / "avcodec-61.dll", False),
        ("Qt6Core.dll", OBS_BIN_DIR / "Qt6Core.dll", False),
        ("libcef.dll", OBS_PLUGINS_DIR / "libcef.dll", False),
    ]

    results: List[Dict[str, Any]] = []
    cli_sample = None

    with tempfile.TemporaryDirectory(prefix="bintra_obs_blind_") as tmp_dir_str:
        blind_dir = Path(tmp_dir_str)
        for name, src_path, has_pdb_expected in targets:
            if not src_path.exists():
                results.append({"name": name, "error": "missing binary"})
                continue

            blind_copy = blind_dir / name
            shutil.copy2(src_path, blind_copy)

            t0 = time.perf_counter()
            bintra_info = inspector.inspect(str(blind_copy))
            inspect_ms = round((time.perf_counter() - t0) * 1000, 2)

            if name == "obs.dll":
                proc = subprocess.run(
                    ["bintra", "inspect", "--file", str(blind_copy)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                cli_sample = {
                    "command": "bintra inspect --file <blind_dir>/obs.dll",
                    "returncode": proc.returncode,
                    "stdout_head": proc.stdout[:1200],
                    "stderr": proc.stderr[:400],
                }

            deob_summary = None
            sensory_summary = None
            if src_path.stat().st_size <= 10 * 1024 * 1024:
                t1 = time.perf_counter()
                deob = deobfuscator.deobfuscate_file(str(blind_copy), length=4096)
                deob_ms = round((time.perf_counter() - t1) * 1000, 2)
                deob_summary = {
                    "elapsed_ms": deob_ms,
                    "keys": list(deob.keys()),
                    "disassembled_count": len(deob.get("instructions", [])),
                    "opaque_predicates_found": len(deob.get("opaque_predicates", [])),
                    "cff_detected": bool(deob.get("control_flow_flattening", {}).get("detected")),
                    "error": deob.get("error"),
                }

                t2 = time.perf_counter()
                sense = cortex.evaluate_all_senses(file_path=str(blind_copy))
                sense_ms = round((time.perf_counter() - t2) * 1000, 2)
                sensory_summary = {
                    "elapsed_ms": sense_ms,
                    "top_keys": list(sense.keys()),
                    "senses_count": len(sense.get("senses", {})),
                    "sense_names": list(sense.get("senses", {}).keys()),
                }

            pe_spec = extract_pefile_spec(blind_copy)

            pdb_truth = None
            if has_pdb_expected:
                pdb_truth = enumerate_pdb_symbols(src_path, src_path.parent)

            bintra_imports_obj = bintra_info.get("imports", {})
            bintra_modules = bintra_imports_obj.get("modules", {}) if isinstance(bintra_imports_obj, dict) else {}
            bintra_import_dlls = len(bintra_modules)
            bintra_import_syms = sum(len(v) for v in bintra_modules.values() if isinstance(v, list))
            bintra_exports_obj = bintra_info.get("exports", {})
            bintra_export_count_header = (
                int(bintra_exports_obj.get("exported_functions_count", 0))
                if isinstance(bintra_exports_obj, dict)
                else 0
            )
            bintra_export_funcs = (
                bintra_exports_obj.get("functions", [])
                if isinstance(bintra_exports_obj, dict)
                else []
            )
            bintra_export_parsed_count = len(bintra_export_funcs)

            entry_record = {
                "name": name,
                "level1_blind": {
                    "inspect_ms": inspect_ms,
                    "bintra_keys": list(bintra_info.keys()),
                    "format": bintra_info.get("format"),
                    "pe_type": bintra_info.get("pe_type"),
                    "machine": bintra_info.get("machine"),
                    "image_base": bintra_info.get("image_base"),
                    "entrypoint_rva": bintra_info.get("entry_point_rva"),
                    "subsystem": bintra_info.get("subsystem"),
                    "mitigations": bintra_info.get("windows_security_mitigations"),
                    "sections_count": bintra_info.get("sections_count"),
                    "import_dlls": bintra_import_dlls,
                    "import_symbols_parsed": bintra_import_syms,
                    "export_count_header": bintra_export_count_header,
                    "export_parsed_count": bintra_export_parsed_count,
                    "has_strings_extraction": "strings" in bintra_info,
                    "has_xrefs_extraction": "xrefs" in bintra_info,
                    "has_compiler_version_info": "version_info" in bintra_info or "rich_header" in bintra_info,
                    "has_delay_imports": "delay_imports" in bintra_info or "DelayImportDescriptor" in bintra_info.get("data_directories", {}),
                    "has_delay_import_parsed_list": "delay_imports" in bintra_info,
                    "has_authenticode": "authenticode" in bintra_info or "signature" in bintra_info,
                    "has_authenticode_dir_rva": "CertificateTable" in bintra_info.get("data_directories", {}),
                    "deobfuscator_4kb_entry": deob_summary,
                    "sensory_cortex": sensory_summary,
                },
                "level2_pdb_ground_truth": pdb_truth,
                "level3_pefile_ground_truth": {
                    k: v for k, v in pe_spec.items() if k not in {"all_export_names", "normal_import_map"}
                },
                "deltas": {
                    "import_dll_delta_pefile_minus_bintra": pe_spec["normal_import_dlls"] - bintra_import_dlls,
                    "import_symbol_delta_pefile_minus_bintra": pe_spec["normal_import_symbols"] - bintra_import_syms,
                    "missed_delay_import_dlls": [
                        d for d in pe_spec["delay_import_dlls"]
                        if d.lower() not in {x.lower() for x in bintra_info.get("delay_imports", {}).get("modules", {}).keys()}
                    ],
                    "export_parsed_delta_pefile_minus_bintra": pe_spec["export_total_symbols"] - bintra_export_parsed_count,
                    "blind_internal_function_recall_vs_pdb": (
                        f"{bintra_export_parsed_count}/{pdb_truth['enumerated_function_symbols']} "
                        f"({round(100.0 * bintra_export_parsed_count / max(1, pdb_truth['enumerated_function_symbols']), 2)}% exported-only)"
                        if pdb_truth and pdb_truth.get("enumerated_function_symbols")
                        else None
                    ),
                },
            }
            results.append(entry_record)

    payload = {
        "test_id": "BINTRA-OBS-001",
        "cli_probe": cli_sample,
        "binaries": results,
    }
    write_evidence("obs_001.json", payload)
    return payload


# ---------------------------------------------------------------------------
# PoC 002: Dependency Mapping & Import/Export Graph
# ---------------------------------------------------------------------------

def run_poc_002() -> Dict[str, Any]:
    resolver = WindowsDependencyResolver()
    inspector = BinaryFormatInspector()

    targets = [
        ("obs64.exe", OBS_BIN_DIR / "obs64.exe"),
        ("obs.dll", OBS_BIN_DIR / "obs.dll"),
        ("obs-frontend-api.dll", OBS_BIN_DIR / "obs-frontend-api.dll"),
        ("obs-browser.dll", OBS_PLUGINS_DIR / "obs-browser.dll"),
        ("droidcam-obs.dll", OBS_PLUGINS_DIR / "droidcam-obs.dll"),
        ("win-capture.dll", OBS_PLUGINS_DIR / "win-capture.dll"),
    ]

    audits: List[Dict[str, Any]] = []
    cli_probe = None

    for name, target in targets:
        if not target.exists():
            continue
        t0 = time.perf_counter()
        audit = resolver.audit_dependencies(str(target))
        ms = round((time.perf_counter() - t0) * 1000, 2)
        pe_spec = extract_pefile_spec(target)
        bintra_pe = inspector.inspect(str(target))

        if name == "obs64.exe":
            proc = subprocess.run(
                ["bintra", "resolve-deps", "--file", str(target)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            cli_probe = {
                "command": "bintra resolve-deps --file <OBS>/bin/64bit/obs64.exe",
                "returncode": proc.returncode,
                "stdout_head": proc.stdout[:1200],
                "stderr": proc.stderr[:400],
            }

        missing = audit.get("missing_dlls", [])
        resolved_dlls = audit.get("resolved_dlls", [])
        api_sets_resolved = [r for r in resolved_dlls if r.get("is_api_set")]
        false_missing_in_obs_bin = [
            m.get("imported_name")
            for m in missing
            if isinstance(m, dict) and (OBS_BIN_DIR / str(m.get("imported_name", ""))).exists()
        ]
        false_missing_in_obs_plugins = [
            m.get("imported_name")
            for m in missing
            if isinstance(m, dict) and (OBS_PLUGINS_DIR / str(m.get("imported_name", ""))).exists()
        ]

        audits.append(
            {
                "binary": name,
                "elapsed_ms": ms,
                "verdict": audit.get("verdict"),
                "loader_mode": audit.get("loader_mode"),
                "total_imports_checked": audit.get("total_imported_dlls"),
                "resolved_dlls_count": audit.get("resolved_dlls_count"),
                "api_sets_resolved_count": len(api_sets_resolved),
                "missing_dlls_count": audit.get("missing_dlls_count"),
                "missing_dlls": missing,
                "missing_exports_count": audit.get("missing_exports_count"),
                "missing_exports_sample": audit.get("missing_exports", [])[:10],
                "architecture_mismatches": audit.get("architecture_mismatches", []),
                "level3_pe_normal_dll_count": pe_spec["normal_import_dlls"],
                "level3_pe_delay_load_dlls": pe_spec["delay_import_dlls"],
                "bintra_pe_imports_count": bintra_pe.get("imports", {}).get("imported_dlls_count"),
                "false_missing_actually_in_obs_bin_dir": false_missing_in_obs_bin,
                "false_missing_actually_in_obs_plugins_dir": false_missing_in_obs_plugins,
            }
        )

    payload = {
        "test_id": "BINTRA-OBS-002",
        "cli_probe": cli_probe,
        "audits": audits,
    }
    write_evidence("obs_002.json", payload)
    return payload


# ---------------------------------------------------------------------------
# PoC 009: OBS Plugin Architecture & Multi-Layer Boundary Audit
# ---------------------------------------------------------------------------

def run_poc_009() -> Dict[str, Any]:
    inspector = BinaryFormatInspector()
    resolver = WindowsDependencyResolver()

    core_dlls = sorted(p.name for p in OBS_BIN_DIR.glob("*.dll")) if OBS_BIN_DIR.exists() else []
    core_exes = sorted(p.name for p in OBS_BIN_DIR.glob("*.exe")) if OBS_BIN_DIR.exists() else []
    plugin_dlls = sorted(p.name for p in OBS_PLUGINS_DIR.glob("*.dll")) if OBS_PLUGINS_DIR.exists() else []
    plugin_exes = sorted(p.name for p in OBS_PLUGINS_DIR.glob("*.exe")) if OBS_PLUGINS_DIR.exists() else []
    hook_dlls = sorted(p.name for p in WIN_CAPTURE_DATA_DIR.glob("*.dll")) if WIN_CAPTURE_DATA_DIR.exists() else []

    plugin_probe_names = [
        "droidcam-obs.dll",
        "obs-browser.dll",
        "win-capture.dll",
        "obs-ffmpeg.dll",
        "obs-nvenc.dll",
        "obs-websocket.dll",
        "obs-x264.dll",
        "win-wasapi.dll",
        "image-source.dll",
        "libcef.dll",
    ]

    analyzed_plugins: List[Dict[str, Any]] = []
    for pname in plugin_probe_names:
        ppath = OBS_PLUGINS_DIR / pname
        if not ppath.exists():
            continue
        bintra_pe = inspector.inspect(str(ppath))
        pe_spec = extract_pefile_spec(ppath)
        dep_audit = resolver.audit_dependencies(str(ppath))

        export_names = set(pe_spec["all_export_names"])
        has_obs_plugin_exports = "obs_module_load" in export_names and "obs_module_ver" in export_names
        imports_lower = {k.lower() for k in pe_spec["normal_import_map"].keys()}
        uses_obs_core = "obs.dll" in imports_lower
        uses_frontend_api = "obs-frontend-api.dll" in imports_lower
        uses_qt6 = any(d.startswith("qt6") for d in imports_lower)

        analyzed_plugins.append(
            {
                "name": pname,
                "size_bytes": pe_spec["size_bytes"],
                "bintra_exports_count": bintra_pe.get("exports", {}).get("exported_functions_count", 0),
                "has_obs_module_load_and_ver": has_obs_plugin_exports,
                "imports_obs_dll": uses_obs_core,
                "imports_frontend_api": uses_frontend_api,
                "imports_qt6": uses_qt6,
                "pe_version_info": pe_spec["version_info"],
                "has_pdb_next_to_binary": ppath.with_suffix(".pdb").exists(),
                "bintra_dep_verdict": dep_audit.get("verdict"),
                "bintra_dep_missing": [m.get("imported_name") for m in dep_audit.get("missing_dlls", [])],
                "bintra_dep_missing_exports_count": dep_audit.get("missing_exports_count", 0),
            }
        )

    payload = {
        "test_id": "BINTRA-OBS-009",
        "inventory_counts": {
            "core_bin_64bit_exes": core_exes,
            "core_bin_64bit_dlls_count": len(core_dlls),
            "obs_plugins_64bit_exes": plugin_exes,
            "obs_plugins_64bit_dlls_count": len(plugin_dlls),
            "win_capture_hook_dlls": hook_dlls,
            "third_party_plugin_detected": "droidcam-obs.dll" in plugin_dlls,
        },
        "plugin_probe": analyzed_plugins,
        "bintra_plugin_architecture_capabilities": {
            "built_in_obs_plugin_classifier": False,
            "built_in_cef_version_detector": False,
            "pe_exports_parsed_by_bintra": True,
            "cross_dir_plugin_to_bin_resolution": "Audit below shows whether obs.dll resolves from plugins dir",
        },
    }
    write_evidence("obs_009.json", payload)
    return payload


# ---------------------------------------------------------------------------
# PoC 011: Version Differential Check (Honest Scope + Auxiliary Test)
# ---------------------------------------------------------------------------

def _first_export_slice(binary_path: Path, symbol_name: str, length: int = 96) -> Optional[str]:
    pe = pefile.PE(str(binary_path), fast_load=False)
    try:
        rva = None
        if symbol_name == "__ENTRYPOINT__":
            rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        elif hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if sym.name and sym.name.decode("utf-8", errors="ignore") == symbol_name:
                    rva = sym.address
                    break
        if rva is None:
            return None
        off = pe.get_offset_from_rva(rva)
        if off is None:
            return None
        raw = pe.__data__[off : off + length]
        return raw.hex()
    finally:
        pe.close()


def run_poc_011() -> Dict[str, Any]:
    matcher = SemanticFunctionMatcher()
    aux_results: List[Dict[str, Any]] = []

    pairs = [
        (
            "identical_obs_module_ver_obs_browser",
            OBS_PLUGINS_DIR / "obs-browser.dll",
            "obs_module_ver",
            OBS_PLUGINS_DIR / "obs-browser.dll",
            "obs_module_ver",
        ),
        (
            "same_api_obs_module_ver_win_capture_vs_droidcam",
            OBS_PLUGINS_DIR / "win-capture.dll",
            "obs_module_ver",
            OBS_PLUGINS_DIR / "droidcam-obs.dll",
            "obs_module_ver",
        ),
        (
            "d3d11_vs_opengl_device_present",
            OBS_BIN_DIR / "libobs-d3d11.dll",
            "device_present",
            OBS_BIN_DIR / "libobs-opengl.dll",
            "device_present",
        ),
        (
            "graphics_hook64_vs_graphics_hook32_entrypoint_cross_bitness",
            WIN_CAPTURE_DATA_DIR / "graphics-hook64.dll",
            "__ENTRYPOINT__",
            WIN_CAPTURE_DATA_DIR / "graphics-hook32.dll",
            "__ENTRYPOINT__",
        ),
    ]

    for label, p1, s1, p2, s2 in pairs:
        if not (p1.exists() and p2.exists()):
            aux_results.append({"label": label, "skipped": "missing file"})
            continue
        h1 = _first_export_slice(p1, s1, 64)
        h2 = _first_export_slice(p2, s2, 64)
        if not h1 or not h2:
            aux_results.append({"label": label, "skipped": "symbol not found"})
            continue
        res = matcher.match_functions(h1, h2)
        aux_results.append(
            {
                "label": label,
                "bin1": p1.name,
                "sym1": s1,
                "bin2": p2.name,
                "sym2": s2,
                "match_result": res,
            }
        )

    payload = {
        "test_id": "BINTRA-OBS-011",
        "primary_verdict": "NOT TESTED",
        "classification": "Test Limitation",
        "reason": "Only OBS Studio 32.1.2 (64-bit) is installed locally; OBS 33.0.0 and 33.0.1 binaries are not present on this machine.",
        "auxiliary_same_version_semantic_matcher_tests": aux_results,
    }
    write_evidence("obs_011.json", payload)
    return payload


def main() -> None:
    print("Running Axis A1 Static PoCs against OBS Studio 32.1.2...")
    r1 = run_poc_001()
    print(f"[001] Inspected {len(r1['binaries'])} binaries.")
    r2 = run_poc_002()
    print(f"[002] Audited dependencies for {len(r2['audits'])} binaries.")
    r9 = run_poc_009()
    print(f"[009] Profiled {len(r9['plugin_probe'])} plugins & core layers.")
    r11 = run_poc_011()
    print(f"[011] Primary verdict: {r11['primary_verdict']} ({len(r11['auxiliary_same_version_semantic_matcher_tests'])} auxiliary matches).")


if __name__ == "__main__":
    main()
