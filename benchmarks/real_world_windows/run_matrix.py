#!/usr/bin/env python3
"""
Bintra real-world Windows test matrix runner.

See TEST_PLAN.md next to this file. Every case runs against genuine host
artifacts (system binaries, installed applications, crash dumps, live helper
processes, a real MCP stdio session). Missing samples are skipped, not failed.

Usage:
    python benchmarks/real_world_windows/run_matrix.py [--levels L1,L2,...]
        [--workspace DIR] [--extra-sample PATH]... [--extra-dump PATH]...
        [--scale-count N] [--quick]
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import textwrap
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
CLI = str(SRC_DIR / "cli.py")
MCP = str(SRC_DIR / "mcp_server.py")
IS_WINDOWS = os.name == "nt"

WIN = Path(os.environ.get("SystemRoot", r"C:\Windows"))
SYS32 = WIN / "System32"
WOW64 = WIN / "SysWOW64"
PF = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
PF86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", ""))

MAGIC = 0x1337BEEF


# --------------------------------------------------------------------------
# Result bookkeeping
# --------------------------------------------------------------------------
class Matrix:
    def __init__(self, workspace: Path):
        self.ws = workspace
        self.results: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def record(self, level: str, case_id: str, status: str, detail: str = "", duration: float = 0.0, **extra):
        row = {"level": level, "case": case_id, "status": status, "detail": detail[:2000], "duration_s": round(duration, 3)}
        row.update(extra)
        with self.lock:
            self.results.append(row)
        icon = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP"}.get(status, status.upper())
        print(f"[{icon}] {level} {case_id} ({duration:.2f}s){'  -- ' + detail[:300] if status != 'pass' and detail else ''}", flush=True)

    def skip(self, level: str, case_id: str, why: str):
        self.record(level, case_id, "skip", why)


def child_env() -> Dict[str, str]:
    env = dict(os.environ)
    # Reproduce default Windows behaviour (ANSI code page) -- no UTF-8 overrides.
    env.pop("PYTHONIOENCODING", None)
    env.pop("PYTHONUTF8", None)
    env["PYTHONPATH"] = str(SRC_DIR) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def run_cli(m: Matrix, level: str, case_id: str, args: List[str], *, expect_rc: Optional[int] = 0,
            json_out: bool = True, expect_error: bool = False, tolerant: bool = False,
            check: Optional[Callable[[Any], Optional[str]]] = None, timeout: int = 240) -> Any:
    """Runs `python src/cli.py <args>` and applies the generic + specific pass criteria."""
    t0 = time.perf_counter()
    try:
        proc = subprocess.run([sys.executable, CLI] + [str(a) for a in args], capture_output=True,
                              env=child_env(), timeout=timeout, cwd=str(m.ws))
    except subprocess.TimeoutExpired:
        m.record(level, case_id, "fail", f"TIMEOUT after {timeout}s", time.perf_counter() - t0, args=args)
        return None
    dt = time.perf_counter() - t0
    out = proc.stdout.decode("utf-8", errors="replace")
    err = proc.stderr.decode("utf-8", errors="replace")
    problems: List[str] = []
    if expect_rc is not None and proc.returncode != expect_rc:
        problems.append(f"rc={proc.returncode} (expected {expect_rc})")
    if expect_rc is None and expect_error and proc.returncode == 0:
        problems.append("expected a controlled non-zero exit")
    if "Traceback (most recent call last)" in out or "Traceback (most recent call last)" in err:
        problems.append("traceback leaked: " + (err or out)[-600:])
    data: Any = None
    if json_out:
        try:
            data = json.loads(out)
        except Exception as e:
            problems.append(f"stdout is not a single JSON document ({e}); head={out[:200]!r} tail={out[-200:]!r}")
    if isinstance(data, dict) and not expect_error and not tolerant and str(data.get("status", "")).lower() == "error":
        problems.append(f"status=error: {data.get('error') or data.get('message')}")
    if not problems and check is not None:
        try:
            msg = check(data if json_out else out)
            if msg:
                problems.append(msg)
        except Exception as e:
            problems.append(f"check raised {type(e).__name__}: {e}")
    m.record(level, case_id, "fail" if problems else "pass", "; ".join(problems), dt, args=[str(a) for a in args])
    return data if json_out else out


def first_existing(*paths) -> Optional[Path]:
    for p in paths:
        if p and Path(p).is_file():
            return Path(p)
    return None


# --------------------------------------------------------------------------
# Samples
# --------------------------------------------------------------------------
def discover_samples(m: Matrix, extra: List[str]) -> Dict[str, Optional[Path]]:
    s: Dict[str, Optional[Path]] = {
        "pe64_exe": first_existing(SYS32 / "notepad.exe"),
        "pe32_exe": first_existing(WOW64 / "notepad.exe"),
        "dll64": first_existing(SYS32 / "kernel32.dll"),
        "driver": first_existing(SYS32 / "drivers" / "ntfs.sys", SYS32 / "drivers" / "disk.sys"),
        "msvc_cpp": first_existing(SYS32 / "msvcp140.dll", SYS32 / "msvcp_win.dll"),
        "dotnet": first_existing(WIN / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe"),
        "go_bin": first_existing(PF / "Git" / "mingw64" / "bin" / "git-lfs.exe", PF / "GitHub CLI" / "gh.exe"),
        "mingw_bin": first_existing(PF / "Git" / "mingw64" / "bin" / "git.exe"),
        "inno_overlay": next((Path(p) for p in glob.glob(str(PF / "*" / "unins000.exe"))), None),
        "large_bin": first_existing(*sorted(glob.glob(str(PF / "Blender Foundation" / "*" / "blender.exe"))), PF / "nodejs" / "node.exe"),
        "app_local_deps": first_existing(PF / "VideoLAN" / "VLC" / "vlc.exe", PF / "7-Zip" / "7z.exe"),
        "python_dll": first_existing(Path(sys.base_prefix) / f"python{sys.version_info.major}{sys.version_info.minor}.dll"),
        "legacy_game32": None,
    }
    for i, e in enumerate(extra):
        s[f"extra_{i}"] = first_existing(e)
    # Legacy 32-bit game referenced by a host crash dump, if present.
    for drive in ("C:", "D:", "E:"):
        for p in glob.glob(drive + r"\*\gta_sa.exe") + glob.glob(drive + r"\Games\*\*.exe")[:1]:
            s["legacy_game32"] = Path(p)
            break
        if s["legacy_game32"]:
            break
    # Workspace-generated samples: non-ASCII path, non-PE, empty, pyc
    if s["pe64_exe"]:
        ar = m.ws / "عينات_عربية" / "مجلد فيه مسافات"
        ar.mkdir(parents=True, exist_ok=True)
        shutil.copy2(s["pe64_exe"], ar / "notepad_نسخة.exe")
        s["arabic_path"] = ar / "notepad_نسخة.exe"
    txt = m.ws / "plain_text.txt"
    txt.write_text("not a PE file\n" * 100, encoding="utf-8")
    s["non_pe"] = txt
    empty = m.ws / "empty.bin"
    empty.write_bytes(b"")
    s["empty"] = empty
    import py_compile
    pysrc = m.ws / "sample_module.py"
    pysrc.write_text(textwrap.dedent("""
        import os, subprocess
        SECRET = "k3y"
        def run(cmd):
            return subprocess.run(cmd, shell=False)
        def add(a, b):
            return a + b
        class Greeter:
            def hello(self, name):
                return f"hi {name}"
    """), encoding="utf-8")
    s["pyc"] = Path(py_compile.compile(str(pysrc), cfile=str(m.ws / "sample_module.pyc")))
    return s


# --------------------------------------------------------------------------
# Helper processes (L4)
# --------------------------------------------------------------------------
TARGET_SRC = r'''
import ctypes, json, os, sys, time
val = ctypes.c_int32(%d)
holder = (ctypes.c_void_p * 4)(ctypes.addressof(val), 0, 0, 0)
ctl = sys.argv[1]
print(json.dumps({"pid": os.getpid(), "addr": ctypes.addressof(val), "holder": ctypes.addressof(holder)}), flush=True)
while not os.path.exists(ctl + ".stop"):
    if os.path.exists(ctl + ".inc"):
        val.value += 1
        os.remove(ctl + ".inc")
        open(ctl + ".ack", "w").close()
    time.sleep(0.02)
''' % MAGIC

LEAKER_SRC = r'''
import json, os, sys, time
print(json.dumps({"pid": os.getpid()}), flush=True)
hoard = []
handles = []
end = time.time() + float(sys.argv[1])
while time.time() < end:
    hoard.append(bytearray(os.urandom(1)) * (4 * 1024 * 1024))
    try:
        handles.append(open(sys.executable, "rb"))
    except Exception:
        pass
    time.sleep(0.05)
'''

LOCKER_SRC = r'''
import json, os, sys, time
f = open(sys.argv[1], "r+b")
print(json.dumps({"pid": os.getpid()}), flush=True)
time.sleep(float(sys.argv[2]))
'''


def spawn_helper(m: Matrix, name: str, src: str, args: List[str]) -> tuple:
    script = m.ws / f"helper_{name}.py"
    script.write_text(src, encoding="utf-8")
    flags = 0x08000000 if IS_WINDOWS else 0  # CREATE_NO_WINDOW
    proc = subprocess.Popen([sys.executable, str(script)] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            creationflags=flags)
    line = proc.stdout.readline().decode("utf-8", "replace")
    info = json.loads(line)  # real interpreter PID (venv launchers spawn a child)
    return proc, info


# --------------------------------------------------------------------------
# Synthetic-but-realistic fixtures
# --------------------------------------------------------------------------
def write_safetensors(path: Path, plant_outlier: bool = True) -> None:
    import numpy as np
    rng = np.random.default_rng(7)
    w = rng.normal(0, 0.02, size=(256, 128)).astype(np.float32)
    if plant_outlier:
        w[:, 42] += rng.normal(0, 0.02, size=256).astype(np.float32) + 0.9  # planted trojan-like neuron
    b = np.zeros(128, dtype=np.float32)
    tensors = {"model.layers.0.mlp.down_proj.weight": w, "model.layers.0.mlp.down_proj.bias": b}
    header: Dict[str, Any] = {"__metadata__": {"format": "pt"}}
    blobs = []
    off = 0
    for k, t in tensors.items():
        raw = t.tobytes()
        header[k] = {"dtype": "F32", "shape": list(t.shape), "data_offsets": [off, off + len(raw)]}
        blobs.append(raw)
        off += len(raw)
    hb = json.dumps(header).encode("utf-8")
    hb += b" " * ((8 - len(hb) % 8) % 8)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(hb)))
        f.write(hb)
        for raw in blobs:
            f.write(raw)


def build_fuzz_corpus(seed_pe: Path, out_dir: Path, n_random: int = 24) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    data = bytearray(seed_pe.read_bytes())
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    coff = e_lfanew + 4
    n_sec_off = coff + 2
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    sec_tbl = opt + opt_size
    dd_off = opt + (112 if magic == 0x20B else 96)
    variants: Dict[str, bytes] = {}

    def mut(name: str, fn):
        b = bytearray(data)
        fn(b)
        variants[name] = bytes(b)

    for cut in (2, 0x40, e_lfanew + 2, coff + 10, opt + 8, sec_tbl + 20, len(data) // 2, len(data) - 1):
        variants[f"trunc_{cut}"] = bytes(data[:cut])
    mut("lfanew_beyond_eof", lambda b: struct.pack_into("<I", b, 0x3C, len(b) + 0x1000))
    mut("lfanew_negative_like", lambda b: struct.pack_into("<I", b, 0x3C, 0xFFFFFFF0))
    mut("lfanew_zero", lambda b: struct.pack_into("<I", b, 0x3C, 0))
    mut("bad_pe_sig", lambda b: b.__setitem__(slice(e_lfanew, e_lfanew + 4), b"PX\0\0"))
    mut("nsections_ffff", lambda b: struct.pack_into("<H", b, n_sec_off, 0xFFFF))
    mut("nsections_zero", lambda b: struct.pack_into("<H", b, n_sec_off, 0))
    mut("opt_size_huge", lambda b: struct.pack_into("<H", b, coff + 16, 0xFFFF))
    mut("opt_size_zero", lambda b: struct.pack_into("<H", b, coff + 16, 0))
    mut("bad_opt_magic", lambda b: struct.pack_into("<H", b, opt, 0x1234))
    mut("sec0_rawptr_eof", lambda b: struct.pack_into("<I", b, sec_tbl + 20, 0x7FFFFFF0))
    mut("sec0_rawsize_huge", lambda b: struct.pack_into("<I", b, sec_tbl + 16, 0xFFFFFFFF))
    mut("sec0_vsize_zero", lambda b: struct.pack_into("<I", b, sec_tbl + 8, 0))
    mut("all_sections_overlap", lambda b: [struct.pack_into("<I", b, sec_tbl + 40 * i + 20, 0x400) for i in range(struct.unpack_from("<H", b, n_sec_off)[0])])
    for i, nm in enumerate(["export", "import", "resource", "exception", "security", "reloc", "debug"]):
        mut(f"dd_{nm}_bogus", lambda b, i=i: struct.pack_into("<II", b, dd_off + 8 * i, 0x7FFFFFF0, 0x7FFFFFF0))
        mut(f"dd_{nm}_tiny_rva", lambda b, i=i: struct.pack_into("<II", b, dd_off + 8 * i, 0x10, 0xFFFFFFFF))
    mut("num_rva_sizes_huge", lambda b: struct.pack_into("<I", b, dd_off - 4, 0xFFFFFFFF))
    mut("entrypoint_bogus", lambda b: struct.pack_into("<I", b, opt + 16, 0xFFFFFFF0))
    mut("filealign_zero", lambda b: struct.pack_into("<I", b, opt + 36, 0))
    mut("sectionalign_zero", lambda b: struct.pack_into("<I", b, opt + 32, 0))
    rng = random.Random(1337)
    for k in range(n_random):
        b = bytearray(data)
        hdr_end = min(len(b), sec_tbl + 40 * 16)
        for _ in range(rng.randint(4, 64)):
            pos = rng.randrange(0, hdr_end)
            b[pos] = rng.randrange(256)
        variants[f"flip_hdr_{k}"] = bytes(b)
    paths = []
    for name, blob in variants.items():
        p = out_dir / f"{seed_pe.stem}_{name}.bin"
        p.write_bytes(blob)
        paths.append(p)
    return paths


# --------------------------------------------------------------------------
# Generic semantic checks
# --------------------------------------------------------------------------
def expect_keys(*keys):
    def _c(d):
        missing = [k for k in keys if not (isinstance(d, dict) and k in d)]
        return f"missing keys {missing}" if missing else None
    return _c


def expect_pe_type(token: str):
    def _c(d):
        t = str(d.get("pe_type", ""))
        return None if token in t else f"pe_type={t!r} does not contain {token!r}"
    return _c


# --------------------------------------------------------------------------
# Levels
# --------------------------------------------------------------------------
def level_1(m: Matrix, s: Dict[str, Optional[Path]], quick: bool):
    L = "L1"
    pe_keys = [k for k in ("pe64_exe", "pe32_exe", "dll64", "driver", "msvc_cpp", "dotnet", "go_bin", "mingw_bin",
                           "inno_overlay", "large_bin", "app_local_deps", "python_dll", "legacy_game32", "arabic_path")
               if True] + [k for k in s if k.startswith("extra_")]
    for key in pe_keys:
        p = s.get(key)
        if not p:
            m.skip(L, f"{key}/*", "sample not present on host")
            continue
        chk = expect_pe_type("PE32+") if key in ("pe64_exe", "dll64", "driver") else (
            expect_pe_type("PE32 (") if key == "pe32_exe" else expect_keys("format"))
        run_cli(m, L, f"{key}/inspect", ["inspect", "--file", p], check=chk)
        run_cli(m, L, f"{key}/dump", ["dump", "--file", p, "--offset", "0", "--length", "64"],
                check=lambda d: None if str(d.get("hex", "")).replace(" ", "").upper().startswith("4D5A") else "dump does not start with MZ")
        run_cli(m, L, f"{key}/pe-forensics", ["pe-forensics", "--file", p])
        run_cli(m, L, f"{key}/slack-audit", ["slack-audit", "-f", p])
        run_cli(m, L, f"{key}/sig-verify", ["sig-verify", "--file", p])
        if not quick or key in ("pe64_exe", "pe32_exe", "arabic_path"):
            run_cli(m, L, f"{key}/sense", ["sense", "--file", p], timeout=300)
            run_cli(m, L, f"{key}/scan-hybrid", ["scan-hybrid", "--file", p], timeout=300)
            run_cli(m, L, f"{key}/deobfuscate", ["deobfuscate", "--file", p], timeout=300)
            run_cli(m, L, f"{key}/triage", ["triage", "--file", p], timeout=600,
                    check=expect_keys("status", "stage_statuses", "summary"))
    # Semantic spot checks on special formats
    if s.get("msvc_cpp"):
        run_cli(m, L, "msvc_cpp/rtti-recovered", ["pe-forensics", "--file", s["msvc_cpp"]],
                check=lambda d: None if int((d.get("msvc_rtti") or {}).get("type_descriptors_count", 0)) > 0 else "no RTTI type descriptors recovered from an MSVC C++ DLL")
    if s.get("inno_overlay"):
        run_cli(m, L, "inno_overlay/overlay-detected", ["slack-audit", "-f", s["inno_overlay"]],
                check=lambda d: None if d.get("has_overlay") or d.get("has_trailing_slack") else "installer overlay not detected")
    # Non-PE / empty: must answer cleanly (no traceback, valid JSON)
    for key in ("non_pe", "empty"):
        p = s[key]
        for cmd in (["inspect", "--file", p], ["pe-forensics", "--file", p], ["slack-audit", "-f", p],
                    ["sense", "--file", p], ["scan-hybrid", "--file", p], ["triage", "--file", p],
                    ["deobfuscate", "--file", p], ["dump", "--file", p, "--offset", "0", "--length", "16"]):
            # Generic-byte analyzers may legitimately succeed on non-PE input; the contract is a
            # clean single-JSON answer, no traceback, and rc!=0 only together with status=error.
            run_cli(m, L, f"{key}/{cmd[0]}", cmd, expect_rc=None, tolerant=True,
                    check=lambda d: None if isinstance(d, dict) else "non-object JSON")
    missing = m.ws / "does_not_exist.exe"
    run_cli(m, L, "missing_file/inspect", ["inspect", "--file", missing], expect_rc=None, expect_error=True)
    run_cli(m, L, "directory_as_file/inspect", ["inspect", "--file", m.ws], expect_rc=None, expect_error=True)


def level_2(m: Matrix, s: Dict[str, Optional[Path]], quick: bool):
    L = "L2"
    run_cli(m, L, "win-audit", ["win-audit"], check=expect_keys("os", "devices", "security"))
    for key in ("pe64_exe", "pe32_exe", "app_local_deps", "large_bin", "legacy_game32", "dotnet", "arabic_path"):
        if s.get(key):
            run_cli(m, L, f"resolve-deps/{key}", ["resolve-deps", "--binary", s[key]], check=expect_keys("verdict", "resolved_dlls"))
    if s.get("app_local_deps"):
        run_cli(m, L, "resolve-deps/app-local-dlls-found", ["resolve-deps", "--binary", s["app_local_deps"]],
                check=lambda d: None if not d.get("missing_dlls") else f"app-local DLLs reported missing: {[x if isinstance(x, str) else x.get('name') for x in d['missing_dlls']][:8]}")
    for args in (["hw-audit"], ["hw-audit", "--problems-only"], ["driver-audit"], ["service-audit"], ["etw-audit"],
                 ["reg-audit"], ["wer-inspect"], ["dev-match"], ["net-conns"], ["port-audit"],
                 ["hw-tree", "--format", "json"], ["sys-perf", "--format", "json"], ["proc-list", "--format", "json", "--limit", "5"],
                 ["proc-search", "--query", "explorer", "--format", "json"], ["dev-list", "--format", "json"],
                 ["dev-classes", "--format", "json"], ["capabilities"],
                 ["reg-read", "--key", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "--format", "json"],
                 ["sig-audit", "--dir", str(SYS32), "--pattern", "*.exe", "--limit", "15"]):
        run_cli(m, L, " ".join(args[:2]) if len(args) > 1 and not args[1].startswith("-") else args[0] + (" " + args[1] if len(args) > 1 else ""),
                args, timeout=300)
    if s.get("legacy_game32"):
        run_cli(m, L, "wer-inspect/legacy_game32", ["wer-inspect", "--binary", s["legacy_game32"].name])
    if s.get("pe64_exe"):
        run_cli(m, L, "diagnose/pe64_exe", ["diagnose", "--binary", s["pe64_exe"]], timeout=300,
                check=expect_keys("verdict", "severity"))
    for key in ("pe64_exe", "dll64"):
        if s.get(key):
            run_cli(m, L, f"proc-modules/{s[key].name}", ["proc-modules", "--module", s[key].name])


def find_dumps(extra: List[str]) -> List[Path]:
    pats = [LOCALAPPDATA / "CrashDumps" / "*.dmp", WIN / "Minidump" / "*.dmp",
            Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows" / "WER" / "**" / "*.mdmp"]
    out = []
    for p in pats:
        out += [Path(x) for x in glob.glob(str(p), recursive=True)]
    out += [Path(x) for x in extra if Path(x).is_file()]
    seen, uniq = set(), []
    for d in sorted(out, key=lambda x: x.stat().st_size):
        if str(d).lower() not in seen:
            seen.add(str(d).lower())
            uniq.append(d)
    return uniq


def guess_binary_for_dump(dmp: Path, s: Dict[str, Optional[Path]]) -> Optional[Path]:
    img = dmp.name.split(".exe")[0] + ".exe"
    for c in (SYS32 / img, SYS32 / "WindowsPowerShell" / "v1.0" / img, PF / "Windows NT" / "Accessories" / img, WIN / img):
        if c.is_file():
            return c
    g = s.get("legacy_game32")
    if g and g.name.lower() == img.lower():
        return g
    return None


def rca_consistent(d: Any) -> Optional[str]:
    """Semantic invariants for a crash-rca report (catches fabricated register blame)."""
    miss = expect_keys("exception_code", "root_cause_classification")(d)
    if miss:
        return miss
    blame = d.get("blame_details") or {}
    win = d.get("disassembly_window") or {}
    if blame.get("computed_address") and d.get("confidence") in ("CONFIDENT_DETERMINISTIC", "HIGH_HEURISTIC") \
            and "MISMATCH" not in d.get("root_cause_classification", ""):
        try:
            if int(blame["computed_address"], 16) != int(d["target_address"], 16):
                return f"blamed operand evaluates to {blame['computed_address']} but fault target is {d['target_address']}"
        except ValueError:
            pass
    src = win.get("code_source")
    if win.get("available") and src == "ON_DISK_IMAGE":
        analyzed = os.path.basename(str(win.get("binary_analyzed", ""))).lower()
        if analyzed != str(d.get("fault_module", "")).lower():
            return f"disassembled '{analyzed}' but the fault is in '{d.get('fault_module')}'"
        if win.get("image_identity") == "MISMATCH":
            return "disassembled an on-disk image that does not match the crashed module"
    if d.get("exception_name") == "UNKNOWN_EXCEPTION":
        return f"exception code {d.get('exception_code')} is not named"
    return None


def level_3(m: Matrix, s: Dict[str, Optional[Path]], extra_dumps: List[str], quick: bool):
    L = "L3"
    dumps = find_dumps(extra_dumps)
    if not dumps:
        m.skip(L, "*", "no minidumps on host")
        return
    run_cli(m, L, "dmp-inspect --scan", ["dmp-inspect", "--scan"], check=expect_keys("total_dumps_discovered"))
    for d in dumps:
        tag = d.name
        run_cli(m, L, f"dmp-inspect/{tag}", ["dmp-inspect", "--file", d], timeout=300,
                check=expect_keys("system_info", "exception_info"))
        rca = run_cli(m, L, f"crash-rca/{tag}", ["crash-rca", "--dmp", d], timeout=300, check=rca_consistent)
        b = guess_binary_for_dump(d, s)
        if b:
            rca = run_cli(m, L, f"crash-rca+binary/{tag}", ["crash-rca", "--dmp", d, "--binary", b], timeout=300,
                          check=rca_consistent) or rca
            if isinstance(rca, dict):
                cj = m.ws / f"crash_{d.stem}.json"
                cj.write_text(json.dumps(rca), encoding="utf-8")
                run_cli(m, L, f"diagnose+crash-json/{tag}", ["diagnose", "--binary", b, "--crash-json", cj], timeout=300,
                        check=expect_keys("verdict", "root_cause_summary"))
                run_cli(m, L, f"triage+dmp/{tag}", ["triage", "--file", b, "--dmp", d, "--skip-deobf"], timeout=600,
                        check=expect_keys("status", "stage_statuses"))


def level_4(m: Matrix, s: Dict[str, Optional[Path]], quick: bool):
    L = "L4"
    if not IS_WINDOWS:
        m.skip(L, "*", "live runtime requires Windows")
        return
    ctl = m.ws / "target_ctl"
    for suffix in (".stop", ".inc", ".ack"):
        try:
            os.remove(str(ctl) + suffix)
        except FileNotFoundError:
            pass
    proc, info = spawn_helper(m, "target", TARGET_SRC, [str(ctl)])
    pid, addr, holder = info["pid"], info["addr"], info["holder"]
    try:
        run_cli(m, L, "vad-inspect", ["vad-inspect", "--pid", pid], check=lambda d: None if d.get("is_simulated") is False else "VAD inspection fell back to simulation")
        run_cli(m, L, "vad-inspect/address", ["vad-inspect", "--pid", pid, "--address", hex(addr)])
        run_cli(m, L, "vad-inspect/regions", ["vad-inspect", "--pid", pid, "--regions"])
        sess = m.ws / "memscan_session.json"
        if sess.exists():
            sess.unlink()

        def has_addr(d):
            cands = d.get("candidates_sample") or d.get("candidates") or []
            addrs = set()
            for c in cands:
                a = c.get("address") if isinstance(c, dict) else c
                try:
                    addrs.add(int(a, 16) if isinstance(a, str) else int(a))
                except Exception:
                    pass
            return None if addr in addrs else f"known address {hex(addr)} not among {d.get('total_candidates')} candidates (sample={list(addrs)[:5]})"

        run_cli(m, L, "mem-scan/first-exact", ["mem-scan", "--pid", pid, "--type", "int32", "--mode", "exact", "--value", MAGIC,
                                                "--session-file", sess, "--max-results", "100000"], timeout=300, check=has_addr)
        open(str(ctl) + ".inc", "w").close()
        for _ in range(100):
            if os.path.exists(str(ctl) + ".ack"):
                break
            time.sleep(0.05)
        run_cli(m, L, "mem-scan/next-increased", ["mem-scan", "--pid", pid, "--type", "int32", "--mode", "increased",
                                                   "--session-file", sess], timeout=300, check=has_addr)
        run_cli(m, L, "mem-scan/next-exact", ["mem-scan", "--pid", pid, "--type", "int32", "--mode", "exact", "--value", MAGIC + 1,
                                               "--session-file", sess], timeout=300, check=has_addr)
        run_cli(m, L, "mem-scan/string", ["mem-scan", "--pid", pid, "--type", "string", "--mode", "exact", "--value", "ctypes", "--max-results", "50"], timeout=300)
        run_cli(m, L, "pointer-scan/depth1", ["pointer-scan", "--pid", pid, "--target", hex(addr), "--max-depth", "1"], timeout=300,
                check=lambda d: None if any(holder <= int(str(p.get("base_address", p.get("base", "0"))), 16 if str(p.get("base_address", p.get("base", "0"))).startswith("0x") else 10) <= holder + 32 or str(hex(holder)).lower() in json.dumps(p).lower() for p in d.get("paths", [])) or d.get("paths_count", 0) > 0 else "no pointer path found although a heap pointer to the target exists")
        run_cli(m, L, "dissect-struct", ["dissect-struct", "--pid", pid, "--address", hex(holder), "--size", "32"],
                check=expect_keys("fields"))
        run_cli(m, L, "proc-info", ["proc-info", "--pid", pid, "--format", "json"])
        run_cli(m, L, "process-mitigations", ["process-mitigations", "--pid", pid])
        run_cli(m, L, "proc-modules/python-dll", ["proc-modules", "--module", f"python{sys.version_info.major}{sys.version_info.minor}.dll"],
                check=lambda d: None if any(int(h.get("pid", h.get("process_id", -1))) == pid for h in d.get("hosting_processes", [])) else "helper process not listed as host of its python DLL")
        run_cli(m, L, "etw-capture", ["etw-capture", "--session-name", "bintra_rw", "--pid", pid, "--duration", "1.5"], timeout=120)
        run_cli(m, L, "net-conns/pid", ["net-conns", "--pid", pid])
    finally:
        open(str(ctl) + ".stop", "w").close()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()

    # Leak detection
    lproc, linfo = spawn_helper(m, "leaker", LEAKER_SRC, ["12"])
    try:
        time.sleep(0.5)
        run_cli(m, L, "proc-profile/leaker", ["proc-profile", "-p", linfo["pid"], "-n", "12", "-i", "0.25"], timeout=120,
                check=lambda d: None if "LEAK" in str(d.get("behavior_classification", "")).upper() or "GROWTH" in str(d.get("behavior_classification", "")).upper() else f"leaking process classified as {d.get('behavior_classification')}")
    finally:
        lproc.kill()

    # File lock attribution
    locked = m.ws / "locked_file.dat"
    locked.write_bytes(b"\0" * 4096)
    kproc, kinfo = spawn_helper(m, "locker", LOCKER_SRC, [str(locked), "30"])
    try:
        run_cli(m, L, "file-locks/held", ["file-locks", "--file", locked],
                check=lambda d: None if kinfo["pid"] in [int(p.get("pid", p.get("process_id", -1))) for p in d.get("locking_processes", [])] else f"locker PID {kinfo['pid']} not reported: {d.get('locking_processes')}")
    finally:
        kproc.kill()
        kproc.wait()
    run_cli(m, L, "file-locks/free", ["file-locks", "--file", locked],
            check=lambda d: None if not d.get("is_locked") else "file reported locked after holder exited")

    # WOW64 (32-bit) live target
    ping32 = WOW64 / "PING.EXE"
    if ping32.is_file():
        wproc = subprocess.Popen([str(ping32), "-n", "60", "127.0.0.1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=0x08000000)
        try:
            time.sleep(0.5)
            run_cli(m, L, "wow64/vad-inspect", ["vad-inspect", "--pid", wproc.pid],
                    check=lambda d: None if "32" in json.dumps(d.get("architecture", "")) or "wow" in json.dumps(d).lower()[:4000] else f"WOW64 target not identified as 32-bit: {d.get('architecture')}")
            run_cli(m, L, "wow64/mem-scan", ["mem-scan", "--pid", wproc.pid, "--type", "string", "--mode", "exact", "--value", "127.0.0.1", "--max-results", "20"], timeout=300)
            run_cli(m, L, "wow64/proc-info", ["proc-info", "--pid", wproc.pid, "--format", "json"])
            run_cli(m, L, "wow64/process-mitigations", ["process-mitigations", "--pid", wproc.pid])
        finally:
            wproc.kill()
    # Protected / inaccessible process must fail cleanly
    run_cli(m, L, "protected/vad-inspect-pid4", ["vad-inspect", "--pid", "4"], expect_rc=None, expect_error=True)
    run_cli(m, L, "protected/mem-scan-pid4", ["mem-scan", "--pid", "4", "--type", "int32", "--mode", "exact", "--value", "1"], expect_rc=None, expect_error=True)
    run_cli(m, L, "dead-pid/proc-info", ["proc-info", "--pid", "999999", "--format", "json"], expect_rc=None, expect_error=True)


def level_5(m: Matrix, s: Dict[str, Optional[Path]], quick: bool):
    L = "L5"
    src = s.get("pe64_exe")
    if src:
        run_cli(m, L, "patch/locate-entry", ["inspect", "--file", src])
        out = m.ws / "patched" / "notepad_patched.exe"
        out.parent.mkdir(exist_ok=True)
        # Patch inside the overlay-free tail of .text with NOPs over existing INT3/NOP padding if available
        data = src.read_bytes()
        off = data.find(b"\xCC" * 8, 0x1000)
        if off < 0:
            m.skip(L, "patch-binary", "no padding run found")
        else:
            run_cli(m, L, "patch-binary/nop-padding", ["patch-binary", "--file", src, "--output", out, "--offset", hex(off), "--patch-hex", "90 90 90 90"],
                        check=lambda d: None if d.get("is_safe") and d.get("original_sha256") != d.get("patched_sha256") else f"unexpected patch report: {json.dumps(d)[:300]}")
            if out.exists():
                run_cli(m, L, "patch-binary/reinspect", ["inspect", "--file", out], check=expect_pe_type("PE32+"))
                run_cli(m, L, "patch-binary/diff-vs-original", ["diff-binaries", "--baseline", src, "--target", out])
        run_cli(m, L, "patch-binary/refuse-in-place", ["patch-binary", "--file", src, "--output", src, "--offset", hex(max(off, 0x400)), "--patch-hex", "90"],
                expect_rc=None, expect_error=True)
        run_cli(m, L, "patch-binary/refuse-target-dir", ["patch-binary", "--file", src, "--output", src.parent / "bintra_should_not_exist.exe", "--offset", hex(max(off, 0x400)), "--patch-hex", "90"],
                expect_rc=None, expect_error=True)
        if (src.parent / "bintra_should_not_exist.exe").exists():
            m.record(L, "patch-binary/refuse-target-dir/no-file-created", "fail", "file was created inside the target directory")
    if s.get("pe64_exe") and s.get("pe32_exe"):
        run_cli(m, L, "diff-binaries/x64-vs-x86", ["diff-binaries", "--baseline", s["pe64_exe"], "--target", s["pe32_exe"]], timeout=600)
    if s.get("dll64") and s.get("python_dll"):
        run_cli(m, L, "diff-binaries/unrelated-dlls", ["diff-binaries", "--baseline", s["dll64"], "--target", s["python_dll"]], timeout=600)
    (m.ws / "models_in").mkdir(exist_ok=True)
    (m.ws / "models_out").mkdir(exist_ok=True)
    model = m.ws / "models_in" / "model_planted.safetensors"
    write_safetensors(model, plant_outlier=True)
    run_cli(m, L, "wsp-audit/planted-outlier", ["wsp-audit", "--model", model], timeout=300,
            check=lambda d: None if "42" in json.dumps(d.get("zero_eval_security_audit", d)) else "planted outlier column 42 not surfaced by the audit")
    pout = m.ws / "models_out" / "model_clean.safetensors"
    run_cli(m, L, "patch-weights/column-subtract", ["patch-weights", "--source", model, "--output", pout,
                                                    "--tensor", "model.layers.0.mlp.down_proj.weight", "--operation", "column_direction_subtract"], timeout=300,
            check=lambda d: None if Path(str(d.get("output_path", pout))).exists() else "output safetensors not written")
    run_cli(m, L, "patch-weights/refuse-in-place", ["patch-weights", "--source", model, "--output", model,
                                                    "--tensor", "model.layers.0.mlp.down_proj.weight"], expect_rc=None, expect_error=True)
    if s.get("pyc"):
        run_cli(m, L, "py-bytecode/generated-pyc", ["py-bytecode", "--file", s["pyc"]])
    stdlib_pyc = sorted(glob.glob(str(Path(sys.base_prefix) / "Lib" / "__pycache__" / "json*.pyc")) + glob.glob(str(Path(sys.base_prefix) / "Lib" / "json" / "__pycache__" / "*.pyc")))
    if stdlib_pyc:
        run_cli(m, L, "py-bytecode/stdlib-pyc", ["py-bytecode", "--file", stdlib_pyc[0]])
        if len(stdlib_pyc) > 1:
            run_cli(m, L, "py-bytecode/compare", ["py-bytecode", "--file", stdlib_pyc[0], "--compare-with", stdlib_pyc[1]])


def level_6(m: Matrix, s: Dict[str, Optional[Path]], quick: bool):
    L = "L6"
    target = s.get("arabic_path") or s.get("pe64_exe")
    reqs: List[Any] = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "rw-matrix", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
        {"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "bintra://capabilities"}},
        {"jsonrpc": "2.0", "id": 5, "method": "prompts/list", "params": {}},
        {"jsonrpc": "2.0", "id": 6, "method": "prompts/get", "params": {"name": "triage_pe_binary", "arguments": {"file_path": str(target)}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "bintra_inspect_binary", "arguments": {"file_path": str(target)}}},
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "bintra_triage_binary", "arguments": {"file_path": str(target), "include_deobfuscation": False}}},
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "bintra_no_such_tool", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "bintra_inspect_binary", "arguments": {"file_path": 12345}}},
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "bintra_inspect_binary", "arguments": {}}},
        [{"jsonrpc": "2.0", "id": 12, "method": "ping"}, {"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "bintra_list_capabilities", "arguments": {}}}],
        "{this is not json",
        [],
        {"jsonrpc": "2.0", "id": 14, "method": "no/such/method"},
        {"jsonrpc": "2.0", "id": 15, "method": "tools/list", "params": {"cursor": "garbage-cursor"}},
    ]
    lines = [r if isinstance(r, str) else json.dumps(r, ensure_ascii=False) for r in reqs]
    t0 = time.perf_counter()
    try:
        p = subprocess.run([sys.executable, MCP], input=("\n".join(lines) + "\n").encode("utf-8"), capture_output=True,
                           env=child_env(), timeout=600, cwd=str(m.ws))
    except subprocess.TimeoutExpired:
        m.record(L, "mcp-session", "fail", "TIMEOUT", time.perf_counter() - t0)
        return
    dt = time.perf_counter() - t0
    raw = p.stdout
    resp_by_id: Dict[Any, Any] = {}
    frames = []
    bad = []
    for ln in raw.decode("utf-8", "replace").split("\n"):
        if not ln.strip():
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            bad.append(f"non-JSON frame: {ln[:120]!r}")
            continue
        frames.append(obj)
        for o in (obj if isinstance(obj, list) else [obj]):
            resp_by_id[o.get("id")] = o
    m.record(L, "mcp-session/framing", "fail" if (bad or b"\r\n" in raw) else "pass", "; ".join(bad) + (" CRLF framing" if b"\r\n" in raw else ""), dt)
    if "Traceback" in p.stderr.decode("utf-8", "replace"):
        m.record(L, "mcp-session/stderr-clean", "fail", p.stderr.decode("utf-8", "replace")[-800:])

    def case(cid, rid, fn):
        r = resp_by_id.get(rid)
        if r is None:
            m.record(L, cid, "fail", f"no response for id={rid}")
            return
        try:
            msg = fn(r)
        except Exception as e:
            msg = f"{type(e).__name__}: {e}; resp={json.dumps(r)[:300]}"
        m.record(L, cid, "fail" if msg else "pass", msg or "")

    def tool_ok(r):
        res = r.get("result") or {}
        if res.get("isError"):
            return "isError: " + res["content"][0]["text"][:300]
        d = json.loads(res["content"][0]["text"])
        if isinstance(d, dict) and d.get("format") == "FILE_NOT_FOUND":
            return "FILE_NOT_FOUND for an existing (non-ASCII) path"
        return None

    case("initialize", 1, lambda r: None if r.get("result", {}).get("protocolVersion") else "no protocolVersion")
    case("tools/list", 2, lambda r: None if len(r["result"]["tools"]) >= 40 else f"only {len(r['result']['tools'])} tools")
    case("resources/list", 3, lambda r: None if r["result"]["resources"] else "no resources")
    case("resources/read", 4, lambda r: None if r["result"]["contents"] else "empty resource")
    case("prompts/list", 5, lambda r: None if r["result"]["prompts"] else "no prompts")
    case("prompts/get", 6, lambda r: None if any(str(target) in str((msg.get("content") or {}).get("text", "")) for msg in r["result"]["messages"]) else "prompt does not embed the argument")
    case("tools/call inspect (non-ASCII path)", 7, tool_ok)
    case("tools/call triage", 8, tool_ok)
    case("unknown tool -> error", 9, lambda r: None if ("error" in r or r.get("result", {}).get("isError")) else "unknown tool accepted")
    case("schema violation (int path) -> error", 10, lambda r: None if ("error" in r or r.get("result", {}).get("isError")) else "type violation accepted")
    case("missing required arg -> error", 11, lambda r: None if ("error" in r or r.get("result", {}).get("isError")) else "missing arg accepted")
    case("batch ping", 12, lambda r: None if "result" in r else "ping failed")
    case("batch tools/call", 13, lambda r: None if not r.get("result", {}).get("isError") else "capabilities failed")
    case("unknown method -> -32601", 14, lambda r: None if r.get("error", {}).get("code") == -32601 else f"got {r.get('error')}")
    case("garbage cursor handled", 15, lambda r: None if ("error" in r or "result" in r) else "no answer")
    nulls = [f for f in frames if isinstance(f, dict) and f.get("id") is None and "error" in f]
    codes = sorted({f["error"]["code"] for f in nulls})
    m.record(L, "parse error + empty batch -> id:null errors", "pass" if -32700 in codes and -32600 in codes else "fail", f"codes={codes}")
    if any(isinstance(f, dict) and f.get("id") is None and "result" in f for f in frames):
        m.record(L, "notification must not be answered", "fail", "a response was emitted for a notification")
    else:
        m.record(L, "notification must not be answered", "pass")


STATIC_TOOLS = [
    ("bintra_inspect_binary", lambda p: {"file_path": p}),
    ("bintra_pe_deep_forensics", lambda p: {"file_path": p}),
    ("bintra_inspect_slack_space", lambda p: {"file_path": p}),
    ("bintra_sensory_audit", lambda p: {"file_path": p}),
    ("bintra_scan_hybrid", lambda p: {"file_path": p}),
    ("bintra_deobfuscate_binary", lambda p: {"file_path": p}),
    ("bintra_dump_bytes", lambda p: {"file_path": p, "offset": 0, "length": 64}),
    ("bintra_triage_binary", lambda p: {"file_path": p, "include_deobfuscation": True}),
]

DEFECT_TYPES = ("IndexError", "KeyError", "TypeError", "AttributeError", "ZeroDivisionError", "struct.error",
                "error: unpack", "OverflowError", "MemoryError", "RecursionError", "UnboundLocalError", "NameError",
                "UnicodeDecodeError", "Internal error", "Traceback", "unpack_from requires", "unpack requires")


def call_tool_inprocess(srv, name: str, args: Dict[str, Any], budget_s: float) -> tuple:
    box: Dict[str, Any] = {}

    def _run():
        try:
            box["r"] = srv.handle_tools_call({"name": name, "arguments": args})
        except BaseException as e:  # noqa
            box["exc"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()[-1500:]}"

    t0 = time.perf_counter()
    th = threading.Thread(target=_run, daemon=True)
    th.start()
    th.join(budget_s)
    dt = time.perf_counter() - t0
    if th.is_alive():
        return "hang", f"exceeded {budget_s}s", dt
    if "exc" in box:
        return "raised", box["exc"], dt
    r = box["r"]
    txt = r["content"][0]["text"] if r.get("content") else json.dumps(r)
    hit = next((t for t in DEFECT_TYPES if t in txt), None)
    if hit:
        return "defect", txt[:1500], dt
    return "ok", "", dt


def level_7(m: Matrix, s: Dict[str, Optional[Path]], quick: bool):
    L = "L7"
    sys.path.insert(0, str(SRC_DIR))
    from mcp_server import BintraMcpServer
    srv = BintraMcpServer(workspace_root=str(m.ws))
    seeds = [p for p in (s.get("pe64_exe"), s.get("pe32_exe")) if p]
    for seed in seeds:
        corpus = build_fuzz_corpus(seed, m.ws / "fuzz" / seed.parent.name, n_random=8 if quick else 24)
        failures: Dict[str, List[str]] = {}
        t_all = time.perf_counter()
        for f in corpus:
            for name, mk in STATIC_TOOLS:
                verdict, detail, dt = call_tool_inprocess(srv, name, mk(str(f)), budget_s=60)
                if verdict != "ok":
                    key = f"{name}::{verdict}::{detail.splitlines()[0][:160] if detail else ''}"
                    failures.setdefault(key, []).append(f.name)
        for key, files in failures.items():
            name, verdict, first = key.split("::", 2)
            m.record(L, f"{seed.parent.name}/{name}/{verdict}", "fail", f"{first} | {len(files)} inputs e.g. {files[:4]}", 0.0)
        m.record(L, f"{seed.parent.name}/corpus({len(corpus)} files x {len(STATIC_TOOLS)} tools)",
                 "fail" if failures else "pass", f"{len(failures)} distinct defect signatures" if failures else "", time.perf_counter() - t_all)


def level_8(m: Matrix, s: Dict[str, Optional[Path]], quick: bool, count: int):
    L = "L8"
    sys.path.insert(0, str(SRC_DIR))
    from mcp_server import BintraMcpServer
    srv = BintraMcpServer(workspace_root=str(m.ws))
    files = sorted(glob.glob(str(SYS32 / "*.dll")) + glob.glob(str(SYS32 / "*.exe")) + glob.glob(str(SYS32 / "drivers" / "*.sys")))
    if not files:
        m.skip(L, "*", "no System32")
        return
    step = max(1, len(files) // count)
    picked = files[::step][:count]
    lat = []
    fails: Dict[str, List[str]] = {}
    t_all = time.perf_counter()
    for f in picked:
        verdict, detail, dt = call_tool_inprocess(srv, "bintra_triage_binary", {"file_path": f, "include_deobfuscation": True}, budget_s=120)
        lat.append((dt, os.path.basename(f)))
        if verdict != "ok":
            fails.setdefault(f"{verdict}: {detail.splitlines()[0][:200] if detail else ''}", []).append(os.path.basename(f))
    lat.sort(reverse=True)
    tot = time.perf_counter() - t_all
    for sig, fl in fails.items():
        m.record(L, f"triage-scale/{sig[:80]}", "fail", f"{sig} | {len(fl)} files e.g. {fl[:5]}")
    vals = sorted(x[0] for x in lat)
    p50 = vals[len(vals) // 2]
    p95 = vals[int(len(vals) * 0.95) - 1] if len(vals) > 1 else vals[0]
    m.record(L, f"triage-scale({len(picked)} System32 binaries)", "fail" if fails else "pass",
             f"p50={p50:.2f}s p95={p95:.2f}s max={lat[0][0]:.2f}s ({lat[0][1]}); slowest={[(round(a, 1), b) for a, b in lat[:5]]}", tot,
             p50=p50, p95=p95, slowest=[(round(a, 2), b) for a, b in lat[:10]])


# --------------------------------------------------------------------------
def write_reports(m: Matrix, started: float):
    res = m.results
    summ = {st: sum(1 for r in res if r["status"] == st) for st in ("pass", "fail", "skip")}
    (m.ws / "results.json").write_text(json.dumps({"summary": summ, "results": res, "python": sys.version,
                                                   "platform": sys.platform, "elapsed_s": round(time.time() - started, 1)},
                                                  indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["# Real-World Matrix Summary", "", f"- Python: `{sys.version.split()[0]}`  Platform: `{sys.platform}`",
             f"- Elapsed: {time.time() - started:.0f}s", f"- **pass {summ['pass']} / fail {summ['fail']} / skip {summ['skip']}**", "",
             "| Level | Pass | Fail | Skip |", "|---|---|---|---|"]
    for lv in sorted({r["level"] for r in res}):
        rr = [r for r in res if r["level"] == lv]
        lines.append(f"| {lv} | {sum(r['status'] == 'pass' for r in rr)} | {sum(r['status'] == 'fail' for r in rr)} | {sum(r['status'] == 'skip' for r in rr)} |")
    fails = [r for r in res if r["status"] == "fail"]
    if fails:
        lines += ["", "## Failures", ""]
        for r in fails:
            lines.append(f"- **{r['level']} {r['case']}** — {r['detail'][:400]}")
    (m.ws / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n" + "\n".join(lines[:12]))
    return summ


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--levels", default="L1,L2,L3,L4,L5,L6,L7,L8")
    ap.add_argument("--workspace", default=str(REPO_ROOT / "workspace" / "real_world"))
    ap.add_argument("--extra-sample", action="append", default=[])
    ap.add_argument("--extra-dump", action="append", default=[])
    ap.add_argument("--scale-count", type=int, default=150)
    ap.add_argument("--quick", action="store_true", help="Smaller corpus / fewer heavy analyzers")
    a = ap.parse_args()
    ws = Path(a.workspace).resolve()
    ws.mkdir(parents=True, exist_ok=True)
    m = Matrix(ws)
    started = time.time()
    s = discover_samples(m, a.extra_sample)
    print("Samples:", json.dumps({k: str(v) if v else None for k, v in s.items()}, indent=1, ensure_ascii=False))
    lv = {x.strip().upper() for x in a.levels.split(",")}
    steps = [("L1", lambda: level_1(m, s, a.quick)), ("L2", lambda: level_2(m, s, a.quick)),
             ("L3", lambda: level_3(m, s, a.extra_dump, a.quick)), ("L4", lambda: level_4(m, s, a.quick)),
             ("L5", lambda: level_5(m, s, a.quick)), ("L6", lambda: level_6(m, s, a.quick)),
             ("L7", lambda: level_7(m, s, a.quick)), ("L8", lambda: level_8(m, s, a.quick, a.scale_count))]
    for name, fn in steps:
        if name in lv:
            print(f"\n===== {name} =====", flush=True)
            try:
                fn()
            except Exception:
                m.record(name, "harness", "fail", "harness crashed: " + traceback.format_exc()[-1500:])
    summ = write_reports(m, started)
    sys.exit(1 if summ["fail"] else 0)


if __name__ == "__main__":
    main()
