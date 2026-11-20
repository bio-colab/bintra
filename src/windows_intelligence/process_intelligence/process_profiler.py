# -*- coding: utf-8 -*-
"""
Process Longitudinal Resource Profiler & Memory Leak Diagnostic Engine.
Provides high-fidelity, passive, multi-sample resource auditing for Windows processes:
1. Exact memory counters matching Microsoft Learn standards:
   - Private Bytes (PagefileUsage) representing unshared dedicated process commit.
   - Working Set (WorkingSetSize) representing physical RAM footprint.
   - Peak Working Set and Peak Private Bytes.
2. Kernel and GUI object resource tracking:
   - Kernel Handles (via GetProcessHandleCount).
   - GDI Objects (via GetGuiResources GR_GDIOBJECTS).
   - USER Objects (via GetGuiResources GR_USEROBJECTS).
3. Longitudinal regression and behavior classification:
   - Linear regression slopes for memory, kernel handles, and GDI objects.
   - Empirical distinction between STABLE, SATURATION_PLATEAU (undo/font caches), and ACTIVE_LEAK.
"""

from __future__ import annotations

import os
import sys
import time
import ctypes
from ctypes import wintypes
from typing import Dict, Any, List, Optional, Tuple


# Win32 Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010

GR_GDIOBJECTS = 0
GR_USEROBJECTS = 1

_WIN32_INITIALIZED = False


def _init_win32_prototypes():
    """Explicitly configures Win32 foreign function prototypes with 64-bit safe ctypes."""
    global _WIN32_INITIALIZED
    if _WIN32_INITIALIZED or os.name != "nt":
        return
    windll = getattr(ctypes, "windll", None)
    if not windll:
        return

    k32 = getattr(windll, "kernel32", None)
    if k32:
        if hasattr(k32, "OpenProcess"):
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
        if hasattr(k32, "CloseHandle"):
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL
        if hasattr(k32, "GetProcessHandleCount"):
            k32.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            k32.GetProcessHandleCount.restype = wintypes.BOOL
        if hasattr(k32, "GetLastError"):
            k32.GetLastError.argtypes = []
            k32.GetLastError.restype = wintypes.DWORD

    ps = getattr(windll, "psapi", getattr(windll, "kernel32", None))
    if ps and hasattr(ps, "GetProcessMemoryInfo"):
        ps.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
            wintypes.DWORD
        ]
        ps.GetProcessMemoryInfo.restype = wintypes.BOOL

    u32 = getattr(windll, "user32", None)
    if u32 and hasattr(u32, "GetGuiResources"):
        u32.GetGuiResources.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        u32.GetGuiResources.restype = wintypes.DWORD

    _WIN32_INITIALIZED = True



class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),  # Private Bytes
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


class ProcessResourceSample:
    """Represents a single atomic resource measurement for a target process."""

    def __init__(
        self,
        sample_index: int,
        timestamp_epoch: float,
        working_set_bytes: int,
        private_bytes: int,
        peak_working_set_bytes: int,
        peak_private_bytes: int,
        kernel_handles: int,
        gdi_handles: int,
        user_handles: int,
    ):
        self.sample_index = sample_index
        self.timestamp_epoch = timestamp_epoch
        self.working_set_bytes = working_set_bytes
        self.private_bytes = private_bytes
        self.peak_working_set_bytes = peak_working_set_bytes
        self.peak_private_bytes = peak_private_bytes
        self.kernel_handles = kernel_handles
        self.gdi_handles = gdi_handles
        self.user_handles = user_handles

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_index": self.sample_index,
            "timestamp_epoch": self.timestamp_epoch,
            "working_set_mb": round(self.working_set_bytes / (1024 * 1024), 3),
            "private_bytes_mb": round(self.private_bytes / (1024 * 1024), 3),
            "peak_working_set_mb": round(self.peak_working_set_bytes / (1024 * 1024), 3),
            "peak_private_bytes_mb": round(self.peak_private_bytes / (1024 * 1024), 3),
            "kernel_handles": self.kernel_handles,
            "gdi_handles": self.gdi_handles,
            "user_handles": self.user_handles,
        }


class ProcessLongitudinalProfiler:
    """
    Longitudinal resource profiler and leak diagnosis engine for Windows processes.
    """

    @classmethod
    def _get_kernel32(cls):
        windll = getattr(ctypes, "windll", None)
        return getattr(windll, "kernel32", None) if windll else None

    @classmethod
    def _get_user32(cls):
        windll = getattr(ctypes, "windll", None)
        return getattr(windll, "user32", None) if windll else None

    @classmethod
    def _get_psapi(cls):
        windll = getattr(ctypes, "windll", None)
        return getattr(windll, "psapi", getattr(windll, "kernel32", None)) if windll else None

    @classmethod
    def sample_process(cls, pid: int) -> Optional[Dict[str, Any]]:
        """
        Samples real-time memory and resource counters for a running process by PID.
        Returns None if process cannot be opened or platform is not Windows.
        """
        if os.name != "nt":
            return None

        _init_win32_prototypes()
        k32 = cls._get_kernel32()
        u32 = cls._get_user32()
        ps = cls._get_psapi()
        if not k32 or not ps:
            return None

        h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            # Fallback to limited information
            h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h_proc:
                return None

        try:
            pmc = PROCESS_MEMORY_COUNTERS_EX()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
            success = ps.GetProcessMemoryInfo(h_proc, ctypes.byref(pmc), pmc.cb)
            if not success:
                return None

            h_cnt = wintypes.DWORD(0)
            handles_val = 0
            if hasattr(k32, "GetProcessHandleCount"):
                if k32.GetProcessHandleCount(h_proc, ctypes.byref(h_cnt)):
                    handles_val = h_cnt.value
                else:
                    handles_val = -1

            gdi_cnt = 0
            usr_cnt = 0
            if u32 and hasattr(u32, "GetGuiResources"):
                gdi_cnt = u32.GetGuiResources(h_proc, GR_GDIOBJECTS)
                usr_cnt = u32.GetGuiResources(h_proc, GR_USEROBJECTS)

            sample = ProcessResourceSample(
                sample_index=0,
                timestamp_epoch=time.time(),
                working_set_bytes=pmc.WorkingSetSize,
                private_bytes=pmc.PagefileUsage,
                peak_working_set_bytes=pmc.PeakWorkingSetSize,
                peak_private_bytes=pmc.PeakPagefileUsage,
                kernel_handles=handles_val,
                gdi_handles=gdi_cnt,
                user_handles=usr_cnt,
            )
            return sample.to_dict()
        finally:
            k32.CloseHandle(h_proc)

    @classmethod
    def profile_pid_longitudinal(
        cls,
        pid: int,
        samples_count: int = 10,
        interval_seconds: float = 0.2
    ) -> Dict[str, Any]:
        """
        Profiles a target process over multiple consecutive time intervals,
        computing linear regression slopes and classifying resource behavior.
        Enforces defensive bounds:
          - samples_count: bounded to [2, 120]
          - interval_seconds: bounded to [0.01, 10.0]
        """
        if os.name != "nt":
            return {
                "status": "not_applicable",
                "platform": sys.platform,
                "reason": "Process longitudinal profiling requires Windows NT."
            }

        _init_win32_prototypes()
        samples_count = max(2, min(int(samples_count), 120))
        interval_seconds = max(0.01, min(float(interval_seconds), 10.0))

        k32 = cls._get_kernel32()
        u32 = cls._get_user32()
        ps = cls._get_psapi()
        if not k32 or not ps:
            return {"status": "error", "error": "Win32 APIs not accessible."}

        h_proc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h_proc:
            h_proc = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h_proc:
                err = k32.GetLastError() if hasattr(k32, "GetLastError") else 0
                return {"status": "error", "error": f"Failed to open process PID {pid} (Win32 error: {err})."}

        samples: List[ProcessResourceSample] = []
        try:
            for idx in range(1, samples_count + 1):
                pmc = PROCESS_MEMORY_COUNTERS_EX()
                pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
                if not ps.GetProcessMemoryInfo(h_proc, ctypes.byref(pmc), pmc.cb):
                    break

                h_cnt = wintypes.DWORD(0)
                handles_val = 0
                if hasattr(k32, "GetProcessHandleCount"):
                    if k32.GetProcessHandleCount(h_proc, ctypes.byref(h_cnt)):
                        handles_val = h_cnt.value
                    else:
                        handles_val = -1

                gdi_cnt = 0
                usr_cnt = 0
                if u32 and hasattr(u32, "GetGuiResources"):
                    gdi_cnt = u32.GetGuiResources(h_proc, GR_GDIOBJECTS)
                    usr_cnt = u32.GetGuiResources(h_proc, GR_USEROBJECTS)

                s = ProcessResourceSample(
                    sample_index=idx,
                    timestamp_epoch=time.time(),
                    working_set_bytes=pmc.WorkingSetSize,
                    private_bytes=pmc.PagefileUsage,
                    peak_working_set_bytes=pmc.PeakWorkingSetSize,
                    peak_private_bytes=pmc.PeakPagefileUsage,
                    kernel_handles=handles_val,
                    gdi_handles=gdi_cnt,
                    user_handles=usr_cnt,
                )
                samples.append(s)

                if idx < samples_count and interval_seconds > 0:
                    time.sleep(interval_seconds)
        finally:
            k32.CloseHandle(h_proc)

        if not samples:
            return {"status": "error", "error": f"Failed to acquire memory telemetry for PID {pid}."}

        return cls.analyze_telemetry_series(pid, [s.to_dict() for s in samples])

    @classmethod
    def analyze_telemetry_series(
        cls,
        pid: Optional[int],
        telemetry_samples: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyzes an existing series of process samples (from live profiling or recorded logs),
        computing regression slopes, handle deltas, and behavioral diagnostics across
        Private Bytes, Working Set, Kernel Handles, GDI Objects, and USER Objects.
        """
        n = len(telemetry_samples)
        if n == 0:
            return {"status": "error", "error": "Empty telemetry series."}

        x = [s.get("sample_index", i + 1) for i, s in enumerate(telemetry_samples)]
        y_priv = [s["private_bytes_mb"] for s in telemetry_samples]
        y_ws = [s["working_set_mb"] for s in telemetry_samples]
        y_hnd = [s.get("kernel_handles", 0) for s in telemetry_samples]
        y_gdi = [s.get("gdi_handles", 0) for s in telemetry_samples]
        y_usr = [s.get("user_handles", 0) for s in telemetry_samples]

        def calc_linear_regression(x_vals: List[float], y_vals: List[float]) -> Tuple[float, float]:
            """Returns (slope, r_squared)"""
            if len(x_vals) < 2:
                return 0.0, 1.0
            mean_x = sum(x_vals) / len(x_vals)
            mean_y = sum(y_vals) / len(y_vals)
            ss_tot = sum((y - mean_y) ** 2 for y in y_vals)
            num = sum((x_vals[i] - mean_x) * (y_vals[i] - mean_y) for i in range(len(x_vals)))
            den = sum((x_vals[i] - mean_x) ** 2 for i in range(len(x_vals)))
            if den == 0:
                return 0.0, 0.0
            slope = num / den
            if ss_tot == 0:
                r_sq = 1.0
            else:
                ss_res = sum((y_vals[i] - (mean_y + slope * (x_vals[i] - mean_x))) ** 2 for i in range(len(x_vals)))
                r_sq = max(0.0, 1.0 - (ss_res / ss_tot))
            return round(slope, 5), round(r_sq, 4)

        slope_priv, r2_priv = calc_linear_regression(x, y_priv)
        slope_ws, r2_ws = calc_linear_regression(x, y_ws)
        slope_hnd, _ = calc_linear_regression(x, [float(v) for v in y_hnd])
        slope_gdi, r2_gdi = calc_linear_regression(x, [float(v) for v in y_gdi])
        slope_usr, r2_usr = calc_linear_regression(x, [float(v) for v in y_usr])

        delta_priv = round(y_priv[-1] - y_priv[0], 3)
        delta_ws = round(y_ws[-1] - y_ws[0], 3)
        delta_hnd = y_hnd[-1] - y_hnd[0]
        delta_gdi = y_gdi[-1] - y_gdi[0]
        delta_usr = y_usr[-1] - y_usr[0]

        # Plateau detection: examine variance and slope in second half of samples
        half_idx = max(1, n // 2)
        second_half_priv = y_priv[half_idx:]
        second_half_slope, _ = calc_linear_regression(x[half_idx:], second_half_priv)
        second_half_gdi_slope, _ = calc_linear_regression(x[half_idx:], [float(v) for v in y_gdi[half_idx:]])
        second_half_usr_slope, _ = calc_linear_regression(x[half_idx:], [float(v) for v in y_usr[half_idx:]])
        second_half_hnd_slope, _ = calc_linear_regression(x[half_idx:], [float(v) for v in y_hnd[half_idx:]])
        is_plateau = False

        if n >= 6 and delta_priv > 0:
            # If second half slope is near zero while overall delta grew
            if abs(second_half_slope) <= 0.02 and (max(second_half_priv) - min(second_half_priv)) <= 0.25:
                is_plateau = True

        # Active leaks require ongoing unconstrained accumulation into the second half of the series
        is_gdi_leak = delta_gdi > 10 and slope_gdi > 0.5 and second_half_gdi_slope > 0.1
        is_usr_leak = delta_usr > 10 and slope_usr > 0.5 and second_half_usr_slope > 0.1
        is_hnd_leak = delta_hnd > 20 and slope_hnd > 0.5 and second_half_hnd_slope > 0.1
        is_mem_leak = slope_priv > 0.05 and r2_priv > 0.6 and not is_plateau

        # Behavioral Classification (Strictly considers memory, kernel handles, GDI, and USER objects)
        if is_gdi_leak:
            classification = "ACTIVE_GDI_LEAK_SUSPECTED"
            explanation = (
                f"Continuous unconstrained GDI object accumulation (+{delta_gdi} objects, slope: +{slope_gdi}/sample); "
                f"risk of reaching 10,000 Win32 GDI quota."
            )
        elif is_usr_leak:
            classification = "ACTIVE_USER_OBJECT_LEAK_SUSPECTED"
            explanation = (
                f"Continuous unconstrained USER object accumulation (+{delta_usr} objects, slope: +{slope_usr}/sample); "
                f"potential window/hook handle leak."
            )
        elif is_hnd_leak:
            classification = "ACTIVE_HANDLE_LEAK_SUSPECTED"
            explanation = f"Monotonic kernel handle growth (+{delta_hnd} handles) without release."
        elif is_mem_leak:
            classification = "ACTIVE_MEMORY_LEAK_SUSPECTED"
            explanation = (
                f"Continuous monotonic private bytes growth (+{delta_priv} MB, slope: +{slope_priv} MB/sample) "
                f"without stabilization."
            )
        elif is_plateau:
            classification = "SATURATION_PLATEAU"
            explanation = (
                "Initial memory/resource growth leveled off into a flat plateau; characteristic of "
                "internal queue limits (e.g., undo history buffer, font cache saturation)."
            )
        elif (
            slope_priv <= 0.01 and delta_priv <= 0.1 and
            delta_hnd <= 2 and delta_gdi <= 2 and delta_usr <= 2
        ):
            classification = "STABLE_EQUILIBRIUM"
            explanation = "Process demonstrates strict bounded memory, zero handle accumulation, and stable GDI/USER resources."
        else:
            classification = "MONITORED_NORMAL_VARIATION"
            explanation = "Normal workload-driven memory fluctuations within expected runtime bounds."

        return {
            "status": "ok",
            "target_pid": pid,
            "total_samples": n,
            "behavior_classification": classification,
            "diagnostic_explanation": explanation,
            "metrics_summary": {
                "initial_private_bytes_mb": y_priv[0],
                "final_private_bytes_mb": y_priv[-1],
                "delta_private_bytes_mb": delta_priv,
                "slope_private_bytes_mb_per_sample": slope_priv,
                "r_squared_private_bytes": r2_priv,
                "initial_working_set_mb": y_ws[0],
                "final_working_set_mb": y_ws[-1],
                "delta_working_set_mb": delta_ws,
                "slope_working_set_mb_per_sample": slope_ws,
                "initial_kernel_handles": y_hnd[0],
                "final_kernel_handles": y_hnd[-1],
                "delta_kernel_handles": delta_hnd,
                "slope_kernel_handles_per_sample": slope_hnd,
                "initial_gdi_handles": y_gdi[0],
                "final_gdi_handles": y_gdi[-1],
                "delta_gdi_handles": delta_gdi,
                "slope_gdi_handles_per_sample": slope_gdi,
                "initial_user_handles": y_usr[0],
                "final_user_handles": y_usr[-1],
                "delta_user_handles": delta_usr,
                "slope_user_handles_per_sample": slope_usr,
                "is_saturation_plateau": is_plateau,
            },
            "samples": telemetry_samples,
        }

    # Alias for API backwards compatibility
    classify_dynamics = analyze_telemetry_series
