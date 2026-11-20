# -*- coding: utf-8 -*-
"""
Tests for ProcessLongitudinalProfiler and Memory Leak Diagnostic Engine.
"""

import os
import unittest
from windows_intelligence.process_intelligence.process_profiler import ProcessLongitudinalProfiler


class TestProcessLongitudinalProfiler(unittest.TestCase):

    def test_analyze_stable_series(self):
        """Verify that a series with flat memory is classified as STABLE_EQUILIBRIUM."""
        samples = [
            {
                "sample_index": i,
                "timestamp_epoch": 1000.0 + i,
                "working_set_mb": 45.0,
                "private_bytes_mb": 14.5,
                "peak_working_set_mb": 45.0,
                "peak_private_bytes_mb": 14.5,
                "kernel_handles": 480,
                "gdi_handles": 320,
                "user_handles": 100,
            }
            for i in range(1, 11)
        ]
        res = ProcessLongitudinalProfiler.analyze_telemetry_series(pid=1234, telemetry_samples=samples)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["behavior_classification"], "STABLE_EQUILIBRIUM")
        self.assertEqual(res["metrics_summary"]["delta_private_bytes_mb"], 0.0)
        self.assertEqual(res["metrics_summary"]["slope_private_bytes_mb_per_sample"], 0.0)

    def test_analyze_saturation_plateau(self):
        """Verify detection of saturation plateau (initial growth then flat line)."""
        # Cycles 1..5 grow, cycles 6..10 remain flat at 28.0 MB
        priv_vals = [14.0, 18.0, 22.0, 26.0, 28.0, 28.0, 28.0, 28.0, 28.0, 28.0]
        samples = [
            {
                "sample_index": i + 1,
                "timestamp_epoch": 1000.0 + i,
                "working_set_mb": 40.0 + (priv_vals[i] * 0.5),
                "private_bytes_mb": priv_vals[i],
                "peak_working_set_mb": 60.0,
                "peak_private_bytes_mb": 28.0,
                "kernel_handles": 485,
                "gdi_handles": 300 + (i * 20 if i < 5 else 100),
                "user_handles": 100,
            }
            for i in range(10)
        ]
        res = ProcessLongitudinalProfiler.analyze_telemetry_series(pid=5678, telemetry_samples=samples)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["behavior_classification"], "SATURATION_PLATEAU")
        self.assertTrue(res["metrics_summary"]["is_saturation_plateau"])
        self.assertEqual(res["metrics_summary"]["final_private_bytes_mb"], 28.0)

    def test_analyze_active_memory_leak(self):
        """Verify detection of monotonic unconstrained private bytes growth."""
        samples = [
            {
                "sample_index": i + 1,
                "timestamp_epoch": 1000.0 + i,
                "working_set_mb": 40.0 + i * 2.0,
                "private_bytes_mb": 10.0 + i * 5.0,  # +5 MB every sample monotonically
                "peak_working_set_mb": 60.0,
                "peak_private_bytes_mb": 60.0,
                "kernel_handles": 485,
                "gdi_handles": 300,
                "user_handles": 100,
            }
            for i in range(10)
        ]
        res = ProcessLongitudinalProfiler.analyze_telemetry_series(pid=9999, telemetry_samples=samples)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["behavior_classification"], "ACTIVE_MEMORY_LEAK_SUSPECTED")
        self.assertGreater(res["metrics_summary"]["slope_private_bytes_mb_per_sample"], 4.0)

    def test_sample_current_process(self):
        """Verify sampling of the current running Python process on Windows."""
        if os.name == "nt":
            sample = ProcessLongitudinalProfiler.sample_process(os.getpid())
            self.assertIsNotNone(sample)
            self.assertIn("working_set_mb", sample)
            self.assertIn("private_bytes_mb", sample)
            self.assertIn("kernel_handles", sample)
            self.assertGreater(sample["working_set_mb"], 0.0)


    def test_active_gdi_leak_classification(self):
        """Verify active GDI leak detection when GDI handles accumulate without ceiling."""
        samples = [
            {
                "sample_index": i + 1,
                "timestamp_epoch": 1000.0 + i,
                "working_set_mb": 50.0,
                "private_bytes_mb": 20.0,
                "peak_working_set_mb": 50.0,
                "peak_private_bytes_mb": 20.0,
                "kernel_handles": 300,
                "gdi_handles": 100 + (i * 15),  # Accumulates 15 GDI handles each cycle (100 -> 235)
                "user_handles": 50,
            }
            for i in range(10)
        ]
        res = ProcessLongitudinalProfiler.analyze_telemetry_series(pid=4321, telemetry_samples=samples)
        self.assertEqual(res["behavior_classification"], "ACTIVE_GDI_LEAK_SUSPECTED")
        self.assertIn("GDI object accumulation", res["diagnostic_explanation"])
        self.assertGreater(res["metrics_summary"]["delta_gdi_handles"], 100)

    def test_active_user_object_leak_classification(self):
        """Verify active USER object leak detection."""
        samples = [
            {
                "sample_index": i + 1,
                "timestamp_epoch": 1000.0 + i,
                "working_set_mb": 50.0,
                "private_bytes_mb": 20.0,
                "peak_working_set_mb": 50.0,
                "peak_private_bytes_mb": 20.0,
                "kernel_handles": 300,
                "gdi_handles": 50,
                "user_handles": 80 + (i * 12),  # Accumulates 12 USER handles each cycle
            }
            for i in range(10)
        ]
        res = ProcessLongitudinalProfiler.analyze_telemetry_series(pid=4322, telemetry_samples=samples)
        self.assertEqual(res["behavior_classification"], "ACTIVE_USER_OBJECT_LEAK_SUSPECTED")
        self.assertIn("USER object accumulation", res["diagnostic_explanation"])

    def test_win32_prototypes_initialized(self):
        """Verify that win32 foreign function prototypes are properly configured on Windows NT."""
        if os.name == "nt":
            from windows_intelligence.process_intelligence.process_profiler import _init_win32_prototypes
            import ctypes
            from ctypes import wintypes
            _init_win32_prototypes()
            windll = getattr(ctypes, "windll", None)
            if windll:
                k32 = getattr(windll, "kernel32", None)
                if k32 and hasattr(k32, "OpenProcess"):
                    self.assertEqual(k32.OpenProcess.restype, wintypes.HANDLE)
                    self.assertEqual(len(k32.OpenProcess.argtypes), 3)

if __name__ == "__main__":
    unittest.main()
