import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from windows_intelligence.device_intelligence.device_identity import DeviceIdentity
from windows_intelligence.device_intelligence.driver_matcher import DriverMatcher
from windows_intelligence.device_intelligence.driver_package_inventory import DriverPackageInventory
from windows_intelligence.system_introspection.device_inspector import NativeDeviceInspector


class TestDocsSkillsToolsHwUpgrades(unittest.TestCase):
    def test_device_identity_extended_buses_and_vendors(self):
        hda = DeviceIdentity.parse_device_instance(r"HDAUDIO\FUNC_01&VEN_10EC&DEV_0892&SUBSYS_10438691&REV_1003")
        self.assertEqual(hda["bus_type"], "HDAUDIO")
        self.assertEqual(hda["vendor_id"], "10EC")
        self.assertEqual(hda["device_id"], "0892")

        hid = DeviceIdentity.parse_device_instance(r"HID\VID_0FD9&PID_0063&MI_00")
        self.assertEqual(hid["bus_type"], "HID")
        self.assertEqual(hid["vendor_id"], "0FD9")
        self.assertIn("Elgato", hid["vendor_name"])

        acpi = DeviceIdentity.parse_device_instance(r"ACPI\PNP0A08\0")
        self.assertEqual(acpi["bus_type"], "ACPI")

    def test_native_device_inspector_problem_descriptions(self):
        self.assertIn("CM_PROB_FAILED_START", NativeDeviceInspector.describe_problem_code(10))
        self.assertIn("CM_PROB_UNSIGNED_DRIVER", NativeDeviceInspector.describe_problem_code(52))
        self.assertEqual(NativeDeviceInspector.describe_problem_code(0), "Healthy")

    def test_offline_inf_parsing_and_driver_rank_matching(self):
        inf_text = """
        [Version]
        Signature="$WINDOWS NT$"
        Class=MEDIA
        Provider=%MfgName%
        DriverVer=06/15/2026,1.2.3.4
        CatalogFile=elgato_audio.cat

        [Manufacturer]
        %MfgName%=Models,NTamd64

        [Models.NTamd64]
        %DevDesc%=InstallSec, USB\\VID_0FD9&PID_0063&REV_0100

        [Strings]
        MfgName="Elgato Systems GmbH"
        DevDesc="Elgato Wave Device"
        """
        parsed = DriverPackageInventory.parse_inf_text(inf_text, source_name="elgato.inf")
        self.assertEqual(parsed["class_name"], "MEDIA")
        self.assertEqual(parsed["provider_name"], "Elgato Systems GmbH")
        self.assertEqual(parsed["driver_version"], "1.2.3.4")
        self.assertIn("USB\\VID_0FD9&PID_0063&REV_0100", parsed["hardware_ids"])

        res = DriverMatcher.match_offline_device_to_infs(
            {"device_instance_id": r"USB\VID_0FD9&PID_0063&REV_0100", "hardware_ids": [r"USB\VID_0FD9&PID_0063&REV_0100"]},
            [parsed],
        )
        self.assertEqual(res["driver_rank"], 1)
        self.assertEqual(res["matched_inf"]["source"], "elgato.inf")

    def test_obs_common_helper_and_cli_help(self):
        scripts_dir = Path(__file__).resolve().parent.parent / "benchmarks" / "obs_studio" / "scripts"
        sys.path.insert(0, str(scripts_dir))
        try:
            import obs_common
            cleaned = obs_common.sanitize_text("/obs/root/bin/obs64.exe", Path("/obs/root"), Path("/repo/root"))
            self.assertEqual(cleaned, "<OBS_ROOT>/bin/obs64.exe")
        finally:
            sys.path.pop(0)

        repo_root = Path(__file__).resolve().parent.parent
        env = dict(os.environ, PYTHONPATH=str(repo_root / "src"))
        proc = subprocess.run(
            [sys.executable, str(repo_root / "src" / "cli.py"), "evidence-graph", "--help"],
            capture_output=True, text=True, env=env, timeout=10
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--format", proc.stdout)

    def test_mcp_offline_inf_matching_dispatch(self):
        from mcp_server import BintraMcpServer
        srv = BintraMcpServer()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".inf", delete=False, encoding="utf-8") as tf:
            tf.write("[Version]\nClass=USB\n[Models]\nDev=Inst, USB\\VID_0FD9&PID_0063\n")
            inf_path = tf.name
        try:
            res = srv.dispatch_tool("bintra_device_driver_intelligence", {
                "device_id": r"USB\VID_0FD9&PID_0063",
                "offline_inf_paths": [inf_path],
            })
            self.assertEqual(res["driver_rank"], 1)
            self.assertEqual(res["identity"]["vendor_id"], "0FD9")
        finally:
            os.unlink(inf_path)


if __name__ == "__main__":
    unittest.main()
