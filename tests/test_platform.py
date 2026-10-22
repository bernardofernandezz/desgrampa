import tempfile
import unittest
from pathlib import Path
from unittest import mock

from desgrampa import adb, evidence, oscompat, paths
from desgrampa.checks import pcnet


class WirelessTests(unittest.TestCase):
    def test_target_validation(self):
        self.assertEqual(adb.wireless_target("192.168.0.12", "37123"), "192.168.0.12:37123")
        for host, port in (("8.8.8.8", 5555), ("192.168.0.12", 0), ("exemplo.com", 5555), ("192.168.0.12", "x"),
                           ("192.168.0.12; rm -rf /", 5555)):
            with self.assertRaises(adb.AdbError):
                adb.wireless_target(host, port)

    def test_pair_requires_six_digit_code(self):
        with mock.patch.object(adb, "_run") as run:
            for code in ("12345", "abcdef", "1234567", None):
                with self.assertRaises(adb.AdbError):
                    adb.pair("192.168.0.12", 37123, code)
            run.assert_not_called()

    def test_pair_and_connect_results(self):
        ok = mock.Mock(stdout="Successfully paired to 192.168.0.12:37123 [guid=adb-X]", stderr="")
        with mock.patch.object(adb, "_run", return_value=ok) as run:
            adb.pair("192.168.0.12", 37123, "123456")
        run.assert_called_once_with(["pair", "192.168.0.12:37123", "123456"], timeout=30)
        fail = mock.Mock(stdout="failed to connect to 192.168.0.12:41567", stderr="")
        with mock.patch.object(adb, "_run", return_value=fail), self.assertRaises(adb.AdbError):
            adb.connect("192.168.0.12", 41567)

    def test_wireless_serials(self):
        self.assertTrue(adb.is_wireless_serial("192.168.0.12:41567"))
        self.assertTrue(adb.is_wireless_serial("adb-R58M123-abc._adb-tls-connect._tcp"))
        self.assertFalse(adb.is_wireless_serial("R58M123ABC"))
        with self.assertRaises(adb.AdbError):
            adb.disconnect("R58M123ABC")

    def test_missing_adb_binary_is_an_adb_error(self):
        with mock.patch.dict("os.environ", {"DESGRAMPA_ADB": "/nao/existe/adb"}), self.assertRaises(adb.AdbError):
            adb.list_devices()


class NetworkParserTests(unittest.TestCase):
    def test_windows_arp_and_route(self):
        arp = """
Interface: 192.168.0.10 --- 0x5
  Endereço IP           Endereço físico       Tipo
  192.168.0.1           aa-bb-cc-dd-ee-ff     dinâmico
  192.168.0.255         ff-ff-ff-ff-ff-ff     estático
  224.0.0.22            01-00-5e-00-00-16     estático
"""
        self.assertEqual(pcnet.parse_arp_a(arp), {"192.168.0.1": "aa:bb:cc:dd:ee:ff"})
        route = """
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.0.0.1       10.0.0.5     50
          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.10     25
"""
        self.assertEqual(pcnet.parse_route_print(route), ("192.168.0.1", "192.168.0.10"))
        self.assertEqual(pcnet.parse_route_print(""), (None, None))

    def test_macos_arp_and_route(self):
        arp = "? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0\n"
        self.assertEqual(pcnet.parse_arp_a(arp), {"192.168.1.1": "0a:0b:0c:0d:0e:0f"})
        self.assertEqual(pcnet.parse_route_get("    gateway: 192.168.1.1\n  interface: en0\n"), ("192.168.1.1", "en0"))


class PathTests(unittest.TestCase):
    def test_user_data_dir_per_system(self):
        with mock.patch.object(paths, "IS_WINDOWS", True), mock.patch.dict("os.environ", {"LOCALAPPDATA": "C:/Users/a/AppData/Local"}):
            self.assertEqual(paths.user_data_dir(), Path("C:/Users/a/AppData/Local") / "Desgrampa")
        with mock.patch.object(paths, "IS_WINDOWS", False), mock.patch.object(paths, "IS_MAC", True):
            self.assertEqual(paths.user_data_dir().name, "Desgrampa")
        with mock.patch.object(paths, "IS_WINDOWS", False), mock.patch.object(paths, "IS_MAC", False), \
                mock.patch.dict("os.environ", {"XDG_DATA_HOME": "/xdg"}):
            self.assertEqual(paths.user_data_dir(), Path("/xdg/desgrampa"))

    def test_tool_lookup_order(self):
        with mock.patch.dict("os.environ", {"DESGRAMPA_ADB": "/opt/adb"}):
            self.assertEqual(oscompat.find_tool("adb", "DESGRAMPA_ADB"), "/opt/adb")
        self.assertTrue(str(oscompat.venv_script("/env", "mvt-android")).endswith(oscompat.exe("mvt-android")))


class EvidenceDirTests(unittest.TestCase):
    def test_same_second_scans_get_separate_folders(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(evidence, "REPORTS_DIR", Path(tmp)):
            a = evidence.new_dir("SER", 0)
            b = evidence.new_dir("SER", 0)
            c = evidence.new_dir("SER", 0, prefix="ATD-20260101-001")
        self.assertNotEqual(a, b)
        self.assertTrue(b.name.endswith("-2"))
        self.assertTrue(c.name.startswith("ATD-20260101-001_"))
