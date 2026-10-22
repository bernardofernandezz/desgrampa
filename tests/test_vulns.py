import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from desgrampa import bulletins
from desgrampa.checks import vulns
from desgrampa.context import PackageInfo

from .fake_device import FakeDevice
from .test_scan import BULLETINS, FIXTURES, scan, titles


def pkg(name, version):
    return PackageInfo(name=name, version=version, third_party=True, installer="com.android.vending")


class UnpatchedTests(unittest.TestCase):
    def ids(self, rows):
        return [r[0] for r in rows]

    def test_android_version_and_patch(self):
        confirmed, likely = vulns.unpatched(BULLETINS, "13", "2024-02-05")
        self.assertEqual(self.ids(confirmed), ["CVE-2024-0002", "CVE-2024-0003"])
        self.assertEqual(likely, [])

    def test_pixel_and_qualcomm_only_when_applicable(self):
        confirmed, _ = vulns.unpatched(BULLETINS, "14", "2023-01-01", pixel=True, qualcomm=True)
        self.assertEqual(self.ids(confirmed),
                         ["CVE-2024-0001", "CVE-2024-0003", "CVE-2024-0004", "CVE-2024-0005", "CVE-2024-0006"])

    def test_up_to_date_device(self):
        self.assertEqual(vulns.unpatched(BULLETINS, "14", "2024-06-05", True, True), ([], []))

    def test_end_of_life_version_gets_likely_findings(self):
        confirmed, likely = vulns.unpatched(BULLETINS, "11", "2023-01-01")
        self.assertEqual(self.ids(confirmed), ["CVE-2024-0003"])
        self.assertEqual(self.ids(likely), ["CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0006"])

    def test_qualcomm_detection(self):
        self.assertTrue(vulns.is_qualcomm({"ro.soc.manufacturer": "QTI"}))
        self.assertTrue(vulns.is_qualcomm({"ro.board.platform": "lahaina"}))
        self.assertFalse(vulns.is_qualcomm({"ro.board.platform": "mt6789", "ro.soc.manufacturer": "Mediatek"}))


class VersionTests(unittest.TestCase):
    def test_chromium_behind_and_exploited(self):
        rows = vulns.chromium_status(BULLETINS, {"com.google.android.webview": pkg("com.google.android.webview",
                                                                                  "121.0.6167.178")})
        self.assertEqual(rows[0]["behind"], 4)
        self.assertEqual(rows[0]["exploited"], ["CVE-2024-2222"])   # entrou no KEV depois da 122

    def test_chromium_current(self):
        rows = vulns.chromium_status(BULLETINS, {"com.android.chrome": pkg("com.android.chrome", "125.0.1")})
        self.assertEqual((rows[0]["behind"], rows[0]["exploited"]), (0, []))

    def test_chromium_older_than_history(self):
        rows = vulns.chromium_status(BULLETINS, {"com.android.chrome": pkg("com.android.chrome", "99.0")})
        self.assertEqual(rows[0]["exploited"], ["CVE-2024-1111", "CVE-2024-2222"])

    def test_messaging_app_versions(self):
        old = vulns.outdated_apps(BULLETINS, {"com.whatsapp": pkg("com.whatsapp", "2.22.9.75")})
        new = vulns.outdated_apps(BULLETINS, {"com.whatsapp": pkg("com.whatsapp", "2.22.16.12")})
        self.assertEqual([a["cve"] for a in old], ["CVE-2022-36934"])
        self.assertEqual(new, [])

    def test_exposure_levels(self):
        f = [{"label": "a", "points": 30, "active": True}, {"label": "b", "points": 30, "active": True},
             {"label": "c", "points": 50, "active": False}]
        self.assertEqual(vulns.exposure(f)["score"], 60)
        self.assertEqual(vulns.exposure(f)["level"], "alto")
        self.assertEqual(vulns.exposure([])["level"], "baixo")


class ScanTests(unittest.TestCase):
    def test_old_patch_lists_exploited_vulnerability(self):
        r = scan(FakeDevice(patch="2024-02-05"))
        t = titles(r)
        self.assertIn("1 falha(s) explorada(s) ativamente sem correção neste aparelho", t)
        data = r["data"]["vulns"]
        self.assertEqual(data["counts"]["kev"], 1)
        self.assertEqual(data["items"][0]["cve"], "CVE-2024-0002")   # exploradas primeiro
        self.assertFalse(data["device"]["eol"])
        cat = next(c for c in r["categories"] if c["id"] == "vulns")
        self.assertEqual(cat["status"], "alta")

    def test_up_to_date_device_has_no_vulnerability_findings(self):
        r = scan(FakeDevice())
        self.assertFalse([f for f in r["findings"] if f["category"] == "vulns"])
        self.assertIn("exposure", r["data"]["vulns"])

    def test_without_database_area_is_not_verified(self):
        r = scan(FakeDevice(), bulletins={})
        cat = next(c for c in r["categories"] if c["id"] == "vulns")
        self.assertEqual(cat["status"], "nao_verificado")


class DatabaseTests(unittest.TestCase):
    def test_newest_copy_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            newer = {**BULLETINS, "generated": "2100-01-01"}
            (Path(tmp) / bulletins.FILE).write_text(json.dumps(newer), encoding="utf-8")
            self.assertEqual(bulletins.load(tmp, FIXTURES)["generated"], "2100-01-01")
            self.assertEqual(bulletins.load(FIXTURES, tmp)["generated"], "2100-01-01")

    def test_invalid_file_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / bulletins.FILE).write_text("{}", encoding="utf-8")
            self.assertEqual(bulletins.load(tmp, FIXTURES)["generated"], BULLETINS["generated"])
            self.assertIsNone(bulletins.load(tmp, tmp))

    def test_build_tool_parses_osv(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
        import build_bulletins as tool

        records = {
            "a.json": {"id": "ASB-A-1", "aliases": ["CVE-2025-1"], "details": "Primeira frase. Segunda.",
                       "affected": [{"package": {"name": "platform/frameworks/base"}, "versions": ["13", "14-next"],
                                     "ecosystem_specific": {"spl": "2025-01-01", "severity": "Critical"}}]},
            "b.json": {"id": "ASB-A-1b", "aliases": ["CVE-2025-1"],
                       "affected": [{"package": {"name": "platform/frameworks/base"}, "versions": ["12L"],
                                     "ecosystem_specific": {"spl": "2024-12-01", "severity": "Critical"}}]},
            "c.json": {"id": "PUB-A-2", "aliases": ["CVE-2025-2"],
                       "affected": [{"package": {"name": ":unknown:"}, "versions": ["Pixel-family specific"],
                                     "ecosystem_specific": {"spl": "2025-02-05", "severity": "High"}}]},
            "d.json": {"id": "ASB-A-3", "aliases": ["CVE-2025-3"],
                       "affected": [{"package": {"name": ":unknown:"}, "versions": ["SoCVersion"],
                                     "ecosystem_specific": {"spl": "2025-02-05", "severity": "High"}}]},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "all.zip"
            with zipfile.ZipFile(path, "w") as z:
                for name, rec in records.items():
                    z.writestr(name, json.dumps(rec))
            rows, skipped = tool.parse_osv(zipfile.ZipFile(path), kev={"CVE-2025-2"})
        self.assertEqual(rows, [
            ["CVE-2025-1", "2024-12-01", "C", "aosp", ["12", "13", "14"], "frameworks/base", [], 0, "Primeira frase."],
            ["CVE-2025-2", "2025-02-05", "H", "pixel", [], "unknown", [], 1, ""],
        ])
        self.assertEqual(skipped["sem escopo"], 1)
