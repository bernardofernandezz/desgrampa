import json
import tempfile
import unittest
from pathlib import Path

from desgrampa import devinfo, evidence

GETPROP = """\
[ro.product.model]: [Redmi Note 9 Pro]
[ro.product.marketname]: [Redmi Note 9 Pro]
[ro.product.manufacturer]: [Xiaomi]
[ro.build.version.release]: [12]
[ro.miui.ui.version.name]: [V130]
[ro.build.version.incremental]: [V13.0.4.0.SJZMIXM]
[ro.build.version.security_patch]: [2023-01-01]
"""
BATTERY = "Current Battery Service state:\n  AC powered: false\n  status: 2\n  level: 78\n  scale: 100\n"


SAMSUNG = """\
[ro.product.brand]: [samsung]
[ro.product.manufacturer]: [samsung]
[ro.product.model]: [SM-A155M]
[ro.product.device]: [a15]
[ro.build.version.release]: [14]
[ro.build.version.sdk]: [34]
[ro.build.version.oneui]: [60100]
[ro.build.PDA]: [A155MUBS6BYE1]
[ro.build.version.security_patch]: [2025-03-01]
[ro.soc.manufacturer]: [Mediatek]
[ro.soc.model]: [MT6789V/CD]
[gsm.sim.operator.alpha]: [Claro BR]
[ro.csc.country_code]: [Brazil]
[ro.csc.sales_code]: [ZTO]
[ro.boot.verifiedbootstate]: [green]
[ro.boot.flash.locked]: [1]
[ro.crypto.type]: [file]
"""
SAMSUNG_BATTERY = ("Current Battery Service state:\n  AC powered: false\n  USB powered: true\n  status: 2\n"
                   "  health: 2\n  level: 25\n  scale: 100\n  temperature: 349\n")


def collect_output(getprop, battery, name="null", df="", mem="", uptime=""):
    return "\n@@@\n".join([getprop, battery, name, df, mem, uptime])


class DevInfoTests(unittest.TestCase):
    def test_summary_xiaomi(self):
        info = devinfo.summarize("DEMO1234", collect_output(GETPROP, BATTERY))
        self.assertEqual(info["name"], "Redmi Note 9 Pro")
        self.assertEqual(info["rom"], "MIUI 13.0.4")
        self.assertEqual(info["android"], "12")
        self.assertEqual(info["battery"]["level"], 78)
        self.assertTrue(info["battery"]["charging"])
        self.assertIsNone(info["device_name"])          # "null" do settings vira None
        self.assertIsNone(info["storage"])

    def test_summary_samsung_real_values(self):
        out = collect_output(
            SAMSUNG, SAMSUNG_BATTERY, "A15 de Fulano",
            "/dev/block/dm-55 110741504 71748680  38861752  65% /data",
            "MemTotal:        3726076 kB\nMemAvailable:    1114116 kB\n", "100238.33 439611.59")
        info = devinfo.summarize("R58DEMO0001", out, "1-6")
        self.assertEqual(info["name"], "Samsung SM-A155M")
        self.assertEqual(info["device_name"], "A15 de Fulano")
        self.assertEqual((info["android"], info["sdk"], info["rom"]), ("14", 34, "One UI 6.1"))
        self.assertEqual(info["build"], "A155MUBS6BYE1")
        self.assertEqual(info["soc"], "Mediatek MT6789V/CD")
        self.assertEqual(info["operators"], ["Claro BR"])
        self.assertEqual(info["bootloader"], {"verified_boot": "green", "locked": True})
        self.assertEqual(info["storage"], {"total_gb": 113.4, "used_gb": 73.5, "used_pct": 65})
        self.assertEqual(info["memory"]["nominal_gb"], 4)
        self.assertEqual(info["uptime_s"], 100238)
        self.assertEqual(info["battery"], {"level": 25, "charging": True, "status": "carregando", "health": "boa",
                                           "temperature_c": 34.9, "power_source": "USB"})
        self.assertEqual(info["transport"], "1-6")

    def test_dual_sim_operator_trailing_comma(self):
        info = devinfo.summarize("x", collect_output("[gsm.sim.operator.alpha]: [CLARO BR,]\n", ""))
        self.assertEqual(info["operators"], ["CLARO BR"])

    def test_one_ui(self):
        self.assertEqual(devinfo.rom_version({"ro.build.version.oneui": "50101"}), "One UI 5.1.1")
        self.assertEqual(devinfo.rom_version({"ro.build.version.oneui": "60000"}), "One UI 6.0")
        self.assertIsNone(devinfo.rom_version({}))

    def test_reports_listing_and_path_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp) / "20261020-101010_ABC"
            d.mkdir()
            (d / "relatorio.json").write_text(json.dumps({
                "started": "2026-10-20 10:10:10", "mode": "rapida", "device": {"model": "X", "serial": "ABC"},
                "verdict": {"code": "ok"}, "counts": {}, "stats": {"categories_verified": 12, "categories_total": 12}}))
            items = evidence.list_reports(tmp)
            self.assertEqual(items[0]["name"], d.name)
            self.assertIsNotNone(evidence.report_path(d.name, reports_dir=tmp))
            self.assertIsNone(evidence.report_path("..", reports_dir=tmp))
            self.assertIsNone(evidence.report_path(d.name, "../../etc/passwd", reports_dir=tmp))
            self.assertIsNone(evidence.report_path("nao-existe", reports_dir=tmp))


if __name__ == "__main__":
    unittest.main()
