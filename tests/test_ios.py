import json
import os
import plistlib
import stat
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from desgrampa import evidence, ios

from .test_scan import BULLETINS, IOCS

FAKE_MVT = """#!{python}
import json, sys, pathlib
args = sys.argv[1:]
out = pathlib.Path(args[args.index("-o") + 1])
out.mkdir(parents=True, exist_ok=True)
(out / "sms_detected.json").write_text(json.dumps([{{"message": "Found a known suspicious domain", "level": "CRITICAL",
    "module": "SMS", "matched_indicator": {{"value": "evil.example", "name": "Pegasus"}}}}]))
(out / "configuration_profiles.json").write_text(json.dumps([{{"plist": {{"PayloadDisplayName": "Perfil MDM"}}}}]))
"""


def make_backup(folder, version="17.5", model="iPhone14,2", encrypted=False):
    folder.mkdir(parents=True)
    (folder / "Info.plist").write_bytes(plistlib.dumps({
        "Device Name": "iPhone de Teste", "Product Type": model, "Product Version": version, "Build Version": "21F79",
        "Serial Number": "F2LTEST", "Unique Identifier": "00008110-000A1B2C3D4E", "Last Backup Date": datetime(2024, 8, 1)}))
    (folder / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": encrypted}))
    (folder / "Manifest.db").write_bytes(b"")
    return folder


class IosStatusTests(unittest.TestCase):
    def test_outdated_with_exploited(self):
        st = ios.ios_status(BULLETINS, "iPhone14,2", "17.5")
        self.assertTrue(st["update_available"])
        self.assertEqual(st["best_for_model"], "18.0")
        self.assertEqual(st["exploited"], ["CVE-2024-2000"])   # entrou no KEV depois da 17.6
        titles = [f.title for f in ios.version_findings(st)]
        self.assertEqual(titles, ["iOS desatualizado (17.5)"])

    def test_current(self):
        st = ios.ios_status(BULLETINS, "iPhone14,2", "18.0")
        self.assertFalse(st["update_available"])
        self.assertEqual(ios.version_findings(st), [])

    def test_old_model_without_support(self):
        st = ios.ios_status(BULLETINS, "iPhone10,1", "16.7.10")
        self.assertFalse(st["supported"])
        self.assertIn("iPhone sem atualizações de segurança atuais", [f.title for f in ios.version_findings(st)])

    def test_ideviceinfo_parse(self):
        self.assertEqual(ios.parse_ideviceinfo("ProductType: iPhone14,2\nProductVersion: 17.5\n"),
                         {"ProductType": "iPhone14,2", "ProductVersion": "17.5"})


class IosScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.patch = mock.patch.object(evidence, "REPORTS_DIR", self.root / "relatorios")
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmp.cleanup()

    def test_backup_without_mvt(self):
        backup = make_backup(self.root / "backup")
        with mock.patch.object(ios, "mvt_ios_path", return_value=None):
            r = ios.run_scan(IOCS, BULLETINS, backup_dir=str(backup))
        self.assertEqual(r["device"]["platform"], "ios")
        self.assertEqual(r["device"]["ios"], "17.5")
        self.assertIn("iOS desatualizado (17.5)", [f["title"] for f in r["findings"]])
        cats = {c["id"]: c["status"] for c in r["categories"]}
        self.assertEqual(cats["mercenario"], "nao_verificado")
        self.assertEqual(cats["vulns"], "alta")
        self.assertTrue(evidence.load(r["report_name"]))

    @unittest.skipIf(os.name == "nt", "script de MVT falso usa shebang")
    def test_backup_with_mvt_alerts_and_profiles(self):
        backup = make_backup(self.root / "backup", version="18.0")
        fake = self.root / "mvt-ios"
        fake.write_text(FAKE_MVT.format(python=sys.executable))
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
        with mock.patch.object(ios, "mvt_ios_path", return_value=str(fake)):
            r = ios.run_scan(IOCS, BULLETINS, backup_dir=str(backup))
        titles = {f["title"] for f in r["findings"]}
        self.assertIn("Perfil de configuração instalado no iPhone", titles)
        self.assertEqual(r["verdict"]["code"], "alto_risco")
        self.assertEqual(json.loads((Path(r["evidence_dir"]) / "relatorio.json").read_text(encoding="utf-8"))["platform"], "ios")

    def test_encrypted_backup_needs_password(self):
        backup = make_backup(self.root / "backup", encrypted=True)
        with mock.patch.object(ios, "mvt_ios_path", return_value="/bin/true"), self.assertRaises(ios.IosError):
            ios.run_scan(IOCS, BULLETINS, backup_dir=str(backup))

    def test_not_a_backup(self):
        (self.root / "vazio").mkdir()
        with self.assertRaises(ios.IosError):
            ios.read_backup_info(self.root / "vazio")
