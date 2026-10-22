import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from desgrampa import actions, evidence, grouping, server

from .fake_device import FakeDevice
from .test_scan import IOCS, scan


class PhoneWithApps:
    """Aparelho falso que entende os comandos de remoção."""
    serial = "FAKE123"

    def __init__(self, installed, admin=False):
        self.installed = set(installed)
        self.admin = admin
        self.commands = []

    def shell(self, cmd, timeout=60):
        self.commands.append(cmd)
        if cmd.startswith("pm list packages --user"):
            pkg = cmd.split()[-1]
            return "".join(f"package:{p}\n" for p in self.installed if pkg in p)
        if cmd.startswith("pm path"):
            return f"package:/data/app/{cmd.split()[-1]}/base.apk\npackage:/data/app/{cmd.split()[-1]}/split_x.apk\n"
        if cmd.startswith("pm uninstall"):
            if self.admin:
                return "Failure [DELETE_FAILED_DEVICE_POLICY_MANAGER]"
            self.installed.discard(cmd.split()[-1])
            return "Success"
        if cmd.startswith("pm disable-user"):
            return f"Package {cmd.split()[-1]} new state: disabled-user"
        return ""

    def pull(self, remote, local, timeout=300):
        Path(local).write_bytes(b"APK " + remote.encode())


def candidate(pkg="com.systemservice", **kw):
    return {"package": pkg, "user": 0, "admin_components": [], "device_admin": False, "mercenary": False, **kw}


class GroupingTests(unittest.TestCase):
    def test_tree_and_groups_from_infected_scan(self):
        r = scan(FakeDevice(infected=True))
        spy = next(g for g in r["groups"] if g["package"] == "com.systemservice")
        self.assertEqual(spy["family"], "TheTruthSpy")
        self.assertEqual(spy["total"], sum(spy["counts"].values()))
        self.assertGreaterEqual(spy["counts"]["critica"], 2)
        self.assertEqual(r["groups"][0]["worst"], "critica")
        cats = {c["category"]: c for c in r["tree"]}
        self.assertEqual(cats["spyware"]["total"], sum(c["total"] for c in cats["spyware"]["children"]))

    def test_removal_candidates(self):
        r = scan(FakeDevice(infected=True))
        cands = {c["package"]: c for c in r["removal_candidates"]}
        self.assertIn("com.systemservice", cands)          # stalkerware conhecido
        self.assertIn("com.vodaservices", cands)           # spyware mercenário no perfil 10
        self.assertTrue(cands["com.vodaservices"]["mercenary"])
        self.assertEqual(cands["com.vodaservices"]["user"], 10)
        self.assertNotIn("com.android.settings", cands)    # app do sistema nunca é sugerido
        self.assertNotIn("com.whatsapp", cands)

    def test_old_report_mvt_messages_grouped_by_package(self):
        findings = [{"severity": "critica", "title": 'MVT: Found a known suspicious app with ID "com.life360.android.safetymapd" matching indicators from "Life360"',
                     "detail": "", "recommendation": "", "package": None, "check": "MVT", "category": "mercenario"}] * 3
        groups, _ = grouping.build_groups(findings)
        self.assertEqual(groups[0]["package"], "com.life360.android.safetymapd")
        self.assertEqual(groups[0]["total"], 3)


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_uninstall_keeps_apk_copy_and_logs(self):
        phone = PhoneWithApps({"com.systemservice"})
        res = actions.perform(phone, self.dir, candidate(), "uninstall")
        self.assertEqual(res["status"], "ok")
        self.assertNotIn("com.systemservice", phone.installed)
        self.assertEqual(len(res["saved"]), 2)
        self.assertTrue((self.dir / "removidos/com.systemservice/base.apk").exists())
        self.assertEqual(actions.read_log(self.dir)[0]["package"], "com.systemservice")
        # a cópia é feita ANTES da remoção
        cmds = phone.commands
        self.assertLess(cmds.index(next(c for c in cmds if c.startswith("pm path"))),
                        cmds.index(next(c for c in cmds if c.startswith("pm uninstall"))))

    def test_device_admin_needs_manual_step(self):
        phone = PhoneWithApps({"com.systemservice"}, admin=True)
        res = actions.perform(phone, self.dir, candidate(device_admin=True,
                              admin_components=["com.systemservice/.Admin"]), "uninstall", keep_apk=False)
        self.assertEqual(res["status"], "manual")
        self.assertIn("dpm remove-active-admin --user 0 com.systemservice/.Admin", phone.commands)

    def test_disable_and_not_installed(self):
        phone = PhoneWithApps({"com.systemservice"})
        self.assertEqual(actions.perform(phone, self.dir, candidate(), "disable", keep_apk=False)["status"], "ok")
        self.assertEqual(actions.perform(phone, self.dir, candidate("com.outro.app"), "uninstall")["status"], "nao_instalado")

    def test_extra_profile_uses_user_flag(self):
        phone = PhoneWithApps({"com.vodaservices"})
        actions.perform(phone, self.dir, candidate("com.vodaservices", user=10), "uninstall", keep_apk=False)
        self.assertIn("pm uninstall --user 10 com.vodaservices", phone.commands)

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            actions.perform(PhoneWithApps(set()), self.dir, candidate("com.x; rm -rf /"), "uninstall")
        with self.assertRaises(ValueError):
            actions.perform(PhoneWithApps(set()), self.dir, candidate(), "format")


class ActionApiTests(unittest.TestCase):
    """O endpoint só aceita apps sugeridos, com confirmação digitada e o aparelho certo conectado."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        reports = Path(self.tmp.name)
        r = scan(FakeDevice(infected=True))
        (reports / "rel_FAKE123").mkdir()
        (reports / "rel_FAKE123" / "relatorio.json").write_text(json.dumps(r, ensure_ascii=False))
        self.phone = PhoneWithApps({"com.systemservice", "com.vodaservices"})
        self.patches = [mock.patch.object(evidence, "REPORTS_DIR", reports),
                        mock.patch.object(server.adb, "list_devices", return_value=[{"serial": "FAKE123", "state": "device"}]),
                        mock.patch.object(server.adb, "Device", return_value=self.phone),
                        mock.patch.object(server.iocs, "load", return_value=IOCS)]
        for p in self.patches:
            p.start()
        self.httpd = server.Server(0)   # porta livre escolhida pelo sistema
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def post(self, body):
        req = urllib.request.Request(self.base + "/api/actions", json.dumps(body).encode(),
                                     {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_rejections_and_success(self):
        base = {"report": "rel_FAKE123", "action": "uninstall", "keep_apk": False}
        code, body = self.post({**base, "package": "com.whatsapp", "confirm": "com.whatsapp"})
        self.assertEqual(code, 400, body)                                   # não é sugestão
        code, body = self.post({**base, "package": "com.systemservice", "confirm": "com.system"})
        self.assertEqual(code, 400, body)                                   # confirmação errada
        code, body = self.post({**base, "package": "com.vodaservices", "confirm": "com.vodaservices"})
        self.assertEqual(code, 400, body)                                   # mercenário sem ciência
        self.assertEqual(self.phone.commands, [])                           # nada foi executado até aqui
        code, body = self.post({**base, "package": "com.systemservice", "confirm": "com.systemservice"})
        self.assertEqual((code, body["status"]), (200, "ok"))
        with urllib.request.urlopen(self.base + "/api/reports/rel_FAKE123/relatorio.json") as resp:
            report = json.load(resp)
        self.assertEqual(report["actions"][0]["package"], "com.systemservice")


if __name__ == "__main__":
    unittest.main()
