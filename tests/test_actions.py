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
        if cmd.startswith("pm enable"):
            return f"Package {cmd.split()[-1]} new state: enabled"
        if cmd.endswith("get secure enabled_accessibility_services"):
            return "com.systemservice/.Spy:com.google.android.marvin.talkback/.TalkBackService\n"
        if cmd.endswith("get secure enabled_notification_listeners"):
            return "com.systemservice/.Notif\n"
        if cmd.startswith("dumpsys package"):
            return ("    runtime permissions:\n      android.permission.READ_SMS: granted=true\n"
                    "      android.permission.CAMERA: granted=false\n      android.permission.INTERNET: granted=true\n")
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
        self.assertEqual(cands["com.systemservice"]["level"], "ameaca")
        levels = [c["level"] for c in r["removal_candidates"]]
        self.assertEqual(levels, sorted(levels, key=lambda lv: lv != "ameaca"))   # ameaças primeiro

    def test_dossier_explains_why_and_what_the_app_can_do(self):
        r = scan(FakeDevice(infected=True))
        cands = {c["package"]: c["explain"] for c in r["removal_candidates"]}
        spy = cands["com.systemservice"]
        self.assertEqual(spy["kind"], "stalkerware")
        self.assertTrue(any("TheTruthSpy" in w for w in spy["why"]))
        self.assertIn("Tela", {c["theme"] for c in spy["can_do"]})              # acessibilidade
        self.assertEqual((spy["recommendation"]["action"], spy["preselect"]), ("uninstall", True))
        merc = cands["com.vodaservices"]                                         # preservar provas
        self.assertEqual((merc["kind"], merc["recommendation"]["action"], merc["preselect"]), ("mercenario", "restrict", False))
        anydesk = cands["com.anydesk.anydeskandroid"]                            # acesso remoto não é "stalkerware"
        self.assertEqual(anydesk["kind"], "revisar")
        self.assertFalse(any("listas públicas" in w for w in anydesk["why"]))

    def test_legacy_mvt_category_does_not_make_monitoring_app_mercenary(self):
        result = {"apps": [{"package": "com.life360.android.safetymapd", "sideloaded": False, "has_launcher": True}],
                  "data": {}, "findings": [
                      {"severity": "alta", "title": "MVT: App conhecido nas bases de spyware", "category": "mercenario",
                       "package": "com.life360.android.safetymapd", "family": "Life360"},
                      {"severity": "alta", "title": "App de monitoramento conhecido: Life360", "category": "spyware",
                       "package": "com.life360.android.safetymapd", "family": "Life360"}]}
        (cand,) = grouping.removal_candidates(result)
        self.assertFalse(cand["mercenary"])
        self.assertEqual((cand["explain"]["kind"], cand["explain"]["preselect"]), ("monitoramento", False))

    def test_high_finding_app_is_offered_for_review(self):
        result = {"apps": [{"package": "com.desconhecido"}], "data": {},
                  "findings": [{"severity": "alta", "title": "App com acesso de acessibilidade", "category": "apps",
                                "package": "com.desconhecido"}]}
        (cand,) = grouping.removal_candidates(result)
        self.assertEqual((cand["package"], cand["level"]), ("com.desconhecido", "revisar"))

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

    def test_restrict_cuts_access_but_keeps_app(self):
        phone = PhoneWithApps({"com.systemservice"})
        res = actions.perform(phone, self.dir, candidate(), "restrict", keep_apk=False)
        self.assertEqual(res["status"], "ok", res)
        self.assertIn("com.systemservice", phone.installed)                      # evidência preservada
        cmds = phone.commands
        # só o serviço do app sai da acessibilidade; o TalkBack fica
        self.assertIn("settings --user 0 put secure enabled_accessibility_services "
                      "com.google.android.marvin.talkback/.TalkBackService", cmds)
        self.assertIn("settings --user 0 delete secure enabled_notification_listeners", cmds)
        self.assertIn("cmd notification disallow_listener com.systemservice/.Notif 0", cmds)
        self.assertIn("pm revoke --user 0 com.systemservice android.permission.READ_SMS", cmds)
        self.assertFalse(any("CAMERA" in c or "INTERNET" in c for c in cmds if c.startswith("pm revoke")))
        self.assertEqual(cmds[-1], "am force-stop --user 0 com.systemservice")
        self.assertFalse(any(c.startswith(("pm uninstall", "pm disable")) for c in cmds))

    def test_enable_reverts_disable(self):
        phone = PhoneWithApps({"com.systemservice"})
        res = actions.perform(phone, self.dir, candidate(), "enable")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["saved"], [])                                        # reativar não copia o APK
        self.assertIn("pm enable --user 0 com.systemservice", phone.commands)

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
        (reports / "rel_FAKE123" / "relatorio.json").write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
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

    def test_cleanup_plan_uses_one_typed_word_and_logs_reason(self):
        base = {"report": "rel_FAKE123", "action": "uninstall", "keep_apk": False, "package": "com.systemservice"}
        code, body = self.post({**base, "confirm": "REMOVER"})
        self.assertEqual(code, 400, body)                                   # fora do plano, só o nome do pacote
        code, body = self.post({**base, "confirm": "remover", "via": "plano"})
        self.assertEqual(code, 400, body)
        code, body = self.post({**base, "confirm": "REMOVER", "via": "plano"})
        self.assertEqual((code, body["status"], body["via"]), (200, "ok", "plano"))
        self.assertIn("TheTruthSpy", body["reason"])
        with urllib.request.urlopen(self.base + "/api/reports/rel_FAKE123/relatorio.html") as resp:
            html = resp.read().decode("utf-8")
        self.assertIn("plano de limpeza", html)
        self.assertIn("Em poucas palavras", html)
        self.assertIn("O que ele consegue fazer", html)

    def test_rejections_and_success(self):
        base = {"report": "rel_FAKE123", "action": "uninstall", "keep_apk": False}
        code, body = self.post({**base, "package": "com.whatsapp", "confirm": "com.whatsapp"})
        self.assertEqual(code, 400, body)                                   # não é sugestão
        code, body = self.post({**base, "package": "com.systemservice", "confirm": "com.system"})
        self.assertEqual(code, 400, body)                                   # confirmação errada
        code, body = self.post({**base, "package": "com.vodaservices", "confirm": "com.vodaservices"})
        self.assertEqual(code, 400, body)                                   # mercenário sem ciência
        self.assertEqual(self.phone.commands, [])                           # nada foi executado até aqui
        code, body = self.post({**base, "action": "disable", "package": "com.systemservice"})
        self.assertEqual(code, 400, body)                                   # reversível, mas sem consentimento
        self.assertEqual(self.phone.commands, [])                           # nada foi executado até aqui
        code, body = self.post({**base, "action": "restrict", "package": "com.systemservice", "consent": True})
        self.assertEqual((code, body["status"]), (200, "ok"))
        code, body = self.post({**base, "package": "com.systemservice", "consent": True})
        self.assertEqual(code, 400, body)                                   # remover exige o nome digitado
        code, body = self.post({**base, "package": "com.systemservice", "confirm": "com.systemservice"})
        self.assertEqual((code, body["status"]), (200, "ok"))
        with urllib.request.urlopen(self.base + "/api/reports/rel_FAKE123/relatorio.json") as resp:
            report = json.load(resp)
        self.assertEqual([a["action"] for a in report["actions"]], ["restrict", "uninstall"])


if __name__ == "__main__":
    unittest.main()
