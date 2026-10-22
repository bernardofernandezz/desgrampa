import unittest
from pathlib import Path
from unittest import mock

from desgrampa import bulletins, iocs
from desgrampa.checks import accounts, netactivity, network, pcnet, traces
from desgrampa.context import (
    parse_appops_usage,
    parse_components,
    parse_device_policy,
    parse_dumpsys_package,
    parse_hidden_system_packages,
    parse_pm_list,
    parse_users,
)
from desgrampa.scanner import run_scan

from . import fake_device as fx
from .fake_device import FakeDevice

FIXTURES = Path(__file__).parent / "fixtures"
IOCS = iocs.load(FIXTURES / "iocs")   # bases mínimas e fixas: testes offline e reprodutíveis
BULLETINS = bulletins.load(FIXTURES, FIXTURES)


def scan(dev, mode="rapida", **kw):
    # sem internet nos testes: a referência DoH falha e o teste de DNS usa só o que o celular respondeu
    with mock.patch.object(netactivity, "doh_resolve", side_effect=OSError("offline")):
        return run_scan(dev, IOCS, mode, save_evidence=False, bulletins=kw.pop("bulletins", BULLETINS), **kw)


def titles(r):
    return {f["title"] for f in r["findings"]}


class ParserTests(unittest.TestCase):
    def test_pm_list_with_equals_in_path(self):
        pkgs = parse_pm_list(fx.PM_LIST)
        self.assertEqual(pkgs["com.whatsapp"],
                         ("/data/app/~~aGVsbG8=/com.whatsapp-x1Y2==/base.apk", "com.android.vending", 10150))
        self.assertIsNone(pkgs["com.android.settings"][1])

    def test_dumpsys_package(self):
        d = parse_dumpsys_package(fx.DUMPSYS_PACKAGE)
        wa = d["com.whatsapp"]
        self.assertIn("android.permission.READ_SMS", wa["requested"])
        self.assertEqual(wa["granted"], {"android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED",
                                         "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"})
        self.assertEqual(wa["first_install"], "2020-01-01 10:00:00")
        self.assertFalse(wa["system"])
        self.assertTrue(d["com.android.settings"]["system"])
        self.assertEqual(d["com.android.settings"]["shared_user"], "android.uid.system")
        self.assertNotIn("com.android.ignored", d)
        self.assertEqual(parse_hidden_system_packages(fx.DUMPSYS_PACKAGE), {"com.android.ignored"})

    def test_components(self):
        self.assertEqual(parse_components("a.b/.X:c.d/c.d.Y"), [("a.b", "a.b/.X"), ("c.d", "c.d/c.d.Y")])
        self.assertEqual(parse_components("null"), [])

    def test_device_policy(self):
        out = fx.DEVICE_POLICY + "  Device Owner: \n    admin=ComponentInfo{com.evil.mdm/com.evil.mdm.R}\n" \
            "    mOwnerInstalledCaCerts=[CN=Corp Inspection CA]\n"
        dp = parse_device_policy(out)
        self.assertEqual(dp["admins"], ["com.android.settings"])
        self.assertEqual(dp["device_owner"], "com.evil.mdm")
        self.assertEqual(dp["owner_ca_certs"], ["CN=Corp Inspection CA"])

    def test_appops_usage_both_formats(self):
        old = "RECORD_AUDIO: allow; time=+2h3m4s5ms ago; duration=+1s\nCAMERA: allow\n"
        new = "CAMERA (allow):\n  null=[\n    Access: [bg-s] 2024-01-01 10:00:00.000 (-1d2h3m4s5ms)\n  ]\n"
        self.assertEqual(parse_appops_usage(old)["RECORD_AUDIO"]["ago"], 2 * 3600 + 3 * 60 + 4)
        self.assertNotIn("CAMERA", parse_appops_usage(old))
        cam = parse_appops_usage(new)["CAMERA"]
        self.assertEqual(cam["ago"], 86400 + 2 * 3600 + 3 * 60 + 4)
        self.assertTrue(cam["background"])

    def test_link_properties_and_wifi_proxy(self):
        links = network.parse_link_properties(fx.CONNECTIVITY_BAD)
        self.assertEqual(links, [{"iface": "wlan0", "dns": ["192.168.0.1", "45.33.1.2"],
                                  "gateways": ["192.168.0.1"], "proxy": "10.0.0.9:3128", "private_dns": None}])
        self.assertEqual(network.parse_wifi_proxies(fx.WIFI_BAD), [("CasaNet", "proxy.evil.lan:8080")])

    def test_proc_net(self):
        conns = netactivity.parse_proc_net(fx.PROC_NET_BAD)
        self.assertEqual(conns[0], ("69.64.74.239", 443, 10201, "01"))
        self.assertEqual(conns[1][0], "192.168.0.1")
        v6 = "  0: 0000000000000000FFFF00000A00A8C0:9C40 0000000000000000FFFF0000EF4A4045:01BB 01 " \
             "00000000:00000000 00:00000000 00000000 10201 0 1 1"
        self.assertEqual(netactivity.parse_proc_net(v6)[0][0], "69.64.74.239")

    def test_netstats(self):
        out = ("UID stats:\n  ident=[{type=WIFI}] uid=10201 set=DEFAULT tag=0x0\n"
               "    NetworkStatsHistory: bucketDuration=7200\n      st=1 rb=100 rp=1 tb=500000000 tp=9 op=0\n"
               "  ident=[{type=WIFI}] uid=10201 set=FOREGROUND tag=0x0\n      st=1 rb=10 rp=1 tb=20 tp=1 op=0\n"
               "UID tag stats:\n  ident=[] uid=10201 set=DEFAULT tag=0xff\n      st=1 rb=1 rp=1 tb=999 tp=1 op=0\n")
        self.assertEqual(netactivity.parse_netstats(out)[10201],
                         {"bg_tx": 500000000, "fg_tx": 20, "bg_rx": 100, "fg_rx": 10})

    def test_accounts_users_battery(self):
        accs, auths = accounts.parse_accounts(fx.ACCOUNTS_BAD)
        self.assertEqual(len(accs), 3)
        self.assertEqual(auths["net.qwe.helper.account"], "net.qwe.helper")
        self.assertEqual([u["id"] for u in parse_users(fx.USERS_BAD)], [0, 10])
        events, seen = traces.parse_battery_history(fx.BATTERY_BAD)
        self.assertEqual([(e["event"], e["time"]) for e in events],
                         [("instalado", "2026-10-01 11:00"), ("removido", "2026-10-01 13:00")])
        self.assertIn("com.thetruth", seen)

    def test_arp_parse(self):
        out = "192.168.0.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n192.168.0.7 dev wlan0 lladdr AA:BB:CC:DD:EE:FF STALE\n"
        self.assertEqual(pcnet.parse_ip_neigh(out), {"192.168.0.1": "aa:bb:cc:dd:ee:ff",
                                                     "192.168.0.7": "aa:bb:cc:dd:ee:ff"})


class IocTests(unittest.TestCase):
    def test_domain_parent_match_and_safelist(self):
        self.assertTrue(IOCS.match_domain("cp.mspyonline.com"))
        self.assertIsNone(IOCS.match_domain("google.com"))
        self.assertIsNone(IOCS.match_domain("api.github.com"))

    def test_mercenary_bases_loaded(self):
        s = IOCS.summary()
        self.assertIn("NSO Group Pegasus", s["collections"])
        self.assertEqual(s["apk_sha256"], 1)
        self.assertEqual(IOCS.match_apk_hash("AB" * 32).family, "TheTruthSpy")
        m = IOCS.match_package("com.vodaservices")
        self.assertTrue(m and m.mercenary)
        self.assertFalse(IOCS.match_package("com.systemservice").mercenary)

    def test_stix_parsing(self):
        bundle = {"objects": [
            {"type": "malware", "id": "malware--1", "name": "FooSpy"},
            {"type": "indicator", "id": "indicator--1", "pattern": "[app:id = 'com.foo.spy']"},
            {"type": "indicator", "id": "indicator--2", "pattern": "[url:value = 'https://evil.example/x']"},
            {"type": "relationship", "source_ref": "indicator--1", "target_ref": "malware--1"},
        ]}
        i = iocs.Iocs()
        i.add_stix(bundle, "Teste")
        self.assertEqual(i.match_package("com.foo.spy").family, "FooSpy")
        self.assertEqual(i.match_domain("a.evil.example").family, "Teste")


class ScanTests(unittest.TestCase):
    def test_clean_device(self):
        r = scan(FakeDevice())
        self.assertEqual(r["verdict"]["code"], "ok", titles(r))
        self.assertEqual(r["stats"]["third_party"], 1)
        self.assertEqual(r["apps"][0]["package"], "com.whatsapp")
        statuses = {c["id"]: c["status"] for c in r["categories"]}
        self.assertEqual(statuses["pcnet"], "nao_verificado")   # opção desligada
        self.assertEqual(statuses["intercept"], "ok")

    def test_infected_device(self):
        r = scan(FakeDevice(infected=True))
        self.assertEqual(r["verdict"]["code"], "alto_risco")
        t = titles(r)
        expected = {
            # stalkerware / mercenário
            "Stalkerware conhecido: TheTruthSpy", "Spyware em execução: TheTruthSpy",
            "Spyware mercenário: RCSLab", "Arquivo de spyware encontrado: Predator",
            "Contato com servidor de spyware nos logs: FlexiSpy",
            "Conexão ativa com servidor de spyware: TheTruthSpy",
            # interceptação
            "Proxy HTTP global configurado", "Proxy configurado em rede Wi-Fi", "Proxy ativo na conexão atual",
            "Certificado de segurança instalado (rede pode ser monitorada)",
            "Certificado adicionado ao repositório do sistema", "DNS adulterado no celular",
            "DNS responde a domínios inexistentes",
            # rede, telefonia, contas, controle
            "Servidor DNS público desconhecido", "Desvio de chamadas ativo", "Conectado em rede 2G agora",
            "Rede de outro país sem roaming", "App de terceiro como app padrão de SMS",
            "Mais de uma conta Google no aparelho", "Conta criada por app suspeito", "Perfil adicional: Trabalho",
            "App de acesso remoto: AnyDesk",
            # rastros, sistema, apps, proteções
            "Rastro de spyware removido: TheTruthSpy", "App com permissão privilegiada",
            "App com acesso de acessibilidade", "App lendo suas notificações",
            "App com combinação perigosa de acessos", "Google Play Protect desativado",
        }
        self.assertEqual(expected - t, set())
        cats = {c["id"]: c for c in r["categories"]}
        for cid in ("spyware", "mercenario", "intercept", "telefonia", "contas", "controle",
                    "rastros", "sistema", "apps", "protecoes"):
            self.assertIn(cats[cid]["status"], ("critica", "alta", "media"), cid)
        self.assertEqual(cats["rede"]["status"], "baixa")   # o grave da rede foi para "intercept"
        removed = {x["package"] for x in r["data"]["rastros"]["removed"]}
        self.assertIn("com.thetruth", removed)
        self.assertEqual(r["apps"][0]["package"], "com.systemservice")

    def test_full_mode_without_pull_or_bugreport(self):
        with mock.patch("desgrampa.checks.mvt.mvt_path", return_value="/bin/true"):
            r = scan(FakeDevice(infected=True), mode="completa")
        status = {c["name"]: c for cat in r["categories"] for c in cat["checks"]}
        self.assertEqual(status["Assinatura e hash dos aplicativos"]["status"], "ok")
        self.assertEqual(status["Análise forense MVT (Anistia Internacional)"]["status"], "skipped")
        self.assertIn("bugreport", status["Análise forense MVT (Anistia Internacional)"]["reason"])
        self.assertTrue(any("APK" in n for n in r["notes"]))

    def test_pc_network_check_offline(self):
        with mock.patch.object(pcnet, "run", return_value=[]) as run:
            r = scan(FakeDevice(), options={"pc_network": True})
        run.assert_called_once()
        self.assertEqual(next(c for c in r["categories"] if c["id"] == "pcnet")["status"], "ok")

    def test_old_patch(self):
        r = scan(FakeDevice(patch="2019-01-01"))
        f = next(f for f in r["findings"] if f["title"] == "Atualização de segurança desatualizada")
        self.assertEqual(f["severity"], "alta")

    def test_failing_check_does_not_abort(self):
        with mock.patch("desgrampa.checks.telephony.run", side_effect=RuntimeError("boom")):
            r = scan(FakeDevice())
        self.assertTrue(any("não pôde ser concluída" in f["title"] for f in r["findings"]))
        tel = next(c for c in r["categories"] if c["id"] == "telefonia")
        self.assertEqual(tel["status"], "nao_verificado")

    def test_paths_from_downloaded_bases_are_shell_quoted(self):
        import shlex

        from desgrampa.iocs import Match
        evil = "/data/local/tmp/x'; reboot; echo '"
        IOCS.file_paths[evil] = Match("Teste", "Teste")
        try:
            dev = FakeDevice()
            scan(dev)
        finally:
            del IOCS.file_paths[evil]
        ls = next(c for c in dev.commands if c.startswith("ls -d "))
        self.assertIn(shlex.quote(evil), ls)
        self.assertNotIn("x'; reboot", ls.replace(shlex.quote(evil), ""))

    def test_root_detected_by_mount_source(self):
        mounts = "magisk /system/bin tmpfs rw,relatime 0 0\n/dev/block/dm-0 /system ext4 ro 0 0\n"
        r = scan(FakeDevice(extra={"cat /proc/mounts": mounts}))
        root = next(f for f in r["findings"] if f["title"] == "Sinais de root no aparelho")
        self.assertIn("montagem /system/bin", root["detail"])

    def test_read_only_commands(self):
        dev = FakeDevice(infected=True)
        scan(dev, mode="completa")
        forbidden = ("pm uninstall", "pm disable", "pm clear", "pm grant", "pm revoke", "settings put",
                     "settings delete", "rm ", "am ", "cmd role add", "cmd role remove", "svc ", "reboot",
                     "setprop", "input ", "service call", "pm enable", "cmd appops set", "cmd notification",
                     "dpm ")
        for cmd in dev.commands:
            self.assertFalse(cmd.startswith(forbidden), cmd)


if __name__ == "__main__":
    unittest.main()


class CalibrationTests(unittest.TestCase):
    """Casos vistos num aparelho real que geravam falsos positivos ou alertas repetidos."""

    def test_visible_monitoring_app_from_play_is_high_not_critical(self):
        dev = FakeDevice(extra={
            "pm list packages -f -i -U": fx.PM_LIST + "package:/data/app/x/base.apk=com.life360.android.safetymapd  installer=com.android.vending uid:10300\n",
            "pm list packages -3": fx.PM_THIRD + "package:com.life360.android.safetymapd\n",
            "ps -A -o USER,PID,NAME": fx.PS + "u0_a300 7777 com.life360.android.safetymapd\n",
            "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER":
                fx.LAUNCHER + "    com.life360.android.safetymapd/.Main\n",
        })
        r = scan(dev)
        life = [f for f in r["findings"] if f["package"] == "com.life360.android.safetymapd"]
        self.assertEqual([(f["severity"], f["title"]) for f in life], [("alta", "App de monitoramento conhecido: Life360")])

    def test_ios_process_name_matching_android_daemon_is_ignored(self):
        # como num Xiaomi real: o SELinux nega o stat de /system/bin/gatekeeperd, mas a pasta pode ser listada
        from desgrampa.checks.processes import SYSTEM_BIN_DIRS
        dev = FakeDevice(extra={
            "ps -A -o USER,PID,NAME": fx.PS + "system 1513 gatekeeperd\n",
            f"ls {SYSTEM_BIN_DIRS} 2>/dev/null": "/system/bin:\napexd\ngatekeeperd\nvold\n\n/vendor/bin:\nqseecomd\n",
        })
        r = scan(dev)
        self.assertFalse(any("Pegasus" in f["title"] for f in r["findings"]))
        self.assertTrue(any("gatekeeperd" in n for n in r["notes"]))

    def test_ios_process_name_outside_system_partition_is_reported(self):
        dev = FakeDevice(extra={"ps -A -o USER,PID,NAME": fx.PS + "u0_a99 4242 gatekeeperd\n"})
        r = scan(dev)
        self.assertTrue(any("Pegasus" in f["title"] for f in r["findings"]))

    def test_certificate_only_match_without_behaviour_is_high(self):
        from desgrampa.checks import certificates
        cert = next(c for c, m in IOCS.cert_sha1.items() if m.family == "MobileTrackerFree")
        dev = FakeDevice(extra={
            "pm list packages -f -i -U": fx.PM_LIST + "package:/data/app/c/base.apk=com.google.android.apps.cameralite  installer=com.google.android.packageinstaller uid:10400\n",
            "pm list packages -3": fx.PM_THIRD + "package:com.google.android.apps.cameralite\n",
            "cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.LAUNCHER":
                fx.LAUNCHER + "    com.google.android.apps.cameralite/.Main\n",
        })
        dev.pull = lambda *a, **k: None
        with mock.patch.object(certificates.apksig, "certificates", return_value=[{"sha1": cert, "sha256": ""}]), \
             mock.patch.object(certificates.apksig, "file_sha256", return_value="00"):
            r = scan(dev, mode="completa")
        cam = {(f["severity"], f["title"]) for f in r["findings"] if f["package"] == "com.google.android.apps.cameralite"}
        self.assertIn(("alta", "Assinatura coincide com spyware: MobileTrackerFree"), cam)
        self.assertIn(("media", "App com nome de sistema instalado manualmente"), cam)

    def test_mvt_alerts_are_grouped_and_translated(self):
        import json
        import tempfile
        from pathlib import Path

        from desgrampa.checks import mvt
        from desgrampa.context import ScanContext
        alerts = [{"level": "CRITICAL", "module": "dbinfo", "event_time": f"2026-10-{d:02d}",
                   "message": 'Found a known suspicious app with ID "com.x.spy" matching indicators from "X"'}
                  for d in range(1, 21)]
        alerts += [{"level": "MEDIUM", "module": "appops", "event_time": t,
                    "message": f"Package 'com.android.chrome' had risky permission 'REQUEST_INSTALL_PACKAGES' set to '{s}' at {t}"}
                   for s, t in (("access", "2025-05-01"), ("reject", "2025-05-02"))]
        alerts.append({"level": "MEDIUM", "module": "appops", "message": "Risky package 'com.android.shell' had 'FINE_LOCATION' permission set to 'access' at x"})
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "dbinfo_detected.json").write_text(json.dumps(alerts))
            ctx = ScanContext(FakeDevice(), IOCS)
            raw, findings = mvt.parse_alerts(ctx, tmp)
        self.assertEqual(len(raw), 23)
        self.assertEqual(len(findings), 3)
        by_title = {f.title: f for f in findings}
        self.assertIn("repetido em 20 eventos", by_title["MVT: App conhecido nas bases de spyware: com.x.spy (X)"].detail)
        shell = next(f for f in findings if "com.android.shell" in f.title)
        self.assertEqual(shell.severity, "baixa")
