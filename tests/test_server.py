import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from unittest import mock

from desgrampa import atendimento, evidence, export, report, server
from desgrampa.checks import netactivity

from .fake_device import FakeDevice
from .test_scan import BULLETINS, IOCS, scan


class ApiCase(unittest.TestCase):
    attendance = False
    ephemeral = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reports = Path(self.tmp.name)
        self.patches = [mock.patch.object(evidence, "REPORTS_DIR", self.reports),
                        mock.patch.object(server, "REPORTS_DIR", self.reports),
                        mock.patch.object(server.adb, "list_devices", return_value=[{"serial": "FAKE123", "state": "device"}]),
                        mock.patch.object(server.adb, "Device", side_effect=lambda serial: FakeDevice(infected=True)),
                        mock.patch.object(server.iocs, "load", return_value=IOCS),
                        mock.patch.object(server.bulletins, "load", return_value=BULLETINS),
                        mock.patch.object(netactivity, "doh_resolve", side_effect=OSError("offline"))]
        for p in self.patches:
            p.start()
        self.httpd = server.Server(0, server.State(ephemeral=self.ephemeral, attendance=self.attendance))
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd.state.cleanup()
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, e.headers, e.read()

    def post(self, path, body):
        req = urllib.request.Request(self.base + path, json.dumps(body).encode(), {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def save_report(self, name="rel_FAKE123"):
        r = scan(FakeDevice(infected=True, patch="2024-02-05"))
        (self.reports / name).mkdir()
        evidence.save(self.reports / name, r, {"getprop": "x"})
        return name

    def run_scan(self):
        code, body = self.post("/api/scan", {"serial": "FAKE123", "mode": "rapida"})
        self.assertEqual(code, 200, body)
        for _ in range(200):
            _, _, raw = self.get(f"/api/scan/{body['id']}")
            job = json.loads(raw)
            if job["state"] != "running":
                return job
            time.sleep(0.05)
        self.fail("varredura não terminou")


class ExportTests(ApiCase):
    def test_report_formats(self):
        name = self.save_report()
        code, headers, body = self.get(f"/api/reports/{name}/relatorio.html")
        self.assertIn("attachment", headers["Content-Disposition"])
        code, headers, body = self.get(f"/api/reports/{name}/relatorio.html?ver=1")
        self.assertIsNone(headers["Content-Disposition"])
        self.assertIn(b"window.print()", body)
        self.assertIn(b"Vulnerabilidades conhecidas", body)

        code, _, body = self.get(f"/api/reports/{name}/atendimento.html")
        html = body.decode()
        self.assertEqual(code, 200)
        self.assertIn("Cadeia de custódia", html)
        self.assertIn("154-A", html)
        self.assertIn(evidence.integrity(name)["report_sha256"], html)

        code, _, body = self.get(f"/api/reports/{name}/relatorio.stix.json")
        bundle = json.loads(body)
        kinds = {o["type"] for o in bundle["objects"]}
        self.assertEqual(kinds, {"identity", "note", "vulnerability", "report"})

        code, _, body = self.get(f"/api/reports/{name}/vulnerabilidades.csv")
        self.assertIn("CVE-2024-0002", body.decode("utf-8-sig"))

        code, headers, body = self.get(f"/api/reports/{name}/evidencias.zip")
        names = zipfile.ZipFile(io.BytesIO(body)).namelist()
        self.assertIn(f"{name}/SHA256SUMS.txt", names)
        self.assertIn(f"{name}/atendimento.html", names)

    def test_unknown_report_and_traversal(self):
        self.assertEqual(self.get("/api/reports/nao-existe/atendimento.html")[0], 404)
        self.assertEqual(self.get("/api/reports/..%2F..%2Fetc/relatorio.json")[0], 404)

    def test_help_data(self):
        code, _, body = self.get("/api/ajuda")
        data = json.loads(body)
        self.assertEqual(len(data["defensorias"]), 27)
        self.assertTrue(all(law["fonte"].startswith("https://") for law in data["leis"]))
        self.assertTrue(data["termo"])

    def test_stix_ids_are_deterministic(self):
        r = scan(FakeDevice(infected=True))
        self.assertEqual(export.to_stix(r), export.to_stix(r))


class PrivacyTests(ApiCase):
    def test_wipe_requires_typed_confirmation(self):
        self.save_report()
        self.assertEqual(self.post("/api/privacy/wipe", {"confirm": "sim"})[0], 400)
        self.assertTrue(evidence.list_reports())
        code, body = self.post("/api/privacy/wipe", {"confirm": "APAGAR"})
        self.assertEqual((code, body["removed"]), (200, 1))
        self.assertEqual(evidence.list_reports(), [])

    def test_ephemeral_mode_keeps_reports_out_of_the_data_folder(self):
        code, body = self.post("/api/privacy/ephemeral", {"on": True})
        self.assertTrue(body["ephemeral"])
        temp = self.httpd.state.ephemeral_dir
        job = self.run_scan()
        self.assertEqual(job["state"], "done", job.get("error"))
        self.assertTrue((temp / job["result"]["report_name"] / "relatorio.json").exists())
        self.assertEqual(list(self.reports.iterdir()), [])
        self.post("/api/privacy/ephemeral", {"on": False})
        self.assertFalse(temp.exists())


class AttendanceTests(ApiCase):
    attendance = True

    def test_full_attendance_flow(self):
        code, body = self.post("/api/scan", {"serial": "FAKE123", "mode": "rapida"})
        self.assertEqual(code, 409)                                      # sem atendimento aberto
        self.assertEqual(self.post("/api/atendimento/abrir", {"consent": False})[0], 400)
        code, case = self.post("/api/atendimento/abrir", {"consent": True, "name": "Maria"})
        self.assertTrue(atendimento.CASE_RE.fullmatch(case["id"]))

        job = self.run_scan()
        self.assertTrue(job["result"]["report_name"].startswith(case["id"] + "_"))
        _, _, raw = self.get("/api/atendimento")
        self.assertEqual(len(json.loads(raw)["cases"][0]["reports"]), 1)

        self.assertEqual(self.post("/api/atendimento/encerrar", {"case": case["id"]})[0], 409)   # pacote não baixado
        code, headers, body = self.get(f"/api/atendimento/{case['id']}/pacote.zip")
        names = zipfile.ZipFile(io.BytesIO(body)).namelist()
        self.assertIn("termo_de_consentimento.html", names)
        self.assertTrue(any(n.endswith("/atendimento.html") for n in names))

        code, body = self.post("/api/atendimento/encerrar", {"case": case["id"]})
        self.assertEqual((code, body["removed"]), (200, 1))
        _, _, raw = self.get("/api/atendimento")
        data = json.loads(raw)
        self.assertIsNone(data["current"])
        self.assertEqual(data["cases"][0]["reports"], [])

    def test_ephemeral_cannot_be_turned_off(self):
        self.assertEqual(self.post("/api/privacy/ephemeral", {"on": False})[0], 409)


class ReportRenderTests(unittest.TestCase):
    def test_authority_report_only_cites_relevant_laws(self):
        clean = scan(FakeDevice())
        html = report.render_authority(clean, {}, {"leis": [
            {"titulo": "A", "norma": "n", "texto": "t", "explicacao": "x", "quando": ["spyware"]},
            {"titulo": "Custódia", "norma": "n", "texto": "t", "explicacao": "x", "quando": []}]})
        self.assertNotIn("<b>A</b>", html)
        self.assertIn("<b>Custódia</b>", html)
