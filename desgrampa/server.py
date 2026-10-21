"""Servidor HTTP local (somente 127.0.0.1) com a API da interface web."""

import json
import mimetypes
import re
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import actions, adb, devinfo, grouping, iocs, report, scanner
from .checks import mvt
from .paths import REPORTS_DIR, WEB_DIR

API_VERSION = 3   # a interface avisa quando o servidor em execução é mais antigo que ela


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.iocs = iocs.load()
        self.iocs_job = {"state": "ok" if self.iocs.total_count else "ausente", "error": None}
        self.scans = {}
        if not self.iocs.total_count:
            self.refresh_iocs()   # primeira execução: baixa as bases em segundo plano
        self.mvt = None
        self.device_cache = {}

    def device_info(self, serial):
        """Resumo do aparelho para o cartão (cache de 20 s para não martelar o adb)."""
        cached = self.device_cache.get(serial)
        if cached and time.time() - cached[0] < 20:
            return cached[1]
        listed = next((d for d in adb.list_devices() if d["serial"] == serial), None)
        if not listed or listed["state"] != "device":
            raise adb.AdbError("aparelho não conectado ou não autorizado")
        info = devinfo.summarize(serial, adb.Device(serial).shell(devinfo.COLLECT, timeout=30), listed.get("usb"))
        self.device_cache[serial] = (time.time(), info)
        return info

    def refresh_iocs(self):
        if self.iocs_job["state"] == "baixando":
            return

        def worker():
            try:
                self.iocs = iocs.update()
                self.iocs_job.update(state="ok", error=None)
            except Exception as e:
                self.iocs_job.update(state="erro", error=str(e))

        self.iocs_job.update(state="baixando", error=None)
        threading.Thread(target=worker, daemon=True).start()

    def mvt_status(self):
        if self.mvt is None or not self.mvt["installed"]:
            self.mvt = {"installed": bool(mvt.mvt_path()), "version": mvt.mvt_version()}
        return self.mvt

    def start_scan(self, serial, mode, options):
        scan_id = uuid.uuid4().hex[:12]
        job = {"id": scan_id, "state": "running", "progress": 0.0, "step": "Iniciando",
               "result": None, "error": None, "serial": serial, "mode": mode}
        with self.lock:
            if any(j["state"] == "running" and j["serial"] == serial for j in self.scans.values()):
                raise ValueError("Já existe uma varredura em andamento neste aparelho.")
            self.scans[scan_id] = job

        def progress(frac, step):
            job["progress"], job["step"] = round(frac, 3), step

        def worker():
            try:
                job["result"] = scanner.run_scan(adb.Device(serial), self.iocs, mode, progress, options)
                job["state"], job["progress"], job["step"] = "done", 1.0, "Concluído"
            except Exception as e:
                traceback.print_exc()
                job["state"], job["error"] = "error", str(e)

        threading.Thread(target=worker, daemon=True).start()
        return scan_id


def make_handler(state, port):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8", headers=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False)
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self):
            # bloqueia DNS rebinding: só aceita requisições endereçadas ao próprio localhost
            if self.headers.get("Host") not in allowed_hosts:
                self._send(403, {"error": "host não permitido"})
                return False
            return True

        def do_GET(self):
            if not self._host_ok():
                return
            path = self.path.split("?")[0]
            if path == "/api/status":
                return self._status()
            m = re.fullmatch(r"/api/device/([\w.:-]+)", path)
            if m:
                try:
                    return self._send(200, state.device_info(m.group(1)))
                except adb.AdbError as e:
                    return self._send(503, {"error": str(e)})
            if path == "/api/reports":
                return self._send(200, devinfo.list_reports(REPORTS_DIR))
            m = re.fullmatch(r"/api/reports/([\w.-]+)/(relatorio\.(?:json|html))", path)
            if m:
                target = devinfo.report_path(REPORTS_DIR, m.group(1), m.group(2))
                if not target:
                    return self._send(404, {"error": "relatório não encontrado"})
                result = load_report(m.group(1))
                if m.group(2).endswith(".html"):
                    return self._send(200, report.render(result), "text/html; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="{m.group(1)}.html"'})
                return self._send(200, result)
            m = re.fullmatch(r"/api/scan/(\w+)(/report\.(html|json))?", path)
            if m:
                job = state.scans.get(m.group(1))
                if not job:
                    return self._send(404, {"error": "varredura não encontrada"})
                if not m.group(2):
                    return self._send(200, {k: job[k] for k in
                                            ("id", "state", "progress", "step", "result", "error", "mode")})
                if job["state"] != "done":
                    return self._send(409, {"error": "varredura ainda não concluída"})
                name = f"desgrampa-{job['result']['started'].replace(' ', '_').replace(':', '')}"
                if m.group(3) == "html":
                    return self._send(200, report.render(job["result"]), "text/html; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="{name}.html"'})
                return self._send(200, json.dumps(job["result"], ensure_ascii=False, indent=2),
                                  headers={"Content-Disposition": f'attachment; filename="{name}.json"'})
            return self._static(path)

        def do_POST(self):
            if not self._host_ok():
                return
            if "application/json" not in (self.headers.get("Content-Type") or ""):
                return self._send(415, {"error": "use application/json"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "JSON inválido"})
            if self.path == "/api/scan":
                serial, mode = body.get("serial"), body.get("mode", "rapida")
                options = {"pc_network": bool(body.get("pc_network"))}
                if mode not in ("rapida", "completa"):
                    return self._send(400, {"error": "modo inválido"})
                try:
                    devices = {d["serial"]: d for d in adb.list_devices()}
                except adb.AdbError as e:
                    return self._send(503, {"error": str(e)})
                if devices.get(serial, {}).get("state") != "device":
                    return self._send(400, {"error": "aparelho não conectado ou não autorizado"})
                try:
                    return self._send(200, {"id": state.start_scan(serial, mode, options)})
                except ValueError as e:
                    return self._send(409, {"error": str(e)})
            if self.path == "/api/actions":
                return self._action(body)
            if self.path == "/api/iocs/update":
                state.refresh_iocs()
                return self._send(202, {"job": state.iocs_job})
            return self._send(404, {"error": "não encontrado"})

        def _action(self, body):
            name, pkg, action = body.get("report"), body.get("package"), body.get("action")
            if action not in actions.ACTIONS:
                return self._send(400, {"error": "ação inválida"})
            if not name or not devinfo.report_path(REPORTS_DIR, name):
                return self._send(404, {"error": "relatório não encontrado"})
            result = load_report(name)
            candidate = next((c for c in result["removal_candidates"] if c["package"] == pkg), None)
            if not candidate:
                return self._send(400, {"error": "este app não está entre as sugestões de remoção deste relatório"})
            if body.get("confirm") != pkg:
                return self._send(400, {"error": "confirmação não confere: digite o nome exato do pacote"})
            if candidate["mercenary"] and not body.get("mercenary_ack"):
                return self._send(400, {"error": "confirme que entende o risco de apagar evidências de spyware mercenário"})
            serial = result["device"]["serial"]
            try:
                devices = {d["serial"]: d for d in adb.list_devices()}
            except adb.AdbError as e:
                return self._send(503, {"error": str(e)})
            if devices.get(serial, {}).get("state") != "device":
                return self._send(409, {"error": f"conecte e autorize o aparelho {serial} deste relatório"})
            with state.lock:
                if any(j["state"] == "running" and j["serial"] == serial for j in state.scans.values()):
                    return self._send(409, {"error": "aguarde a varredura em andamento terminar"})
                entry = actions.perform(adb.Device(serial), REPORTS_DIR / name, candidate, action,
                                        keep_apk=bool(body.get("keep_apk", True)))
            state.device_cache.pop(serial, None)
            return self._send(200, entry)

        def _status(self):
            status = {"api": API_VERSION, "adb": adb.adb_path(), "devices": [], "error": None,
                      "iocs": {**state.iocs.summary(), "job": state.iocs_job},
                      "mvt": state.mvt_status(),
                      "running": [{k: j[k] for k in ("id", "serial", "mode", "progress", "step")}
                                  for j in state.scans.values() if j["state"] == "running"]}
            if status["adb"]:
                try:
                    status["devices"] = adb.list_devices()
                except adb.AdbError as e:
                    status["error"] = str(e)
            return self._send(200, status)

        def _static(self, path):
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            target = (WEB_DIR / rel).resolve()
            if WEB_DIR not in target.parents or not target.is_file():
                return self._send(404, "não encontrado", "text/plain; charset=utf-8")
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype.endswith("javascript"):
                ctype += "; charset=utf-8"
            return self._send(200, target.read_bytes(), ctype)

    return Handler


def load_report(name):
    """Relatório salvo + agrupamento/sugestões (calculados na hora) + histórico de ações."""
    path = devinfo.report_path(REPORTS_DIR, name)
    result = grouping.enrich(json.loads(path.read_text(encoding="utf-8")))
    result["actions"] = actions.read_log(path.parent)
    result["report_name"] = name
    return result


def serve(port=8765):
    state = State()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state, port))
    return httpd
