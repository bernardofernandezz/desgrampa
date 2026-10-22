"""Servidor HTTP local (somente 127.0.0.1) com a API usada pela interface web.

Rotas:
    GET  /api/status                        estado do adb, aparelhos, bases e varreduras em andamento
    GET  /api/device/<serial>               resumo do aparelho (devinfo)
    GET  /api/scan/<id>                     progresso/resultado de uma varredura
    GET  /api/reports                       relatórios salvos
    GET  /api/reports/<nome>/relatorio.json|html
    POST /api/scan                          {serial, mode, pc_network}
    POST /api/actions                       {report, package, action, confirm, keep_apk, mercenary_ack}
    POST /api/iocs/update                   baixa as bases de indicadores em segundo plano
"""

import json
import logging
import mimetypes
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import actions, adb, devinfo, evidence, iocs, report, scanner
from .checks import mvt
from .paths import WEB_DIR

API_VERSION = 3              # a interface avisa quando o servidor em execução é mais antigo que ela
DEVICE_INFO_CACHE_S = 20     # evita chamar o adb a cada atualização da tela
SCAN_MODES = ("rapida", "completa")

log = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class State:
    """Estado do servidor: bases de indicadores, varreduras em andamento e caches."""

    def __init__(self):
        self.lock = threading.Lock()
        self.scans = {}
        self.mvt = None
        self.device_cache = {}
        self.iocs = iocs.load()
        self.iocs_job = {"state": "ok" if self.iocs.total_count else "ausente", "error": None}
        if not self.iocs.total_count:
            self.refresh_iocs()   # primeira execução: baixa as bases em segundo plano

    # ---- aparelhos

    def ready_device(self, serial):
        """Aparelho conectado e autorizado, ou ApiError."""
        device = next((d for d in adb.list_devices() if d["serial"] == serial), None)
        if not device or device["state"] != "device":
            raise ApiError(409, f"conecte e autorize o aparelho {serial}")
        return device

    def device_info(self, serial):
        cached = self.device_cache.get(serial)
        if cached and time.time() - cached[0] < DEVICE_INFO_CACHE_S:
            return cached[1]
        device = self.ready_device(serial)
        info = devinfo.summarize(serial, adb.Device(serial).shell(devinfo.COLLECT, timeout=30), device.get("usb"))
        self.device_cache[serial] = (time.time(), info)
        return info

    # ---- varreduras

    def is_scanning(self, serial):
        return any(j["state"] == "running" and j["serial"] == serial for j in self.scans.values())

    def start_scan(self, serial, mode, options):
        job = {"id": uuid.uuid4().hex[:12], "state": "running", "progress": 0.0, "step": "Iniciando",
               "result": None, "error": None, "serial": serial, "mode": mode}
        with self.lock:
            if self.is_scanning(serial):
                raise ApiError(409, "Já existe uma varredura em andamento neste aparelho.")
            self.scans[job["id"]] = job

        def progress(fraction, step):
            job["progress"], job["step"] = round(fraction, 3), step

        def worker():
            try:
                job["result"] = scanner.run_scan(adb.Device(serial), self.iocs, mode, progress, options)
                job.update(state="done", progress=1.0, step="Concluído")
            except Exception as e:
                log.exception("varredura de %s falhou", serial)
                job.update(state="error", error=str(e))

        threading.Thread(target=worker, daemon=True).start()
        return job["id"]

    # ---- bases e ferramentas

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
        if self.mvt is None or not self.mvt["installed"]:   # reconsulta até o MVT ser instalado
            self.mvt = {"installed": bool(mvt.mvt_path()), "version": mvt.mvt_version()}
        return self.mvt


class Handler(BaseHTTPRequestHandler):
    GET_ROUTES = [
        (re.compile(r"/api/status"), "get_status"),
        (re.compile(r"/api/device/([\w.:-]+)"), "get_device"),
        (re.compile(r"/api/scan/(\w+)"), "get_scan"),
        (re.compile(r"/api/reports"), "get_reports"),
        (re.compile(r"/api/reports/([\w.-]+)/(relatorio\.(?:json|html))"), "get_report"),
    ]
    POST_ROUTES = {"/api/scan": "post_scan", "/api/actions": "post_action", "/api/iocs/update": "post_iocs_update"}

    @property
    def state(self):
        return self.server.state

    def log_message(self, fmt, *args):
        pass   # sem log de cada requisição no terminal

    # ---- roteamento

    def do_GET(self):
        if not self._host_ok():
            return
        path = urlsplit(self.path).path
        for pattern, handler in self.GET_ROUTES:
            match = pattern.fullmatch(path)
            if match:
                return self._dispatch(getattr(self, handler), *match.groups())
        return self._static(path)

    def do_POST(self):
        if not self._host_ok():
            return
        handler = self.POST_ROUTES.get(urlsplit(self.path).path)
        if not handler:
            return self._send(404, {"error": "não encontrado"})
        # exigir JSON obriga o navegador a fazer preflight CORS, o que bloqueia POSTs de outros sites
        if "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._send(415, {"error": "use application/json"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            return self._send(400, {"error": "JSON inválido"})
        return self._dispatch(getattr(self, handler), body)

    def _dispatch(self, handler, *args):
        try:
            handler(*args)
        except ApiError as e:
            self._send(e.status, {"error": str(e)})
        except adb.AdbError as e:
            self._send(503, {"error": str(e)})

    # ---- GET

    def get_status(self):
        st = self.state
        status = {
            "api": API_VERSION, "adb": adb.adb_path(), "devices": [], "error": None,
            "iocs": {**st.iocs.summary(), "job": st.iocs_job},
            "mvt": st.mvt_status(),
            "running": [{k: j[k] for k in ("id", "serial", "mode", "progress", "step")}
                        for j in st.scans.values() if j["state"] == "running"],
        }
        if status["adb"]:
            try:
                status["devices"] = adb.list_devices()
            except adb.AdbError as e:
                status["error"] = str(e)
        self._send(200, status)

    def get_device(self, serial):
        self._send(200, self.state.device_info(serial))

    def get_scan(self, scan_id):
        job = self.state.scans.get(scan_id)
        if not job:
            raise ApiError(404, "varredura não encontrada")
        self._send(200, {k: job[k] for k in ("id", "state", "progress", "step", "result", "error", "mode")})

    def get_reports(self):
        self._send(200, evidence.list_reports())

    def get_report(self, name, filename):
        result = evidence.load(name)
        if not result:
            raise ApiError(404, "relatório não encontrado")
        if filename.endswith(".html"):
            disposition = {"Content-Disposition": f'attachment; filename="{name}.html"'}
            return self._send(200, report.render(result), "text/html; charset=utf-8", disposition)
        return self._send(200, result)

    # ---- POST

    def post_scan(self, body):
        serial, mode = body.get("serial"), body.get("mode", "rapida")
        if mode not in SCAN_MODES:
            raise ApiError(400, "modo inválido")
        self.state.ready_device(serial)
        scan_id = self.state.start_scan(serial, mode, {"pc_network": bool(body.get("pc_network"))})
        self._send(200, {"id": scan_id})

    def post_action(self, body):
        """Remove/desativa um app SUGERIDO no relatório, só com a confirmação digitada pelo usuário."""
        name, pkg, action = body.get("report"), body.get("package"), body.get("action")
        if action not in actions.ACTIONS:
            raise ApiError(400, "ação inválida")
        result = evidence.load(name) if name else None
        if not result:
            raise ApiError(404, "relatório não encontrado")
        candidate = next((c for c in result["removal_candidates"] if c["package"] == pkg), None)
        if not candidate:
            raise ApiError(400, "este app não está entre as sugestões de remoção deste relatório")
        if body.get("confirm") != pkg:
            raise ApiError(400, "confirmação não confere: digite o nome exato do pacote")
        if candidate["mercenary"] and not body.get("mercenary_ack"):
            raise ApiError(400, "confirme que entende o risco de apagar evidências de spyware mercenário")

        serial = result["device"]["serial"]
        self.state.ready_device(serial)
        with self.state.lock:
            if self.state.is_scanning(serial):
                raise ApiError(409, "aguarde a varredura em andamento terminar")
            entry = actions.perform(adb.Device(serial), result["report_dir"], candidate, action,
                                    keep_apk=bool(body.get("keep_apk", True)))
        self.state.device_cache.pop(serial, None)
        self._send(200, entry)

    def post_iocs_update(self, _body):
        self.state.refresh_iocs()
        self._send(202, {"job": self.state.iocs_job})

    # ---- utilidades

    def _host_ok(self):
        # bloqueia DNS rebinding: só aceita requisições endereçadas ao próprio localhost
        port = self.server.server_address[1]
        if self.headers.get("Host") not in (f"127.0.0.1:{port}", f"localhost:{port}"):
            self._send(403, {"error": "host não permitido"})
            return False
        return True

    def _send(self, code, body, content_type="application/json; charset=utf-8", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _static(self, path):
        target = (WEB_DIR / (path.lstrip("/") or "index.html")).resolve()
        if WEB_DIR not in target.parents or not target.is_file():
            return self._send(404, "não encontrado", "text/plain; charset=utf-8")
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type.endswith("javascript"):
            content_type += "; charset=utf-8"
        return self._send(200, target.read_bytes(), content_type)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, state=None):
        super().__init__(("127.0.0.1", port), Handler)
        self.state = state or State()


def serve(port=8765):
    return Server(port)
