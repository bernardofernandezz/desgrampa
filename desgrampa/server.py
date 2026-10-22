"""Servidor HTTP local (somente 127.0.0.1) com a API usada pela interface web.

Rotas:
    GET  /api/status                        estado do adb, aparelhos, bases e varreduras em andamento
    GET  /api/device/<serial>               resumo do aparelho (devinfo)
    GET  /api/scan/<id>                     progresso/resultado de uma varredura
    GET  /api/reports                       relatórios salvos
    GET  /api/reports/<nome>/relatorio.json|html   (?ver=1: abre no navegador, pronto para imprimir/PDF)
    GET  /api/reports/<nome>/atendimento.html      versão para delegacia/Defensoria/serviço de apoio
    GET  /api/reports/<nome>/relatorio.stix.json   achados e CVEs em STIX 2.1
    GET  /api/reports/<nome>/vulnerabilidades.csv
    GET  /api/reports/<nome>/evidencias.zip        pasta de evidências inteira + relatório para atendimento
    GET  /api/ajuda                         rede de apoio, Defensorias por UF e base legal
    POST /api/privacy/ephemeral             {on}  modo sem rastros: relatórios numa pasta temporária
    POST /api/privacy/wipe                  {confirm: "APAGAR"}  apaga todos os relatórios deste computador
    GET  /api/atendimento                   atendimentos abertos (modo atendimento)
    POST /api/atendimento/abrir             {consent, name, operator}
    GET  /api/atendimento/<id>/pacote.zip   evidências + relatórios + termo do atendimento
    POST /api/atendimento/encerrar          {case}  apaga os dados do atendimento deste computador
    GET  /api/ios                           ferramentas e iPhones conectados
    POST /api/ios/scan                      {udid} (backup pelo cabo) ou {backup_path}, mais {password}
    POST /api/scan                          {serial, mode, pc_network}
    POST /api/actions                       {report, package, action, confirm|consent, keep_apk, mercenary_ack, via}
    POST /api/iocs/update                   baixa as bases de indicadores em segundo plano
    POST /api/wireless/pair                 {host, port, code}   depuração sem fio: pareamento
    POST /api/wireless/connect              {host, port}
    POST /api/wireless/disconnect           {serial}
"""

import atexit
import json
import logging
import mimetypes
import re
import shutil
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from . import (
    __version__,
    actions,
    adb,
    ajuda,
    atendimento,
    bulletins,
    devinfo,
    evidence,
    export,
    iocs,
    ios,
    oscompat,
    report,
    scanner,
)
from .checks import SEVERITIES, mvt
from .paths import REPORTS_DIR, WEB_DIR

API_VERSION = 4              # a interface avisa quando o servidor em execução é mais antigo que ela
DEVICE_INFO_CACHE_S = 20     # evita chamar o adb a cada atualização da tela
SCAN_MODES = ("rapida", "completa")

log = logging.getLogger(__name__)
PLAN_CONFIRM = "REMOVER"   # digitado uma vez para aprovar as remoções de um plano de limpeza


TEMP_PREFIX = "desgrampa-"
STALE_TEMP_S = 12 * 3600


def purge_stale_tempdirs():
    """Apaga pastas temporárias de sessões sem rastros que não terminaram direito (ex.: janela fechada no
    Windows, queda de energia). Só as com mais de 12 h, para não atingir outra instância aberta."""
    for path in Path(tempfile.gettempdir()).glob(f"{TEMP_PREFIX}*"):
        try:
            if path.is_dir() and time.time() - path.stat().st_mtime > STALE_TEMP_S:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


def attachment(filename):
    return {"Content-Disposition": f'attachment; filename="{filename}"'}


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class State:
    """Estado do servidor: bases de indicadores, varreduras em andamento e caches."""

    def __init__(self, ephemeral=False, attendance=False):
        self.lock = threading.Lock()
        self.scans = {}
        self.ephemeral_dir = None
        self.attendance = atendimento.Cases() if attendance else None
        if ephemeral or attendance:
            self.set_ephemeral(True)
        self.mvt = None
        self.device_cache = {}
        self.iocs = iocs.load()
        self.bulletins = bulletins.load()
        self.iocs_job = {"state": "ok" if self.iocs.total_count else "ausente", "error": None}
        if not self.iocs.total_count:
            self.refresh_iocs()   # primeira execução: baixa as bases em segundo plano

    # ---- privacidade

    def set_ephemeral(self, on):
        """Liga/desliga o modo sem rastros: relatórios novos vão para uma pasta temporária, apagada ao sair."""
        if on and not self.ephemeral_dir:
            purge_stale_tempdirs()
            self.ephemeral_dir = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX))
            evidence.use_reports_dir(self.ephemeral_dir)
            atexit.register(self.cleanup)
        elif not on and self.ephemeral_dir:
            if self.attendance:
                raise ApiError(409, "no modo atendimento os relatórios são sempre temporários")
            shutil.rmtree(self.ephemeral_dir, ignore_errors=True)
            self.ephemeral_dir = None
            evidence.use_reports_dir(REPORTS_DIR)

    def cleanup(self):
        if self.ephemeral_dir:
            shutil.rmtree(self.ephemeral_dir, ignore_errors=True)

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
               "result": None, "error": None, "serial": serial, "mode": mode, "started_at": time.time(),
               "checks": [{"name": c.NAME, "category": c.CATEGORY, "status": "pending"} for c in scanner.CHECKS],
               "found": dict.fromkeys(SEVERITIES, 0), "alerts": []}
        with self.lock:
            if self.is_scanning(serial):
                raise ApiError(409, "Já existe uma varredura em andamento neste aparelho.")
            self.scans[job["id"]] = job

        def progress(fraction, step):
            job["progress"], job["step"] = round(fraction, 3), step
            for c in job["checks"]:
                if c["name"] == step and c["status"] == "pending":
                    c["status"] = "running"

        def on_check(index, status, found):
            counts = {s: sum(f.severity == s for f in found) for s in SEVERITIES}
            job["checks"][index] = {**job["checks"][index], "status": status["status"],
                                    "reason": status["reason"], "counts": counts}
            for s, n in counts.items():
                job["found"][s] += n
            job["alerts"] += [{"severity": f.severity, "title": f.title, "package": f.package}
                              for f in found if f.severity in ("critica", "alta")]

        def worker():
            try:
                job["result"] = scanner.run_scan(adb.Device(serial), self.iocs, mode, progress, options,
                                                 bulletins=self.bulletins, on_check=on_check)
                job.update(state="done", progress=1.0, step="Concluído")
            except Exception as e:
                log.exception("varredura de %s falhou", serial)
                job.update(state="error", error=str(e))

        threading.Thread(target=worker, daemon=True).start()
        return job["id"]

    def start_ios_scan(self, udid=None, backup_path=None, password=None, case=None):
        key = udid or "backup"
        job = {"id": uuid.uuid4().hex[:12], "state": "running", "progress": 0.0, "step": "Iniciando",
               "result": None, "error": None, "serial": key, "mode": "iphone"}
        with self.lock:
            if self.is_scanning(key):
                raise ApiError(409, "Já existe uma análise em andamento neste iPhone.")
            self.scans[job["id"]] = job

        def progress(fraction, step):
            job["progress"], job["step"] = round(fraction, 3), step

        def worker():
            try:
                job["result"] = ios.run_scan(self.iocs, self.bulletins, udid=udid, backup_dir=backup_path,
                                             password=password, on_progress=progress, case=case)
                job.update(state="done", progress=1.0, step="Concluído")
            except ios.IosError as e:
                job.update(state="error", error=str(e))
            except Exception as e:
                log.exception("análise do iPhone falhou")
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
                bulletins.download()
                self.bulletins = bulletins.load()
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
        (re.compile(r"/api/reports/([\w.-]+)/(relatorio\.(?:json|html|stix\.json)|atendimento\.html|vulnerabilidades\.csv)"),
         "get_report"),
        (re.compile(r"/api/reports/([\w.-]+)/evidencias\.zip"), "get_evidence_zip"),
        (re.compile(r"/api/ajuda"), "get_help"),
        (re.compile(r"/api/atendimento"), "get_attendance"),
        (re.compile(r"/api/atendimento/(ATD-\d{8}-\d{3})/pacote\.zip"), "get_case_package"),
        (re.compile(r"/api/ios"), "get_ios"),
    ]
    POST_ROUTES = {"/api/scan": "post_scan", "/api/actions": "post_action", "/api/iocs/update": "post_iocs_update",
                   "/api/wireless/pair": "post_wireless_pair", "/api/wireless/connect": "post_wireless_connect",
                   "/api/wireless/disconnect": "post_wireless_disconnect",
                   "/api/privacy/ephemeral": "post_ephemeral", "/api/privacy/wipe": "post_wipe",
                   "/api/atendimento/abrir": "post_case_open", "/api/atendimento/encerrar": "post_case_close",
                   "/api/ios/scan": "post_ios_scan"}

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
            "api": API_VERSION, "version": __version__, "system": oscompat.SYSTEM,
            "adb": adb.adb_path(), "devices": [], "error": None,
            "iocs": {**st.iocs.summary(), "job": st.iocs_job},
            "bulletins": bulletins.summary(st.bulletins),
            "privacy": {"ephemeral": bool(st.ephemeral_dir)},
            "attendance": {"enabled": True, "current": st.attendance.current} if st.attendance else {"enabled": False},
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
        live = {k: job[k] for k in ("checks", "found", "alerts") if k in job}
        if "started_at" in job:
            live["elapsed_s"] = round(time.time() - job["started_at"])
        self._send(200, {**{k: job[k] for k in ("id", "state", "progress", "step", "result", "error", "mode")}, **live})

    def get_reports(self):
        self._send(200, evidence.list_reports())

    def get_report(self, name, filename):
        result = evidence.load(name)
        if not result:
            raise ApiError(404, "relatório não encontrado")
        html = "text/html; charset=utf-8"
        if filename == "relatorio.html":
            inline = "ver=1" in (urlsplit(self.path).query or "")
            return self._send(200, report.render(result, printable=inline), html,
                              None if inline else attachment(f"{name}.html"))
        if filename == "atendimento.html":
            return self._send(200, report.render_authority(result, evidence.integrity(name), ajuda.load()), html)
        if filename == "relatorio.stix.json":
            return self._send(200, export.stix_json(result), "application/json; charset=utf-8",
                              attachment(f"{name}.stix.json"))
        if filename == "vulnerabilidades.csv":
            return self._send(200, export.vulns_csv(result), "text/csv; charset=utf-8",
                              attachment(f"{name}_vulnerabilidades.csv"))
        # hashes que identificam a pasta de evidências, mostrados no cabeçalho do relatório (rastreabilidade)
        return self._send(200, {**result, "integrity": evidence.integrity(name)})

    def get_help(self):
        self._send(200, ajuda.load())

    def get_evidence_zip(self, name):
        if not evidence.load(name):
            raise ApiError(404, "relatório não encontrado")
        data = evidence.zip_reports([name], {f"{name}/atendimento.html": self._authority_html(name)})
        self._send(200, data, "application/zip", attachment(f"{name}_evidencias.zip"))

    def _authority_html(self, name):
        return report.render_authority(evidence.load(name), evidence.integrity(name), ajuda.load())

    def get_attendance(self):
        if not self.state.attendance:
            raise ApiError(404, "inicie com “desgrampa --atendimento” para usar o modo atendimento")
        self._send(200, self.state.attendance.summary())

    def get_case_package(self, case_id):
        cases = self._cases()
        try:
            data = cases.package(case_id, self._authority_html, ajuda.load())
        except KeyError:
            raise ApiError(404, "atendimento não encontrado")
        self._send(200, data, "application/zip", attachment(f"{case_id}.zip"))

    def _cases(self):
        if not self.state.attendance:
            raise ApiError(404, "modo atendimento desligado")
        return self.state.attendance

    # ---- POST

    def post_scan(self, body):
        serial, mode = body.get("serial"), body.get("mode", "rapida")
        if mode not in SCAN_MODES:
            raise ApiError(400, "modo inválido")
        self.state.ready_device(serial)
        options = {"pc_network": bool(body.get("pc_network"))}
        case = self._case_for_scan()
        if case:
            options["case"] = case
        scan_id = self.state.start_scan(serial, mode, options)
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
        # remover é definitivo: exige o nome do pacote digitado (ou, no plano de limpeza revisado pelo usuário,
        # a palavra PLAN_CONFIRM digitada uma vez para o plano todo); as ações reversíveis, o aceite explícito
        via = "plano" if body.get("via") == "plano" else "individual"
        typed = body.get("confirm")
        if action == "uninstall" and typed != pkg and not (via == "plano" and typed == PLAN_CONFIRM):
            raise ApiError(400, "confirmação não confere: digite o nome exato do pacote")
        if action != "uninstall" and body.get("consent") is not True and typed != pkg:
            raise ApiError(400, "confirme que você quer fazer esta alteração no aparelho")
        if candidate["mercenary"] and action != "enable" and not body.get("mercenary_ack"):
            raise ApiError(400, "confirme que entende o risco de alterar evidências de spyware mercenário")

        serial = result["device"]["serial"]
        self.state.ready_device(serial)
        with self.state.lock:
            if self.state.is_scanning(serial):
                raise ApiError(409, "aguarde a varredura em andamento terminar")
            entry = actions.perform(adb.Device(serial), result["report_dir"], candidate, action,
                                    keep_apk=bool(body.get("keep_apk", True)), via=via)
        self.state.device_cache.pop(serial, None)
        self._send(200, entry)

    def post_iocs_update(self, _body):
        self.state.refresh_iocs()
        self._send(202, {"job": self.state.iocs_job})

    def get_ios(self):
        try:
            devices = ios.list_devices()
            error = None
        except ios.IosError as e:
            devices, error = [], str(e)
        self._send(200, {**ios.status(), "devices": devices, "error": error})

    def post_ios_scan(self, body):
        udid, path = body.get("udid"), (body.get("backup_path") or "").strip()
        if not udid and not path:
            raise ApiError(400, "escolha um iPhone conectado ou informe a pasta de um backup")
        if path and not Path(path).expanduser().is_dir():
            raise ApiError(400, "pasta de backup não encontrada")
        case = self._case_for_scan()
        scan_id = self.state.start_ios_scan(udid=None if path else udid, backup_path=path or None,
                                            password=body.get("password") or None, case=case)
        self._send(200, {"id": scan_id})

    def _case_for_scan(self):
        if not self.state.attendance:
            return None
        if not self.state.attendance.current:
            raise ApiError(409, "abra um atendimento (com o termo de consentimento) antes da varredura")
        return self.state.attendance.current

    def post_ephemeral(self, body):
        self.state.set_ephemeral(bool(body.get("on")))
        self._send(200, {"ephemeral": bool(self.state.ephemeral_dir)})

    def post_wipe(self, body):
        """Apaga todos os relatórios e evidências deste computador (a pasta atual e a permanente)."""
        if body.get("confirm") != "APAGAR":
            raise ApiError(400, "digite APAGAR para confirmar")
        if self.state.scans and any(j["state"] == "running" for j in self.state.scans.values()):
            raise ApiError(409, "aguarde a varredura em andamento terminar")
        removed = evidence.wipe() + (evidence.wipe(REPORTS_DIR) if self.state.ephemeral_dir else 0)
        self.state.scans.clear()
        self.state.device_cache.clear()
        self._send(200, {"removed": removed})

    def post_case_open(self, body):
        try:
            case = self._cases().open(body.get("consent"), body.get("name"), body.get("operator"))
        except ValueError as e:
            raise ApiError(400, str(e))
        self._send(200, case)

    def post_case_close(self, body):
        cases = self._cases()
        case_id = body.get("case") or ""
        if not atendimento.CASE_RE.fullmatch(case_id) or case_id not in cases.cases:
            raise ApiError(404, "atendimento não encontrado")
        if not cases.get(case_id)["delivered"] and not body.get("force"):
            raise ApiError(409, "baixe o pacote do atendimento antes de encerrar (ou confirme que não quer guardá-lo)")
        if any(j["state"] == "running" for j in self.state.scans.values()):
            raise ApiError(409, "aguarde a varredura em andamento terminar")
        self._send(200, {"removed": cases.close(case_id)})

    def post_wireless_pair(self, body):
        adb.pair(body.get("host"), body.get("port"), body.get("code"))
        self._send(200, {"paired": True})

    def post_wireless_connect(self, body):
        self._send(200, {"serial": adb.connect(body.get("host"), body.get("port"))})

    def post_wireless_disconnect(self, body):
        adb.disconnect(body.get("serial") or "")
        self._send(200, {"ok": True})

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


def serve(port=8765, ephemeral=False, attendance=False):
    return Server(port, State(ephemeral=ephemeral, attendance=attendance))
