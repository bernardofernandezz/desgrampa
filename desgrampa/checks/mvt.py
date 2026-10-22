"""(Varredura completa) Gera um bugreport do aparelho e o analisa com o MVT — Mobile Verification
Toolkit da Anistia Internacional — contra todas as bases de spyware mercenário."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from .. import iocs as iocs_mod
from .. import oscompat
from ..adb import AdbError
from ..context import SkipCheck
from ..paths import DATA_DIR, REPO_DIR
from ..util import QUOTED_PACKAGE_RE
from . import Finding
from .packages import visible_monitoring_app

NAME = "Análise forense MVT (Anistia Internacional)"
CATEGORY = "mercenario"
FULL_ONLY = True

LEVELS = {"CRITICAL": "critica", "HIGH": "alta", "MEDIUM": "media", "LOW": "baixa", "INFORMATIONAL": "info"}


def mvt_path():
    # variável de ambiente > mesmo ambiente Python do Desgrampa > .venv do repositório > PATH
    for candidate in (os.environ.get("DESGRAMPA_MVT"), oscompat.venv_script(sys.prefix, "mvt-android"),
                      oscompat.venv_script(REPO_DIR / ".venv", "mvt-android"), shutil.which("mvt-android")):
        if candidate and Path(candidate).exists():
            return str(candidate)
    return None


def mvt_version():
    path = mvt_path()
    if not path:
        return None
    try:
        out = oscompat.run([path, "--disable-update-check", "version"], capture_output=True,
                           text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        if "Version:" in line:
            return line.split("Version:", 1)[1].strip()
    return "?"


def available(ctx):
    if not ctx.full:
        return "disponível só na varredura completa"
    if not mvt_path():
        return "MVT não instalado (veja o README: .venv/bin/pip install mvt)"
    return None


def run(ctx):
    mvt = mvt_path()
    base = Path(ctx.evidence_dir) if ctx.evidence_dir else Path(tempfile.mkdtemp(prefix="desgrampa-mvt-"))
    out_dir = base / "mvt"
    out_dir.mkdir(exist_ok=True)
    bugreport = base / "bugreport.zip"

    ctx.progress("Gerando bugreport do aparelho (2 a 6 minutos; mantenha desbloqueado)")
    try:
        ctx.device.bugreport(str(bugreport), timeout=900)
    except AdbError as e:
        raise SkipCheck(f"não foi possível gerar o bugreport: {e}")
    if not bugreport.exists() or not zipfile.is_zipfile(bugreport):
        raise SkipCheck("o aparelho não gerou o bugreport")

    ctx.progress("Analisando o bugreport com o MVT")
    cmd = [mvt, "--disable-update-check", "--disable-indicator-update-check", "check-bugreport",
           "-o", str(out_dir)]
    for f in iocs_mod.stix_files():
        cmd += ["-i", str(f)]
    cmd.append(str(bugreport))
    env = {**os.environ, "MVT_DATA_FOLDER": str(DATA_DIR / "mvt")}
    try:
        proc = oscompat.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1200,
                            env=env)
    except subprocess.TimeoutExpired:
        raise SkipCheck("o MVT demorou demais (mais de 20 min)")
    (out_dir / "mvt.log").write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")

    alerts, findings = parse_alerts(ctx, out_dir)
    modules = len([f for f in out_dir.glob("*.json") if not f.name.endswith("_detected.json")])
    ctx.data["mvt"] = {"version": mvt_version(), "alerts": len(alerts),
                       "modules_with_data": modules, "returncode": proc.returncode, "output_dir": str(out_dir),
                       "bugreport_mb": round(bugreport.stat().st_size / 1024 / 1024, 1)}
    if proc.returncode != 0 and not alerts and modules == 0:
        raise SkipCheck(f"o MVT falhou (código {proc.returncode}); veja {out_dir / 'mvt.log'}")
    return findings


def _pkg_in_message(ctx, message):
    """Primeiro pacote instalado citado entre aspas na mensagem do MVT."""
    return next((m.group(1) for m in QUOTED_PACKAGE_RE.finditer(message or "") if m.group(1) in ctx.packages), None)


# Tradução/agrupamento das mensagens mais comuns do MVT: (padrão, chave de agrupamento, texto em português)
MESSAGES = [
    (r'Found a known suspicious app with ID "([^"]+)" matching indicators from "([^"]+)"',
     "ioc:{0}", "App conhecido nas bases de spyware: {0} ({1})"),
    (r"Package '([^']+)' had risky permission '([^']+)' set to",
     "perm:{0}:{1}", "O app {0} teve a permissão sensível {1} alterada (histórico de permissões)"),
    (r"Detected downgrade of package (\S+)", "down:{0}", "Versão anterior reinstalada (downgrade) do pacote {0}"),
    (r"Potentially suspicious crash in process '([^']+)' running as UID '0'",
     "crash:{0}", "Falha de um processo do sistema rodando como root: {0}"),
    (r"Risky package '([^']+)' had '([^']+)' permission", "risky:{0}:{1}",
     "O pacote {0} usou a permissão {1}"),
    (r"has not received security updates for more than six months", "patch",
     "Aparelho sem atualização de segurança há mais de 6 meses"),
]


def _normalize(message):
    for pattern, key, text in MESSAGES:
        m = re.search(pattern, message)
        if m:
            return key.format(*m.groups()), text.format(*m.groups())
    return message, message


def _group_alerts(out_dir):
    """Lê os *_detected.json do MVT e junta alertas repetidos (o MVT gera um alerta por evento)."""
    alerts, groups = [], {}
    for path in sorted(Path(out_dir).glob("*_detected.json")):
        try:
            items = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for alert in items if isinstance(items, list) else []:
            alerts.append(alert)
            key, title = _normalize(alert.get("message") or "alerta")
            group = groups.setdefault(key, {"alert": alert, "title": title, "modules": set(), "times": [], "count": 0})
            group["count"] += 1
            group["modules"].add(alert.get("module") or path.stem.removesuffix("_detected"))
            if alert.get("event_time"):
                group["times"].append(str(alert["event_time"]))
    return alerts, groups


def _adjusted_severity(ctx, key, message, severity, pkg):
    """Corrige a severidade de alertas que, no contexto do Desgrampa, sabemos ser menos graves.
    Devolve (severidade, nota explicativa)."""
    if key.startswith("down:com.google.android."):
        return "baixa", " Módulos do sistema do Google (Mainline) às vezes voltam de versão em atualizações normais."
    if "com.android.shell" in message:
        # o "shell" é a própria sessão de depuração USB: acessos dele são esperados durante a varredura
        return "baixa", (" O pacote com.android.shell é a sessão de depuração USB; esses acessos são esperados "
                         "enquanto você usa ADB (inclusive nesta varredura).")
    match = ctx.iocs.match_package(pkg) if pkg else None
    if severity == "critica" and match and visible_monitoring_app(ctx, pkg, match):
        return "alta", " App visível instalado pela loja oficial (veja o achado do próprio app)."
    return severity, ""


def _finding_for(ctx, key, group):
    alert = group["alert"]
    message = alert.get("message") or ""
    pkg = _pkg_in_message(ctx, message)
    severity, note = _adjusted_severity(ctx, key, message, LEVELS.get(str(alert.get("level")).upper(), "media"), pkg)

    indicator = alert.get("matched_indicator") or {}
    indicator_txt = ""
    if isinstance(indicator, dict) and indicator.get("value"):
        source = indicator.get("name") or indicator.get("stix2_file_name") or ""
        indicator_txt = f" Indicador: {indicator['value']} ({source})."
    times = sorted(group["times"])
    when = f" Eventos de {times[0]} a {times[-1]}." if len(times) > 1 else f" Data do evento: {times[0]}." if times else ""
    repeated = f", repetido em {group['count']} eventos." if group["count"] > 1 else "."
    original = f" Mensagem original: {message}" if group["title"] != message else ""
    match = ctx.iocs.match_package(pkg) if pkg else None

    return Finding(
        severity, f"MVT: {group['title']}"[:160],
        f"Alerta do MVT (módulo {', '.join(sorted(group['modules']))}){repeated}{when}{indicator_txt}{note}{original}",
        "Alertas do MVT devem ser confirmados por especialista. Não apague nada: envie a pasta de evidências "
        "para a Access Now Helpline (accessnow.org/help) ou o Amnesty Security Lab.",
        package=pkg, family=match.family if match else None)


def parse_alerts(ctx, out_dir):
    """Devolve (alertas brutos do MVT, achados agrupados e traduzidos)."""
    alerts, groups = _group_alerts(out_dir)
    # o alerta de patch antigo já é coberto pela verificação "Atualização de segurança desatualizada"
    findings = [_finding_for(ctx, key, group) for key, group in groups.items() if key != "patch"]
    return alerts, findings
