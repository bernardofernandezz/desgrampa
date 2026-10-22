"""Relatórios salvos em disco: uma pasta por varredura, com as evidências e um SHA256SUMS.txt.

    relatorios/<data>_<serial>/
        relatorio.json, relatorio.html
        comandos/NNN_<comando>.txt     saída bruta de cada comando adb
        bugreport.zip, mvt/            varredura completa
        removidos/, acoes.jsonl        remoções feitas pelo usuário (actions.py)
        SHA256SUMS.txt
"""

import json
import re
import time
from pathlib import Path

from . import actions, grouping, report
from .paths import REPORTS_DIR
from .util import sha256_file

REPORT_FILES = ("relatorio.json", "relatorio.html")


def new_dir(serial, started):
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(started))
    safe_serial = re.sub(r"[^\w.-]", "_", serial)
    path = REPORTS_DIR / f"{stamp}_{safe_serial}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def save(base, result, raw_commands):
    """Grava relatório, saídas brutas dos comandos e o SHA256SUMS.txt de tudo que está na pasta."""
    base = Path(base)
    commands_dir = base / "comandos"
    commands_dir.mkdir(exist_ok=True)
    for i, (cmd, out) in enumerate(raw_commands.items(), 1):
        slug = re.sub(r"\W+", "_", cmd)[:60].strip("_")
        (commands_dir / f"{i:03d}_{slug}.txt").write_text(f"$ adb shell {cmd}\n\n{out or ''}", encoding="utf-8")
    (base / "relatorio.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (base / "relatorio.html").write_text(report.render(result), encoding="utf-8")

    files = sorted(p for p in base.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
    sums = [f"{sha256_file(f)}  {f.relative_to(base)}" for f in files]
    (base / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")


def report_path(name, filename="relatorio.json", reports_dir=None):
    """Caminho de um arquivo de relatório, ou None se não existir ou tentar sair da pasta de relatórios."""
    reports_dir = Path(reports_dir or REPORTS_DIR).resolve()
    if not re.fullmatch(r"[\w.-]+", name) or filename not in REPORT_FILES:
        return None
    path = (reports_dir / name / filename).resolve()
    if reports_dir not in path.parents or not path.is_file():
        return None
    return path


def list_reports(reports_dir=None):
    """Resumo dos relatórios salvos, mais recentes primeiro."""
    items = []
    for path in sorted(Path(reports_dir or REPORTS_DIR).glob("*/relatorio.json"), reverse=True):
        try:
            r = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        device = r.get("device", {})
        stats = r.get("stats", {})
        items.append({
            "name": path.parent.name,
            "started": r.get("started"),
            "mode": r.get("mode"),
            "device": " ".join(x for x in (device.get("manufacturer"), device.get("model")) if x) or device.get("serial"),
            "serial": device.get("serial"),
            "verdict": r.get("verdict"),
            "counts": r.get("counts"),
            "duration_s": r.get("duration_s"),
            "categories_verified": stats.get("categories_verified"),
            "categories_total": stats.get("categories_total"),
        })
    return items


def load(name, reports_dir=None):
    """Relatório salvo + agrupamento e sugestões (recalculados) + histórico de ações. None se não existir."""
    path = report_path(name, reports_dir=reports_dir)
    if not path:
        return None
    result = grouping.enrich(json.loads(path.read_text(encoding="utf-8")))
    result["actions"] = actions.read_log(path.parent)
    result["report_name"] = name
    result["report_dir"] = str(path.parent)
    return result
