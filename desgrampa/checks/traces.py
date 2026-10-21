"""Rastros: apps que estiveram no aparelho e foram removidos, sobras no armazenamento,
arquivos de spyware conhecidos e domínios/IPs maliciosos citados nos logs do sistema."""

import re
import shlex
from datetime import datetime, timedelta

from . import Finding
from .packages import DISGUISE_WORDS, SUSPICIOUS_WORDS

NAME = "Rastros e histórico"
CATEGORY = "rastros"

PKG = r"[a-zA-Z][\w]*(?:\.[\w]+)+"
IGNORE_PREFIXES = ("android.", "com.android.", "com.google.android.gms", "androidx.", "java.", "kotlin.")


def _wall(value):
    for fmt in ("%Y-%m-%d-%H-%M-%S", "%Y-%m-%d-%H-%M-%S-%f"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    return None


def _elapsed(token):
    if not token.startswith("+"):
        return None
    units = {"d": 86400, "h": 3600, "m": 60, "s": 1, "ms": 0.001}
    return sum(int(n) * units[u] for n, u in re.findall(r"(\d+)(ms|d|h|m|s)", token))


def parse_battery_history(out):
    """`dumpsys batterystats --history` -> (eventos de instalação/remoção, pacotes que rodaram)."""
    events, seen = [], set()
    anchor, anchor_el = None, 0.0
    for line in out.splitlines():
        s = line.strip()
        t = re.search(r"(?:RESET:)?TIME:\s*(\S+)", s)
        if t:
            parsed = _wall(t.group(1))
            if parsed:
                anchor, anchor_el = parsed, _elapsed(s.split()[0]) or 0.0
            continue
        for kind, pkg in re.findall(r"\b(pkginst|pkgunin)=[^:\s]+:\"(" + PKG + r")\"", s):
            el = _elapsed(s.split()[0]) if s else None
            when = (anchor + timedelta(seconds=el - anchor_el)).strftime("%Y-%m-%d %H:%M") \
                if anchor and el is not None else None
            events.append({"event": "instalado" if kind == "pkginst" else "removido", "package": pkg, "time": when})
            seen.add(pkg)
        for pkg in re.findall(r"[+-](?:top|job)=[^:\s]+:\"(?:\*job\*/)?(" + PKG + r")", s):
            seen.add(pkg)
    return events, seen


def parse_logcat_removals(out):
    pkgs = set()
    for m in re.finditer(r"(?:Removing package|deletePackage\w*|uninstall pkg|Package removed|"
                         r"pkg=|packageName=)\s*:?\s*(" + PKG + r")", out):
        if re.search(r"remov|delet|uninstall", out[max(0, m.start() - 80):m.end()], re.I):
            pkgs.add(m.group(1))
    return pkgs


def run(ctx):
    findings = []
    installed = set(ctx.packages)
    for u in ctx.data.get("contas", {}).get("extra_users", []):
        installed |= set(u.get("apps", []))
    sources = {}

    def saw(pkg, source):
        if pkg in installed or pkg.startswith(IGNORE_PREFIXES) or pkg.count(".") > 6:
            return
        sources.setdefault(pkg, set()).add(source)

    ctx.progress("Lendo histórico de bateria (instalações e remoções)")
    events, ran = parse_battery_history(ctx.try_sh("dumpsys batterystats --history", timeout=180))
    for e in events:
        saw(e["package"], "histórico de instalação")
    for pkg in ran:
        saw(pkg, "histórico de bateria")

    usage = ctx.try_sh("dumpsys usagestats", timeout=120)
    for pkg in set(re.findall(r"\bpackage=(" + PKG + r")", usage)):
        saw(pkg, "estatísticas de uso")

    for pkg in set(re.findall(r"/data/(?:user/\d+|data)/(" + PKG + r")/databases", ctx.try_sh("dumpsys dbinfo"))):
        saw(pkg, "bancos de dados abertos")

    for folder in ("/sdcard/Android/data", "/sdcard/Android/media", "/sdcard/Android/obb"):
        for name in ctx.try_sh(f"ls -1 {folder} 2>/dev/null").split():
            if re.fullmatch(PKG, name):
                saw(name, f"pasta {folder}")

    ctx.progress("Lendo logs do sistema")
    logcat = ctx.try_sh("logcat -d -b all -v time", timeout=120)
    for pkg in parse_logcat_removals(logcat):
        saw(pkg, "logs do sistema")

    removed = []
    for pkg, srcs in sorted(sources.items()):
        match = ctx.iocs.match_package(pkg)
        removed.append({"package": pkg, "sources": sorted(srcs), "ioc": str(match) if match else None})
        if match:
            findings.append(Finding(
                "critica", f"Rastro de spyware removido: {match.family}",
                f"{pkg} não está mais instalado, mas deixou rastros ({', '.join(sorted(srcs))}). Ele "
                f"consta nos indicadores de {match}. Isso indica que o aparelho foi monitorado, ou que "
                "o app continua escondido em outro lugar.",
                "Troque todas as senhas a partir de outro aparelho e guarde as evidências. Considere "
                "restaurar o aparelho para as configurações de fábrica depois de salvar o relatório.",
                package=pkg, category="mercenario" if match.mercenary else "rastros", family=match.family))
        elif SUSPICIOUS_WORDS.search(pkg) or DISGUISE_WORDS.search(pkg):
            findings.append(Finding(
                "media", "Rastro de app suspeito removido",
                f"{pkg} já esteve no aparelho ({', '.join(sorted(srcs))}) e tem nome associado a "
                "monitoramento ou disfarce.",
                "Lembre se você instalou esse app. Se não, considere que o aparelho foi monitorado.",
                package=pkg))
    if removed:
        findings.append(Finding(
            "info", "Apps que já estiveram no aparelho",
            f"{len(removed)} app(s) deixaram rastros mas não estão instalados (lista completa no painel "
            "“Rastros”). Revise se reconhece todos.", ""))

    files = []
    paths = [p for p in ctx.iocs.file_paths if p.startswith(("/data/", "/sdcard/", "/storage/", "/system/", "/vendor/"))]
    if paths:
        # os caminhos vêm das bases baixadas da internet: sempre escapados antes de ir ao shell
        found = ctx.try_sh("ls -d " + " ".join(shlex.quote(p.rstrip("/")) for p in paths) + " 2>/dev/null").split()
        for path in found:
            m = ctx.iocs.file_paths.get(path) or ctx.iocs.file_paths.get(path + "/")
            if m:
                files.append(path)
                findings.append(Finding(
                    "critica", f"Arquivo de spyware encontrado: {m.family}",
                    f"O caminho {path} existe no aparelho e é indicador de {m}.",
                    "Não apague nada. Salve as evidências e procure análise forense especializada.",
                    category="mercenario" if m.mercenary else "spyware"))
    names = set(ctx.iocs.file_names)
    if names:
        listing = ctx.try_sh("ls -1a /data/local/tmp /sdcard /sdcard/Download 2>/dev/null")
        for name in set(listing.split()) & names:
            m = ctx.iocs.file_names[name]
            findings.append(Finding(
                "critica", f"Arquivo com nome de spyware: {m.family}",
                f"Um arquivo chamado {name} foi encontrado e é indicador de {m}.",
                "Salve as evidências e procure análise forense especializada.",
                category="mercenario" if m.mercenary else "spyware"))

    text = logcat + "\n" + usage
    hits = {**ctx.iocs.domains_in_text(text), **ctx.iocs.ips_in_text(text)}
    for host, m in sorted(hits.items()):
        findings.append(Finding(
            "critica", f"Contato com servidor de spyware nos logs: {m.family}",
            f"Os logs do sistema mencionam {host}, endereço usado por {m}.",
            "Guarde as evidências (pasta do relatório) e procure análise especializada.",
            category="mercenario" if m.mercenary else "spyware"))

    ctx.data["rastros"] = {"install_events": events[-200:], "removed": removed, "ioc_files": files,
                           "log_hits": {h: str(m) for h, m in hits.items()},
                           "logcat_lines": logcat.count("\n")}
    return findings
