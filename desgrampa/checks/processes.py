"""Processos em execução comparados com as bases de spyware e locais suspeitos."""

import re

from ..context import parse_ps
from . import Finding, ioc_category
from .packages import visible_monitoring_app

NAME = "Processos em execução"
CATEGORY = "spyware"


def run(ctx):
    findings = []
    out = ctx.try_sh("ps -A -o USER,PID,NAME")
    procs = parse_ps(out) if "PID" in out else parse_ps(ctx.try_sh("ps"))
    if not procs:
        ctx.notes.append("Não foi possível listar processos")
        return findings

    reported = set()
    system_bins = {}

    def is_system_binary(proc):
        # vários indicadores de processo vêm de ataques a iPhone; nomes como "gatekeeperd" também
        # existem como serviços legítimos do Android. Se o binário está na partição do sistema, ignoramos.
        if not re.fullmatch(r"[\w.@+-]+", proc):
            return False   # nome estranho vindo do aparelho: não vai para o shell
        if proc not in system_bins:
            out = ctx.try_sh(f"ls /system/bin/{proc} /system_ext/bin/{proc} /vendor/bin/{proc} "
                             f"/system/bin/hw/{proc} /vendor/bin/hw/{proc} 2>/dev/null")
            system_bins[proc] = bool(out.strip())
        return system_bins[proc]

    for user, pid, name in procs:
        base = name.split(":")[0]
        short = name.rsplit("/", 1)[-1]
        match = ctx.iocs.match_process(short)
        if match and not ctx.iocs.match_package(base) and "." not in short and is_system_binary(short):
            ctx.notes.append(f"Processo {short} tem o nome de um indicador de {match}, mas é um serviço "
                             "legítimo do Android (binário do sistema) — ignorado")
            match = None
        if match and ctx.iocs.match_package(base) and visible_monitoring_app(ctx, base, match):
            match = None   # app visível da loja oficial: já reportado (com contexto) pela verificação de apps
        if match and base not in reported:
            reported.add(base)
            findings.append(Finding(
                "critica", f"Spyware em execução: {match.family}",
                f"O processo {name} (PID {pid}, usuário {user}) está rodando agora e corresponde a "
                f"um indicador de {match}.",
                "Não reinicie nem apague nada antes de salvar o relatório e as evidências; procure "
                "ajuda especializada.", package=base, category=ioc_category(match), family=match.family))
        if name.startswith(("/data/local/tmp/", "/sdcard/", "/data/local/")):
            findings.append(Finding(
                "alta", "Programa rodando de pasta temporária",
                f"O processo {name} (PID {pid}, usuário {user}) roda a partir de uma pasta "
                "temporária, comportamento típico de exploits e ferramentas de invasão.",
                "Salve as evidências, reinicie o aparelho e faça nova varredura. Se persistir, "
                "restaure o firmware.", category="sistema"))
    return findings
