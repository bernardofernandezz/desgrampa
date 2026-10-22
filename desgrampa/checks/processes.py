"""Processos em execução comparados com as bases de spyware e locais suspeitos."""


from ..context import parse_ps
from . import Finding, ioc_category
from .packages import visible_monitoring_app

NAME = "Processos em execução"
CATEGORY = "spyware"


SYSTEM_BIN_DIRS = "/system/bin /system_ext/bin /vendor/bin /system/bin/hw /vendor/bin/hw /product/bin"


def parse_ls_dirs(out):
    """Saída de `ls dir1 dir2...` -> nomes de arquivo (ignora os cabeçalhos "dir:" e linhas vazias)."""
    return {line.strip() for line in out.splitlines() if line.strip() and not line.rstrip().endswith(":")}


def system_binaries(ctx):
    return ctx._cached("system_bins", lambda: parse_ls_dirs(ctx.try_sh(f"ls {SYSTEM_BIN_DIRS} 2>/dev/null")))


def run(ctx):
    findings = []
    out = ctx.try_sh("ps -A -o USER,PID,NAME")
    procs = parse_ps(out) if "PID" in out else parse_ps(ctx.try_sh("ps"))
    if not procs:
        ctx.notes.append("Não foi possível listar processos")
        return findings

    reported = set()

    def is_system_binary(proc):
        # vários indicadores de processo vêm de ataques a iPhone; nomes como "gatekeeperd" também
        # existem como serviços legítimos do Android. Se o binário está na partição do sistema, ignoramos.
        # Lista as pastas em vez de consultar o arquivo: em vários aparelhos (ex.: Xiaomi) o SELinux nega
        # o stat de /system/bin/<serviço> ao shell, mas permite listar a pasta.
        return proc in system_binaries(ctx)

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
