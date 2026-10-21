"""Serviços de acessibilidade ativos: o principal meio usado por stalkerware para ler a tela e as mensagens."""

from . import KNOWN_BENIGN, Finding, app_label

NAME = "Serviços de acessibilidade"
CATEGORY = "apps"


def run(ctx):
    findings = []
    for pkg, comp in ctx.accessibility:
        info = ctx.packages.get(pkg)
        if info is None or not info.third_party or pkg in KNOWN_BENIGN:
            findings.append(Finding(
                "info", "Serviço de acessibilidade ativo",
                f"{comp} — {app_label(ctx, pkg)}. App do sistema ou conhecido.",
                package=pkg))
            continue
        findings.append(Finding(
            "alta" if info.sideloaded or info.has_launcher is False else "media",
            "App com acesso de acessibilidade",
            f"{app_label(ctx, pkg)} pode ver tudo o que aparece na tela, ler mensagens e "
            f"registrar o que você digita (serviço {comp}).",
            "Se não reconhece, desative em Configurações > Acessibilidade > Apps instalados.",
            package=pkg))
    return findings
