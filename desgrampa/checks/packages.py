"""Aplicativos instalados: bases de spyware conhecido, nomes suspeitos e imitação de apps do sistema."""

import re

from . import SAFETY_TIP, Finding, app_label, ioc_category, spy_signals

NAME = "Apps de espionagem conhecidos"
CATEGORY = "spyware"

SUSPICIOUS_WORDS = re.compile(
    r"spy|espia|stalk|keylog|snoop|stealth|track(?:er|ing)|monitor|cheat|spouse|"
    r"hidden|hide(?:app)?|secret|sms.?forward|call.?record|parental",
    re.I)
SYSTEM_PREFIXES = ("com.android.", "android.", "com.google.android.", "com.samsung.android.",
                   "com.sec.android.", "com.miui.", "com.huawei.", "com.motorola.")
DISGUISE_WORDS = re.compile(
    r"system.?(service|update|sync|core|manager)|sys.?update|wifi.?service|"
    r"update.?service|sync.?service|device.?health|battery.?service|google.?service", re.I)


def visible_monitoring_app(ctx, pkg, match):
    """App de monitoramento comercial que está à vista (loja oficial, com ícone, sem acessos de
    espionagem ativos) — ex.: Life360. É monitoramento real, mas pode ter sido instalado por você."""
    app = ctx.packages.get(pkg)
    return (not match.mercenary and app is not None and app.third_party and not app.sideloaded
            and app.has_launcher is not False and not any(
                s for s in spy_signals(ctx, pkg) if not s.startswith("permissões")))


def sold_in_brazil_note(ctx, match):
    sites = getattr(ctx.iocs, "sold_in_brazil", {}).get(match.family)
    if not sites:
        return ""
    return (f" É vendido no Brasil ({', '.join(sites[:3])}): vender ou distribuir programa feito para invadir "
            "aparelhos também é crime (Código Penal, art. 154-A, § 1º).")


def ioc_finding(ctx, pkg, match, where=""):
    if visible_monitoring_app(ctx, pkg, match):
        return Finding(
            "alta", f"App de monitoramento conhecido: {match.family}",
            f"{app_label(ctx, pkg)}{where} consta na base de stalkerware ({match}). Está visível e veio "
            "da loja oficial, então pode ter sido instalado por você — mas ele compartilha dados (como "
            "localização) com outras pessoas.",
            "Abra o app e confira com quem ele compartilha seus dados. Se você não o instalou ou não "
            "reconhece as pessoas, considere que está sendo monitorado.",
            package=pkg, category="spyware", family=match.family)
    kind = "Spyware mercenário" if match.mercenary else "Stalkerware conhecido"
    return Finding(
        "critica", f"{kind}: {match.family}",
        f"O pacote {app_label(ctx, pkg)}{where} consta na base de indicadores ({match}). "
        + ("Esse tipo de spyware é usado em ataques direcionados e tem acesso amplo ao aparelho."
           if match.mercenary else
           "Esse tipo de app costuma ler mensagens, localização, chamadas e enviar para outra pessoa.")
        + sold_in_brazil_note(ctx, match),
        SAFETY_TIP + (" Para spyware mercenário, NÃO apague nada: procure a Access Now Helpline ou o "
                      "Amnesty Security Lab para análise forense." if match.mercenary else
                      " Para remover: Configurações > Apps (retire antes a permissão de administrador, se houver)."),
        package=pkg, category=ioc_category(match), family=match.family)


def run(ctx):
    findings = []
    for pkg, info in sorted(ctx.packages.items()):
        match = ctx.iocs.match_package(pkg)
        if match:
            findings.append(ioc_finding(ctx, pkg, match))
            continue
        if not info.third_party:
            continue
        if pkg.startswith(SYSTEM_PREFIXES) and info.manual_install:
            signals = spy_signals(ctx, pkg)
            findings.append(Finding(
                "alta" if signals else "media", "App com nome de sistema instalado manualmente",
                f"{app_label(ctx, pkg)} usa um nome de pacote do Google/fabricante, mas veio de um arquivo "
                "APK. Spywares usam esse truque para parecer legítimos; também acontece com apps "
                "baixados de sites de APK." + (f" Sinais: {', '.join(signals)}." if signals else ""),
                "Se você não baixou esse APK de propósito, desinstale. Prefira instalar pela Play Store.",
                package=pkg))
        elif DISGUISE_WORDS.search(pkg):
            findings.append(Finding(
                "alta" if info.sideloaded else "media", "Nome de app disfarçado",
                f"{app_label(ctx, pkg)} tem nome que imita um serviço do sistema "
                "(ex.: “System Service”, “Sync”, “Update”). Stalkerwares costumam se disfarçar assim.",
                "Confirme se o app é seu. Apps do sistema de verdade não são instalados como apps de usuário.",
                package=pkg))
        elif SUSPICIOUS_WORDS.search(pkg):
            findings.append(Finding(
                "media" if info.sideloaded else "baixa", "App de monitoramento/rastreamento",
                f"{app_label(ctx, pkg)} tem nome associado a monitoramento, rastreamento ou "
                "controle parental.",
                "Se você não instalou ou não sabe para que serve, investigue o app.",
                package=pkg))
    return findings
