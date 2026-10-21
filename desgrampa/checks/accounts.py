"""Contas cadastradas e perfis/usuários adicionais (onde apps podem ficar escondidos)."""

import re

from ..context import parse_components, parse_package_names
from . import Finding, app_label
from .packages import ioc_finding

NAME = "Contas e perfis"
CATEGORY = "contas"

PROFILE_KINDS = {"150": "Pasta Segura (Samsung)", "95": "Apps duplicados", "999": "Apps duplos (Xiaomi)"}


def parse_accounts(out):
    """`dumpsys account` -> ([{user, name, type}], {type: pacote autenticador})"""
    accounts, authenticators = [], {}
    user = 0
    for line in out.splitlines():
        um = re.match(r"^User UserInfo\{(\d+):", line)
        if um:
            user = int(um.group(1))
        am = re.search(r"Account \{name=(.*?), type=([\w.\-]+)\}", line)
        if am and "Accounts:" not in line:
            entry = {"user": user, "name": am.group(1), "type": am.group(2)}
            if entry not in accounts:
                accounts.append(entry)
        sm = re.search(r"AuthenticatorDescription \{type=([\w.\-]+)\}, ComponentInfo\{([\w.]+)/", line)
        if sm:
            authenticators[sm.group(1)] = sm.group(2)
    return accounts, authenticators


def run(ctx):
    findings = []
    accounts, auths = parse_accounts(ctx.try_sh("dumpsys account", timeout=60))
    for a in accounts:
        a["app"] = auths.get(a["type"])

    google = [a for a in accounts if a["type"] == "com.google"]
    if len(google) > 1:
        findings.append(Finding(
            "media", "Mais de uma conta Google no aparelho",
            "Contas: " + ", ".join(a["name"] for a in google) + ". Uma conta de outra pessoa no seu "
            "celular pode receber backup de fotos, contatos, localização e histórico.",
            "Confirme que todas são suas. Remova as que não forem em Configurações > Contas."))

    for a in accounts:
        match = ctx.iocs.match_email(a["name"])
        if match:
            findings.append(Finding(
                "critica", f"Conta ligada a spyware: {match.family}",
                f"A conta {a['name']} ({a['type']}) aparece nos indicadores de {match}.",
                "Não apague nada. Procure análise forense especializada.",
                category="mercenario" if match.mercenary else "spyware"))
        app = ctx.packages.get(a["app"]) if a["app"] else None
        if app and app.third_party and (app.sideloaded or app.has_launcher is False):
            findings.append(Finding(
                "alta", "Conta criada por app suspeito",
                f"{app_label(ctx, app.name)} registrou uma conta no sistema ({a['name']}, tipo "
                f"{a['type']}). Spywares usam contas para sincronizar dados em segundo plano.",
                "Remova a conta em Configurações > Contas e investigue o app.", package=app.name))

    users = ctx.users
    extra_users = []
    for u in users:
        if u["id"] == 0:
            continue
        kind = PROFILE_KINDS.get(str(u["id"])) or (u["name"] or "Perfil")
        pkgs = parse_package_names(ctx.try_sh(f"pm list packages -3 --user {u['id']}"))
        extra_only = sorted(pkgs - {p.name for p in ctx.third_party()})
        a11y = parse_components(ctx.setting("secure", "enabled_accessibility_services", user=u["id"]))
        extra_users.append({**u, "kind": kind, "apps": sorted(pkgs), "only_here": extra_only,
                            "accessibility": [c for _, c in a11y]})
        for pkg in pkgs:
            match = ctx.iocs.match_package(pkg)
            if match:
                findings.append(ioc_finding(ctx, pkg, match, where=f" no perfil “{kind}” (usuário {u['id']})"))
        findings.append(Finding(
            "media" if extra_only or a11y else "info", f"Perfil adicional: {kind}",
            f"Existe o usuário/perfil {u['id']} (“{u['name']}”) com {len(pkgs)} app(s) de terceiros"
            + (f"; {len(extra_only)} existem só nele: {', '.join(extra_only[:8])}" if extra_only else "")
            + (f"; acessibilidade ativa: {', '.join(c for _, c in a11y)}" if a11y else "")
            + ". Apps em outro perfil não aparecem na sua lista de apps normal.",
            "Confirme que você criou esse perfil. Se não, remova em Configurações > Sistema > Vários usuários."))

    ctx.data["contas"] = {"accounts": accounts, "users": [{k: u[k] for k in ("id", "name", "running")}
                                                         for u in users], "extra_users": extra_users}
    return findings
