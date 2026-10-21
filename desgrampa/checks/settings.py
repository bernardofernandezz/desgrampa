"""Proteções desligadas: Play Protect, instalação de fontes desconhecidas, patch de segurança."""

from datetime import date

from . import Finding, app_label

NAME = "Proteções do sistema"
CATEGORY = "protecoes"


def run(ctx):
    findings = []

    patch = ctx.props.get("ro.build.version.security_patch")
    if patch:
        try:
            age = (date.today() - date.fromisoformat(patch)).days
        except ValueError:
            age = None
        if age is not None and age > 365:
            findings.append(Finding(
                "alta" if age > 730 else "media",
                "Atualização de segurança desatualizada",
                f"Último patch de segurança: {patch} (há {age // 30} meses). Aparelhos sem "
                "atualização são vulneráveis a spywares que exploram falhas conhecidas — é assim "
                "que spyware mercenário costuma entrar sem nenhum clique.",
                "Instale as atualizações em Configurações > Sistema > Atualização. Se o fabricante "
                "não atualiza mais, considere trocar de aparelho."))

    if ctx.setting("global", "package_verifier_enable") == "0" or \
            ctx.setting("global", "package_verifier_user_consent") == "-1":
        findings.append(Finding(
            "alta", "Google Play Protect desativado",
            "A verificação de apps do Play Protect está desligada. Instaladores de stalkerware "
            "pedem para desativá-la antes da instalação.",
            "Reative em Play Store > Perfil > Play Protect > Configurações."))

    installers = sorted(p.name for p in ctx.third_party() if "REQUEST_INSTALL_PACKAGES" in p.appops)
    if installers:
        findings.append(Finding(
            "media", "Apps autorizados a instalar outros apps",
            "Podem instalar apps de fontes desconhecidas: "
            + ", ".join(app_label(ctx, p) for p in installers) + ".",
            "Revogue o que não for necessário em Configurações > Apps > Acesso especial > "
            "Instalar apps desconhecidos."))

    if ctx.setting("global", "install_non_market_apps") == "1" and ctx.sdk < 26:
        findings.append(Finding(
            "media", "Fontes desconhecidas permitidas",
            "O aparelho permite instalar apps de fora da loja oficial.",
            "Desative em Configurações > Segurança > Fontes desconhecidas."))

    if ctx.setting("global", "development_settings_enabled") == "1":
        findings.append(Finding(
            "info", "Opções do desenvolvedor ligadas",
            "Necessário para esta varredura. Mas, deixadas ligadas, facilitam que alguém com o "
            "aparelho na mão instale ou configure ferramentas de monitoramento via cabo.",
            "Depois da varredura, desligue a Depuração USB e as Opções do desenvolvedor."))
    return findings
