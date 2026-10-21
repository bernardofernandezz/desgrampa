"""Administradores do dispositivo e gerenciamento (MDM / device owner)."""

from . import Finding, app_label

NAME = "Administradores e gerenciamento (MDM)"
CATEGORY = "controle"


def run(ctx):
    findings = []
    dp = ctx.device_policy

    if dp["device_owner"]:
        findings.append(Finding(
            "alta", "Aparelho gerenciado por terceiro (Device Owner)",
            f"{app_label(ctx, dp['device_owner'])} controla o aparelho como proprietário "
            "(MDM). Ele pode instalar apps, ver localização e aplicar políticas.",
            "Normal apenas em aparelhos corporativos. Se o aparelho é pessoal, isso é muito suspeito.",
            package=dp["device_owner"]))
    for pkg in dp["profile_owners"]:
        findings.append(Finding(
            "media", "Perfil gerenciado (Profile Owner)",
            f"{app_label(ctx, pkg)} gerencia um perfil de trabalho neste aparelho.",
            "Normal se você usa perfil de trabalho da empresa.", package=pkg))

    for pkg in dp["admins"]:
        info = ctx.packages.get(pkg)
        if info is None or not info.third_party:
            findings.append(Finding(
                "info", "Administrador do dispositivo (sistema)", app_label(ctx, pkg), package=pkg))
            continue
        findings.append(Finding(
            "alta" if info.sideloaded else "media", "App com privilégio de administrador",
            f"{app_label(ctx, pkg)} é administrador do dispositivo: pode bloquear a tela, "
            "apagar dados e impedir a própria desinstalação — tática comum de stalkerware.",
            "Se não reconhece, remova em Configurações > Segurança > Apps de administração "
            "do dispositivo, e depois desinstale.",
            package=pkg))
    return findings
