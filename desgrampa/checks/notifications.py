"""Apps com acesso às notificações (podem ler o conteúdo de mensagens do WhatsApp, SMS, e-mail...)."""

from . import KNOWN_BENIGN, Finding, app_label

NAME = "Acesso às notificações"
CATEGORY = "apps"


# apps legítimos cujo objetivo é espelhar suas notificações em outro aparelho
MIRRORING = {"org.kde.kdeconnect_tp": "KDE Connect", "com.pushbullet.android": "Pushbullet",
             "com.microsoft.appmanager": "Vincular ao Windows", "com.samsung.android.mdx": "Link to Windows",
             "com.join.android": "Join", "net.xdroid.notifmirror": "Notification Mirror"}


def run(ctx):
    findings = []
    seen = set()
    for pkg, comp in ctx.notification_listeners:
        if pkg in seen:
            continue
        seen.add(pkg)
        if pkg in MIRRORING:
            findings.append(Finding(
                "media", f"Notificações espelhadas em outro aparelho: {MIRRORING[pkg]}",
                f"{app_label(ctx, pkg)} envia o conteúdo das suas notificações (mensagens, códigos de "
                "verificação) para os computadores/aparelhos pareados com ele.",
                "Abra o app e confira se TODOS os aparelhos pareados são seus. Remova os desconhecidos.",
                package=pkg))
            continue
        info = ctx.packages.get(pkg)
        if info is None or not info.third_party or pkg in KNOWN_BENIGN:
            findings.append(Finding(
                "info", "Leitor de notificações ativo",
                f"{comp} — {app_label(ctx, pkg)}. App do sistema ou conhecido.", package=pkg))
            continue
        findings.append(Finding(
            "alta" if info.sideloaded or info.has_launcher is False else "media",
            "App lendo suas notificações",
            f"{app_label(ctx, pkg)} recebe o conteúdo de todas as notificações, incluindo "
            "mensagens e códigos de verificação.",
            "Se não reconhece, desative em Configurações > Notificações > Acesso a notificações.",
            package=pkg))
    return findings
