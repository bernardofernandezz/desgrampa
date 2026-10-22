"""(Varredura completa) Uso recente de microfone, câmera, localização, SMS e chamadas por apps de terceiros."""

from ..context import parse_appops_usage
from . import Finding, app_label

NAME = "Uso recente de recursos sensíveis"
CATEGORY = "apps"
FULL_ONLY = True

WATCHED = {
    "RECORD_AUDIO": "microfone", "CAMERA": "câmera", "FINE_LOCATION": "localização precisa",
    "COARSE_LOCATION": "localização", "READ_SMS": "SMS", "READ_CALL_LOG": "histórico de chamadas",
    "READ_CONTACTS": "contatos", "READ_CLIPBOARD": "área de transferência",
}
WINDOW = 7 * 86400


def _ago(seconds):
    if seconds < 3600:
        return f"{seconds // 60} min"
    if seconds < 86400:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} dia(s)"


def run(ctx):
    findings = []
    apps = sorted(ctx.third_party(), key=lambda p: p.name)
    for i, app in enumerate(apps, 1):
        ctx.progress(f"Verificando uso de sensores {i}/{len(apps)}: {app.name}")
        usage = parse_appops_usage(ctx.try_sh(f"cmd appops get {app.name}"))
        recent = {op: u for op, u in usage.items() if op in WATCHED and u["ago"] <= WINDOW}
        if not recent:
            continue
        ctx.sensor_usage[app.name] = recent
        background = [op for op, u in recent.items() if u["background"]]
        suspicious = app.sideloaded or app.has_launcher is False
        parts = [f"{WATCHED[op]} há {_ago(u['ago'])}" + (" (em segundo plano)" if u["background"] else "")
                 for op, u in sorted(recent.items(), key=lambda kv: kv[1]["ago"])]
        severity = "alta" if suspicious and background else "media" if suspicious or background else "info"
        findings.append(Finding(
            severity, "Uso recente de recursos sensíveis",
            f"{app_label(ctx, app.name)} usou nos últimos 7 dias: " + "; ".join(parts) + ".",
            "Se o app não deveria usar esses recursos, revogue as permissões em Configurações > Apps."
            if severity != "info" else "",
            package=app.name))
    return findings
