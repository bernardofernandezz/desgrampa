"""Pontuação de risco por aplicativo, combinando todos os sinais coletados.

Roda por último para aproveitar o resultado das outras verificações.
"""

from datetime import datetime, timedelta

from . import (
    KNOWN_BENIGN,
    PRIVILEGED_PERMISSIONS,
    RISKY_APPOPS,
    RISKY_PERMISSIONS,
    Finding,
    app_label,
)

NAME = "Perfil de risco dos aplicativos"
CATEGORY = "apps"


def _recent(ts, days=30):
    try:
        return datetime.fromisoformat(ts[:19]) >= datetime.now() - timedelta(days=days)
    except (TypeError, ValueError):
        return False


def score_app(ctx, app):
    reasons = []

    def add(points, text):
        reasons.append((points, text))

    if ctx.iocs.match_package(app.name):
        add(20, "consta na base de stalkerware")
    a11y = {p for p, _ in ctx.accessibility}
    nls = {p for p, _ in ctx.notification_listeners}
    dp = ctx.device_policy
    if app.name in a11y:
        add(4, "serviço de acessibilidade ativo")
    if app.name in nls:
        add(3, "lê notificações")
    if app.name in dp["admins"]:
        add(3, "administrador do dispositivo")
    if app.name == dp["device_owner"]:
        add(5, "controla o aparelho (Device Owner)")
    for perm, (pts, text) in RISKY_PERMISSIONS.items():
        if perm in app.granted:
            add(pts, text)
    for op, (pts, text) in RISKY_APPOPS.items():
        if op in app.appops:
            add(pts, text)
    privileged = [d for p, d in PRIVILEGED_PERMISSIONS.items() if p in app.granted]
    if privileged:
        add(4, "permissão privilegiada: " + ", ".join(privileged[:3]))
    bg = next((r for r in ctx.data.get("rede", {}).get("data_usage", []) if r["package"] == app.name), None)
    if bg and bg["bg_tx"] >= 100 * 1024 * 1024:
        add(2, f"enviou {bg['bg_tx'] // 1024 // 1024} MB em segundo plano")
    if "android.permission.RECEIVE_BOOT_COMPLETED" in app.requested:
        add(1, "inicia junto com o aparelho")
    if app.battery_whitelisted:
        add(1, "isento da economia de bateria")
    if app.has_launcher is False:
        add(3, "sem ícone na tela de apps")
    if app.sideloaded:
        add(2, "instalado fora da loja oficial")
    if _recent(app.first_install):
        add(1, "instalado nos últimos 30 dias")
    if app.name in ctx._cache.get("activity", {}):
        add(1, "usou sensores recentemente")
    if app.name in KNOWN_BENIGN:
        add(-4, "app popular conhecido")
    return sum(p for p, _ in reasons), [t for p, t in reasons if p > 0]


def run(ctx):
    findings = []
    rows = []
    for app in ctx.third_party():
        score, reasons = score_app(ctx, app)
        apk = ctx._cache.get("apk_info", {}).get(app.name, {})
        rows.append({
            "package": app.name, "score": score, "reasons": reasons,
            "installer": app.installer, "sideloaded": app.sideloaded,
            "has_launcher": app.has_launcher, "first_install": app.first_install,
            "sha256": apk.get("sha256"), "certificates": apk.get("certificates", []),
        })
        if ctx.iocs.match_package(app.name):
            continue  # já reportado como crítico
        severity = "alta" if score >= 12 else "media" if score >= 8 else \
            "baixa" if score >= 5 and ctx.full else None
        if severity:
            findings.append(Finding(
                severity, "App com combinação perigosa de acessos",
                f"{app_label(ctx, app.name)} — pontuação {score}: " + ", ".join(reasons) + ".",
                "Confirme se você reconhece e usa este app. Se não, revogue as permissões e "
                "desinstale.",
                package=app.name))
    rows.sort(key=lambda r: -r["score"])
    ctx._cache["app_rows"] = rows
    return findings
