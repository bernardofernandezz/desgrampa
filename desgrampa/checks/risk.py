"""Pontuação de risco por aplicativo, combinando todos os sinais coletados.

Roda por último para aproveitar o resultado das outras verificações.
"""

from datetime import datetime, timedelta

from .. import explain
from . import (
    KNOWN_BENIGN,
    PRIVILEGED_PERMISSIONS,
    RISKY_APPOPS,
    RISKY_PERMISSIONS,
    Finding,
    app_label,
)
from .netactivity import BG_UPLOAD_ALERT

NAME = "Perfil de risco dos aplicativos"
CATEGORY = "apps"

HIGH_SCORE, MEDIUM_SCORE, LOW_SCORE = 12, 8, 5   # limites para alta / média / baixa (baixa só na completa)
RECENT_INSTALL_DAYS = 30


def _installed_recently(timestamp):
    try:
        installed = datetime.fromisoformat(timestamp[:19])
    except (TypeError, ValueError):
        return False
    return installed >= datetime.now() - timedelta(days=RECENT_INSTALL_DAYS)


def _background_upload(ctx, pkg):
    rows = ctx.data.get("rede", {}).get("data_usage", [])
    return next((r["bg_tx"] for r in rows if r["package"] == pkg), 0)


def score_app(ctx, app):
    """Soma os sinais de risco do app. Devolve (pontuação, motivos positivos)."""
    policy = ctx.device_policy
    privileged = [desc for perm, desc in PRIVILEGED_PERMISSIONS.items() if perm in app.granted]
    upload = _background_upload(ctx, app.name)

    # (o sinal está presente?, pontos, descrição)
    signals = [
        (ctx.iocs.match_package(app.name), 20, "consta na base de stalkerware"),
        (app.name in ctx.accessibility_packages, 4, "serviço de acessibilidade ativo"),
        (app.name in ctx.listener_packages, 3, "lê notificações"),
        (app.name in policy["admins"], 3, "administrador do dispositivo"),
        (app.name == policy["device_owner"], 5, "controla o aparelho (Device Owner)"),
        *((perm in app.granted, pts, desc) for perm, (pts, desc) in RISKY_PERMISSIONS.items()),
        *((op in app.appops, pts, desc) for op, (pts, desc) in RISKY_APPOPS.items()),
        (privileged, 4, "permissão privilegiada: " + ", ".join(privileged[:3])),
        (upload >= BG_UPLOAD_ALERT, 2, f"enviou {upload // 1024 // 1024} MB em segundo plano"),
        ("android.permission.RECEIVE_BOOT_COMPLETED" in app.requested, 1, "inicia junto com o aparelho"),
        (app.battery_whitelisted, 1, "isento da economia de bateria"),
        (app.has_launcher is False, 3, "sem ícone na tela de apps"),
        (app.sideloaded, 2, "instalado fora da loja oficial"),
        (_installed_recently(app.first_install), 1, f"instalado nos últimos {RECENT_INSTALL_DAYS} dias"),
        (app.name in ctx.sensor_usage, 1, "usou sensores recentemente"),
        (app.name in KNOWN_BENIGN, -4, "app popular conhecido"),
    ]
    present = [(points, desc) for active, points, desc in signals if active]
    return sum(points for points, _ in present), [desc for points, desc in present if points > 0]


def _signals(ctx, app):
    """Sinais que viram capacidades em linguagem simples (explain.SIGNAL_CAPS)."""
    policy = ctx.device_policy
    flags = {"accessibility": app.name in ctx.accessibility_packages, "listener": app.name in ctx.listener_packages,
             "admin": app.name in policy["admins"], "owner": app.name == policy["device_owner"],
             "hidden": app.has_launcher is False,
             "boot": "android.permission.RECEIVE_BOOT_COMPLETED" in app.requested}
    return [k for k, on in flags.items() if on]


def _severity(ctx, score):
    if score >= HIGH_SCORE:
        return "alta"
    if score >= MEDIUM_SCORE:
        return "media"
    if score >= LOW_SCORE and ctx.full:
        return "baixa"
    return None


def run(ctx):
    findings = []
    for app in ctx.third_party():
        score, reasons = score_app(ctx, app)
        apk = ctx.apk_info.get(app.name, {})
        ctx.app_rows.append({
            "package": app.name, "score": score, "reasons": reasons,
            "installer": app.installer, "sideloaded": app.sideloaded,
            "has_launcher": app.has_launcher, "first_install": app.first_install, "version": app.version,
            "sha256": apk.get("sha256"), "certificates": apk.get("certificates", []),
            "can_do": explain.capabilities(app, _signals(ctx, app)),
        })
        severity = _severity(ctx, score)
        if severity and not ctx.iocs.match_package(app.name):   # stalkerware conhecido já foi reportado
            findings.append(Finding(
                severity, "App com combinação perigosa de acessos",
                f"{app_label(ctx, app.name)} — pontuação {score}: " + ", ".join(reasons) + ".",
                "Confirme se você reconhece e usa este app. Se não, revogue as permissões e desinstale.",
                package=app.name))
    ctx.app_rows.sort(key=lambda r: -r["score"])
    return findings
