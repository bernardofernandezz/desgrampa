"""Orquestra as verificações, mede o progresso, calcula o veredito e salva as evidências."""

import logging
import time

from . import evidence, grouping
from .checks import (
    CATEGORIES,
    SEVERITIES,
    Finding,
    accessibility,
    accounts,
    activity,
    admin,
    certificates,
    certstore,
    device,
    firmware,
    mvt,
    netactivity,
    network,
    notifications,
    packages,
    pcnet,
    processes,
    remote,
    risk,
    settings,
    telephony,
    traces,
)
from .context import ScanContext, SkipCheck

log = logging.getLogger(__name__)

# A ordem importa: network antes de netactivity (links), accounts antes de traces (perfis),
# netactivity/activity/certificates antes de risk, que fica por último.
CHECKS = [packages, accessibility, notifications, admin, remote, device, firmware, certstore,
          network, netactivity, telephony, accounts, processes, certificates, activity, traces,
          mvt, pcnet, settings, risk]

VERDICTS = {
    "critica": ("alto_risco", "Alto risco",
                "Foram encontrados indicadores de spyware ou interceptação ativa. Leia os achados críticos."),
    "alta": ("suspeito", "Suspeito", "Há sinais fortes de monitoramento ou adulteração que precisam ser verificados."),
    "media": ("atencao", "Atenção", "Há configurações ou apps que merecem uma conferida."),
    None: ("ok", "Nenhum sinal encontrado",
           "Nenhum indício de spyware ou interceptação foi encontrado nas verificações realizadas."),
}
IOC_CATEGORIES = ("spyware", "mercenario")   # áreas que dependem das bases de indicadores


def verdict(findings):
    worst = next((s for s in ("critica", "alta", "media") if any(f.severity == s for f in findings)), None)
    code, label, text = VERDICTS[worst]
    return {"code": code, "label": label, "text": text}


def _skip_reason(check, ctx):
    if getattr(check, "FULL_ONLY", False) and not ctx.full:
        return "disponível só na varredura completa"
    available = getattr(check, "available", None)
    return available(ctx) if available else None


def _run_check(check, ctx):
    """Executa uma verificação. Devolve (achados, status). Uma verificação com defeito não derruba a varredura."""
    status = {"name": check.NAME, "category": check.CATEGORY, "status": "ok", "reason": None}
    reason = _skip_reason(check, ctx)
    if reason:
        return [], {**status, "status": "skipped", "reason": reason}
    try:
        findings = check.run(ctx)
    except SkipCheck as e:
        return [], {**status, "status": "skipped", "reason": str(e)}
    except Exception as e:
        log.exception("verificação %s falhou", check.NAME)
        error = f"{type(e).__name__}: {e}"
        failure = Finding("info", f"Verificação “{check.NAME}” não pôde ser concluída", error)
        findings, status = [failure], {**status, "status": "error", "reason": error}
    for f in findings:
        f.check = check.NAME
        f.category = f.category or check.CATEGORY
    return findings, status


def _categories(findings, check_status, iocs_available):
    result = []
    for cid, title, description in CATEGORIES:
        mine = [f for f in findings if f.category == cid]
        checks = [c for c in check_status if c["category"] == cid]
        worst = next((s for s in ("critica", "alta", "media", "baixa") if any(f.severity == s for f in mine)), None)
        ran = any(c["status"] == "ok" for c in checks)
        status = worst or ("ok" if ran or not checks else "nao_verificado")
        if cid in IOC_CATEGORIES and not iocs_available and status in ("ok", "baixa"):
            status = "nao_verificado"   # sem bases, "nada encontrado" seria enganoso
        result.append({
            "id": cid, "title": title, "description": description, "status": status,
            "counts": {s: sum(f.severity == s for f in mine) for s in SEVERITIES},
            "checks": checks,
        })
    return result


def _device_summary(ctx):
    p = ctx.props
    return {
        "serial": ctx.device.serial,
        "manufacturer": p.get("ro.product.manufacturer"),
        "model": p.get("ro.product.model"),
        "android": p.get("ro.build.version.release"),
        "sdk": ctx.sdk,
        "security_patch": p.get("ro.build.version.security_patch"),
        "build": p.get("ro.build.display.id"),
        "fingerprint": p.get("ro.build.fingerprint"),
    }


def run_scan(device, iocs, mode="rapida", on_progress=None, options=None, save_evidence=True):
    """Executa a varredura e devolve o resultado (dict). on_progress(fração, texto) acompanha o andamento."""
    report_progress = on_progress or (lambda _fraction, _step: None)
    current = {"check": 0}

    def progress(step):
        report_progress(current["check"] / (len(CHECKS) + 1), step)

    started = time.time()
    ctx = ScanContext(device, iocs, mode, progress, options)
    if save_evidence:
        ctx.evidence_dir = evidence.new_dir(device.serial, started)

    progress("Lendo informações do aparelho")
    _ = ctx.props, ctx.packages   # coleta inicial (a parte mais demorada da varredura rápida)

    findings, check_status = [], []
    for i, check in enumerate(CHECKS, 1):
        current["check"] = i
        progress(check.NAME)
        found, status = _run_check(check, ctx)
        findings += found
        check_status.append(status)

    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.title))
    if not iocs.total_count:
        ctx.notes.insert(0, "Bases de indicadores ausentes: apps, certificados, domínios e IPs NÃO foram "
                            "comparados com spyware conhecido. Atualize as bases e repita a varredura.")
    categories = _categories(findings, check_status, iocs_available=bool(iocs.total_count))
    third = ctx.third_party()
    result = {
        "mode": mode,
        "options": ctx.options,
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_s": round(time.time() - started, 1),
        "device": _device_summary(ctx),
        "stats": {
            "packages": len(ctx.packages),
            "third_party": len(third),
            "sideloaded": sum(p.sideloaded for p in third),
            "checks_run": sum(c["status"] == "ok" for c in check_status),
            "checks_total": len(check_status),
            "categories_verified": sum(c["status"] != "nao_verificado" for c in categories),
            "categories_total": len(categories),
            "commands": len(ctx.raw),
        },
        "iocs": iocs.summary(),
        "verdict": verdict(findings),
        "counts": {s: sum(f.severity == s for f in findings) for s in SEVERITIES},
        "categories": categories,
        "findings": [f.to_dict() for f in findings],
        "apps": ctx.app_rows,
        "data": ctx.data,
        "notes": ctx.notes,
        "evidence_dir": str(ctx.evidence_dir) if ctx.evidence_dir else None,
        "report_name": ctx.evidence_dir.name if ctx.evidence_dir else None,
    }
    grouping.enrich(result)
    if ctx.evidence_dir:
        evidence.save(ctx.evidence_dir, result, ctx.raw)
    return result
