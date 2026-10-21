"""Orquestra as verificações, mede o progresso, calcula o veredito e salva as evidências."""

import hashlib
import json
import re
import time
import traceback
from pathlib import Path

from . import grouping, report
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
from .paths import REPORTS_DIR

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


def verdict(findings):
    worst = next((s for s in SEVERITIES[:3] if any(f.severity == s for f in findings)), None)
    code, label, text = VERDICTS[worst]
    return {"code": code, "label": label, "text": text}


def _skip_reason(check, ctx):
    if getattr(check, "FULL_ONLY", False) and not ctx.full:
        return "disponível só na varredura completa"
    fn = getattr(check, "available", None)
    return fn(ctx) if fn else None


def _categories(findings, check_status):
    result = []
    for cid, title, desc in CATEGORIES:
        mine = [f for f in findings if f.category == cid]
        checks = [c for c in check_status if c["category"] == cid]
        ran = [c for c in checks if c["status"] == "ok"]
        worst = next((s for s in SEVERITIES[:4] if any(f.severity == s for f in mine)), None)
        status = worst or ("ok" if ran or not checks else "nao_verificado")
        result.append({
            "id": cid, "title": title, "description": desc, "status": status,
            "counts": {s: sum(f.severity == s for f in mine) for s in SEVERITIES},
            "checks": checks,
        })
    return result


def _save_evidence(ctx, result):
    base = Path(ctx.evidence_dir)
    raw = base / "comandos"
    raw.mkdir(exist_ok=True)
    for i, (cmd, out) in enumerate(ctx.raw.items(), 1):
        slug = re.sub(r"[^\w]+", "_", cmd)[:60].strip("_")
        (raw / f"{i:03d}_{slug}.txt").write_text(f"$ adb shell {cmd}\n\n{out or ''}", encoding="utf-8")
    (base / "relatorio.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    (base / "relatorio.html").write_text(report.render(result), encoding="utf-8")
    sums = []
    for f in sorted(p for p in base.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"):
        h = hashlib.sha256()
        with open(f, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        sums.append(f"{h.hexdigest()}  {f.relative_to(base)}")
    (base / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")


def run_scan(device, iocs, mode="rapida", on_progress=None, options=None, save_evidence=True):
    on_progress = on_progress or (lambda frac, step: None)
    state = {"i": 0}

    def progress(msg):
        on_progress(state["i"] / (len(CHECKS) + 1), msg)

    ctx = ScanContext(device, iocs, mode, progress, options)
    started = time.time()
    if save_evidence:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(started))
        safe_serial = re.sub(r"[^\w.-]", "_", device.serial)
        ctx.evidence_dir = REPORTS_DIR / f"{stamp}_{safe_serial}"
        ctx.evidence_dir.mkdir(parents=True, exist_ok=True)

    progress("Lendo informações do aparelho")
    props = ctx.props
    _ = ctx.packages  # coleta inicial (a parte mais demorada da varredura rápida)

    findings = []
    check_status = []
    for i, check in enumerate(CHECKS, 1):
        state["i"] = i
        status = {"name": check.NAME, "category": check.CATEGORY, "status": "ok", "reason": None}
        check_status.append(status)
        reason = _skip_reason(check, ctx)
        if reason:
            status.update(status="skipped", reason=reason)
            continue
        progress(check.NAME)
        try:
            for f in check.run(ctx):
                f.check = check.NAME
                f.category = f.category or check.CATEGORY
                findings.append(f)
        except SkipCheck as e:
            status.update(status="skipped", reason=str(e))
        except Exception as e:  # uma verificação com defeito não derruba a varredura
            traceback.print_exc()
            status.update(status="error", reason=f"{type(e).__name__}: {e}")
            findings.append(Finding("info", f"Verificação “{check.NAME}” não pôde ser concluída",
                                    f"{type(e).__name__}: {e}", check=check.NAME, category=check.CATEGORY))

    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.title))
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITIES}
    categories = _categories(findings, check_status)
    if not iocs.total_count:
        ctx.notes.insert(0, "Bases de indicadores ausentes: apps, certificados, domínios e IPs NÃO foram "
                            "comparados com spyware conhecido. Atualize as bases e repita a varredura.")
        for c in categories:
            if c["id"] in ("spyware", "mercenario") and c["status"] in ("ok", "baixa"):
                c["status"] = "nao_verificado"
    third = ctx.third_party()
    result = {
        "mode": mode,
        "options": ctx.options,
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_s": round(time.time() - started, 1),
        "device": {
            "serial": device.serial,
            "manufacturer": props.get("ro.product.manufacturer"),
            "model": props.get("ro.product.model"),
            "android": props.get("ro.build.version.release"),
            "sdk": ctx.sdk,
            "security_patch": props.get("ro.build.version.security_patch"),
            "build": props.get("ro.build.display.id"),
            "fingerprint": props.get("ro.build.fingerprint"),
        },
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
        "counts": counts,
        "categories": categories,
        "findings": [f.to_dict() for f in findings],
        "apps": ctx._cache.get("app_rows", []),
        "data": ctx.data,
        "notes": ctx.notes,
        "evidence_dir": str(ctx.evidence_dir) if ctx.evidence_dir else None,
    }
    grouping.enrich(result)
    if ctx.evidence_dir:
        _save_evidence(ctx, result)
    return result
