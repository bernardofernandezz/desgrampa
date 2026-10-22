"""Vulnerabilidades conhecidas: falhas dos boletins de segurança do Android ainda sem correção no
aparelho (pelo patch de segurança), versão do Android sem suporte, Chrome/WebView e apps de mensagem
desatualizados, e um índice de exposição que resume a superfície de ataque.

Não depende de root nem de nada além de getprop/dumpsys: compara versões com a base gerada por
tools/build_bulletins.py (Android Security Bulletins + CISA KEV)."""

import re
from datetime import date

from .. import bulletins
from . import Finding

NAME = "Vulnerabilidades conhecidas"
CATEGORY = "vulns"

STALE_DB_DAYS = 75          # base mais velha que isso: avisa para atualizar
MAX_ITEMS = 2000            # falhas listadas no relatório (aparelhos muito antigos têm milhares)
CHROMIUM_PACKAGES = {"com.google.android.webview": "Android System WebView", "com.android.chrome": "Chrome",
                     "com.google.android.trichromelibrary": "Trichrome (base do Chrome/WebView)"}
QUALCOMM_PLATFORMS = re.compile(r"^(msm|sdm|sm\d|qcs|apq|lahaina|kona|lito|bengal|holi|taro|kalama|pineapple|sun|"
                                r"parrot|crow|blair|cliffs|trinket|atoll|khaje|monaco|volcano|niobe|canoe)", re.I)
EXPOSURE_LEVELS = [(75, "critico", "Crítica"), (50, "alto", "Alta"), (25, "moderado", "Moderada"), (0, "baixo", "Baixa")]


def available(ctx):
    if not _db(ctx):
        return "base de vulnerabilidades ausente (Configurações › Atualizar bases)"
    if not ctx.props.get("ro.build.version.security_patch"):
        return "o aparelho não informa o patch de segurança"
    return None


def _db(ctx):
    if ctx.bulletins is None:
        ctx.bulletins = bulletins.load() or {}
    return ctx.bulletins


# ---------------------------------------------------------------- comparação

def is_qualcomm(props):
    maker = (props.get("ro.soc.manufacturer") or "").lower()
    return "qti" in maker or "qualcomm" in maker or props.get("ro.hardware") == "qcom" \
        or bool(QUALCOMM_PLATFORMS.match(props.get("ro.board.platform") or ""))


def android_major(props):
    m = re.match(r"\d+", props.get("ro.build.version.release") or "")
    return m.group() if m else None


def unpatched(db, major, spl, pixel=False, qualcomm=False):
    """Falhas corrigidas depois do patch do aparelho que se aplicam a ele: (confirmadas, prováveis).

    “Prováveis” são falhas do Android corrigidas só em versões mais novas que a do aparelho: o boletim
    já não lista versões sem suporte, mas o código vulnerável quase sempre existe nelas também."""
    supported = set(db.get("android_supported", []))
    eol = major not in supported
    oldest_supported = min((int(v) for v in supported), default=0)
    confirmed, likely = [], []
    for row in db["vulns"]:
        _, fixed_spl, _, scope, versions, *_ = row
        if fixed_spl <= spl:
            continue
        if scope == "aosp":
            if major in versions:
                confirmed.append(row)
            elif eol and major and int(major) < oldest_supported and versions and int(major) < int(versions[0]):
                likely.append(row)
        elif scope == "kernel" or (scope == "qcom" and qualcomm) or (scope == "pixel" and pixel):
            confirmed.append(row)
    return confirmed, likely


def version_tuple(version):
    return tuple(int(x) for x in re.findall(r"\d+", version or "")[:4])


def chromium_status(db, packages):
    """Chrome/WebView instalados vs. versão estável atual e falhas do Chromium exploradas desde então."""
    chrome = db.get("chrome") or {}
    stable = chrome.get("stable_major")
    first_stable = chrome.get("first_stable", {})
    rows = []
    for pkg, label in CHROMIUM_PACKAGES.items():
        info = packages.get(pkg)
        if not info or not info.version or not stable:
            continue
        parts = version_tuple(info.version)
        if not parts:
            continue
        installed = str(parts[0])
        behind = int(stable) - int(installed)
        # falhas exploradas que entraram no KEV depois que saiu a versão seguinte à instalada
        newer = first_stable.get(str(int(installed) + 1))
        if newer is None and behind > 0:
            newer = min(first_stable.values(), default=None)   # versão anterior ao histórico guardado
        exploited = [k for k in db.get("kev_chromium", []) if newer and k["added"] >= newer] if behind > 0 else []
        rows.append({"package": pkg, "name": label, "version": info.version, "major": installed, "stable": stable,
                     "behind": behind, "exploited": [k["cve"] for k in exploited]})
    return rows


def outdated_apps(db, packages):
    rows = []
    for app in db.get("apps", []):
        info = packages.get(app["package"])
        if info and info.version and version_tuple(info.version) < version_tuple(app["fixed"]):
            rows.append({**app, "version": info.version})
    return rows


def exposure(factors):
    """Índice 0–100 a partir dos fatores [{label, points, active}]."""
    score = min(100, sum(f["points"] for f in factors if f["active"]))
    code, label = next((c, lab) for floor, c, lab in EXPOSURE_LEVELS if score >= floor)
    return {"score": score, "level": code, "label": label, "factors": factors}


def _patch_age_days(spl):
    try:
        return (date.today() - date.fromisoformat(spl)).days
    except ValueError:
        return None


def _exposure_factors(ctx, spl, eol, kev_count, chromium, apps):
    p = ctx.props
    age = _patch_age_days(spl)
    third = ctx.third_party()
    return [
        {"label": f"Patch de segurança com {age // 30} meses" if age is not None else "Patch de segurança desconhecido",
         "points": 0 if age is None else 30 if age > 365 else 20 if age > 180 else 10 if age > 90 else 0,
         "active": age is None or age > 90},
        {"label": "Versão do Android sem atualizações do Google", "points": 20, "active": eol},
        {"label": "Falhas exploradas ativamente sem correção", "points": 20, "active": kev_count > 0},
        {"label": "Chrome/WebView desatualizado", "points": 10, "active": any(c["behind"] >= 2 for c in chromium)},
        {"label": "App de mensagem com falha explorada por spyware", "points": 15, "active": bool(apps)},
        {"label": "Bootloader desbloqueado", "points": 10,
         "active": p.get("ro.boot.flash.locked") == "0" or p.get("ro.boot.verifiedbootstate") in ("orange", "yellow")},
        {"label": "Criptografia do armazenamento desligada", "points": 10,
         "active": p.get("ro.crypto.state") == "unencrypted"},
        {"label": "Play Protect desativado", "points": 10,
         "active": ctx.setting("global", "package_verifier_enable") == "0"},
        {"label": "Apps autorizados a instalar outros apps", "points": 5,
         "active": any("REQUEST_INSTALL_PACKAGES" in a.appops for a in third)},
        {"label": "Apps instalados fora das lojas oficiais", "points": 5, "active": any(a.sideloaded for a in third)},
    ]


# ---------------------------------------------------------------- verificação

def _join(items):
    return " e ".join([", ".join(items[:-1]), items[-1]]) if len(items) > 1 else "".join(items)


def _cve_list(rows, limit=8):
    names = [f"{r[0]} ({r[5]})" for r in rows[:limit]]
    return ", ".join(names) + (f" e mais {len(rows) - limit}" if len(rows) > limit else "")


def run(ctx):
    db = _db(ctx)
    p = ctx.props
    spl = p["ro.build.version.security_patch"]
    major = android_major(p)
    pixel = (p.get("ro.product.manufacturer") or "").lower() == "google"
    qualcomm = is_qualcomm(p)
    supported = db.get("android_supported", [])
    eol = bool(supported) and major not in supported

    confirmed, likely = unpatched(db, major, spl, pixel, qualcomm)
    kev = [r for r in confirmed if r[7]]
    counts = {s: sum(r[2] == s for r in confirmed) for s in "CHML"}
    chromium = chromium_status(db, ctx.packages)
    apps = outdated_apps(db, ctx.packages)

    findings = []
    update_tip = ("Instale todas as atualizações em Configurações › Sistema › Atualização de software e "
                  "atualize os apps pela Play Store. Se não houver atualização, o aparelho não recebe mais "
                  "correções do fabricante: considere trocá-lo ou usar um sistema alternativo com suporte.")
    if kev:
        findings.append(Finding(
            "alta", f"{len(kev)} falha(s) explorada(s) ativamente sem correção neste aparelho",
            f"Com o patch de segurança de {spl}, o aparelho ainda tem falhas que a CISA (agência de "
            f"cibersegurança dos EUA) confirma estarem sendo usadas em ataques reais: {_cve_list(kev)}. "
            "Spyware mercenário costuma explorar exatamente esse tipo de falha.", update_tip))
    if counts["C"]:
        findings.append(Finding(
            "media", f"{counts['C']} falha(s) crítica(s) conhecida(s) sem correção",
            f"Além de {counts['H']} de gravidade alta. Falhas críticas podem permitir que alguém execute "
            "código no aparelho, às vezes só com uma mensagem ou um arquivo de mídia.", update_tip))
    elif counts["H"]:
        findings.append(Finding(
            "baixa", f"{counts['H']} falha(s) de gravidade alta sem correção",
            f"Corrigidas em boletins posteriores ao patch {spl} do aparelho.", update_tip))
    if eol:
        findings.append(Finding(
            "media", f"Android {major} não recebe mais atualizações de segurança",
            f"Os boletins recentes só corrigem o Android {_join(supported)}. "
            + (f"Há ainda {len(likely)} falhas corrigidas só nas versões novas que provavelmente também "
               "afetam este aparelho. " if likely else "")
            + "Cada falha nova descoberta a partir de agora fica aberta para sempre neste sistema.",
            "Troque o aparelho quando possível. Até lá, evite instalar apps fora da Play Store, abrir "
            "links e arquivos de desconhecidos e mantenha os apps atualizados."))
    for c in chromium:
        if c["behind"] < 2:
            continue
        exploited = len(c["exploited"])
        findings.append(Finding(
            "alta" if exploited and c["behind"] >= 3 else "media",
            f"{c['name']} desatualizado ({c['version']})",
            f"A versão estável atual é a {c['stable']}; a instalada está {c['behind']} versões atrás. "
            + (f"Desde então, {exploited} falhas do Chromium entraram na lista de exploradas ativamente "
               f"({', '.join(c['exploited'][:5])}{'…' if exploited > 5 else ''}). " if exploited else "")
            + "O WebView é usado por quase todos os apps para abrir páginas: uma falha nele é porta de entrada "
            "comum de spyware por link.",
            f"Atualize “{c['name']}” na Play Store (busque pelo nome) e confira se as atualizações "
            "automáticas estão ligadas.", package=c["package"]))
    for a in apps:
        findings.append(Finding(
            "alta", f"{a['name']} com falha usada para espionagem ({a['version']})",
            f"{a['cve']}: {a['summary']} Corrigida na versão {a['fixed']}.",
            f"Atualize o {a['name']} pela Play Store agora.", package=a["package"]))

    age = (date.today() - date.fromisoformat(db["generated"])).days
    if age > STALE_DB_DAYS:
        ctx.notes.append(f"A base de vulnerabilidades é de {db['generated']} ({age} dias): atualize as bases "
                         "para incluir os boletins mais recentes.")
    if spl > db["latest_spl"]:
        ctx.notes.append(f"O patch do aparelho ({spl}) é mais novo que a base de vulnerabilidades "
                         f"({db['latest_spl']}): atualize as bases para ver o que ainda falta corrigir.")

    ordered = sorted(confirmed, key=lambda r: (-r[7], "CHML".index(r[2]), r[1]))
    ctx.data["vulns"] = {
        "db": {"generated": db["generated"], "latest_spl": db["latest_spl"], "sources": db.get("sources", {})},
        "device": {"android": major, "spl": spl, "eol": eol, "supported": supported, "pixel": pixel,
                   "qualcomm": qualcomm},
        "counts": {**counts, "kev": len(kev), "total": len(confirmed), "likely": len(likely)},
        "items": [bulletins.as_dict(r) for r in ordered[:MAX_ITEMS]],
        "chromium": chromium,
        "apps": apps,
        "exposure": exposure(_exposure_factors(ctx, spl, eol, len(kev), chromium, apps)),
    }
    return findings
