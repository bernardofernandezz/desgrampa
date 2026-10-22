"""Agrupamento dos achados (categoria → origem) e sugestões de remoção.

Trabalha só com o dicionário do relatório, então também se aplica a relatórios salvos por
versões anteriores do app.
"""

import re

from . import explain
from .checks import CATEGORIES, SEVERITIES
from .util import QUOTED_PACKAGE_RE

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
# títulos que trazem a família depois de ":" (relatórios antigos não têm o campo "family")
FAMILY_TITLE = re.compile(r"^(?:Stalkerware conhecido|Spyware mercenário|Spyware disfarçado|Spyware em execução|"
                          r"Assinatura coincide com spyware|App de monitoramento conhecido|Rastro de spyware removido|"
                          r"Conexão ativa com servidor de spyware): (.+)$")
SPYWARE_CATEGORIES = {"spyware", "mercenario"}


def _family(f):
    if f.get("family"):
        return f["family"]
    m = FAMILY_TITLE.match(f.get("title", ""))
    return m.group(1) if m else None


def subject(f):
    """(chave, rótulo, tipo) da origem de um achado: o app, ou a verificação quando não há app."""
    pkg = f.get("package")
    if not pkg:   # relatórios antigos: alertas do MVT citam o pacote só na mensagem
        m = QUOTED_PACKAGE_RE.search(f.get("title", ""))
        pkg = m.group(1) if m else None
    if pkg:
        return f"app:{pkg}", pkg, "app"
    return f"check:{f.get('check') or 'Geral'}", f.get("check") or "Geral", "sistema"


def _summary(findings):
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"]] += 1
    worst = next((s for s in SEVERITIES if counts[s]), "info")
    return counts, worst


def build_groups(findings):
    """Grupos por origem (cada um com as categorias onde aparece) e árvore categoria → origem."""
    by_subject = {}
    for i, f in enumerate(findings):
        key, label, kind = subject(f)
        g = by_subject.setdefault(key, {"key": key, "label": label, "kind": kind,
                                        "package": label if kind == "app" else None,
                                        "family": None, "items": [], "categories": []})
        g["items"].append(i)
        g["family"] = g["family"] or _family(f)
        if f.get("category") and f["category"] not in g["categories"]:
            g["categories"].append(f["category"])
    groups = []
    for g in by_subject.values():
        items = [findings[i] for i in g["items"]]
        g["counts"], g["worst"] = _summary(items)
        g["total"] = len(items)
        if g["kind"] == "app" and g["family"]:
            g["label"] = f"{g['family']} · {g['package']}"
        groups.append(g)
    groups.sort(key=lambda g: (SEV_RANK[g["worst"]], -g["counts"]["critica"], -g["counts"]["alta"], -g["total"], g["label"]))

    tree = []
    for cid, title, _ in CATEGORIES:
        idx = [i for i, f in enumerate(findings) if f.get("category") == cid]
        if not idx:
            continue
        subs = {}
        for i in idx:
            key, _, _ = subject(findings[i])
            subs.setdefault(key, []).append(i)
        children = []
        for key, items in subs.items():
            base = by_subject[key]
            counts, worst = _summary([findings[i] for i in items])
            children.append({"key": key, "label": base["label"], "kind": base["kind"], "package": base["package"],
                             "family": base["family"], "items": items, "counts": counts, "worst": worst,
                             "total": len(items)})
        children.sort(key=lambda c: (SEV_RANK[c["worst"]], -c["total"], c["label"]))
        counts, worst = _summary([findings[i] for i in idx])
        tree.append({"category": cid, "title": title, "counts": counts, "worst": worst, "total": len(idx),
                     "children": children})
    return groups, tree


def _mercenary(items):
    """Spyware mercenário? Relatórios antigos punham todo alerta do MVT em "mercenario", inclusive de stalkerware
    comum (ex.: Life360); se outra verificação já classificou a família como stalkerware, ela prevalece."""
    stalkerware = any(f.get("family") and f.get("category") == "spyware" for f in items)
    return not stalkerware and any(f.get("category") == "mercenario" and f["severity"] in ("critica", "alta")
                                   for f in items)


def removal_candidates(result):
    """Apps instalados pelo usuário sobre os quais o app oferece agir (remover, desativar, cortar acessos).

    level "ameaca": achado crítico ou de spyware/malware; level "revisar": achado alto em outra área (ex.:
    acessibilidade ou leitura de notificações por app desconhecido). Nada é feito sem confirmação manual."""
    findings = result.get("findings", [])
    apps = {a["package"]: a for a in result.get("apps", [])}
    extra = {}
    for u in result.get("data", {}).get("contas", {}).get("extra_users", []):
        for pkg in u.get("apps", []):
            extra.setdefault(pkg, u["id"])
    policy = result.get("data", {}).get("controle", {}).get("device_policy", {}) or {}
    admins = set(policy.get("admins", []))
    components = policy.get("admin_components", [])

    by_pkg = {}
    for f in findings:
        pkg = f.get("package")
        if pkg:
            by_pkg.setdefault(pkg, []).append(f)
    candidates = []
    for pkg, items in by_pkg.items():
        if pkg not in apps and pkg not in extra:
            continue   # app do sistema ou que não está mais instalado
        spy = [f for f in items if f.get("category") in SPYWARE_CATEGORIES and f["severity"] in ("critica", "alta")]
        critical = [f for f in items if f["severity"] == "critica"]
        high = [f for f in items if f["severity"] == "alta"]
        if not spy and not critical and not high:
            continue
        counts, worst = _summary(items)
        family = next((_family(f) for f in items if _family(f)), None)
        app = apps.get(pkg, {})
        candidates.append({
            "package": pkg,
            "user": 0 if pkg in apps else extra[pkg],
            "family": family,
            "level": "ameaca" if spy or critical else "revisar",
            "worst": worst,
            "counts": counts,
            "mercenary": _mercenary(items),
            "reasons": list(dict.fromkeys(f["title"] for f in sorted(items, key=lambda f: SEV_RANK[f["severity"]])))[:5],
            "device_admin": pkg in admins,
            "admin_components": [c for c in components if c.startswith(pkg + "/")],
            "sideloaded": app.get("sideloaded"),
            "installer": app.get("installer"),
        })
    for c in candidates:
        c["explain"] = explain.dossier(c, by_pkg[c["package"]], apps.get(c["package"]))
    candidates.sort(key=lambda c: (c["level"] != "ameaca", SEV_RANK[c["worst"]], -c["counts"]["critica"], c["package"]))
    return candidates


def enrich(result):
    """Adiciona grupos e sugestões ao relatório (idempotente)."""
    result["groups"], result["tree"] = build_groups(result.get("findings", []))
    result["removal_candidates"] = removal_candidates(result)
    return result
