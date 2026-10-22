"""Exportações do relatório para outras ferramentas: STIX 2.1 (achados e CVEs) e CSV das vulnerabilidades."""

import csv
import io
import json
import uuid

from . import __version__

NAMESPACE = uuid.UUID("6f0c5e8a-2b1d-4f3e-9a7c-1d2e3f4a5b6c")   # ids determinísticos: o mesmo relatório gera o mesmo STIX
STIX_SEVERITY = {"critica": "critical", "alta": "high", "media": "medium", "baixa": "low", "info": "informational"}


def _id(kind, *parts):
    return f"{kind}--{uuid.uuid5(NAMESPACE, '|'.join(str(p) for p in parts))}"


def _timestamp(started):
    return started.replace(" ", "T") + ".000Z" if started else "1970-01-01T00:00:00.000Z"


def to_stix(r):
    """Bundle STIX 2.1: um report com uma note por achado e um vulnerability por CVE aberta."""
    ts = _timestamp(r.get("started"))
    name = r.get("report_name") or "relatorio"
    identity = {"type": "identity", "spec_version": "2.1", "id": _id("identity", "desgrampa"),
                "created": ts, "modified": ts, "name": f"Desgrampa {__version__}", "identity_class": "system"}
    objects = [identity]
    for i, f in enumerate(r.get("findings", [])):
        objects.append({
            "type": "note", "spec_version": "2.1", "id": _id("note", name, i), "created": ts, "modified": ts,
            "created_by_ref": identity["id"], "abstract": f["title"],
            "content": "\n\n".join(x for x in (f["detail"], f.get("recommendation")) if x),
            "labels": [f"severity:{STIX_SEVERITY.get(f['severity'], f['severity'])}", f"category:{f.get('category')}"]
                      + ([f"package:{f['package']}"] if f.get("package") else [])
                      + ([f"family:{f['family']}"] if f.get("family") else []),
            "object_refs": [identity["id"]],
        })
    for v in (r.get("data", {}).get("vulns") or {}).get("items", []):
        refs = [{"source_name": "cve", "external_id": v["cve"]}] if v["cve"].startswith("CVE-") else []
        objects.append({
            "type": "vulnerability", "spec_version": "2.1", "id": _id("vulnerability", v["cve"]),
            "created": ts, "modified": ts, "created_by_ref": identity["id"], "name": v["cve"],
            "description": v.get("summary") or v["component"], "external_references": refs,
            "labels": [f"component:{v['component']}", f"fixed-in-spl:{v['spl']}"]
                      + (["cisa-kev"] if v.get("kev") else []),
        })
    device = r.get("device", {})
    objects.append({
        "type": "report", "spec_version": "2.1", "id": _id("report", name), "created": ts, "modified": ts,
        "created_by_ref": identity["id"], "published": ts,
        "name": f"Desgrampa: {device.get('manufacturer') or ''} {device.get('model') or ''} — {r['verdict']['label']}".strip(),
        "description": r["verdict"]["text"], "report_types": ["threat-report"],
        "object_refs": [o["id"] for o in objects[1:]] or [identity["id"]],
    })
    return {"type": "bundle", "id": _id("bundle", name), "objects": objects}


def stix_json(r):
    return json.dumps(to_stix(r), ensure_ascii=False, indent=1)


def vulns_csv(r):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["cve", "gravidade", "explorada_ativamente", "componente", "escopo", "corrigida_no_patch",
                     "tipos", "resumo"])
    for v in (r.get("data", {}).get("vulns") or {}).get("items", []):
        writer.writerow([v["cve"], v["severity"], "sim" if v["kev"] else "não", v["component"], v["scope"], v["spl"],
                         " ".join(v["types"]), v["summary"]])
    return "﻿" + out.getvalue()   # BOM: o Excel abre com acentos corretos
