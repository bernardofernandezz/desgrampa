"""Gera desgrampa/dados/android_bulletins.json: vulnerabilidades corrigidas pelos Android Security
Bulletins, marcadas quando estão no catálogo CISA KEV (exploradas ativamente), mais as versões do
Chrome/WebView e o histórico de falhas do Chromium exploradas ativamente.

    python tools/build_bulletins.py                 # baixa tudo e grava o arquivo
    python tools/build_bulletins.py --osv all.zip   # usa um all.zip do OSV já baixado

Fontes (dados públicos):
- OSV, ecossistema Android (espelho dos Android Security Bulletins e dos Pixel Update Bulletins)
  https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip
- CISA Known Exploited Vulnerabilities  https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Chrome VersionHistory API             https://versionhistory.googleapis.com/

Formato compacto (uma linha por falha) para caber no pacote:
    vulns: [cve, spl, severidade, escopo, versões, componente, tipos, kev, resumo]
      severidade  C | H | M | L
      escopo      aosp (depende da versão do Android) | kernel | qcom (chip Qualcomm) | pixel (só Google Pixel)
"""

import argparse
import io
import json
import re
import sys
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CHROME_RELEASES = ("https://versionhistory.googleapis.com/v1/chrome/platforms/android/channels/stable/versions/all/"
                   "releases?order_by=starttime%20desc&pageSize=1000&filter=starttime%3E{since}")
OUT = Path(__file__).resolve().parent.parent / "desgrampa" / "dados" / "android_bulletins.json"

SEVERITY = {"Critical": "C", "High": "H", "Moderate": "M", "Low": "L"}
SUMMARY_CHARS = 160
SUPPORT_WINDOW_DAYS = 200     # versões do Android citadas nos boletins recentes = versões ainda atualizadas
CHROME_HISTORY_YEARS = 4

# Apps de mensagem com falhas exploradas para instalar spyware, e a primeira versão Android corrigida.
APPS = [
    {"package": "com.whatsapp", "name": "WhatsApp", "fixed": "2.19.134", "cve": "CVE-2019-3568",
     "summary": "Falha na chamada de voz usada para instalar o spyware Pegasus sem nenhum toque.",
     "url": "https://www.facebook.com/security/advisories/cve-2019-3568"},
    {"package": "com.whatsapp", "name": "WhatsApp", "fixed": "2.22.16.12", "cve": "CVE-2022-36934",
     "summary": "Falha em chamadas de vídeo que permitia executar código remotamente.",
     "url": "https://www.whatsapp.com/security/advisories/2022"},
    {"package": "com.whatsapp.w4b", "name": "WhatsApp Business", "fixed": "2.22.16.12", "cve": "CVE-2022-36934",
     "summary": "Falha em chamadas de vídeo que permitia executar código remotamente.",
     "url": "https://www.whatsapp.com/security/advisories/2022"},
    {"package": "org.telegram.messenger", "name": "Telegram", "fixed": "10.14.5", "cve": "CVE-2024-7014",
     "summary": "“EvilVideo”: arquivo disfarçado de vídeo instalava um app malicioso.",
     "url": "https://www.welivesecurity.com/en/eset-research/cursed-tapes-exploiting-evilvideo-vulnerability-telegram-android/"},
]


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "desgrampa-build-bulletins"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def summarize(text):
    text = re.sub(r"\s+", " ", (text or "").replace("\xa0", " ")).strip()
    first = re.split(r"(?<=\.)\s", text, maxsplit=1)[0]
    return first if len(first) <= SUMMARY_CHARS else first[:SUMMARY_CHARS - 1].rstrip() + "…"


def major(label):
    """'13' -> '13', '12L' -> '12', '16-qpr2-next' -> '16', '8.1' -> '8' (None para rótulos sem versão)."""
    m = re.match(r"(\d+)", label)
    return m.group(1) if m else None


def scope_of(package, versions):
    if "Pixel-family specific" in versions:
        return "pixel"
    if "SoCVersion" in versions:
        return "qcom" if "qcom" in package.lower() or "qualcomm" in package.lower() else None
    if "Kernel" in versions:
        return "kernel"
    if any(major(v) for v in versions):
        return "aosp"
    return None   # “Device specific” e chips de fabricante não informado: não dá para atribuir ao aparelho


def parse_osv(archive, kev):
    rows, skipped = {}, Counter()
    for name in archive.namelist():
        rec = json.loads(archive.read(name))
        cve = next((a for a in rec.get("aliases", []) if a.startswith("CVE-")), rec["id"])
        for aff in rec.get("affected", []):
            es = aff.get("ecosystem_specific", {})
            spl, versions = es.get("spl"), aff.get("versions", [])
            scope = scope_of(aff["package"]["name"], versions)
            if not spl or not scope:
                skipped[scope or "sem escopo"] += 1
                continue
            majors = sorted({major(v) for v in versions if major(v)}, key=int) if scope == "aosp" else []
            key = (cve, scope)
            if key in rows:   # a mesma CVE em várias versões: junta as versões e fica com o patch mais antigo
                row = rows[key]
                row[1] = min(row[1], spl)
                row[4] = sorted(set(row[4]) | set(majors), key=int)
                continue
            component = aff["package"]["name"].replace("platform/", "").strip(":") or "?"
            rows[key] = [cve, spl, SEVERITY.get(es.get("severity"), "M"), scope, majors, component,
                         es.get("types", []), int(cve in kev), summarize(rec.get("details"))]
    return sorted(rows.values(), key=lambda r: (r[1], r[0])), skipped


def supported_versions(rows, generated):
    since = (generated - timedelta(days=SUPPORT_WINDOW_DAYS)).isoformat()
    return sorted({v for r in rows if r[3] == "aosp" and r[1] >= since for v in r[4]}, key=int)


def chrome_history(generated):
    """{major: data da primeira versão estável no Android} dos últimos anos, e a versão estável atual."""
    since = (generated - timedelta(days=365 * CHROME_HISTORY_YEARS)).isoformat() + "T00:00:00Z"
    data = json.loads(fetch(CHROME_RELEASES.format(since=since)))
    first = {}
    for rel in data.get("releases", []):
        mj = rel["version"].split(".")[0]
        start = rel["serving"]["startTime"][:10]
        first[mj] = min(first.get(mj, start), start)
    stable = max(first, key=int) if first else None
    return {"stable_major": stable, "first_stable": dict(sorted(first.items(), key=lambda kv: int(kv[0])))}


def kev_chromium(kev_items):
    return sorted(({"cve": v["cveID"], "added": v["dateAdded"], "name": v["vulnerabilityName"]}
                   for v in kev_items if v["vendorProject"] == "Google" and "Chromium" in v["product"]),
                  key=lambda v: v["added"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--osv", help="all.zip do OSV já baixado")
    parser.add_argument("--kev", help="known_exploited_vulnerabilities.json já baixado")
    parser.add_argument("--sem-chrome", action="store_true", help="não consultar a API de versões do Chrome")
    parser.add_argument("-o", "--saida", default=str(OUT))
    args = parser.parse_args(argv)

    generated = datetime.now(timezone.utc).date()
    kev_data = json.loads(Path(args.kev).read_bytes() if args.kev else fetch(KEV_URL))
    kev = {v["cveID"] for v in kev_data["vulnerabilities"]}
    archive = zipfile.ZipFile(args.osv if args.osv else io.BytesIO(fetch(OSV_URL)))
    rows, skipped = parse_osv(archive, kev)

    db = {
        "format": 1,
        "generated": generated.isoformat(),
        "latest_spl": max(r[1] for r in rows),
        "sources": {
            "osv": OSV_URL,
            "kev": f"{KEV_URL} (versão {kev_data.get('catalogVersion')})",
            "chrome": "https://versionhistory.googleapis.com/",
        },
        "android_supported": supported_versions(rows, generated),
        "vulns": rows,
        "apps": APPS,
        "kev_chromium": kev_chromium(kev_data["vulnerabilities"]),
        "chrome": None if args.sem_chrome else chrome_history(generated),
    }
    out = Path(args.saida)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(db, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    kev_count = sum(r[7] for r in rows)
    print(f"{out}: {len(rows)} falhas ({kev_count} exploradas ativamente), patch mais recente {db['latest_spl']}, "
          f"Android atualizados {', '.join(db['android_supported'])}; ignoradas: {dict(skipped)}; "
          f"{out.stat().st_size // 1024} KB", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
