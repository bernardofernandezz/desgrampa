"""Indicadores de comprometimento (IOCs).

Fontes:
- AssoEchap/stalkerware-indicators (ioc.yaml) — stalkerware comercial.
- mvt-project/mvt-indicators (STIX2) — spyware mercenário/estatal (Pegasus, Predator, Candiru,
  NoviSpy, Cellebrite...) usado pelo Mobile Verification Toolkit da Anistia Internacional.

As bases não são distribuídas com o código (licenças das fontes e tamanho): são baixadas na
primeira execução para paths.DATA_DIR e podem ser atualizadas pela interface ou pela linha de comando.
"""

import json
import re
import shutil
import tempfile
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .paths import DATA_DIR

ECHAP_FILE = "ioc.yaml"
STIX_DIR = "stix"
ECHAP_URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
MVT_INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"

STALKERWARE = "Stalkerware (AssoEchap)"

# tipo STIX2 -> atributo do Iocs
STIX_KINDS = {
    "app:id": "packages", "app:cert.sha1": "cert_sha1", "app:cert.sha256": "cert_sha256",
    "file:hashes.sha256": "apk_sha256", "process:name": "processes", "domain-name:value": "domains",
    "ipv4-addr:value": "ips", "file:path": "file_paths", "file:name": "file_names",
    "android-property:name": "properties", "email-addr:value": "emails",
}
KINDS = sorted(set(STIX_KINDS.values()))

# Domínios legítimos que às vezes aparecem nas bases (ex.: github.com, via URL de um repositório
# de malware). Como comparamos também domínios-pai, mantê-los geraria falsos positivos em massa.
SAFE_DOMAINS = {
    "github.com", "github.io", "raw.githubusercontent.com", "gitlab.com", "google.com", "googleapis.com",
    "gstatic.com", "googleusercontent.com", "firebaseio.com", "firebaseapp.com", "appspot.com",
    "amazonaws.com", "cloudfront.net", "cloudflare.com", "workers.dev", "pages.dev", "microsoft.com",
    "azurewebsites.net", "apple.com", "icloud.com", "facebook.com", "fbcdn.net", "whatsapp.com",
    "whatsapp.net", "telegram.org", "t.me", "youtube.com", "dropbox.com", "bit.ly", "goo.gl",
    "umeng.com", "baidu.com", "qq.com", "aliyuncs.com", "herokuapp.com", "blogspot.com",
    "wordpress.com", "pastebin.com", "mediafire.com", "mega.nz", "sourceforge.net", "amazon.com",
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com", "office.com", "web.app",
    "netlify.app", "vercel.app", "duckdns.org", "ddns.net", "no-ip.com",
}


@dataclass
class Match:
    family: str        # nome da família/malware
    collection: str    # conjunto de indicadores de onde veio

    @property
    def mercenary(self):
        """True para spyware estatal/mercenário (tudo que não é a base de stalkerware)."""
        return "stalkerware" not in self.collection.lower()

    def __str__(self):
        return self.family if self.family == self.collection else f"{self.family} — {self.collection}"


class Iocs:
    def __init__(self):
        for kind in KINDS:
            setattr(self, kind, {})
        self.collections = {}   # nome -> quantidade de indicadores
        self.source = ""
        self.updated = ""

    def _add(self, kind, value, match):
        value = value.strip()
        if not value:
            return
        if kind in ("cert_sha1", "cert_sha256", "apk_sha256"):
            value = value.upper().replace(":", "")
        elif kind in ("packages", "domains", "emails"):
            value = value.lower()
        if kind == "domains":
            value = re.sub(r"^\w+://", "", value).split("/")[0].split(":")[0].strip(".")
            if value in SAFE_DOMAINS or "." not in value:
                return
        table = getattr(self, kind)
        if value not in table:
            table[value] = match
            self.collections[match.collection] = self.collections.get(match.collection, 0) + 1

    def add_echap(self, entries):
        for e in entries:
            m = Match(e.get("name", "desconhecido"), STALKERWARE)
            c2 = e.get("c2") or {}
            for p in e.get("packages") or []:
                self._add("packages", p, m)
            for c in e.get("certificates") or []:
                self._add("cert_sha1", c, m)
            for d in [*(e.get("websites") or []), *(e.get("distribution") or []), *(c2.get("domains") or [])]:
                if re.fullmatch(r"[\d.]+", d):
                    self._add("ips", d, m)
                else:
                    self._add("domains", d, m)
            for ip in c2.get("ips") or []:
                self._add("ips", ip, m)

    def add_stix(self, bundle, collection):
        objects = bundle.get("objects", [])
        malware = {o["id"]: o.get("name", collection) for o in objects if o.get("type") == "malware"}
        family_of = {}
        for o in objects:
            if o.get("type") == "relationship" and o.get("target_ref") in malware:
                family_of[o.get("source_ref")] = malware[o["target_ref"]]
        for o in objects:
            if o.get("type") != "indicator":
                continue
            m = Match(family_of.get(o["id"], collection), collection)
            for key, value in re.findall(r"([\w:.\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'", o.get("pattern", "")):
                if key == "url:value":
                    host = re.sub(r"^\w+://", "", value).split("/")[0].split(":")[0]
                    self._add("domains", host, m)
                elif key in STIX_KINDS:
                    self._add(STIX_KINDS[key], value, m)

    # ------------------------------------------------------------ consultas

    @property
    def total_count(self):
        return sum(len(getattr(self, k)) for k in KINDS)

    def match_package(self, pkg):
        return self.packages.get(pkg.lower())

    def match_certificate(self, sha1_hex=None, sha256_hex=None):
        return (sha1_hex and self.cert_sha1.get(sha1_hex.upper())) or \
            (sha256_hex and self.cert_sha256.get(sha256_hex.upper()))

    def match_apk_hash(self, sha256_hex):
        return self.apk_sha256.get(sha256_hex.upper())

    def match_process(self, name):
        return self.processes.get(name) or self.match_package(name.split(":")[0])

    def match_ip(self, ip):
        return self.ips.get(ip)

    def match_email(self, email):
        return self.emails.get(email.lower())

    def match_domain(self, host):
        """Casa o domínio ou qualquer domínio pai (ex.: a.b.mspy.com -> mspy.com)."""
        host = host.lower().strip(".")
        parts = host.split(".")
        for i in range(len(parts) - 1):
            hit = self.domains.get(".".join(parts[i:]))
            if hit:
                return hit
        return None

    def domains_in_text(self, text):
        """Procura domínios maliciosos citados em um texto livre (logs, dumps)."""
        hits = {}
        for host in set(re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", text.lower())):
            m = self.match_domain(host)
            if m:
                hits[host] = m
        return hits

    def ips_in_text(self, text):
        hits = {}
        for ip in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)):
            m = self.match_ip(ip)
            if m:
                hits[ip] = m
        return hits

    def summary(self):
        return {
            "source": self.source,
            "updated": self.updated,
            "collections": dict(sorted(self.collections.items(), key=lambda kv: -kv[1])),
            "families": len({m.family for kind in KINDS for m in getattr(self, kind).values()}),
            "total": sum(len(getattr(self, k)) for k in KINDS),
            **{k: len(getattr(self, k)) for k in KINDS},
        }


# ---------------------------------------------------------------- carga / atualização

def _read_echap(path):
    with open(path, encoding="utf-8") as f:
        entries = yaml.safe_load(f)
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"arquivo de IOCs inválido: {path}")
    return entries


def _read_stix_dir(path):
    index = json.loads((path / "index.json").read_text(encoding="utf-8"))
    for item in index:
        bundle = json.loads((path / item["file"]).read_text(encoding="utf-8"))
        yield item["name"], bundle


def available(data_dir=None):
    data_dir = Path(data_dir or DATA_DIR)
    return (data_dir / ECHAP_FILE).exists() and (data_dir / STIX_DIR / "index.json").exists()


def load(data_dir=None):
    """Carrega as bases baixadas. Sem bases, devolve um conjunto vazio (source="ausente")."""
    data_dir = Path(data_dir or DATA_DIR)
    iocs = Iocs()
    if not available(data_dir):
        iocs.source = "ausente"
        return iocs
    iocs.add_echap(_read_echap(data_dir / ECHAP_FILE))
    for name, bundle in _read_stix_dir(data_dir / STIX_DIR):
        # a versão STIX da base de stalkerware traz também hashes de APK
        iocs.add_stix(bundle, STALKERWARE if "stalkerware" in name.lower() else name)
    iocs.source = "baixada da internet"
    iocs.updated = datetime.fromtimestamp((data_dir / ECHAP_FILE).stat().st_mtime, timezone.utc).strftime("%Y-%m-%d")
    return iocs


def stix_files(data_dir=None):
    """Arquivos STIX2 em uso (passados ao MVT)."""
    stix_dir = Path(data_dir or DATA_DIR) / STIX_DIR
    if not (stix_dir / "index.json").exists():
        return []
    index = json.loads((stix_dir / "index.json").read_text(encoding="utf-8"))
    return [stix_dir / item["file"] for item in index]


def _fetch(url):
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read()


def download(data_dir=None):
    """Baixa todas as bases; só substitui as atuais se tudo vier válido."""
    data_dir = Path(data_dir or DATA_DIR)
    data_dir.mkdir(parents=True, exist_ok=True)
    yaml_dest, stix_dest = data_dir / ECHAP_FILE, data_dir / STIX_DIR
    with tempfile.TemporaryDirectory(dir=data_dir) as tmp:
        tmp = Path(tmp)
        (tmp / ECHAP_FILE).write_bytes(_fetch(ECHAP_URL))
        _read_echap(tmp / ECHAP_FILE)

        stix_tmp = tmp / "stix"
        stix_tmp.mkdir()
        index = []
        for item in yaml.safe_load(_fetch(MVT_INDEX_URL))["indicators"]:
            g = item.get("github")
            url = (f"https://raw.githubusercontent.com/{g['owner']}/{g['repo']}/{g['branch']}/{g['path']}"
                   if g else item.get("download_url"))
            if not url:
                continue
            data = _fetch(url)
            json.loads(data)  # valida
            fname = re.sub(r"[^\w.-]", "_", Path(url).name)
            if (stix_tmp / fname).exists():
                fname = f"{len(index)}_{fname}"
            (stix_tmp / fname).write_bytes(data)
            index.append({"name": item["name"].replace(" Indicators of Compromise", ""), "file": fname,
                          "references": item.get("references", [])})
        (stix_tmp / "index.json").write_text(json.dumps(index, indent=1, ensure_ascii=False), encoding="utf-8")

        shutil.move(tmp / ECHAP_FILE, yaml_dest)
        if stix_dest.exists():
            shutil.rmtree(stix_dest)
        shutil.move(stix_tmp, stix_dest)


def update(data_dir=None):
    download(data_dir)
    return load(data_dir)
