"""Base de vulnerabilidades do Android (boletins de segurança + CISA KEV), gerada por
tools/build_bulletins.py.

Uma cópia vem com o código (desgrampa/dados). “Atualizar bases” baixa a versão mais nova publicada no
repositório para a pasta de dados; vale a mais recente das duas.
"""

import json
import logging
import urllib.request
from pathlib import Path

from .paths import BUNDLED_DATA_DIR, DATA_DIR

FILE = "android_bulletins.json"
URL = "https://raw.githubusercontent.com/bernardofernandezz/desgrampa/main/desgrampa/dados/" + FILE
FIELDS = ("cve", "spl", "severity", "scope", "versions", "component", "types", "kev", "summary")
SEVERITY_NAMES = {"C": "Crítica", "H": "Alta", "M": "Moderada", "L": "Baixa"}

log = logging.getLogger(__name__)


def _read(path):
    try:
        db = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return db if isinstance(db, dict) and db.get("format") == 1 and db.get("vulns") else None


def load(data_dir=None, bundled_dir=None):
    """A base mais recente entre a embutida e a baixada (None se nenhuma existir)."""
    candidates = [_read(Path(bundled_dir or BUNDLED_DATA_DIR) / FILE), _read(Path(data_dir or DATA_DIR) / FILE)]
    candidates = [db for db in candidates if db]
    return max(candidates, key=lambda db: db["generated"]) if candidates else None


def download(data_dir=None):
    """Baixa a base publicada no repositório. Falhas não interrompem a atualização das outras bases."""
    dest = Path(data_dir or DATA_DIR) / FILE
    try:
        with urllib.request.urlopen(URL, timeout=60) as resp:
            raw = resp.read()
        db = json.loads(raw)
        if db.get("format") != 1 or not db.get("vulns"):
            raise ValueError("formato inesperado")
    except Exception as e:
        log.warning("não foi possível baixar a base de vulnerabilidades: %s", e)
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(raw)
    return True


def as_dict(row):
    return dict(zip(FIELDS, row, strict=True))


def summary(db):
    if not db:
        return {"available": False}
    return {"available": True, "generated": db["generated"], "latest_spl": db["latest_spl"],
            "total": len(db["vulns"]), "kev": sum(r[7] for r in db["vulns"]),
            "android_supported": db.get("android_supported", [])}
