"""Pequenos utilitários usados em vários módulos."""

import hashlib
import re

# Nome de pacote Android: letras/dígitos/_ separados por pontos, começando com letra (ex.: com.exemplo.app)
PACKAGE = r"[a-zA-Z]\w*(?:\.\w+)+"
PACKAGE_RE = re.compile(PACKAGE)
QUOTED_PACKAGE_RE = re.compile(rf"[\"']({PACKAGE})[\"']")   # pacote citado entre aspas numa mensagem

DAY = 86400   # segundos


def is_package_name(text):
    return bool(PACKAGE_RE.fullmatch(text or ""))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
