"""Rede de apoio e base legal (desgrampa/dados/ajuda.json): contatos, Defensorias por UF, leis e como
preservar evidências. Usado pela página “Preciso de ajuda” e pelo relatório para atendimento."""

import json
from functools import cache

from .paths import BUNDLED_DATA_DIR


@cache
def load():
    return json.loads((BUNDLED_DATA_DIR / "ajuda.json").read_text(encoding="utf-8"))
