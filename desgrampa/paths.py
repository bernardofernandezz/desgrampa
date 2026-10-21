"""Onde o Desgrampa guarda dados: bases de indicadores baixadas e relatórios com evidências.

- DESGRAMPA_HOME, se definida;
- a pasta do repositório, quando rodando a partir de um clone (tem pyproject.toml);
- senão, ~/.local/share/desgrampa (ou $XDG_DATA_HOME/desgrampa).
"""

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent


def home():
    if os.environ.get("DESGRAMPA_HOME"):
        return Path(os.environ["DESGRAMPA_HOME"]).expanduser()
    if (REPO_DIR / "pyproject.toml").exists():
        return REPO_DIR
    xdg = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(xdg) / "desgrampa"


HOME = home()
DATA_DIR = HOME / "data"            # bases de indicadores baixadas
REPORTS_DIR = HOME / "relatorios"   # um diretório por varredura, com as evidências
WEB_DIR = PACKAGE_DIR / "web"
