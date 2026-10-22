"""Onde o Desgrampa guarda dados: bases de indicadores baixadas e relatórios com evidências.

- DESGRAMPA_HOME, se definida;
- a pasta do repositório, quando rodando a partir de um clone (tem pyproject.toml);
- senão, a pasta de dados do usuário no sistema:
    Linux    ~/.local/share/desgrampa (ou $XDG_DATA_HOME/desgrampa)
    macOS    ~/Library/Application Support/Desgrampa
    Windows  %LOCALAPPDATA%\\Desgrampa
"""

import os
from pathlib import Path

from .oscompat import FROZEN, IS_MAC, IS_WINDOWS

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent


def user_data_dir():
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
        return Path(base) / "Desgrampa"
    if IS_MAC:
        return Path.home() / "Library" / "Application Support" / "Desgrampa"
    xdg = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(xdg) / "desgrampa"


def home():
    if os.environ.get("DESGRAMPA_HOME"):
        return Path(os.environ["DESGRAMPA_HOME"]).expanduser()
    if not FROZEN and (REPO_DIR / "pyproject.toml").exists():
        return REPO_DIR
    return user_data_dir()


HOME = home()
DATA_DIR = HOME / "data"            # bases de indicadores baixadas
REPORTS_DIR = HOME / "relatorios"   # um diretório por varredura, com as evidências
WEB_DIR = PACKAGE_DIR / "web"     # no executável único, o PyInstaller extrai o pacote com a mesma estrutura
# bases versionadas junto com o código (dados públicos: boletins de segurança, indicadores brasileiros)
BUNDLED_DATA_DIR = PACKAGE_DIR / "dados"
