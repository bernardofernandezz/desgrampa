"""Diferenças entre Linux, macOS e Windows no lado do computador: nomes de executáveis, ferramentas
embutidas no executável único (PyInstaller) e subprocessos sem janela de console no Windows."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
FROZEN = bool(getattr(sys, "frozen", False))   # rodando de dentro do executável gerado pelo PyInstaller
SYSTEM = "windows" if IS_WINDOWS else "macos" if IS_MAC else "linux"

# No Windows, cada subprocesso abriria uma janela preta de console; CREATE_NO_WINDOW evita isso.
_NO_WINDOW = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}


def exe(name):
    return f"{name}.exe" if IS_WINDOWS else name


def run(cmd, **kwargs):
    """subprocess.run com check=False e sem janela de console no Windows."""
    kwargs.setdefault("check", False)
    return subprocess.run(cmd, **_NO_WINDOW, **kwargs)


def bundle_dir():
    """Pasta com os arquivos embutidos no executável único (None quando rodando do Python)."""
    return Path(sys._MEIPASS) if FROZEN else None


def bundled_tool(name):
    """Ferramenta embutida (ex.: adb do platform-tools), procurada no executável e ao lado dele."""
    candidates = []
    if FROZEN:
        candidates += [bundle_dir() / "platform-tools" / exe(name), Path(sys.executable).parent / "platform-tools" / exe(name)]
    candidates.append(Path(__file__).resolve().parent / "platform-tools" / exe(name))
    return next((str(p) for p in candidates if p.is_file()), None)


def venv_script(prefix, name):
    """Script instalado num ambiente Python (bin/ no Unix, Scripts\\ no Windows)."""
    return Path(prefix) / ("Scripts" if IS_WINDOWS else "bin") / exe(name)


def find_tool(name, env_var=None):
    """Variável de ambiente > ferramenta embutida > PATH."""
    return (env_var and os.environ.get(env_var)) or bundled_tool(name) or shutil.which(name)
