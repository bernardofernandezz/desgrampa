# Executável único do Desgrampa (PyInstaller), com o adb do Android platform-tools embutido.
#
#   python packaging/baixar_adb.py          # baixa o platform-tools do sistema atual para packaging/platform-tools
#   pyinstaller packaging/desgrampa.spec    # gera dist/desgrampa(.exe)
#
# O MVT (análise forense) não vai no executável: é grande e tem dependências nativas. Quem precisa
# da varredura forense instala `pipx install "desgrampa[forense]"` ou aponta DESGRAMPA_MVT.

from pathlib import Path

ROOT = Path(SPECPATH).parent
PLATFORM_TOOLS = Path(SPECPATH) / "platform-tools"

datas = [
    (str(ROOT / "desgrampa" / "web"), "desgrampa/web"),
    (str(ROOT / "desgrampa" / "dados"), "desgrampa/dados"),
]
if PLATFORM_TOOLS.is_dir():
    datas.append((str(PLATFORM_TOOLS), "platform-tools"))

a = Analysis(
    [str(Path(SPECPATH) / "entrada.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=["yaml"],
    excludes=["tkinter", "mvt"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="desgrampa",
    console=True,          # mostra o endereço do painel e permite encerrar com Ctrl+C
    upx=False,             # UPX aumenta falsos positivos de antivírus
)
