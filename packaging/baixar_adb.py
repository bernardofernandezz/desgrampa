"""Baixa o Android platform-tools (adb) do sistema atual para packaging/platform-tools.

Só os arquivos necessários para o adb funcionar são mantidos (adb e, no Windows, as DLLs dele)."""

import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

URL = "https://dl.google.com/android/repository/platform-tools-latest-{}.zip"
SYSTEMS = {"win32": "windows", "darwin": "darwin"}
KEEP = {"adb", "adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll", "NOTICE.txt", "source.properties"}


def main():
    dest = Path(__file__).resolve().parent / "platform-tools"
    url = URL.format(SYSTEMS.get(sys.platform, "linux"))
    print(f"baixando {url}")
    with urllib.request.urlopen(url, timeout=120) as resp:
        archive = zipfile.ZipFile(io.BytesIO(resp.read()))
    shutil.rmtree(dest, ignore_errors=True)
    dest.mkdir(parents=True)
    for info in archive.infolist():
        name = Path(info.filename).name
        if name in KEEP and not info.is_dir():
            target = dest / name
            target.write_bytes(archive.read(info))
            if name == "adb":
                target.chmod(0o755)
    print("ok:", ", ".join(sorted(p.name for p in dest.iterdir())))


if __name__ == "__main__":
    main()
