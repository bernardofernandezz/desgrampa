"""Wrapper mínimo em volta do binário `adb`. Somente leitura: nada aqui altera o aparelho."""

import os
import re
import shutil
import subprocess


class AdbError(Exception):
    pass


def adb_path():
    return os.environ.get("DESGRAMPA_ADB") or shutil.which("adb")


def _run(args, timeout=60):
    adb = adb_path()
    if not adb:
        raise AdbError("adb não encontrado. Instale com: sudo pacman -S android-tools")
    try:
        proc = subprocess.run(
            [adb, *args], capture_output=True, text=True, errors="replace", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise AdbError(f"tempo esgotado executando: adb {' '.join(args)}")
    if proc.returncode != 0 and proc.stderr.strip().startswith(("error:", "adb: error")):
        raise AdbError(proc.stderr.strip())
    return proc


def list_devices():
    """Retorna [{serial, state, model}] — state: device | unauthorized | offline | ..."""
    out = _run(["devices", "-l"], timeout=15).stdout
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2:
            continue
        model = re.search(r"model:(\S+)", line)
        usb = re.search(r"usb:(\S+)", line)
        devices.append({
            "serial": parts[0],
            "state": parts[1],
            "model": model.group(1).replace("_", " ") if model else None,
            "usb": usb.group(1) if usb else None,
        })
    return devices


class Device:
    def __init__(self, serial):
        self.serial = serial

    def shell(self, cmd, timeout=60):
        """Executa um comando no shell do aparelho e devolve o stdout (mesmo com exit != 0)."""
        return _run(["-s", self.serial, "shell", cmd], timeout=timeout).stdout

    def pull(self, remote, local, timeout=300):
        proc = _run(["-s", self.serial, "pull", remote, local], timeout=timeout)
        if proc.returncode != 0:
            raise AdbError(proc.stderr.strip() or f"falha ao copiar {remote}")

    def bugreport(self, local_zip, timeout=900):
        proc = _run(["-s", self.serial, "bugreport", local_zip], timeout=timeout)
        if proc.returncode != 0:
            raise AdbError(proc.stderr.strip() or "falha ao gerar o bugreport")
