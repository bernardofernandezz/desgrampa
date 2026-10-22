"""Wrapper mínimo em volta do binário `adb`. Somente leitura: nada aqui altera o aparelho.

pair/connect/disconnect só mexem na conexão do computador com o aparelho (depuração sem fio),
não em dados ou configurações do celular."""

import ipaddress
import re
import subprocess

from . import oscompat


class AdbError(Exception):
    pass


def adb_path():
    # DESGRAMPA_ADB > adb embutido no executável > PATH
    return oscompat.find_tool("adb", "DESGRAMPA_ADB")


def _run(args, timeout=60):
    adb = adb_path()
    if not adb:
        raise AdbError("adb não encontrado: instale o Android platform-tools (pacote adb ou android-tools)")
    try:
        # o código de saída é tratado abaixo (só "error:" do próprio adb vira exceção)
        proc = oscompat.run([adb, *args], capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AdbError(f"tempo esgotado executando: adb {' '.join(args)}")
    if proc.returncode != 0 and proc.stderr.strip().startswith(("error:", "adb: error")):
        raise AdbError(proc.stderr.strip())
    return proc


def list_devices():
    """Retorna [{serial, state, model, usb, wireless}] — state: device | unauthorized | offline | ..."""
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
            "wireless": is_wireless_serial(parts[0]),
        })
    return devices


# ---------------------------------------------------------------- depuração sem fio (Android 11+)

def is_wireless_serial(serial):
    """Aparelhos conectados por Wi-Fi aparecem como ip:porta ou adb-<id>._adb-tls-connect._tcp."""
    return bool(re.fullmatch(r"[\d.]+:\d+", serial) or "._adb-tls-connect." in serial)


def wireless_target(host, port):
    """Valida e normaliza 'ip:porta' (só IPs de rede local: o pareamento é na mesma rede Wi-Fi)."""
    try:
        ip = ipaddress.ip_address(str(host).strip())
        port = int(port)
    except (TypeError, ValueError):
        raise AdbError("informe o endereço IP e a porta mostrados no celular (ex.: 192.168.0.12 e 37123)")
    if not ip.is_private or ip.version != 4 or not 1 <= port <= 65535:
        raise AdbError("use o IP de rede local mostrado na tela de depuração sem fio do celular")
    return f"{ip}:{port}"


def pair(host, port, code):
    """`adb pair ip:porta código` — o código de 6 dígitos aparece em “Parear dispositivo com código”."""
    code = str(code or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        raise AdbError("o código de pareamento tem 6 dígitos")
    proc = _run(["pair", wireless_target(host, port), code], timeout=30)
    out = (proc.stdout + proc.stderr).strip()
    if "Successfully paired" not in out:
        raise AdbError(f"pareamento falhou: {out or 'sem resposta do aparelho'}")
    return out


def connect(host, port):
    """`adb connect ip:porta` — porta mostrada no topo da tela “Depuração por Wi-Fi”."""
    target = wireless_target(host, port)
    proc = _run(["connect", target], timeout=20)
    out = (proc.stdout + proc.stderr).strip()
    if not re.search(r"\b(connected|already connected) to\b", out):
        raise AdbError(f"conexão falhou: {out or 'sem resposta do aparelho'}")
    return target


def disconnect(serial):
    if not is_wireless_serial(serial):
        raise AdbError("só aparelhos conectados por Wi-Fi podem ser desconectados por aqui")
    _run(["disconnect", serial], timeout=15)


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
