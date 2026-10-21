"""Remoção/desativação de apps — SOMENTE por pedido explícito do usuário na interface.

Nada aqui é chamado pela varredura. Antes de alterar o aparelho, a cópia do APK é guardada como
evidência (se pedido) e toda ação é registrada em acoes.jsonl na pasta do relatório.
"""

import hashlib
import json
import re
import time
from pathlib import Path

from .adb import AdbError

ACTIONS = {"uninstall": "remover", "disable": "desativar"}


def _installed(device, pkg, user):
    out = device.shell(f"pm list packages --user {user} {pkg}")
    return f"package:{pkg}" in {line.strip() for line in out.splitlines()}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_log(report_dir):
    log = Path(report_dir) / "acoes.jsonl"
    if not log.exists():
        return []
    entries = []
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def perform(device, report_dir, candidate, action, keep_apk=True):
    """Executa a ação pedida. Devolve {status, message, ...} e registra em acoes.jsonl."""
    if action not in ACTIONS:
        raise ValueError("ação inválida")
    pkg, user = candidate["package"], int(candidate.get("user", 0))
    if not re.fullmatch(r"[a-zA-Z][\w]*(\.[\w]+)+", pkg):
        raise ValueError("nome de pacote inválido")
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "package": pkg, "user": user, "action": action,
             "commands": [], "saved": []}

    def sh(cmd, timeout=120):
        out = device.shell(cmd, timeout=timeout)
        entry["commands"].append({"cmd": cmd, "output": out.strip()[:2000]})
        return out

    def finish(status, message):
        entry.update(status=status, message=message)
        with open(Path(report_dir) / "acoes.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    try:
        if not _installed(device, pkg, user):
            return finish("nao_instalado", "O app não está mais instalado neste aparelho.")

        if keep_apk:
            dest = Path(report_dir) / "removidos" / pkg
            dest.mkdir(parents=True, exist_ok=True)
            for line in sh(f"pm path --user {user} {pkg}").splitlines():
                remote = line.strip().removeprefix("package:")
                if not remote.endswith(".apk"):
                    continue
                local = dest / Path(remote).name
                device.pull(remote, str(local), timeout=600)
                entry["saved"].append({"file": str(local.relative_to(report_dir)), "sha256": _sha256(local)})

        if action == "disable":
            out = sh(f"pm disable-user --user {user} {pkg}")
            if "disabled-user" in out:
                return finish("ok", "App desativado. Ele continua no aparelho, mas não roda mais. Para reverter: "
                                    "Configurações > Apps > (app) > Ativar.")
            return finish("falhou", f"O Android recusou a desativação: {out.strip() or 'sem resposta'}")

        for component in candidate.get("admin_components", []):
            # só funciona para administradores de teste; nos demais o Android exige retirar pela tela
            sh(f"dpm remove-active-admin --user {user} {component}")
        out = sh(f"pm uninstall {pkg}" if user == 0 else f"pm uninstall --user {user} {pkg}", timeout=180)
        if "Success" in out and not _installed(device, pkg, user):
            return finish("ok", "App removido do aparelho.")
        if "DEVICE_POLICY" in out or candidate.get("device_admin"):
            return finish("manual", "O app é administrador do aparelho e o Android bloqueia a remoção pelo cabo. "
                                    "No celular: Configurações > Segurança (ou Senhas e segurança) > Apps de "
                                    "administração do dispositivo > desmarque o app; depois tente remover de novo.")
        return finish("falhou", f"O Android recusou a remoção: {out.strip() or 'sem resposta'}")
    except AdbError as e:
        return finish("falhou", f"Erro de comunicação com o aparelho: {e}")
