"""Remoção/desativação de apps — SOMENTE por pedido explícito do usuário na interface.

Nada aqui é chamado pela varredura. Antes de alterar o aparelho, a cópia do APK é guardada como
evidência (se pedido) e toda ação é registrada em acoes.jsonl na pasta do relatório.
"""

import json
import time
from pathlib import Path

from .adb import AdbError
from .util import is_package_name, sha256_file

ACTIONS = {"uninstall": "remover", "disable": "desativar"}
LOG_FILE = "acoes.jsonl"

MSG_DISABLED = ("App desativado. Ele continua no aparelho, mas não roda mais. "
                "Para reverter: Configurações > Apps > (app) > Ativar.")
MSG_ADMIN = ("O app é administrador do aparelho e o Android bloqueia a remoção pelo cabo. No celular: "
             "Configurações > Segurança (ou Senhas e segurança) > Apps de administração do dispositivo > "
             "desmarque o app; depois tente remover de novo.")


def read_log(report_dir):
    log = Path(report_dir) / LOG_FILE
    if not log.exists():
        return []
    entries = []
    for line in log.read_text(encoding="utf-8").splitlines():
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue   # linha corrompida não impede de ler as outras
    return entries


class _Action:
    """Uma ação em andamento: executa comandos no aparelho e acumula o registro."""

    def __init__(self, device, report_dir, candidate, action):
        self.device = device
        self.report_dir = Path(report_dir)
        self.candidate = candidate
        self.pkg = candidate["package"]
        self.user = int(candidate.get("user", 0))
        self.entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "package": self.pkg, "user": self.user,
                      "action": action, "commands": [], "saved": []}

    def sh(self, cmd, timeout=120):
        out = self.device.shell(cmd, timeout=timeout)
        self.entry["commands"].append({"cmd": cmd, "output": out.strip()[:2000]})
        return out

    def is_installed(self):
        out = self.device.shell(f"pm list packages --user {self.user} {self.pkg}")
        return f"package:{self.pkg}" in {line.strip() for line in out.splitlines()}

    def backup_apk(self):
        dest = self.report_dir / "removidos" / self.pkg
        dest.mkdir(parents=True, exist_ok=True)
        for line in self.sh(f"pm path --user {self.user} {self.pkg}").splitlines():
            remote = line.strip().removeprefix("package:")
            if remote.endswith(".apk"):
                local = dest / Path(remote).name
                self.device.pull(remote, str(local), timeout=600)
                self.entry["saved"].append({"file": str(local.relative_to(self.report_dir)),
                                            "sha256": sha256_file(local)})

    def disable(self):
        out = self.sh(f"pm disable-user --user {self.user} {self.pkg}")
        if "disabled-user" in out:
            return "ok", MSG_DISABLED
        return "falhou", f"O Android recusou a desativação: {out.strip() or 'sem resposta'}"

    def uninstall(self):
        for component in self.candidate.get("admin_components", []):
            # só funciona para administradores de teste; nos demais o Android exige retirar pela tela
            self.sh(f"dpm remove-active-admin --user {self.user} {component}")
        # usuário 0: remove de todos os perfis; perfil extra: só daquele perfil
        cmd = f"pm uninstall {self.pkg}" if self.user == 0 else f"pm uninstall --user {self.user} {self.pkg}"
        out = self.sh(cmd, timeout=180)
        if "Success" in out and not self.is_installed():
            return "ok", "App removido do aparelho."
        if "DEVICE_POLICY" in out or self.candidate.get("device_admin"):
            return "manual", MSG_ADMIN
        return "falhou", f"O Android recusou a remoção: {out.strip() or 'sem resposta'}"

    def save(self, status, message):
        self.entry.update(status=status, message=message)
        with open(self.report_dir / LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(self.entry, ensure_ascii=False) + "\n")
        return self.entry


def perform(device, report_dir, candidate, action, keep_apk=True):
    """Executa a ação pedida. Devolve o registro {status, message, ...}, também salvo em acoes.jsonl."""
    if action not in ACTIONS:
        raise ValueError("ação inválida")
    if not is_package_name(candidate["package"]):
        raise ValueError("nome de pacote inválido")

    job = _Action(device, report_dir, candidate, action)
    try:
        if not job.is_installed():
            return job.save("nao_instalado", "O app não está mais instalado neste aparelho.")
        if keep_apk:
            job.backup_apk()
        status, message = job.disable() if action == "disable" else job.uninstall()
        return job.save(status, message)
    except AdbError as e:
        return job.save("falhou", f"Erro de comunicação com o aparelho: {e}")
