"""Remoção/desativação de apps — SOMENTE por pedido explícito do usuário na interface.

Nada aqui é chamado pela varredura. Antes de alterar o aparelho, a cópia do APK é guardada como
evidência (se pedido) e toda ação é registrada em acoes.jsonl na pasta do relatório.
"""

import json
import re
import shlex
import time
from pathlib import Path

from .adb import AdbError
from .util import is_package_name, sha256_file

ACTIONS = {"uninstall": "remover", "disable": "desativar", "restrict": "cortar acessos", "enable": "reativar"}
LOG_FILE = "acoes.jsonl"

# Permissões perigosas que stalkerware usa; só estas são revogadas (as demais não são revogáveis pelo pm)
SPY_PERMISSIONS = {f"android.permission.{p}" for p in (
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "RECEIVE_MMS", "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE", "ANSWER_PHONE_CALLS", "READ_CONTACTS", "GET_ACCOUNTS",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_CALENDAR", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO", "BODY_SENSORS", "ACTIVITY_RECOGNITION")}
GRANTED = re.compile(r"(android\.permission\.\w+): granted=true")
# operações especiais: sobrepor a tela, gravar a tela, ler o uso de apps e rodar em segundo plano
SPY_APPOPS = ("SYSTEM_ALERT_WINDOW", "PROJECT_MEDIA", "GET_USAGE_STATS", "RUN_ANY_IN_BACKGROUND")

MSG_DISABLED = ("App desativado. Ele continua no aparelho, mas não roda mais. "
                "Para reverter: Configurações > Apps > (app) > Ativar.")
MSG_ENABLED = "App reativado. Ele volta a funcionar normalmente."
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
                      "action": action, "commands": [], "saved": [],
                      "reason": (candidate.get("explain") or {}).get("summary")}

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

    def enable(self):
        out = self.sh(f"pm enable --user {self.user} {self.pkg}")
        if "enabled" in out:
            return "ok", MSG_ENABLED
        return "falhou", f"O Android recusou a reativação: {out.strip() or 'sem resposta'}"

    def remove_admin(self):
        for component in self.candidate.get("admin_components", []):
            # só funciona para administradores de teste; nos demais o Android exige retirar pela tela
            self.sh(f"dpm remove-active-admin --user {self.user} {component}")

    def drop_from_setting(self, key):
        """Tira os componentes do app de uma lista do tipo "a/.X:b/.Y" em settings secure. Devolve os retirados."""
        current = self.device.shell(f"settings --user {self.user} get secure {key}").strip()
        items = [c for c in current.split(":") if c and c != "null"]
        mine = [c for c in items if c.split("/")[0] == self.pkg]
        if mine:
            rest = ":".join(c for c in items if c not in mine)
            # componentes de outros apps vêm do aparelho: aspas para o shell não interpretar "$"
            self.sh(f"settings --user {self.user} put secure {key} {shlex.quote(rest)}" if rest
                    else f"settings --user {self.user} delete secure {key}")
        return mine

    def restrict(self):
        """Corta os acessos de espionagem sem apagar o app (as evidências ficam no aparelho)."""
        cut = []
        if self.drop_from_setting("enabled_accessibility_services"):
            cut.append("acessibilidade (ler a tela)")
        listeners = self.drop_from_setting("enabled_notification_listeners")
        for component in listeners:
            self.sh(f"cmd notification disallow_listener {shlex.quote(component)} {self.user}")
        if listeners:
            cut.append("leitura de notificações")
        dump = self.device.shell(f"dumpsys package {self.pkg}", timeout=60)
        perms = sorted({p for p in GRANTED.findall(dump) if p in SPY_PERMISSIONS})
        revoked = [p for p in perms if not self.sh(f"pm revoke --user {self.user} {self.pkg} {p}").strip()]
        if revoked:
            cut.append(f"{len(revoked)} permissão(ões) (" + ", ".join(p.rsplit(".", 1)[1] for p in revoked) + ")")
        for op in SPY_APPOPS:
            self.sh(f"cmd appops set --user {self.user} {self.pkg} {op} ignore")
        cut.append("sobreposição e gravação da tela, uso de apps e execução em segundo plano")
        self.remove_admin()
        self.sh(f"am force-stop --user {self.user} {self.pkg}")
        message = ("Acessos cortados: " + "; ".join(cut) + ". O app continua instalado (as evidências são "
                   "preservadas), mas foi parado. Se ele pedir acesso de novo, não conceda.")
        if self.candidate.get("device_admin"):
            return "manual", message + " " + MSG_ADMIN
        return "ok", message

    def uninstall(self):
        self.remove_admin()
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


def perform(device, report_dir, candidate, action, keep_apk=True, via="individual"):
    """Executa a ação pedida. Devolve o registro {status, message, ...}, também salvo em acoes.jsonl.
    `via`: "individual" (assistente de um app) ou "plano" (plano de limpeza aprovado pelo usuário)."""
    if action not in ACTIONS:
        raise ValueError("ação inválida")
    if not is_package_name(candidate["package"]):
        raise ValueError("nome de pacote inválido")

    job = _Action(device, report_dir, candidate, action)
    job.entry["via"] = "plano" if via == "plano" else "individual"
    try:
        if not job.is_installed():
            return job.save("nao_instalado", "O app não está mais instalado neste aparelho.")
        if keep_apk and action != "enable":
            job.backup_apk()
        status, message = getattr(job, action)()
        return job.save(status, message)
    except AdbError as e:
        return job.save("falhou", f"Erro de comunicação com o aparelho: {e}")
