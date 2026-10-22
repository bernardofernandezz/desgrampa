"""Coleta de dados do aparelho (com cache) e parsers das saídas de `adb shell`.

Os parsers são funções puras para poderem ser testadas com saídas gravadas.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from .adb import AdbError
from .util import DAY

OFFICIAL_STORES = {
    "com.android.vending",            # Google Play
    "com.google.android.feedback",    # Google Play (antigo)
    "com.amazon.venezia",             # Amazon Appstore
    "com.sec.android.app.samsungapps",  # Galaxy Store
    "com.huawei.appmarket",
    "com.xiaomi.market",
    "com.xiaomi.mipicks",
    "com.heytap.market",
    "com.oppo.market",
    "com.vivo.appstore",
    "com.motorola.ccc.ota",
    "com.xiaomi.discover",            # atualizador de apps do sistema Xiaomi
    "com.miui.global.packageinstaller",
}
ALT_STORES = {
    "org.fdroid.fdroid": "F-Droid", "org.fdroid.basic": "F-Droid", "com.aurora.store": "Aurora Store",
    "com.uptodown": "Uptodown", "com.apkpure.aegon": "APKPure", "cm.aptoide.pt": "Aptoide",
    "com.happymod.apk": "HappyMod", "com.looker.droidify": "Droid-ify", "dev.imranr.obtainium": "Obtainium",
}
MANUAL_INSTALLERS = {None, "com.google.android.packageinstaller", "com.android.packageinstaller",
                     "com.miui.packageinstaller", "com.samsung.android.packageinstaller", "adb", "com.android.shell"}


class SkipCheck(Exception):
    """Lançada por uma verificação que não pode rodar neste aparelho/modo."""


@dataclass
class PackageInfo:
    name: str
    path: str = ""
    installer: str | None = None
    uid: int | None = None
    third_party: bool = False
    requested: set = field(default_factory=set)
    granted: set = field(default_factory=set)
    appops: set = field(default_factory=set)       # ops liberadas (GET_USAGE_STATS, SYSTEM_ALERT_WINDOW...)
    first_install: str | None = None
    has_launcher: bool | None = None               # None = não foi possível verificar
    battery_whitelisted: bool = False
    code_path: str | None = None
    system_flag: bool = False
    shared_user: str | None = None
    version: str | None = None                     # versionName

    @property
    def sideloaded(self):
        return self.third_party and (self.installer or "null") not in OFFICIAL_STORES

    @property
    def manual_install(self):
        """Instalado a partir de um arquivo APK (não por loja, nem alternativa)."""
        return self.third_party and self.installer in MANUAL_INSTALLERS


# ---------------------------------------------------------------- parsers

def parse_getprop(out):
    return dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", out, re.M))


def parse_pm_list(out):
    """`pm list packages -f -i -U` -> {pkg: (path, installer, uid)}"""
    result = {}
    for line in out.splitlines():
        # o caminho pode conter '=' (ex.: /data/app/~~aGVsbG8=/...), mas nunca espaços
        m = re.match(r"^package:(\S+)=([\w.]+)(?:\s+installer=(\S+))?(?:\s+uid:(\d+))?", line.strip())
        if m:
            installer = m.group(3)
            result[m.group(2)] = (
                m.group(1),
                None if installer in (None, "null") else installer,
                int(m.group(4)) if m.group(4) else None,
            )
    return result


def parse_package_names(out):
    return {line.strip()[8:] for line in out.splitlines() if line.strip().startswith("package:")}


# linhas "chave=valor" do dumpsys package -> campo do resultado (só o primeiro valor de cada pacote vale)
DUMPSYS_FIELDS = {"firstInstallTime": "first_install", "codePath": "code_path", "userId": "app_id", "appId": "app_id",
                  "versionName": "version"}
PERMISSION_SECTIONS = {"requested permissions:": "requested", "install permissions:": "install",
                       "runtime permissions:": "runtime"}
PERMISSION_LINE = re.compile(r"^(\w+\.[\w.]+)(?::\s*granted=(true|false))?(?:[,:\s]|$)")


def _leading_int(text):
    digits = re.match(r"\d+", text)
    return int(digits.group()) if digits else None


def _new_package_entry():
    return {"requested": set(), "granted": set(), "first_install": None, "code_path": None,
            "system": False, "shared_user": None, "app_id": None, "version": None}


def parse_dumpsys_package(out):
    """`dumpsys package packages` -> {pkg: {requested, granted, first_install, code_path, system,
    shared_user, app_id, version}}"""
    packages, cur, section = {}, None, None
    for line in out.splitlines():
        if line.startswith("Hidden system packages:"):
            break
        header = re.match(r"^  Package \[([^\]]+)\]", line)
        if header:
            cur, section = packages.setdefault(header.group(1), _new_package_entry()), None
            continue
        if cur is None:
            continue
        text = line.strip()
        key, _, value = text.partition("=")

        if text in PERMISSION_SECTIONS:
            section = PERMISSION_SECTIONS[text]
        elif key in DUMPSYS_FIELDS:
            field_name = DUMPSYS_FIELDS[key]
            if cur[field_name] is None:
                cur[field_name] = _leading_int(value) if field_name == "app_id" else value
        elif key in ("flags", "pkgFlags") and section is None:
            cur["system"] = cur["system"] or " SYSTEM " in value
        elif key == "sharedUser":
            shared = re.search(r"\s([\w.]+)/\d+\}", value)
            cur["shared_user"] = shared.group(1) if shared else value
        elif section:
            perm = PERMISSION_LINE.match(text)
            if not perm:
                section = None   # qualquer linha que não seja "nome.da.permissao[: granted=...]" encerra a seção
            elif section == "requested":
                cur["requested"].add(perm.group(1))
            elif perm.group(2) == "true":
                cur["granted"].add(perm.group(1))
    return packages


def parse_hidden_system_packages(out):
    """Pacotes de sistema que receberam atualização (a versão original fica 'escondida')."""
    idx = out.find("Hidden system packages:")
    if idx < 0:
        return set()
    return set(re.findall(r"^  Package \[([^\]]+)\]", out[idx:], re.M))


def parse_components(value):
    """Valor de settings 'pkg/cls:pkg2/cls2' -> [(pkg, componente)]"""
    value = (value or "").strip()
    if not value or value == "null":
        return []
    result = []
    for raw in value.split(":"):
        comp = raw.strip()
        if "/" in comp:
            result.append((comp.split("/", 1)[0], comp))
    return result


def parse_launcher_packages(out):
    return set(re.findall(r"^\s*([\w.]+)/[\w.$]+\s*$", out, re.M))


def parse_device_policy(out):
    admins, profile_owners, components = [], [], []
    device_owner = None
    m = re.search(r"Device Owner:\s*\n(?:.*\n){0,3}?\s*admin=ComponentInfo\{([^/}]+)/", out)
    if m:
        device_owner = m.group(1)
    for m in re.finditer(r"Profile Owner[^\n]*:\s*\n(?:.*\n){0,3}?\s*admin=ComponentInfo\{([^/}]+)/", out):
        profile_owners.append(m.group(1))
    in_admins = False
    for line in out.splitlines():
        if re.match(r"^\s*Enabled Device Admins", line):
            in_admins = True
            continue
        if in_admins:
            m = re.match(r"^\s+ComponentInfo\{([^/}]+)/([^}]*)\}:?\s*$", line)
            if m:
                if m.group(1) not in admins:
                    admins.append(m.group(1))
                component = f"{m.group(1)}/{m.group(2)}"
                if component not in components:
                    components.append(component)
            elif line.strip() and not line.startswith("    "):
                in_admins = False
    ca = re.findall(r"(?:mOwnerInstalledCaCerts|ownerInstalledCaCerts|mAcceptedCaCertificates)\s*[=:]\s*\[([^\]]+)\]", out)
    return {"admins": admins, "admin_components": components, "device_owner": device_owner,
            "profile_owners": profile_owners,
            "owner_ca_certs": [c.strip() for group in ca for c in group.split(",") if c.strip()]}


def parse_appops_query(out):
    """`cmd appops query-op OP allow` -> conjunto de pacotes"""
    return {line.strip() for line in out.splitlines() if re.match(r"^[\w.]+$", line.strip()) and "." in line}


def parse_deviceidle_whitelist(out):
    """`dumpsys deviceidle whitelist` -> pacotes adicionados pelo usuário (linhas 'user,pkg,uid')"""
    return {m.group(1) for m in re.finditer(r"^user,([\w.]+),", out, re.M)}


def parse_ps(out):
    """`ps -A -o USER,PID,NAME` -> [(user, pid, name)]"""
    procs = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[1].isdigit():
            procs.append((parts[0], int(parts[1]), parts[2].strip()))
    return procs


def parse_users(out):
    """`pm list users` -> [{id, name, flags, running}]"""
    return [{"id": int(m.group(1)), "name": m.group(2), "flags": m.group(3), "running": bool(m.group(4))}
            for m in re.finditer(r"UserInfo\{(\d+):([^:]*):([0-9a-fA-F]+)\}( running)?", out)]


_DURATION = re.compile(r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m(?!s))?(?:(\d+)s)?(?:(\d+)ms)?")


def duration_seconds(text):
    m = _DURATION.fullmatch(text)
    if not m or not any(m.groups()):
        return None
    d, h, mi, s, _ = (int(g) if g else 0 for g in m.groups())
    return d * DAY + h * 3600 + mi * 60 + s


def parse_appops_usage(out):
    """`cmd appops get <pkg>` -> {OP: {"ago": segundos desde o último uso, "background": bool}}

    Aceita os dois formatos conhecidos:
      RECORD_AUDIO: allow; time=+2h3m4s5ms ago            (Android <= 10)
      RECORD_AUDIO (allow):\\n  Access: [bg-s] 2024-.. (-2h3m4s5ms)   (Android 11+)
    """
    usage = {}
    op = None
    for line in out.splitlines():
        m = re.match(r"^\s*([A-Z_]{3,})(?: \([\w ]+\))?:", line)
        if m:
            op = m.group(1)
        if not op:
            continue
        t = re.search(r"time=\+([\dhdms]+) ago", line) or (
            re.search(r"\(-([\dhdms]+)\)", line) if "Access" in line else None)
        if not t:
            continue
        ago = duration_seconds(t.group(1))
        if ago is None:
            continue
        entry = usage.setdefault(op, {"ago": ago, "background": False})
        entry["ago"] = min(entry["ago"], ago)
        if "[bg" in line:
            entry["background"] = True
    return usage


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global


# ---------------------------------------------------------------- contexto

class ScanContext:
    def __init__(self, device, iocs, mode="rapida", progress=None, options=None):
        self.device = device
        self.iocs = iocs
        self.mode = mode
        self.options = options or {}
        self.progress = progress or (lambda _msg: None)
        self.notes = []          # limitações encontradas (comandos indisponíveis etc.)
        self.data = {}           # dados exibidos no dashboard, por categoria
        self.raw = {}            # saída bruta de cada comando (salva como evidência)
        self.evidence_dir = None
        # resultados que uma verificação produz para outra usar (ex.: risk usa os dois primeiros)
        self.apk_info = {}       # pacote -> {"sha256", "certificates"}  (certificates.py)
        self.sensor_usage = {}   # pacote -> uso recente de microfone/câmera/...  (activity.py)
        self.app_rows = []       # tabela de apps com pontuação  (risk.py)
        self.bulletins = None    # base de vulnerabilidades (bulletins.load); vulns.py carrega se faltar
        self._cache = {}

    @property
    def full(self):
        return self.mode == "completa"

    def sh(self, cmd, timeout=60):
        out = self.device.shell(cmd, timeout=timeout)
        self.raw[cmd] = out
        return out

    def try_sh(self, cmd, timeout=60):
        try:
            return self.sh(cmd, timeout=timeout) or ""
        except AdbError as e:
            self.notes.append(f"{cmd}: {e}")
            return ""

    def setting(self, namespace, key, user=None):
        flag = f"--user {user} " if user is not None else ""
        v = self.try_sh(f"settings {flag}get {namespace} {key}").strip()
        return None if v in ("", "null") else v

    def _cached(self, key, fn):
        if key not in self._cache:
            self._cache[key] = fn()
        return self._cache[key]

    def cached_sh(self, cmd, timeout=60):
        return self._cached(("sh", cmd), lambda: self.try_sh(cmd, timeout=timeout))

    @property
    def props(self):
        return self._cached("props", lambda: parse_getprop(self.sh("getprop")))

    @property
    def sdk(self):
        try:
            return int(self.props.get("ro.build.version.sdk", "0"))
        except ValueError:
            return 0

    @property
    def accessibility(self):
        return self._cached("a11y", lambda: parse_components(
            self.setting("secure", "enabled_accessibility_services")))

    @property
    def notification_listeners(self):
        return self._cached("nls", lambda: parse_components(
            self.setting("secure", "enabled_notification_listeners")))

    @property
    def accessibility_packages(self):
        return {pkg for pkg, _ in self.accessibility}

    @property
    def listener_packages(self):
        return {pkg for pkg, _ in self.notification_listeners}

    @property
    def device_policy(self):
        return self._cached("dpm", lambda: parse_device_policy(self.try_sh("dumpsys device_policy")))

    @property
    def users(self):
        return self._cached("users", lambda: parse_users(self.try_sh("pm list users")))

    @property
    def packages(self):
        return self._cached("packages", self._collect_packages)

    @property
    def hidden_system(self):
        _ = self.packages   # a lista de pacotes de sistema "escondidos" é coletada junto com os pacotes
        return self._cache["hidden_system"]

    def third_party(self):
        return [p for p in self.packages.values() if p.third_party]

    def package_by_uid(self, uid):
        appid = uid % 100000
        return self._cached("uidmap", lambda: {p.uid % 100000: p.name for p in self.packages.values()
                                               if p.uid is not None}).get(appid)

    def _collect_packages(self):
        self.progress("Listando aplicativos instalados")
        listing = parse_pm_list(self.sh("pm list packages -f -i -U"))
        if not listing:
            listing = parse_pm_list(self.sh("pm list packages -f -i"))
        third = parse_package_names(self.sh("pm list packages -3"))

        self.progress("Lendo permissões de todos os aplicativos (pode demorar)")
        raw_dump = self.sh("dumpsys package packages", timeout=240)
        dump = parse_dumpsys_package(raw_dump)
        if not dump:
            raw_dump = self.sh("dumpsys package", timeout=240)
            dump = parse_dumpsys_package(raw_dump)
        self._cache["hidden_system"] = parse_hidden_system_packages(raw_dump)

        launcher_out = self.try_sh(
            "cmd package query-activities --brief -a android.intent.action.MAIN "
            "-c android.intent.category.LAUNCHER")
        launcher = parse_launcher_packages(launcher_out) if launcher_out else set()
        if not launcher:
            self.notes.append("Não foi possível listar apps com ícone no launcher (Android antigo?)")

        appops = {}
        for op in ("GET_USAGE_STATS", "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
                   "MANAGE_EXTERNAL_STORAGE"):
            for pkg in parse_appops_query(self.try_sh(f"cmd appops query-op --user 0 {op} allow")):
                appops.setdefault(pkg, set()).add(op)

        whitelist = parse_deviceidle_whitelist(self.try_sh("dumpsys deviceidle whitelist"))

        packages = {}
        for name, (path, installer, uid) in listing.items():
            d = dump.get(name, {})
            packages[name] = PackageInfo(
                name=name, path=path, installer=installer,
                uid=uid if uid is not None else d.get("app_id"),
                third_party=name in third,
                requested=d.get("requested", set()),
                granted=d.get("granted", set()),
                appops=appops.get(name, set()),
                first_install=d.get("first_install"),
                has_launcher=(name in launcher) if launcher else None,
                battery_whitelisted=name in whitelist,
                code_path=d.get("code_path"),
                system_flag=d.get("system", False),
                shared_user=d.get("shared_user"),
                version=d.get("version"),
            )
        return packages
