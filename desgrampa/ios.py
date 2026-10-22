"""iPhone: backup local + MVT (`mvt-ios check-backup`) e checagem da versão do iOS.

O iPhone não tem nada parecido com o ADB: a forma de olhar dentro dele sem jailbreak é o backup
local, o mesmo que o Finder/iTunes fazem. O Desgrampa pode:
- gerar o backup pelo cabo com o libimobiledevice (idevicebackup2), ou
- analisar uma pasta de backup já feita no Finder (Mac) ou no iTunes/Dispositivos Apple (Windows).

O backup criptografado traz muito mais dados (por isso o MVT recomenda ativá-lo); a senha é passada
ao MVT pela variável MVT_IOS_BACKUP_PASSWORD, nunca na linha de comando.
"""

import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import evidence, grouping, oscompat
from . import iocs as iocs_mod
from .checks import CATEGORIES, SEVERITIES, Finding, mvt
from .paths import DATA_DIR, REPO_DIR
from .scanner import verdict

# Áreas que fazem sentido para um backup de iPhone
IOS_CATEGORIES = ("spyware", "mercenario", "controle", "vulns")
BACKUP_TIMEOUT_S = 3 * 3600
MVT_TIMEOUT_S = 3600
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


class IosError(Exception):
    pass


# ---------------------------------------------------------------- ferramentas

def tool(name):
    return oscompat.find_tool(name)


def mvt_ios_path():
    for candidate in (os.environ.get("DESGRAMPA_MVT_IOS"), oscompat.venv_script(sys.prefix, "mvt-ios"),
                      oscompat.venv_script(REPO_DIR / ".venv", "mvt-ios"), shutil.which("mvt-ios")):
        if candidate and Path(candidate).exists():
            return str(candidate)
    return None


def status():
    return {"idevice": bool(tool("idevice_id") and tool("idevicebackup2")), "mvt": bool(mvt_ios_path())}


def _run(cmd, timeout=60, env=None):
    try:
        return oscompat.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise IosError(f"tempo esgotado: {Path(cmd[0]).name}")
    except OSError as e:
        raise IosError(f"não foi possível executar {Path(cmd[0]).name}: {e.strerror or e}")


def list_devices():
    """iPhones conectados pelo cabo: [{udid, state, name, model, version}] (state: ok | sem_confianca)."""
    idevice_id = tool("idevice_id")
    if not idevice_id:
        return []
    udids = [u.strip() for u in _run([idevice_id, "-l"], timeout=15).stdout.split() if u.strip()]
    devices = []
    for udid in udids:
        info = parse_ideviceinfo(_run([tool("ideviceinfo"), "-u", udid], timeout=15).stdout) if tool("ideviceinfo") else {}
        devices.append({"udid": udid, "state": "ok" if info.get("ProductType") else "sem_confianca",
                        "name": info.get("DeviceName"), "model": info.get("ProductType"),
                        "version": info.get("ProductVersion")})
    return devices


def parse_ideviceinfo(out):
    return dict(re.findall(r"^(\w+): (.*)$", out, re.M))


# ---------------------------------------------------------------- backup

def make_backup(udid, dest, progress):
    """Backup completo pelo cabo. Devolve a pasta do backup (dest/<udid>)."""
    backup_tool = tool("idevicebackup2")
    if not backup_tool:
        raise IosError("libimobiledevice não instalado (idevicebackup2)")
    if not re.fullmatch(r"[0-9A-Fa-f-]{20,64}", udid or ""):
        raise IosError("identificador de iPhone inválido")
    progress("Fazendo o backup do iPhone pelo cabo (pode levar de 10 minutos a mais de 1 hora)")
    dest.mkdir(parents=True, exist_ok=True)
    proc = _run([backup_tool, "-u", udid, "backup", "--full", str(dest)], timeout=BACKUP_TIMEOUT_S)
    folder = dest / udid
    if proc.returncode != 0 or not (folder / "Manifest.db").exists():
        raise IosError("o backup não foi concluído. Desbloqueie o iPhone, toque em “Confiar” e tente de novo. "
                       + (proc.stderr.strip().splitlines() or [""])[-1])
    return folder


def _plist(path):
    try:
        return plistlib.loads(Path(path).read_bytes())
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def read_backup_info(folder):
    folder = Path(folder)
    info, manifest = _plist(folder / "Info.plist"), _plist(folder / "Manifest.plist")
    if not (folder / "Manifest.db").exists() and not manifest:
        raise IosError("a pasta escolhida não parece um backup de iPhone (falta Manifest.db/Manifest.plist)")
    last = info.get("Last Backup Date")
    return {"name": info.get("Device Name"), "model": info.get("Product Type"), "version": info.get("Product Version"),
            "build": info.get("Build Version"), "serial": info.get("Serial Number") or info.get("Unique Identifier"),
            "udid": info.get("Unique Identifier"), "encrypted": bool(manifest.get("IsEncrypted")),
            "last_backup": last.strftime("%Y-%m-%d %H:%M") if hasattr(last, "strftime") else None}


# ---------------------------------------------------------------- versão do iOS

def vkey(version):
    return tuple(int(x) for x in re.findall(r"\d+", version or ""))


def ios_status(db, model, version):
    """Versão instalada x versão mais nova disponível para o modelo e falhas da Apple exploradas desde então."""
    ios = (db or {}).get("ios") or {}
    if not ios or not version:
        return None
    versions, devices = ios.get("versions", {}), ios.get("devices", {})
    best = devices.get(model)
    latest = ios.get("latest")
    newer_dates = [d for v, d in versions.items() if vkey(v) > vkey(version) and d]
    since = min(newer_dates) if newer_dates else None
    if since is None and best and vkey(best) > vkey(version):
        since = min((d for d in versions.values() if d), default=None)
    exploited = [k["cve"] for k in db.get("kev_apple", []) if since and k["added"] >= since]
    # a Apple só garante todas as correções na versão principal mais nova (e parte delas na anterior)
    supported = best is not None and latest is not None and vkey(best)[0] >= vkey(latest)[0] - 1
    return {"model": model, "version": version, "best_for_model": best, "latest": latest,
            "update_available": bool(best and vkey(best) > vkey(version)), "exploited": exploited,
            "supported": supported, "known_model": best is not None}


def version_findings(st):
    if not st:
        return []
    findings = []
    if st["update_available"]:
        n = len(st["exploited"])
        findings.append(Finding(
            "alta" if n else "media", f"iOS desatualizado ({st['version']})",
            f"Este iPhone pode ser atualizado para o iOS {st['best_for_model']}. "
            + (f"Desde a sua versão, {n} falhas da Apple entraram na lista de exploradas ativamente da CISA "
               f"({', '.join(st['exploited'][:6])}{'…' if n > 6 else ''}). Spywares como Pegasus e Predator "
               "exploram exatamente esse tipo de falha." if n else ""),
            "Atualize em Ajustes › Geral › Atualização de Software e ative as atualizações automáticas.",
            category="vulns"))
    if st["known_model"] and not st["supported"]:
        findings.append(Finding(
            "media", "iPhone sem atualizações de segurança atuais",
            f"A versão mais nova disponível para este modelo é a {st['best_for_model']}, bem atrás do iOS "
            f"{st['latest']}. Falhas descobertas daqui em diante podem não ser corrigidas.",
            "Considere trocar de aparelho. Até lá, evite links e anexos de desconhecidos.", category="vulns"))
    return findings


# ---------------------------------------------------------------- varredura

class _Ctx:
    """O mínimo que o leitor de alertas do MVT precisa (ele foi escrito para o Android)."""

    def __init__(self, iocs):
        self.iocs = iocs
        self.packages = {}


def _categories(findings, check_status):
    result = []
    for cid, title, description in CATEGORIES:
        if cid not in IOS_CATEGORIES:
            continue
        mine = [f for f in findings if f.category == cid]
        checks = [c for c in check_status if c["category"] == cid]
        worst = next((s for s in ("critica", "alta", "media", "baixa") if any(f.severity == s for f in mine)), None)
        ran = any(c["status"] == "ok" for c in checks)
        result.append({"id": cid, "title": title, "description": description,
                       "status": worst or ("ok" if ran else "nao_verificado"),
                       "counts": {s: sum(f.severity == s for f in mine) for s in SEVERITIES}, "checks": checks})
    return result


def _profiles_findings(out_dir):
    """Perfis de configuração instalados (MDM/proxy/certificados) aparecem no módulo ConfigurationProfiles."""
    path = Path(out_dir) / "configuration_profiles.json"
    try:
        profiles = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [], []
    names = [p.get("plist", {}).get("PayloadDisplayName") or p.get("plist", {}).get("PayloadIdentifier") or "?"
             for p in profiles if isinstance(p, dict)]
    findings = [Finding(
        "alta", "Perfil de configuração instalado no iPhone",
        f"Perfis encontrados: {', '.join(names)}. Perfis podem instalar certificados, proxy, VPN ou gerenciamento "
        "remoto (MDM) e são usados para interceptar e controlar o aparelho.",
        "Confira em Ajustes › Geral › VPN e Gerenciamento de Dispositivos. Se não reconhece, remova "
        "depois de guardar o relatório.", category="controle")] if names else []
    return findings, names


def run_scan(iocs, bulletins=None, udid=None, backup_dir=None, password=None, on_progress=None, case=None):
    """Analisa um iPhone (backup novo pelo cabo ou pasta existente) e devolve um resultado no mesmo
    formato da varredura Android, salvo em uma pasta de evidências."""
    progress = on_progress or (lambda _fraction, _step: None)
    started = time.time()
    folder_name = udid or (Path(backup_dir).name if backup_dir else "iphone")
    base = evidence.new_dir(f"iPhone_{folder_name}", started, prefix=case)
    notes, check_status, findings = [], [], []

    if backup_dir:
        source = Path(backup_dir).expanduser()
        if not source.is_dir():
            raise IosError("pasta de backup não encontrada")
        progress(0.05, "Lendo o backup informado")
    else:
        source = make_backup(udid, base / "backup", lambda step: progress(0.1, step))
    info = read_backup_info(source)

    mvt_path = mvt_ios_path()
    out_dir = base / "mvt"
    out_dir.mkdir(exist_ok=True)
    alerts = []
    if not mvt_path:
        check_status.append({"name": "Análise forense MVT (iOS)", "category": "mercenario", "status": "skipped",
                             "reason": 'MVT não instalado (pip install "desgrampa[forense]")'})
    else:
        env = {**os.environ, "MVT_DATA_FOLDER": str(DATA_DIR / "mvt")}
        target = source
        if info["encrypted"]:
            if not password:
                raise IosError("este backup é criptografado: informe a senha do backup para analisá-lo")
            progress(0.4, "Descriptografando o backup (a senha não é guardada)")
            target = base / "backup_descriptografado"
            proc = _run([mvt_path, "decrypt-backup", "-d", str(target), str(source)], timeout=MVT_TIMEOUT_S,
                        env={**env, "MVT_IOS_BACKUP_PASSWORD": password})
            if proc.returncode != 0 or not (target / "Manifest.db").exists():
                raise IosError("não foi possível descriptografar o backup: confira a senha")
        progress(0.6, "Analisando o backup com o MVT (Anistia Internacional)")
        cmd = [mvt_path, "--disable-update-check", "--disable-indicator-update-check", "check-backup", "-o", str(out_dir)]
        for f in iocs_mod.stix_files():
            cmd += ["-i", str(f)]
        proc = _run([*cmd, str(target)], timeout=MVT_TIMEOUT_S, env=env)
        (out_dir / "mvt.log").write_text(proc.stdout + "\n" + proc.stderr, encoding="utf-8")
        alerts, mvt_findings = mvt.parse_alerts(_Ctx(iocs), out_dir)
        for f in mvt_findings:
            f.category = f.category or "mercenario"
            f.check = "Análise forense MVT (iOS)"
        findings += mvt_findings
        check_status.append({"name": "Análise forense MVT (iOS)", "category": "mercenario", "status": "ok", "reason": None})
        check_status.append({"name": "Apps de espionagem conhecidos (MVT)", "category": "spyware", "status": "ok", "reason": None})
        profile_findings, profiles = _profiles_findings(out_dir)
        for f in profile_findings:
            f.check = "Perfis de configuração"
        findings += profile_findings
        check_status.append({"name": "Perfis de configuração", "category": "controle", "status": "ok", "reason": None})
        if target != source:
            shutil.rmtree(target, ignore_errors=True)   # não deixar uma cópia aberta do backup no disco
        if not info["encrypted"]:
            notes.append("Backup sem criptografia: o iOS deixa de fora dados importantes (histórico de chamadas, "
                         "Saúde, chaves). Para uma análise mais completa, ative “Criptografar backup local” e repita.")

    progress(0.9, "Verificando a versão do iOS")
    st = ios_status(bulletins, info["model"], info["version"])
    for f in version_findings(st):
        f.check = "Versão do iOS"
        findings.append(f)
    check_status.append({"name": "Versão do iOS", "category": "vulns", "status": "ok" if st else "skipped",
                         "reason": None if st else "base de versões do iOS ausente"})

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.title))
    categories = _categories(findings, check_status)
    result = {
        "platform": "ios",
        "mode": "iphone",
        "options": {"backup": "existente" if backup_dir else "pelo cabo", "encrypted": info["encrypted"]},
        "started": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(started)),
        "duration_s": round(time.time() - started, 1),
        "device": {"platform": "ios", "serial": info["serial"] or folder_name, "manufacturer": "Apple",
                   "model": info["model"], "name": info["name"], "android": None, "ios": info["version"],
                   "security_patch": None, "build": info["build"], "fingerprint": None},
        "stats": {"packages": 0, "third_party": 0, "sideloaded": 0,
                  "checks_run": sum(c["status"] == "ok" for c in check_status), "checks_total": len(check_status),
                  "categories_verified": sum(c["status"] != "nao_verificado" for c in categories),
                  "categories_total": len(categories), "commands": 0},
        "iocs": iocs.summary(),
        "verdict": verdict(findings),
        "counts": {s: sum(f.severity == s for f in findings) for s in SEVERITIES},
        "categories": categories,
        "findings": [f.to_dict() for f in findings],
        "apps": [],
        "data": {"ios": {**info, "status": st, "mvt_alerts": len(alerts), "backup_folder": str(source)}},
        "notes": notes,
        "evidence_dir": str(base),
        "report_name": base.name,
    }
    grouping.enrich(result)
    evidence.save(base, result, {})
    return result
