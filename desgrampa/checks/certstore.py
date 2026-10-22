"""Certificados de segurança (CA) usados para interceptar conexões HTTPS.

Sem root não dá para listar os certificados instalados pelo usuário diretamente. Usamos sinais
indiretos: o aviso "A rede pode estar sendo monitorada" que o próprio Android exibe, certificados
instalados por administrador/MDM, e adulteração do repositório de certificados do sistema.
"""

import re
import shlex
from collections import Counter

from . import Finding
from .device import parse_mounts

NAME = "Certificados de interceptação (HTTPS)"
CATEGORY = "intercept"

SYSTEM_STORES = ["/system/etc/security/cacerts", "/apex/com.android.conscrypt/cacerts"]
INTERCEPTION_NAMES = re.compile(
    r"\b(?:mitmproxy|portswigger|burp|charles|fiddler|http ?toolkit|proxyman|telerik|"
    r"do_not_trust|superfish|zscaler|netskope|fortinet|fortigate|palo ?alto|blue ?coat|"
    r"kaspersky|eset|avast|avg|bitdefender|sophos|cisco umbrella|untangle|forcepoint)\b", re.I)
# Notificação do sistema SystemMessage.NOTE_SSL_CERT_INFO (id 33) publicada pelo pacote "android"
CA_WARNING = re.compile(r"\|android\|33\||ssl_ca_cert_warning|network may be monitored|"
                        r"rede pode (?:estar sendo|ser) monitorada", re.I)


def _subject(text):
    m = re.search(r"Subject:\s*(.+)", text) or re.search(r"subject=\s*(.+)", text)
    return m.group(1).strip() if m else None


def _user_certificates(ctx, info):
    """Certificados instalados pelo usuário (via aviso do sistema) ou por um administrador/MDM."""
    findings = []
    notifications = ctx.try_sh("dumpsys notification --noredact", timeout=90) or ctx.try_sh("dumpsys notification")
    if CA_WARNING.search(notifications):
        info["user_ca_warning"] = True
        findings.append(Finding(
            "alta", "Certificado de segurança instalado (rede pode ser monitorada)",
            "O próprio Android está exibindo o aviso “A rede pode estar sendo monitorada”, que aparece "
            "quando um certificado de autoridade (CA) foi instalado manualmente. Com ele, quem controla "
            "o certificado pode ler conexões HTTPS (sites, alguns apps) se o tráfego passar por ele.",
            "Veja em Configurações > Segurança > Criptografia e credenciais > Credenciais confiáveis > "
            "Usuário. Remova o que você não reconhece."))
    owner = ctx.device_policy.get("owner_ca_certs", [])
    if owner:
        info["owner_ca_certs"] = owner
        findings.append(Finding(
            "alta", "Certificado instalado por administrador/MDM",
            f"{len(owner)} certificado(s) de segurança foram instalados por um app administrador: "
            + ", ".join(owner[:5]) + ".",
            "Normal apenas em aparelho corporativo. Em aparelho pessoal, remova o administrador."))
    return findings


def _store_outliers(entries):
    """Num firmware original todos os certificados têm a mesma data; um arquivo diferente foi adicionado depois."""
    mtimes = Counter(mtime for mtime, _ in entries)
    common, count = mtimes.most_common(1)[0]
    if len(mtimes) == 1 or count <= len(entries) * 0.8:
        return []
    return [path for mtime, path in entries if mtime != common]


def _system_store(ctx, store, info):
    """Certificados adicionados ao repositório do sistema e, na completa, certificados de ferramentas de inspeção."""
    listing = ctx.try_sh(f"stat -c '%Y %n' {store}/* 2>/dev/null")
    entries = [tuple(line.split(" ", 1)) for line in listing.splitlines() if " " in line]
    if not entries:
        return []
    info["stores"][store] = len(entries)
    findings = []

    outliers = _store_outliers(entries)
    injected = [{"path": path, "subject": _subject(ctx.try_sh(f"cat {shlex.quote(path)}")) or path.rsplit("/", 1)[-1]}
                for path in outliers[:20]]
    info["injected"].extend(injected)
    if injected:
        findings.append(Finding(
            "alta", "Certificado adicionado ao repositório do sistema",
            f"{len(injected)} certificado(s) em {store} têm data diferente dos originais do firmware: "
            + "; ".join(c["subject"] for c in injected[:5]) + ". Certificados no repositório do sistema "
            "permitem interceptar praticamente qualquer app.",
            "Só é possível com root. Restaure o firmware oficial."))

    if ctx.full:
        subjects = (_subject(ctx.try_sh(f"head -c 4000 {shlex.quote(path)}")) or ""
                    for _, path in entries if path not in outliers)
        named = [subject for subject in subjects if INTERCEPTION_NAMES.search(subject)]
        if named:
            findings.append(Finding(
                "alta", "Certificado de ferramenta de interceptação no sistema",
                "Certificados de produtos de inspeção de tráfego no repositório do sistema: "
                + "; ".join(named[:5]) + ".",
                "Esses certificados não vêm de fábrica. Restaure o firmware oficial."))
    return findings


def run(ctx):
    info = {"user_ca_warning": False, "owner_ca_certs": [], "stores": {}, "injected": []}
    findings = _user_certificates(ctx, info)

    mounted = [m.point for m in parse_mounts(ctx.cached_sh("cat /proc/mounts")) if "cacerts" in m.point]
    if mounted:
        findings.append(Finding(
            "alta", "Repositório de certificados do sistema substituído",
            "Há uma montagem sobre a pasta de certificados do sistema (" + ", ".join(mounted) + "). "
            "Essa técnica é usada para fazer o aparelho confiar em certificados de interceptação.",
            "Indica root/modificação. Salve as evidências e restaure o firmware oficial."))

    for store in SYSTEM_STORES:
        findings += _system_store(ctx, store, info)
    ctx.data["intercept"] = info
    return findings
