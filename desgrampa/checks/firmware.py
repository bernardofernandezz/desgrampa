"""Firmware e apps de sistema: chaves públicas de teste, permissões privilegiadas, apps de sistema falsos."""

import os
import tempfile

from .. import apksig
from ..adb import AdbError
from . import PRIVILEGED_PERMISSIONS, Finding, app_label
from .packages import SYSTEM_PREFIXES

NAME = "Firmware e permissões privilegiadas"
CATEGORY = "sistema"

# Certificados públicos de teste do AOSP (build/target/product/security). Qualquer pessoa tem a
# chave privada: um firmware assinado com eles permite que QUALQUER app se passe por app de sistema.
AOSP_TEST_KEYS = {
    "27196E386B875E76ADF700E7EA84E4C6EEE33DFA": "platform",
    "61ED377E85D386A8DFEE6B864BD85B0BFAA5AF81": "testkey",
    "5B368CFF2DA2686996BC95EAC190EAA4F5630FE5": "shared",
    "B79DF4A82E90B57EA76525AB7037AB238A42F5D3": "media",
    "7C8BDABD21F953A1B18CCBE7B91393D9FDF94830": "networkstack",
}
SYSTEM_SHARED_USERS = {"android.uid.system", "android.uid.phone", "android.uid.shell",
                       "android.media", "android.uid.bluetooth", "android.uid.nfc"}


def platform_certificate(ctx):
    path = ctx.try_sh("pm path android").strip().removeprefix("package:").splitlines()
    if not path:
        return None
    with tempfile.TemporaryDirectory(prefix="desgrampa-") as tmp:
        local = os.path.join(tmp, "framework-res.apk")
        try:
            ctx.device.pull(path[0].strip(), local, timeout=180)
            certs = apksig.certificates(local)
        except (AdbError, OSError, ValueError, IndexError) as e:
            ctx.notes.append(f"Não foi possível ler o certificado da plataforma: {e}")
            return None
    return certs[0]["sha1"] if certs else None


def run(ctx):
    findings = []

    for app in sorted(ctx.third_party(), key=lambda p: p.name):
        privileged = [desc for perm, desc in PRIVILEGED_PERMISSIONS.items()
                      if perm in app.granted and perm != "android.permission.PACKAGE_USAGE_STATS"]
        if privileged and not app.sideloaded and app.name.startswith(SYSTEM_PREFIXES):
            privileged = []   # app do fabricante atualizado pela loja do fabricante (assinatura dele)
        if privileged:
            findings.append(Finding(
                "alta", "App com permissão privilegiada",
                f"{app_label(ctx, app.name)} recebeu permissões que apps comuns não conseguem: "
                + ", ".join(privileged) + ". Isso só acontece se alguém concedeu via cabo USB/ADB "
                "ou se o app é assinado pelo fabricante — passo típico na instalação de spyware.",
                "Se você não configurou isso, desinstale o app e revogue as autorizações de "
                "depuração USB (Opções do desenvolvedor).",
                package=app.name))
        if app.shared_user in SYSTEM_SHARED_USERS or (app.uid is not None and app.uid % 100000 < 10000):
            findings.append(Finding(
                "alta", "App de usuário rodando como sistema",
                f"{app_label(ctx, app.name)} roda com a identidade do sistema "
                f"({app.shared_user or f'uid {app.uid}'}), o que exige a chave do fabricante.",
                "Muito incomum para um app instalado pelo usuário. Investigue a origem.",
                package=app.name))

    hidden = ctx.hidden_system
    for app in ctx.packages.values():
        if app.system_flag and app.code_path and app.code_path.startswith("/data/") \
                and app.name not in hidden:
            findings.append(Finding(
                "alta", "App de sistema falso",
                f"{app.name} está marcado como app de sistema, mas foi instalado em {app.code_path} "
                "sem ser atualização de um app de fábrica.",
                "Indica manipulação do sistema. Salve as evidências e restaure o firmware oficial.",
                package=app.name))

    if ctx.full:
        ctx.progress("Verificando o certificado do firmware")
        cert = platform_certificate(ctx)
        ctx.data["platform_cert"] = cert
        if cert in AOSP_TEST_KEYS:
            findings.append(Finding(
                "alta", "Firmware assinado com chave pública de teste",
                f"O sistema é assinado com a chave “{AOSP_TEST_KEYS[cert]}” de teste do AOSP ({cert}). "
                "Essa chave é pública: qualquer pessoa pode criar um app que o aparelho aceita como "
                "parte do sistema, com acesso total.",
                "Comum em aparelhos genéricos/baratos e ROMs não oficiais. Para uso sensível, prefira "
                "um aparelho de fabricante com atualizações oficiais."))

    props = ctx.props
    for name in ctx.iocs.properties:
        if name in props:
            m = ctx.iocs.properties[name]
            findings.append(Finding(
                "critica", f"Propriedade de sistema ligada a spyware: {m.family}",
                f"A propriedade {name}={props[name]!r} existe neste aparelho e é indicador de {m}.",
                "Não apague nada. Salve as evidências e procure análise forense especializada.",
                category="mercenario"))
    return findings
