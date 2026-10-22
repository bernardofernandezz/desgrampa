"""Telefonia: desvio de chamadas, rede 2G (ERB falsa), operadora, apps padrão de SMS/telefone."""

import re

from ..util import is_package_name
from . import Finding, app_label

NAME = "Telefonia e SIM"
CATEGORY = "telefonia"

KNOWN_SMS_DIALER = {
    "com.google.android.apps.messaging", "com.samsung.android.messaging", "com.android.mms",
    "com.android.messaging", "com.google.android.dialer", "com.samsung.android.dialer",
    "com.android.dialer", "com.android.contacts", "com.android.server.telecom",
    "com.miui.securitycenter", "com.android.incallui", "com.oneplus.mms", "com.motorola.messaging",
    "com.truecaller", "org.thoughtcrime.securesms", "com.textra",
}
ROLES = {
    "android.app.role.SMS": "app padrão de SMS",
    "android.app.role.DIALER": "app padrão de telefone",
    "android.app.role.CALL_REDIRECTION": "app de redirecionamento de chamadas",
    "android.app.role.CALL_SCREENING": "app de triagem de chamadas",
}


def role_holders(ctx, role):
    out = ctx.try_sh(f"cmd role get-role-holders --user 0 {role}")
    return [line.strip() for line in out.splitlines() if is_package_name(line.strip())]


def run(ctx):
    findings = []
    p = ctx.props
    reg = ctx.try_sh("dumpsys telephony.registry", timeout=60)

    forwarding = "mCallForwarding=true" in reg
    if forwarding:
        findings.append(Finding(
            "alta", "Desvio de chamadas ativo",
            "O aparelho indica desvio de chamadas incondicional: suas ligações estão sendo "
            "encaminhadas para outro número sem tocar no seu celular.",
            "Disque *#21# para ver o número de destino e ##002# para cancelar todos os desvios. "
            "Se não foi você, avise a operadora (pode indicar clonagem/troca de chip)."))

    rat = re.findall(r"(?:RadioTechnology=\d+\(|accessNetworkTechnology=|NetworkType=)(GSM|GPRS|EDGE)\b", reg)
    if rat:
        findings.append(Finding(
            "media", "Conectado em rede 2G agora",
            f"O aparelho está usando rede {rat[0]} (2G). O 2G não autentica a antena e tem criptografia "
            "fraca; equipamentos de interceptação (“IMSI catchers”/ERB falsa) forçam o celular para 2G.",
            "Se o seu Android permitir, desligue “Permitir 2G” em Configurações > Rede > Chip. "
            "Se acontecer sempre no mesmo lugar onde há boa cobertura 4G/5G, desconfie."))

    sim_num = (p.get("gsm.sim.operator.numeric") or "").split(",")
    net_num = (p.get("gsm.operator.numeric") or "").split(",")
    roaming = (p.get("gsm.operator.isroaming") or "").split(",")
    sim_name = (p.get("gsm.sim.operator.alpha") or "").split(",")
    net_name = (p.get("gsm.operator.alpha") or "").split(",")
    slots = []
    for i, sim in enumerate(sim_num):
        if not sim.strip():
            continue
        net = net_num[i] if i < len(net_num) else ""
        roam = roaming[i] if i < len(roaming) else ""
        slots.append({"slot": i + 1, "sim": sim_name[i] if i < len(sim_name) else "", "sim_code": sim,
                      "network": net_name[i] if i < len(net_name) else "", "network_code": net,
                      "roaming": roam == "true"})
        if net and sim[:3] != net[:3] and roam != "true":
            findings.append(Finding(
                "media", "Rede de outro país sem roaming",
                f"Chip {i + 1}: o chip é do país {sim[:3]}, mas está registrado na rede {net} "
                f"({net_name[i] if i < len(net_name) else '?'}), sem indicar roaming. Pode indicar "
                "uma antena falsa.",
                "Observe se isso se repete em locais específicos. Desligue o 2G se possível."))

    roles = {}
    for role, label in ROLES.items():
        holders = role_holders(ctx, role)
        roles[label] = holders
        for pkg in holders:
            app = ctx.packages.get(pkg)
            if pkg in KNOWN_SMS_DIALER or (app and not app.third_party):
                continue
            sideloaded = app is None or app.sideloaded
            severity = "alta" if sideloaded else "media" if role.endswith("REDIRECTION") else "baixa"
            findings.append(Finding(
                severity, f"App de terceiro como {label}",
                f"{app_label(ctx, pkg)} é o {label}. Ele "
                + ("pode desviar suas ligações para outro número."
                   if role.endswith("REDIRECTION") else "tem acesso a todas as suas ligações/mensagens."),
                "Se não reconhece, troque em Configurações > Apps > Apps padrão.", package=pkg))
    if not any(roles.values()):
        sms = ctx.setting("secure", "sms_default_application")
        roles["app padrão de SMS"] = [sms] if sms else []

    ctx.data["telefonia"] = {"call_forwarding": forwarding, "radio_2g": rat[0] if rat else None,
                             "slots": slots, "roles": roles}
    return findings
