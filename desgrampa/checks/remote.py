"""Apps de acesso remoto, de localização/controle parental e assistente padrão."""

import re

from . import Finding, app_label

NAME = "Acesso remoto e localização"
CATEGORY = "controle"

REMOTE_ACCESS = {
    "com.teamviewer.quicksupport.market": "TeamViewer QuickSupport", "com.teamviewer.host.market": "TeamViewer Host",
    "com.teamviewer.teamviewer.market.mobile": "TeamViewer", "com.anydesk.anydeskandroid": "AnyDesk",
    "com.anydesk.adcontrol.ad1": "AnyDesk plugin", "com.carriez.flutter_hbb": "RustDesk",
    "com.splashtop.streamer.addon.knox": "Splashtop", "com.splashtop.sos": "Splashtop SOS",
    "com.sand.airdroid": "AirDroid", "com.sand.airdroidbiz": "AirDroid Business",
    "com.sand.airmirror": "AirMirror", "com.sand.airdroidkidp": "AirDroid Kids",
    "com.realvnc.viewer.android": "VNC Viewer", "com.realvnc.server": "VNC Server",
    "com.rsupport.mobizen.sec": "Mobizen", "com.koushikdutta.vysor": "Vysor",
    "com.microsoft.rdc.androidx": "Remote Desktop", "com.zoho.assist.agent": "Zoho Assist",
    "com.logmein.rescuemobile": "LogMeIn Rescue", "com.screenleap.android": "Screenleap",
    "com.apowersoft.mirror": "ApowerMirror", "com.dwservice.agent": "DWService",
    "com.remotepc.viewer": "RemotePC", "net.christianbeier.droidvnc_ng": "droidVNC-NG",
}
LOCATION_PARENTAL = {
    "com.life360.android.safetymapd": "Life360", "org.findmykids.app": "Find My Kids",
    "org.findmykids.child": "Find My Kids (criança)", "app.pingo": "Pingo",
    "com.google.android.apps.kids.familylinkhelper": "Family Link (aparelho supervisionado)",
    "com.google.android.apps.kids.familylink": "Family Link (pais)",
    "com.kaspersky.safekids": "Kaspersky Safe Kids", "com.symantec.familysafety": "Norton Family",
    "com.qustodio.qustodioapp": "Qustodio", "com.wondershare.famisafe": "FamiSafe",
    "com.wondershare.famisafe.kids": "FamiSafe Kids", "com.mmguardian.childapp": "MMGuardian",
    "com.bitdefender.parental2013": "Bitdefender Parental", "com.screentime": "Screen Time",
    "com.locategy.family": "Locategy", "com.glympse.android.glympse": "Glympse",
    "com.fsp.android.c": "Family Locator", "com.geozilla.family": "GeoZilla",
    "com.sygic.familygps": "Family GPS", "ru.kidcontrol.gpstracker": "Kid Control",
    "com.zoemob.gpstracking": "Zoemob", "com.mspy.lite": "mSpy Lite",
    "com.eyezy.parent": "Eyezy", "com.hoverwatch.tracker": "Hoverwatch",
    "io.familytime.parentalcontrol": "FamilyTime", "com.securekids.launcher_reloaded": "SecureKids",
}


def run(ctx):
    findings = []
    seen = []
    for pkg, name in {**REMOTE_ACCESS, **LOCATION_PARENTAL}.items():
        app = ctx.packages.get(pkg)
        if not app:
            continue
        remote = pkg in REMOTE_ACCESS
        hidden = app.has_launcher is False
        a11y = pkg in ctx.accessibility_packages
        seen.append({"package": pkg, "name": name, "type": "acesso remoto" if remote else "localização/parental",
                     "hidden": hidden, "accessibility": a11y})
        if ctx.iocs.match_package(pkg):
            continue   # já reportado pela verificação das bases de spyware
        severity = "alta" if hidden or app.sideloaded or (remote and a11y) else "media"
        findings.append(Finding(
            severity, f"App de {'acesso remoto' if remote else 'localização/controle parental'}: {name}",
            f"{app_label(ctx, pkg)} "
            + ("permite que outra pessoa veja e controle a tela do aparelho à distância"
               if remote else "compartilha sua localização e/ou atividade com outra pessoa")
            + (" e está sem ícone (oculto)" if hidden else "")
            + (" e tem acesso de acessibilidade" if a11y else "") + ".",
            "Se você não usa este app, desinstale-o. Se for controle parental em aparelho de adulto, "
            "é monitoramento.", package=pkg, family=name))

    assistants = ctx.try_sh("cmd role get-role-holders --user 0 android.app.role.ASSISTANT").split()
    for pkg in assistants:
        app = ctx.packages.get(pkg)
        if app and app.third_party and re.fullmatch(r"[\w.]+", pkg):
            findings.append(Finding(
                "media", "Assistente padrão de terceiro",
                f"{app_label(ctx, pkg)} é o assistente padrão e pode ler o conteúdo da tela quando acionado.",
                "Se não reconhece, troque em Configurações > Apps > Apps padrão > Assistente.", package=pkg))

    ctx.data["controle"] = {"apps": seen, "assistant": assistants, "device_policy": ctx.device_policy}
    return findings
