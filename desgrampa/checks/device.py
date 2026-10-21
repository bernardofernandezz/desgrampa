"""Integridade do aparelho: root, bootloader, verified boot, SELinux, build."""

from . import Finding

NAME = "Root, bootloader e build"
CATEGORY = "sistema"

SU_PATHS = ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/data/local/su",
            "/data/local/bin/su", "/data/local/xbin/su", "/system/app/Superuser.apk",
            "/system/bin/.ext/su", "/system/usr/we-need-root/su", "/cache/su", "/dev/su"]
ROOT_PACKAGES = {
    "com.topjohnwu.magisk": "Magisk", "eu.chainfire.supersu": "SuperSU",
    "com.koushikdutta.superuser": "Superuser", "com.noshufou.android.su": "Superuser",
    "me.weishu.kernelsu": "KernelSU", "com.kingroot.kinguser": "KingRoot",
    "com.kingo.root": "KingoRoot", "de.robv.android.xposed.installer": "Xposed",
    "org.lsposed.manager": "LSPosed", "io.github.huskydg.magisk": "Magisk Delta",
    "me.bmax.apatch": "APatch",
}


def run(ctx):
    findings = []
    p = ctx.props

    if p.get("ro.boot.verifiedbootstate") in ("orange", "yellow") or p.get("ro.boot.flash.locked") == "0" \
            or p.get("ro.boot.vbmeta.device_state") == "unlocked":
        findings.append(Finding(
            "alta", "Bootloader desbloqueado",
            f"Estado do verified boot: {p.get('ro.boot.verifiedbootstate', '?')}. O bootloader desbloqueado "
            "permite instalar sistemas modificados e ferramentas de monitoramento com acesso total.",
            "Se você não desbloqueou o aparelho, alguém pode tê-lo feito. Considere restaurar a "
            "ROM oficial e bloquear o bootloader."))

    if p.get("ro.boot.veritymode") in ("disabled", "logging", "eio"):
        findings.append(Finding(
            "alta", "Verificação de integridade (dm-verity) desligada",
            f"ro.boot.veritymode={p['ro.boot.veritymode']}: alterações na partição do sistema não são bloqueadas.",
            "Restaure o firmware oficial do fabricante."))

    if p.get("ro.boot.warranty_bit") == "1" or p.get("ro.warranty_bit") == "1":
        findings.append(Finding(
            "alta", "Knox/garantia violados (Samsung)",
            "O aparelho registra que já rodou firmware não oficial (warranty bit = 1).",
            "Se você nunca modificou o aparelho, isso indica que outra pessoa o fez."))

    if p.get("sys.oem_unlock_allowed") == "1":
        findings.append(Finding(
            "media", "Desbloqueio OEM permitido",
            "A opção “Desbloqueio de OEM” está ligada nas Opções do desenvolvedor: alguém com o "
            "aparelho na mão pode desbloquear o bootloader.",
            "Desligue em Opções do desenvolvedor > Desbloqueio de OEM."))

    build_type = p.get("ro.build.type")
    if build_type and build_type != "user":
        findings.append(Finding(
            "media", f"Build de desenvolvimento ({build_type})",
            "O sistema não é uma build de usuário final (ro.build.type).",
            "Verifique se o aparelho usa uma ROM que você reconhece."))

    if "test-keys" in p.get("ro.build.tags", ""):
        findings.append(Finding(
            "media", "Sistema assinado com chaves de teste",
            "O sistema (ro.build.tags=test-keys) não é uma build oficial do fabricante.",
            "Verifique se o aparelho usa uma ROM personalizada que você reconhece."))

    if p.get("ro.debuggable") == "1" or p.get("ro.secure") == "0":
        findings.append(Finding(
            "media", "Sistema em modo depurável",
            "ro.debuggable=1 / ro.secure=0: o sistema permite acesso privilegiado via ADB.",
            "Builds oficiais não vêm assim. Verifique a origem da ROM."))

    selinux = ctx.try_sh("getenforce").strip()
    if selinux.lower() in ("permissive", "disabled"):
        findings.append(Finding(
            "alta", f"SELinux {selinux.lower()}",
            "A proteção SELinux não está bloqueando nada, o que é comum em aparelhos com root "
            "ou comprometidos.",
            "Restaure o firmware oficial do fabricante."))

    su_found = ctx.try_sh("ls " + " ".join(SU_PATHS) + " 2>/dev/null; which su 2>/dev/null").split()
    su_found = sorted({s for s in su_found if s.endswith("su") or s.endswith(".apk")})
    root_apps = [f"{name} ({pkg})" for pkg, name in ROOT_PACKAGES.items() if pkg in ctx.packages]
    mounts = ctx.cached_sh("cat /proc/mounts")
    magisk_mounts = [line.split()[1] for line in mounts.splitlines()
                     if any(k in line.lower() for k in ("magisk", "kernelsu", "/debug_ramdisk", "apatch"))]
    if su_found or root_apps or magisk_mounts:
        findings.append(Finding(
            "alta", "Sinais de root no aparelho",
            "Encontrado: " + ", ".join(su_found + root_apps + [f"montagem {m}" for m in magisk_mounts[:5]])
            + ". Com root, um spyware pode ler mensagens de qualquer app e se esconder do sistema.",
            "Se você não fez root no aparelho, trate isso como sinal forte de comprometimento: "
            "salve as evidências, faça backup dos dados pessoais e restaure o firmware oficial."))

    system_rw = [line.split()[1] for line in mounts.splitlines()
                 if len(line.split()) > 3 and line.split()[1] in ("/system", "/vendor", "/product")
                 and line.split()[3].startswith("rw")]
    if system_rw:
        findings.append(Finding(
            "alta", "Partição do sistema montada com escrita",
            f"{', '.join(system_rw)} está montada como leitura e escrita (rw). Em aparelhos normais "
            "ela é somente leitura.",
            "Indica modificação do sistema. Restaure o firmware oficial."))

    benign = (" .", " ..", " .studio", " perfd", " lldb", " lldb-server", " .gradle")
    tmp = [line for line in ctx.try_sh("ls -la /data/local/tmp 2>/dev/null").splitlines()
           if line and not line.startswith("total") and not line.rstrip().endswith(benign)]
    if tmp:
        names = [line.split()[-1] for line in tmp][:15]
        findings.append(Finding(
            "media", "Arquivos em /data/local/tmp",
            f"{len(tmp)} arquivo(s) na pasta temporária do ADB: {', '.join(names)}. Essa pasta "
            "é usada por ferramentas de desenvolvimento, mas também por exploits e ferramentas "
            "de root.",
            "Se você não usa ferramentas de desenvolvedor, investigue esses arquivos."))

    ctx.data["device_integrity"] = {
        "verified_boot": p.get("ro.boot.verifiedbootstate"),
        "bootloader_locked": p.get("ro.boot.flash.locked"),
        "selinux": selinux or None,
        "build_type": build_type,
        "build_tags": p.get("ro.build.tags"),
    }
    return findings
