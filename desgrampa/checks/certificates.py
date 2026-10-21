"""(Varredura completa) Copia cada APK de terceiros e compara certificado de assinatura e hash
com as bases. Pega spyware mesmo quando o nome do pacote foi trocado para enganar."""

import os
import tempfile

from .. import apksig
from ..adb import AdbError
from . import SAFETY_TIP, Finding, app_label, ioc_category, spy_signals

NAME = "Assinatura e hash dos aplicativos"
CATEGORY = "spyware"
FULL_ONLY = True


def run(ctx):
    findings = []
    apps = sorted(ctx.third_party(), key=lambda p: p.name)
    results = ctx._cache.setdefault("apk_info", {})
    with tempfile.TemporaryDirectory(prefix="desgrampa-") as tmp:
        for i, app in enumerate(apps, 1):
            if not app.path:
                continue
            ctx.progress(f"Analisando assinatura {i}/{len(apps)}: {app.name}")
            local = os.path.join(tmp, "app.apk")
            try:
                ctx.device.pull(app.path, local)
                certs = apksig.certificates(local)
                sha256 = apksig.file_sha256(local)
            except (AdbError, OSError, ValueError, IndexError) as e:
                ctx.notes.append(f"{app.name}: não foi possível analisar o APK ({e})")
                continue
            finally:
                if os.path.exists(local):
                    os.unlink(local)
            results[app.name] = {"sha256": sha256, "certificates": [c["sha1"] for c in certs]}
            if ctx.iocs.match_package(app.name):
                continue  # já reportado pelo nome
            match = ctx.iocs.match_apk_hash(sha256)
            how = f"o arquivo do app (SHA-256 {sha256}) é idêntico a uma amostra conhecida"
            if not match:
                for c in certs:
                    match = ctx.iocs.match_certificate(c["sha1"], c["sha256"])
                    if match:
                        how = f"é assinado com o certificado {c['sha1']}, usado por esse spyware"
                        break
            if not match:
                continue
            signals = spy_signals(ctx, app.name)
            exact = how.startswith("o arquivo")
            if exact or signals or match.mercenary:
                findings.append(Finding(
                    "critica", f"Spyware disfarçado: {match.family}",
                    f"{app_label(ctx, app.name)} {how} ({match}). O nome do app foi alterado para "
                    "não ser reconhecido." + (f" Comportamento encontrado: {', '.join(signals)}." if signals else ""),
                    SAFETY_TIP, package=app.name, category=ioc_category(match), family=match.family))
            else:
                findings.append(Finding(
                    "alta", f"Assinatura coincide com spyware: {match.family}",
                    f"{app_label(ctx, app.name)} {how} ({match}), mas o app não tem nenhum acesso de "
                    "espionagem ativo (sem acessibilidade, notificações, administrador ou permissões "
                    "sensíveis). O mais provável é um APK modificado e reassinado com uma chave que "
                    "também aparece em amostras desse spyware — ainda assim, não é o app original.",
                    "Desinstale esse app e, se precisar dele, instale a versão original pela Play Store.",
                    package=app.name, category=ioc_category(match), family=match.family))
    return findings
