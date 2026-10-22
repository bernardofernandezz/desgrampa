"""Explicações em linguagem simples: o que um app consegue fazer, por que é suspeito e o que recomendamos.

Usado na varredura (risk.py guarda o que cada app consegue fazer), nas sugestões (grouping.py), no registro das
ações (actions.py) e nos relatórios. Nada aqui consulta o aparelho: só traduz o que a varredura já coletou.
"""

from .checks import PRIVILEGED_PERMISSIONS, RISKY_APPOPS, RISKY_PERMISSIONS
from .context import ALT_STORES, MANUAL_INSTALLERS

SPY_CATEGORIES = ("spyware", "mercenario")

# Temas, na ordem em que aparecem para o usuário
THEMES = ("Mensagens", "Tela", "Ligações", "Microfone e câmera", "Localização", "Fotos e arquivos",
          "Contatos e contas", "Uso do celular", "Controle do aparelho", "Esconder-se")

PERMISSION_CAPS = {f"android.permission.{k}": v for k, v in {
    "READ_SMS": ("Mensagens", "ler seus SMS, inclusive códigos de verificação de bancos e do WhatsApp"),
    "RECEIVE_SMS": ("Mensagens", "receber uma cópia de cada SMS que chega"),
    "SEND_SMS": ("Mensagens", "enviar SMS em seu nome"),
    "READ_CALL_LOG": ("Ligações", "ver com quem você fala, quando e por quanto tempo"),
    "PROCESS_OUTGOING_CALLS": ("Ligações", "saber para quem você liga"),
    "READ_PHONE_STATE": ("Ligações", "saber quando você está numa ligação"),
    "RECORD_AUDIO": ("Microfone e câmera", "gravar o som ao redor e as ligações"),
    "CAMERA": ("Microfone e câmera", "tirar fotos e gravar vídeos"),
    "ACCESS_FINE_LOCATION": ("Localização", "saber onde você está, com precisão"),
    "ACCESS_BACKGROUND_LOCATION": ("Localização", "acompanhar sua localização o tempo todo, mesmo fechado"),
    "READ_CONTACTS": ("Contatos e contas", "copiar sua lista de contatos"),
    "GET_ACCOUNTS": ("Contatos e contas", "ver quais contas (Google, WhatsApp…) estão no celular"),
    "READ_EXTERNAL_STORAGE": ("Fotos e arquivos", "ver suas fotos, vídeos e arquivos"),
    "READ_MEDIA_IMAGES": ("Fotos e arquivos", "ver suas fotos"),
    "READ_MEDIA_VIDEO": ("Fotos e arquivos", "ver seus vídeos"),
}.items()}

APPOP_CAPS = {
    "GET_USAGE_STATS": ("Uso do celular", "saber quais apps você abre e por quanto tempo"),
    "SYSTEM_ALERT_WINDOW": ("Tela", "mostrar janelas por cima de outros apps (inclusive telas falsas de senha)"),
    "REQUEST_INSTALL_PACKAGES": ("Controle do aparelho", "instalar outros apps"),
    "MANAGE_EXTERNAL_STORAGE": ("Fotos e arquivos", "acessar todos os seus arquivos"),
}

SIGNAL_CAPS = {
    "accessibility": ("Tela", "ver tudo o que aparece na tela e o que você digita, inclusive dentro das conversas"),
    "listener": ("Mensagens", "ler o conteúdo de todas as notificações (WhatsApp, e-mail, banco)"),
    "admin": ("Controle do aparelho", "bloquear o celular, apagar dados e dificultar a própria remoção"),
    "owner": ("Controle do aparelho", "controlar o aparelho inteiro (instalar, bloquear, mudar configurações)"),
    "hidden": ("Esconder-se", "funcionar sem ícone na tela de apps"),
    "boot": ("Esconder-se", "ligar sozinho sempre que o celular é ligado"),
}

# Relatórios antigos não guardam "can_do": traduz os motivos do perfil de risco (risk.py)
_REASON_CAPS = {
    **{desc: PERMISSION_CAPS[perm] for perm, (_, desc) in RISKY_PERMISSIONS.items() if perm in PERMISSION_CAPS},
    **{desc: APPOP_CAPS[op] for op, (_, desc) in RISKY_APPOPS.items() if op in APPOP_CAPS},
    "serviço de acessibilidade ativo": SIGNAL_CAPS["accessibility"], "lê notificações": SIGNAL_CAPS["listener"],
    "administrador do dispositivo": SIGNAL_CAPS["admin"], "controla o aparelho (Device Owner)": SIGNAL_CAPS["owner"],
    "sem ícone na tela de apps": SIGNAL_CAPS["hidden"], "inicia junto com o aparelho": SIGNAL_CAPS["boot"],
}

SEVERITY_PLAIN = {"critica": "Grave", "alta": "Preocupante", "media": "Vale conferir", "baixa": "Pouco preocupante",
                  "info": "Informativo"}

VERDICT_PLAIN = {
    "alto_risco": "Encontramos sinais fortes de que o celular pode estar sendo espionado ou adulterado.",
    "suspeito": "Encontramos sinais que precisam ser verificados com atenção.",
    "atencao": "Nada indica espionagem, mas há configurações ou falhas que deixam o celular mais exposto.",
    "ok": "Não encontramos sinais de espionagem nas verificações feitas. Isso não prova que o celular está limpo.",
}

# Mesmos nomes do modo simples da interface (web/js/simple.js)
AREAS = {
    "spyware": ("Apps espiões", "Existe algum app espião conhecido instalado?"),
    "mercenario": ("Espionagem avançada", "Há sinais de spyware usado por governos ou empresas de vigilância?"),
    "intercept": ("Conexões interceptadas", "Alguém pode estar lendo o que você acessa na internet?"),
    "rede": ("Internet do celular", "O celular está mandando dados para lugares estranhos?"),
    "pcnet": ("Rede Wi-Fi", "A rede deste computador está adulterada?"),
    "telefonia": ("Ligações e chip", "Suas ligações ou SMS estão sendo desviados?"),
    "contas": ("Contas e perfis", "Tem conta ou perfil escondido no celular?"),
    "controle": ("Controle à distância", "Alguém consegue controlar ou localizar o celular?"),
    "rastros": ("Rastros", "Já houve um app espião que foi apagado?"),
    "sistema": ("Sistema", "O sistema do celular foi modificado?"),
    "apps": ("Apps com acesso demais", "Algum app tem acesso perigoso a mensagens, tela ou microfone?"),
    "protecoes": ("Proteções", "As proteções do Android estão ligadas?"),
    "vulns": ("Falhas de segurança", "O celular tem falhas conhecidas que permitem invasão?"),
}
AREA_STATE = {"critica": "Problema", "alta": "Problema", "media": "Atenção", "baixa": "OK", "ok": "OK",
              "nao_verificado": "Não verificado"}


def _ordered(caps):
    unique = list(dict.fromkeys(caps))
    return [{"theme": t, "text": x} for t, x in sorted(unique, key=lambda c: THEMES.index(c[0]))]


def capabilities(app, signals):
    """O que o app consegue fazer, a partir das permissões concedidas e dos sinais (accessibility, listener…)."""
    caps = [PERMISSION_CAPS[p] for p in app.granted if p in PERMISSION_CAPS]
    caps += [APPOP_CAPS[op] for op in app.appops if op in APPOP_CAPS]
    caps += [SIGNAL_CAPS[s] for s in signals if s in SIGNAL_CAPS]
    caps += [("Controle do aparelho", desc) for perm, desc in PRIVILEGED_PERMISSIONS.items() if perm in app.granted]
    return _ordered(caps)


def capabilities_from_reasons(reasons):
    return _ordered(_REASON_CAPS[r] for r in reasons if r in _REASON_CAPS)


def _spy_family(items):
    """Família de spyware de um achado de spyware (não vale, p.ex., o nome de um app de acesso remoto)."""
    return next((f.get("family") for f in items if f.get("family") and f.get("category") in SPY_CATEGORIES
                 and f["severity"] in ("critica", "alta")), None)


def _origin(app):
    installer = app.get("installer")
    if installer in MANUAL_INSTALLERS:
        return "por arquivo APK"
    return f"pela loja alternativa {ALT_STORES.get(installer, installer)}"


def _kind(candidate, items, app):
    if candidate["mercenary"]:
        return "mercenario"
    if _spy_family(items):
        visible = app and not app.get("sideloaded") and app.get("has_launcher") is not False
        return "monitoramento" if visible else "stalkerware"
    return "suspeito" if candidate["level"] == "ameaca" else "revisar"


KIND_TEXT = {
    "mercenario": ("Spyware mercenário",
                   "Ferramenta cara de espionagem, usada por governos ou empresas de vigilância contra alvos "
                   "específicos (jornalistas, ativistas, advogados, políticos)."),
    "stalkerware": ("App espião (stalkerware)",
                    "App vendido para vigiar outra pessoa às escondidas. Quem instalou costuma acompanhar mensagens, "
                    "localização, fotos e ligações por um site, sem que a vítima perceba."),
    "monitoramento": ("App de monitoramento",
                      "App de localização ou controle familiar. É legítimo quando todos combinaram o uso, mas também "
                      "é usado para controlar alguém sem consentimento."),
    "suspeito": ("App suspeito",
                 "App com sinais graves de espionagem ou de programa malicioso encontrados nesta varredura."),
    "revisar": ("App com acessos perigosos",
                "Um app comum com acessos que permitem espionar. Pode ser legítimo (um app que você usa) — "
                "confira se você reconhece."),
}


def _why(candidate, items, app, kind):
    why = []
    titles = [f["title"] for f in items]
    family = _spy_family(items)
    if family:
        why.append(f"Está nas listas públicas de spyware como “{family}”"
                   + (" (spyware mercenário)." if kind == "mercenario" else "."))
    if any(t.startswith("Spyware em execução") for t in titles):
        why.append("Estava rodando no celular durante a varredura.")
    if any("servidor de spyware" in t for t in titles):
        why.append("O celular se comunicou com um servidor usado por spyware.")
    if app:
        if app.get("has_launcher") is False:
            why.append("Não tem ícone na tela de apps: fica escondido.")
        if app.get("sideloaded"):
            why.append(f"Foi instalado por fora da loja oficial, {_origin(app)}.")
        if app.get("first_install"):
            why.append(f"Instalado em {app['first_install'][:10]}. Lembre se alguém mexeu no celular nessa época.")
    if candidate.get("device_admin"):
        why.append("É administrador do aparelho, o que dificulta a remoção.")
    if candidate.get("user"):
        why.append(f"Está num perfil separado do celular (perfil {candidate['user']}), onde é mais difícil de ver.")
    if any(t.startswith("MVT:") for t in titles):
        why.append("Foi apontado pela análise forense do MVT (Anistia Internacional).")
    known = {"Spyware em execução", "Stalkerware conhecido", "Spyware mercenário", "MVT:"}
    why += [t + "." for t in titles if not t.startswith(tuple(known)) and "servidor de spyware" not in t][:3]
    return list(dict.fromkeys(why))


def _recommendation(kind, candidate):
    if kind == "mercenario":
        rec = ("restrict", "Não apague nada ainda: remover destrói provas que um laboratório forense precisa. "
               "Procure a Access Now Helpline ou o Amnesty Security Lab. Se precisar parar a espionagem já, "
               "corte os acessos — o app fica no celular como prova.")
    elif kind == "stalkerware":
        rec = ("uninstall", "App de espionagem conhecido, sem uso legítimo no seu celular. Remover encerra a "
               "espionagem; uma cópia do app fica guardada como prova.")
    elif kind == "monitoramento":
        rec = ("uninstall", "Se você não instalou nem combinou o uso, remova. Se é da sua família e todos "
               "concordaram, pode manter.")
    elif kind == "suspeito":
        rec = ("uninstall", "Os sinais são graves. Remover é o mais seguro; uma cópia do app fica como prova.")
    else:
        rec = ("restrict", "Se você não reconhece este app, corte os acessos: ele para de espionar sem ser "
               "apagado. Se depois confirmar que não usa, remova.")
    action, text = rec
    if candidate.get("device_admin"):
        text += " Como é administrador do aparelho, talvez seja preciso desmarcá-lo no celular primeiro."
    return {"action": action, "text": text}


def dossier(candidate, items, app):
    """Explicação completa de um app sugerido: o que é, por que é suspeito, o que faz e o que recomendamos."""
    kind = _kind(candidate, items, app)
    label, what = KIND_TEXT[kind]
    can_do = (app or {}).get("can_do") or capabilities_from_reasons((app or {}).get("reasons", []))
    recommendation = _recommendation(kind, candidate)
    why = _why(candidate, items, app, kind)
    known_ioc = kind in ("mercenario", "stalkerware")
    return {
        "kind": kind,
        "label": label,
        "what": what,
        "why": why,
        "can_do": can_do,
        "risk_if_kept": ("Se ficar, ele pode continuar a " + "; ".join(c["text"] for c in can_do[:3]) + ".")
                        if can_do else None,
        "confidence": "alta" if known_ioc or any(f["severity"] == "critica" for f in items) else "media",
        "recommendation": recommendation,
        # entra marcado no plano de limpeza só o que é claramente espionagem (nunca mercenário: preservar provas)
        "preselect": kind in ("stalkerware", "suspeito"),
        "summary": f"{label}: " + (why[:1] or [what])[0],
    }
