"""Base comum das verificações: categorias, permissões de risco, Finding e helpers."""

from dataclasses import asdict, dataclass

from ..context import ALT_STORES

SEVERITIES = ["critica", "alta", "media", "baixa", "info"]
SEVERITY_LABELS = {
    "critica": "Crítica", "alta": "Alta", "media": "Média", "baixa": "Baixa", "info": "Informativo",
}

# Áreas do dashboard: (id, título, o que cobre)
CATEGORIES = [
    ("spyware", "Stalkerware comercial",
     "Apps de espionagem vendidos ao público (mSpy, FlexiSPY, TheTruthSpy...): nome, certificado, hash e processos."),
    ("mercenario", "Spyware estatal / mercenário",
     "Indicadores de Pegasus, Predator, Candiru, NoviSpy, Cellebrite e outros (bases do MVT/Anistia), incluindo análise do MVT."),
    ("intercept", "Interceptação de conexões",
     "Certificados de segurança adicionados, proxy (global e por Wi-Fi), VPN e DNS privado."),
    ("rede", "Rede e conexões do aparelho",
     "DNS e gateway em uso, teste de DNS feito pelo celular, conexões ativas e apps enviando dados em segundo plano."),
    ("pcnet", "Rede local (teste pelo computador)",
     "DNS adulterado, HTTPS interceptado, proxy transparente e ARP spoofing na rede deste computador."),
    ("telefonia", "Telefonia e SIM",
     "Desvio de chamadas, rede 2G, operadora, apps padrão de SMS/telefone e redirecionamento de chamadas."),
    ("contas", "Contas e perfis",
     "Contas cadastradas no aparelho e perfis/usuários adicionais onde algo pode estar escondido."),
    ("controle", "Controle remoto e gerenciamento",
     "Administradores, MDM, apps de acesso remoto, de localização/controle parental e assistente padrão."),
    ("rastros", "Rastros e histórico",
     "Apps que já estiveram instalados e foram removidos, sobras no armazenamento e menções a domínios maliciosos nos logs."),
    ("sistema", "Integridade do sistema",
     "Root, bootloader, SELinux, firmware assinado com chaves públicas, permissões privilegiadas e apps de sistema falsos."),
    ("apps", "Apps e permissões",
     "Acessibilidade, leitura de notificações, combinação de permissões e uso recente de microfone/câmera/localização."),
    ("protecoes", "Proteções do sistema",
     "Play Protect, instalação de fontes desconhecidas e patch de segurança."),
]

# Permissões/recursos considerados sensíveis para monitoramento -> (pontos, descrição)
RISKY_PERMISSIONS = {
    "android.permission.READ_SMS": (2, "ler SMS"),
    "android.permission.RECEIVE_SMS": (1, "interceptar SMS recebidos"),
    "android.permission.READ_CALL_LOG": (2, "ler histórico de chamadas"),
    "android.permission.PROCESS_OUTGOING_CALLS": (1, "monitorar chamadas feitas"),
    "android.permission.RECORD_AUDIO": (1, "usar o microfone"),
    "android.permission.CAMERA": (1, "usar a câmera"),
    "android.permission.ACCESS_FINE_LOCATION": (1, "localização precisa"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (2, "localização em segundo plano"),
    "android.permission.READ_CONTACTS": (1, "ler contatos"),
    "android.permission.READ_PHONE_STATE": (1, "dados do telefone/chamadas"),
}
RISKY_APPOPS = {
    "GET_USAGE_STATS": (2, "ver quais apps você usa"),
    "SYSTEM_ALERT_WINDOW": (1, "desenhar sobre outros apps"),
    "REQUEST_INSTALL_PACKAGES": (1, "instalar outros apps"),
    "MANAGE_EXTERNAL_STORAGE": (1, "acesso total aos arquivos"),
}
# Permissões que um app comum não consegue obter: só com assinatura do fabricante ou concedidas
# manualmente via ADB por alguém com o aparelho na mão (passo típico de instalação de stalkerware).
PRIVILEGED_PERMISSIONS = {
    "android.permission.WRITE_SECURE_SETTINGS": "alterar configurações protegidas",
    "android.permission.READ_LOGS": "ler os logs de todo o sistema",
    "android.permission.INSTALL_PACKAGES": "instalar apps silenciosamente",
    "android.permission.DELETE_PACKAGES": "remover apps silenciosamente",
    "android.permission.MANAGE_USERS": "gerenciar usuários",
    "android.permission.INTERACT_ACROSS_USERS_FULL": "agir em todos os perfis",
    "android.permission.CAPTURE_AUDIO_OUTPUT": "gravar o áudio do sistema/chamadas",
    "android.permission.CAPTURE_VIDEO_OUTPUT": "gravar a tela",
    "android.permission.READ_FRAME_BUFFER": "capturar a tela",
    "android.permission.READ_PRIVILEGED_PHONE_STATE": "ler identificadores do chip/aparelho",
    "android.permission.MODIFY_PHONE_STATE": "controlar chamadas e rede móvel",
    "android.permission.GRANT_RUNTIME_PERMISSIONS": "conceder permissões a si mesmo",
    "android.permission.DUMP": "ler o estado interno do sistema",
    "android.permission.PACKAGE_USAGE_STATS": "ver quais apps você usa",
}

# Apps legítimos e populares que costumam usar acessibilidade / leitura de notificações
KNOWN_BENIGN = {
    "com.x8bit.bitwarden", "com.lastpass.lpandroid", "com.agilebits.onepassword",
    "com.callpod.android_apps.keeper", "com.dashlane", "proton.android.pass",
    "com.google.android.apps.authenticator2", "com.microsoft.launcher",
    "com.samsung.android.app.watchmanager", "com.samsung.android.wearable",
    "com.google.android.wearable.app", "com.mi.health", "com.xiaomi.wearable",
    "com.huami.watch.hmwatchmanager", "com.fitbit.FitbitMobile", "com.garmin.android.apps.connectmobile",
    "com.huawei.health", "com.zepp.life", "com.joaomgcd.autonotification", "net.dinglisch.android.taskerm",
    "com.teslacoilsw.launcher", "com.nianticlabs.pokemongo", "com.spotify.music",
    "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "com.microsoft.appmanager",
}


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    recommendation: str = ""
    package: str | None = None
    check: str = ""
    category: str | None = None   # sobrescreve a categoria padrão da verificação
    family: str | None = None     # família de spyware/app conhecido (agrupamento por origem)

    def to_dict(self):
        d = asdict(self)
        d["severity_label"] = SEVERITY_LABELS[self.severity]
        return d


def ioc_category(match, default="spyware"):
    """Categoria de um achado ligado a indicador: spyware mercenário tem área própria."""
    return "mercenario" if match.mercenary else default


def app_label(ctx, pkg):
    p = ctx.packages.get(pkg)
    if p is None:
        return pkg
    if not p.third_party:
        origin = "app do sistema"
    elif p.manual_install:
        origin = "instalado manualmente por arquivo APK"
    elif p.sideloaded:
        origin = f"instalado pela loja alternativa {ALT_STORES.get(p.installer, p.installer)}"
    else:
        origin = f"instalado via {p.installer}"
    return f"{pkg} ({origin})"


def spy_signals(ctx, pkg):
    """Comportamentos típicos de espionagem que o app realmente tem (não só o nome/assinatura)."""
    p = ctx.packages.get(pkg)
    if not p:
        return []
    signals = []
    if pkg in ctx.accessibility_packages:
        signals.append("acessibilidade ativa")
    if pkg in ctx.listener_packages:
        signals.append("lê notificações")
    if pkg in ctx.device_policy["admins"] or pkg == ctx.device_policy["device_owner"]:
        signals.append("administrador do aparelho")
    if p.has_launcher is False:
        signals.append("sem ícone")
    risky = [d for perm, (_, d) in RISKY_PERMISSIONS.items() if perm in p.granted]
    if len(risky) >= MIN_RISKY_PERMISSIONS:
        signals.append("permissões: " + ", ".join(risky[:4]))
    return signals


MIN_RISKY_PERMISSIONS = 2   # a partir de quantas permissões sensíveis isso vira um "sinal"

SAFETY_TIP = ("Antes de remover, pense na sua segurança: quem instalou pode ser avisado da remoção. "
              "Guarde o relatório e as evidências e, se possível, procure apoio especializado.")
