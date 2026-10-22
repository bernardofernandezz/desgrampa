// Estado global da interface e rótulos compartilhados.
export const SEV_ORDER = ["critica", "alta", "media", "baixa", "info"];

export const SEV_LABEL = { critica: "Crítica", alta: "Alta", media: "Média", baixa: "Baixa", info: "Info" };

export const STATUS_LABEL = {
  critica: "Crítico", alta: "Suspeito", media: "Atenção", baixa: "Baixo risco",
  ok: "Nada encontrado", nao_verificado: "Não verificado",
};

export const VERDICT_PILL = { alto_risco: "bad", suspeito: "warn", atencao: "warn", ok: "ok" };

export const SEV_PLURAL = { critica: ["crítico", "críticos"], alta: ["alto", "altos"], media: ["médio", "médios"],
  baixa: ["baixo", "baixos"], info: ["info", "info"] };

export const API_VERSION = 4;

const ADB_HINTS = {
  linux: "instale o adb: sudo apt install adb (Debian/Ubuntu) · sudo pacman -S android-tools (Arch) · sudo dnf install android-tools (Fedora)",
  macos: "instale o adb: brew install android-platform-tools — ou use o Desgrampa para macOS da página de downloads, que já traz o adb",
  windows: "use o Desgrampa para Windows da página de downloads, que já traz o adb — ou instale o Android platform-tools e adicione-o ao PATH",
};

export const adbHint = () => ADB_HINTS[app.status?.system] || ADB_HINTS.linux;

export const INSTALL_HINTS = {
  mvt: 'pip install "desgrampa[forense]"',
  restart: "desgrampa",
};

export const app = {
  status: null,
  serial: null,          // aparelho escolhido
  info: {},              // serial -> resumo do aparelho (/api/device)
  infoAt: {},
  infoError: {},         // serial -> mensagem de erro da última leitura
  scanning: false,
  polling: null,         // id da varredura acompanhada
  reports: [],
};
