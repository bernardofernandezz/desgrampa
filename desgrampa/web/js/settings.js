// Página de configurações: tema, ferramentas e bases de indicadores.

import { $, api, el, fill, icon, table } from "./dom.js";
import { adbHint, app, INSTALL_HINTS } from "./state.js";
import { refreshStatus } from "./device.js";

function iocsLine(iocs) {
  if (iocs.job?.state === "baixando") return "Baixando as bases de indicadores… (pode levar alguns minutos)";
  if (iocs.job?.state === "erro") return `Falha ao baixar as bases: ${iocs.job.error}`;
  if (!iocs.total) return "Bases ainda não baixadas.";
  return `${iocs.total.toLocaleString("pt-BR")} indicadores · ${iocs.families} famílias de spyware · ${iocs.source} em ${iocs.updated}`;
}

// O tema é guardado como texto puro (não JSON, como em `store`) porque o script inline do
// index.html o lê antes de a página pintar, para evitar o "piscar" do tema claro.
const THEME_KEY = "desgrampa-theme";

function currentTheme() {
  try { return localStorage.getItem(THEME_KEY) || "dark"; } catch { return "dark"; }
}

function applyTheme(theme) {
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* sem armazenamento */ }
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  renderSettings();
}

export function renderSettings() {
  const st = app.status;
  const theme = currentTheme();
  const iocs = st?.iocs;
  fill($("#settings"), el("div", { class: "card" },
      el("h2", {}, "Aparência"),
      el("p", { class: "muted small" }, "Tema da interface."),
      el("div", { class: "seg" }, [["dark", "Escuro"], ["light", "Claro"], ["system", "Sistema"]].map(([k, label]) =>
        el("button", { class: theme === k ? "on" : "", onclick: () => applyTheme(k) }, label)))),
    el("div", { class: "card" },
      el("h2", {}, "Ferramentas"),
      el("div", { class: "list-row" }, el("div", { class: "grow" }, el("strong", {}, "adb (Android Debug Bridge)"),
        el("span", { class: "muted small" }, st?.adb || `não instalado — ${adbHint()}`)),
        el("span", { class: `pill ${st?.adb ? "ok" : "warn"}` }, st?.adb ? "instalado" : "ausente")),
      el("div", { class: "list-row" }, el("div", { class: "grow" }, el("strong", {}, "MVT — Mobile Verification Toolkit"),
        el("span", { class: "muted small" }, st?.mvt.installed ? `versão ${st.mvt.version}` : INSTALL_HINTS.mvt)),
        el("span", { class: `pill ${st?.mvt.installed ? "ok" : "warn"}` }, st?.mvt.installed ? "instalado" : "ausente"))),
    privacyCard(st),
    iocs ? el("div", { class: "card" },
      el("div", { class: "list-row" },
        el("div", { class: "grow" }, el("h2", {}, "Bases de indicadores"),
          el("span", { class: "muted small" }, iocsLine(iocs))),
        el("button", { onclick: updateIocs, disabled: iocs.job?.state === "baixando" }, icon("refresh", "sm"),
          el("span", {}, iocs.job?.state === "baixando" ? "Baixando…" : "Atualizar bases"))),
      table(["Conjunto", "Indicadores"], Object.entries(iocs.collections).map(([k, v]) => [k, v.toLocaleString("pt-BR")])),
      el("p", { class: "muted small" }, "Fontes: AssoEchap/stalkerware-indicators e mvt-project/mvt-indicators (Anistia Internacional, Citizen Lab, Google, Meta e outros)."),
      el("h3", {}, "Vulnerabilidades do Android"),
      el("p", { class: "muted small" }, st.bulletins?.available
        ? `${st.bulletins.total.toLocaleString("pt-BR")} falhas dos boletins de segurança (${st.bulletins.kev} exploradas ativamente), `
          + `boletins até ${st.bulletins.latest_spl}, base gerada em ${st.bulletins.generated}. Atualizada junto com as bases acima.`
        : "Base de vulnerabilidades ausente.")) : null,
  );
}

// Privacidade: modo sem rastros, apagar relatórios e limpar o que o navegador guardou.
function privacyCard(st) {
  if (!st) return null;
  const ephemeral = st.privacy?.ephemeral;
  const attendance = st.attendance?.enabled;
  const msg = el("p", { class: "small", role: "status" });
  const wipe = async () => {
    const typed = prompt("Isto apaga TODOS os relatórios e evidências deste computador, sem volta.\nDigite APAGAR para confirmar:");
    if (typed !== "APAGAR") return;
    try {
      const { removed } = await api("/api/privacy/wipe", { confirm: "APAGAR" });
      clearBrowser();
      msg.textContent = `${removed} relatório(s) apagado(s) e dados do navegador limpos.`;
    } catch (e) {
      msg.textContent = e.message;
    }
    await refreshStatus();
  };
  const toggle = async () => {
    try {
      await api("/api/privacy/ephemeral", { on: !ephemeral });
    } catch (e) {
      alert(e.message);
    }
    await refreshStatus();
    renderSettings();
  };
  return el("div", { class: "card" },
    el("h2", {}, "Privacidade neste computador"),
    el("p", { class: "muted small" }, "Útil se o computador é compartilhado ou se alguém pode mexer nele depois."),
    el("div", { class: "list-row" }, el("div", { class: "grow" }, el("strong", {}, "Modo sem rastros"),
      el("span", { class: "muted small" }, "Relatórios das próximas varreduras ficam numa pasta temporária, apagada ao fechar o "
        + "programa. Baixe o pacote de evidências antes de sair. Também dá para iniciar assim: desgrampa --sem-rastros")),
    el("button", { onclick: toggle, disabled: attendance }, ephemeral ? "Desligar" : "Ligar")),
    el("div", { class: "list-row" }, el("div", { class: "grow" }, el("strong", {}, "Apagar relatórios deste computador"),
      el("span", { class: "muted small" }, "Remove todas as varreduras e evidências salvas e o que este navegador guardou "
        + "(tema, checklist, estado escolhido). Baixe antes o que quiser guardar.")),
    el("button", { class: "danger", onclick: wipe }, "Apagar tudo")),
    msg,
    el("p", { class: "muted small" }, "Depois, apague também o histórico do navegador (Ctrl+Shift+Del) se não quiser que "
      + "fique registrado que você abriu o Desgrampa."));
}

function clearBrowser() {
  try { localStorage.clear(); sessionStorage.clear(); } catch { /* sem armazenamento */ }
}

async function updateIocs() {
  try {
    await api("/api/iocs/update", {});
  } catch (e) {
    alert(e.message);
  }
  await refreshStatus();
  renderSettings();
}
