// Página de configurações: tema, ferramentas e bases de indicadores.

import { $, api, el, fill, icon, table } from "./dom.js";
import { app, INSTALL_HINTS } from "./state.js";
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
        el("span", { class: "muted small" }, st?.adb || `não instalado — ${INSTALL_HINTS.adb}`)),
        el("span", { class: `pill ${st?.adb ? "ok" : "warn"}` }, st?.adb ? "instalado" : "ausente")),
      el("div", { class: "list-row" }, el("div", { class: "grow" }, el("strong", {}, "MVT — Mobile Verification Toolkit"),
        el("span", { class: "muted small" }, st?.mvt.installed ? `versão ${st.mvt.version}` : INSTALL_HINTS.mvt)),
        el("span", { class: `pill ${st?.mvt.installed ? "ok" : "warn"}` }, st?.mvt.installed ? "instalado" : "ausente"))),
    iocs ? el("div", { class: "card" },
      el("div", { class: "list-row" },
        el("div", { class: "grow" }, el("h2", {}, "Bases de indicadores"),
          el("span", { class: "muted small" }, iocsLine(iocs))),
        el("button", { onclick: updateIocs, disabled: iocs.job?.state === "baixando" }, icon("refresh", "sm"),
          el("span", {}, iocs.job?.state === "baixando" ? "Baixando…" : "Atualizar bases"))),
      table(["Conjunto", "Indicadores"], Object.entries(iocs.collections).map(([k, v]) => [k, v.toLocaleString("pt-BR")])),
      el("p", { class: "muted small" }, "Fontes: AssoEchap/stalkerware-indicators e mvt-project/mvt-indicators (Anistia Internacional, Citizen Lab, Google, Meta e outros).")) : null,
  );
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
