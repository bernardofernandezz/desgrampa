// Página de relatórios salvos.

import { $, api, el, fill, fmtDate, icon } from "./dom.js";
import { app, VERDICT_PILL } from "./state.js";
import { go } from "./router.js";
import { renderSystem } from "./device.js";
import { reportLinks, showReport } from "./scan.js";

export async function loadReports() {
  try { app.reports = await api("/api/reports"); } catch { app.reports = []; }
  renderSystem();
}

export async function renderReportsPage(arg) {
  const [name, sub, index] = (arg || "").split("/");
  const focus = sub === "achado" && /^\d+$/.test(index || "") ? { finding: Number(index) } : {};
  await loadReports();
  const list = $("#reports-list");
  const view = $("#report-view");
  if (name) {
    list.classList.add("hidden");
    view.classList.remove("hidden");
    fill(view, el("p", { class: "muted" }, "Carregando…"));
    try {
      const box = el("div");
      await showReport(box, name, focus);
      fill(view, el("p", {}, el("a", { href: "#relatorios" }, "← Todos os relatórios")), box);
    } catch (e) {
      fill(view, el("p", {}, e.message), el("a", { href: "#relatorios" }, "← Voltar"));
    }
    return;
  }
  view.classList.add("hidden");
  list.classList.remove("hidden");
  fill(list, el("div", { class: "card" },
    app.reports.length ? app.reports.map((r) => el("div", { class: "list-row" },
      icon("file", "circle"),
      el("div", { class: "grow" },
        el("strong", {}, r.device || r.serial),
        el("span", { class: "muted small" }, `${fmtDate(r.started)} · varredura ${r.mode} · ${r.duration_s ?? "?"} s · `
          + `${r.categories_verified}/${r.categories_total} áreas`)),
      el("span", { class: "muted small" }, `${r.counts?.critica ?? 0} crít. · ${r.counts?.alta ?? 0} altos · ${r.counts?.media ?? 0} médios`),
      el("span", { class: `pill ${VERDICT_PILL[r.verdict?.code] || ""}` }, r.verdict?.label || "?"),
      el("div", { class: "actions" },
        el("button", { onclick: () => go(`#relatorios/${r.name}`) }, "Abrir"),
        el("a", { href: reportLinks(r.name).html, download: true }, el("button", {}, icon("download", "sm"), "HTML")),
        el("a", { href: reportLinks(r.name).zip, download: true, title: "Pasta de evidências inteira + relatório para atendimento" },
          el("button", {}, icon("download", "sm"), "Evidências")))))
      : el("div", { class: "empty" }, "Nenhuma varredura salva ainda.")));
}
