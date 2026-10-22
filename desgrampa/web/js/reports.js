// Página de relatórios salvos: histórico agrupado por aparelho, com tendência entre varreduras.

import { $, api, el, fill, fmtDate, icon } from "./dom.js";
import { app, VERDICT_PILL } from "./state.js";
import { go } from "./router.js";
import { renderSystem } from "./device.js";
import { reportLinks, showReport } from "./scan.js";
import { countsTrend, fmtDuration, MODE_LABEL, prettyDevice, relTime, reportsOf, sevBar } from "./history.js";

let query = "";

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
  $("#page-relatorios").classList.toggle("is-detail", Boolean(name));
  if (name) {
    list.classList.add("hidden");
    view.classList.remove("hidden");
    fill(view, breadcrumb(name), el("p", { class: "muted" }, "Carregando…"));
    try {
      const box = el("div");
      await showReport(box, name, focus);
      fill(view, breadcrumb(name), box);
    } catch (e) {
      fill(view, breadcrumb(name), el("div", { class: "card" }, el("p", {}, e.message), el("a", { href: "#relatorios" }, "← Voltar")));
    }
    return;
  }
  view.classList.add("hidden");
  list.classList.remove("hidden");
  renderList(list);
}

// Relatórios › Aparelho (série) › data — sempre mostra onde a pessoa está e como voltar.
function breadcrumb(name) {
  const r = app.reports.find((x) => x.name === name);
  return el("nav", { class: "crumbs", "aria-label": "Você está em" },
    el("a", { href: "#relatorios" }, "← Relatórios"),
    r ? [el("span", { class: "crumb-sep", "aria-hidden": "true" }, "›"),
      el("span", {}, prettyDevice(r.device || r.serial), r.serial ? el("code", { class: "muted" }, ` ${r.serial}`) : null),
      el("span", { class: "crumb-sep", "aria-hidden": "true" }, "›"),
      el("span", { "aria-current": "page" }, fmtDate(r.started))] : null);
}

function matches(r, q) {
  if (!q) return true;
  return [r.device, r.serial, r.name, r.verdict?.label, MODE_LABEL[r.mode], fmtDate(r.started)]
    .join(" ").toLowerCase().includes(q);
}

function renderList(list) {
  if (!app.reports.length) {
    fill(list, el("div", { class: "card empty" }, icon("file", "circle"),
      el("p", {}, el("strong", {}, "Nenhuma varredura salva ainda.")),
      el("p", { class: "small" }, "Conecte o celular e faça a primeira varredura; ela aparece aqui com as evidências."),
      el("a", { class: "btn", href: "#varredura" }, "Ir para a varredura")));
    return;
  }
  const q = query.trim().toLowerCase();
  const serials = [...new Set(app.reports.map((r) => r.serial || r.name))];
  const groups = serials.map((serial) => {
    const all = reportsOf(serial);
    if (!all.length) all.push(...app.reports.filter((r) => r.name === serial));   // relatório sem nº de série
    return { serial, all, shown: all.filter((r) => matches(r, q)) };
  }).filter((g) => g.shown.length);

  const search = el("input", { class: "search", type: "search", value: query, placeholder: "Buscar por aparelho, série, data ou ID",
    "aria-label": "Buscar relatórios", oninput: (ev) => {
      query = ev.target.value;
      const pos = ev.target.selectionStart;
      renderList(list);
      const again = list.querySelector("input.search");
      again?.focus();
      again?.setSelectionRange(pos, pos);
    } });
  fill(list,
    el("div", { class: "filters reports-bar" }, search,
      el("span", { class: "muted small" }, `${app.reports.length} varredura(s) de ${serials.length} aparelho(s)`)),
    groups.length ? groups.map(deviceGroup) : el("div", { class: "card empty" }, "Nenhum relatório corresponde à busca."));
}

function deviceGroup({ serial, all, shown }) {
  const last = all[0];
  return el("section", { class: "card report-group" },
    el("header", { class: "report-group-head" },
      icon("phone", "circle"),
      el("div", { class: "grow" },
        el("strong", {}, prettyDevice(last.device || serial)),
        el("div", { class: "muted small" }, last.serial ? el("code", {}, last.serial) : null,
          ` · ${all.length} varredura(s) · última ${relTime(last.started) || fmtDate(last.started)}`)),
      el("span", { class: `pill ${VERDICT_PILL[last.verdict?.code] || ""}`, title: "Resultado da varredura mais recente" },
        el("span", { class: "dot" }), last.verdict?.label || "?")),
    el("ol", { class: "report-rows" }, shown.map((r) => reportRow(r, all[all.indexOf(r) + 1]))));
}

function reportRow(r, prev) {
  const links = reportLinks(r.name);
  const c = r.counts || {};
  const trend = prev ? countsTrend(c, prev.counts) : [];
  return el("li", { class: `report-row v-${r.verdict?.code || "x"}` },
    el("button", { class: "report-open", onclick: () => go(`#relatorios/${r.name}`), title: "Abrir relatório" },
      el("span", { class: "report-when" }, el("strong", {}, fmtDate(r.started)),
        el("span", { class: "muted small" }, [relTime(r.started), MODE_LABEL[r.mode] || r.mode, fmtDuration(r.duration_s),
          `${r.categories_verified}/${r.categories_total} áreas`].filter(Boolean).join(" · "))),
      el("span", { class: "report-sev" }, sevBar(c),
        el("span", { class: "small" }, `${c.critica ?? 0} crít. · ${c.alta ?? 0} altos · ${c.media ?? 0} médios`)),
      el("span", { class: "report-trend small" }, prev
        ? (trend.length ? trend.map((t) => el("span", { class: t.d > 0 ? "up" : "down" }, t.text)) : el("span", { class: "muted" }, "igual à anterior"))
        : el("span", { class: "muted" }, "primeira")),
      el("span", { class: `pill ${VERDICT_PILL[r.verdict?.code] || ""}` }, r.verdict?.label || "?")),
    el("div", { class: "actions report-dl" },
      el("a", { class: "btn icon-only", href: links.html, download: true, title: `Baixar HTML · ID ${r.name}` },
        icon("download", "sm"), "HTML"),
      el("a", { class: "btn icon-only", href: links.zip, download: true, title: "Pasta de evidências inteira + relatório para atendimento" },
        icon("download", "sm"), "Evidências")),
    el("span", { class: "report-name muted small", title: "ID do relatório (nome da pasta de evidências)" }, el("code", {}, r.name)));
}
