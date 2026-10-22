// Dashboard do resultado: veredito, áreas, abas e achados agrupados (categoria → origem).

import { api, el, fill, fmtDate, icon, store } from "./dom.js";
import { app, SEV_LABEL, SEV_ORDER, SEV_PLURAL, STATUS_LABEL, VERDICT_PILL } from "./state.js";
import { copyText, diffFindings, findingCode, fmtDuration, MODE_LABEL, prettyDevice, previousOf, relTime, when } from "./history.js";
import { suggestionsCard } from "./actions.js";
import { accountsTab, appsTab, evidenceTab, manualTab, networkTab, telephonyTab, tracesTab } from "./tabs.js";
import { simpleView } from "./simple.js";
import { timelineTab, vulnsTab } from "./vulns.js";

const VIEW_KEY = "desgrampa-view";   // "simples" (padrão) ou "tecnico"

function deviceTitle(d) {
  return `${prettyDevice(d.manufacturer || "")} ${d.model || ""}`.trim() || d.serial;
}

export const systemLabel = (d) => (d.platform === "ios" ? `iOS ${d.ios || "?"}`
  : `Android ${d.android || "?"} · patch ${d.security_patch || "?"}`);

// Veredito + números principais.
function heroSection(r) {
  const s = r.stats;
  const kpi = (label, value, cls = "") => el("div", { class: `kpi ${cls}` }, el("span", {}, label), el("strong", {}, value));
  return el("div", { class: "hero" },
    el("div", { class: `verdict ${r.verdict.code}` },
      el("h2", {}, r.verdict.label),
      el("p", {}, r.verdict.text),
      r.verdict.code === "ok" ? el("p", { class: "muted small" },
        "Nada foi encontrado, mas isso não prova que o aparelho está limpo. Spyware mercenário pode não deixar "
        + "rastros acessíveis sem análise forense.") : null),
    el("div", { class: "kpis" },
      kpi("Críticos", r.counts.critica, r.counts.critica ? "crit" : ""),
      kpi("Altos", r.counts.alta, r.counts.alta ? "high" : ""),
      kpi("Médios", r.counts.media, r.counts.media ? "med" : ""),
      kpi("Áreas verificadas", `${s.categories_verified}/${s.categories_total}`),
      kpi("Apps analisados", `${s.packages}`),
      kpi("Indicadores consultados", r.iocs.total.toLocaleString("pt-BR"))));
}

// Bloco de uma das 12 áreas; clicar filtra os achados daquela área.
function categoryTile(c, onClick) {
  const counts = ["critica", "alta", "media", "baixa"].filter((sv) => c.counts[sv])
    .map((sv) => `${c.counts[sv]} ${SEV_LABEL[sv].toLowerCase()}`).join(" · ");
  const skipped = c.checks.filter((x) => x.status !== "ok");
  const notVerified = c.status === "nao_verificado";
  return el("button", { class: `cat st-${c.status}`, onclick: onClick, title: c.description },
    el("div", { class: "cat-top" }, el("span", { class: "cat-title" }, c.title),
      el("span", { class: "cat-status" }, STATUS_LABEL[c.status])),
    el("div", { class: "cat-counts" }, counts || (notVerified ? "" : "nenhum achado relevante")),
    el("div", { class: "cat-desc" }, notVerified && skipped.length ? skipped.map((x) => x.reason).join("; ") : c.description));
}

// Botões de exportação: relatório pessoal, versão para atendimento/autoridade, JSON, STIX e CSV.
function exportMenu(links) {
  const item = (href, label, hint, download = true) => el("a", { href, download: download || null,
    target: download ? null : "_blank", rel: "noopener", role: "menuitem" }, el("strong", {}, label), el("span", {}, hint));
  return el("details", { class: "menu" },
    el("summary", { class: "btn" }, icon("download", "sm"), "Baixar relatório"),
    el("div", { class: "menu-items", role: "menu" },
      item(links.view, "Ver e imprimir (PDF)", "Relatório para você, pronto para salvar em PDF", false),
      item(links.authority, "Para atendimento ou autoridade", "Fatos, hashes, cadeia de custódia e base legal", false),
      item(links.zip, "Pacote de evidências (.zip)", "Pasta inteira com hashes, para especialista ou pendrive"),
      item(links.html, "Arquivo HTML", "Relatório completo para guardar"),
      item(links.json, "JSON", "Todos os dados, para especialistas"),
      item(links.stix, "STIX 2.1", "Achados e CVEs para ferramentas de inteligência"),
      item(links.csv, "CSV de vulnerabilidades", "Planilha com as falhas abertas")));
}

export function renderDashboard(container, r, links, reload, focus = {}) {
  const ui = { severities: new Set(["critica", "alta", "media", "baixa"]), category: null, tab: "achados",
    groupBy: store.get("desgrampa-groupby", "categoria"), query: "", focus: focus.finding ?? null,
    view: focus.finding != null ? "tecnico" : store.get(VIEW_KEY, "simples") };

  const catTiles = new Map();
  const tabButtons = new Map();
  const panel = el("div", { class: "tabpanel", role: "tabpanel" });
  const body = el("div");
  const compare = el("div", { class: "compare-slot" });   // preenchido depois, ao comparar com a varredura anterior

  const tabs = {
    achados: ["Achados", () => findingsTab(r, ui, redraw, links)],
    vulns: [`Vulnerabilidades${r.data.vulns ? ` (${r.data.vulns.counts.total})` : ""}`, () => vulnsTab(r.data.vulns, r.data.ios)],
    tempo: ["Linha do tempo", () => timelineTab(r)],
    rede: ["Rede", () => networkTab(r.data)],
    telefonia: ["Telefonia", () => telephonyTab(r.data.telefonia)],
    contas: ["Contas e perfis", () => accountsTab(r.data.contas, r.data.controle)],
    rastros: ["Rastros", () => tracesTab(r.data.rastros)],
    apps: [`Apps (${r.apps.length})`, () => appsTab(r.apps)],
    evidencias: ["Cobertura e evidências", () => evidenceTab(r)],
    manual: ["Verificações manuais", () => manualTab()],
  };

  function redraw() {
    for (const [cid, tile] of catTiles) tile.classList.toggle("active", ui.category === cid);
    for (const [tid, btn] of tabButtons) {
      btn.classList.toggle("on", ui.tab === tid);
      btn.setAttribute("aria-selected", String(ui.tab === tid));
    }
    fill(panel, tabs[ui.tab][1]());
    if (ui.focus != null) {
      const card = panel.querySelector(`#achado-${ui.focus}`);
      card?.classList.add("focus");
      card?.scrollIntoView({ block: "center" });
      ui.focus = null;
    }
  }

  function selectCategory(cid) {
    ui.category = ui.category === cid ? null : cid;
    ui.tab = cid === "vulns" && !r.findings.some((f) => f.category === "vulns") ? "vulns" : "achados";
    redraw();
    panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function technical() {
    catTiles.clear();
    tabButtons.clear();
    const cats = el("div", { class: "cats" }, r.categories.map((c) => {
      const tile = categoryTile(c, () => selectCategory(c.id));
      catTiles.set(c.id, tile);
      return tile;
    }));
    const view = [
      heroSection(r),
      compare,
      suggestionsCard(r, reload),
      el("h3", {}, "Áreas analisadas ", el("span", { class: "muted small", style: "font-weight:400" }, "— clique para filtrar os achados")),
      cats,
      el("div", { class: "tabs", role: "tablist" }, Object.entries(tabs).map(([tid, [label]]) => {
        const b = el("button", { role: "tab", onclick: () => { ui.tab = tid; redraw(); } }, label);
        tabButtons.set(tid, b);
        return b;
      })),
      panel,
    ];
    redraw();
    return view;
  }

  function setView(view, category = null) {
    ui.view = view;
    store.set(VIEW_KEY, view);
    for (const b of modeButtons) b.classList.toggle("on", b.dataset.view === view);
    if (category) { ui.category = category; ui.tab = "achados"; }
    fill(body, view === "simples" ? simpleView(r, (cid) => setView("tecnico", cid), suggestionsCard(r, reload), compare) : technical());
    if (category) panel.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  const modeButtons = [["simples", "Simples"], ["tecnico", "Técnico"]].map(([k, label]) =>
    el("button", { "data-view": k, class: ui.view === k ? "on" : "", onclick: () => setView(k),
      title: k === "simples" ? "Resumo em linguagem simples" : "Todos os detalhes, CVEs, linha do tempo e evidências" }, label));

  fill(container, identityHeader(r, links, el("div", { class: "actions" },
    el("div", { class: "seg", role: "group", "aria-label": "Modo de visualização" }, modeButtons),
    exportMenu(links))), body);
  setView(ui.view);
  loadComparison(r, links.name, ui, compare, () => { if (ui.view === "tecnico") redraw(); });
}

// Cabeçalho que identifica o relatório sem ambiguidade: aparelho, série, data, modo, ID e hash de integridade.
function identityHeader(r, links, actions) {
  const d = r.device;
  const integ = r.integrity || {};
  const copyBtn = (text, label) => el("button", { class: "link-btn small", title: `Copiar ${label}`,
    onclick: (ev) => copyText(text, ev.currentTarget) }, "copiar");
  const chip = (label, value, extra = null, title = null) =>
    el("div", { class: "id-chip", title }, el("dt", {}, label), el("dd", {}, value, extra));
  return el("header", { class: "report-id" },
    el("div", { class: "report-id-top" },
      el("div", { class: "report-id-title" },
        icon("phone", "circle"),
        el("div", { class: "grow" },
          el("div", { class: "eyebrow", style: "margin:0" }, "Relatório da varredura"),
          el("h2", {}, deviceTitle(d), " ",
            el("span", { class: `pill ${VERDICT_PILL[r.verdict.code] || ""}` }, el("span", { class: "dot" }), r.verdict.label)))),
      actions),
    el("dl", { class: "id-chips" },
      chip("Nº de série", el("code", {}, d.serial || "—")),
      chip("Sistema", systemLabel(d)),
      chip("Data", fmtDate(r.started), null, relTime(r.started)),
      chip("Tipo", MODE_LABEL[r.mode] || r.mode),
      chip("Duração", fmtDuration(r.duration_s)),
      links?.name ? chip("ID do relatório", el("code", {}, links.name), copyBtn(links.name, "o ID do relatório")) : null,
      integ.report_sha256 ? chip("SHA-256 do relatório", el("code", {}, `${integ.report_sha256.slice(0, 12)}…`),
        copyBtn(integ.report_sha256, "o hash completo"),
        `Hash completo: ${integ.report_sha256}. Confere com o SHA256SUMS.txt da pasta de evidências.`) : null));
}

// Compara com a varredura anterior do mesmo aparelho: o que é novo, o que sumiu e o que continua.
async function loadComparison(r, name, ui, slot, onNew) {
  if (!name) return;
  try { app.reports = await api("/api/reports"); } catch { return; }
  const prevInfo = previousOf(name, r.device.serial);
  if (!prevInfo) {
    fill(slot, el("p", { class: "compare-first muted small" }, icon("refresh", "sm"),
      "Primeira varredura salva deste aparelho. As próximas serão comparadas com esta."));
    return;
  }
  let prev;
  try { prev = await api(`/api/reports/${encodeURIComponent(prevInfo.name)}/relatorio.json`); } catch { return; }
  const diff = diffFindings(prev.findings || [], r.findings);
  ui.added = new Set(diff.added);
  fill(slot, comparisonCard(r, prev, prevInfo, diff));
  if (diff.added.length) onNew();
}

function comparisonCard(r, prev, prevInfo, diff) {
  const stat = (n, label, cls) => el("div", { class: `cmp-stat ${n ? cls : ""}` }, el("strong", {}, n), el("span", {}, label));
  const line = (f, i) => el("li", { class: `s-${f.severity}` }, el("span", { class: "sev" }, f.severity_label || SEV_LABEL[f.severity]),
    f.title, i != null ? el("a", { class: "fcode", href: `#relatorios/${r.report_name}/achado/${i}` }, findingCode(i)) : null);
  const list = (title, items, empty) => el("div", {}, el("h4", {}, title),
    items.length ? el("ul", { class: "cmp-list" }, items.slice(0, 6), items.length > 6
      ? el("li", { class: "muted" }, `e mais ${items.length - 6}`) : null) : el("p", { class: "muted small" }, empty));
  const sameMode = prev.mode === r.mode;
  return el("div", { class: "card compare-card" },
    el("div", { class: "compare-head" },
      el("div", { class: "grow" }, el("strong", {}, "Desde a varredura anterior"),
        el("div", { class: "muted small" }, `${when(prevInfo.started)} · ${MODE_LABEL[prev.mode] || prev.mode} · `,
          el("span", {}, prevInfo.verdict?.label || ""))),
      el("a", { class: "btn", href: `#relatorios/${prevInfo.name}` }, "Abrir a anterior")),
    el("div", { class: "cmp-stats" },
      stat(diff.added.length, "novos", "bad"), stat(diff.resolved.length, "não aparecem mais", "good"),
      stat(diff.kept, "continuam", "")),
    diff.added.length || diff.resolved.length ? el("div", { class: "cmp-cols" },
      list("Apareceram agora", diff.added.map((i) => line(r.findings[i], i)), "Nada novo."),
      list("Não aparecem mais", diff.resolved.map((f) => line(f, null)), "Nada sumiu.")) : null,
    el("p", { class: "muted small" }, sameMode ? "" : `As duas varreduras são de tipos diferentes (${MODE_LABEL[prev.mode] || prev.mode} `
      + `× ${MODE_LABEL[r.mode] || r.mode}); parte da diferença pode vir disso. `,
    "Um achado que não aparece mais não prova que o problema acabou: confira o que mudou no celular."));
}

function matches(f, query) {
  if (!query) return true;
  return `${f.title} ${f.detail} ${f.recommendation} ${f.package || ""} ${f.family || ""}`.toLowerCase().includes(query);
}

function findingsTab(r, ui, redraw, links) {
  const catTitle = Object.fromEntries(r.categories.map((c) => [c.id, c.title]));
  const query = ui.query.trim().toLowerCase();
  const visible = (i) => ui.severities.has(r.findings[i].severity) && (!ui.category || r.findings[i].category === ui.category)
    && matches(r.findings[i], query) && (!ui.onlyNew || ui.added?.has(i));
  const card = (i) => findingCard(r.findings[i], catTitle, i, links, ui.added?.has(i));
  const candidates = new Map((r.removal_candidates || []).map((c) => [c.package, c]));
  const setGroup = (g) => { ui.groupBy = g; store.set("desgrampa-groupby", g); redraw(); };

  const search = el("input", { class: "search", type: "search", value: ui.query, placeholder: "Buscar nos achados",
    "aria-label": "Buscar nos achados", oninput: (ev) => {
      ui.query = ev.target.value;
      const pos = ev.target.selectionStart;
      redraw();
      const again = document.querySelector(".tabpanel input.search");
      again?.focus();
      again?.setSelectionRange(pos, pos);
    } });
  const controls = el("div", { class: "filters" },
    search,
    el("div", { class: "seg small-seg" }, [["categoria", "Por categoria"], ["origem", "Por origem"], ["lista", "Lista"]]
      .map(([k, label]) => el("button", { class: ui.groupBy === k ? "on" : "", onclick: () => setGroup(k) }, label))),
    el("span", { class: "sep" }),
    SEV_ORDER.map((sv) => el("button", {
      class: ui.severities.has(sv) ? "on" : "",
      onclick: () => { ui.severities.has(sv) ? ui.severities.delete(sv) : ui.severities.add(sv); redraw(); },
    }, `${SEV_LABEL[sv]} (${r.counts[sv]})`)),
    ui.added?.size ? el("button", { class: ui.onlyNew ? "on" : "", title: "Mostrar só o que não aparecia na varredura anterior",
      onclick: () => { ui.onlyNew = !ui.onlyNew; redraw(); } }, `Só novos (${ui.added.size})`) : null,
    ui.category ? el("button", { class: "on", onclick: () => { ui.category = null; redraw(); } },
      `Área: ${catTitle[ui.category]} ✕`) : null,
  );

  const sourceGroup = (g, extra) => {
    const items = g.items.filter(visible);
    if (!items.length) return null;
    const cand = g.package && candidates.get(g.package);
    const open = Boolean(query) || ["critica", "alta"].includes(g.worst) || items.includes(ui.focus);
    return el("details", { class: `group src st-${g.worst}`, open },
      el("summary", {},
        el("span", { class: "g-title" }, g.label, el("span", { class: "g-total" }, ` (${g.total})`)),
        countsLine(g.counts),
        extra || null,
        cand ? el("span", { class: "tag bad", title: "Sugerido para remoção" }, "remoção sugerida") : null),
      items.map(card));
  };

  let content;
  if (ui.groupBy === "lista") {
    const shown = r.findings.map((_, i) => i).filter(visible);
    content = shown.map(card);
  } else if (ui.groupBy === "origem") {
    content = (r.groups || []).map((g) => sourceGroup(g,
      el("span", { class: "muted small" }, g.categories.map((c) => catTitle[c]).join(" · "))));
  } else {
    content = (r.tree || []).filter((c) => !ui.category || c.category === ui.category).map((cat) => {
      const children = cat.children.map((g) => sourceGroup(g)).filter(Boolean);
      if (!children.length) return null;
      return el("details", { class: `group cat-group st-${cat.worst}`, open: true },
        el("summary", {}, el("span", { class: "g-title" }, cat.title, el("span", { class: "g-total" }, ` (${cat.total})`)),
          countsLine(cat.counts), el("span", { class: "muted small" }, `${cat.children.length} origem(ns)`)),
        children);
    });
  }
  content = (content || []).filter(Boolean);
  return el("div", {}, controls, content.length ? content : el("p", { class: "muted" }, "Nenhum achado neste filtro."));
}

export function countsLine(counts) {
  const parts = SEV_ORDER.filter((sv) => counts[sv]).map((sv) =>
    el("span", { class: `cnt s-${sv}` }, `${counts[sv]} ${SEV_PLURAL[sv][counts[sv] === 1 ? 0 : 1]}`));
  return el("span", { class: "counts" }, parts.flatMap((p, i) => (i ? [el("span", { class: "dotsep" }, "·"), p] : [p])));
}

function findingCard(f, catTitle, index, links, isNew = false) {
  const copy = (ev) => copyText(`${location.origin}/#relatorios/${links.name}/achado/${index}`, ev.currentTarget, "Link copiado");
  return el("div", { class: `finding s-${f.severity}`, id: `achado-${index}` },
    el("div", { class: "finding-top" },
      el("span", { class: "fcode", title: "Código deste achado no relatório" }, findingCode(index)),
      el("span", { class: "sev" }, f.severity_label), el("span", { class: "title grow" }, f.title),
      isNew ? el("span", { class: "tag new", title: "Não aparecia na varredura anterior deste aparelho" }, "novo") : null,
      links?.name ? el("button", { class: "link-btn small", onclick: copy, title: "Copiar link direto para este achado" }, "Copiar link") : null),
    el("p", {}, f.detail),
    f.recommendation ? el("p", { class: "rec" }, el("strong", {}, "O que fazer: "), f.recommendation) : null,
    el("p", { class: "muted small finding-src" }, [...new Set([catTitle[f.category], f.check])].filter(Boolean).join(" · "),
      f.package ? [" · ", el("code", {}, f.package)] : null),
  );
}
