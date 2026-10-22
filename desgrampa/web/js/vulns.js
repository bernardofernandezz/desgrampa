// Abas técnicas novas: vulnerabilidades (CVEs com filtros) e linha do tempo do aparelho.

import { el, fill, table, tag } from "./dom.js";
import { ACTION_NOUN } from "./state.js";

const SEV = { C: ["Crítica", "bad"], H: ["Alta", "warn"], M: ["Moderada", ""], L: ["Baixa", ""] };
const SCOPE = { aosp: "Android", kernel: "Kernel Linux", qcom: "Chip Qualcomm", pixel: "Google Pixel" };
const TYPES = { RCE: "execução remota de código", EoP: "elevação de privilégio", ID: "vazamento de informação",
  DoS: "negação de serviço" };
const PAGE = 100;

const cveLink = (cve) => (/^CVE-\d{4}-\d+$/.test(cve)
  ? el("a", { href: `https://nvd.nist.gov/vuln/detail/${cve}`, target: "_blank", rel: "noopener" }, cve) : cve);

function iosVulns(ios) {
  const st = ios.status;
  return el("div", {},
    el("div", { class: "facts" },
      el("div", {}, el("span", {}, "Modelo"), ios.model || "?"),
      el("div", {}, el("span", {}, "iOS instalado"), ios.version || "?"),
      el("div", {}, el("span", {}, "Mais novo para este modelo"), st?.best_for_model || "desconhecido"),
      el("div", {}, el("span", {}, "iOS mais recente"), st?.latest || "?"),
      el("div", {}, el("span", {}, "Backup"), `${ios.encrypted ? "criptografado" : "sem criptografia"}${ios.last_backup ? ` · ${ios.last_backup}` : ""}`),
      el("div", {}, el("span", {}, "Alertas do MVT"), String(ios.mvt_alerts ?? 0))),
    st?.exploited?.length ? [el("h3", {}, "Falhas da Apple exploradas ativamente desde a sua versão"),
      el("p", {}, st.exploited.map(cveLink).flatMap((x, i) => (i ? [", ", x] : [x])))] : null,
    el("p", { class: "muted small" }, "Para iPhone, a base de boletins não tem detalhe por componente: a comparação "
      + "usa as versões publicadas pela Apple e o catálogo de falhas exploradas da CISA."));
}

export function vulnsTab(v, ios) {
  if (!v && ios) return iosVulns(ios);
  if (!v) return el("p", { class: "muted" }, "Vulnerabilidades não verificadas nesta varredura (base ausente ou relatório antigo).");
  const ui = { sev: new Set(["C", "H", "M", "L"]), kev: false, scope: "", q: "", shown: PAGE };
  const list = el("div");
  const scopes = [...new Set(v.items.map((i) => i.scope))];

  function draw() {
    const q = ui.q.trim().toLowerCase();
    const rows = v.items.filter((i) => ui.sev.has(i.severity) && (!ui.kev || i.kev) && (!ui.scope || i.scope === ui.scope)
      && (!q || `${i.cve} ${i.component} ${i.summary}`.toLowerCase().includes(q)));
    fill(list,
      el("p", { class: "muted small" }, `${rows.length} de ${v.items.length} falhas`),
      table(["CVE", "Gravidade", "Explorada", "Componente", "Corrigida no patch", "Tipo", "Resumo"],
        rows.slice(0, ui.shown).map((i) => [cveLink(i.cve), tag(SEV[i.severity][0], SEV[i.severity][1]),
          i.kev ? tag("SIM", "bad") : "—", `${i.component} (${SCOPE[i.scope] || i.scope})`, i.spl,
          i.types.map((t) => TYPES[t] || t).join(", ") || "—", i.summary || "—"]),
        "Nenhuma falha neste filtro."),
      rows.length > ui.shown ? el("button", { onclick: () => { ui.shown += PAGE * 5; draw(); } },
        `Mostrar mais (${rows.length - ui.shown} restantes)`) : null);
  }

  const toggle = (k) => el("button", { class: ui.sev.has(k) ? "on" : "", onclick: (ev) => {
    ui.sev.has(k) ? ui.sev.delete(k) : ui.sev.add(k);
    ev.currentTarget.classList.toggle("on");
    ui.shown = PAGE;
    draw();
  } }, `${SEV[k][0]} (${v.counts[k]})`);

  const exp = v.exposure;
  const d = v.device;
  draw();
  return el("div", {},
    el("div", { class: "facts" },
      el("div", {}, el("span", {}, "Patch de segurança"), d.spl),
      el("div", {}, el("span", {}, "Android"), `${d.android}${d.eol ? " (sem suporte)" : ""}`),
      el("div", {}, el("span", {}, "Versões ainda atualizadas"), d.supported.join(", ")),
      el("div", {}, el("span", {}, "Falhas sem correção"), `${v.counts.total} (${v.counts.kev} exploradas ativamente)`),
      el("div", {}, el("span", {}, "Prováveis (versão sem suporte)"), String(v.counts.likely)),
      el("div", {}, el("span", {}, "Base"), `boletins até ${v.db.latest_spl} · gerada em ${v.db.generated}`)),
    exp ? [el("h3", {}, `Índice de exposição: ${exp.score}/100 (${exp.label})`),
      table(["Fator", "Pontos", "Presente"], exp.factors.map((f) => [f.label, f.points, f.active ? tag("sim", "warn") : "não"]))] : null,
    v.chromium.length ? [el("h3", {}, "Chrome e WebView"),
      table(["App", "Versão", "Estável atual", "Atraso", "Falhas exploradas desde então"], v.chromium.map((c) => [
        c.name, c.version, c.stable, c.behind > 0 ? tag(`${c.behind} versões`, c.behind >= 2 ? "warn" : "") : tag("em dia", "good"),
        c.exploited.length ? c.exploited.map(cveLink).flatMap((x, i) => (i ? [", ", x] : [x])) : "—"]))] : null,
    v.apps.length ? [el("h3", {}, "Apps de mensagem com falha explorada"),
      table(["App", "Instalado", "Corrigido em", "Falha"], v.apps.map((a) => [a.name, a.version, a.fixed,
        [cveLink(a.cve), " — ", a.summary]]))] : null,
    el("h3", {}, "Falhas dos boletins de segurança ainda abertas"),
    el("div", { class: "filters" },
      ["C", "H", "M", "L"].map(toggle),
      el("button", { class: ui.kev ? "on" : "", onclick: (ev) => { ui.kev = !ui.kev; ev.currentTarget.classList.toggle("on"); draw(); } },
        `Só exploradas (${v.counts.kev})`),
      el("select", { class: "plain", "aria-label": "Componente", onchange: (ev) => { ui.scope = ev.target.value; draw(); } },
        el("option", { value: "" }, "Todos os componentes"), scopes.map((s) => el("option", { value: s }, SCOPE[s] || s))),
      el("input", { class: "search", type: "search", placeholder: "Buscar CVE ou componente", "aria-label": "Buscar falha",
        oninput: (ev) => { ui.q = ev.target.value; ui.shown = PAGE; draw(); } })),
    list,
    el("p", { class: "muted small" }, "Fontes: Android Security Bulletins (via OSV), CISA Known Exploited Vulnerabilities e "
      + "Chrome Version History. Falhas de chips de outros fabricantes (MediaTek, Exynos, Unisoc) e boletins próprios "
      + "das marcas (Samsung, Motorola…) não estão na base: o número real pode ser maior."),
  );
}

// ------------------------------------------------------------ linha do tempo

const KIND = { install: ["Instalação", ""], removal: ["Remoção", "warn"], spy: ["Indicador de spyware", "bad"],
  action: ["Ação no Desgrampa", "good"], scan: ["Varredura", ""] };

export function timelineEvents(r) {
  const events = [];
  const spy = new Set((r.findings || []).filter((f) => f.package && ["critica", "alta"].includes(f.severity)).map((f) => f.package));
  for (const a of r.apps || []) {
    if (a.first_install) events.push({ time: a.first_install, kind: spy.has(a.package) ? "spy" : "install",
      text: `${a.package} instalado${a.version ? ` (versão ${a.version})` : ""}${a.sideloaded ? " fora da loja oficial" : ""}` });
  }
  for (const e of r.data?.rastros?.install_events || []) {
    if (!e.time) continue;
    events.push({ time: e.time, kind: e.event === "removido" ? "removal" : spy.has(e.package) ? "spy" : "install",
      text: `${e.package} ${e.event} (histórico de bateria)` });
  }
  for (const a of r.actions || []) events.push({ time: a.time, kind: "action", text: `${ACTION_NOUN[a.action] || a.action}: ${a.package} — ${a.status}` });
  events.push({ time: r.started, kind: "scan", text: `Varredura ${r.mode} pelo Desgrampa` });
  return events.filter((e) => /^\d{4}-\d{2}-\d{2}/.test(e.time) && !e.time.startsWith("1970") && !e.time.startsWith("2008"))
    .sort((a, b) => b.time.localeCompare(a.time));
}

export function timelineTab(r) {
  const events = timelineEvents(r);
  if (!events.length) return el("p", { class: "muted" }, "Sem datas suficientes para montar a linha do tempo.");
  let month = null;
  return el("div", {},
    el("p", { class: "muted small" }, "Datas de instalação dos apps, instalações e remoções do histórico de bateria e "
      + "ações feitas no Desgrampa. Procure instalações perto de quando alguém teve acesso ao seu celular."),
    el("ol", { class: "timeline" }, events.map((e) => {
      const m = e.time.slice(0, 7);
      const head = m !== month ? el("li", { class: "tl-month" }, new Date(`${m}-01T00:00:00`)
        .toLocaleDateString("pt-BR", { month: "long", year: "numeric" })) : null;
      month = m;
      return [head, el("li", { class: `tl-${e.kind}` }, el("time", {}, e.time.slice(0, 16)),
        tag(KIND[e.kind][0], KIND[e.kind][1]), el("span", {}, e.text))];
    })));
}
