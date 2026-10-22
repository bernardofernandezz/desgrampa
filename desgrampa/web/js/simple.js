// Modo simples do resultado: semáforo, o que fazer agora e áreas em linguagem do dia a dia.

import { el } from "./dom.js";

const LIGHT = {
  alto_risco: ["vermelho", "Risco", "Encontramos sinais fortes de que o celular pode estar sendo espionado ou adulterado."],
  suspeito: ["vermelho", "Risco", "Encontramos sinais que precisam ser verificados com atenção."],
  atencao: ["amarelo", "Atenção", "Nada indica espionagem, mas há configurações ou falhas que deixam o celular mais exposto."],
  ok: ["verde", "Nenhum sinal encontrado", "Não encontramos sinais de espionagem nas verificações feitas."],
};

// Área -> [nome simples, pergunta que ela responde, ícone]
export const AREAS = {
  spyware: ["Apps espiões", "Existe algum app espião conhecido instalado?", "eye"],
  mercenario: ["Espionagem avançada", "Há sinais de spyware usado por governos ou empresas de vigilância?", "target"],
  intercept: ["Conexões interceptadas", "Alguém pode estar lendo o que você acessa na internet?", "lock"],
  rede: ["Internet do celular", "O celular está mandando dados para lugares estranhos?", "wifi"],
  pcnet: ["Rede Wi-Fi", "A rede deste computador está adulterada?", "router"],
  telefonia: ["Ligações e chip", "Suas ligações ou SMS estão sendo desviados?", "phoneCall"],
  contas: ["Contas e perfis", "Tem conta ou perfil escondido no celular?", "user"],
  controle: ["Controle à distância", "Alguém consegue controlar ou localizar o celular?", "remote"],
  rastros: ["Rastros", "Já houve um app espião que foi apagado?", "footprints"],
  sistema: ["Sistema", "O sistema do celular foi modificado?", "chip"],
  apps: ["Apps com acesso demais", "Algum app tem acesso perigoso a mensagens, tela ou microfone?", "grid"],
  protecoes: ["Proteções", "As proteções do Android estão ligadas?", "shield"],
  vulns: ["Falhas de segurança", "O celular tem falhas conhecidas que permitem invasão?", "bug"],
};

const AREA_STATE = {
  critica: ["bad", "Problema"], alta: ["bad", "Problema"], media: ["warn", "Atenção"],
  baixa: ["ok", "OK"], ok: ["ok", "OK"], nao_verificado: ["nv", "Não verificado"],
};

// Ícones de traço próprios desta tela (conteúdo fixo, nunca dados do aparelho)
const ICONS = {
  eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  wifi: '<path d="M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M2 9a15 15 0 0 1 20 0"/><circle cx="12" cy="19.5" r=".8"/>',
  router: '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 16.5h.01M11 16.5h.01M17 13V5"/>',
  phoneCall: '<path d="M5 3h4l2 5-2.5 1.5a11 11 0 0 0 6 6L16 13l5 2v4a2 2 0 0 1-2 2A17 17 0 0 1 3 5a2 2 0 0 1 2-2Z"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  remote: '<rect x="7" y="2" width="10" height="20" rx="3"/><circle cx="12" cy="8" r="2"/><path d="M10 14h4M10 17h4"/>',
  footprints: '<path d="M7 16c-1.5 0-3-1.8-3-5S5.3 4 7 4s3 2.7 3 6-1.5 6-3 6ZM17 20c-1.5 0-3-1.8-3-5s1.3-7 3-7 3 2.7 3 6-1.5 6-3 6Z"/>',
  chip: '<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  shield: '<path d="M12 3 5 6v5c0 4.5 3 8.3 7 9.5 4-1.2 7-5 7-9.5V6l-7-3Z"/>',
  bug: '<rect x="7" y="7" width="10" height="13" rx="5"/><path d="M12 7V4M9 4l1.5 3M15 4l-1.5 3M3 12h4M17 12h4M4 18l3-2M20 18l-3-2"/>',
};

function areaIcon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", "ico area-ico");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = ICONS[name];
  return svg;
}

const RANK = { critica: 0, alta: 1, media: 2, baixa: 3, info: 4 };
// Gravidade em palavras do dia a dia (igual a explain.SEVERITY_PLAIN)
const PLAIN_SEV = { critica: "Grave", alta: "Preocupante", media: "Vale conferir", baixa: "Pouco preocupante", info: "Informativo" };

// Até `limit` passos, do mais grave para o menos grave, sem repetir a mesma recomendação.
export function nextSteps(r, limit = 5) {
  const steps = [];
  const seen = new Set();
  if ((r.removal_candidates || []).length || r.counts.critica) {
    steps.push({ sev: "critica", title: "Antes de apagar qualquer coisa, pense na sua segurança",
      text: "Quem instalou um app espião pode perceber a remoção. Guarde este relatório, baixe a versão para "
        + "atendimento e, se possível, procure apoio (veja “Preciso de ajuda”)." });
  }
  const findings = r.findings.filter((f) => f.severity !== "info" && f.recommendation)
    .sort((a, b) => RANK[a.severity] - RANK[b.severity]);
  for (const f of findings) {
    if (steps.length >= limit) break;
    if (seen.has(f.recommendation)) continue;
    seen.add(f.recommendation);
    steps.push({ sev: f.severity, title: f.title, text: f.recommendation });
  }
  if (steps.length < limit) {
    steps.push({ sev: "info", title: "Desligue a Depuração USB",
      text: "Em Configurações › Opções do desenvolvedor, desligue a Depuração USB (e a por Wi-Fi) e toque em "
        + "“Revogar autorizações”. Ligada, ela facilita que alguém com o celular na mão instale algo." });
  }
  if (steps.length < limit) {
    steps.push({ sev: "info", title: "Confira também o que não aparece pelo cabo",
      text: "Dispositivos conectados ao WhatsApp e à conta Google, compartilhamento de localização e desvio "
        + "de chamadas na operadora: veja a lista em “Verificações manuais” no modo técnico." });
  }
  return steps;
}

function exposureGauge(exp) {
  if (!exp) return null;
  return el("div", { class: `gauge lv-${exp.level}`, role: "img",
    "aria-label": `Exposição a ataques: ${exp.label}, ${exp.score} de 100` },
    el("div", { class: "gauge-head" }, el("span", {}, "Exposição a ataques"), el("strong", {}, exp.label)),
    el("div", { class: "gauge-bar" }, el("div", { style: `width:${Math.max(exp.score, 3)}%` })),
    el("ul", { class: "gauge-factors" }, exp.factors.filter((f) => f.active).slice(0, 4).map((f) => el("li", {}, f.label))),
  );
}

// `threats`: painel de ameaças (actions.js), mostrado logo abaixo do semáforo.
export function simpleView(r, openArea, threats = null) {
  const [color, label, text] = LIGHT[r.verdict.code] || LIGHT.ok;
  const exp = r.data?.vulns?.exposure;
  const byCat = (cid) => r.findings.filter((f) => f.category === cid && f.severity !== "info");
  return el("div", { class: "simple" },
    el("div", { class: `light ${color}` },
      el("div", { class: "bulbs", "aria-hidden": "true" }, ["vermelho", "amarelo", "verde"].map((c) =>
        el("span", { class: `bulb ${c} ${c === color ? "on" : ""}` }))),
      el("div", { class: "grow" },
        el("h2", {}, label), el("p", {}, text),
        r.verdict.code === "ok" ? el("p", { class: "muted small" },
          "Isso não garante que o celular esteja limpo: nenhuma ferramenta consegue provar isso. Spyware muito "
          + "sofisticado pode não deixar rastros visíveis pelo cabo.") : null),
      exposureGauge(exp)),
    threats,
    el("h3", {}, "O que fazer agora"),
    el("ol", { class: "next-steps" }, nextSteps(r).map((s) => el("li", { class: `s-${s.sev}` },
      el("strong", {}, s.title), el("span", {}, s.text)))),
    el("h3", {}, "O que verificamos"),
    el("div", { class: "areas" }, r.categories.map((c) => {
      const [name, question, ico] = AREAS[c.id] || [c.title, c.description, "shield"];
      const [cls, state] = AREA_STATE[c.status];
      const found = byCat(c.id);
      return el("details", { class: `area st-${cls}` },
        el("summary", {}, areaIcon(ico), el("span", { class: "grow" }, el("strong", {}, name),
          el("span", { class: "muted small" }, question)), el("span", { class: `pill ${cls}` }, state)),
        el("div", { class: "area-body" },
          el("p", { class: "small" }, el("strong", {}, "Por que isso importa: "), c.description),
          found.length ? el("ul", { class: "small" }, found.slice(0, 4).map((f) => el("li", {}, el("strong", {}, `${PLAIN_SEV[f.severity]}: `), f.title)),
            found.length > 4 ? el("li", { class: "muted" }, `e mais ${found.length - 4}`) : null)
            : el("p", { class: "small muted" }, c.status === "nao_verificado"
              ? `Não verificado: ${c.checks.map((x) => x.reason).filter(Boolean).join("; ") || "sem dados"}.`
              : "Nada preocupante encontrado aqui."),
          found.length ? el("button", { class: "link-btn", onclick: () => openArea(c.id) }, "Ver detalhes técnicos") : null));
    })),
  );
}
