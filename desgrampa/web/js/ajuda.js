// Página “Preciso de ajuda”: contatos, Defensoria por estado, como preservar evidências e base legal.

import { $, api, el, fill, store } from "./dom.js";
import { app } from "./state.js";
import { reportLinks } from "./scan.js";

let cache = null;

async function helpData() {
  cache = cache || await api("/api/ajuda");
  return cache;
}

function contactCard(c) {
  return el("div", { class: "contact" },
    el("strong", {}, c.nome),
    el("span", { class: "muted small" }, c.quando),
    el("div", { class: "contact-links" },
      c.telefone ? el("a", { href: `tel:${c.telefone}`, class: "pill" }, `Ligar ${c.telefone}`) : null,
      c.url ? el("a", { href: c.url, target: "_blank", rel: "noopener noreferrer" }, "Abrir site") : null));
}

function defensoria(data) {
  const out = el("p", { class: "small" });
  const show = (uf) => {
    const d = data.defensorias[uf];
    fill(out, d ? ["Defensoria Pública do ", d[0], ": ", el("a", { href: d[1], target: "_blank", rel: "noopener noreferrer" }, d[1])]
      : "Escolha o estado para ver o site da Defensoria Pública.");
  };
  const saved = store.get("desgrampa-uf", "");
  const select = el("select", { class: "plain", "aria-label": "Estado", onchange: (ev) => {
    store.set("desgrampa-uf", ev.target.value);
    show(ev.target.value);
  } }, el("option", { value: "" }, "Seu estado"),
  Object.entries(data.defensorias).sort((a, b) => a[1][0].localeCompare(b[1][0], "pt-BR"))
    .map(([uf, [name]]) => el("option", { value: uf, selected: uf === saved }, name)));
  show(saved);
  return el("div", {}, select, out);
}

export async function renderHelp() {
  const box = $("#ajuda");
  let data;
  try {
    data = await helpData();
  } catch (e) {
    fill(box, el("p", {}, e.message));
    return;
  }
  const last = app.reports[0];
  fill(box,
    el("div", { class: "card urgent" },
      el("h2", {}, "Em perigo agora? Ligue 190."),
      el("p", {}, "Violência contra a mulher: ", el("strong", {}, "Ligue 180"), " (gratuito, 24 h, também pelo WhatsApp (61) 9610-0180)."),
      el("p", { class: "small muted" }, "Use o botão “Sair rápido”, no alto da tela, se alguém se aproximar: ele troca esta página por um site comum.")),
    el("div", { class: "grid-2" },
      el("div", { class: "card" },
        el("h2", {}, "Com quem falar"),
        el("div", { class: "contacts" }, data.contatos.map(contactCard))),
      el("div", { class: "card" },
        el("h2", {}, "Onde registrar e pedir proteção"),
        el("ul", { class: "small" }, data.onde_registrar.map((t) => el("li", {}, t))),
        defensoria(data),
        last ? el("p", { class: "small" }, "Leve o relatório da última varredura: ",
          el("a", { href: reportLinks(last.name).authority, target: "_blank", rel: "noopener" }, "relatório para atendimento"),
          " · ", el("a", { href: reportLinks(last.name).zip, download: true }, "pacote de evidências (.zip)"))
          : null)),
    el("div", { class: "card" },
      el("h2", {}, "Como guardar as provas"),
      el("ol", { class: "steps" }, data.evidencias.map((t) => el("li", {}, t)))),
    el("div", { class: "card" },
      el("h2", {}, "O que diz a lei"),
      el("p", { class: "muted small" }, data.aviso),
      data.leis.map((law) => el("details", { class: "law" },
        el("summary", {}, el("strong", {}, law.titulo), el("span", { class: "muted small" }, ` — ${law.norma}`)),
        el("p", {}, law.explicacao),
        el("blockquote", {}, law.texto),
        el("a", { class: "small", href: law.fonte, target: "_blank", rel: "noopener noreferrer" }, "Texto oficial")))),
  );
}

// ------------------------------------------------------------ saída rápida

const NEUTRAL_URL = "https://www.google.com/search?q=previs%C3%A3o+do+tempo";

export function quickExit() {
  try { sessionStorage.clear(); } catch { /* sem armazenamento */ }
  document.title = "Nova guia";
  document.body.replaceChildren();
  location.replace(NEUTRAL_URL);   // replace: o botão “voltar” não retorna ao painel
}

export function installQuickExit() {
  $("#quick-exit").addEventListener("click", quickExit);
  let last = 0;
  document.addEventListener("keydown", (ev) => {   // Esc duas vezes seguidas também sai
    if (ev.key !== "Escape") return;
    if (Date.now() - last < 600) quickExit();
    last = Date.now();
  });
}
