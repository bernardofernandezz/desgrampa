// Utilitários de DOM e de rede: criação segura de elementos, ícones, chamadas à API e formatação.
export const $ = (sel) => document.querySelector(sel);

// Cria elemento com texto seguro (dados do aparelho nunca vão para innerHTML)
export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

// replaceChildren() transforma null em texto "null" — este helper ignora filhos vazios
export function fill(node, ...children) {
  node.replaceChildren(...children.flat(Infinity).filter((c) => c != null && c !== false));
  return node;
}

// Ícones de traço (conteúdo fixo, nunca dados do aparelho)
const ICONS = {
  usb: '<path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z"/>',
  shield: '<path d="M12 3 5 6v5c0 4.5 3 8.3 7 9.5 4-1.2 7-5 7-9.5V6l-7-3Z"/><path d="m9 12 2 2 4-4"/>',
  shieldAlert: '<path d="M12 3 5 6v5c0 4.5 3 8.3 7 9.5 4-1.2 7-5 7-9.5V6l-7-3Z"/><path d="M12 8v4M12 15h.01"/>',
  battery: '<rect x="7" y="4" width="10" height="17" rx="2"/><path d="M10 2h4"/>',
  batteryCharging: '<rect x="7" y="4" width="10" height="17" rx="2"/><path d="M10 2h4M12.5 8l-2 4h3l-2 4"/>',
  file: '<path d="M14 2H7a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7l-5-5Z"/><path d="M14 2v5h5"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
  phone: '<rect x="6" y="2" width="12" height="20" rx="2.5"/><path d="M11 18h2"/>',
};

export function icon(name, cls = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("class", `ico ${cls}`);
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = ICONS[name];
  return svg;
}

export async function api(path, body) {
  const opts = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

export const store = {
  get(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* armazenamento indisponível */ }
  },
};

export function fmtDate(s) {
  if (!s) return "—";
  const d = new Date(s.replace(" ", "T"));
  if (Number.isNaN(d.getTime())) return s;
  return d.toLocaleDateString("pt-BR", { day: "numeric", month: "short", year: "numeric" })
    + " · " + d.toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit" });
}

export const num = (n) => n.toLocaleString("pt-BR", { maximumFractionDigits: 1 });

export function table(headers, rows, empty = "Nada a mostrar.") {
  if (!rows.length) return el("p", { class: "muted" }, empty);
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.map((row) => el("tr", {}, row.map((c) => el("td", {}, c ?? "—")))))));
}

export function tag(text, kind = "") {
  return el("span", { class: `tag ${kind}` }, text);
}

export function facts(items) {
  return el("div", { class: "facts" }, items.map(([label, value]) => el("div", {}, el("span", {}, label), value ?? "—")));
}

export const MB = (n) => `${Math.round(n / 1048576)} MB`;
