// Rastreabilidade: identificação de relatórios e aparelhos, histórico por aparelho e comparação entre varreduras.

import { el, fmtDate } from "./dom.js";
import { app, SEV_PLURAL } from "./state.js";

export const MODE_LABEL = { rapida: "Rápida", completa: "Completa (forense)", iphone: "iPhone (backup + MVT)" };

// "samsung SM-A515F" -> "Samsung SM-A515F"
export function prettyDevice(name) {
  return name ? name.charAt(0).toUpperCase() + name.slice(1) : "";
}

export function fmtDuration(s) {
  if (s == null) return "—";
  if (s < 1) return "menos de 1 s";
  if (s < 60) return `${Math.round(s)} s`;
  const m = Math.floor(s / 60);
  return `${m} min ${String(Math.round(s % 60)).padStart(2, "0")} s`;
}

const toDate = (s) => new Date(String(s || "").replace(" ", "T"));

// "agora há pouco", "há 3 h", "ontem", "há 5 dias", "há 2 meses"
export function relTime(s, now = Date.now()) {
  const d = toDate(s);
  if (Number.isNaN(d.getTime())) return "";
  const min = Math.round((now - d.getTime()) / 60000);
  if (min < 2) return "agora há pouco";
  if (min < 60) return `há ${min} min`;
  const h = Math.round(min / 60);
  if (h < 24) return `há ${h} h`;
  const days = Math.round(h / 24);
  if (days === 1) return "ontem";
  if (days < 31) return `há ${days} dias`;
  const months = Math.round(days / 30.44);
  return months < 12 ? `há ${months} ${months === 1 ? "mês" : "meses"}` : `há ${Math.round(months / 12)} ano(s)`;
}

export const when = (s) => [fmtDate(s), relTime(s)].filter(Boolean).join(" · ");

// Relatórios do mesmo aparelho, do mais recente para o mais antigo.
export function reportsOf(serial, reports = app.reports) {
  return reports.filter((r) => r.serial && r.serial === serial)
    .sort((a, b) => toDate(b.started) - toDate(a.started));
}

// Varredura imediatamente anterior a `name` do mesmo aparelho (ou null).
export function previousOf(name, serial, reports = app.reports) {
  const list = reportsOf(serial, reports);
  const i = list.findIndex((r) => r.name === name);
  return i >= 0 ? list[i + 1] || null : null;
}

// Mesmo achado em duas varreduras: mesma área, mesmo app e mesmo título.
export const findingKey = (f) => `${f.category}|${f.package || ""}|${f.title}`;

// Compara os achados relevantes (sem "info") de duas varreduras.
// added: índices em `cur` dos achados novos; resolved: achados de `prev` que sumiram; kept: quantos continuam.
export function diffFindings(prev, cur) {
  const relevant = (f) => f.severity !== "info";
  const before = new Set(prev.filter(relevant).map(findingKey));
  const now = new Set(cur.filter(relevant).map(findingKey));
  const added = cur.map((f, i) => [f, i]).filter(([f]) => relevant(f) && !before.has(findingKey(f))).map(([, i]) => i);
  const resolved = prev.filter((f) => relevant(f) && !now.has(findingKey(f)));
  const kept = [...now].filter((k) => before.has(k)).length;
  return { added, resolved, kept };
}

// Diferença de contagem por gravidade (ex.: "+2 críticos · −3 altos"); vazio quando nada mudou.
export function countsTrend(cur = {}, prev = {}) {
  return ["critica", "alta", "media"].map((sv) => [sv, (cur[sv] || 0) - (prev[sv] || 0)]).filter(([, d]) => d)
    .map(([sv, d]) => ({ sv, d, text: `${d > 0 ? "+" : "−"}${Math.abs(d)} ${SEV_PLURAL[sv][Math.abs(d) === 1 ? 0 : 1]}` }));
}

// Barra empilhada com a proporção de achados por gravidade.
export function sevBar(counts = {}) {
  const parts = ["critica", "alta", "media", "baixa"].map((sv) => [sv, counts[sv] || 0]).filter(([, n]) => n);
  const total = parts.reduce((a, [, n]) => a + n, 0);
  return el("div", { class: "sevbar", role: "img", "aria-label": total
    ? parts.map(([sv, n]) => `${n} ${SEV_PLURAL[sv][n === 1 ? 0 : 1]}`).join(", ") : "nenhum achado" },
  total ? parts.map(([sv, n]) => el("span", { class: `s-${sv}`, style: `flex:${n}` })) : el("span", { class: "s-none" }));
}

// Código curto e estável de um achado dentro do relatório (#01, #02…), usado em links e conversas.
export const findingCode = (i) => `#${String(i + 1).padStart(2, "0")}`;

export async function copyText(text, button, done = "Copiado") {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = done;
    setTimeout(() => { button.textContent = old; }, 1600);
  } catch {
    prompt("Copie:", text);
  }
}
