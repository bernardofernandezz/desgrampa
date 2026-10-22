// Início e acompanhamento de uma varredura.

import { $, api, el, fill } from "./dom.js";
import { app, SEV_LABEL, SEV_PLURAL } from "./state.js";
import { go, route } from "./router.js";
import { refreshStatus, setReady } from "./device.js";
import { loadReports } from "./reports.js";
import { renderDashboard } from "./dashboard.js";

const POLL_MS = 800;          // enquanto a varredura roda
const POLL_RETRY_MS = 2000;   // depois de uma falha de rede

export async function startScan() {
  const mode = document.querySelector("input[name=mode]:checked").value;
  try {
    const { id } = await api("/api/scan", { serial: app.serial, mode, pc_network: $("#pc-network").checked });
    go(`#varredura/scan/${id}`);
  } catch (e) {
    showError(e.message);
  }
}

// Ao abrir a página com uma varredura já em andamento, volta a acompanhá-la.
export function resumeRunning() {
  const run = (app.status.running || [])[0];
  if (run && !app.polling && route().page === "varredura") go(`#varredura/scan/${run.id}`);
}

export function showScan(id) {
  if (app.polling === id) return;
  app.polling = id;
  app.scanning = true;
  setReady();
  $("#result").classList.add("hidden");
  $("#progress").classList.remove("hidden");
  setProgress({ progress: 0, step: "Iniciando" });
  poll(id);
}

const CHECK_STATE = { pending: "aguardando", running: "em andamento", ok: "concluída", skipped: "não executada",
  error: "falhou" };

const fmtElapsed = (s) => (s < 60 ? `${s}s` : `${Math.floor(s / 60)}min ${String(s % 60).padStart(2, "0")}s`);

// Linha de uma verificação: estado, nome e quantos achados relevantes ela trouxe.
function checkItem(c) {
  const relevant = ["critica", "alta", "media"].filter((sv) => c.counts?.[sv]);
  const worst = relevant[0];
  return el("li", { class: `ck ck-${c.status}${worst ? ` s-${worst}` : ""}`, title: c.reason || CHECK_STATE[c.status] },
    el("span", { class: "ck-mark", "aria-hidden": "true" }),
    el("span", { class: "grow" }, c.name, el("span", { class: "sr-only" }, ` — ${CHECK_STATE[c.status]}`)),
    worst ? el("span", { class: "cnt" }, relevant.map((sv) => c.counts[sv]).reduce((a, b) => a + b)) : null);
}

function setProgress(job) {
  const pct = Math.round(job.progress * 100);
  $("#bar-fill").style.width = `${pct}%`;
  $("#bar").setAttribute("aria-valuenow", pct);
  $("#pct").textContent = `${pct}%`;
  $("#step").textContent = job.step;
  $("#elapsed").textContent = job.elapsed_s != null ? fmtElapsed(job.elapsed_s) : "";
  const checks = job.checks || [];   // a análise de iPhone só informa a etapa
  const done = checks.filter((c) => !["pending", "running"].includes(c.status)).length;
  const found = job.found || {};
  fill($("#live-found"), checks.length ? [
    el("span", { class: "muted small" }, `${done} de ${checks.length} verificações`),
    ["critica", "alta", "media"].filter((sv) => found[sv]).map((sv) =>
      el("span", { class: `cnt s-${sv} small` }, `${found[sv]} ${SEV_PLURAL[sv][found[sv] === 1 ? 0 : 1]}`)),
  ] : null);
  fill($("#checklist"), checks.map(checkItem));
  const alerts = (job.alerts || []).map((a, i) => ({ ...a, i }))   // críticos primeiro, depois os mais recentes
    .sort((a, b) => (a.severity === b.severity ? b.i - a.i : a.severity === "critica" ? -1 : 1));
  fill($("#live-alerts"), alerts.length ? el("div", { class: "live-alerts" },
    el("strong", {}, "Encontrado até agora"),
    el("ul", {}, alerts.slice(0, 5).map((a) => el("li", { class: `s-${a.severity}` },
      el("span", { class: "sev" }, SEV_LABEL[a.severity]), a.title, a.package ? el("code", { class: "muted" }, ` ${a.package}`) : null))),
    alerts.length > 5 ? el("span", { class: "muted small" }, `e mais ${alerts.length - 5}`) : null) : null);
}

function stopTracking() {
  app.polling = null;
  app.scanning = false;
  $("#progress").classList.add("hidden");
}

async function poll(id) {
  if (app.polling !== id) return;
  let job;
  try {
    job = await api(`/api/scan/${id}`);
  } catch (e) {
    if (e.status === 404) {   // servidor reiniciado: a varredura em memória não existe mais
      stopTracking();
      go("#varredura");
    } else {
      setTimeout(() => poll(id), POLL_RETRY_MS);
    }
    return;
  }

  setProgress(job);
  if (job.state === "running") {
    setTimeout(() => poll(id), POLL_MS);
    return;
  }
  stopTracking();
  if (job.state === "error") {
    showError(job.error);
    return;
  }
  const box = $("#result");
  box.classList.remove("hidden");
  await showReport(box, job.result.report_name);
  box.scrollIntoView({ behavior: "smooth" });
  loadReports();
  refreshStatus();
}

function showError(message) {
  stopTracking();
  const box = $("#result");
  box.classList.remove("hidden");
  fill(box, el("div", { class: "verdict suspeito", style: "margin-bottom:18px" },
    el("h2", {}, "A varredura não foi concluída"), el("p", {}, message),
    el("p", { class: "muted" }, "Verifique se o aparelho continua conectado e autorizado, e tente novamente.")));
  setReady();
}

// Mostra um relatório salvo no elemento `box`; após uma remoção/desativação ele se recarrega.
export async function showReport(box, name, focus = {}) {
  const report = await api(reportLinks(name).json);
  renderDashboard(box, report, reportLinks(name), () => showReport(box, name), focus);
}

export function reportLinks(name) {
  const base = `/api/reports/${encodeURIComponent(name)}`;
  return { name, html: `${base}/relatorio.html`, json: `${base}/relatorio.json`, view: `${base}/relatorio.html?ver=1`,
    authority: `${base}/atendimento.html`, stix: `${base}/relatorio.stix.json`, csv: `${base}/vulnerabilidades.csv`,
    zip: `${base}/evidencias.zip` };
}
