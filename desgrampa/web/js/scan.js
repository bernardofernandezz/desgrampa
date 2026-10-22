// Início e acompanhamento de uma varredura.

import { $, api, el, fill } from "./dom.js";
import { app } from "./state.js";
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
  setProgress(0, "Iniciando");
  poll(id);
}

function setProgress(fraction, step) {
  const pct = `${Math.round(fraction * 100)}%`;
  $("#bar-fill").style.width = pct;
  $("#pct").textContent = pct;
  $("#step").textContent = step;
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

  setProgress(job.progress, job.step);
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
export async function showReport(box, name) {
  const report = await api(reportLinks(name).json);
  renderDashboard(box, report, reportLinks(name), () => showReport(box, name));
}

export function reportLinks(name) {
  const base = `/api/reports/${encodeURIComponent(name)}`;
  return { html: `${base}/relatorio.html`, json: `${base}/relatorio.json` };
}
