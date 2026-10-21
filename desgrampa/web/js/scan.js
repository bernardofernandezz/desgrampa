// Início e acompanhamento de uma varredura.

import { $, api, el, fill } from "./dom.js";
import { app } from "./state.js";
import { go, route } from "./router.js";
import { refreshStatus, setReady } from "./device.js";
import { loadReports } from "./reports.js";
import { renderDashboard } from "./dashboard.js";

export async function startScan() {
  const mode = document.querySelector("input[name=mode]:checked").value;
  try {
    const { id } = await api("/api/scan", { serial: app.serial, mode, pc_network: $("#pc-network").checked });
    go(`#varredura/scan/${id}`);
  } catch (e) {
    showError(e.message);
  }
}

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

function setProgress(frac, step) {
  const pct = `${Math.round(frac * 100)}%`;
  $("#bar-fill").style.width = pct;
  $("#pct").textContent = pct;
  $("#step").textContent = step;
}

async function poll(id) {
  if (app.polling !== id) return;
  try {
    const job = await api(`/api/scan/${id}`);
    setProgress(job.progress, job.step);
    if (job.state === "running") return setTimeout(() => poll(id), 800);
    app.scanning = false;
    $("#progress").classList.add("hidden");
    if (job.state === "error") return showError(job.error);
    const r = job.result;
    const name = r.evidence_dir ? r.evidence_dir.split("/").pop() : null;
    const box = $("#result");
    box.classList.remove("hidden");
    if (name) await showReport(box, name);
    else renderDashboard(box, r, { html: `/api/scan/${id}/report.html`, json: `/api/scan/${id}/report.json` });
    box.scrollIntoView({ behavior: "smooth" });
    loadReports();
    refreshStatus();
  } catch (e) {
    if (/não encontrada/.test(e.message)) {   // servidor reiniciado: a varredura em memória sumiu
      app.polling = null;
      app.scanning = false;
      $("#progress").classList.add("hidden");
      return go("#varredura");
    }
    setTimeout(() => poll(id), 2000);
  }
}

function showError(msg) {
  app.scanning = false;
  app.polling = null;
  const box = $("#result");
  box.classList.remove("hidden");
  fill(box, el("div", { class: "verdict suspeito", style: "margin-bottom:18px" },
    el("h2", {}, "A varredura não foi concluída"), el("p", {}, msg),
    el("p", { class: "muted" }, "Verifique se o aparelho continua conectado e autorizado, e tente novamente.")));
  setReady();
}

export async function showReport(box, name) {
  const r = await api(reportLinks(name).json);
  renderDashboard(box, r, reportLinks(name), () => showReport(box, name));
}

export function reportLinks(name) {
  const base = `/api/reports/${encodeURIComponent(name)}`;
  return { html: `${base}/relatorio.html`, json: `${base}/relatorio.json` };
}
