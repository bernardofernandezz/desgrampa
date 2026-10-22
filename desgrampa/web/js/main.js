// Ponto de entrada: roteamento entre páginas e atualização periódica do status.

import { $ } from "./dom.js";
import { app } from "./state.js";
import { PAGES, route } from "./router.js";
import { refreshStatus } from "./device.js";
import { showScan, startScan } from "./scan.js";
import { loadReports, renderReportsPage } from "./reports.js";
import { renderSettings } from "./settings.js";
import { renderConnectGuide } from "./connect.js";

const STATUS_REFRESH_MS = 2500;

function render() {
  const { page, arg } = route();
  for (const p of PAGES) $(`#page-${p}`).classList.toggle("hidden", p !== page);
  for (const a of document.querySelectorAll(".nav a")) a.classList.toggle("on", a.dataset.page === page);
  if (page === "relatorios") renderReportsPage(arg);
  if (page === "configuracoes") renderSettings();
  if (page === "dispositivos") {
    const waiting = (app.status?.devices || []).find((d) => d.state !== "device");
    renderConnectGuide($("#connect-guide"), waiting?.model);
  }
  if (page === "varredura" && arg.startsWith("scan/")) showScan(arg.slice(5));
}

window.addEventListener("hashchange", render);

$("#device-picker").addEventListener("change", (ev) => {
  app.serial = ev.target.value || null;
  refreshStatus();
});

$("#start").addEventListener("click", startScan);

loadReports();

refreshStatus().then(render);

setInterval(refreshStatus, STATUS_REFRESH_MS);
