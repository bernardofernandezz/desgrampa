// Status do servidor e do aparelho: seletor, cartão do aparelho e página de dispositivos.

import { $, api, el, fill, fmtDate, icon, num } from "./dom.js";
import { adbHint, API_VERSION, app, INSTALL_HINTS } from "./state.js";
import { go } from "./router.js";
import { resumeRunning } from "./scan.js";

const INFO_TTL_MS = 20000;        // relê os dados do aparelho a cada 20 s
const INFO_RETRY_MS = 5000;       // depois de uma falha, tenta de novo em 5 s
const OLD_PATCH_MONTHS = 6;       // patch mais antigo que isso aparece em destaque
const LOW_BATTERY = 20;

const REGION_PT = { Brazil: "Brasil", Portugal: "Portugal", USA: "Estados Unidos", Mexico: "México",
  Argentina: "Argentina", Spain: "Espanha", Germany: "Alemanha", France: "França", "United Kingdom": "Reino Unido" };
const VERIFIED_BOOT = { green: "íntegro (verde)", yellow: "chave própria (amarelo)", orange: "desbloqueado (laranja)",
  red: "falhou (vermelho)" };
const ENCRYPTION = { file: "por arquivo (FBE)", block: "disco inteiro (FDE)", encrypted: "ativa" };

// ------------------------------------------------------------ status

export async function refreshStatus() {
  try {
    app.status = await api("/api/status");
  } catch {
    app.status = null;
  }
  renderSystem();
  if (!app.status) return;
  renderOutdatedBanner();
  renderIocsBanner();
  renderPrivacyBanner();
  pickDevice();
  await loadDeviceInfo();
  renderPicker();
  renderDeviceCard();
  renderDevicesPage();
  renderMvtLine();
  setReady();
  resumeRunning();
}

function currentDevice() {
  return (app.status?.devices || []).find((d) => d.serial === app.serial);
}

function pickDevice() {
  if (currentDevice()) return;
  const devices = app.status.devices || [];
  app.serial = (devices.find((d) => d.state === "device") || devices[0])?.serial ?? null;
}

function serverOutdated() {
  return app.status && app.status.api !== API_VERSION;
}

async function loadDeviceInfo() {
  const dev = currentDevice();
  if (!dev || dev.state !== "device" || app.scanning || serverOutdated()) return;
  if (Date.now() - (app.infoAt[dev.serial] || 0) < INFO_TTL_MS) return;
  try {
    app.info[dev.serial] = await api(`/api/device/${encodeURIComponent(dev.serial)}`);
    app.infoAt[dev.serial] = Date.now();
    delete app.infoError[dev.serial];
  } catch (e) {
    app.infoError[dev.serial] = e.message;
    app.infoAt[dev.serial] = Date.now() - INFO_TTL_MS + INFO_RETRY_MS;
  }
}

function deviceName(d) {
  return app.info[d.serial]?.name || d.model || d.serial;
}

function needsCase() {
  const att = app.status?.attendance;
  return Boolean(att?.enabled && !att.current);
}

export function setReady() {
  const dev = currentDevice();
  $("#start").disabled = !dev || dev.state !== "device" || app.scanning || needsCase();
  $("#start").title = needsCase() ? "Abra um atendimento (página Atendimento) antes de iniciar" : "";
}

// ------------------------------------------------------------ barra lateral, seletor e avisos

export function renderSystem() {
  $("#sys-status").classList.toggle("off", !app.status);
  $("#sys-text").textContent = app.status ? "Sistema online" : "Servidor offline";
  $("#last-scan").textContent = app.reports[0] ? fmtDate(app.reports[0].started) : "nenhuma ainda";
}

function renderPicker() {
  const sel = $("#device-picker");
  const devices = app.status.devices || [];
  const signature = JSON.stringify([app.serial, app.scanning, devices.map((d) => [d.serial, d.state, deviceName(d)])]);
  if (sel.dataset.sig === signature) return;   // não redesenha (e não fecha) o seletor à toa
  sel.dataset.sig = signature;
  fill(sel, devices.length
    ? devices.map((d) => el("option", { value: d.serial, selected: d.serial === app.serial },
      deviceName(d) + (d.state === "device" ? "" : " (não autorizado)")))
    : el("option", { value: "" }, "Nenhum aparelho"));
  sel.disabled = !devices.length || app.scanning;
}

// Aviso no topo da página; `text` null remove o aviso.
function setBanner(id, title, text) {
  let banner = document.getElementById(id);
  if (!text) { banner?.remove(); return; }
  if (!banner) {
    banner = el("div", { id, class: "card warn-card" });
    $(".main .topbar").after(banner);
  }
  fill(banner, el("strong", {}, title), el("p", { class: "muted" }, text));
}

function renderIocsBanner() {
  const job = app.status?.iocs?.job;
  const text = {
    baixando: "Baixando as bases de indicadores de spyware (primeira execução)… a varredura pode começar depois disso.",
    erro: `Não foi possível baixar as bases de indicadores: ${job?.error}. Verifique a internet e tente em Configurações.`,
    ausente: "As bases de indicadores ainda não foram baixadas. Abra Configurações › Atualizar bases.",
  }[job?.state];
  setBanner("iocs-banner", "Bases de indicadores", text);
}

function renderPrivacyBanner() {
  const st = app.status;
  $("#nav-atendimento").classList.toggle("hidden", !st.attendance?.enabled);
  let text = null;
  if (st.attendance?.enabled) {
    text = st.attendance.current
      ? `Atendimento ${st.attendance.current} em andamento. Ao terminar, baixe o pacote e encerre na página Atendimento.`
      : "Modo atendimento: abra um atendimento com o termo de consentimento (página Atendimento) antes de iniciar a varredura.";
  } else if (st.privacy?.ephemeral) {
    text = "Os relatórios desta sessão ficam numa pasta temporária e serão apagados ao fechar o programa. "
      + "Baixe o pacote de evidências (.zip) do relatório antes de sair.";
  }
  setBanner("privacy-banner", st.attendance?.enabled ? "Modo atendimento" : "Modo sem rastros", text);
}

function renderOutdatedBanner() {
  setBanner("outdated", "O servidor em execução é de uma versão anterior da interface.", serverOutdated()
    ? `Por isso os dados do aparelho não aparecem. No terminal onde o app está rodando, aperte Ctrl+C, inicie de novo `
      + `com “${INSTALL_HINTS.restart}” e recarregue esta página.`
    : null);
}

function renderMvtLine() {
  const mvt = app.status.mvt;
  $("#mvt-status").textContent = mvt.installed
    ? `MVT ${mvt.version || ""} instalado — será usado na varredura completa.`
    : `MVT não encontrado: a varredura completa roda sem ele (${INSTALL_HINTS.mvt}).`;
}

// ------------------------------------------------------------ cartão do aparelho

function patchAgeMonths(patch) {
  const date = new Date(`${patch}T00:00:00`);
  return Number.isNaN(date.getTime()) ? null : Math.floor((Date.now() - date.getTime()) / (30.44 * 86400000));
}

function patchLabel(patch) {
  const months = patchAgeMonths(patch);
  if (months == null) return patch;
  const age = months <= 0 ? "atual" : months === 1 ? "há 1 mês" : `há ${months} meses`;
  return [patch, " ", el("span", { class: months > OLD_PATCH_MONTHS ? "warn-text" : "muted" }, `(${age})`)];
}

function fmtUptime(seconds) {
  if (seconds == null) return null;
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60);
  if (d) return `${d} d ${h} h`;
  return h ? `${h} h ${m} min` : `${m} min`;
}

const joinParts = (...parts) => parts.filter(Boolean).join(" · ");

function statsRow(items) {
  return el("div", { class: "device-stats" }, items.map(([ic, label, value, cls]) =>
    el("div", { class: "stat" }, icon(ic, "circle"),
      el("div", {}, el("div", {}, label), el("div", { class: `v ${cls}` }, value)))));
}

function emptyDeviceCard(st) {
  let title, body;
  if (!st.adb) {
    title = "Ferramenta adb não instalada";
    body = [el("div", { class: "device-sub" }, "Instale e recarregue a página:"), el("p", {}, el("code", {}, adbHint()))];
  } else if (st.error) {
    title = "Erro no adb";
    body = el("div", { class: "device-sub" }, st.error);
  } else {
    title = "Nenhum aparelho conectado";
    body = [el("ol", {},
      el("li", {}, "Ative a Depuração USB nas Opções do desenvolvedor."),
      el("li", {}, "Conecte o cabo de dados ao computador."),
      el("li", {}, "Toque em “Permitir” no aviso do celular.")),
    el("p", { class: "small" }, el("a", { href: "#dispositivos" }, "Ver instruções completas"))];
  }
  return [
    el("div", { class: "device-head" },
      el("div", { class: "phone off" }),
      el("div", { class: "grow device-empty" }, el("div", { class: "device-name" }, title), body),
      el("span", { class: "pill" }, el("span", { class: "dot" }), "Desconectado")),
    statsRow([["usb", "USB", "Aguardando", ""], ["shield", "Depuração", "—", ""], ["battery", "Bateria", "—", ""]]),
  ];
}

function deviceSubtitle(ready, info, error) {
  if (!ready) return "Desbloqueie o celular e toque em “Permitir” no aviso de depuração USB.";
  if (serverOutdated()) return "Servidor desatualizado — reinicie o app (veja o aviso acima).";
  if (error) return `Não foi possível ler os dados: ${error}`;
  if (!info) return "Lendo informações pelo USB…";
  return joinParts(info.android && `Android ${info.android}`, info.rom, info.sdk && `API ${info.sdk}`);
}

function deviceDetails(info) {
  const bat = info.battery;
  const boot = info.bootloader;
  const locked = boot?.locked === true ? "bloqueado" : boot?.locked === false ? "DESBLOQUEADO" : null;
  const rows = [
    ["Patch de segurança", info.security_patch && patchLabel(info.security_patch)],
    ["Build", info.build],
    ["Chip", info.soc],
    ["Operadora", info.operators?.join(", ")],
    ["Região", joinParts(REGION_PT[info.region] || info.region, info.csc && `CSC ${info.csc}`)],
    ["Armazenamento", info.storage && `${num(info.storage.used_gb)} de ${num(info.storage.total_gb)} GB (${info.storage.used_pct}%)`],
    ["Memória RAM", info.memory && `${num(info.memory.nominal_gb)} GB`],
    ["Bootloader", boot && joinParts(locked, VERIFIED_BOOT[boot.verified_boot])],
    ["Criptografia", info.encryption && (ENCRYPTION[info.encryption] || info.encryption)],
    ["Bateria", bat && joinParts(bat.health && `saúde ${bat.health}`, bat.temperature_c != null && `${num(bat.temperature_c)} °C`,
      bat.power_source && `energia via ${bat.power_source}`)],
    ["Ligado há", fmtUptime(info.uptime_s)],
    ["Nome no aparelho", info.device_name],
  ].filter(([, value]) => value);
  return rows.length ? el("dl", { class: "device-details" }, rows.map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v)))) : null;
}

function renderDeviceCard() {
  const card = $("#device-card");
  const dev = currentDevice();
  if (!app.status.adb || app.status.error || !dev) {
    fill(card, emptyDeviceCard(app.status));
    return;
  }
  const ready = dev.state === "device";
  const info = app.info[dev.serial];
  const error = app.infoError[dev.serial];
  const bat = info?.battery;
  fill(card,
    el("div", { class: "device-head" },
      el("div", { class: "phone" }),
      el("div", { class: "grow" },
        el("div", { class: "device-name" }, info?.name || dev.model || "Android"),
        el("div", { class: `device-sub ${error && !info ? "warn-text" : ""}` }, deviceSubtitle(ready, info, error)),
        el("div", { class: "device-serial" }, joinParts(dev.serial, info?.codename && `codinome ${info.codename}`,
          dev.usb && `porta USB ${dev.usb}`))),
      el("span", { class: `pill ${ready ? "ok" : "warn"}` }, el("span", { class: "dot" }), ready ? "Conectado" : "Não autorizado")),
    statsRow([
      dev.wireless ? ["usb", "Conexão", "Wi-Fi", "ok"] : ["usb", "USB", "Conectado", "ok"],
      ["shield", "Depuração", ready ? "Autorizada" : "Toque em “Permitir” no celular", ready ? "" : "warn"],
      [bat?.charging ? "batteryCharging" : "battery", "Bateria", bat ? `${bat.level}%${bat.charging ? " · carregando" : ""}` : "—",
        bat && bat.level < LOW_BATTERY && !bat.charging ? "warn" : ""],
    ]),
    info ? deviceDetails(info) : null,
  );
}

// ------------------------------------------------------------ página de dispositivos

function renderDevicesPage() {
  const st = app.status;
  const devices = st.devices || [];
  const rows = devices.map((d) => {
    const info = app.info[d.serial] || {};
    const ready = d.state === "device";
    const state = ready ? "Conectado" : d.state === "unauthorized" ? "Aguardando autorização" : d.state;
    return el("div", { class: "list-row" },
      icon("phone", "circle"),
      el("div", { class: "grow" }, el("strong", {}, deviceName(d)),
        el("span", { class: "muted small" }, joinParts(d.serial, info.android && `Android ${info.android}`, info.rom))),
      el("span", { class: `pill ${ready ? "ok" : "warn"}` }, el("span", { class: "dot" }), state),
      ready ? el("button", { onclick: () => { app.serial = d.serial; go("#varredura"); refreshStatus(); } }, "Usar este") : null,
      d.wireless ? el("button", { onclick: () => disconnect(d.serial) }, "Desconectar Wi-Fi") : null);
  });
  fill($("#devices-list"), el("div", { class: "card" },
    el("h2", {}, "Detectados agora"),
    el("p", { class: "muted small" }, st.adb ? `adb: ${st.adb}` : `adb não instalado — ${adbHint()}`),
    rows.length ? rows : el("div", { class: "empty" }, "Nenhum aparelho detectado (cabo USB ou Wi-Fi).")));
}

async function disconnect(serial) {
  try {
    await api("/api/wireless/disconnect", { serial });
  } catch (e) {
    alert(e.message);
  }
  refreshStatus();
}
