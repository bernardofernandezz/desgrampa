// Status do servidor e do aparelho: seletor, cartão do aparelho e página de dispositivos.

import { $, api, el, fill, fmtDate, icon, num } from "./dom.js";
import { API_VERSION, app } from "./state.js";
import { go } from "./router.js";
import { resumeRunning } from "./scan.js";

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
  pickDevice();
  await loadDeviceInfo();
  renderPicker();
  renderDeviceCard();
  renderDevicesPage();
  renderMvtLine();
  setReady();
  resumeRunning();
}

function readyDevices() {
  return (app.status?.devices || []).filter((d) => d.state === "device");
}

function pickDevice() {
  const devices = app.status.devices || [];
  if (!devices.find((d) => d.serial === app.serial)) {
    app.serial = (readyDevices()[0] || devices[0])?.serial ?? null;
  }
}

async function loadDeviceInfo() {
  const dev = (app.status.devices || []).find((d) => d.serial === app.serial);
  if (!dev || dev.state !== "device" || app.scanning || serverOutdated()) return;
  if (app.infoAt[dev.serial] && Date.now() - app.infoAt[dev.serial] < 20000) return;
  try {
    app.info[dev.serial] = await api(`/api/device/${encodeURIComponent(dev.serial)}`);
    app.infoAt[dev.serial] = Date.now();
    delete app.infoError[dev.serial];
  } catch (e) {
    app.infoError[dev.serial] = e.message;
    app.infoAt[dev.serial] = Date.now() - 15000;   // tenta de novo em ~5 s
  }
}

function deviceName(d) {
  return app.info[d.serial]?.name || d.model || d.serial;
}

export function renderSystem() {
  $("#sys-status").classList.toggle("off", !app.status);
  $("#sys-text").textContent = app.status ? "Sistema online" : "Servidor offline";
  $("#last-scan").textContent = app.reports[0] ? fmtDate(app.reports[0].started) : "nenhuma ainda";
}

function renderPicker() {
  const sel = $("#device-picker");
  const devices = app.status.devices || [];
  const sig = JSON.stringify([app.serial, app.scanning, devices.map((d) => [d.serial, d.state, deviceName(d)])]);
  if (sel.dataset.sig === sig) return;   // não redesenha (e não fecha) o seletor à toa
  sel.dataset.sig = sig;
  fill(sel, ...(devices.length
    ? devices.map((d) => el("option", { value: d.serial, selected: d.serial === app.serial },
      deviceName(d) + (d.state === "device" ? "" : " (não autorizado)")))
    : [el("option", { value: "" }, "Nenhum aparelho")]));
  sel.disabled = !devices.length || app.scanning;
}

function serverOutdated() {
  return app.status && app.status.api !== API_VERSION;
}

function renderIocsBanner() {
  const job = app.status?.iocs?.job;
  let banner = $("#iocs-banner");
  if (!job || job.state === "ok") { banner?.remove(); return; }
  const text = {
    baixando: "Baixando as bases de indicadores de spyware (primeira execução)… a varredura pode começar depois disso.",
    erro: `Não foi possível baixar as bases de indicadores: ${job.error}. Verifique a internet e tente em Configurações.`,
    ausente: "As bases de indicadores ainda não foram baixadas. Abra Configurações › Atualizar bases.",
  }[job.state];
  if (!banner) {
    banner = el("div", { id: "iocs-banner", class: "card warn-card" });
    $(".main .topbar").after(banner);
  }
  fill(banner, el("strong", {}, "Bases de indicadores"), el("p", { class: "muted" }, text));
}

function renderOutdatedBanner() {
  let banner = $("#outdated");
  if (!serverOutdated()) { banner?.remove(); return; }
  if (banner) return;
  banner = el("div", { id: "outdated", class: "card warn-card" },
    el("strong", {}, "O servidor em execução é de uma versão anterior da interface."),
    el("p", { class: "muted" }, "Por isso os dados do aparelho não aparecem. No terminal onde o app está rodando, aperte ",
      el("code", {}, "Ctrl+C"), " e inicie de novo com ", el("code", {}, ".venv/bin/python app.py"), ". Depois recarregue esta página."));
  $(".main .topbar").after(banner);
}

const REGION_PT = { Brazil: "Brasil", Portugal: "Portugal", USA: "Estados Unidos", Mexico: "México",
  Argentina: "Argentina", Spain: "Espanha", Germany: "Alemanha", France: "França", "United Kingdom": "Reino Unido" };

const VB_LABEL = { green: "íntegro (verde)", yellow: "chave própria (amarelo)", orange: "desbloqueado (laranja)", red: "falhou (vermelho)" };

function patchAge(patch) {
  const d = new Date(`${patch}T00:00:00`);
  if (Number.isNaN(d.getTime())) return null;
  const months = Math.floor((Date.now() - d.getTime()) / (30.44 * 86400000));
  return months <= 0 ? "atual" : months === 1 ? "há 1 mês" : `há ${months} meses`;
}

function fmtUptime(s) {
  if (s == null) return null;
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} d ${h} h` : h ? `${h} h ${m} min` : `${m} min`;
}

function renderDeviceCard() {
  const card = $("#device-card");
  const st = app.status;
  const dev = (st.devices || []).find((d) => d.serial === app.serial);

  if (!st.adb || st.error || !dev) {
    const title = !st.adb ? "Ferramenta adb não instalada" : st.error ? "Erro no adb" : "Nenhum aparelho conectado";
    fill(card,
      el("div", { class: "device-head" },
        el("div", { class: "phone off" }),
        el("div", { class: "grow device-empty" },
          el("div", { class: "device-name" }, title),
          !st.adb ? [el("div", { class: "device-sub" }, "Instale e recarregue a página:"),
            el("p", {}, el("code", {}, "sudo pacman -S android-tools"))]
            : st.error ? el("div", { class: "device-sub" }, st.error)
              : el("ol", {},
                el("li", {}, "Ative a Depuração USB nas Opções do desenvolvedor."),
                el("li", {}, "Conecte o cabo de dados ao computador."),
                el("li", {}, "Toque em “Permitir” no aviso do celular.")),
          st.adb && !st.error ? el("p", { class: "small" }, el("a", { href: "#dispositivos" }, "Ver instruções completas")) : null),
        el("span", { class: "pill" }, el("span", { class: "dot" }), "Desconectado")),
      statsRow([["usb", "USB", "Aguardando", ""], ["shield", "Depuração", "—", ""], ["battery", "Bateria", "—", ""]]),
    );
    return;
  }

  const ready = dev.state === "device";
  const info = app.info[dev.serial];
  const error = app.infoError[dev.serial];
  const bat = info?.battery;

  let sub;
  if (!ready) sub = "Desbloqueie o celular e toque em “Permitir” no aviso de depuração USB.";
  else if (serverOutdated()) sub = "Servidor desatualizado — reinicie o app (veja o aviso acima).";
  else if (error) sub = `Não foi possível ler os dados: ${error}`;
  else if (!info) sub = "Lendo informações pelo USB…";
  else sub = [info.android && `Android ${info.android}`, info.rom, info.sdk && `API ${info.sdk}`].filter(Boolean).join(" · ");

  const batteryText = bat ? `${bat.level}%${bat.charging ? " · carregando" : ""}` : "—";

  const details = info ? [
    ["Patch de segurança", info.security_patch && [info.security_patch, " ",
      el("span", { class: patchAge(info.security_patch)?.match(/\d+/)?.[0] > 6 ? "warn-text" : "muted" }, `(${patchAge(info.security_patch)})`)]],
    ["Build", info.build],
    ["Chip", info.soc],
    ["Operadora", info.operators?.join(", ")],
    ["Região", [REGION_PT[info.region] || info.region, info.csc && `CSC ${info.csc}`].filter(Boolean).join(" · ")],
    ["Armazenamento", info.storage && `${num(info.storage.used_gb)} de ${num(info.storage.total_gb)} GB (${info.storage.used_pct}%)`],
    ["Memória RAM", info.memory && `${num(info.memory.nominal_gb)} GB`],
    ["Bootloader", info.bootloader && [info.bootloader.locked === true ? "bloqueado" : info.bootloader.locked === false ? "DESBLOQUEADO" : null,
      VB_LABEL[info.bootloader.verified_boot]].filter(Boolean).join(" · ")],
    ["Criptografia", info.encryption && ({ file: "por arquivo (FBE)", block: "disco inteiro (FDE)", encrypted: "ativa" }[info.encryption] || info.encryption)],
    ["Bateria", bat && [bat.health && `saúde ${bat.health}`, bat.temperature_c != null && `${num(bat.temperature_c)} °C`,
      bat.power_source && `energia via ${bat.power_source}`].filter(Boolean).join(" · ")],
    ["Ligado há", fmtUptime(info.uptime_s)],
    ["Nome no aparelho", info.device_name],
  ].filter(([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length)) : [];

  fill(card,
    el("div", { class: "device-head" },
      el("div", { class: "phone" }),
      el("div", { class: "grow" },
        el("div", { class: "device-name" }, info?.name || dev.model || "Android"),
        el("div", { class: `device-sub ${error && !info ? "warn-text" : ""}` }, sub),
        el("div", { class: "device-serial" }, [dev.serial, info?.codename && `codinome ${info.codename}`, dev.usb && `porta USB ${dev.usb}`]
          .filter(Boolean).join(" · "))),
      el("span", { class: `pill ${ready ? "ok" : "warn"}` }, el("span", { class: "dot" }), ready ? "Conectado" : "Não autorizado")),
    statsRow([
      ["usb", "USB", "Conectado", "ok"],
      ["shield", "Depuração", ready ? "Autorizada" : "Toque em “Permitir” no celular", ready ? "" : "warn"],
      [bat?.charging ? "batteryCharging" : "battery", "Bateria", batteryText, bat && bat.level < 20 && !bat.charging ? "warn" : ""],
    ]),
    details.length ? el("dl", { class: "device-details" },
      details.map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v)))) : null,
  );
}

function statsRow(items) {
  return el("div", { class: "device-stats" }, items.map(([ic, label, value, cls]) =>
    el("div", { class: "stat" }, icon(ic, "circle"),
      el("div", {}, el("div", {}, label), el("div", { class: `v ${cls}` }, value)))));
}

function renderMvtLine() {
  const mvt = app.status.mvt;
  $("#mvt-status").textContent = mvt.installed
    ? `MVT ${mvt.version || ""} instalado — será usado na varredura completa.`
    : "MVT não encontrado: a varredura completa roda sem ele (.venv/bin/pip install mvt).";
}

export function setReady() {
  const dev = (app.status?.devices || []).find((d) => d.serial === app.serial);
  $("#start").disabled = !dev || dev.state !== "device" || app.scanning;
}

function renderDevicesPage() {
  const st = app.status;
  const devices = st.devices || [];
  fill($("#devices-list"), el("div", { class: "card" },
    el("h2", {}, "Detectados agora"),
    el("p", { class: "muted small" }, st.adb ? `adb: ${st.adb}` : "adb não instalado — sudo pacman -S android-tools"),
    devices.length ? devices.map((d) => {
      const info = app.info[d.serial] || {};
      const ready = d.state === "device";
      return el("div", { class: "list-row" },
        icon("phone", "circle"),
        el("div", { class: "grow" }, el("strong", {}, deviceName(d)),
          el("span", { class: "muted small" }, [d.serial, info.android && `Android ${info.android}`, info.rom]
            .filter(Boolean).join(" · "))),
        el("span", { class: `pill ${ready ? "ok" : "warn"}` }, el("span", { class: "dot" }),
          ready ? "Conectado" : d.state === "unauthorized" ? "Aguardando autorização" : d.state),
        ready ? el("button", { onclick: () => { app.serial = d.serial; go("#varredura"); refreshStatus(); } }, "Usar este") : null);
    }) : el("div", { class: "empty" }, "Nenhum aparelho detectado pelo cabo USB.")));
}
