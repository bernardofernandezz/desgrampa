// Como conectar o celular: guia por fabricante (depuração USB), depuração sem fio e driver do Windows.

import { api, el, fill, store } from "./dom.js";
import { app } from "./state.js";

// Caminhos dos menus em português, por fabricante. "tap" = onde tocar 7 vezes; "dev" = onde ficam as
// Opções do desenvolvedor depois de liberadas; "extra" = passos próprios da marca.
export const GUIDES = {
  generico: { label: "Outra marca / não sei",
    tap: "Configurações › Sobre o telefone › Número da versão (às vezes dentro de “Informações do software”)",
    dev: "Configurações › Sistema › Opções do desenvolvedor (ou procure “desenvolvedor” na busca das Configurações)" },
  samsung: { label: "Samsung",
    tap: "Configurações › Sobre o telefone › Informações do software › Número de compilação",
    dev: "Configurações › Opções do desenvolvedor (no fim da lista)",
    extra: ["Se aparecer “Bloqueador automático” (Auto Blocker) ligado, desligue-o temporariamente em "
      + "Configurações › Segurança e privacidade: ele bloqueia comandos pelo cabo."] },
  motorola: { label: "Motorola",
    tap: "Configurações › Sobre o telefone › Número da versão",
    dev: "Configurações › Sistema › Opções do desenvolvedor" },
  xiaomi: { label: "Xiaomi / Redmi / POCO",
    tap: "Configurações › Sobre o telefone › Versão do HyperOS (ou Versão do MIUI)",
    dev: "Configurações › Configurações adicionais › Opções do desenvolvedor",
    extra: ["Ative também “Depuração USB (configurações de segurança)”. A Xiaomi exige um chip no "
      + "aparelho e login na conta Mi para liberar essa opção."] },
  google: { label: "Google Pixel",
    tap: "Configurações › Sobre o telefone › Número da versão",
    dev: "Configurações › Sistema › Opções do desenvolvedor" },
  realme: { label: "Realme / OPPO / OnePlus",
    tap: "Configurações › Sobre o dispositivo › Versão › Número da versão",
    dev: "Configurações › Configurações adicionais › Opções do desenvolvedor" },
  lg: { label: "LG",
    tap: "Configurações › Sobre o telefone › Informações do software › Número da versão",
    dev: "Configurações › Sistema › Opções do desenvolvedor" },
  asus: { label: "ASUS",
    tap: "Configurações › Sobre › Informações do software › Número da versão",
    dev: "Configurações › Sistema › Opções do desenvolvedor" },
};

// Fabricante provável a partir do modelo que o adb mostra (mesmo antes da autorização).
export function guessMaker(model) {
  const m = (model || "").toLowerCase();
  if (/^sm[ -]|galaxy/.test(m)) return "samsung";
  if (/moto|xt\d{4}/.test(m)) return "motorola";
  if (/redmi|poco|^mi |^m\d{4}|xiaomi|^\d{4,5}[a-z0-9]{3,}[a-z]$/.test(m)) return "xiaomi";
  if (/pixel/.test(m)) return "google";
  if (/^rmx|^cph|oneplus|realme|oppo/.test(m)) return "realme";
  if (/^lm-|^lg/.test(m)) return "lg";
  if (/asus|zenfone/.test(m)) return "asus";
  return null;
}

function stepsFor(key) {
  const g = GUIDES[key] || GUIDES.generico;
  return el("ol", { class: "steps" },
    el("li", {}, "Toque 7 vezes em ", el("strong", {}, g.tap), ". Digite o PIN se pedir. Vai aparecer “Você agora é um desenvolvedor”."),
    el("li", {}, "Abra ", el("strong", {}, g.dev), " e ative ", el("strong", {}, "Depuração USB"), "."),
    (g.extra || []).map((x) => el("li", {}, x)),
    el("li", {}, "Conecte um cabo ", el("strong", {}, "de dados"), " (cabos só de carga não funcionam) e, se o celular perguntar, escolha “Transferência de arquivos”."),
    el("li", {}, "Desbloqueie o celular e toque em ", el("strong", {}, "Permitir"), " no aviso “Permitir depuração USB?”."),
    el("li", {}, "Ao terminar a varredura, desligue a Depuração USB e toque em “Revogar autorizações de depuração USB”."));
}

function windowsDriverTip() {
  if (app.status?.system !== "windows") return null;
  return el("div", { class: "tip" },
    el("strong", {}, "No Windows, o celular não aparece?"),
    el("ul", {},
      el("li", {}, "Troque o cabo ou a porta USB (prefira as portas de trás do computador)."),
      el("li", {}, "Instale o driver USB do fabricante: Samsung (“Samsung Android USB Driver”), Motorola "
        + "(“Motorola Device Manager”) ou, para as demais marcas, o “Google USB Driver”. Depois reconecte o cabo."),
      el("li", {}, "Se nada funcionar, use a depuração sem fio abaixo (Android 11 ou mais novo)."),
    ));
}

// ------------------------------------------------------------ depuração sem fio

function wirelessCard() {
  const msg = el("p", { class: "small", role: "status", "aria-live": "polite" });
  const input = (name, label, attrs = {}) => el("label", { class: "field" }, el("span", {}, label),
    el("input", { name, autocomplete: "off", ...attrs }));
  const say = (text, cls = "") => { msg.className = `small ${cls}`; msg.textContent = text; };

  const pairForm = el("form", { class: "inline-form" },
    input("host", "IP", { placeholder: "192.168.0.12", inputmode: "decimal", required: true }),
    input("port", "Porta de pareamento", { placeholder: "37123", inputmode: "numeric", required: true, size: 7 }),
    input("code", "Código", { placeholder: "123456", inputmode: "numeric", maxlength: 6, required: true, size: 7 }),
    el("button", { type: "submit" }, "Parear"));
  const connectForm = el("form", { class: "inline-form" },
    input("host", "IP", { placeholder: "192.168.0.12", inputmode: "decimal", required: true }),
    input("port", "Porta (topo da tela)", { placeholder: "41567", inputmode: "numeric", required: true, size: 7 }),
    el("button", { type: "submit", class: "primary" }, "Conectar"));

  const submit = (form, path, done) => form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const body = Object.fromEntries(new FormData(form));
    say("Aguarde…");
    try {
      const res = await api(path, body);
      done(res, body);
    } catch (e) {
      say(e.message, "warn-text");
    }
  });
  submit(pairForm, "/api/wireless/pair", (_res, body) => {
    connectForm.elements.host.value = body.host;
    say("Pareado. Agora informe a porta mostrada no topo da tela “Depuração por Wi-Fi” e toque em Conectar.", "ok-text");
  });
  submit(connectForm, "/api/wireless/connect", (res) => {
    app.serial = res.serial;
    say("Conectado. O aparelho já aparece na lista.", "ok-text");
  });

  return el("div", { class: "card" },
    el("h2", {}, "Sem cabo: depuração por Wi-Fi"),
    el("p", { class: "muted small" }, "Android 11 ou mais novo. O celular e este computador precisam estar na mesma rede Wi-Fi."),
    el("ol", { class: "steps" },
      el("li", {}, "Com as Opções do desenvolvedor liberadas (passo 1 acima), ative ", el("strong", {}, "Depuração por Wi-Fi"), " e toque no nome dela."),
      el("li", {}, "Toque em ", el("strong", {}, "Parear dispositivo com código de pareamento"), " e copie IP, porta e código abaixo."),
      el("li", {}, "Depois de parear, use o IP e a porta que aparecem no topo da tela “Depuração por Wi-Fi” para conectar.")),
    pairForm, connectForm, msg,
    el("p", { class: "muted small" }, "Desligue a Depuração por Wi-Fi ao terminar: ligada, ela permite que alguém na mesma rede tente parear."));
}

// ------------------------------------------------------------ página

export function renderConnectGuide(container, model) {
  const guessed = guessMaker(model);
  let maker = guessed || store.get("desgrampa-maker", "generico");
  const steps = el("div");
  const select = el("select", { "aria-label": "Marca do celular", onchange: (ev) => {
    maker = ev.target.value;
    store.set("desgrampa-maker", maker);
    fill(steps, stepsFor(maker));
  } }, Object.entries(GUIDES).map(([k, g]) => el("option", { value: k, selected: k === maker }, g.label)));
  fill(steps, stepsFor(maker));
  fill(container,
    el("div", { class: "card" },
      el("div", { class: "list-row" }, el("h2", { class: "grow" }, "Como conectar o celular pelo cabo"),
        el("label", { class: "field" }, el("span", {}, "Marca"), select)),
      guessed ? el("p", { class: "muted small" }, `Marca detectada pelo modelo ${model}.`) : null,
      steps, windowsDriverTip()),
    wirelessCard());
}
