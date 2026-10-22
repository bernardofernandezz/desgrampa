// iPhone: backup pelo cabo ou pasta de backup existente, analisados pelo MVT.

import { api, el, fill } from "./dom.js";
import { go } from "./router.js";

export async function renderIphone(container) {
  let st;
  try {
    st = await api("/api/ios");
  } catch (e) {
    fill(container, el("div", { class: "card" }, el("h2", {}, "iPhone"), el("p", { class: "muted" }, e.message)));
    return;
  }
  const msg = el("p", { class: "small warn-text", role: "alert" });
  const start = async (body) => {
    msg.textContent = "";
    try {
      const { id } = await api("/api/ios/scan", body);
      go(`#varredura/scan/${id}`);
    } catch (e) {
      msg.textContent = e.message;
    }
  };
  const password = el("input", { type: "password", name: "password", autocomplete: "off", placeholder: "só se o backup for criptografado" });
  const passwordField = el("label", { class: "field" }, el("span", {}, "Senha do backup (não é guardada)"), password);

  const devices = st.devices.map((d) => el("div", { class: "list-row" },
    el("div", { class: "grow" }, el("strong", {}, d.name || "iPhone"),
      el("span", { class: "muted small" }, d.state === "ok" ? `${d.model} · iOS ${d.version}` : "Desbloqueie o iPhone e toque em “Confiar neste computador”.")),
    el("button", { class: "primary", disabled: d.state !== "ok" || !st.mvt,
      onclick: () => start({ udid: d.udid, password: password.value }) }, "Fazer backup e analisar")));

  const pathInput = el("input", { name: "backup_path", autocomplete: "off", placeholder: "pasta do backup", size: 46 });
  const folderForm = el("form", { class: "inline-form" },
    el("label", { class: "field" }, el("span", {}, "Pasta de um backup já feito"), pathInput),
    el("button", { type: "submit", disabled: !st.mvt }, "Analisar backup"));
  folderForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    start({ backup_path: pathInput.value, password: password.value });
  });

  fill(container, el("div", { class: "card" },
    el("h2", {}, "iPhone"),
    el("p", { class: "muted small" }, "O iPhone não permite inspeção pelo cabo como o Android. A análise usa um backup local "
      + "com o MVT da Anistia Internacional, que procura rastros de Pegasus, Predator e outros spywares, perfis de "
      + "configuração e a versão do iOS. Para mais dados, ative “Criptografar backup local” no Finder/iTunes."),
    !st.mvt ? el("p", { class: "warn-text small" }, "MVT não instalado: instale com pip install \"desgrampa[forense]\".") : null,
    st.idevice ? (devices.length ? devices : el("p", { class: "muted small" }, "Nenhum iPhone conectado pelo cabo."))
      : el("p", { class: "muted small" }, "Para fazer o backup por aqui, instale o libimobiledevice (Linux: pacote "
        + "libimobiledevice-utils; macOS: brew install libimobiledevice). Ou faça o backup no Finder/iTunes e informe a pasta abaixo."),
    passwordField,
    folderForm,
    el("details", { class: "small" }, el("summary", {}, "Onde fica a pasta do backup?"),
      el("ul", {},
        el("li", {}, "Mac: ~/Library/Application Support/MobileSync/Backup/<identificador>"),
        el("li", {}, "Windows (iTunes da Apple.com): %APPDATA%\\Apple Computer\\MobileSync\\Backup\\<identificador>"),
        el("li", {}, "Windows (app Dispositivos Apple ou iTunes da Microsoft Store): %USERPROFILE%\\Apple\\MobileSync\\Backup\\<identificador>"))),
    msg));
}
