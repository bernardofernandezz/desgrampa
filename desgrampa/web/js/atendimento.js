// Modo atendimento: termo de consentimento, atendimento atual, varreduras do caso, pacote e encerramento.

import { $, api, el, fill, fmtDate, icon } from "./dom.js";
import { app, VERDICT_PILL } from "./state.js";
import { go } from "./router.js";
import { refreshStatus } from "./device.js";
import { reportLinks } from "./scan.js";

let termo = null;

function consentForm(onDone) {
  const msg = el("p", { class: "small warn-text", role: "alert" });
  const form = el("form", { class: "consent" },
    el("ol", { class: "small" }, (termo || []).map((t) => el("li", {}, t))),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "consent", required: true }),
      el("span", {}, "Li o termo para a pessoa atendida, ela entendeu e concordou.")),
    el("div", { class: "inline-form" },
      el("label", { class: "field" }, el("span", {}, "Nome ou apelido da pessoa (opcional)"),
        el("input", { name: "name", autocomplete: "off", maxlength: 120 })),
      el("label", { class: "field" }, el("span", {}, "Responsável pelo atendimento (opcional)"),
        el("input", { name: "operator", autocomplete: "off", maxlength: 120 })),
      el("button", { type: "submit", class: "primary" }, "Abrir atendimento")),
    msg);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const f = new FormData(form);
    try {
      await api("/api/atendimento/abrir", { consent: f.get("consent") === "on", name: f.get("name"), operator: f.get("operator") });
      onDone();
    } catch (e) {
      msg.textContent = e.message;
    }
  });
  return form;
}

function caseCard(c, current, redraw) {
  const pkg = `/api/atendimento/${c.id}/pacote.zip`;
  const close = async () => {
    const force = !c.delivered && confirm("O pacote deste atendimento ainda não foi baixado. Encerrar mesmo assim e apagar as evidências?");
    if (!c.delivered && !force) return;
    if (c.delivered && !confirm("Encerrar o atendimento e apagar as evidências deste computador?")) return;
    try {
      await api("/api/atendimento/encerrar", { case: c.id, force });
    } catch (e) {
      alert(e.message);
    }
    redraw();
  };
  return el("div", { class: `card case ${c.id === current ? "current" : ""}` },
    el("div", { class: "list-row" },
      el("div", { class: "grow" },
        el("h2", {}, c.id, c.id === current ? el("span", { class: "pill ok", style: "margin-left:8px" }, "em andamento") : null,
          c.closed ? el("span", { class: "pill", style: "margin-left:8px" }, "encerrado") : null),
        el("span", { class: "muted small" }, [c.name, c.operator && `responsável: ${c.operator}`, `aberto ${fmtDate(c.opened)}`]
          .filter(Boolean).join(" · "))),
      !c.closed ? el("a", { href: pkg, download: true, onclick: () => setTimeout(redraw, 1500) },
        el("button", {}, icon("download", "sm"), "Baixar pacote (.zip)")) : null,
      !c.closed ? el("button", { onclick: close }, "Encerrar e apagar") : null),
    c.closed ? el("p", { class: "muted small" }, `Encerrado em ${fmtDate(c.closed)}; os dados foram apagados deste computador.`)
      : c.reports.length ? c.reports.map((r) => el("div", { class: "list-row" },
        icon("phone", "circle"),
        el("div", { class: "grow" }, el("strong", {}, r.device || r.serial),
          el("span", { class: "muted small" }, `${fmtDate(r.started)} · varredura ${r.mode}`)),
        el("span", { class: `pill ${VERDICT_PILL[r.verdict?.code] || ""}` }, r.verdict?.label || "?"),
        el("button", { onclick: () => go(`#relatorios/${r.name}`) }, "Abrir"),
        el("a", { href: reportLinks(r.name).authority, target: "_blank", rel: "noopener" }, el("button", {}, "Para atendimento"))))
        : el("p", { class: "muted small" }, c.id === current ? "Nenhuma varredura ainda. Conecte o celular e inicie pela página Varredura." : "Sem varreduras."));
}

export async function renderAttendance() {
  const box = $("#atendimento");
  if (!app.status?.attendance?.enabled) {
    fill(box, el("div", { class: "card" }, el("h2", {}, "Modo atendimento desligado"),
      el("p", {}, "Para usar em Defensorias, delegacias, serviços de apoio e universidades, inicie o programa com:"),
      el("p", {}, el("code", {}, "desgrampa --atendimento")),
      el("p", { class: "muted small" }, "Nesse modo cada pessoa atendida tem termo de consentimento e número de atendimento, "
        + "os relatórios ficam numa pasta temporária e, no fim, você entrega o pacote e apaga tudo deste computador.")));
    return;
  }
  if (!termo) termo = (await api("/api/ajuda")).termo;
  const data = await api("/api/atendimento");
  const redraw = async () => { await refreshStatus(); renderAttendance(); };
  fill(box,
    data.current ? null : el("div", { class: "card" },
      el("h2", {}, "Novo atendimento"),
      el("p", { class: "muted small" }, "Leia o termo em voz alta e confirme que a pessoa concorda antes de conectar o celular."),
      consentForm(redraw)),
    data.cases.length ? data.cases.map((c) => caseCard(c, data.current, redraw)) : null,
    el("div", { class: "card" }, el("h2", {}, "Roteiro do atendimento"),
      el("ol", { class: "steps" },
        el("li", {}, "Acolha sem julgar. Pergunte o que fez a pessoa suspeitar e se é seguro ela levar o celular de volta."),
        el("li", {}, "Abra o atendimento acima com o termo de consentimento."),
        el("li", {}, "Conecte o celular (página Dispositivos) e rode a varredura completa, se houver tempo."),
        el("li", {}, "Explique o resultado no modo simples. Não remova nada sem planejar a segurança com a pessoa."),
        el("li", {}, "Baixe o pacote do atendimento para um pendrive da pessoa ou imprima o relatório para atendimento."),
        el("li", {}, "Encerre o atendimento para apagar os dados deste computador e desligue a depuração USB do celular.")),
      el("p", { class: "small" }, "Guia completo: ", el("a", { href: "https://github.com/bernardofernandezz/desgrampa/blob/main/docs/atendimento.md",
        target: "_blank", rel: "noopener" }, "docs/atendimento.md"))),
  );
}
