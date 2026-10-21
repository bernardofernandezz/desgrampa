// Sugestões de remoção e diálogo de confirmação (nada é removido sem confirmação manual).

import { api, el, icon, tag } from "./dom.js";
import { countsLine } from "./dashboard.js";

const ACTION_STATUS = { ok: ["good", "concluído"], manual: ["warn", "precisa de ação no celular"],
  falhou: ["bad", "falhou"], nao_instalado: ["", "já não estava instalado"] };

export function suggestionsCard(r, reload) {
  const cands = r.removal_candidates || [];
  if (!cands.length) return null;
  const last = {};
  for (const a of r.actions || []) last[a.package] = a;
  const canAct = !!r.report_name;
  return el("div", { class: "card suggest-card" },
    el("div", { class: "card-title" }, icon("shieldAlert", "lg"),
      el("div", {}, el("h2", {}, `Ações sugeridas (${cands.length})`),
        el("p", { class: "muted" }, "Apps com achado crítico ou de spyware/malware. Nada é removido automaticamente — "
          + "você decide, confirma e o app executa. Antes, uma cópia do APK é guardada como evidência."))),
    cands.map((c) => {
      const a = last[c.package];
      const done = a && a.status === "ok";
      return el("div", { class: `suggest-row st-${c.worst}` },
        el("div", { class: "grow" },
          el("div", {}, el("strong", {}, c.family || c.package), " ", el("code", { class: "muted" }, c.package),
            c.user ? el("span", { class: "tag" }, `perfil ${c.user}`) : null,
            c.mercenary ? el("span", { class: "tag bad" }, "spyware mercenário") : null,
            c.device_admin ? el("span", { class: "tag warn" }, "administrador do aparelho") : null),
          el("div", { class: "small" }, countsLine(c.counts)),
          el("div", { class: "muted small" }, c.reasons.join(" · ")),
          a ? el("div", { class: "small" }, tag(`${a.action === "uninstall" ? "Remoção" : "Desativação"}: ${ACTION_STATUS[a.status]?.[1] || a.status}`,
            ACTION_STATUS[a.status]?.[0] || ""), " ", el("span", { class: "muted" }, `${a.time} — ${a.message}`)) : null),
        done ? null : el("div", { class: "actions" },
          el("button", { disabled: !canAct, onclick: () => openActionDialog(r, c, "disable", reload) }, "Desativar…"),
          el("button", { class: "danger", disabled: !canAct, onclick: () => openActionDialog(r, c, "uninstall", reload) }, "Remover…")));
    }));
}

function openActionDialog(r, c, action, reload) {
  const verb = action === "uninstall" ? "Remover" : "Desativar";
  const keep = el("input", { type: "checkbox", checked: true });
  const ack = el("input", { type: "checkbox" });
  const merc = el("input", { type: "checkbox" });
  const typed = el("input", { type: "text", placeholder: c.package, autocomplete: "off", spellcheck: "false" });
  const msg = el("p", { class: "small", role: "status" });
  const confirmBtn = el("button", { class: action === "uninstall" ? "danger" : "primary", disabled: true }, `${verb} agora`);
  const valid = () => typed.value.trim() === c.package && ack.checked && (!c.mercenary || merc.checked);
  for (const input of [typed, ack, merc]) input.addEventListener("input", () => { confirmBtn.disabled = !valid(); });
  for (const input of [ack, merc]) input.addEventListener("change", () => { confirmBtn.disabled = !valid(); });

  const dlg = el("dialog", { class: "action-dialog" },
    el("h2", {}, `${verb} ${c.family || c.package}?`),
    el("p", { class: "muted" }, action === "uninstall"
      ? "O app e os dados dele serão apagados do celular. Isso não pode ser desfeito."
      : "O app fica no celular mas deixa de funcionar (reversível em Configurações > Apps)."),
    el("ul", { class: "small" },
      el("li", {}, el("strong", {}, "Segurança: "), "quem instalou um app de monitoramento pode perceber quando ele para de enviar dados."),
      c.device_admin ? el("li", {}, el("strong", {}, "Administrador: "), "o Android pode exigir que você retire o privilégio de administrador no próprio celular antes.") : null,
      c.mercenary ? el("li", { class: "bad-text" }, el("strong", {}, "Spyware mercenário: "), "remover apaga evidências que um laboratório forense usaria. O recomendado é NÃO remover e procurar a Access Now Helpline ou o Amnesty Security Lab primeiro.") : null),
    el("label", { class: "check" }, keep, el("span", {}, "Guardar uma cópia do APK na pasta de evidências antes (recomendado)")),
    el("label", { class: "check" }, ack, el("span", {}, "Entendo os riscos e quero continuar")),
    c.mercenary ? el("label", { class: "check" }, merc, el("span", {}, "Entendo que vou apagar evidências de spyware mercenário")) : null,
    el("label", { class: "small" }, "Para confirmar, digite o nome do pacote: ", el("code", {}, c.package)),
    typed, msg,
    el("div", { class: "actions dialog-actions" },
      el("button", { onclick: () => dlg.close() }, "Cancelar"), confirmBtn));

  confirmBtn.addEventListener("click", async () => {
    confirmBtn.disabled = true;
    msg.textContent = action === "uninstall" ? "Removendo… mantenha o celular conectado." : "Desativando…";
    try {
      const res = await api("/api/actions", { report: r.report_name, package: c.package, action,
        keep_apk: keep.checked, confirm: typed.value.trim(), mercenary_ack: merc.checked });
      msg.textContent = res.message;
      msg.className = `small ${res.status === "ok" ? "good-text" : "bad-text"}`;
      setTimeout(() => { dlg.close(); reload?.(); }, res.status === "ok" ? 1200 : 4000);
    } catch (e) {
      msg.textContent = e.message;
      msg.className = "small bad-text";
      confirmBtn.disabled = !valid();
    }
  });
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  typed.focus();
}
