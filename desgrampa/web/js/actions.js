// Painel de ameaças, assistente de um app e plano de limpeza.
// O Desgrampa propõe o que fazer e explica por quê; nada é alterado no aparelho sem o consentimento explícito do usuário.

import { api, el, fill, icon, tag } from "./dom.js";
import { countsLine } from "./dashboard.js";
import { ACTION_NOUN } from "./state.js";

const ACTION_STATUS = { ok: ["good", "concluído"], manual: ["warn", "precisa de um passo no celular"],
  falhou: ["bad", "falhou"], nao_instalado: ["", "já não estava instalado"] };

const PLAN_CONFIRM = "REMOVER";   // igual a server.PLAN_CONFIRM

// O que cada ação faz. `keep` = oferece guardar a cópia do APK antes; `evidence` = o app e os dados ficam no celular.
export const ACTION_INFO = {
  restrict: { verb: "Cortar acessos", consent: "cortar os acessos deste app", btn: "primary", keep: true, evidence: true,
    what: "Tira acessibilidade, leitura de notificações, SMS, ligações, microfone, câmera, localização, gravação "
      + "de tela e execução em segundo plano, e para o app. Ele continua instalado.",
    tags: [["Reversível", "good"], ["Preserva evidências", "good"]] },
  disable: { verb: "Desativar", consent: "desativar este app", btn: "primary", keep: true, evidence: true,
    what: "O app fica no celular mas deixa de funcionar e some da tela. Pode ser reativado depois.",
    tags: [["Reversível", "good"], ["Preserva evidências", "good"]] },
  uninstall: { verb: "Remover", consent: "remover este app", btn: "danger", keep: true, evidence: false,
    what: "O app e os dados dele são apagados do celular. Se marcado, uma cópia do APK fica na pasta de evidências.",
    tags: [["Definitivo", "bad"], ["Apaga dados do app", "warn"]] },
  enable: { verb: "Reativar", consent: "reativar este app", btn: "", keep: false, evidence: true,
    what: "Desfaz a desativação: o app volta a funcionar.", tags: [["Desfaz a desativação", ""]] },
};
const CHOICES = ["restrict", "disable", "uninstall"];

const LEVEL_HINT = "Apps instalados por alguém com acessos perigosos (ler a tela, as notificações…). "
  + "Se você reconhece e usa, pode ignorar.";

// Estado atual do app segundo o histórico de ações (a mais recente vence).
function appState(lastAction) {
  if (lastAction?.status !== "ok") return null;
  return { uninstall: "removido", disable: "desativado", restrict: "restrito", enable: null }[lastAction.action];
}

const lastActions = (r) => Object.fromEntries((r.actions || []).map((a) => [a.package, a]));
const appName = (c) => c.family || c.package;
// Relatórios salvos sempre passam por grouping.enrich, mas um campo ausente não pode quebrar a tela
const dossier = (c) => c.explain || { label: "App suspeito", what: "", why: c.reasons, can_do: [],
  recommendation: { action: "restrict", text: "" }, confidence: "media", preselect: false, summary: c.reasons[0] };

function lastActionLine(action) {
  const [kind, label] = ACTION_STATUS[action.status] || ["", action.status];
  return el("div", { class: "threat-last small" }, tag(`${ACTION_NOUN[action.action] || action.action}: ${label}`, kind),
    " ", el("span", { class: "muted" }, `${action.time} — ${action.message}`));
}

// "O que ele consegue fazer", agrupado por tema (Mensagens, Tela, Localização…)
function canDoList(caps) {
  const byTheme = new Map();
  for (const c of caps) byTheme.set(c.theme, [...(byTheme.get(c.theme) || []), c.text]);
  return el("ul", { class: "can-do" }, [...byTheme].map(([theme, texts]) =>
    el("li", {}, el("strong", {}, theme), el("span", {}, texts.join("; ")))));
}

function dossierView(c, compact = false) {
  const d = dossier(c);
  const rec = d.recommendation;
  return el("div", { class: "dossier" },
    el("p", { class: "small" }, el("strong", {}, d.label), " — ", d.what,
      el("span", { class: `confidence c-${d.confidence}` }, d.confidence === "alta" ? " Certeza alta." : " Certeza média: confira.")),
    el("div", { class: "dossier-cols" },
      el("div", {}, el("h4", {}, "Por que é suspeito"), el("ul", { class: "small" }, d.why.slice(0, compact ? 3 : 8).map((x) => el("li", {}, x)))),
      d.can_do.length ? el("div", {}, el("h4", {}, "O que ele consegue fazer"), canDoList(d.can_do)) : null),
    rec?.text ? el("div", { class: "recommend small" }, el("strong", {}, `Recomendamos: ${ACTION_INFO[rec.action].verb.toLowerCase()}. `),
      rec.text) : null);
}

function threatCard(r, c, lastAction, reload) {
  const state = appState(lastAction);
  const open = (action) => () => openActionWizard(r, c, action, reload);
  let buttons;
  if (state === "removido") buttons = [el("span", { class: "pill ok" }, icon("shield", "sm"), "Removido do aparelho")];
  else if (state === "desativado") buttons = [el("button", { onclick: open("enable") }, "Reativar…"),
    el("button", { class: "danger", onclick: open("uninstall") }, "Remover…")];
  else if (state === "restrito") buttons = [el("button", { onclick: open(null) }, "Mais opções…")];
  else buttons = [el("button", { class: c.level === "ameaca" ? "primary" : "", onclick: open(null) },
    c.level === "ameaca" ? "Resolver…" : "Agir sobre este app…")];

  return el("article", { class: `threat st-${c.worst}${state ? " is-done" : ""}` },
    el("div", { class: "threat-ico", "aria-hidden": "true" }, icon(c.level === "ameaca" ? "shieldAlert" : "phone")),
    el("div", { class: "grow" },
      el("div", { class: "threat-head" },
        el("strong", {}, appName(c)),
        c.family ? el("code", { class: "muted small" }, c.package) : null),
      el("div", { class: "threat-tags" },
        c.mercenary ? tag("spyware mercenário", "bad") : null,
        c.device_admin ? tag("administrador do aparelho", "warn") : null,
        c.sideloaded ? tag("instalado fora da loja", "warn") : null,
        c.user ? tag(`perfil ${c.user}`) : null,
        state ? tag(state, "good") : null),
      el("div", { class: "small" }, countsLine(c.counts)),
      state ? el("details", { class: "small" }, el("summary", {}, "Por que este app foi apontado"), dossierView(c))
        : dossierView(c, c.level !== "ameaca"),
      lastAction ? lastActionLine(lastAction) : null),
    el("div", { class: "actions threat-actions" }, buttons));
}

export function suggestionsCard(r, reload) {
  const candidates = r.removal_candidates || [];
  if (!candidates.length) return null;
  const last = lastActions(r);
  const byLevel = (lv) => candidates.filter((c) => (c.level || "ameaca") === lv);
  const threats = byLevel("ameaca");
  const open = candidates.filter((c) => !appState(last[c.package]));
  const pending = threats.filter((c) => !appState(last[c.package])).length;
  return el("section", { class: `card threats-card${pending ? " has-threats" : ""}`, "aria-label": "Ações sugeridas" },
    el("div", { class: "card-title" }, icon("shieldAlert", "lg"),
      el("div", { class: "grow" }, el("h2", {}, !threats.length ? "Apps para revisar" : pending
        ? `${pending} ameaça(s) para resolver` : "Ameaças tratadas — faça uma nova varredura para confirmar"),
        el("p", { class: "muted" }, "Para cada app explicamos o que é, por que foi apontado, o que ele consegue fazer "
          + "e o que recomendamos. Nada é alterado no celular sem a sua confirmação.")),
      open.length > 1 || (open.length === 1 && pending) ? el("button", { class: "primary plan-btn",
        onclick: () => openCleanupPlan(r, reload) }, icon("shield", "sm"), "Limpar com o Desgrampa…") : null),
    ["ameaca", "revisar"].map((lv) => {
      const list = byLevel(lv);
      if (!list.length) return null;
      return el("div", { class: "threat-group" },
        threats.length && lv === "revisar" ? el("h3", {}, "Apps para revisar") : null,
        lv === "revisar" ? el("p", { class: "muted small" }, LEVEL_HINT) : null,
        list.map((c) => threatCard(r, c, last[c.package], reload)));
    }));
}

// ---- peças comuns ao assistente e ao plano

function dialogShell(title, eyebrow, subtitle) {
  const steps = el("ol", { class: "wizard-steps" });
  const body = el("div", { class: "wizard-body" });
  const dlg = el("dialog", { class: "action-dialog wizard", "aria-label": title },
    el("div", { class: "wizard-top" },
      el("div", {}, el("div", { class: "eyebrow", style: "margin:0" }, eyebrow), el("h2", {}, title),
        subtitle ? el("code", { class: "muted small" }, subtitle) : null),
      el("button", { class: "icon-btn", "aria-label": "Fechar", onclick: () => dlg.close() }, "✕")),
    steps, body);
  return { dlg, steps, body };
}

function drawSteps(steps, labels, current) {
  fill(steps, current < labels.length ? labels.map((label, i) => el("li", {
    class: i === current ? "on" : i < current ? "done" : "", "aria-current": i === current ? "step" : null }, label)) : null);
}

// Caixa de seleção ligada a ui[key]; o redesenho recria o campo, então devolve o foco a ele
function checkbox(ui, key, label, redraw, body, cls = "") {
  return el("label", { class: `check ${cls}` },
    el("input", { type: "checkbox", checked: ui[key], "data-key": key, onchange: (ev) => {
      ui[key] = ev.target.checked;
      redraw();
      body.querySelector(`input[data-key=${key}]`)?.focus();
    } }),
    el("span", {}, label));
}

function navButtons(dlg, back, next, nextLabel, nextOk = true) {
  return el("div", { class: "actions dialog-actions" },
    back ? el("button", { onclick: back }, "Voltar") : el("button", { onclick: () => dlg.close() }, "Cancelar"),
    el("button", { class: "primary", disabled: !nextOk, onclick: next }, nextLabel));
}

function safetyContent(dlg, mercenary) {
  return [
    el("div", { class: "tip warn-tip" },
      el("strong", {}, "Quem instalou um app espião pode perceber quando ele para de funcionar."),
      el("p", { class: "small" }, "Se essa pessoa convive com você ou pode ficar violenta, pense em quando e onde "
        + "fazer isso. Muitas vezes é mais seguro primeiro guardar as provas e procurar apoio.")),
    el("ul", { class: "small" },
      el("li", {}, "Baixe o relatório ", el("strong", {}, "“Para atendimento ou autoridade”"),
        " antes de mexer no celular — ele serve como prova."),
      el("li", {}, "Apoio: ", el("strong", {}, "Ligue 180"), " (violência contra a mulher), ", el("strong", {}, "190"),
        " em emergência, ou veja ", el("a", { href: "#ajuda", onclick: () => dlg.close() }, "Preciso de ajuda"), "."),
      mercenary ? el("li", { class: "bad-text" }, el("strong", {}, "Spyware mercenário: "), "o recomendado é NÃO "
        + "alterar nada e procurar a Access Now Helpline ou o Amnesty Security Lab, que precisam do aparelho intacto.") : null),
  ];
}

const afterSteps = () => el("ul", { class: "small" },
  el("li", {}, "Faça uma nova varredura para confirmar que nada mais ficou ativo."),
  el("li", {}, "Troque as senhas das contas importantes (Google, WhatsApp, banco), de preferência em outro aparelho."),
  el("li", {}, "Desligue a Depuração USB ao terminar."));

function commandLog(res) {
  return res.commands?.length ? el("details", { class: "small" }, el("summary", {}, "Detalhes técnicos (comandos executados)"),
    el("pre", { class: "cmd-log" }, res.commands.map((x) => `$ ${x.cmd}\n${x.output ? `${x.output}\n` : ""}`).join(""))) : null;
}

function showDialog(dlg, ui, reload) {
  dlg.addEventListener("close", () => {
    dlg.remove();
    if (ui.changed) reload?.();
  });
  document.body.append(dlg);
  dlg.showModal();
}

// ---- assistente de um app: 1 segurança · 2 o que fazer · 3 confirmar · resultado

function openActionWizard(r, c, preset, reload) {
  const d = dossier(c);
  const ui = { step: preset === "enable" ? 2 : 0, action: preset || d.recommendation.action || "restrict",
    keep: true, safe: false, merc: false, typed: "", consent: false, busy: false, result: null, changed: false, drawn: null };
  const { dlg, steps, body } = dialogShell(appName(c), c.level === "ameaca" ? d.label : "Revisar app",
    c.family ? c.package : null);

  const needsMerc = () => c.mercenary && ui.action !== "enable";
  const canFinish = () => ui.consent && (!needsMerc() || ui.merc)
    && (ui.action !== "uninstall" || ui.typed.trim() === c.package);
  const go = (n) => () => { ui.step = n; draw(); };
  const check = (key, label, cls) => checkbox(ui, key, label, draw, body, cls);

  function chooseStep() {
    return [
      dossierView(c),
      el("div", { class: "choices", role: "radiogroup", "aria-label": "O que fazer" }, CHOICES.map((a) => {
        const info = ACTION_INFO[a];
        return el("label", { class: `choice${ui.action === a ? " on" : ""}` },
          el("input", { type: "radio", name: "wiz-action", value: a, checked: ui.action === a,
            onchange: () => { ui.action = a; draw(); body.querySelector(`input[value=${a}]`)?.focus(); } }),
          el("span", { class: "grow" },
            el("strong", {}, info.verb, a === d.recommendation.action ? el("span", { class: "muted small" }, " — recomendado") : null),
            el("span", { class: "small muted" }, info.what),
            el("span", { class: "choice-tags" }, info.tags.map(([t, k]) => tag(t, k)))));
      })),
      ACTION_INFO[ui.action].keep ? check("keep", "Guardar uma cópia do app (APK) na pasta de evidências antes (recomendado)") : null,
      navButtons(dlg, go(0), go(2), "Continuar"),
    ];
  }

  function confirmStep() {
    const info = ACTION_INFO[ui.action];
    const confirmBtn = el("button", { class: info.btn || "primary", disabled: !canFinish() || ui.busy, onclick: run }, `${info.verb} agora`);
    const typed = el("input", { type: "text", placeholder: c.package, autocomplete: "off", spellcheck: "false",
      value: ui.typed, "aria-label": "Nome do pacote",
      oninput: (ev) => { ui.typed = ev.target.value; confirmBtn.disabled = !canFinish(); } });
    return [
      el("div", { class: "summary" },
        el("div", {}, el("span", { class: "muted small" }, "Ação"), el("strong", {}, info.verb)),
        el("div", {}, el("span", { class: "muted small" }, "App"), el("code", {}, c.package)),
        info.keep ? el("div", {}, el("span", { class: "muted small" }, "Cópia do APK"), ui.keep ? "sim" : "não") : null,
        el("div", {}, el("span", { class: "muted small" }, "Evidências no celular"), info.evidence ? "preservadas" : "apagadas")),
      el("p", { class: "small" }, info.what),
      ui.action !== "enable" ? el("p", { class: "small muted" }, el("strong", {}, "Motivo: "), d.summary) : null,
      check("consent", `Eu autorizo o Desgrampa a ${info.consent} no meu celular`),
      needsMerc() ? check("merc", "Entendo que posso comprometer evidências de spyware mercenário", "bad-text") : null,
      ui.action === "uninstall" ? [el("label", { class: "small" }, "Remoção é definitiva. Para confirmar, digite o nome do pacote: ",
        el("code", {}, c.package)), typed] : null,
      el("p", { class: "small", role: "status" }, ui.busy ? "Executando… mantenha o celular conectado e desbloqueado." : ""),
      el("div", { class: "actions dialog-actions" },
        preset === "enable" ? el("button", { onclick: () => dlg.close() }, "Cancelar")
          : el("button", { onclick: go(1), disabled: ui.busy }, "Voltar"),
        confirmBtn),
    ];
  }

  function resultStep() {
    const res = ui.result;
    const ok = res.status === "ok";
    const [kind, label] = ACTION_STATUS[res.status] || ["bad", res.status];
    return [
      el("div", { class: `result-box ${kind}` }, el("strong", {}, `${ACTION_NOUN[ui.action]}: ${label}`), el("p", {}, res.message)),
      res.saved?.length ? el("p", { class: "small muted" }, `Cópia guardada como evidência: ${res.saved.map((s) => s.file).join(", ")}`) : null,
      ok && ui.action !== "enable" ? afterSteps() : null,
      commandLog(res),
      el("div", { class: "actions dialog-actions" },
        ok && ui.action !== "enable" ? el("a", { class: "btn", href: "#varredura", onclick: () => dlg.close() }, "Nova varredura") : null,
        el("button", { class: "primary", onclick: () => dlg.close() }, "Fechar")),
    ];
  }

  async function run() {
    ui.busy = true;
    draw();
    try {
      ui.result = await api("/api/actions", { report: r.report_name, package: c.package, action: ui.action,
        keep_apk: ACTION_INFO[ui.action].keep && ui.keep, consent: ui.consent, mercenary_ack: ui.merc,
        confirm: ui.action === "uninstall" ? ui.typed.trim() : undefined });
      ui.changed = true;
    } catch (e) {
      ui.result = { status: "falhou", message: e.message };
    }
    ui.step = 3;
    ui.busy = false;
    draw();
  }

  function draw() {
    drawSteps(steps, preset === "enable" ? [] : ["Sua segurança", "O que fazer", "Confirmar"], ui.step);
    fill(body, [
      () => [...safetyContent(dlg, c.mercenary), check("safe", "Estou num momento seguro e quero continuar"),
        navButtons(dlg, null, go(1), "Continuar", ui.safe)],
      chooseStep, confirmStep, resultStep][ui.step]());
    if (ui.drawn !== ui.step) body.querySelector("input, .dialog-actions .primary")?.focus();   // só ao trocar de etapa
    ui.drawn = ui.step;
  }

  draw();
  showDialog(dlg, ui, reload);
}

// ---- plano de limpeza: o Desgrampa propõe uma ação para cada app, o usuário revisa, autoriza e acompanha

function openCleanupPlan(r, reload) {
  const last = lastActions(r);
  const items = (r.removal_candidates || []).filter((c) => !appState(last[c.package])).map((c) => {
    const d = dossier(c);
    return { c, d, on: d.preselect, action: d.recommendation.action || "restrict", status: null, res: null };
  });
  const ui = { step: 0, safe: false, keep: true, consent: false, merc: false, typed: "", changed: false, drawn: null };
  const { dlg, steps, body } = dialogShell("Plano de limpeza", "Desgrampa", null);
  const chosen = () => items.filter((it) => it.on);
  const anyUninstall = () => chosen().some((it) => it.action === "uninstall");
  const anyMerc = () => chosen().some((it) => it.c.mercenary);
  const canRun = () => chosen().length && ui.consent && (!anyMerc() || ui.merc) && (!anyUninstall() || ui.typed.trim() === PLAN_CONFIRM);
  const go = (n) => () => { ui.step = n; draw(); };
  const check = (key, label, cls) => checkbox(ui, key, label, draw, body, cls);

  function planRow(it, i) {
    const select = el("select", { class: "plain", "aria-label": `Ação para ${appName(it.c)}`, disabled: !it.on,
      onchange: (ev) => { it.action = ev.target.value; draw(); body.querySelector(`select[data-i="${i}"]`)?.focus(); },
      "data-i": i }, CHOICES.map((a) => el("option", { value: a, selected: it.action === a },
      ACTION_INFO[a].verb + (a === it.d.recommendation.action ? " (recomendado)" : ""))));
    return el("li", { class: `plan-row${it.on ? " on" : ""}` },
      el("label", { class: "plan-pick" },
        el("input", { type: "checkbox", checked: it.on, "data-p": i, onchange: (ev) => {
          it.on = ev.target.checked; draw(); body.querySelector(`input[data-p="${i}"]`)?.focus();
        } }),
        el("span", { class: "grow" }, el("strong", {}, appName(it.c)), " ", el("code", { class: "muted small" }, it.c.package),
          " ", el("span", { class: "muted small" }, `· ${it.d.label}`),
          it.c.mercenary ? [" ", tag("mercenário: preserve provas", "bad")] : null)),
      el("p", { class: "small" }, it.d.summary),
      it.d.can_do.length ? el("p", { class: "small muted" }, "Consegue: ", it.d.can_do.slice(0, 3).map((x) => x.text).join("; "), ".") : null,
      el("div", { class: "plan-action" }, select, el("span", { class: "small muted" }, it.d.recommendation.text)));
  }

  function reviewStep() {
    return [
      el("p", { class: "small" }, "Analisamos cada app e propomos uma ação. Já vêm marcados só os apps de espionagem "
        + "claros; os demais você decide. Mude o que quiser."),
      el("ol", { class: "plan-list" }, items.map(planRow)),
      check("keep", "Guardar uma cópia de cada app (APK) na pasta de evidências antes (recomendado)"),
      navButtons(dlg, go(0), go(2), `Revisar ${chosen().length} ação(ões)`, chosen().length > 0),
    ];
  }

  function authorizeStep() {
    const runBtn = el("button", { class: anyUninstall() ? "danger" : "primary", disabled: !canRun(), onclick: run },
      `Executar ${chosen().length} ação(ões)`);
    const typed = el("input", { type: "text", placeholder: PLAN_CONFIRM, autocomplete: "off", spellcheck: "false",
      value: ui.typed, "aria-label": "Confirmação",
      oninput: (ev) => { ui.typed = ev.target.value; runBtn.disabled = !canRun(); } });
    return [
      el("p", { class: "small" }, "O Desgrampa vai fazer, nesta ordem:"),
      el("ol", { class: "plan-summary small" }, chosen().map((it) => el("li", {},
        el("strong", {}, `${ACTION_INFO[it.action].verb}: ${appName(it.c)}`), " ", el("code", {}, it.c.package),
        " — ", it.d.summary))),
      el("p", { class: "small muted" }, ui.keep ? "Uma cópia de cada app será guardada antes como prova. " : "",
        "Cada ação fica registrada no relatório com o motivo."),
      check("consent", "Eu autorizo o Desgrampa a executar estas ações no meu celular"),
      anyMerc() ? check("merc", "Entendo que posso comprometer evidências de spyware mercenário", "bad-text") : null,
      anyUninstall() ? [el("label", { class: "small" }, "Há remoções, que são definitivas. Para confirmar, digite ",
        el("code", {}, PLAN_CONFIRM), ":"), typed] : null,
      el("div", { class: "actions dialog-actions" }, el("button", { onclick: go(1) }, "Voltar"), runBtn),
    ];
  }

  function progressStep() {
    const label = { null: "aguardando", running: "executando…" };
    const done = items.filter((it) => it.res).length;
    const finished = chosen().every((it) => it.res);
    return [
      el("p", { class: "small", role: "status" }, finished ? "Plano concluído." : `Executando ${done + 1} de ${chosen().length}… mantenha o celular conectado e desbloqueado.`),
      el("ol", { class: "plan-progress" }, chosen().map((it) => {
        const [kind, text] = it.res ? ACTION_STATUS[it.res.status] || ["bad", it.res.status] : ["", label[it.status]];
        return el("li", { class: `pp-${it.res ? it.res.status : it.status || "wait"}` },
          el("span", { class: "ck-mark", "aria-hidden": "true" }),
          el("span", { class: "grow" }, el("strong", {}, `${ACTION_INFO[it.action].verb}: ${appName(it.c)}`),
            el("code", { class: "muted small" }, it.c.package),
            it.res ? el("span", { class: "small muted" }, it.res.message) : null, it.res ? commandLog(it.res) : null),
          tag(text, kind));
      })),
      finished ? afterSteps() : null,
      finished ? el("div", { class: "actions dialog-actions" },
        el("a", { class: "btn", href: "#varredura", onclick: () => dlg.close() }, "Nova varredura"),
        el("button", { class: "primary", onclick: () => dlg.close() }, "Fechar")) : null,
    ];
  }

  async function run() {
    ui.step = 3;
    for (const it of chosen()) {
      it.status = "running";
      draw();
      try {
        it.res = await api("/api/actions", { report: r.report_name, package: it.c.package, action: it.action, via: "plano",
          keep_apk: ui.keep, consent: ui.consent, mercenary_ack: ui.merc,
          confirm: it.action === "uninstall" ? ui.typed.trim() : undefined });
        ui.changed = true;
      } catch (e) {
        it.res = { status: "falhou", message: e.message };
      }
    }
    draw();
  }

  function draw() {
    drawSteps(steps, ["Sua segurança", "Revisar o plano", "Autorizar", "Executar"], ui.step);
    fill(body, [
      () => [...safetyContent(dlg, items.some((it) => it.c.mercenary)),
        check("safe", "Estou num momento seguro e quero continuar"), navButtons(dlg, null, go(1), "Continuar", ui.safe)],
      reviewStep, authorizeStep, progressStep][ui.step]());
    if (ui.drawn !== ui.step) body.querySelector("input, .dialog-actions .primary")?.focus();
    ui.drawn = ui.step;
  }

  // fechar no meio da execução não interrompe o que já foi pedido; o relatório recarrega com o que foi feito
  draw();
  showDialog(dlg, ui, reload);
}
