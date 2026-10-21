// Abas de detalhe do resultado: rede, telefonia, contas, rastros, apps, evidências e checklist manual.

import { el, facts, MB, store, table, tag } from "./dom.js";

const statusTag = (st) => tag(st, { ok: "good", diferente: "", "sem resposta": "" }[st] ?? "bad");

export function networkTab(data) {
  const rede = data.rede || {};
  const links = data.links || [];
  const pc = data.pcnet;
  const vpn = data.vpn || {};
  const pdns = data.private_dns || {};
  const ic = data.intercept || {};
  return el("div", {},
    facts([
      ["Wi-Fi conectado", rede.wifi?.connected],
      ["VPN", vpn.always_on ? `sempre ativa: ${vpn.always_on}` : vpn.active ? "conectada" : "nenhuma"],
      ["DNS privado", pdns.mode === "hostname" ? pdns.host : (pdns.mode || "padrão")],
      ["Aviso de certificado instalado", ic.user_ca_warning ? tag("SIM", "bad") : tag("não", "good")],
      ["Certificados no sistema", Object.entries(ic.stores || {}).map(([k, v]) => `${v} em ${k.split("/").slice(-2).join("/")}`).join(", ")],
      ["Certificados adicionados", (ic.injected || []).length ? tag(String(ic.injected.length), "bad") : tag("0", "good")],
    ]),
    el("h3", {}, "Conexões de rede ativas no celular"),
    table(["Interface", "DNS", "Gateway", "Proxy"],
      links.map((l) => [l.iface, l.dns.join(", "), l.gateways.join(", "), l.proxy ? tag(l.proxy, "bad") : "—"])),
    el("h3", {}, "Servidores DNS em uso"),
    table(["Interface", "Servidor", "Tipo"], (rede.dns_servers || []).map((x) => [x.iface, x.ip, x.kind])),
    el("h3", {}, "Teste de DNS feito pelo celular"),
    el("p", { class: "muted small" }, "Compara a resposta do celular com uma consulta criptografada (DNS-over-HTTPS) feita pelo computador. “diferente” é comum com CDNs; “adulterado” e “sequestro” não."),
    table(["Domínio", "Resposta no celular", "Referência", "Resultado"],
      (rede.dns_tests || []).map((t) => [t.domain, t.phone, (t.reference || []).join(", "), statusTag(t.status)])),
    el("h3", {}, "Conexões ativas por app (destinos públicos)"),
    table(["App", "Destinos"], (rede.connections || []).map((c) => [c.package, c.remotes.slice(0, 6).join(", ")]),
      "Nenhuma conexão listada (o Android pode bloquear essa leitura)."),
    rede.data_usage ? [el("h3", {}, "Dados enviados por app (histórico recente)"),
      table(["App", "Enviado em 2º plano", "Enviado em uso", "Recebido em 2º plano"],
        rede.data_usage.map((u) => [u.package, MB(u.bg_tx), MB(u.fg_tx), MB(u.bg_rx)]))] : null,
    el("h3", {}, "Redes Wi-Fi salvas"),
    table(["Rede", "Segurança"], (rede.wifi?.saved || []).map((n) => [n.ssid,
      /open|none/i.test(n.security) ? tag(n.security, "warn") : n.security])),
    el("h3", {}, "Rede local testada pelo computador"),
    pc ? el("div", {},
      facts([
        ["Gateway", `${pc.gateway || "?"} (${pc.gateway_mac || "MAC ?"})`],
        ["DNS do computador", (pc.dns_servers || []).join(", ")],
        ["IP público", pc.public_ip ? `${pc.public_ip.ip} (${pc.public_ip.country})` : null],
        ["Proxy transparente", pc.http?.proxy_headers && Object.keys(pc.http.proxy_headers).length
          || pc.http?.content_ok === false || pc.http?.generate_204 === false ? tag("detectado", "bad") : tag("não", "good")],
      ]),
      table(["Site (HTTPS)", "Emissor do certificado", "Resultado"],
        (pc.tls || []).map((t) => [t.host, t.issuer, t.status === "ok" ? tag("ok", "good") : tag(t.status, "bad")])),
      table(["Domínio", "DNS da rede", "DNS criptografado", "Resultado"],
        (pc.dns || []).map((t) => [t.domain, t.system.join(", "), (t.doh || []).join(", "), statusTag(t.status)])),
    ) : el("p", { class: "muted" }, "Não testada nesta varredura (opção desmarcada)."),
  );
}

export function telephonyTab(tel) {
  if (!tel) return el("p", { class: "muted" }, "Sem dados de telefonia.");
  return el("div", {},
    facts([
      ["Desvio de chamadas", tel.call_forwarding ? tag("ATIVO", "bad") : tag("não", "good")],
      ["Rede 2G agora", tel.radio_2g ? tag(tel.radio_2g, "warn") : tag("não", "good")],
    ]),
    el("h3", {}, "Chips e redes"),
    table(["Chip", "Operadora do chip", "Rede registrada", "Roaming"],
      tel.slots.map((x) => [x.slot, `${x.sim} (${x.sim_code})`, `${x.network} (${x.network_code})`, x.roaming ? "sim" : "não"])),
    el("h3", {}, "Apps com controle de ligações e mensagens"),
    table(["Função", "App"], Object.entries(tel.roles).map(([k, v]) => [k, v.join(", ") || "—"])),
    el("p", { class: "muted small" }, "Para conferir manualmente na operadora: *#21# (desvio incondicional), *#62# (se não atender), *#67# (se ocupado). ##002# cancela todos os desvios."),
  );
}

export function accountsTab(contas, controle) {
  if (!contas) return el("p", { class: "muted" }, "Sem dados de contas.");
  return el("div", {},
    el("h3", {}, "Contas cadastradas no aparelho"),
    table(["Conta", "Tipo", "App responsável", "Usuário"], contas.accounts.map((a) => [a.name, a.type, a.app, a.user])),
    el("h3", {}, "Usuários e perfis"),
    table(["ID", "Nome", "Em execução"], contas.users.map((u) => [u.id, u.name, u.running ? "sim" : "não"])),
    contas.extra_users.length ? [el("h3", {}, "Apps em perfis adicionais"),
      table(["Perfil", "Apps de terceiros", "Só existem nesse perfil", "Acessibilidade"],
        contas.extra_users.map((u) => [`${u.kind} (${u.id})`, u.apps.length, u.only_here.join(", ") || "—",
          u.accessibility.join(", ") || "—"]))] : null,
    controle ? [
      el("h3", {}, "Gerenciamento e controle remoto"),
      facts([
        ["Device Owner (MDM)", controle.device_policy.device_owner ? tag(controle.device_policy.device_owner, "bad") : tag("nenhum", "good")],
        ["Administradores", controle.device_policy.admins.join(", ") || "nenhum"],
        ["Assistente padrão", controle.assistant.join(", ") || "—"],
      ]),
      table(["App", "Tipo", "Oculto", "Acessibilidade"], controle.apps.map((a) => [`${a.name} (${a.package})`, a.type,
        a.hidden ? tag("sim", "bad") : "não", a.accessibility ? tag("sim", "warn") : "não"]),
      "Nenhum app de acesso remoto ou de localização encontrado."),
    ] : null,
  );
}

export function tracesTab(rastros) {
  if (!rastros) return el("p", { class: "muted" }, "Sem dados de rastros.");
  return el("div", {},
    el("h3", {}, "Apps que já estiveram no aparelho e foram removidos"),
    table(["Pacote", "Onde deixou rastro", "Indicador de spyware"],
      rastros.removed.map((x) => [x.package, x.sources.join(", "), x.ioc ? tag(x.ioc, "bad") : "—"]),
      "Nenhum rastro de app removido."),
    el("h3", {}, "Instalações e remoções registradas (histórico de bateria)"),
    table(["Quando", "Evento", "Pacote"], rastros.install_events.map((x) => [x.time || "?", x.event, x.package]),
      "Nenhum evento registrado."),
    el("h3", {}, "Menções a servidores de spyware nos logs"),
    table(["Endereço", "Indicador"], Object.entries(rastros.log_hits).map(([h, m]) => [h, tag(m, "bad")]),
      `Nenhuma menção em ${rastros.logcat_lines} linhas de log.`),
    rastros.ioc_files.length ? [el("h3", {}, "Arquivos de spyware encontrados"),
      table(["Caminho"], rastros.ioc_files.map((p) => [p]))] : null,
  );
}

export function appsTab(apps) {
  return table(["Pacote", "Risco", "Origem", "Ícone", "Motivos", "SHA-256"], apps.map((a) => [
    el("code", {}, a.package), a.score,
    a.sideloaded ? tag("fora da loja", "warn") : (a.installer || "?"),
    a.has_launcher === false ? tag("oculto", "bad") : a.has_launcher ? "sim" : "?",
    a.reasons.join(", "), a.sha256 ? el("code", {}, a.sha256.slice(0, 16) + "…") : "—",
  ]));
}

export function evidenceTab(r) {
  const mvt = r.data.mvt;
  const statusTagFor = (st) => ({ ok: tag("executada", "good"), skipped: tag("pulada", "warn"), error: tag("erro", "bad") })[st];
  return el("div", {},
    facts([
      ["Pasta de evidências", r.evidence_dir ? el("code", {}, r.evidence_dir) : "não salva"],
      ["Comandos coletados", r.stats.commands],
      ["Verificações executadas", `${r.stats.checks_run}/${r.stats.checks_total}`],
      ["Duração", `${r.duration_s} s`],
    ]),
    el("p", { class: "muted small" }, "A pasta contém a saída bruta de cada comando, o relatório, o bugreport e o resultado do MVT (varredura completa), com SHA256SUMS.txt para provar que nada foi alterado. É isso que você entrega a um especialista."),
    el("h3", {}, "MVT (Anistia Internacional)"),
    mvt ? facts([["Versão", mvt.version], ["Alertas", mvt.alerts ? tag(String(mvt.alerts), "bad") : tag("0", "good")],
      ["Módulos com dados", mvt.modules_with_data], ["Bugreport", `${mvt.bugreport_mb} MB`]])
      : el("p", { class: "muted" }, "Não executado nesta varredura (veja o motivo abaixo)."),
    el("h3", {}, "Todas as verificações"),
    table(["Área", "Verificação", "Situação", "Motivo"], r.categories.flatMap((c) =>
      c.checks.map((x) => [c.title, x.name, statusTagFor(x.status), x.reason || ""]))),
    el("h3", {}, "Bases de indicadores consultadas"),
    table(["Conjunto", "Indicadores"], Object.entries(r.iocs.collections).map(([k, v]) => [k, v.toLocaleString("pt-BR")])),
    r.notes.length ? [el("h3", {}, "Limitações encontradas"), el("ul", { class: "small muted" }, r.notes.map((n) => el("li", {}, n)))] : null,
  );
}

const MANUAL = [
  ["Contas Google", [
    ["g-devices", "Dispositivos conectados à sua conta Google", "https://myaccount.google.com/device-activity"],
    ["g-location", "Google Maps > foto do perfil > Compartilhamento de local: ninguém que você não autorizou", "https://maps.google.com/"],
    ["g-security", "Atividade de segurança recente e e-mail/telefone de recuperação", "https://myaccount.google.com/security"],
    ["g-apps", "Apps de terceiros com acesso à conta", "https://myaccount.google.com/connections"],
    ["g-forward", "Encaminhamento e filtros no Gmail (Configurações > Encaminhamento)", "https://mail.google.com/mail/u/0/#settings/fwdandpop"],
    ["g-fmd", "Find My Device: o aparelho aparece só na SUA conta", "https://www.google.com/android/find"],
  ]],
  ["Mensageiros e redes sociais", [
    ["wa", "WhatsApp > Dispositivos conectados: desconecte o que não reconhecer"],
    ["tg", "Telegram > Configurações > Dispositivos: encerre sessões desconhecidas"],
    ["ig", "Instagram/Facebook > Central de contas > Onde você está conectado"],
    ["icloud", "Se usa Apple/Samsung/Xiaomi: dispositivos na conta Apple ID / Samsung Account / Mi Account"],
  ]],
  ["Operadora e chip", [
    ["mmi", "Discar *#21#, *#62# e *#67# para ver desvios (##002# cancela todos)"],
    ["pin", "Ativar PIN do chip e pedir à operadora bloqueio de troca de chip/portabilidade sem presença"],
    ["2g", "Desligar “Permitir 2G” (Configurações > Rede > Chip), se o aparelho tiver a opção"],
  ]],
  ["Rede de casa", [
    ["router", "Entrar no roteador: conferir DNS configurado, aparelhos conectados e atualizar o firmware"],
    ["wifi", "Trocar a senha do Wi-Fi e a senha de administrador do roteador"],
  ]],
  ["Depois da varredura", [
    ["usb", "Desligar Depuração USB e revogar autorizações (Opções do desenvolvedor)"],
    ["pw", "Trocar senhas a partir de outro aparelho e ativar 2FA com app autenticador ou chave física"],
    ["lockdown", "Se o risco for alto: Proteção Avançada do Google", "https://landing.google.com/advancedprotection/"],
  ]],
];

export function manualTab() {
  const done = store.get("desgrampa-manual", {});
  return el("div", { class: "manual" },
    el("p", { class: "muted" }, "Estas verificações não podem ser feitas pelo cabo USB, porque estão na nuvem ou na operadora. Marque conforme for fazendo (fica salvo neste navegador)."),
    MANUAL.map(([group, items]) => [el("h3", {}, group), el("ul", {}, items.map(([key, label, url]) =>
      el("li", {}, el("label", {},
        el("input", { type: "checkbox", checked: !!done[key], onchange: (ev) => {
          done[key] = ev.target.checked; store.set("desgrampa-manual", done);
        } }),
        el("span", {}, label, url ? [" — ", el("a", { href: url, target: "_blank", rel: "noopener" }, "abrir")] : null)))))]),
  );
}
