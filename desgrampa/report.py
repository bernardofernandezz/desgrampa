"""Relatório HTML autocontido (para salvar, imprimir ou entregar a um especialista).

render() junta seções independentes; cada função _secao recebe o resultado e devolve um trecho HTML.
Todo texto vindo do aparelho passa por e() (escape de HTML).
"""

from html import escape

from .checks import SEVERITY_LABELS

STATUS_LABELS = {"critica": "Crítico", "alta": "Suspeito", "media": "Atenção", "baixa": "Baixo risco",
                 "ok": "Nada encontrado", "nao_verificado": "Não verificado"}
# severidade -> (singular, plural, classe CSS)
SEV_PLURAL = {"critica": ("crítico", "críticos", "c"), "alta": ("alto", "altos", "a"), "media": ("médio", "médios", "m"),
              "baixa": ("baixo", "baixos", ""), "info": ("informativo", "informativos", "")}

CSS = """
body{font:14.5px/1.5 system-ui,sans-serif;max-width:960px;margin:32px auto;padding:0 16px;color:#1d2330;background:#fff}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}
h3{font-size:15px;margin:18px 0 6px}.muted{color:#5d6675}.verdict{padding:14px 18px;border-radius:8px;margin:18px 0;border-left:6px solid}
.alto_risco,.st-critica{background:#fdecec;border-color:#c62828}.suspeito,.st-alta{background:#fff2e5;border-color:#e86a00}
.atencao,.st-media{background:#fff9db;border-color:#c99a00}.ok,.st-ok,.st-baixa{background:#e8f5ec;border-color:#2e7d32}
.st-nao_verificado{background:#f1f2f4;border-color:#8a94a3}
.f{border:1px solid #e3e6ea;border-radius:8px;padding:10px 14px;margin:8px 0;break-inside:avoid}
.sev{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;border-radius:10px;margin-right:6px;color:#fff}
.critica{background:#c62828}.alta{background:#e86a00}.media{background:#b58900}.baixa{background:#5d6675}.info{background:#8a94a3}
.rec{margin-top:6px;font-size:13.5px}table{border-collapse:collapse;width:100%;font-size:13px;margin:6px 0}
td,th{border-bottom:1px solid #eee;padding:5px 6px;text-align:left;vertical-align:top}code{font-size:12px;word-break:break-all}
.cats td:first-child{border-left:5px solid;font-weight:600}
details{margin:6px 0}summary{cursor:pointer;padding:6px 0}summary b{font-size:15px}
details.cat>summary{font-size:16px;border-bottom:1px solid #eee}details.src{margin-left:18px}
.cnt{font-size:12.5px;color:#5d6675;margin-left:6px}.cnt .c{color:#c62828;font-weight:600}.cnt .a{color:#e86a00;font-weight:600}
.cnt .m{color:#b58900;font-weight:600}.sug{border:1px solid #f0c9c9;background:#fdf6f6;border-radius:8px;padding:10px 14px;margin:8px 0}
.toolbar{position:sticky;top:0;background:#fff;padding:10px 0;border-bottom:1px solid #eee;display:flex;gap:10px;align-items:center}
.toolbar button{font:inherit;padding:7px 14px;border-radius:8px;border:1px solid #2f6fed;background:#2f6fed;color:#fff;cursor:pointer}
.box{border:1px solid #ccc;border-radius:6px;padding:10px 14px;margin:10px 0}.sig{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:50px}
.sig div{border-top:1px solid #333;padding-top:4px;font-size:12.5px}dl.kv{display:grid;grid-template-columns:220px 1fr;gap:4px 12px;margin:8px 0}
dl.kv dt{color:#5d6675}dl.kv dd{margin:0}blockquote{margin:6px 0;padding:6px 12px;border-left:3px solid #ccc;color:#333;font-size:13px}
@media print{.toolbar{display:none}body{margin:0;max-width:none;font-size:12px}details{display:block}details>summary{list-style:none}
details:not([open])>*:not(summary){display:block}h2{break-after:avoid}a{color:inherit;text-decoration:none}@page{margin:16mm 14mm}}
"""
TOOLBAR = ("<div class=toolbar><button onclick='window.print()'>Imprimir ou salvar em PDF</button>"
           "<span class=muted>No diálogo de impressão, escolha “Salvar como PDF”.</span></div>")


# ---------------------------------------------------------------- helpers

def system_label(d):
    if d.get("platform") == "ios":
        return f"iOS {d.get('ios') or '?'}"
    return f"Android {d.get('android') or '?'} · patch {d.get('security_patch') or '?'}"


def e(value):
    return escape("" if value is None else str(value))


def table(headers, rows):
    head = "".join(f"<th>{e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


def counts_line(counts):
    """“10 críticos · 10 altos · 5 médios” (só as severidades presentes)."""
    parts = [f"<span class='{cls}'>{counts[sev]} {one if counts[sev] == 1 else many}</span>"
             for sev, (one, many, cls) in SEV_PLURAL.items() if counts.get(sev)]
    return " · ".join(parts)


def finding_html(f):
    recommendation = f"<div class=rec><b>O que fazer:</b> {e(f['recommendation'])}</div>" if f["recommendation"] else ""
    return (f"<div class=f><span class='sev {e(f['severity'])}'>{e(SEVERITY_LABELS[f['severity']])}</span>"
            f"<strong>{e(f['title'])}</strong><div>{e(f['detail'])}</div>{recommendation}"
            f"<div class=muted style='font-size:12px'>{e(f['check'])}</div></div>")


# ---------------------------------------------------------------- seções

def _header(r):
    d, v, s, iocs = r["device"], r["verdict"], r["stats"], r["iocs"]
    out = [
        "<h1>Relatório de varredura</h1>",
        f"<div class=muted>{e(d.get('manufacturer'))} {e(d.get('model'))} · {e(system_label(d))} · "
        f"serial {e(d.get('serial'))} · {e(r['started'])} · varredura "
        f"{e(r['mode'])} ({r['duration_s']} s)</div>",
        f"<div class='verdict {e(v['code'])}'><strong>{e(v['label'])}</strong><br>{e(v['text'])}</div>",
        f"<p class=muted>{s['categories_verified']}/{s['categories_total']} áreas verificadas · "
        f"{s['checks_run']}/{s['checks_total']} verificações executadas · {s['commands']} comandos coletados · "
        f"{s['packages']} apps ({s['third_party']} do usuário, {s['sideloaded']} fora da loja) · "
        f"{iocs['total']} indicadores de {len(iocs['collections'])} bases ({e(iocs['source'])}, {e(iocs['updated'])}).</p>",
    ]
    if r.get("evidence_dir"):
        out.append(f"<p class=muted>Evidências (comandos brutos, bugreport, MVT, SHA256SUMS): "
                   f"<code>{e(r['evidence_dir'])}</code></p>")
    return "".join(out)


def _categories(r):
    rows = []
    for c in r["categories"]:
        checks = "; ".join(x["name"] + (f" ({x['reason']})" if x["status"] != "ok" else "") for x in c["checks"])
        rows.append(f"<tr><td class='st-{e(c['status'])}'>{e(c['title'])}</td><td>{e(STATUS_LABELS[c['status']])}</td>"
                    f"<td class=muted>{e(checks)}</td></tr>")
    return ("<h2>Áreas verificadas</h2><table class=cats><tr><th>Área</th><th>Resultado</th><th>Verificações</th></tr>"
            + "".join(rows) + "</table>")


def _suggestions(r):
    candidates = r.get("removal_candidates", [])
    if not candidates:
        return ""
    done = {a["package"]: a for a in r.get("actions", []) if a.get("status") == "ok"}
    out = ["<h2>Ações sugeridas</h2><p class=muted>Apps com achado crítico ou de spyware/malware. Nada é removido "
           "automaticamente: a remoção só acontece se você confirmar no app.</p>"]
    for c in candidates:
        action = done.get(c["package"])
        out.append(f"<div class=sug><b>{e(c['family'] or c['package'])}</b> <code>{e(c['package'])}</code>"
                   f"<span class=cnt>{counts_line(c['counts'])}</span><br>"
                   f"<span class=muted>{e('; '.join(c['reasons']))}</span>"
                   + (f"<br><b>Ação realizada:</b> {e(action['action'])} em {e(action['time'])}" if action else "")
                   + ("<br><b>Spyware mercenário:</b> não remova antes de uma análise forense." if c["mercenary"] else "")
                   + "</div>")
    return "".join(out)


def _findings_tree(r):
    if not r["findings"]:
        return "<h2>Achados por categoria e origem</h2><p>Nenhum achado.</p>"
    out = ["<h2>Achados por categoria e origem</h2>"]
    for cat in r.get("tree", []):
        out.append(f"<details class=cat open><summary><b>{e(cat['title'])}</b> ({cat['total']})"
                   f"<span class=cnt>{counts_line(cat['counts'])}</span></summary>")
        for src in cat["children"]:
            is_open = "open" if src["worst"] in ("critica", "alta") else ""
            out.append(f"<details class=src {is_open}><summary><b>{e(src['label'])}</b> ({src['total']})"
                       f"<span class=cnt>{counts_line(src['counts'])}</span></summary>"
                       + "".join(finding_html(r["findings"][i]) for i in src["items"]) + "</details>")
        out.append("</details>")
    return "".join(out)


def _groups_summary(r):
    groups = [g for g in r.get("groups", []) if g["worst"] != "info"]
    if not groups:
        return ""
    return "<h2>Resumo por origem</h2>" + table(
        ["Origem", "Total", "Críticos", "Altos", "Médios", "Baixos", "Áreas"],
        [(g["label"], g["total"], g["counts"]["critica"], g["counts"]["alta"], g["counts"]["media"],
          g["counts"]["baixa"], ", ".join(g["categories"])) for g in groups])


def _actions_log(r):
    if not r.get("actions"):
        return ""
    return "<h2>Ações realizadas no aparelho</h2>" + table(
        ["Quando", "App", "Ação", "Resultado", "Cópia do APK"],
        [(a["time"], a["package"], a["action"], a.get("message"),
          ", ".join(s["file"] for s in a.get("saved", [])) or "—") for a in r["actions"]])


def _network_data(data):
    out = []
    links = data.get("links", [])
    if links:
        out.append("<h3>Conexões de rede ativas</h3>" + table(
            ["Interface", "DNS", "Gateway", "Proxy"],
            [(link["iface"], ", ".join(link["dns"]), ", ".join(link["gateways"]), link["proxy"] or "—") for link in links]))
    rede = data.get("rede", {})
    if rede.get("dns_tests"):
        out.append("<h3>Teste de DNS pelo celular</h3>" + table(
            ["Domínio", "Resposta no celular", "Referência (DoH)", "Resultado"],
            [(t["domain"], t["phone"] or "—", ", ".join(t["reference"] or []) or "—", t["status"])
             for t in rede["dns_tests"]]))
    if rede.get("connections"):
        out.append("<h3>Conexões ativas por app</h3>" + table(
            ["App", "Destinos"], [(c["package"], ", ".join(c["remotes"][:8])) for c in rede["connections"]]))
    if rede.get("data_usage"):
        out.append("<h3>Dados enviados em segundo plano</h3>" + table(
            ["App", "Enviado (2º plano)", "Enviado (uso)"],
            [(u["package"], f"{u['bg_tx'] // 1048576} MB", f"{u['fg_tx'] // 1048576} MB") for u in rede["data_usage"]]))
    pc = data.get("pcnet")
    if pc:
        public_ip = pc.get("public_ip") or {}
        out.append("<h3>Rede local (pelo computador)</h3>"
                   f"<p class=muted>Gateway {e(pc.get('gateway'))} ({e(pc.get('gateway_mac'))}) · DNS "
                   f"{e(', '.join(pc.get('dns_servers', [])))} · IP público {e(public_ip.get('ip'))} "
                   f"({e(public_ip.get('country'))})</p>"
                   + table(["Site", "Emissor do certificado", "Resultado"],
                           [(t["host"], t.get("issuer"), t["status"]) for t in pc.get("tls", [])])
                   + table(["Domínio", "DNS da rede", "DoH", "Resultado"],
                           [(t["domain"], ", ".join(t["system"]), ", ".join(t["doh"] or []), t["status"])
                            for t in pc.get("dns", [])]))
    return "".join(out)


def _phone_data(data):
    out = []
    tel = data.get("telefonia")
    if tel:
        out.append("<h3>Telefonia</h3>"
                   f"<p>Desvio de chamadas: <b>{'ATIVO' if tel['call_forwarding'] else 'não'}</b> · Rede 2G agora: "
                   f"<b>{e(tel['radio_2g'] or 'não')}</b></p>"
                   + table(["Chip", "Operadora do chip", "Rede registrada", "Roaming"],
                           [(x["slot"], f"{x['sim']} ({x['sim_code']})", f"{x['network']} ({x['network_code']})",
                             "sim" if x["roaming"] else "não") for x in tel["slots"]])
                   + table(["Função", "App"], [(k, ", ".join(v) or "—") for k, v in tel["roles"].items()]))
    contas = data.get("contas")
    if contas:
        out.append("<h3>Contas no aparelho</h3>" + table(
            ["Conta", "Tipo", "App", "Usuário"],
            [(a["name"], a["type"], a.get("app") or "—", a["user"]) for a in contas["accounts"]]))
        if contas["extra_users"]:
            out.append("<h3>Perfis adicionais</h3>" + table(
                ["Usuário", "Tipo", "Apps de terceiros", "Só neste perfil"],
                [(u["id"], u["kind"], len(u["apps"]), ", ".join(u["only_here"]) or "—") for u in contas["extra_users"]]))
    return "".join(out)


def _traces_data(data):
    out = []
    rastros = data.get("rastros") or {}
    if rastros.get("removed"):
        out.append("<h3>Apps que já estiveram no aparelho</h3>" + table(
            ["Pacote", "Onde foi visto", "Indicador"],
            [(x["package"], ", ".join(x["sources"]), x["ioc"] or "—") for x in rastros["removed"]]))
    if rastros.get("install_events"):
        out.append("<h3>Instalações e remoções registradas</h3>" + table(
            ["Quando", "Evento", "Pacote"], [(x["time"] or "?", x["event"], x["package"]) for x in rastros["install_events"]]))
    m = data.get("mvt")
    if m:
        out.append(f"<h3>MVT</h3><p>Versão {e(m['version'])} · {m['alerts']} alerta(s) · "
                   f"{m['modules_with_data']} módulos com dados · bugreport {m['bugreport_mb']} MB · "
                   f"resultados em <code>{e(m['output_dir'])}</code></p>")
    return "".join(out)


def _apps(r):
    return "<h2>Aplicativos instalados pelo usuário</h2>" + table(
        ["Pacote", "Risco", "Origem", "Motivos", "SHA-256"],
        [(a["package"], a["score"], "fora da loja" if a["sideloaded"] else (a["installer"] or "?"),
          ", ".join(a["reasons"]), a.get("sha256") or "—") for a in r["apps"]])


def _vulns(data):
    v = data.get("vulns")
    if not v:
        return ""
    c, d, exp = v["counts"], v["device"], v["exposure"]
    out = [f"<h2>Vulnerabilidades conhecidas</h2><p>Patch de segurança <b>{e(d['spl'])}</b> · Android {e(d['android'])}"
           f"{' (sem suporte)' if d['eol'] else ''} · <b>{c['total']}</b> falhas sem correção ({c['C']} críticas, "
           f"{c['H']} altas, <b>{c['kev']} exploradas ativamente</b>)"
           + (f" · {c['likely']} prováveis por a versão não ter mais suporte" if c["likely"] else "")
           + f". Índice de exposição: <b>{exp['score']}/100 ({e(exp['label'])})</b>.</p>"]
    active = [f["label"] for f in exp["factors"] if f["active"]]
    if active:
        out.append("<p class=muted>Fatores: " + e("; ".join(active)) + ".</p>")
    kev = [i for i in v["items"] if i["kev"]]
    top = kev + [i for i in v["items"] if not i["kev"] and i["severity"] == "C"][:20]
    if top:
        out.append(table(["CVE", "Gravidade", "Explorada", "Componente", "Corrigida em", "Resumo"],
                         [(i["cve"], i["severity"], "sim" if i["kev"] else "—", i["component"], i["spl"], i["summary"])
                          for i in top]))
    if v["chromium"]:
        out.append(table(["App", "Versão", "Estável atual", "Exploradas desde então"],
                         [(x["name"], x["version"], x["stable"], ", ".join(x["exploited"]) or "—") for x in v["chromium"]]))
    out.append(f"<p class=muted>Base: boletins até {e(v['db']['latest_spl'])}, gerada em {e(v['db']['generated'])}.</p>")
    return "".join(out)


def _notes(r):
    if not r["notes"]:
        return ""
    return "<h2>Limitações desta varredura</h2><ul>" + "".join(f"<li>{e(n)}</li>" for n in r["notes"]) + "</ul>"


def _page(title, sections, printable):
    return ("<!doctype html><html lang=pt-BR><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{e(title)}</title><style>{CSS}</style><body>"
            + (TOOLBAR if printable else "")
            + "\n".join(s for s in sections if s) + "</body></html>")


def render(r, printable=False):
    data = r.get("data", {})
    sections = [
        _header(r), _categories(r), _suggestions(r), _findings_tree(r), _groups_summary(r), _vulns(data),
        _actions_log(r), "<h2>Dados coletados</h2>", _network_data(data), _phone_data(data), _traces_data(data),
        _apps(r), _notes(r),
        "<p class=muted>Gerado pelo Desgrampa. A ausência de achados não prova que o aparelho esteja limpo; "
        "para suspeita de spyware mercenário, procure análise forense especializada.</p>",
    ]
    return _page("Relatório Desgrampa", sections, printable)


# ---------------------------------------------------------------- versão para atendimento / autoridade

def _kv(rows):
    return "<dl class=kv>" + "".join(f"<dt>{e(k)}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


def _ios_method(r):
    opts = r.get("options", {})
    return ("<p>Foi analisado um backup local do iPhone "
            + ("feito pelo cabo nesta verificação" if opts.get("backup") == "pelo cabo" else "informado pela pessoa atendida")
            + (", criptografado" if opts.get("encrypted") else ", sem criptografia")
            + ", com o Mobile Verification Toolkit (MVT) da Anistia Internacional e "
            f"{r['iocs']['total']} indicadores públicos de spyware. Nenhum dado do aparelho foi alterado.</p>")


def render_authority(r, evidence, legal):
    """Relatório factual para delegacia, Defensoria ou serviço de apoio: identificação, método, achados
    relevantes, integridade (hashes), cadeia de custódia e base legal. `evidence` vem de evidence.integrity()."""
    d, s = r["device"], r["stats"]
    relevant = [f for f in r["findings"] if f["severity"] in ("critica", "alta", "media")]
    categories = {f["category"] for f in relevant}
    laws = [law for law in legal.get("leis", []) if not law["quando"] or categories & set(law["quando"])]
    sections = [
        "<h1>Relatório técnico de verificação de dispositivo móvel</h1>",
        "<p class=muted>Documento gerado automaticamente pelo Desgrampa a partir de uma verificação somente leitura "
        "do aparelho. Descreve fatos observados; não é laudo pericial oficial.</p>",
        "<h2>1. Identificação</h2>",
        _kv([("Aparelho", e(f"{d.get('manufacturer') or ''} {d.get('model') or ''}".strip())),
             ("Número de série (adb)", e(d.get("serial"))),
             ("Sistema", e(f"{system_label(d)} · build {d.get('build') or '?'}")),
             ("Impressão digital do sistema", f"<code>{e(d.get('fingerprint'))}</code>"),
             ("Início da verificação", e(r["started"])),
             ("Duração", f"{r['duration_s']} s"),
             ("Ferramenta", e(f"Desgrampa {evidence.get('version', '')} · modo {r['mode']}")),
             ("Responsável pela coleta", "______________________________________________"),
             ("Local", "______________________________________________")]),
        "<h2>2. Método</h2>",
        _ios_method(r) if d.get("platform") == "ios" else
        f"<p>O aparelho foi conectado a um computador por depuração USB (ADB), autorizada na tela do próprio aparelho. "
        f"Foram executados {s['commands']} comandos exclusivamente de consulta (nenhum comando de alteração é usado na "
        f"varredura). Foram comparados {s['packages']} aplicativos e os dados coletados com "
        f"{r['iocs']['total']} indicadores públicos de spyware e stalkerware (AssoEchap e mvt-indicators, "
        f"atualizados em {e(r['iocs']['updated'])})"
        + (" e o relatório do sistema (bugreport) foi analisado pelo Mobile Verification Toolkit (MVT) da Anistia "
           "Internacional" if r.get("data", {}).get("mvt") else "")
        + f". {s['categories_verified']} de {s['categories_total']} áreas puderam ser verificadas.</p>",
        f"<div class='verdict {e(r['verdict']['code'])}'><strong>Resultado: {e(r['verdict']['label'])}</strong><br>"
        f"{e(r['verdict']['text'])}</div>",
        "<h2>3. Fatos relevantes observados</h2>",
        "".join(finding_html(f) for f in relevant) if relevant else
        "<p>Nenhum achado de gravidade média ou superior. A ausência de achados não prova que o aparelho esteja "
        "livre de monitoramento.</p>",
        _actions_log(r) or "<p class=muted>Nenhuma alteração foi feita no aparelho pelo Desgrampa.</p>",
        "<h2>4. Integridade dos arquivos</h2>",
        "<p>A pasta de evidências contém a saída bruta de cada comando, este relatório em JSON e HTML e, na "
        "varredura completa, o bugreport e os resultados do MVT. O arquivo SHA256SUMS.txt lista o hash SHA-256 "
        "de cada arquivo; qualquer alteração posterior muda o hash.</p>",
        _kv([("Pasta de evidências", f"<code>{e(r.get('evidence_dir'))}</code>"),
             ("SHA-256 do relatorio.json", f"<code>{e(evidence.get('report_sha256'))}</code>"),
             ("SHA-256 do SHA256SUMS.txt", f"<code>{e(evidence.get('sums_sha256'))}</code>"),
             ("Arquivos na pasta", str(evidence.get("files", 0)))]),
        "<h2>5. Cadeia de custódia (CPP, arts. 158-A a 158-F)</h2>",
        "<p class=muted>Preencha a cada transferência da pasta de evidências ou do aparelho.</p>",
        table(["Data e hora", "Entregue por", "Recebido por", "Meio (pendrive, e-mail, aparelho)", "Hash conferido?"],
              [("", "", "", "", "") for _ in range(4)]).replace("<td></td>", "<td>&nbsp;</td>"),
        "<h2>6. Referências legais</h2>",
        "".join(f"<div class=box><b>{e(law['titulo'])}</b> — {e(law['norma'])}<blockquote>{e(law['texto'])}</blockquote>"
                f"<span class=muted>{e(law['explicacao'])}</span></div>" for law in laws),
        f"<p class=muted>{e(legal.get('aviso', ''))}</p>",
        "<div class=sig><div>Pessoa atendida</div><div>Responsável pelo atendimento</div></div>",
    ]
    return _page("Relatório para atendimento — Desgrampa", sections, printable=True)
