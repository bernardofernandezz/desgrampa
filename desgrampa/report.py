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
"""


# ---------------------------------------------------------------- helpers

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
        f"<div class=muted>{e(d.get('manufacturer'))} {e(d.get('model'))} · Android {e(d.get('android'))} · "
        f"patch {e(d.get('security_patch'))} · serial {e(d.get('serial'))} · {e(r['started'])} · varredura "
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


def _notes(r):
    if not r["notes"]:
        return ""
    return "<h2>Limitações desta varredura</h2><ul>" + "".join(f"<li>{e(n)}</li>" for n in r["notes"]) + "</ul>"


def render(r):
    data = r.get("data", {})
    sections = [
        _header(r), _categories(r), _suggestions(r), _findings_tree(r), _groups_summary(r), _actions_log(r),
        "<h2>Dados coletados</h2>", _network_data(data), _phone_data(data), _traces_data(data),
        _apps(r), _notes(r),
    ]
    return ("<!doctype html><html lang=pt-BR><meta charset=utf-8>"
            "<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Relatório Desgrampa</title><style>{CSS}</style><body>"
            + "\n".join(s for s in sections if s)
            + "<p class=muted>Gerado pelo Desgrampa. A ausência de achados não prova que o aparelho esteja limpo; "
              "para suspeita de spyware mercenário, procure análise forense especializada.</p></body></html>")
