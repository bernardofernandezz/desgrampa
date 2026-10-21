"""Teste da rede local feito pelo computador (útil quando o celular usa a mesma rede Wi-Fi).

Procura: DNS adulterado, HTTPS interceptado (certificado falso), proxy transparente e ARP spoofing.
Nada aqui usa o celular.
"""

import json
import re
import secrets
import socket
import ssl
import subprocess
import urllib.error
import urllib.request

from ..context import is_public_ip
from . import Finding

NAME = "Rede local (teste pelo computador)"
CATEGORY = "pcnet"

TLS_SITES = ["www.google.com", "www.whatsapp.com", "signal.org", "www.gov.br", "www.wikipedia.org",
             "accounts.google.com", "www.icloud.com", "web.telegram.org"]
DNS_SITES = ["www.google.com", "www.whatsapp.com", "signal.org", "www.gov.br", "www.facebook.com",
             "web.telegram.org"]
INTERCEPTORS = re.compile(
    r"\b(?:fortinet|fortigate|palo ?alto|zscaler|netskope|blue ?coat|symantec web|cisco|umbrella|sophos|"
    r"kaspersky|eset|avast|avg|bitdefender|norton|mcafee|trend ?micro|forcepoint|untangle|"
    r"mitmproxy|portswigger|burp|charles|fiddler|http ?toolkit|do_not_trust|superfish|websense|"
    r"barracuda|checkpoint|check point|sonicwall|watchguard|lightspeed|securly|smoothwall)\b", re.I)


def available(ctx):
    if not ctx.options.get("pc_network"):
        return "desativado (marque “Testar a rede local” se o celular está no mesmo Wi-Fi deste computador)"
    return None


def _system_resolve(name):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except socket.gaierror:
        return []


def _doh(name):
    req = urllib.request.Request(f"https://cloudflare-dns.com/dns-query?name={name}&type=A",
                                 headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        return sorted({a["data"] for a in json.load(resp).get("Answer", []) if a.get("type") == 1})


def _tls(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=8) as sock, \
            ctx.wrap_socket(sock, server_hostname=host) as tls:
        cert = tls.getpeercert()
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    return issuer.get("organizationName") or issuer.get("commonName") or "?"


def parse_ip_neigh(out):
    """`ip neigh` -> {ip: mac}"""
    return {m.group(1): m.group(2).lower()
            for m in re.finditer(r"^(\S+) dev \S+ lladdr ([0-9a-fA-F:]{17})", out, re.M)}


def run(ctx):
    findings = []
    data = {}

    ctx.progress("Testando a rede local a partir do computador")
    route = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout
    gw = re.search(r"default via (\S+) dev (\S+)", route)
    data["gateway"] = gw.group(1) if gw else None
    data["interface"] = gw.group(2) if gw else None
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            data["dns_servers"] = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
    except OSError:
        data["dns_servers"] = []

    # ARP spoofing: o MAC do gateway aparece também para outro IP da rede
    neigh = parse_ip_neigh(subprocess.run(["ip", "neigh"], capture_output=True, text=True).stdout)
    if gw and gw.group(1) in neigh:
        mac = neigh[gw.group(1)]
        data["gateway_mac"] = mac
        dupes = [ip for ip, m in neigh.items() if m == mac and ip != gw.group(1) and ":" not in ip]
        if dupes:
            findings.append(Finding(
                "alta", "Possível ARP spoofing na rede",
                f"O endereço físico (MAC {mac}) do roteador {gw.group(1)} também responde por "
                f"{', '.join(dupes)}. Um equipamento pode estar se passando pelo roteador para "
                "interceptar o tráfego de todos na rede.",
                "Reinicie o roteador e verifique os aparelhos conectados no painel dele. Se persistir, "
                "não use esta rede para assuntos sensíveis."))

    # DNS: resolvedor do sistema x DNS-over-HTTPS (canal criptografado, não adulterável pela rede)
    dns = []
    doh_ok = True
    for name in DNS_SITES:
        local = _system_resolve(name)
        try:
            ref = _doh(name)
        except Exception:
            ref, doh_ok = None, False
        status = "ok"
        if any(not is_public_ip(ip) for ip in local):
            status = "adulterado"
            findings.append(Finding(
                "alta", "DNS da rede adulterado",
                f"A rede resolveu {name} para {', '.join(local)} (endereço privado). O roteador/DNS "
                "está redirecionando esse site.",
                "Verifique o DNS configurado no roteador e troque a senha de administrador dele."))
        elif any(ctx.iocs.match_ip(ip) for ip in local):
            status = "malicioso"
            findings.append(Finding(
                "critica", "DNS da rede aponta para servidor de spyware",
                f"{name} resolve para {', '.join(local)}, ligado a indicadores de spyware.",
                "Desconecte desta rede."))
        elif ref is not None and local and not set(local) & set(ref):
            status = "diferente"
        dns.append({"domain": name, "system": local, "doh": ref, "status": status})
    junk = f"desgrampa-{secrets.token_hex(8)}.com"
    junk_ip = _system_resolve(junk)
    dns.append({"domain": junk + " (não existe)", "system": junk_ip, "doh": None,
                "status": "sequestro de NXDOMAIN" if junk_ip else "ok"})
    if junk_ip:
        findings.append(Finding(
            "media", "DNS da rede responde a domínios inexistentes",
            f"{junk} (inexistente) foi resolvido para {', '.join(junk_ip)}: a rede manipula respostas DNS.",
            "Use DNS criptografado (DNS privado no celular, DoH no computador)."))
    if not doh_ok:
        ctx.notes.append("Não foi possível consultar o DNS de referência (DoH) — comparação de DNS parcial")
    data["dns"] = dns

    # HTTPS: se a rede intercepta, o certificado é recusado ou emitido por um produto de inspeção
    tls = []
    for host in TLS_SITES:
        row = {"host": host}
        try:
            row["issuer"] = _tls(host)
            row["status"] = "ok"
            if INTERCEPTORS.search(row["issuer"]):
                row["status"] = "inspecionado"
                findings.append(Finding(
                    "alta", "HTTPS inspecionado na rede",
                    f"O certificado de {host} foi emitido por “{row['issuer']}”, um produto de "
                    "inspeção de tráfego — não pela autoridade real do site. Suas conexões nesta rede "
                    "(ou neste computador) estão sendo abertas e lidas.",
                    "Normal apenas em rede corporativa com aviso. Em casa, investigue o roteador e o "
                    "antivírus deste computador."))
        except ssl.SSLCertVerificationError as e:
            row["status"] = "certificado falso"
            row["issuer"] = getattr(e, "verify_message", str(e))
            findings.append(Finding(
                "critica", "Interceptação de HTTPS detectada",
                f"A conexão com {host} apresentou um certificado inválido ({row['issuer']}). Isso é o "
                "sinal clássico de um ataque “man-in-the-middle” na rede.",
                "Desconecte desta rede imediatamente e não digite senhas nela."))
        except (OSError, ssl.SSLError) as e:
            row["status"] = "falhou"
            row["issuer"] = str(e)[:80]
        tls.append(row)
    data["tls"] = tls

    # Proxy transparente: a mesma página por HTTP (alterável na rede) e por HTTPS (verificado) devem
    # ser idênticas; e o endpoint generate_204 deve responder 204 sem corpo.
    def fetch(url):
        req = urllib.request.Request(url, headers={"User-Agent": "desgrampa", "Cache-Control": "no-cache"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(20000)

    http = {}
    try:
        _, headers, plain = fetch("http://example.com/")
        _, _, secure = fetch("https://example.com/")
        via = {k: headers[k] for k in ("via", "x-forwarded-for", "x-bluecoat-via", "x-squid-error",
                                       "proxy-connection") if k in headers}
        http = {"proxy_headers": via, "content_ok": b"".join(plain.split()) == b"".join(secure.split())}
    except Exception as e:
        http = {"error": str(e)[:80]}
    try:
        status, _, body = fetch("http://connectivitycheck.gstatic.com/generate_204")
        http["generate_204"] = status == 204 and not body
    except urllib.error.HTTPError as e:
        http["generate_204"] = e.code == 204
    except Exception:
        http["generate_204"] = None
    data["http"] = http
    problems = []
    if http.get("proxy_headers"):
        problems.append("cabeçalhos de proxy (" + ", ".join(f"{k}: {v}" for k, v in http["proxy_headers"].items()) + ")")
    if http.get("content_ok") is False:
        problems.append("a versão HTTP de uma página veio diferente da versão HTTPS (conteúdo alterado no caminho)")
    if http.get("generate_204") is False:
        problems.append("o teste de conectividade do Google foi respondido por outro servidor")
    if problems:
        findings.append(Finding(
            "media", "Proxy transparente ou conteúdo alterado",
            "Tráfego HTTP de teste: " + "; ".join(problems) + ". A rede, a operadora ou um portal "
            "cativo está passando o tráfego por um intermediário.",
            "Use sempre HTTPS/VPN confiável nesta rede e verifique o roteador."))

    try:
        with urllib.request.urlopen("https://www.cloudflare.com/cdn-cgi/trace", timeout=8) as resp:
            trace = dict(line.split("=", 1) for line in resp.read().decode().splitlines() if "=" in line)
        data["public_ip"] = {"ip": trace.get("ip"), "country": trace.get("loc"), "warp": trace.get("warp")}
    except Exception:
        data["public_ip"] = None

    ctx.data["pcnet"] = data
    return findings
