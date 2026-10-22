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

from .. import oscompat
from ..context import is_public_ip
from . import Finding

NAME = "Rede local (teste pelo computador)"
CATEGORY = "pcnet"

TIMEOUT = 8
TLS_SITES = ["www.google.com", "www.whatsapp.com", "signal.org", "www.gov.br", "www.wikipedia.org",
             "accounts.google.com", "www.icloud.com", "web.telegram.org"]
DNS_SITES = ["www.google.com", "www.whatsapp.com", "signal.org", "www.gov.br", "www.facebook.com",
             "web.telegram.org"]
PROXY_HEADERS = ("via", "x-forwarded-for", "x-bluecoat-via", "x-squid-error", "proxy-connection")
INTERCEPTORS = re.compile(
    r"\b(?:fortinet|fortigate|palo ?alto|zscaler|netskope|blue ?coat|symantec web|cisco|umbrella|sophos|"
    r"kaspersky|eset|avast|avg|bitdefender|norton|mcafee|trend ?micro|forcepoint|untangle|"
    r"mitmproxy|portswigger|burp|charles|fiddler|http ?toolkit|do_not_trust|superfish|websense|"
    r"barracuda|checkpoint|check point|sonicwall|watchguard|lightspeed|securly|smoothwall)\b", re.I)


def available(ctx):
    if not ctx.options.get("pc_network"):
        return "desativado (marque “Testar a rede local” se o celular está no mesmo Wi-Fi deste computador)"
    return None


# ---------------------------------------------------------------- consultas

def _run(*cmd):
    try:
        return oscompat.run(cmd, capture_output=True, text=True, errors="replace", timeout=TIMEOUT).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _system_resolve(name):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except socket.gaierror:
        return []


def _doh(name):
    """Resolve via DNS-over-HTTPS (Cloudflare): canal criptografado que a rede não consegue adulterar."""
    req = urllib.request.Request(f"https://cloudflare-dns.com/dns-query?name={name}&type=A",
                                 headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return sorted({a["data"] for a in json.load(resp).get("Answer", []) if a.get("type") == 1})


def _tls_issuer(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock, \
            ctx.wrap_socket(sock, server_hostname=host) as tls:
        cert = tls.getpeercert()
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    return issuer.get("organizationName") or issuer.get("commonName") or "?"


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "desgrampa", "Cache-Control": "no-cache"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read(20000)


def parse_ip_neigh(out):
    """`ip neigh` -> {ip: mac}"""
    return {m.group(1): m.group(2).lower()
            for m in re.finditer(r"^(\S+) dev \S+ lladdr ([0-9a-fA-F:]{17})", out, re.M)}


def _normalize_mac(mac):
    """'a:b:c:d:e:f' (macOS) ou 'aa-bb-cc-dd-ee-ff' (Windows) -> 'aa:bb:cc:dd:ee:ff'"""
    return ":".join(part.zfill(2) for part in re.split("[:-]", mac.lower()))


def parse_arp_a(out):
    """`arp -a` do Windows ou `arp -an` do macOS -> {ip: mac} (ignora entradas incompletas e broadcast)"""
    table = {}
    for m in re.finditer(r"\(?(\d{1,3}(?:\.\d{1,3}){3})\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b", out):
        mac = _normalize_mac(m.group(2))
        if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") and not mac.startswith("01:00:5e"):
            table[m.group(1)] = mac
    return table


def parse_route_print(out):
    """`route print -4 0.0.0.0` (Windows) -> (gateway, ip da interface) da rota padrão de menor métrica"""
    routes = re.findall(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d[\d.]+)\s+(\d[\d.]+)\s+(\d+)", out, re.M)
    if not routes:
        return None, None
    gateway, iface, _ = min(routes, key=lambda r: int(r[2]))
    return gateway, iface


def parse_route_get(out):
    """`route -n get default` (macOS) -> (gateway, interface)"""
    gw = re.search(r"gateway:\s*(\S+)", out)
    iface = re.search(r"interface:\s*(\S+)", out)
    return (gw.group(1) if gw else None), (iface.group(1) if iface else None)


def _network_config():
    """(gateway, interface, servidores DNS, vizinhos {ip: mac}) do computador, conforme o sistema."""
    if oscompat.IS_WINDOWS:
        gateway, iface = parse_route_print(_run("route", "print", "-4", "0.0.0.0"))
        dns = _run("powershell", "-NoProfile", "-Command",
                   "(Get-DnsClientServerAddress -AddressFamily IPv4).ServerAddresses").split()
        return gateway, iface, sorted(set(dns), key=dns.index), parse_arp_a(_run("arp", "-a"))
    if oscompat.IS_MAC:
        gateway, iface = parse_route_get(_run("route", "-n", "get", "default"))
        dns = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", _run("scutil", "--dns"))
        return gateway, iface, sorted(set(dns), key=dns.index), parse_arp_a(_run("arp", "-an"))
    gw = re.search(r"default via (\S+) dev (\S+)", _run("ip", "route", "show", "default"))
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as f:
            dns = re.findall(r"^nameserver\s+(\S+)", f.read(), re.M)
    except OSError:
        dns = []
    return (gw.group(1) if gw else None), (gw.group(2) if gw else None), dns, parse_ip_neigh(_run("ip", "neigh"))


# ---------------------------------------------------------------- testes

def _check_gateway(data, findings):
    """Gateway, DNS do computador e ARP spoofing (MAC do roteador respondendo por outro IP)."""
    gateway, data["interface"], data["dns_servers"], neighbors = _network_config()
    data["gateway"] = gateway
    if gateway not in neighbors:
        return
    mac = data["gateway_mac"] = neighbors[gateway]
    dupes = [ip for ip, m in neighbors.items() if m == mac and ip != gateway and ":" not in ip]
    if dupes:
        findings.append(Finding(
            "alta", "Possível ARP spoofing na rede",
            f"O endereço físico (MAC {mac}) do roteador {gateway} também responde por {', '.join(dupes)}. "
            "Um equipamento pode estar se passando pelo roteador para interceptar o tráfego de todos na rede.",
            "Reinicie o roteador e verifique os aparelhos conectados no painel dele. Se persistir, "
            "não use esta rede para assuntos sensíveis."))


def _check_dns(ctx, data, findings):
    """DNS da rede comparado com DNS-over-HTTPS, mais um domínio inexistente (sequestro de NXDOMAIN)."""
    rows, reference_failed = [], False
    for name in DNS_SITES:
        local = _system_resolve(name)
        try:
            reference = _doh(name)
        except Exception:
            reference, reference_failed = None, True
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
        elif reference is not None and local and not set(local) & set(reference):
            status = "diferente"   # comum com CDNs; só informativo
        rows.append({"domain": name, "system": local, "doh": reference, "status": status})

    junk = f"desgrampa-{secrets.token_hex(8)}.com"
    junk_ips = _system_resolve(junk)
    rows.append({"domain": f"{junk} (não existe)", "system": junk_ips, "doh": None,
                 "status": "sequestro de NXDOMAIN" if junk_ips else "ok"})
    if junk_ips:
        findings.append(Finding(
            "media", "DNS da rede responde a domínios inexistentes",
            f"{junk} (inexistente) foi resolvido para {', '.join(junk_ips)}: a rede manipula respostas DNS.",
            "Use DNS criptografado (DNS privado no celular, DoH no computador)."))
    if reference_failed:
        ctx.notes.append("Não foi possível consultar o DNS de referência (DoH) — comparação de DNS parcial")
    data["dns"] = rows


def _check_tls(data, findings):
    """Se a rede intercepta HTTPS, o certificado é recusado ou emitido por um produto de inspeção."""
    rows = []
    for host in TLS_SITES:
        try:
            issuer = _tls_issuer(host)
        except ssl.SSLCertVerificationError as e:
            reason = getattr(e, "verify_message", str(e))
            rows.append({"host": host, "issuer": reason, "status": "certificado falso"})
            findings.append(Finding(
                "critica", "Interceptação de HTTPS detectada",
                f"A conexão com {host} apresentou um certificado inválido ({reason}). Isso é o sinal "
                "clássico de um ataque “man-in-the-middle” na rede.",
                "Desconecte desta rede imediatamente e não digite senhas nela."))
            continue
        except (OSError, ssl.SSLError) as e:
            rows.append({"host": host, "issuer": str(e)[:80], "status": "falhou"})
            continue
        inspected = bool(INTERCEPTORS.search(issuer))
        rows.append({"host": host, "issuer": issuer, "status": "inspecionado" if inspected else "ok"})
        if inspected:
            findings.append(Finding(
                "alta", "HTTPS inspecionado na rede",
                f"O certificado de {host} foi emitido por “{issuer}”, um produto de inspeção de tráfego — não "
                "pela autoridade real do site. Suas conexões nesta rede (ou neste computador) estão sendo "
                "abertas e lidas.",
                "Normal apenas em rede corporativa com aviso. Em casa, investigue o roteador e o "
                "antivírus deste computador."))
    data["tls"] = rows


def _check_transparent_proxy(data, findings):
    """A mesma página por HTTP (alterável na rede) e por HTTPS (verificado) deve ser idêntica, e o
    endpoint generate_204 do Google deve responder 204 sem corpo."""
    http = {}
    try:
        _, headers, plain = _fetch("http://example.com/")
        _, _, secure = _fetch("https://example.com/")
        http["proxy_headers"] = {k: headers[k] for k in PROXY_HEADERS if k in headers}
        http["content_ok"] = b"".join(plain.split()) == b"".join(secure.split())
    except Exception as e:
        http["error"] = str(e)[:80]
    try:
        status, _, body = _fetch("http://connectivitycheck.gstatic.com/generate_204")
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


def _public_ip():
    try:
        with urllib.request.urlopen("https://www.cloudflare.com/cdn-cgi/trace", timeout=TIMEOUT) as resp:
            trace = dict(line.split("=", 1) for line in resp.read().decode().splitlines() if "=" in line)
    except Exception:
        return None
    return {"ip": trace.get("ip"), "country": trace.get("loc"), "warp": trace.get("warp")}


def run(ctx):
    ctx.progress("Testando a rede local a partir do computador")
    findings, data = [], {}
    _check_gateway(data, findings)
    _check_dns(ctx, data, findings)
    _check_tls(data, findings)
    _check_transparent_proxy(data, findings)
    data["public_ip"] = _public_ip()
    ctx.data["pcnet"] = data
    return findings
