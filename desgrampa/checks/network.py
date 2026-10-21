"""Desvio de tráfego configurado no aparelho: proxy (global e por Wi-Fi), VPN, DNS privado, ADB remoto."""

import re

from . import Finding, app_label

NAME = "Proxy, VPN e DNS privado"
CATEGORY = "intercept"


def _host(value):
    return re.split(r"[:/\s]", value.strip().strip("[]"), maxsplit=1)[0]


def parse_link_properties(out):
    """Redes ativas em `dumpsys connectivity` -> [{iface, dns, gateways, proxy, private_dns}]"""
    links = []
    for m in re.finditer(r"LinkProperties:?\s*\{([^{}]*)\}", out):
        lp = m.group(1)
        iface = re.search(r"InterfaceName: (\S+)", lp)
        dns = re.search(r"DnsAddresses: \[([^\]]*)\]", lp)
        routes = re.search(r"Routes: \[([^\]]*)\]", lp)
        proxy = re.search(r"HttpProxy: \[?([^\]\s]+)\]? (\d+)", lp)
        pdns = re.search(r"PrivateDnsServerName: (\S+)", lp)
        link = {
            "iface": iface.group(1) if iface else None,
            "dns": [a.strip().lstrip("/") for a in dns.group(1).split(",") if a.strip()] if dns else [],
            "gateways": sorted(set(re.findall(r"(?:0\.0\.0\.0/0|::/0) -> ([\w.:]+)", routes.group(1)))) if routes else [],
            "proxy": f"{proxy.group(1)}:{proxy.group(2)}" if proxy else None,
            "private_dns": pdns.group(1) if pdns and pdns.group(1) != "null" else None,
        }
        if link["iface"] and link not in links:
            links.append(link)
    return links


def parse_wifi_proxies(out):
    """Redes Wi-Fi salvas com proxy em `dumpsys wifi` -> [(ssid, proxy)]"""
    result = []
    for block in re.split(r"\n(?=\s*(?:ID: \d+|WifiConfiguration))", out):
        ps = re.search(r"(?:proxySettings|Proxy settings)[:=]\s*(STATIC|PAC)", block, re.I)
        if not ps:
            continue
        ssid = re.search(r"SSID: \"?([^\"\n]+)\"?", block)
        host = re.search(r"HTTP proxy: \[([^\]]+)\] (\d+)", block)
        pac = re.search(r"PAC Script: \[?(\S+?)\]?\s", block)
        proxy = f"{host.group(1)}:{host.group(2)}" if host else pac.group(1) if pac else ps.group(1)
        result.append((ssid.group(1) if ssid else "?", proxy))
    return sorted(set(result))


def run(ctx):
    findings = []

    def proxy_finding(title, where, proxy):
        family = ctx.iocs.match_domain(_host(proxy)) or ctx.iocs.match_ip(_host(proxy))
        findings.append(Finding(
            "critica" if family else "alta", title,
            f"O tráfego web {where} passa pelo proxy {proxy}"
            + (f", que pertence a {family}." if family else
               ". Um proxy pode registrar e, com um certificado instalado, até ler sua navegação."),
            "Se você não configurou, remova: Configurações > Wi-Fi > (rede) > Opções avançadas > "
            "Proxy = Nenhum. Depois esqueça a rede e conecte de novo."))

    proxy = ctx.setting("global", "http_proxy") or ctx.setting("global", "global_http_proxy_host")
    if proxy and proxy not in (":0", "0"):
        proxy_finding("Proxy HTTP global configurado", "de todo o aparelho", proxy)

    wifi_dump = ctx.cached_sh("dumpsys wifi", timeout=90)
    for ssid, wproxy in parse_wifi_proxies(wifi_dump):
        proxy_finding("Proxy configurado em rede Wi-Fi", f"na rede “{ssid}”", wproxy)

    conn = ctx.cached_sh("dumpsys connectivity", timeout=90)
    links = parse_link_properties(conn)
    ctx.data["links"] = links
    for link in links:
        if link["proxy"]:
            proxy_finding("Proxy ativo na conexão atual", f"da interface {link['iface']}", link["proxy"])

    vpn_app = ctx.setting("secure", "always_on_vpn_app")
    vpn_active = bool(re.search(r"NetworkAgentInfo.{0,80}\bVPN\b", conn)) or \
        any((link["iface"] or "").startswith(("tun", "ppp", "ipsec", "wg")) for link in links)
    ctx.data["vpn"] = {"always_on": vpn_app, "active": vpn_active}
    if vpn_app:
        findings.append(Finding(
            "media", "VPN sempre ativa configurada",
            f"{app_label(ctx, vpn_app)} está configurado como VPN sempre ativa: todo o tráfego "
            "passa por ele.",
            "Normal se é a sua VPN. Caso contrário, desative em Configurações > Rede > VPN.",
            package=vpn_app))
    elif vpn_active:
        findings.append(Finding(
            "baixa", "Uma VPN está conectada",
            "Há uma conexão VPN ativa no momento. Todo o tráfego passa pelo app da VPN.",
            "Confirme em Configurações > Rede > VPN se é uma VPN que você usa."))

    dns_mode = ctx.setting("global", "private_dns_mode")
    dns_host = ctx.setting("global", "private_dns_specifier")
    ctx.data["private_dns"] = {"mode": dns_mode, "host": dns_host}
    if dns_mode == "hostname" and dns_host:
        family = ctx.iocs.match_domain(dns_host)
        findings.append(Finding(
            "critica" if family else "baixa", "DNS privado personalizado",
            f"O DNS privado está configurado para {dns_host}"
            + (f", domínio ligado a {family}." if family else
               ". Quem controla o DNS vê quais sites e serviços o aparelho acessa."),
            "Se não reconhece o servidor, mude para Automático em Configurações > Rede > DNS privado."))
    elif dns_mode == "off":
        findings.append(Finding(
            "info", "DNS privado desligado",
            "As consultas DNS saem sem criptografia e podem ser vistas/alteradas pela rede.",
            "Recomendado: Configurações > Rede > DNS privado > dns.google ou one.one.one.one."))

    if ctx.setting("global", "adb_wifi_enabled") == "1":
        findings.append(Finding(
            "alta", "Depuração ADB por Wi-Fi ligada",
            "A depuração sem fio está ativa: um computador na mesma rede, já pareado, pode "
            "controlar o aparelho remotamente.",
            "Desative em Opções do desenvolvedor > Depuração por Wi-Fi e revogue as "
            "autorizações de depuração.", category="controle"))
    tcp_port = ctx.props.get("service.adb.tcp.port") or ctx.props.get("persist.adb.tcp.port")
    if tcp_port and tcp_port not in ("-1", "0"):
        findings.append(Finding(
            "alta", "ADB escutando em porta de rede",
            f"O ADB está aceitando conexões de rede na porta {tcp_port}.",
            "Reinicie o aparelho e revogue as autorizações de depuração USB.", category="controle"))
    return findings
