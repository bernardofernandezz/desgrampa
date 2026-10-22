"""Rede vista pelo aparelho: servidores DNS, resolução DNS adulterada, conexões ativas,
Wi-Fi inseguro e apps enviando dados em segundo plano."""

import ipaddress
import json
import re
import secrets
import urllib.request

from ..context import is_public_ip
from . import Finding, app_label, ioc_category

NAME = "Conexões e DNS do aparelho"
CATEGORY = "rede"

TEST_DOMAINS = ["www.google.com", "www.whatsapp.com", "signal.org", "www.gov.br",
                "www.wikipedia.org", "accounts.google.com"]
KNOWN_RESOLVERS = {
    "8.8.8.8": "Google", "8.8.4.4": "Google", "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
    "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
}
MOBILE_IFACES = ("rmnet", "ccmni", "seth", "v4-rmnet", "pdp", "rmnet_data")
BG_UPLOAD_ALERT = 100 * 1024 * 1024   # 100 MB enviados em segundo plano


def doh_resolve(name):
    """Resolve via DNS-over-HTTPS (Cloudflare) a partir do computador, como referência confiável."""
    req = urllib.request.Request(f"https://cloudflare-dns.com/dns-query?name={name}&type=A",
                                 headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.load(resp)
    return {a["data"] for a in data.get("Answer", []) if a.get("type") == 1}


def phone_resolve(ctx, name):
    out = ctx.try_sh(f"ping -c 1 -W 1 {name} 2>&1", timeout=15)
    m = re.search(r"PING [^(]+\(([\d.]+)\)", out)
    return m.group(1) if m else None


def parse_proc_net(out):
    """/proc/net/tcp[6] -> [(remote_ip, remote_port, uid, state)] só de conexões estabelecidas."""
    conns = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 8 or ":" not in parts[2] or parts[0] == "sl":
            continue
        rem_hex, port_hex = parts[2].split(":")
        state, uid = parts[3], parts[7]
        if state != "01":   # ESTABLISHED
            continue
        try:
            raw = bytes.fromhex(rem_hex)
            if len(raw) == 4:
                ip = str(ipaddress.IPv4Address(raw[::-1]))
            else:
                words = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
                addr = ipaddress.IPv6Address(words)
                ip = str(addr.ipv4_mapped or addr)
            conns.append((ip, int(port_hex, 16), int(uid), state))
        except ValueError:
            continue
    return conns


def parse_netstats(out):
    """`dumpsys netstats detail` -> {uid: {"bg_tx", "fg_tx", "bg_rx", "fg_rx"}} (seção UID stats)."""
    usage = {}
    idx = out.find("UID stats:")
    if idx < 0:
        return usage
    section = out[idx:]
    end = section.find("UID tag stats:")
    if end > 0:
        section = section[:end]
    cur = None
    for line in section.splitlines():
        m = re.search(r"\buid=(-?\d+) set=(\w+) tag=(0x[0-9a-f]+)", line)
        if m:
            cur = None
            if m.group(3) == "0x0":
                bucket = "fg" if m.group(2) in ("FOREGROUND", "1") else "bg"
                cur = (int(m.group(1)), bucket)
            continue
        if cur:
            for rb, tb in re.findall(r"\brb=(\d+).*?\btb=(\d+)", line):
                entry = usage.setdefault(cur[0], {"bg_tx": 0, "fg_tx": 0, "bg_rx": 0, "fg_rx": 0})
                entry[f"{cur[1]}_tx"] += int(tb)
                entry[f"{cur[1]}_rx"] += int(rb)
    return usage


def _mb(n):
    return f"{n / 1024 / 1024:.0f} MB"


def _check_dns_servers(ctx, data, findings):
    """Servidores DNS configurados nas conexões ativas."""
    dns_rows = []
    for link in ctx.data.get("links", []):
        mobile = (link["iface"] or "").startswith(MOBILE_IFACES)
        for ip in link["dns"]:
            kind = "rede local" if not is_public_ip(ip) else KNOWN_RESOLVERS.get(ip) or (
                "operadora" if mobile else "desconhecido")
            dns_rows.append({"iface": link["iface"], "ip": ip, "kind": kind})
            match = ctx.iocs.match_ip(ip)
            if match:
                findings.append(Finding(
                    "critica", "Servidor DNS malicioso",
                    f"A interface {link['iface']} usa o DNS {ip}, ligado a {match}.",
                    "Desconecte desta rede e restaure as configurações de rede do aparelho.",
                    category="intercept"))
            elif kind == "desconhecido":
                findings.append(Finding(
                    "baixa", "Servidor DNS público desconhecido",
                    f"A conexão {link['iface']} usa o DNS {ip}, que não é do roteador local nem de um "
                    "provedor conhecido. Quem controla o DNS pode ver e redirecionar acessos.",
                    "Confira as configurações de DNS do roteador e ative o DNS privado no celular."))
    data["dns_servers"] = dns_rows


def _check_dns_resolution(ctx, data, findings):
    """Resolve domínios conhecidos pelo celular e compara com DNS-over-HTTPS."""
    ctx.progress("Testando DNS a partir do celular")
    tests = []
    for name in TEST_DOMAINS:
        ip = phone_resolve(ctx, name)
        try:
            ref = doh_resolve(name)
        except Exception:
            ref = None
        row = {"domain": name, "phone": ip, "reference": sorted(ref) if ref else None, "status": "ok"}
        if ip and not is_public_ip(ip):
            row["status"] = "adulterado"
            findings.append(Finding(
                "alta", "DNS adulterado no celular",
                f"O celular resolveu {name} para {ip}, um endereço privado/reservado. A rede ou o "
                "aparelho está redirecionando esse site.",
                "Troque de rede (ex.: dados móveis), ative o DNS privado e verifique o roteador.",
                category="intercept"))
        elif ip and ctx.iocs.match_ip(ip):
            row["status"] = "malicioso"
            findings.append(Finding(
                "critica", "DNS redirecionando para servidor malicioso",
                f"{name} foi resolvido para {ip}, ligado a {ctx.iocs.match_ip(ip)}.",
                "Desconecte desta rede imediatamente.", category="intercept"))
        elif ip and ref and ip not in ref:
            row["status"] = "diferente"   # comum com CDNs; só informativo
        elif not ip:
            row["status"] = "sem resposta"
        tests.append(row)
    junk = f"desgrampa-{secrets.token_hex(8)}.com"
    junk_ip = phone_resolve(ctx, junk)
    tests.append({"domain": junk + " (não existe)", "phone": junk_ip, "reference": None,
                  "status": "sequestro de NXDOMAIN" if junk_ip else "ok"})
    if junk_ip:
        findings.append(Finding(
            "media", "DNS responde a domínios inexistentes",
            f"Um domínio que não existe ({junk}) foi resolvido para {junk_ip}. A rede/operadora está "
            "manipulando respostas DNS — o mesmo mecanismo pode ser usado para redirecionar sites reais.",
            "Ative o DNS privado (Configurações > Rede > DNS privado).", category="intercept"))
    data["dns_tests"] = tests
    if all(t["phone"] is None for t in tests[:-1]):
        ctx.notes.append("O celular não resolveu nenhum domínio de teste (sem internet ou ping bloqueado)")


def _check_wifi(ctx, data, findings):
    """Wi-Fi conectado e redes abertas salvas."""
    status = ctx.try_sh("cmd wifi status")
    ssid = re.search(r'connected to "([^"]+)"', status) or re.search(r'SSID: "([^"]+)"', status)
    saved = []
    for line in ctx.try_sh("cmd wifi list-networks").splitlines()[1:]:
        m = re.match(r"^\s*(\d+)\s+(.+?)\s{2,}(\S+)\s*$", line)
        if m:
            saved.append({"ssid": m.group(2).strip(), "security": m.group(3)})
    data["wifi"] = {"connected": ssid.group(1) if ssid else None, "saved": saved}
    open_nets = [n["ssid"] for n in saved if n["security"].lower() in ("open", "none", "owe-transition")]
    if ssid and ssid.group(1) in open_nets:
        findings.append(Finding(
            "media", "Conectado em Wi-Fi aberto",
            f"A rede “{ssid.group(1)}” não tem senha: qualquer pessoa próxima pode ver o tráfego não "
            "criptografado ou criar uma rede falsa com o mesmo nome.",
            "Evite redes abertas; use dados móveis ou VPN confiável."))
    elif open_nets:
        findings.append(Finding(
            "baixa", "Redes Wi-Fi abertas salvas",
            "O celular se conecta automaticamente a: " + ", ".join(open_nets[:8]) + ". Um atacante pode "
            "criar uma rede falsa com esse nome para interceptar o tráfego.",
            "Esqueça essas redes em Configurações > Wi-Fi > Redes salvas."))


def _check_connections(ctx, data, findings):
    """Conexões TCP estabelecidas, comparadas com IPs de spyware."""
    raw = ctx.try_sh("cat /proc/net/tcp /proc/net/tcp6 2>/dev/null")
    conns = parse_proc_net(raw)
    by_app = {}
    for ip, port, uid, _ in conns:
        if not is_public_ip(ip):
            continue
        pkg = ctx.package_by_uid(uid) or f"uid {uid}"
        by_app.setdefault(pkg, set()).add(f"{ip}:{port}")
        match = ctx.iocs.match_ip(ip)
        if match:
            findings.append(Finding(
                "critica", f"Conexão ativa com servidor de spyware: {match.family}",
                f"{app_label(ctx, pkg)} está conectado agora a {ip}:{port}, endereço ligado a {match}.",
                "Não desligue o aparelho antes de salvar as evidências. Procure análise especializada.",
                package=pkg, category=ioc_category(match), family=match.family))
    data["connections"] = [{"package": k, "remotes": sorted(v)} for k, v in
                           sorted(by_app.items(), key=lambda kv: -len(kv[1]))]
    if not raw.strip():
        ctx.notes.append("Este Android não permite listar as conexões ativas pelo ADB")


def _check_data_usage(ctx, data, findings):
    """Apps que enviam muito dado em segundo plano (varredura completa)."""
    if not ctx.full:
        return
    ctx.progress("Analisando volume de dados por app")
    usage = parse_netstats(ctx.try_sh("dumpsys netstats detail", timeout=120))
    rows = []
    for uid, u in usage.items():
        pkg = ctx.package_by_uid(uid)
        app = ctx.packages.get(pkg) if pkg else None
        if not app or not app.third_party:
            continue
        rows.append({"package": pkg, **u})
        if u["bg_tx"] >= BG_UPLOAD_ALERT and u["bg_tx"] > u["fg_tx"] * 2:
            suspicious = app.sideloaded or app.has_launcher is False
            findings.append(Finding(
                "alta" if suspicious else "media", "App enviando muitos dados em segundo plano",
                f"{app_label(ctx, pkg)} enviou {_mb(u['bg_tx'])} em segundo plano (contra "
                f"{_mb(u['fg_tx'])} em uso). Spywares enviam gravações, fotos e mensagens assim.",
                "Se não é um app de backup/sincronização que você usa, investigue e restrinja os "
                "dados em segundo plano (Configurações > Apps > Dados móveis).",
                package=pkg))
    data["data_usage"] = sorted(rows, key=lambda r: -r["bg_tx"])[:15]
    if not usage:
        ctx.notes.append("Não foi possível ler as estatísticas de uso de dados (netstats)")


def run(ctx):
    findings = []
    data = ctx.data.setdefault("rede", {})
    _check_dns_servers(ctx, data, findings)
    _check_dns_resolution(ctx, data, findings)
    _check_wifi(ctx, data, findings)
    _check_connections(ctx, data, findings)
    _check_data_usage(ctx, data, findings)
    return findings
