"""Resumo do aparelho para o cartão da interface: modelo, ROM, chip, bateria, armazenamento etc.

Tudo vem de uma única chamada `adb shell` (COLLECT), separada em blocos por um marcador."""

import re

from .context import parse_getprop

# propriedade -> nome da interface do fabricante
ROM_PROPS = [
    ("ro.mi.os.version.name", "HyperOS"),
    ("ro.miui.ui.version.name", "MIUI"),
    ("ro.build.version.oneui", "One UI"),
    ("ro.build.version.opporom", "ColorOS"),
    ("ro.build.version.emui", "EMUI"),
    ("ro.vivo.os.version", "Funtouch OS"),
    ("ro.oxygen.version", "OxygenOS"),
]
MARKET_NAME_PROPS = ["ro.product.marketname", "ro.product.vendor.marketname", "ro.config.marketing_name",
                     "ro.vendor.oplus.market.name", "ro.product.odm.marketname"]


def _miui_version(props, ui_name):
    """'V13.0.4.0.SJZMIXM' (build) -> '13.0.4'; sem build detalhada, usa o nome da interface ('V130' -> '130')."""
    build = re.match(r"V?(\d+)\.(\d+)\.(\d+)\.\d+", props.get("ro.build.version.incremental", ""))
    return ".".join(build.groups()) if build else ui_name.lstrip("V")


def rom_version(props):
    for prop, name in ROM_PROPS:
        value = props.get(prop)
        if not value:
            continue
        if prop == "ro.build.version.oneui" and value.isdigit():   # 50101 -> 5.1.1
            n = int(value)
            return f"One UI {n // 10000}.{n // 100 % 100}" + (f".{n % 100}" if n % 100 else "")
        if prop == "ro.miui.ui.version.name":
            return f"MIUI {_miui_version(props, value)}"
        return f"{name} {value}"
    return None


BATTERY_STATUS = {"1": "desconhecido", "2": "carregando", "3": "descarregando", "4": "sem carregar", "5": "carga completa"}
BATTERY_HEALTH = {"1": "desconhecida", "2": "boa", "3": "superaquecida", "4": "esgotada", "5": "sobretensão",
                  "6": "falha", "7": "fria"}
NOMINAL_RAM_GB = [1, 1.5, 2, 3, 4, 6, 8, 10, 12, 16, 18, 24, 32]

# Uma única ida ao aparelho; cada bloco é separado por um marcador.
COLLECT = ("getprop; echo @@@; dumpsys battery; echo @@@; settings get global device_name; echo @@@; "
           "df -k /data | tail -1; echo @@@; cat /proc/meminfo; echo @@@; cat /proc/uptime")


def parse_battery(out):
    def field(name):
        m = re.search(rf"^\s*{name}: (.+)$", out, re.M)
        return m.group(1).strip() if m else None

    level, scale = field("level"), field("scale")
    if not level or not level.isdigit():
        return None
    pct = round(int(level) * 100 / int(scale)) if scale and scale.isdigit() and int(scale) else int(level)
    status = field("status")
    temp = field("temperature")
    plugged = [k for k, label in (("AC powered", "tomada"), ("USB powered", "USB"), ("Wireless powered", "sem fio"))
               if field(k) == "true"]
    return {
        "level": pct,
        "charging": status in ("2", "5"),
        "status": BATTERY_STATUS.get(status),
        "health": BATTERY_HEALTH.get(field("health")),
        "temperature_c": round(int(temp) / 10, 1) if temp and temp.lstrip("-").isdigit() else None,
        "power_source": {"AC powered": "tomada", "USB powered": "USB", "Wireless powered": "sem fio"}.get(plugged[0]) if plugged else None,
    }


def parse_df(line):
    parts = line.split()
    if len(parts) < 4 or not parts[1].isdigit() or not parts[2].isdigit():
        return None
    total, used = int(parts[1]) * 1024, int(parts[2]) * 1024
    return {"total_gb": round(total / 1e9, 1), "used_gb": round(used / 1e9, 1),
            "used_pct": round(used * 100 / total) if total else None}


def parse_meminfo(out):
    m = re.search(r"MemTotal:\s+(\d+) kB", out)
    if not m:
        return None
    gb = int(m.group(1)) * 1024 / 1e9
    nominal = next((n for n in NOMINAL_RAM_GB if n >= gb * 0.95), round(gb))
    avail = re.search(r"MemAvailable:\s+(\d+) kB", out)
    return {"total_gb": round(gb, 1), "nominal_gb": nominal,
            "available_gb": round(int(avail.group(1)) * 1024 / 1e9, 1) if avail else None}


def _clean(value):
    value = (value or "").strip().strip(",")
    return None if value in ("", "null", "unknown") else value


def summarize(serial, out, transport=None):
    """Monta o resumo do aparelho a partir da saída de COLLECT."""
    blocks = (out.split("@@@") + [""] * 6)[:6]
    getprop_out, battery_out, name_out, df_out, mem_out, uptime_out = blocks
    p = parse_getprop(getprop_out)
    market = next((p[k] for k in MARKET_NAME_PROPS if p.get(k)), None)
    brand = (p.get("ro.product.brand") or p.get("ro.product.manufacturer") or "").strip()
    model = p.get("ro.product.model")
    title = market or " ".join(x for x in (brand.capitalize() if brand.islower() else brand, model) if x) or serial
    soc = " ".join(x for x in (_clean(p.get("ro.soc.manufacturer")), _clean(p.get("ro.soc.model"))) if x) \
        or _clean(p.get("ro.board.platform")) or _clean(p.get("ro.hardware"))
    operators = [o.strip() for o in (p.get("gsm.sim.operator.alpha") or "").split(",") if _clean(o)]
    uptime = re.match(r"([\d.]+)", uptime_out.strip())
    vb, locked = p.get("ro.boot.verifiedbootstate"), p.get("ro.boot.flash.locked")
    return {
        "serial": serial,
        "name": title,
        "device_name": _clean(name_out.strip().splitlines()[0] if name_out.strip() else None),
        "model": model,
        "brand": brand or None,
        "manufacturer": (p.get("ro.product.manufacturer") or "").capitalize() or None,
        "codename": _clean(p.get("ro.product.device")),
        "android": p.get("ro.build.version.release_or_codename") or p.get("ro.build.version.release"),
        "sdk": int(p["ro.build.version.sdk"]) if p.get("ro.build.version.sdk", "").isdigit() else None,
        "rom": rom_version(p),
        "build": _clean(p.get("ro.build.PDA")) or _clean(p.get("ro.build.version.incremental")) or _clean(p.get("ro.build.display.id")),
        "security_patch": _clean(p.get("ro.build.version.security_patch")),
        "soc": soc,
        "operators": operators,
        "region": _clean(p.get("ro.csc.country_code")) or _clean(p.get("ro.product.locale.region")),
        "csc": _clean(p.get("ro.csc.sales_code")),
        "bootloader": {"verified_boot": _clean(vb), "locked": {"1": True, "0": False}.get(locked)},
        "encryption": _clean(p.get("ro.crypto.type")) or _clean(p.get("ro.crypto.state")),
        "storage": parse_df(df_out.strip()),
        "memory": parse_meminfo(mem_out),
        "uptime_s": int(float(uptime.group(1))) if uptime else None,
        "battery": parse_battery(battery_out),
        "transport": transport,
    }
