"""
Procus Secure — fiche complète d'un appareil (carte réseau : Carte / Liste / Détails).

Rassemble TOUT ce que l'application sait d'un appareil, sans rien inventer : une information inconnue reste vide (None)
et l'interface écrit « — » ou « non disponible ». Sources : découverte (IP, MAC, fabricant), table ARP/voisins IPv6, supervision
(statut, latence), commutateurs SNMP (port), agent (système, CPU/RAM, type de carte réseau), débits, ports ouverts, référentiel,
blocage. Le type de connexion (Wi-Fi / Ethernet) vient, par ordre de fiabilité : choix manuel > cet ordinateur > agent > port de
commutateur SNMP > heuristique (adresse MAC aléatoire d'un téléphone = Wi-Fi probable).
"""
from __future__ import annotations

import ipaddress
import platform
import re
import subprocess
import time
from typing import Optional

from loguru import logger

CONN_LABELS = {"wifi": "Wi-Fi", "ethernet": "Ethernet", "unknown": "Inconnu"}
CONN_TYPES = ("wifi", "ethernet")
SOURCE_LABELS = {"manual": "choisi par vous", "local": "détecté sur cet ordinateur", "agent": "signalé par l'agent",
                 "snmp": "relevé sur le commutateur (SNMP)", "box": "lu sur votre box", "heuristic": "déduit (probable)"}
BANDS = ("2.4", "5", "6")

_MAC = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
_V6 = re.compile(r"((?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4})")


# ───────────── IPv6 des voisins (par adresse MAC) ─────────────
def parse_ipv6_neighbors(text: str) -> dict[str, list[str]]:
    """{mac: [ipv6…]} depuis `ip -6 neigh`, `netsh interface ipv6 show neighbors` ou `ndp -an`. Globales avant lien-local."""
    out: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        low = line.lower()
        if "failed" in low or "incomplete" in low or "unreachable" in low and "lladdr" not in low:
            continue
        m, a = _MAC.search(line), None
        for cand in _V6.findall(line):
            try:
                addr = ipaddress.IPv6Address(cand.split("%")[0])
            except ValueError:
                continue
            a = addr
            break
        if not (m and a) or a.is_multicast or a.is_loopback:
            continue
        mac = m.group(1).replace("-", ":").lower()
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            continue
        out.setdefault(mac, [])
        s = str(a)
        if s not in out[mac]:
            out[mac].append(s)
    for mac, lst in out.items():
        lst.sort(key=lambda s: ipaddress.IPv6Address(s).is_link_local)       # adresse globale d'abord
    return out


def read_ipv6_neighbors() -> dict[str, list[str]]:
    """Voisins IPv6 de cette machine. Ne lève jamais."""
    sysname = platform.system()
    cmds = ([["netsh", "interface", "ipv6", "show", "neighbors"]] if sysname == "Windows"
            else [["ndp", "-an"]] if sysname == "Darwin" else [["ip", "-6", "neigh", "show"]])
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5, text=True, errors="ignore")
            res = parse_ipv6_neighbors(r.stdout)
            if res:
                return res
        except (OSError, subprocess.TimeoutExpired):
            continue
    return {}


# ───────────── type de connexion ─────────────
def classify_iface(name: str) -> str:
    n = (name or "").lower()
    if any(k in n for k in ("loopback", "lo", "docker", "veth", "virbr", "vmnet", "vethernet", "tun", "tap", "vpn", "bridge",
                            "hyper-v", "wsl")) and not n.startswith("eth"):
        if n in ("lo",) or any(k in n for k in ("loopback", "docker", "veth", "virbr", "vmnet", "vethernet", "tun", "tap", "vpn",
                                                "hyper-v", "wsl", "bridge")):
            return "other"
    if any(k in n for k in ("wi-fi", "wifi", "wlan", "wireless", "sans fil", "wlp", "wlx", "wl0")) or re.match(r"^wl\w*", n):
        return "wifi"
    if any(k in n for k in ("ethernet", "eth", "enp", "eno", "ens", "enx", "lan", "local area")) or re.match(r"^en\d", n):
        return "ethernet"
    return "other"


def local_connection() -> Optional[dict]:
    """Type de connexion de CET ordinateur : interface qui porte l'adresse principale."""
    try:
        import psutil
        from core.local_network import get_primary_ip
        ip = get_primary_ip()
        if not ip:
            return None
        for name, addrs in psutil.net_if_addrs().items():
            if any(getattr(a, "address", None) == ip for a in addrs):
                kind = classify_iface(name)
                stats = psutil.net_if_stats().get(name)
                if kind == "other":
                    return None
                return {"type": kind, "detail": name, "link_mbps": int(stats.speed) if stats and stats.speed else None, "ip": ip}
    except Exception as e:
        logger.debug(f"[INFO] connexion locale : {e}")
    return None


def is_random_mac(mac: str) -> bool:
    """Adresse « administrée localement » (2e bit de l'octet 1) : MAC privée aléatoire des téléphones en Wi-Fi."""
    try:
        return bool(int((mac or "").split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def infer_connection(db, host: dict, local: Optional[dict] = None) -> dict:
    """{type, detail, source, probable}. Un choix manuel n'est jamais écrasé."""
    if host.get("conn_source") == "manual" and host.get("conn_type"):
        return {"type": host["conn_type"], "detail": host.get("conn_detail") or "", "source": "manual", "probable": False}
    if local and host.get("ip_address") == local.get("ip"):
        return {"type": local["type"], "detail": local.get("detail") or "", "source": "local", "probable": False}
    if host.get("conn_source") == "agent" and host.get("conn_type"):
        return {"type": host["conn_type"], "detail": host.get("conn_detail") or "", "source": "agent", "probable": False}
    if host.get("conn_source") == "box" and host.get("conn_type"):
        return {"type": host["conn_type"], "detail": host.get("conn_detail") or "", "source": "box", "probable": False}
    mac = host.get("mac_address") or ""
    if mac:
        try:
            from core.netmap import NetMapper
            where = NetMapper(db).where_is(mac)
        except Exception:
            where = None
        if where:
            return {"type": "ethernet", "detail": f"{where['switch']} · port {where['port']}", "source": "snmp", "probable": False}
    dtype = (host.get("device_type") or "").lower()
    if mac and is_random_mac(mac) and dtype in ("mobile", "unknown", "iot", ""):
        return {"type": "wifi", "detail": "", "source": "heuristic", "probable": True}
    if dtype == "mobile":
        return {"type": "wifi", "detail": "", "source": "heuristic", "probable": True}
    return {"type": "unknown", "detail": "", "source": "", "probable": False}


REVISABLE_TYPES = ("mobile", "unknown", "iot", "workstation", "server")
TYPE_CHOICES = (("router", "Routeur / box"), ("switch", "Commutateur"), ("firewall", "Pare-feu"), ("ap", "Borne Wi-Fi"),
                ("server", "Serveur"), ("workstation", "Ordinateur (PC, Mac)"), ("printer", "Imprimante"), ("mobile", "Téléphone / tablette"),
                ("iot", "Objet connecté"), ("tv", "TV / média"), ("camera", "Caméra"), ("unknown", "Je ne sais pas"))


def infer_type(host: dict, names: list, open_ports: set, vendor: str = "") -> Optional[str]:
    """Meilleur type d'après les preuves RÉELLES (nom annoncé, modèle, ports). None = ne rien changer.
    Jamais appliqué sur un choix manuel ni sur un équipement réseau. Corrige par exemple un MacBook classé « téléphone »
    parce que son adresse MAC est privée : un iPhone ouvre le port 62078, un Mac a un nom « MacBook/Mac » ou AirPlay/AFP/partage d'écran."""
    cur = (host.get("device_type") or "unknown").lower()
    if host.get("type_source") == "manual" or cur not in REVISABLE_TYPES:
        return None
    from core.local_network import hint_type_from_name
    for n in names:
        t = hint_type_from_name(n or "")
        if t:
            return t if t != cur else None
    if 62078 in open_ports:                                       # service « lockdownd » : présent sur iPhone / iPad seulement
        return "mobile" if cur != "mobile" else None
    if cur in ("mobile", "unknown", "iot") and open_ports & {548, 5900, 7000, 3389, 445, 135}:
        return "workstation"
    return None


def quality_label(latency_ms: Optional[float], rssi: Optional[int] = None, failed: int = 0) -> Optional[str]:
    """Qualité de la connexion : par signal Wi-Fi si connu, sinon par temps de réponse."""
    if rssi is not None:
        return "Excellent" if rssi >= -55 else "Bon" if rssi >= -67 else "Moyen" if rssi >= -75 else "Faible"
    if latency_ms is None:
        return None
    if failed:
        return "Instable"
    return "Excellent" if latency_ms < 10 else "Bon" if latency_ms < 40 else "Moyen" if latency_ms < 120 else "Faible"


# ───────────── fiche ─────────────
# clés des pictogrammes SVG (ui/icons.py) : jamais d'emoji
ICONS = {k: f"dev_{k}" for k in ("router", "ap", "switch", "firewall", "server", "printer", "mobile", "iot", "tv", "camera", "unknown")}
ICONS["workstation"] = "dev_pc"


def _fmt_time(s: Optional[str]) -> str:
    return (s or "")[:16].replace("T", " ") or ""


def host_blocked(db, ip: str) -> bool:
    return bool(db.fetchone("SELECT 1 x FROM device_blocks WHERE ip = ? AND status = 'blocked' LIMIT 1", (ip,)))


def build_info(db, host: dict, local: Optional[dict] = None, v6: Optional[dict] = None, rates: Optional[dict] = None) -> dict:
    """Fiche d'un appareil. `local`, `v6` et `rates` peuvent être fournis pour éviter de les recalculer pour chaque appareil."""
    from core.local_network import REACH_LABELS
    from core.bandwidth import fmt_rate
    hid, ip, mac = host["id"], host.get("ip_address", ""), (host.get("mac_address") or "").lower()
    dtype = (host.get("device_type") or "unknown").lower()
    status = host.get("status") or "unknown"
    conn = infer_connection(db, host, local)
    lat = db.fetchone("SELECT value FROM metrics WHERE host_id = ? AND metric_name = 'latency' ORDER BY id DESC LIMIT 1", (hid,))
    latency = float(lat["value"]) if lat else None
    ipv6 = host.get("ipv6") or ((v6 or {}).get(mac) or [None])[0]
    cur = (rates or {}).get(ip)
    peak = db.fetchone("SELECT MAX(rx_bps) rx, MAX(tx_bps) tx FROM bw_samples WHERE ip = ? AND ts >= ?", (ip, int(time.time()) - 86400))
    net = None
    if host.get("network_id"):
        n = db.fetchone("SELECT name, cidr FROM networks WHERE id = ?", (host["network_id"],))
        net = f"{n['name']} ({n['cidr']})" if n else None
    ports = db.fetchall("SELECT port, protocol, service_name FROM port_states WHERE host_id = ? AND state = 'open' ORDER BY port LIMIT 12", (hid,)) \
        if _has_cols(db, "port_states", "service_name") else \
        db.fetchall("SELECT port, protocol FROM port_states WHERE host_id = ? AND state = 'open' ORDER BY port LIMIT 12", (hid,))
    role = db.fetchone("SELECT role FROM host_roles WHERE host_id = ?", (hid,))
    agent = db.fetchone("SELECT agent_id, last_seen FROM agents WHERE host_id = ? AND enabled = 1 LIMIT 1", (hid,)) if _table(db, "agents") else None
    sysd = None
    if agent:
        r = db.fetchone("SELECT data FROM agent_data WHERE agent_id = ? AND kind = 'system'", (agent["agent_id"],))
        if r:
            try:
                import json
                sysd = json.loads(r["data"])
            except Exception:
                sysd = None
    usage = {m["metric_name"]: m["value"] for m in db.fetchall(
        "SELECT metric_name, value FROM metrics WHERE host_id = ? AND metric_name IN ('cpu_util','mem_used','disk_used') "
        "AND id IN (SELECT MAX(id) FROM metrics WHERE host_id = ? GROUP BY metric_name)", (hid, hid))}
    events = db.fetchall("SELECT occurred_at, event_type, description FROM events WHERE host_id = ? AND event_type IN "
                         "('host_down','host_up','host_online','host_offline','new_device') ORDER BY id DESC LIMIT 6", (hid,))
    blocked = host_blocked(db, ip)
    q = quality_label(latency, host.get("rssi"), host.get("failed_probes") or 0) if status == "online" else None
    info = {
        "id": hid, "name": host.get("name", ""), "ip": ip, "mac": mac or None, "ipv6": ipv6, "icon": ICONS.get(dtype, "dev_unknown"),
        "device_type": dtype, "type_manual": host.get("type_source") == "manual", "status": status, "active": status == "online",
        "conn": {"type": conn["type"], "label": CONN_LABELS[conn["type"]], "detail": conn["detail"], "source": conn["source"],
                 "source_label": SOURCE_LABELS.get(conn["source"], ""), "probable": conn["probable"]},
        "vendor": host.get("vendor") or None, "model": host.get("model") or (sysd or {}).get("machine") or None,
        "quality": q, "latency_ms": latency, "rssi": host.get("rssi"), "band": host.get("wifi_band"), "link_mbps": host.get("link_mbps"),
        "network": net, "reach": REACH_LABELS.get(host.get("reach_method") or "", None), "role": (role or {}).get("role"),
        "first_seen": _fmt_time(host.get("first_seen") or host.get("created_at")),
        "last_seen": _fmt_time(host.get("last_seen") or host.get("last_check")),
        "approved": host.get("approved", 1) != 0, "blocked": blocked, "access_control": blocked or host.get("approved", 1) == 0,
        "group": host.get("group_name"), "location": host.get("location"), "owner": host.get("owner"), "criticality": host.get("criticality"),
        "os": ((sysd or {}).get("os") or "").capitalize() and f"{(sysd or {}).get('os', '').capitalize()} {(sysd or {}).get('os_release', '')}".strip() or host.get("os_guess") or None,
        "dns_name": host.get("dns_name") or None,
        "hostname": (sysd or {}).get("hostname"), "uptime_s": (sysd or {}).get("uptime_s"),
        "cpu": usage.get("cpu_util"), "ram": usage.get("mem_used"), "disk": usage.get("disk_used"),
        "agent": bool(agent) or bool(host.get("agent_enabled")), "snmp": bool(host.get("snmp_enabled")) and status == "online",
        "open_ports": [f"{p['port']}/{(p.get('protocol') or 'tcp').lower()}" for p in ports],
        "rx_bps": cur["rx_bps"] if cur else None, "tx_bps": cur["tx_bps"] if cur else None,
        "rx_fmt": fmt_rate(cur["rx_bps"]) if cur else None, "tx_fmt": fmt_rate(cur["tx_bps"]) if cur else None,
        "peak_rx_fmt": fmt_rate(peak["rx"]) if peak and peak["rx"] else None, "peak_tx_fmt": fmt_rate(peak["tx"]) if peak and peak["tx"] else None,
        "admin_url": _admin_url(ip, dtype, ports),
        "history": [{"at": _fmt_time(e["occurred_at"]), "what": e["description"]} for e in events],
    }
    return info


def _admin_url(ip: str, dtype: str, ports: list) -> Optional[str]:
    """Page web d'administration d'un équipement réseau, seulement si son port web est réellement ouvert."""
    if dtype not in ("router", "switch", "ap", "firewall", "printer", "camera", "iot", "tv"):
        return None
    open_ = {int(p["port"]) for p in ports}
    for port, scheme in ((443, "https"), (8443, "https"), (80, "http"), (8080, "http")):
        if port in open_:
            return f"{scheme}://{ip}" + ("" if port in (80, 443) else f":{port}")
    return None


def _table(db, name: str) -> bool:
    return bool(db.fetchone("SELECT 1 x FROM sqlite_master WHERE type='table' AND name = ?", (name,)))


def _has_cols(db, table: str, col: str) -> bool:
    return any(r["name"] == col for r in db.fetchall("SELECT name FROM pragma_table_info(?)", (table,)))


def build_all(db, hosts: Optional[list] = None) -> list[dict]:
    """Fiches de tous les appareils (IPv6, connexion locale et débits calculés une seule fois)."""
    from core.bandwidth import BandwidthManager
    hosts = hosts if hosts is not None else db.get_all_hosts()
    local, v6 = local_connection(), read_ipv6_neighbors()
    try:
        rates = {d["ip"]: d for d in BandwidthManager(db).current()}
    except Exception:
        rates = {}
    return [build_info(db, h, local, v6, rates) for h in hosts]


def matches_filter(info: dict, flt: str) -> bool:
    return (flt in (None, "", "all")
            or (flt == "wifi" and info["conn"]["type"] == "wifi")
            or (flt == "ethernet" and info["conn"]["type"] == "ethernet")
            or (flt == "access" and info["access_control"]))


# ───────────── enregistrement ─────────────
def refresh_connection_info(db) -> int:
    """Mémorise type de connexion (hors choix manuel), IPv6 et dernière présence. Retourne le nombre d'appareils mis à jour."""
    local, v6, n = local_connection(), read_ipv6_neighbors(), 0
    for h in db.get_all_hosts():
        c = infer_connection(db, h, local)
        mac = (h.get("mac_address") or "").lower()
        new6 = (v6.get(mac) or [None])[0]
        sets, params = [], []
        if h.get("conn_source") != "manual" and c["type"] != "unknown" and (c["type"], c["detail"], c["source"]) != (
                h.get("conn_type"), h.get("conn_detail"), h.get("conn_source")):
            sets += ["conn_type = ?", "conn_detail = ?", "conn_source = ?"]
            params += [c["type"], c["detail"], c["source"]]
        if new6 and new6 != h.get("ipv6"):
            sets.append("ipv6 = ?")
            params.append(new6)
        if h.get("status") == "online":
            sets.append("last_seen = datetime('now')")
        if sets:
            db.execute("UPDATE hosts SET " + ", ".join(sets) + " WHERE id = ?", tuple(params + [h["id"]]))      # nosec B608 - colonnes constantes
            n += 1
    return n


def update_device_meta(db, host_id: int, who: str = "system", **f) -> dict:
    """Modification manuelle (conn_type, conn_detail, model, wifi_band, rssi, link_mbps). Valide chaque champ."""
    h = db.get_host_by_id(host_id)
    if not h:
        raise ValueError("Appareil introuvable.")
    sets, params = [], []
    if "conn_type" in f:
        ct = (f["conn_type"] or "").lower()
        if ct not in CONN_TYPES + ("", "auto"):
            raise ValueError("Type de connexion : Wi-Fi, Ethernet ou Automatique.")
        if ct in ("", "auto"):
            sets += ["conn_type = NULL", "conn_detail = NULL", "conn_source = NULL"]
        else:
            sets += ["conn_type = ?", "conn_source = 'manual'", "conn_detail = ?"]
            params += [ct, _clean(f.get("conn_detail"), 80)]
    if "model" in f:
        sets.append("model = ?"); params.append(_clean(f["model"], 80))
    if "device_type" in f:
        dt = (f["device_type"] or "").lower()
        if dt in ("", "auto"):
            sets.append("type_source = NULL")
        elif dt in dict(TYPE_CHOICES):
            sets += ["device_type = ?", "type_source = 'manual'"]
            params.append(dt)
        else:
            raise ValueError("Type d'appareil inconnu.")
    if "wifi_band" in f:
        b = (f["wifi_band"] or "").strip()
        if b and b not in BANDS:
            raise ValueError("Bande Wi-Fi : 2.4, 5 ou 6 GHz.")
        sets.append("wifi_band = ?"); params.append(b or None)
    if "rssi" in f:
        r = f["rssi"]
        if r not in (None, "") and not (-100 <= int(r) <= 0):
            raise ValueError("Signal (RSSI) : entre -100 et 0 dBm.")
        sets.append("rssi = ?"); params.append(int(r) if r not in (None, "") else None)
    if "link_mbps" in f:
        m = f["link_mbps"]
        if m not in (None, "") and not (1 <= int(m) <= 400000):
            raise ValueError("Débit de liaison : entre 1 et 400000 Mb/s.")
        sets.append("link_mbps = ?"); params.append(int(m) if m not in (None, "") else None)
    if not sets:
        return h
    db.execute("UPDATE hosts SET " + ", ".join(sets) + ", updated_at = datetime('now') WHERE id = ?", tuple(params + [host_id]))   # nosec B608
    db.write_audit(who, "device_info_edit", f"{h['name']} ({h['ip_address']})", ", ".join(sorted(f)))
    return db.get_host_by_id(host_id)


def _clean(s, n: int) -> Optional[str]:
    s = re.sub(r"[\x00-\x1f\x7f]", " ", (s or "")).strip()[:n]
    return s or None


COMMON_PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554, 631, 993, 1883, 3306, 3389, 5900, 8000, 8080, 8443, 9100)


def quick_port_scan(ip: str, ports=COMMON_PORTS, timeout: float = 0.8) -> list[dict]:
    """Test rapide des services courants (connexion TCP). Bloquant : à appeler depuis un fil de travail."""
    import asyncio
    import socket
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return []

    async def one(p):
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return p
        except Exception:
            return None

    async def run():
        return await asyncio.gather(*[one(p) for p in ports])
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(run())
    finally:
        loop.close()
    out = []
    for p in sorted(x for x in res if x):
        try:
            svc = socket.getservbyport(p, "tcp")
        except OSError:
            svc = "service"
        out.append({"port": p, "service": svc})
    return out
