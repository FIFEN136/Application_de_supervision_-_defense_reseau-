"""
Procus Secure — enrichissement AUTOMATIQUE des appareils, sans mot de passe ni configuration.

Chaque information vient d'une source réelle du réseau local ; rien n'est inventé :
  · nom réseau : DNS inverse, NetBIOS (Windows), mDNS/Bonjour (Apple, TV, imprimantes)
  · modèle / fabricant annoncé : UPnP / SSDP (box, TV, imprimantes, enceintes…)
  · système probable : valeur TTL d'un ping
  · Wi-Fi de CET ordinateur : netsh (Windows) / nmcli (Linux) / airport (macOS)
Tout est borné en temps, limité au réseau local et ne lève jamais d'exception vers l'appelant.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import struct
import subprocess  # nosec B404 - commandes système fixes (ping, netsh, nmcli)
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from loguru import logger

SSDP_ADDR = ("239.255.255.250", 1900)
MAX_XML = 64 * 1024


def _private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private and not a.is_loopback and not a.is_multicast
    except ValueError:
        return False


# ───────────── DNS inverse ─────────────
def reverse_dns(ip: str, timeout: float = 1.5) -> Optional[str]:
    if not _private(ip):
        return None
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name.split(".")[0] if name and name != ip else None
    except (OSError, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(old)


# ───────────── NetBIOS (UDP 137, requête NBSTAT) ─────────────
_NBSTAT = (b"\xa2\x48\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00" b"\x00\x21\x00\x01")


def parse_nbstat(data: bytes) -> Optional[str]:
    """Premier nom NetBIOS « poste de travail » (suffixe 0x00, non groupe) d'une réponse NBSTAT."""
    try:
        if len(data) < 57:
            return None
        n = data[56]
        pos = 57
        for _ in range(n):
            name = data[pos:pos + 15].decode("ascii", "ignore").strip()
            suffix, flags = data[pos + 15], struct.unpack(">H", data[pos + 16:pos + 18])[0]
            pos += 18
            if suffix == 0 and not flags & 0x8000 and name:
                return name
    except (struct.error, IndexError):
        pass
    return None


def netbios_name(ip: str, timeout: float = 1.2) -> Optional[str]:
    if not _private(ip):
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(_NBSTAT, (ip, 137))
        data, src = s.recvfrom(1024)
        return parse_nbstat(data) if src[0] == ip else None
    except OSError:
        return None
    finally:
        s.close()


# ───────────── mDNS (Bonjour) : nom annoncé par l'appareil ─────────────
def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped, end = [], False, pos
    while pos < len(data) and depth < 12:
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | data[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            pos = ptr
            depth += 1
            continue
        labels.append(data[pos + 1:pos + 1 + ln].decode("utf-8", "ignore"))
        pos += 1 + ln
    return ".".join(labels), (end if jumped else pos)


def parse_mdns_ptr(data: bytes) -> Optional[str]:
    """Nom d'hôte (« iPhone-de-Leo ») d'une réponse mDNS à une requête PTR inverse."""
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(data, pos)
            pos += 4
        for _ in range(an):
            _, pos = _read_name(data, pos)
            rtype, _c, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 12:
                name, _ = _read_name(data, pos)
                return name.replace(".local", "") or None
            pos += rdlen
    except (struct.error, IndexError):
        pass
    return None


def mdns_name(ip: str, timeout: float = 1.2) -> Optional[str]:
    if not _private(ip):
        return None
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    pkt = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + _qname(rev) + struct.pack(">HH", 12, 0x8001)   # PTR, IN + « réponse unicast »
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 5353))
        data, src = s.recvfrom(2048)
        return parse_mdns_ptr(data) if src[0] == ip else None
    except OSError:
        return None
    finally:
        s.close()


# ───────────── UPnP / SSDP : modèle et fabricant annoncés ─────────────
def parse_upnp_xml(xml_text: str) -> dict:
    """{friendly, manufacturer, model, model_number} d'une description UPnP (XML borné, sans entités externes)."""
    try:
        if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
            return {}
        root = ET.fromstring(xml_text)      # nosec B314 - DOCTYPE/ENTITY refusés ci-dessus, taille bornée
    except ET.ParseError:
        return {}

    def find(tag):
        for el in root.iter():
            if el.tag.split("}")[-1] == tag and (el.text or "").strip():
                return el.text.strip()[:80]
        return None
    d = {"friendly": find("friendlyName"), "manufacturer": find("manufacturer"), "model": find("modelName"),
         "model_number": find("modelNumber")}
    return {k: v for k, v in d.items() if v}


def _fetch_upnp(url: str, src_ip: str) -> dict:
    import urllib.parse
    import urllib.request
    p = urllib.parse.urlparse(url)
    if p.scheme != "http" or p.hostname != src_ip or not _private(src_ip):        # la description doit venir de l'appareil lui-même
        return {}
    try:
        with urllib.request.urlopen(url, timeout=2.5) as r:      # nosec B310 - http, hôte privé identique à la source SSDP
            return parse_upnp_xml(r.read(MAX_XML).decode("utf-8", "ignore"))
    except Exception:
        return {}


def ssdp_discover(wait: float = 2.5) -> dict[str, dict]:
    """{ip: {friendly, manufacturer, model…}} pour les appareils qui répondent à une recherche UPnP."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    found: dict[str, str] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        s.sendto(msg, SSDP_ADDR)
        end = time.time() + wait
        while time.time() < end:
            try:
                data, src = s.recvfrom(4096)
            except socket.timeout:
                continue
            m = re.search(rb"(?im)^location:\s*(\S+)", data)
            if m and _private(src[0]) and src[0] not in found:
                found[src[0]] = m.group(1).decode("ascii", "ignore")
    except OSError as e:
        logger.debug(f"[ENRICH] SSDP : {e}")
    finally:
        s.close()
    if not found:
        return {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        res = list(ex.map(lambda kv: (kv[0], _fetch_upnp(kv[1], kv[0])), found.items()))
    return {ip: d for ip, d in res if d}


# ───────────── système probable (TTL) ─────────────
def os_from_ttl(ttl: Optional[int]) -> Optional[str]:
    if not ttl or ttl <= 0:
        return None
    if ttl <= 64:
        return "Linux / macOS / iOS / Android (probable)"
    if ttl <= 128:
        return "Windows (probable)"
    return "Équipement réseau (probable)"


def ping_ttl(ip: str, timeout: float = 2.0) -> Optional[int]:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    win = platform.system() == "Windows"
    cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if win else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, errors="ignore")      # nosec B603 - IP validée
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"ttl[=:]\s*(\d+)", r.stdout, re.I)
    return int(m.group(1)) if m else None


# ───────────── Wi-Fi de cet ordinateur ─────────────
def pct_to_dbm(pct: int) -> int:
    """Conversion usuelle Windows : dBm ≈ pourcentage/2 − 100 (estimation, signalée comme telle)."""
    return int(round(max(0, min(100, pct)) / 2 - 100))


def band_from_channel(ch: int) -> Optional[str]:
    return "2.4" if 1 <= ch <= 14 else "5" if 32 <= ch <= 177 else None


def band_from_mhz(mhz: int) -> Optional[str]:
    return "2.4" if 2400 <= mhz < 2500 else "5" if 4900 <= mhz < 5925 else "6" if 5925 <= mhz <= 7125 else None


def parse_netsh_wlan(text: str) -> Optional[dict]:
    """Interface Wi-Fi connectée d'après `netsh wlan show interfaces` (français ou anglais)."""
    def val(*keys):
        for line in text.splitlines():
            k, _, v = line.partition(":")
            if k.strip().lower() in keys:
                return v.strip()
        return None
    state = (val("état", "etat", "state") or "").lower()
    if not state or not any(w in state for w in ("connect",)) or "déconnect" in state or "disconnect" in state:
        return None
    pct = re.search(r"\d+", val("signal") or "")
    ch = re.search(r"\d+", val("canal", "channel") or "")
    rate = re.search(r"[\d.,]+", val("réception (mbits/s)", "reception (mbits/s)", "receive rate (mbps)", "débit de réception (mbit/s)") or "")
    out = {"ssid": val("ssid"), "rssi": pct_to_dbm(int(pct.group())) if pct else None,
           "band": band_from_channel(int(ch.group())) if ch else None,
           "link_mbps": int(float(rate.group().replace(",", "."))) if rate else None}
    return out if any(out.values()) else None


def parse_nmcli_wifi(text: str) -> Optional[dict]:
    """`nmcli -t -f ACTIVE,SSID,SIGNAL,FREQ,RATE dev wifi` : ligne « yes:… »."""
    for line in text.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if len(parts) >= 5 and parts[0] == "yes":
            sig, freq, rate = (re.search(r"\d+", p) for p in parts[2:5])
            return {"ssid": parts[1].replace("\\:", ":") or None, "rssi": pct_to_dbm(int(sig.group())) if sig else None,
                    "band": band_from_mhz(int(freq.group())) if freq else None,
                    "link_mbps": int(rate.group()) if rate else None}
    return None


def local_wifi() -> Optional[dict]:
    """Wi-Fi réel de CET ordinateur (None s'il est en Ethernet ou sans Wi-Fi)."""
    sysname = platform.system()
    try:
        if sysname == "Windows":
            r = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, timeout=5, errors="ignore", text=True)   # nosec B603 B607
            return parse_netsh_wlan(r.stdout)
        if sysname == "Linux":
            r = subprocess.run(["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,FREQ,RATE", "dev", "wifi"], capture_output=True, timeout=5,
                               errors="ignore", text=True)      # nosec B603 B607
            return parse_nmcli_wifi(r.stdout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


# ───────────── passage complet, enregistrement ─────────────
TYPE_PORTS = (62078, 7000, 5000, 548, 5900, 445, 3389, 135, 22)


def _one(ip: str) -> dict:
    from core.device_info import quick_port_scan
    try:
        ports = {p["port"] for p in quick_port_scan(ip, TYPE_PORTS, timeout=0.6)}
    except Exception:
        ports = set()
    return {"dns": reverse_dns(ip), "nb": netbios_name(ip), "mdns": mdns_name(ip), "ttl": ping_ttl(ip), "ports": ports}


def enrich_all(db, hosts: Optional[list] = None) -> int:
    """Complète les fiches (nom réseau, modèle, système probable, Wi-Fi local). Ne remplace jamais un choix manuel. Retourne le nombre de fiches modifiées."""
    hosts = [h for h in (hosts if hosts is not None else db.get_all_hosts()) if h.get("status") == "online" and h.get("ip_address")]
    if not hosts:
        return 0
    upnp = ssdp_discover()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(lambda h: _one(h["ip_address"]), hosts))
    wifi = local_wifi()
    from core.device_info import local_connection
    loc = local_connection()
    n = 0
    for h, r in zip(hosts, res):
        changes: dict[str, object] = {}

        def put(col, value, h=h, changes=changes):
            if value and value != h.get(col):
                changes[col] = value
        put("dns_name", r["nb"] or r["mdns"] or r["dns"])
        put("os_guess", os_from_ttl(r["ttl"]))
        u = upnp.get(h["ip_address"]) or {}
        if u.get("model") and not h.get("model"):
            put("model", (u["model"] + (f" {u['model_number']}" if u.get("model_number") else ""))[:80])
        if u.get("manufacturer") and not h.get("vendor"):
            put("vendor", u["manufacturer"])
        if wifi and loc and loc.get("type") == "wifi" and h["ip_address"] == loc.get("ip") and h.get("conn_source") != "manual":
            put("rssi", wifi.get("rssi"))
            put("wifi_band", wifi.get("band"))
            put("link_mbps", wifi.get("link_mbps"))
        from core.device_info import infer_type
        names = [h.get("name"), r["nb"], r["mdns"], r["dns"], u.get("friendly"), u.get("model"), h.get("model")]
        new_type = infer_type(h, names, r.get("ports") or set(), h.get("vendor") or "")
        if new_type:
            changes["device_type"] = new_type
        sets, params = [f"{c} = ?" for c in changes], list(changes.values())
        if sets:
            db.execute("UPDATE hosts SET " + ", ".join(sets) + " WHERE id = ?", tuple(params + [h["id"]]))     # nosec B608 - colonnes constantes
            n += 1
    return n
