"""
Procus Secure — Réseau local de la machine hôte
Procus Tech

Permet à l'application de se connecter AUTOMATIQUEMENT au réseau sur lequel
tourne la machine :
  - détection des interfaces actives, de l'IP principale, du sous-réseau, de la passerelle
  - enregistrement automatique de « cette machine » et de la passerelle comme hôtes supervisés
  - mesure de la bande passante réelle (débits entrant/sortant) via psutil, sans SNMP
  - métriques locales CPU / mémoire / disque
  - disponibilité d'un hôte (ICMP via la commande système + sondes TCP)
  - découverte des hôtes actifs du sous-réseau (balayage TCP asynchrone, plafonné à un /24)

Aucune dépendance Qt : testable seul.
"""
from __future__ import annotations

import asyncio
import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from loguru import logger

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:                      # pragma: no cover
    psutil = None
    HAS_PSUTIL = False


# Ports sondés pour décider qu'un hôte est vivant (un RST « refusé » prouve aussi qu'il répond)
PROBE_PORTS = (443, 80, 22, 445, 3389, 135, 139, 53, 8080, 21, 23, 5900)

LOCAL_HOST_NAME_PREFIX = "Cette machine"
GATEWAY_HOST_NAME = "Passerelle"


# ─────────────────────────────────────────────────────────────────
# Interfaces & adresses
# ─────────────────────────────────────────────────────────────────

def _is_usable_ipv4(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast)


def get_local_interfaces() -> list[dict]:
    """
    Interfaces IPv4 actives (hors loopback / link-local).
    Retourne [{name, ip, netmask, network, is_up}, ...]
    """
    result: list[dict] = []
    if not HAS_PSUTIL:
        ip = get_primary_ip()
        if ip:
            result.append({"name": "default", "ip": ip, "netmask": "255.255.255.0",
                           "network": str(ipaddress.ip_network(f"{ip}/24", strict=False)),
                           "is_up": True})
        return result

    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        st = stats.get(name)
        if st is not None and not st.isup:
            continue
        for a in addrs:
            if a.family != socket.AF_INET or not _is_usable_ipv4(a.address):
                continue
            mask = a.netmask or "255.255.255.0"
            try:
                net = ipaddress.ip_network(f"{a.address}/{mask}", strict=False)
            except ValueError:
                continue
            result.append({"name": name, "ip": a.address, "netmask": mask,
                           "network": str(net), "is_up": True})
    return result


def get_primary_ip() -> Optional[str]:
    """IP de l'interface qui sort vers le réseau (aucun paquet n'est émis par un connect UDP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(0.5)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        if _is_usable_ipv4(ip):
            return ip
    except OSError:
        pass
    finally:
        s.close()
    ifaces = get_local_interfaces() if HAS_PSUTIL else []
    return ifaces[0]["ip"] if ifaces else None


def get_local_addresses() -> set[str]:
    """Toutes les IPv4 de la machine, loopback compris."""
    addrs = {"127.0.0.1", "localhost"}
    if HAS_PSUTIL:
        for list_ in psutil.net_if_addrs().values():
            for a in list_:
                if a.family == socket.AF_INET:
                    addrs.add(a.address)
    p = get_primary_ip()
    if p:
        addrs.add(p)
    return addrs


def is_local_address(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("127."):
        return True
    return ip in get_local_addresses()


def parse_windows_default_routes(text: str) -> list[tuple[str, int]]:
    """[(passerelle, métrique)] pour chaque route par défaut de `route print` (plusieurs cartes = plusieurs routes)."""
    routes = []
    for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                         text, re.M):
        routes.append((m.group(1), int(m.group(3))))
    if not routes:                                        # ancien format sans interface/métrique
        for m in re.finditer(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", text, re.M):
            routes.append((m.group(1), 0))
    return routes


def _pick_gateway(routes: list[tuple[str, int]], own_ip: Optional[str] = None) -> Optional[str]:
    """Passerelle utilisable : dans le sous-réseau de l'IP principale, métrique la plus basse,
    jamais l'adresse réseau / broadcast / notre propre IP."""
    own_ip = own_ip or get_primary_ip()
    net = None
    if own_ip:
        for itf in (get_local_interfaces() if HAS_PSUTIL else []):
            if itf["ip"] == own_ip:
                net = ipaddress.ip_network(itf["network"], strict=False)
        if net is None:
            net = ipaddress.ip_network(f"{own_ip}/24", strict=False)
    ok = []
    for gw, metric in routes:
        if not _is_usable_ipv4(gw) or gw == own_ip:
            continue
        if net is not None:
            a = ipaddress.ip_address(gw)
            if a not in net or a == net.network_address or a == net.broadcast_address:
                continue
        ok.append((metric, gw))
    return min(ok)[1] if ok else (routes and next((g for g, _ in routes if _is_usable_ipv4(g) and g != own_ip), None)) or None


def get_default_gateway() -> Optional[str]:
    """Passerelle par défaut (Linux : /proc/net/route ; Windows/macOS : commandes système)."""
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/net/route", encoding="ascii") as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "00000000" and int(parts[3], 16) & 2:
                        gw = socket.inet_ntoa(int(parts[2], 16).to_bytes(4, "little"))
                        if _is_usable_ipv4(gw):
                            return gw
        elif system == "Windows":
            out = subprocess.run(["route", "print", "-4", "0.0.0.0"], capture_output=True,
                                 text=True, timeout=5).stdout
            gw = _pick_gateway(parse_windows_default_routes(out))
            if gw:
                return gw
        else:  # macOS / BSD
            out = subprocess.run(["netstat", "-rn", "-f", "inet"], capture_output=True,
                                 text=True, timeout=5).stdout
            m = re.search(r"^default\s+(\d+\.\d+\.\d+\.\d+)", out, re.M)
            if m and _is_usable_ipv4(m.group(1)):
                return m.group(1)
    except Exception as e:
        logger.debug(f"[NET] passerelle introuvable : {e}")
    return None


def get_primary_network() -> Optional[str]:
    """Sous-réseau CIDR de l'interface principale (ex: 192.168.1.0/24)."""
    ip = get_primary_ip()
    if not ip:
        return None
    for itf in get_local_interfaces():
        if itf["ip"] == ip:
            return itf["network"]
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


# ─────────────────────────────────────────────────────────────────
# Bande passante & métriques locales (psutil)
# ─────────────────────────────────────────────────────────────────

_VIRTUAL_PREFIXES = ("docker", "veth", "br-", "virbr", "vmnet", "vboxnet", "tun", "tap", "wg", "zt")
_VIRTUAL_WORDS = ("loopback", "vethernet", "hyper-v", "vmware", "virtualbox", "wsl", "bluetooth",
                  "isatap", "teredo", "npcap", "pseudo", "tailscale", "vpn")


def _is_physical_nic(name: str) -> bool:
    low = name.lower()
    if low == "lo" or low.startswith(_VIRTUAL_PREFIXES):
        return False
    return not any(w in low for w in _VIRTUAL_WORDS)


def _primary_nic_name() -> Optional[str]:
    """Nom de l'interface qui porte l'IP principale (celle qui sort réellement sur le réseau)."""
    if not HAS_PSUTIL:
        return None
    ip = get_primary_ip()
    if not ip:
        return None
    for name, addrs in psutil.net_if_addrs().items():
        if any(getattr(a, "address", None) == ip for a in addrs):
            return name
    return None


def link_speed_mbps(nic: Optional[str] = None) -> Optional[float]:
    """Vitesse négociée du lien (Mbps) si l'OS la fournit (sinon None)."""
    if not HAS_PSUTIL:
        return None
    try:
        stats = psutil.net_if_stats()
        nic = nic or _primary_nic_name()
        st = stats.get(nic) if nic else None
        return float(st.speed) if st and st.speed and st.speed > 0 else None
    except Exception:
        return None


def format_rate(mbps: float) -> tuple[str, str]:
    """(valeur, unité) lisibles : 0.16 → ('160', 'Kb/s') ; 700 → ('700', 'Mb/s') ; 1500 → ('1.50', 'Gb/s')."""
    if mbps >= 1000:
        return f"{mbps / 1000:.2f}", "Gb/s"
    if mbps >= 1:
        return f"{mbps:.1f}", "Mb/s"
    return f"{mbps * 1000:.0f}", "Kb/s"


class BandwidthSampler:
    """
    Débit réseau instantané = Δoctets × 8 / Δt (Mbps), mesuré sur l'interface PRINCIPALE
    (celle qui porte l'IP du réseau local). Additionner toutes les cartes compte plusieurs
    fois le même trafic (pont Hyper-V/WSL, VPN, carte virtuelle) et gonfle le débit.
    Une mesure supérieure à la vitesse du lien (physiquement impossible) est écartée.
    include_virtual=True : somme de toutes les interfaces (tests / usage avancé).
    """

    def __init__(self, include_virtual: bool = False):
        self.include_virtual = include_virtual
        self._last: Optional[tuple[float, int, int]] = None
        self._nic: Optional[str] = None
        self._nic_checked = 0.0
        self.last_in_mbps = 0.0
        self.last_out_mbps = 0.0

    @property
    def nic(self) -> Optional[str]:
        return self._nic

    def _select_nic(self):
        now = time.monotonic()
        if self._nic_checked and now - self._nic_checked < 60:
            return
        self._nic_checked = now
        new = None if self.include_virtual else _primary_nic_name()
        if new != self._nic:
            self._nic = new
            self._last = None            # changement d'interface : repartir d'une base propre

    def _read(self) -> tuple[int, int]:
        if not HAS_PSUTIL:
            return 0, 0
        counters = psutil.net_io_counters(pernic=True)
        if self._nic and self._nic in counters:
            c = counters[self._nic]
            return c.bytes_recv, c.bytes_sent
        rx = tx = 0
        for name, c in counters.items():
            if self.include_virtual or _is_physical_nic(name):
                rx += c.bytes_recv
                tx += c.bytes_sent
        return rx, tx

    def sample(self) -> tuple[float, float]:
        """Retourne (in_mbps, out_mbps). Le tout premier appel retourne (0, 0)."""
        self._select_nic()
        now = time.monotonic()
        rx, tx = self._read()
        if self._last is None:
            self._last = (now, rx, tx)
            return 0.0, 0.0
        t0, rx0, tx0 = self._last
        dt = now - t0
        self._last = (now, rx, tx)
        if dt < 0.2:                         # intervalle trop court : mesure instable
            return self.last_in_mbps, self.last_out_mbps
        d_rx, d_tx = rx - rx0, tx - tx0
        if d_rx < 0 or d_tx < 0:            # compteurs réinitialisés
            return 0.0, 0.0
        in_m = d_rx * 8 / dt / 1_000_000
        out_m = d_tx * 8 / dt / 1_000_000
        cap = None if self.include_virtual else link_speed_mbps(self._nic)
        if cap and (in_m > cap * 1.05 or out_m > cap * 1.05):
            return self.last_in_mbps, self.last_out_mbps     # impossible sur ce lien : mesure ignorée
        self.last_in_mbps, self.last_out_mbps = in_m, out_m
        return in_m, out_m


def collect_local_metrics() -> dict:
    """CPU %, mémoire %, mémoire dispo (GB), disque racine % de la machine locale."""
    if not HAS_PSUTIL:
        return {}
    import os
    vm = psutil.virtual_memory()
    root = os.path.abspath(os.sep)
    out = {
        "cpu_util": float(psutil.cpu_percent(interval=0.3)),
        "mem_used_pct": float(vm.percent),
        "mem_avail_gb": vm.available / (1024 ** 3),
    }
    try:
        out["disk_used_pct"] = float(psutil.disk_usage(root).percent)
    except OSError:
        pass
    return out


# ─────────────────────────────────────────────────────────────────
# Disponibilité (ICMP système + TCP)
# ─────────────────────────────────────────────────────────────────

def ping_icmp(ip: str, timeout_s: float = 1.0) -> tuple[bool, float]:
    """Ping ICMP via la commande système (ne demande pas les droits root). Bloquant."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), ip]
    elif system == "Darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout_s * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_s)))), ip]
    start = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_s + 2)
        if r.returncode == 0:
            m = re.search(rb"time[=<]\s*([\d.]+)", r.stdout)
            lat = float(m.group(1)) if m else (time.monotonic() - start) * 1000
            return True, lat
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return False, 0.0


async def _tcp_alive(ip: str, port: int, timeout: float) -> Optional[float]:
    """Latence (ms) si l'hôte répond sur ce port (connexion OU refus RST), sinon None."""
    start = time.monotonic()
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return (time.monotonic() - start) * 1000
    except ConnectionRefusedError:
        return (time.monotonic() - start) * 1000      # RST : l'hôte est bien là
    except (asyncio.TimeoutError, OSError):
        return None


async def _probe_async(ip: str, timeout: float, ports=PROBE_PORTS) -> tuple[bool, float]:
    res = await asyncio.gather(*[_tcp_alive(ip, p, timeout) for p in ports])
    lats = [r for r in res if r is not None]
    return (True, min(lats)) if lats else (False, 0.0)


_arp_lock = threading.Lock()
_arp_cache: dict = {"t": 0.0, "table": {}}


def arp_cache(ttl: float = 4.0) -> dict[str, str]:
    """Table ARP mise en cache quelques secondes (évite une commande par hôte lors d'un cycle parallèle)."""
    with _arp_lock:
        now = time.monotonic()
        if now - _arp_cache["t"] > ttl:
            _arp_cache["table"] = read_arp_table()
            _arp_cache["t"] = now
        return dict(_arp_cache["table"])


def is_onlink(ip: str) -> bool:
    """L'IP appartient-elle à un sous-réseau directement relié à cette machine ?"""
    try:
        addr = ipaddress.ip_address(ip)
        for itf in (get_local_interfaces() if HAS_PSUTIL else []):
            if addr in ipaddress.ip_network(itf["network"], strict=False):
                return True
    except ValueError:
        pass
    return False


def probe_host_ex(ip: str, timeout: float = 0.8, use_icmp: bool = True) -> dict:
    """
    Hôte vivant ? Retourne {"alive", "latency_ms", "method"} avec method ∈
    local | icmp | tcp | arp | none.
      1. ICMP (commande système)           2. sondes TCP parallèles (connexion OU refus RST)
      3. ARP — pour un hôte du même réseau local dont le pare-feu ignore ping ET TCP : sa
         présence dans la table ARP prouve qu'il est branché (les sondes TCP ont forcé la résolution).
    """
    if is_local_address(ip):
        return {"alive": True, "latency_ms": 0.0, "method": "local"}
    if use_icmp:
        ok, lat = ping_icmp(ip, timeout_s=max(1.0, timeout))
        if ok:
            return {"alive": True, "latency_ms": lat, "method": "icmp"}
    loop = asyncio.new_event_loop()
    try:
        ok, lat = loop.run_until_complete(_probe_async(ip, timeout))
    finally:
        loop.close()
    if ok:
        return {"alive": True, "latency_ms": lat, "method": "tcp"}
    hard = False                                               # « preuve nette de départ » (ARP en échec), jamais un simple silence
    if is_onlink(ip):
        from core import liveness
        v = liveness.arp_verdict(ip, ip in arp_cache())
        hard = v is False and liveness.arp_hard_dead(ip)
        liveness.nudge([ip])                                   # reconfirme le voisin : le verdict sera net au prochain passage
        if v is True:
            return {"alive": True, "latency_ms": 0.0, "method": "arp"}
        if v is None:                                          # entrée ARP ancienne : ni preuve de présence ni d'absence
            return {"alive": False, "latency_ms": 0.0, "method": "arp-unsure", "unsure": True}
    return {"alive": False, "latency_ms": 0.0, "method": "none", "hard": hard}


def probe_host(ip: str, timeout: float = 0.8, use_icmp: bool = True) -> tuple[bool, float]:
    """Compatibilité : (vivant, latence_ms). Bloquant → à appeler depuis un thread de travail."""
    r = probe_host_ex(ip, timeout, use_icmp)
    return r["alive"], r["latency_ms"]


REACH_LABELS = {
    "local": "machine locale", "icmp": "ping (ICMP)", "tcp": "connexion TCP",
    "arp": "ARP uniquement (pare-feu : ping et TCP bloqués)", "none": "aucune réponse",
    "agent": "agent Procus",
}


# ─────────────────────────────────────────────────────────────────
# Découverte du sous-réseau
# ─────────────────────────────────────────────────────────────────

def _scan_targets(network: str, own_ip: Optional[str]) -> list[str]:
    """Hôtes à sonder : jamais plus qu'un /24, uniquement réseaux privés."""
    net = ipaddress.ip_network(network, strict=False)
    if not net.is_private:
        raise ValueError(f"Réseau non privé refusé : {network}")
    if net.prefixlen < 24:
        if own_ip and ipaddress.ip_address(own_ip) in net:
            net = ipaddress.ip_network(f"{own_ip}/24", strict=False)
        else:
            net = ipaddress.ip_network(f"{next(net.hosts())}/24", strict=False)
    return [str(h) for h in net.hosts()]


async def _discover_async(targets: list[str], timeout: float, concurrency: int) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    found: list[dict] = []

    async def one(ip: str):
        async with sem:
            alive, lat = await _probe_async(ip, timeout)
        if alive:
            found.append({"ip": ip, "latency_ms": lat})

    await asyncio.gather(*[one(ip) for ip in targets])
    found.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return found


def _reverse_dns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(0.8)
    try:
        return socket.gethostbyaddr(ip)[0].split(".")[0]
    except (OSError, UnicodeError):
        return ""
    finally:
        socket.setdefaulttimeout(old)


def discover_hosts(network: Optional[str] = None, timeout: float = 0.5,
                   concurrency: int = 128) -> list[dict]:
    """
    Balayage TCP du sous-réseau (≤ /24, réseaux privés uniquement).
    Retourne [{ip, name, latency_ms}]. Bloquant → thread de travail.
    """
    own = get_primary_ip()
    network = network or get_primary_network()
    if not network:
        return []
    targets = _scan_targets(network, own)
    loop = asyncio.new_event_loop()
    try:
        found = loop.run_until_complete(_discover_async(targets, timeout, concurrency))
    finally:
        loop.close()
    for f in found:
        f["name"] = _reverse_dns(f["ip"])
    return found


# ─────────────────────────────────────────────────────────────────
# Noms lisibles des équipements (DNS inverse, NetBIOS, mDNS, indices)
# ─────────────────────────────────────────────────────────────────

TYPE_LABELS = {
    "router": "Routeur", "switch": "Switch", "firewall": "Pare-feu", "ap": "Borne Wi-Fi",
    "server": "Serveur", "workstation": "PC", "printer": "Imprimante", "mobile": "Mobile",
    "iot": "Objet connecté", "tv": "TV / média", "camera": "Caméra", "unknown": "Appareil",
}

_NAME_HINTS = (
    ("mobile",      ("iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi", "xiaomi", "oppo")),
    ("tv",          ("tv", "bravia", "roku", "chromecast", "firetv", "appletv", "smarttv", "samsungtv")),
    ("camera",      ("camera", "ipcam", "hikvision", "dahua", "reolink", "cam")),
    ("printer",     ("printer", "imprimante", "epson", "canon", "brother", "laserjet", "officejet")),
    ("workstation", ("desktop", "laptop", "macbook", "imac", "mac", "pc", "thinkpad", "latitude", "win")),
    ("server",      ("srv", "server", "serveur", "nas", "synology", "proxmox", "esxi", "raspberry")),
)


def hint_type_from_name(name: str) -> str:
    """Type d'après le nom réseau, par mots entiers (« camille-phone » n'est pas une caméra)."""
    tokens = [t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if t]
    for dtype, words in _NAME_HINTS:
        for t in tokens:
            for w in words:
                if t == w or (len(w) >= 5 and w in t) or (len(w) < 5 and re.fullmatch(w + r"\d+", t)):
                    return dtype
    return ""


def _netbios_name(ip: str, timeout: float = 0.6) -> str:
    """Nom NetBIOS (UDP 137, NBSTAT) — répond sur la plupart des PC Windows du réseau local."""
    pkt = (b"\xab\xcd\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
           + b"\x00\x00\x21\x00\x01")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(1024)
        n = data[56]
        for i in range(n):
            entry = data[57 + 18 * i: 57 + 18 * i + 18]
            if len(entry) == 18 and entry[15] == 0x00 and not (entry[16] & 0x80):   # nom unique de la machine
                return entry[:15].decode("ascii", "ignore").strip()
    except (OSError, IndexError):
        pass
    finally:
        s.close()
    return ""


def _mdns_name(ip: str, timeout: float = 0.6) -> str:
    """Nom mDNS/Bonjour (UDP 5353, requête PTR unicast) — Mac, iPhone, TV, imprimantes."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = b"".join(bytes([len(p)]) + p.encode() for p in qname.split(".")) + b"\x00"
    pkt = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + q + b"\x00\x0c\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 5353))
        data, _ = s.recvfrom(2048)
        m = re.search(rb"([A-Za-z0-9][A-Za-z0-9\-_ ]{1,40})\x05local", data)
        if m:
            return m.group(1).decode("ascii", "ignore").strip()
    except OSError:
        pass
    finally:
        s.close()
    return ""


def resolve_name(ip: str) -> str:
    """Meilleur nom disponible : DNS inverse → NetBIOS → mDNS ('' si aucun)."""
    for fn in (_reverse_dns, _netbios_name, _mdns_name):
        try:
            n = fn(ip)
        except Exception:
            n = ""
        n = re.sub(r"[^\w\-\. ]", "", n or "").strip()
        if n and not re.fullmatch(r"\d+(\.\d+){3}", n):
            return n
    return ""


def friendly_name(name: str, device_type: str, vendor: str, ip: str) -> str:
    """Nom affiché : nom réseau si connu, sinon « Type-dernierOctet » (ex : Mobile-154)."""
    if name:
        return name
    base = TYPE_LABELS.get(device_type, "Appareil")
    if vendor and not vendor.startswith("Adresse privée") and device_type in ("unknown", "iot", "server"):
        base = vendor.split(" (")[0]
    return f"{base}-{ip.split('.')[-1]}".replace(" / ", "-").replace(" ", "-")


def is_auto_name(name: str) -> bool:
    """Nom généré automatiquement (donc remplaçable par un meilleur nom quand il est découvert)."""
    n = (name or "").lower()
    return bool(re.match(r"^(host|equipement|appareil|mobile|pc|serveur|routeur|imprimante|tv|camera|objet|switch|borne|pare)[-\w]*-\d+$", n)) \
        or n.startswith("host-")


# ─────────────────────────────────────────────────────────────────
# Enregistrement automatique en base
# ─────────────────────────────────────────────────────────────────

def _unique_name(db, wanted: str) -> str:
    name, i = wanted, 2
    while db.fetchone("SELECT 1 AS x FROM hosts WHERE name = ?", (name,)):
        name = f"{wanted} ({i})"
        i += 1
    return name


LOCAL_LOCATION = "Machine locale (Procus Secure)"
GATEWAY_LOCATION = "Passerelle par défaut"


def _adopt(db, role_location: str, ip: str, wanted_name: str, device_type: str) -> int:
    """
    Retourne l'id de l'UNIQUE hôte portant ce rôle (machine locale / passerelle).
    Quand l'IP change (autre réseau, DHCP, carte virtuelle) on met à jour l'hôte existant au lieu
    d'en créer un second « (2) » : doublons fusionnés (historique conservé).
    """
    by_ip = db.get_host_by_ip(ip)
    roled = db.fetchall("SELECT * FROM hosts WHERE location = ? ORDER BY id", (role_location,))
    keeper = by_ip or (roled[0] if roled else None)
    if keeper is None:
        keeper_id = db.add_host(name=_unique_name(db, wanted_name), ip=ip,
                                device_type=device_type, location=role_location)
        db.execute("UPDATE hosts SET snmp_enabled = 0 WHERE id = ?", (keeper_id,))   # communauté inconnue
        logger.info(f"[NET] {role_location} enregistrée : {ip}")
        return keeper_id
    keeper_id = keeper["id"]
    for dup in roled:
        if dup["id"] != keeper_id:
            logger.info(f"[NET] Doublon « {dup['name']} » ({dup['ip_address']}) fusionné dans « {keeper['name']} »")
            db.merge_hosts(keeper_id, dup["id"])
    if keeper["ip_address"] != ip:
        db.execute("UPDATE hosts SET ip_address = ?, status = 'unknown', updated_at = datetime('now') WHERE id = ?",
                   (ip, keeper_id))
        logger.info(f"[NET] {role_location} : IP {keeper['ip_address']} → {ip}")
    if keeper.get("location") != role_location and not (keeper.get("location") or "").strip("— "):
        db.execute("UPDATE hosts SET location = ? WHERE id = ?", (role_location, keeper_id))
    elif by_ip and keeper.get("location") in (None, "", "Découvert automatiquement", "Découvert sur le réseau saisi"):
        db.execute("UPDATE hosts SET location = ? WHERE id = ?", (role_location, keeper_id))
    if wanted_name and re.search(r"\(\d+\)$", keeper["name"]) and not db.fetchone(
            "SELECT 1 AS x FROM hosts WHERE name = ?", (wanted_name,)):
        db.execute("UPDATE hosts SET name = ? WHERE id = ?", (wanted_name, keeper_id))   # « … (2) » → nom propre
    return keeper_id


def ensure_local_hosts(db) -> dict:
    """
    Enregistre (idempotent) la machine locale et la passerelle comme hôtes supervisés.
    Retourne {"local": host_id|None, "gateway": host_id|None, "ip":..., "gateway_ip":...}.
    """
    ip = get_primary_ip()
    gw = get_default_gateway()
    if gw and ip:                                           # passerelle aberrante (adresse réseau, notre IP)
        try:
            net = ipaddress.ip_network(get_primary_network() or f"{ip}/24", strict=False)
            if gw == ip or ipaddress.ip_address(gw) in (net.network_address, net.broadcast_address):
                gw = None
        except ValueError:
            gw = None
    info = {"local": None, "gateway": None, "ip": ip, "gateway_ip": gw}
    try:
        if ip and db.is_removed_network(get_primary_network() or f"{ip}/24"):
            logger.info("[NET] Réseau de cette machine retiré par l'utilisateur : non réenregistré.")
            return info
    except Exception:
        pass
    if ip:
        info["local"] = _adopt(db, LOCAL_LOCATION, ip,
                               f"{LOCAL_HOST_NAME_PREFIX} ({socket.gethostname() or 'local'})", "server")
    if gw:
        info["gateway"] = _adopt(db, GATEWAY_LOCATION, gw, GATEWAY_HOST_NAME, "router")
    return info


def _not_ignored(db, found: list[dict]) -> list[dict]:
    """Écarte les équipements retirés volontairement de la supervision (table ignored_devices)."""
    try:
        ign = {r["ip"] for r in db.fetchall("SELECT ip FROM ignored_devices")}
    except Exception:
        return found
    return [f for f in found if f.get("ip") not in ign] if ign else found


def register_discovered(db, found: list[dict]) -> int:
    """Ajoute en base les hôtes découverts qui n'existent pas encore. Retourne le nombre ajouté."""
    added = 0
    found = _not_ignored(db, found)
    for f in found:
        if db.get_host_by_ip(f["ip"]):
            continue
        name = _unique_name(db, f.get("name") or f"host-{f['ip']}")
        hid = db.add_host(name=name, ip=f["ip"], device_type="unknown",
                          location="Découvert automatiquement")
        # SNMP désactivé par défaut : on ne sonde en SNMP que les équipements que l'admin déclare
        db.execute("UPDATE hosts SET snmp_enabled = 0 WHERE id = ?", (hid,))
        added += 1
    return added


MAX_PREFIX_SPAN = 22          # /22 = 1022 hôtes au plus par réseau saisi


def parse_network_input(text: str) -> dict:
    """
    Accepte une IP de routeur/box (192.168.1.1 → réseau /24 contenant cette IP)
    ou un réseau CIDR (192.168.1.0/24, 10.0.0.0/22, 192.168.1.0/255.255.255.0).
    Réseaux PRIVÉS uniquement (RFC 1918), de /22 à /30.
    Retourne {"cidr", "gateway_ip" (ou None), "num_hosts"}. ValueError si invalide.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Saisissez l'adresse IP du routeur ou un réseau (ex : 192.168.1.1 ou 192.168.1.0/24).")
    gateway = None
    try:
        if "/" in raw:
            net = ipaddress.ip_network(raw, strict=False)
        else:
            ip = ipaddress.ip_address(raw)
            if ip.version == 4:
                gateway = str(ip)
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip}/128")
    except ValueError:
        raise ValueError(f"Adresse ou réseau invalide : « {raw} ».") from None
    if net.version != 4:
        raise ValueError("Seul IPv4 est pris en charge.")
    if not net.is_private or net.is_loopback or net.is_link_local:
        raise ValueError("Réseau non privé refusé : seules les plages 10.x, 172.16-31.x et 192.168.x sont autorisées.")
    if net.prefixlen < MAX_PREFIX_SPAN:
        raise ValueError(f"Réseau trop grand (/{net.prefixlen}) : maximum /{MAX_PREFIX_SPAN} (1022 équipements).")
    if net.prefixlen > 30:
        raise ValueError("Réseau trop petit : minimum /30.")
    return {"cidr": str(net), "gateway_ip": gateway, "num_hosts": max(net.num_addresses - 2, 0)}


_OUI = {
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox", "00155D": "Microsoft Hyper-V",
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "001132": "Synology", "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti",
    "FCECDA": "Ubiquiti", "802AA8": "Ubiquiti", "4C5E0C": "MikroTik", "E48D8C": "MikroTik",
    "240AC4": "Espressif (IoT)", "30AEA4": "Espressif (IoT)",
}
_NETWORK_VENDORS = {"Ubiquiti": "ap", "MikroTik": "router"}


def mac_vendor(mac: str) -> str:
    """Fabricant (table réduite, indicative). MAC aléatoire = téléphone/PC en Wi-Fi privé."""
    hexa = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(hexa) < 12:
        return ""
    if int(hexa[1], 16) & 0x2:                      # bit « localement administrée »
        return "Adresse privée (smartphone / PC)"
    return _OUI.get(hexa[:6], "")


_MAC_RE = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f])")
_IP_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")


def parse_arp_output(text: str) -> dict[str, str]:
    """{ip: mac} depuis `arp -a` (Windows/macOS) ou `ip neigh` (Linux). Ignore broadcast/multicast/incomplets."""
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        low = line.lower()
        if "incomplete" in low or "failed" in low:
            continue
        ip_m, mac_m = _IP_RE.search(line), _MAC_RE.search(line)
        if not (ip_m and mac_m):
            continue
        mac = mac_m.group(1).replace("-", ":").lower()
        if mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e") or mac == "00:00:00:00:00:00":
            continue
        out[ip_m.group(1)] = mac
    return out


def read_arp_table() -> dict[str, str]:
    """Table ARP de la machine (voisins déjà contactés sur le réseau local). Ne lève jamais."""
    cmds = [["arp", "-a"]] if platform.system() in ("Windows", "Darwin") else [["ip", "neigh", "show"], ["arp", "-an"]]
    for cmd in cmds:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5, text=True, errors="ignore")
            table = parse_arp_output(r.stdout)
            if table:
                return table
        except (OSError, subprocess.TimeoutExpired):
            continue
    try:                                             # repli Linux
        with open("/proc/net/arp") as f:
            return parse_arp_output(f.read())
    except OSError:
        return {}


def guess_device_type(open_ports: set, vendor: str = "", is_gateway: bool = False, name: str = "") -> str:
    """Type probable d'après passerelle / nom / ports / fabricant (heuristique, modifiable ensuite)."""
    if is_gateway:
        return "router"
    by_name = hint_type_from_name(name)
    if by_name:
        return by_name
    if vendor in _NETWORK_VENDORS:
        return _NETWORK_VENDORS[vendor]
    if open_ports & {9100, 515, 631}:
        return "printer"
    if open_ports & {3389, 445, 135, 139, 5900}:
        return "workstation"
    if 22 in open_ports or (open_ports & {80, 443, 8080} and len(open_ports) > 1):
        return "server"
    if vendor.startswith("Adresse privée"):
        return "mobile"
    if vendor.startswith("Espressif") or vendor == "Raspberry Pi":
        return "iot"
    return "unknown"


async def _probe_ports_async(ip: str, timeout: float) -> tuple[bool, float, set]:
    """Hôte vivant + ports ouverts (connexion établie) + meilleure latence."""
    start = time.monotonic()

    async def one(port):
        t0 = time.monotonic()
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass
            return port, (time.monotonic() - t0) * 1000, True
        except ConnectionRefusedError:
            return port, (time.monotonic() - t0) * 1000, False
        except (asyncio.TimeoutError, OSError):
            return port, None, False

    res = await asyncio.gather(*[one(p) for p in PROBE_PORTS + (9100, 515, 631)])
    lats = [r[1] for r in res if r[1] is not None]
    opened = {r[0] for r in res if r[2]}
    return bool(lats), (min(lats) if lats else 0.0), opened


async def _discover_net_async(targets: list[str], timeout: float, concurrency: int) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    found: list[dict] = []

    async def one(ip: str):
        async with sem:
            alive, lat, ports = await _probe_ports_async(ip, timeout)
        if alive:
            found.append({"ip": ip, "latency_ms": lat, "open_ports": ports})

    await asyncio.gather(*[one(ip) for ip in targets])
    return found


def _arp_nudge(targets: list[str], settle_s: float = 1.0) -> int:
    """
    Force la résolution ARP de TOUTES les adresses du sous-réseau : un petit datagramme UDP (requête de nom
    NetBIOS) oblige le système à demander « qui a cette IP ? », même si l'équipement ignore ping et TCP.
    Les équipements présents entrent dans la table ARP. Retourne le nombre de datagrammes émis. Ne lève jamais.
    """
    sent = 0
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        probe = b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
        for ip in targets:
            try:
                sock.sendto(probe, (ip, 137))
                sent += 1
            except (OSError, BlockingIOError):
                continue
        if sent and settle_s:
            time.sleep(settle_s)                      # laisse le noyau terminer les résolutions ARP
    except OSError:
        pass
    finally:
        if sock:
            sock.close()
    return sent


def discover_network(cidr: str, gateway_ip: Optional[str] = None, timeout: float = 0.6,
                     concurrency: int = 200) -> list[dict]:
    """
    Découvre les équipements d'un réseau saisi : balayage TCP parallèle + table ARP
    (révèle aussi les équipements qui ignorent tout trafic TCP : téléphones, caméras…).
    Retourne [{ip, name, mac, vendor, device_type, latency_ms, open_ports}]. Bloquant → thread.
    """
    info = parse_network_input(cidr)
    net = ipaddress.ip_network(info["cidr"])
    targets = [str(h) for h in net.hosts()]
    loop = asyncio.new_event_loop()
    try:
        found = loop.run_until_complete(_discover_net_async(targets, timeout, concurrency))
    finally:
        loop.close()
    by_ip = {f["ip"]: f for f in found}
    if is_onlink(str(next(net.hosts()))):             # réseau directement relié : on force ARP + 2e passage
        _arp_nudge(targets)
        missing = [t for t in targets if t not in by_ip]
        if missing:
            loop2 = asyncio.new_event_loop()
            try:
                for f in loop2.run_until_complete(_discover_net_async(missing, timeout * 1.5, concurrency)):
                    by_ip.setdefault(f["ip"], f)
            finally:
                loop2.close()
    for ip, mac in read_arp_table().items():          # voisins on-link (cache rempli par le balayage)
        try:
            if ipaddress.ip_address(ip) in net and ip not in by_ip and ip != str(net.broadcast_address):
                by_ip[ip] = {"ip": ip, "latency_ms": 0.0, "open_ports": set()}
        except ValueError:
            continue
    arp = read_arp_table()
    gw = gateway_ip or info.get("gateway_ip")
    if gw and gw not in by_ip:                         # le routeur saisi est toujours enregistré (même muet)
        try:
            if ipaddress.ip_address(gw) in net:
                by_ip[gw] = {"ip": gw, "latency_ms": 0.0, "open_ports": set()}
        except ValueError:
            pass
    result = []
    for ip in sorted(by_ip, key=lambda x: tuple(int(p) for p in x.split("."))):
        f = by_ip[ip]
        f["mac"] = arp.get(ip, "")
        f["vendor"] = mac_vendor(f["mac"])
        result.append(f)
    with ThreadPoolExecutor(max_workers=16) as ex:                   # noms en parallèle (DNS/NetBIOS/mDNS)
        for f, name in zip(result, ex.map(lambda d: resolve_name(d["ip"]), result)):
            f["name"] = name
            f["device_type"] = guess_device_type(f["open_ports"], f["vendor"],
                                                 is_gateway=(f["ip"] == gw), name=name)
    return result


def register_network_hosts(db, network_id: int, found: list[dict],
                           gateway_ip: Optional[str] = None) -> dict:
    """
    Enregistre les équipements découverts (rattachés au réseau) et met à jour ceux déjà connus.
    Retourne {"added": [hôtes nouveaux], "known": n}. Un équipement nouveau déclenche un événement.
    """
    added, known = [], 0
    net = db.fetchone("SELECT last_discovery FROM networks WHERE id = ?", (network_id,)) or {}
    baseline = not net.get("last_discovery")          # 1re découverte = référentiel (approuvé d'office)
    found = _not_ignored(db, found)
    for f in found:
        row = db.get_host_by_ip(f["ip"])
        wanted = friendly_name(f.get("name") or "", f["device_type"], f.get("vendor") or "", f["ip"])
        if row:
            db.update_host_identity(row["id"], mac=f.get("mac") or None, vendor=f.get("vendor") or None,
                                    network_id=network_id,
                                    device_type=f["device_type"] if row.get("device_type") in (None, "", "unknown") else None)
            if f.get("name") and is_auto_name(row.get("name", "")) and row["name"] != wanted:
                db.execute("UPDATE hosts SET name = ? WHERE id = ?", (_unique_name(db, wanted), row["id"]))
            known += 1
            continue
        name = _unique_name(db, wanted)
        hid = db.add_host(name=name, ip=f["ip"], device_type=f["device_type"],
                          location="Découvert sur le réseau saisi")
        db.execute("UPDATE hosts SET snmp_enabled = 0, first_seen = datetime('now'), approved = ? WHERE id = ?",
                   (1 if baseline else 0, hid))
        db.update_host_identity(hid, mac=f.get("mac") or None, vendor=f.get("vendor") or None,
                                network_id=network_id)
        added.append({"id": hid, "name": name, "ip": f["ip"], "device_type": f["device_type"],
                      "mac": f.get("mac", "")})
    db.execute("UPDATE networks SET last_discovery = datetime('now') WHERE id = ?", (network_id,))
    return {"added": added, "known": known}
