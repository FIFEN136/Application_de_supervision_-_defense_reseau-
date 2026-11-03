"""
Procus Secure — visibilité du trafic (v15, bloc 1).

Sources de flux (lecture seule, rien n'est modifié sur le réseau) :
  • NetFlow v5 reçu en UDP d'un routeur / pare-feu / commutateur (collecteur activable) ;
  • connexions observées par les agents ;
  • connexions de cette machine (psutil, facultatif).
Les flux sont agrégés par (source, destination, protocole, port destination) : la base reste petite et sert de
référence « qui parle à qui » pour proposer puis SIMULER des règles de filtrage.
Limites : NetFlow v9/IPFIX ne sont pas pris en charge ; UDP n'est pas authentifié (restreindre les exporteurs).
"""
from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from typing import Iterable, Optional

from loguru import logger

PROTO_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}
V5_HEADER = struct.Struct("!HHIIIIBBH")            # 24 octets
V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")   # 48 octets
MAX_V5_RECORDS = 30
FLOW_RETENTION_DAYS = 30


def proto_name(n) -> str:
    if isinstance(n, str):
        n = n.lower()
        return n if n in ("tcp", "udp", "icmp") else "other"
    return PROTO_NAMES.get(int(n), "other")


def _usable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_multicast or a.is_unspecified or a.is_reserved and not a.is_private
                or str(a) == "255.255.255.255")


class FlowStore:
    def __init__(self, db):
        self.db = db

    def add(self, src: str, dst: str, proto, dport: int = 0, bytes_: int = 0, packets: int = 0, flows: int = 1,
            source: str = "") -> bool:
        if not (_usable(src) and _usable(dst)):
            return False
        p = proto_name(proto)
        dport = int(dport) if p in ("tcp", "udp") and 0 <= int(dport) <= 65535 else 0
        self.db.execute(
            "INSERT INTO flows_agg (src_ip, dst_ip, proto, dst_port, flows, bytes, packets, source) VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(src_ip, dst_ip, proto, dst_port) DO UPDATE SET flows = flows + excluded.flows, "
            "bytes = bytes + excluded.bytes, packets = packets + excluded.packets, source = excluded.source, "
            "last_seen = datetime('now')",
            (src, dst, p, dport, max(int(flows), 0), max(int(bytes_), 0), max(int(packets), 0), source[:40]))
        return True

    def add_many(self, records: Iterable[dict], source: str = "") -> int:
        n = 0
        for r in records:
            try:
                n += bool(self.add(r["src"], r["dst"], r["proto"], r.get("dport", 0), r.get("bytes", 0),
                                   r.get("packets", 0), r.get("flows", 1), source))
            except (KeyError, ValueError, TypeError):
                continue
        return n

    _TOP_SQL = {
        "bytes": "SELECT * FROM flows_agg ORDER BY bytes DESC LIMIT ?",
        "flows": "SELECT * FROM flows_agg ORDER BY flows DESC LIMIT ?",
        "packets": "SELECT * FROM flows_agg ORDER BY packets DESC LIMIT ?",
    }

    def top(self, limit: int = 50, by: str = "bytes") -> list[dict]:
        return self.db.fetchall(self._TOP_SQL.get(by, self._TOP_SQL["bytes"]), (int(limit),))   # requêtes constantes : pas de SQL construit

    def all(self, limit: int = 20000) -> list[dict]:
        return self.db.fetchall("SELECT * FROM flows_agg ORDER BY last_seen DESC LIMIT ?", (int(limit),))

    def count(self) -> int:
        return self.db.fetchone("SELECT COUNT(*) n FROM flows_agg")["n"]

    def purge(self, days: int = FLOW_RETENTION_DAYS):
        self.db.execute("DELETE FROM flows_agg WHERE last_seen < datetime('now', ?)", (f"-{int(days)} days",))


# ───────────── NetFlow v5 ─────────────
def parse_netflow_v5(data: bytes) -> list[dict]:
    """Décode un datagramme NetFlow v5 ; retourne [] si invalide (jamais d'exception)."""
    if len(data) < V5_HEADER.size:
        return []
    version, count, _up, _s, _ns, _seq, _et, _eid, sampling = V5_HEADER.unpack_from(data, 0)
    if version != 5 or not 1 <= count <= MAX_V5_RECORDS or len(data) != V5_HEADER.size + count * V5_RECORD.size:
        return []
    interval = max(sampling & 0x3FFF, 1)             # échantillonnage : on rétablit l'ordre de grandeur
    out = []
    for i in range(count):
        f = V5_RECORD.unpack_from(data, V5_HEADER.size + i * V5_RECORD.size)
        src, dst = socket.inet_ntoa(f[0]), socket.inet_ntoa(f[1])
        out.append({"src": src, "dst": dst, "packets": f[5] * interval, "bytes": f[6] * interval,
                    "dport": f[10], "proto": f[13], "flows": interval})
    return out


def build_netflow_v5(records: list[dict], sampling: int = 0) -> bytes:
    """Construit un datagramme v5 (sert aux tests et à l'auto-diagnostic)."""
    hdr = V5_HEADER.pack(5, len(records), 0, int(time.time()), 0, 0, 0, 0, sampling)
    body = b""
    for r in records:
        body += V5_RECORD.pack(socket.inet_aton(r["src"]), socket.inet_aton(r["dst"]), b"\0\0\0\0", 0, 0,
                               r.get("packets", 1), r.get("bytes", 100), 0, 0, 0, r.get("dport", 0), 0, 0,
                               r.get("proto", 6), 0, 0, 0, 24, 24, 0)
    return hdr + body


class NetflowCollector:
    MAX_PPS = 2000

    def __init__(self, store: FlowStore, port: int = 2055, bind: str = "0.0.0.0", allowed: Optional[set] = None):
        self.store, self.port, self.bind = store, int(port), bind
        self.allowed = {a for a in (allowed or set()) if a}
        self.received = self.dropped = self.refused = 0
        self.error = ""
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        if self.running:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((self.bind, self.port))
            s.settimeout(0.5)
        except OSError as e:
            self.error = f"port UDP {self.port} indisponible : {e.strerror or e}"
            return False
        self.error = ""
        self._sock = s
        self.port = s.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="netflow", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self._sock:
            self._sock.close()
        self._thread = self._sock = None

    def _loop(self):
        window, count = time.monotonic(), 0
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            now = time.monotonic()
            if now - window >= 1:
                window, count = now, 0
            count += 1
            if count > self.MAX_PPS:
                self.dropped += 1
                continue
            if self.allowed and addr[0] not in self.allowed:
                self.refused += 1
                continue
            recs = parse_netflow_v5(data)
            if recs:
                try:
                    self.store.add_many(recs, source=f"netflow:{addr[0]}")
                    self.received += 1
                except Exception as e:
                    logger.debug(f"[FLUX] enregistrement impossible : {e}")


# ───────────── connexions d'un hôte (agents, machine locale) ─────────────
def ingest_connections(store: FlowStore, conns: list, source: str, local_ip: str = "") -> int:
    """conns : [{'laddr','lport','raddr','rport','proto','dir'}]. dir='in' : un tiers se connecte à nous."""
    n = 0
    for c in (conns or [])[:5000]:
        if not isinstance(c, dict):
            continue
        l, r = c.get("laddr") or local_ip, c.get("raddr")
        if not (l and r):
            continue
        try:
            if c.get("dir") == "in":
                n += bool(store.add(r, l, c.get("proto", "tcp"), int(c.get("lport", 0)), source=source))
            else:
                n += bool(store.add(l, r, c.get("proto", "tcp"), int(c.get("rport", 0)), source=source))
        except (TypeError, ValueError):
            continue
    return n


def local_connections() -> list[dict]:
    """Connexions établies de cette machine (psutil facultatif ; liste vide sinon)."""
    try:
        import psutil
    except ImportError:
        return []
    out = []
    try:
        socks = psutil.net_connections(kind="inet")
    except Exception:
        return []
    listening = {c.laddr.port for c in socks if c.status == psutil.CONN_LISTEN and c.laddr}
    for c in socks:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr or not c.laddr:
            continue
        out.append({"laddr": c.laddr.ip, "lport": c.laddr.port, "raddr": c.raddr.ip, "rport": c.raddr.port,
                    "proto": "tcp", "dir": "in" if c.laddr.port in listening else "out"})
    return out
