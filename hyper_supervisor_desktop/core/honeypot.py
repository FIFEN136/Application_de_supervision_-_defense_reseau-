"""
Procus Secure — honeypots (leurres réseau).

Un honeypot ouvre un port qui n'offre AUCUN vrai service. Personne de légitime n'a de raison de s'y connecter :
toute connexion est donc suspecte (balayage de ports, ver, attaquant déjà dans le réseau). Chaque connexion est
enregistrée (adresse source, premiers octets envoyés) et déclenche une alerte.

Sûreté : les leurres ne traitent aucune donnée (ils lisent 256 octets au plus, n'exécutent rien, ne renvoient
qu'une bannière fixe) ; les ports par défaut sont élevés (≥ 2000) pour ne jamais entrer en conflit avec un vrai
service ni demander de privilèges. Activés uniquement sur demande de l'administrateur.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from typing import Optional

from loguru import logger

from core import local_network as lnet

PROFILES = {
    "ssh":     {"label": "SSH",     "banner": b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"},
    "telnet":  {"label": "Telnet",  "banner": b"\r\nlogin: "},
    "ftp":     {"label": "FTP",     "banner": b"220 FTP server ready.\r\n"},
    "http":    {"label": "HTTP",    "banner": None,
                "reply": b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n"},
    "generic": {"label": "Générique", "banner": None},
}
DEFAULT_PORTS = [
    {"port": 2222, "profile": "ssh"}, {"port": 2323, "profile": "telnet"}, {"port": 2121, "profile": "ftp"},
    {"port": 8081, "profile": "http"}, {"port": 3390, "profile": "generic"},
]
SCAN_THRESHOLD = 5          # connexions d'une même source en 60 s → balayage de ports (disaster)
EVENT_COOLDOWN_S = 30       # une seule alerte par source toutes les 30 s (sauf aggravation) ; toutes les connexions restent enregistrées


def sanitize(data: bytes, limit: int = 200) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[:limit])


def load_ports(db) -> list[dict]:
    try:
        ports = json.loads(db.get_setting("honeypot_ports", "") or "[]")
        ports = [p for p in ports if isinstance(p, dict) and 1 <= int(p.get("port", 0)) <= 65535]
        return ports or [dict(p) for p in DEFAULT_PORTS]
    except (ValueError, TypeError):
        return [dict(p) for p in DEFAULT_PORTS]


def save_ports(db, ports: list[dict]):
    clean = []
    for p in ports:
        port = int(p["port"])
        if not 1 <= port <= 65535:
            raise ValueError(f"Port invalide : {port}")
        prof = p.get("profile") if p.get("profile") in PROFILES else "generic"
        if port not in [c["port"] for c in clean]:
            clean.append({"port": port, "profile": prof})
    db.set_setting("honeypot_ports", json.dumps(clean))


class HoneypotManager:
    def __init__(self, db, sink, ports: Optional[list[dict]] = None, bind: str = "0.0.0.0",
                 ignore_local: bool = True):
        self.db, self.sink = db, sink
        self.ports = ports if ports is not None else load_ports(db)
        self.bind = bind
        self.ignore_local = ignore_local
        self.status: dict[int, str] = {}              # port configuré → « à l'écoute » / erreur
        self.bound: dict[int, int] = {}               # port configuré → port réel (utile avec le port 0)
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._ready = threading.Event()
        self._last_event: dict[str, tuple[float, str]] = {}

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, wait: float = 5.0) -> dict:
        if self.running:
            return self.status
        self._ready.clear()
        self._thread = threading.Thread(target=self._run, name="honeypots", daemon=True)
        self._thread.start()
        self._ready.wait(wait)
        return self.status

    def stop(self):
        loop = self._loop
        if loop and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        self._thread, self._loop = None, None
        self.status = {p["port"]: "arrêté" for p in self.ports}

    def _run(self):
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        servers = []
        try:
            for p in self.ports:
                port, profile = int(p["port"]), p.get("profile", "generic")
                try:
                    srv = loop.run_until_complete(asyncio.start_server(
                        lambda r, w, pr=profile, pt=port: self._handle(r, w, pr, pt), self.bind, port))
                    servers.append(srv)
                    self.bound[port] = srv.sockets[0].getsockname()[1]
                    self.status[port] = "à l'écoute"
                except OSError as e:
                    self.status[port] = f"indisponible : {e.strerror or e}"
                    logger.warning(f"[HONEYPOT] port {port} indisponible : {e}")
            self._ready.set()
            loop.run_forever()
        finally:
            for srv in servers:
                srv.close()
            try:
                loop.run_until_complete(asyncio.sleep(0))
            except Exception:
                pass
            loop.close()
            self._ready.set()

    async def _handle(self, reader, writer, profile: str, port: int):
        peer = writer.get_extra_info("peername") or ("?", 0)
        src, sport = peer[0], peer[1]
        data = b""
        try:
            prof = PROFILES.get(profile, PROFILES["generic"])
            if prof.get("banner"):
                writer.write(prof["banner"])
                await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=3.0)
            except (asyncio.TimeoutError, ConnectionError, OSError):
                data = b""
            if data and prof.get("reply"):
                writer.write(prof["reply"])
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass
        self.record_hit(src, sport, port, profile, data)

    # séparée pour être testable sans réseau
    def record_hit(self, src: str, sport: int, port: int, profile: str, data: bytes = b""):
        if self.ignore_local and lnet.is_local_address(src):
            return                                          # nos propres tests/scans ne sont pas une attaque
        payload = sanitize(data)
        self.db.execute("INSERT INTO honeypot_hits (port, profile, src_ip, src_port, payload) VALUES (?, ?, ?, ?, ?)",
                        (port, profile, src, sport, payload))
        row = self.db.fetchone("SELECT COUNT(DISTINCT port) n, COUNT(*) c FROM honeypot_hits "
                               "WHERE src_ip = ? AND seen_at >= datetime('now','-60 seconds')", (src,))
        scan = (row["n"] >= 2 and row["c"] >= SCAN_THRESHOLD) or row["c"] >= SCAN_THRESHOLD * 2
        severity = "disaster" if scan else "high"
        now = time.monotonic()
        last = self._last_event.get(src)
        if last and now - last[0] < EVENT_COOLDOWN_S and not (severity == "disaster" and last[1] != "disaster"):
            return
        self._last_event[src] = (now, severity)
        label = PROFILES.get(profile, PROFILES["generic"])["label"]
        if scan:
            desc = (f"Balayage de ports détecté depuis {src} : {row['c']} connexions vers {row['n']} leurre(s) "
                    f"en 60 s (dernier : {label} {port}/tcp)")
        else:
            desc = f"Honeypot {label} {port}/tcp touché par {src}" + (f" — reçu : « {payload[:60]} »" if payload else "")
        self.sink.emit(severity, "honeypot_hit", desc, port=port,
                       tags=["attack.discovery", "attack.t1046"], extra={"src_ip": src})

    def purge(self, days: int = 30):
        self.db.execute("DELETE FROM honeypot_hits WHERE seen_at < datetime('now', ?)", (f"-{int(days)} days",))
