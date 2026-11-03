"""
Procus Secure — collecte et analyse des journaux (syslog UDP + agents) avec règles Sigma.

Chaque ligne reçue est stockée (durée de conservation réglable), enrichie (adresse source, utilisateur, programme),
puis confrontée aux règles Sigma activées. Une correspondance crée un événement « sigma_match » rattaché à
l'équipement émetteur : le pipeline d'automatisation le corrèle ensuite avec les autres détections.
"""
from __future__ import annotations

import json
import re
import socket
import threading
import time
from typing import Optional

from loguru import logger

from core.sigma_engine import SigmaEngine, seed_builtin_rules

_IP = r"(\d{1,3}(?:\.\d{1,3}){3})"
_SRC_PATTERNS = [re.compile(rf"\bfrom {_IP}"), re.compile(rf"rhost={_IP}"), re.compile(rf"\bsrc[= ]{_IP}"),
                 re.compile(rf"\({_IP}\)"), re.compile(rf"\b{_IP}\b")]
_USER_PATTERNS = [re.compile(r"Invalid user (\S+)"), re.compile(r"for (?:invalid user )?(\S+) from"),
                  re.compile(r"\buser[= ]'?(\w[\w.\-]*)'?"), re.compile(r"\bby (\S+) \(")]
_PROG = re.compile(r"(?:^|\s)([A-Za-z][\w.\-]*)(?:\[\d+\])?: ")
_PRI = re.compile(r"^<\d{1,3}>")


def extract_fields(message: str) -> dict:
    out = {}
    for rx in _SRC_PATTERNS:
        m = rx.search(message)
        if m:
            out["src_ip"] = m.group(1); break
    for rx in _USER_PATTERNS:
        m = rx.search(message)
        if m:
            out["user"] = m.group(1); break
    m = _PROG.search(message)
    if m:
        out["program"] = m.group(1)
    return out


def parse_syslog(data: bytes) -> str:
    text = data.decode("utf-8", "replace").strip("\x00\r\n ")
    return _PRI.sub("", text, count=1)


class LogPipeline:
    def __init__(self, db, sink, engine: Optional[SigmaEngine] = None):
        self.db, self.sink = db, sink
        seed_builtin_rules(db)
        self.engine = engine or SigmaEngine.from_db(db)

    def reload_rules(self):
        self.engine = SigmaEngine.from_db(self.db)

    def ingest(self, message: str, src_addr: str = "", source: str = "syslog", fields: Optional[dict] = None,
               host: Optional[dict] = None, store: bool = True) -> list[dict]:
        message = (message or "").strip()[:2000]
        if not message:
            return []
        f = {**extract_fields(message), **(fields or {})}
        host = host or self.sink.host_by_ip(src_addr)
        if store:
            try:
                self.db.execute("INSERT INTO log_events (host_id, source, src_addr, message, fields) VALUES (?, ?, ?, ?, ?)",
                                ((host or {}).get("id"), source, src_addr, message, json.dumps(f, ensure_ascii=False, default=str)))
            except Exception as e:
                logger.debug(f"[LOG] stockage ignoré : {e}")
        matches = self.engine.evaluate(message, f)
        for m in matches:
            rule = m["rule"]
            who = (host or {}).get("name") or src_addr or "source inconnue"
            extra = ""
            if rule.threshold:
                grp = ", ".join(str(g) for g in m.get("group", ()) if g)
                extra = f" — {m['count']} occurrences en {rule.threshold['timeframe']} s" + (f" ({grp})" if grp else "")
            self.sink.emit(rule.severity, "sigma_match", f"[Sigma] {rule.title} — {who}{extra} : {message[:140]}",
                           host=host, tags=rule.tags + [f"sigma:{rule.id}"],
                           extra={"rule_id": rule.id, "src_ip": f.get("src_ip", "")})
        return matches

    def purge(self, days: Optional[int] = None):
        days = days if days is not None else int(self.db.get_setting("log_retention_days", "14") or 14)
        self.db.execute("DELETE FROM log_events WHERE received_at < datetime('now', ?)", (f"-{int(days)} days",))


class SyslogReceiver:
    """Récepteur syslog UDP. Le port 514 exige des privilèges : 5514 par défaut (redirigeable)."""
    MAX_PER_SEC = 500

    def __init__(self, pipeline: LogPipeline, port: int = 5514, bind: str = "0.0.0.0"):
        self.pipeline, self.port, self.bind = pipeline, port, bind
        self.sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.received = self.dropped = 0
        self.error: Optional[str] = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> bool:
        if self.running:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((self.bind, self.port)); s.settimeout(0.5)
        except OSError as e:
            self.error = f"port {self.port}/udp indisponible : {e.strerror or e}"
            return False
        self.error = None
        self.sock = s; self.port = s.getsockname()[1]
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="syslog", daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)
        if self.sock:
            self.sock.close()
        self._thread = self.sock = None

    def _loop(self):
        window, n = time.monotonic(), 0
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                return
            now = time.monotonic()
            if now - window >= 1.0:
                window, n = now, 0
            n += 1
            if n > self.MAX_PER_SEC:                  # protection contre l'inondation
                self.dropped += 1
                continue
            self.received += 1
            try:
                self.pipeline.ingest(parse_syslog(data), src_addr=addr[0], source="syslog")
            except Exception as e:
                logger.debug(f"[SYSLOG] message ignoré : {e}")
