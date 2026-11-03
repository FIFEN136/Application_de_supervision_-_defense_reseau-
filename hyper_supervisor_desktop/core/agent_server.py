"""
Procus Secure — réception des rapports des agents légers.

Canal sécurisé :
  • chaque agent a un identifiant et un SECRET propre (chiffré en base) ;
  • chaque rapport est signé HMAC-SHA256 (secret, horodatage, nonce, corps) : intégrité + authenticité ;
  • horodatage ±5 min et nonce à usage unique → un rapport capturé ne peut pas être rejoué ;
  • HTTPS par défaut avec certificat auto-signé dont l'empreinte est « épinglée » côté agent (pas d'autorité tierce,
    pas d'attaque par faux certificat) ;
  • corps limité à 2 Mo, JSON uniquement, aucune exécution de code ni commande renvoyée à l'agent : le serveur ne
    renvoie que sa configuration (fichiers à surveiller, intervalle).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import ssl
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from loguru import logger

from core.fim import FimEngine
from core.security import CryptoHelper

MAX_BODY = 2 * 1024 * 1024
MAX_SKEW = 300
DEFAULT_WATCH = {
    "linux": ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/hosts", "/etc/crontab",
              "/root/.ssh/authorized_keys"],
    "windows": ["C:\\Windows\\System32\\drivers\\etc\\hosts"],
}


def sign(secret: str, ts: str, nonce: str, body: bytes) -> str:
    return hmac.new(secret.encode(), ts.encode() + b"." + nonce.encode() + b"." + body, hashlib.sha256).hexdigest()


def generate_self_signed(cert_path: str, key_path: str, cn: str = "procus-secure") -> str:
    """Crée un certificat auto-signé (10 ans). Retourne l'empreinte SHA-256 (hex) à donner aux agents."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256()))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert.fingerprint(hashes.SHA256()).hex()


def cert_fingerprint(cert_path: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read()).fingerprint(hashes.SHA256()).hex()


class AgentRegistry:
    def __init__(self, db):
        self.db = db

    def enroll(self, name: str, host_id: Optional[int] = None, os_name: str = "linux",
               watch_paths: Optional[list] = None, interval_s: int = 60) -> dict:
        """Crée un agent. Le secret n'est retourné QU'ICI (ensuite stocké chiffré)."""
        if not name.strip():
            raise ValueError("Nom de l'agent requis.")
        if host_id and not self.db.get_host_by_id(host_id):
            raise ValueError("Équipement introuvable.")
        agent_id = "ag_" + secrets.token_hex(6)
        secret = secrets.token_urlsafe(32)
        watch = watch_paths if watch_paths is not None else DEFAULT_WATCH.get(os_name.lower(), [])
        self.db.execute(
            "INSERT INTO agents (agent_id, host_id, name, secret_enc, os, watch_paths, interval_s) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (agent_id, host_id, name.strip(), CryptoHelper.encrypt(secret), os_name.lower(), json.dumps(watch),
             max(10, int(interval_s))))
        if host_id:
            self.db.execute("UPDATE hosts SET agent_enabled = 1 WHERE id = ?", (host_id,))
        return {"agent_id": agent_id, "secret": secret}

    def get(self, agent_id: str, with_secret: bool = False) -> Optional[dict]:
        row = self.db.fetchone("SELECT * FROM agents WHERE agent_id = ?", (agent_id,))
        if not row:
            return None
        enc = row.pop("secret_enc")
        if with_secret:
            row["secret"] = CryptoHelper.decrypt(enc)
        row["watch_paths"] = json.loads(row["watch_paths"] or "[]")
        return row

    def list(self) -> list[dict]:
        return [self.get(r["agent_id"]) for r in self.db.fetchall("SELECT agent_id FROM agents ORDER BY id")]

    def revoke(self, agent_id: str):
        self.db.execute("DELETE FROM agents WHERE agent_id = ?", (agent_id,))
        self.db.execute("DELETE FROM agent_data WHERE agent_id = ?", (agent_id,))
        self.db.execute("DELETE FROM fim_baseline WHERE agent_id = ?", (agent_id,))

    def set_watch_paths(self, agent_id: str, paths: list[str]):
        self.db.execute("UPDATE agents SET watch_paths = ? WHERE agent_id = ?", (json.dumps(paths), agent_id))


class AgentServer:
    def __init__(self, db, sink, pipeline, port: int = 8765, bind: str = "0.0.0.0",
                 certfile: Optional[str] = None, keyfile: Optional[str] = None,
                 rate_per_min: int = 600, max_conn: int = 64):
        self.db, self.sink, self.pipeline = db, sink, pipeline
        self.registry = AgentRegistry(db)
        self.fim = FimEngine(db, sink)
        self.port, self.bind, self.certfile, self.keyfile = port, bind, certfile, keyfile
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._nonces: dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        self._net_prev: dict[str, tuple[float, int, int]] = {}     # agent -> (t, rx, tx) pour le calcul du débit
        self._lock = threading.Lock()
        self._hits: dict[str, deque] = defaultdict(deque)          # IP → horodatages (limite de débit par source)
        self.rate_per_min = rate_per_min
        self._slots = threading.BoundedSemaphore(max_conn)         # plafond de connexions simultanées
        self.error: Optional[str] = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def tls(self) -> bool:
        return bool(self.certfile and self.keyfile)

    def start(self) -> bool:
        if self.running:
            return True
        server = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *a): pass
            def _reply(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close"); self.end_headers(); self.wfile.write(body)
            def do_POST(self):
                if not server._slots.acquire(blocking=False):
                    return self._reply(503, {"error": "busy"})
                try:
                    if not server.allow_ip(self.client_address[0]):
                        return self._reply(429, {"error": "too many requests"})
                    return self._post()
                finally:
                    server._slots.release()
            def _post(self):
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return self._reply(400, {"error": "bad length"})
                if self.path != "/api/v1/report":
                    return self._reply(404, {"error": "not found"})
                if n <= 0 or n > MAX_BODY:
                    return self._reply(413, {"error": "bad size"})
                body = self.rfile.read(n)
                code, obj = server.handle_report(self.headers.get("X-Procus-Agent", ""), self.headers.get("X-Procus-Timestamp", ""),
                                                 self.headers.get("X-Procus-Nonce", ""), self.headers.get("X-Procus-Signature", ""), body)
                self._reply(code, obj)
            def do_GET(self):
                self._reply(405, {"error": "POST only"})

        try:
            httpd = ThreadingHTTPServer((self.bind, self.port), H)
            httpd.daemon_threads = True
            if self.tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(self.certfile, self.keyfile)
                httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        except (OSError, ssl.SSLError) as e:
            self.error = f"port {self.port}/tcp indisponible ou certificat invalide : {getattr(e, 'strerror', None) or e}"
            return False
        self.error = None
        self._httpd = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(target=httpd.serve_forever, name="agent-server", daemon=True)
        self._thread.start()
        return True

    def allow_ip(self, ip: str) -> bool:
        """Fenêtre glissante d'une minute par adresse source."""
        import time as _t
        now = _t.monotonic()
        with self._lock:
            q = self._hits[ip]
            while q and now - q[0] > 60:
                q.popleft()
            if len(q) >= self.rate_per_min:
                return False
            q.append(now)
            if len(self._hits) > 5000:                              # purge des sources inactives
                for k in [k for k, v in self._hits.items() if not v or now - v[-1] > 60]:
                    self._hits.pop(k, None)
        return True

    def stop(self):
        if self._httpd:
            self._httpd.shutdown(); self._httpd.server_close()
        if self._thread:
            self._thread.join(timeout=3)
        self._httpd = self._thread = None

    # ───────────── traitement d'un rapport ─────────────
    def handle_report(self, agent_id: str, ts: str, nonce: str, signature: str, body: bytes) -> tuple[int, dict]:
        agent = self.registry.get(agent_id, with_secret=True) if agent_id else None
        # réponse identique pour « agent inconnu » et « signature fausse » : pas d'énumération des agents
        if not agent or not agent["enabled"]:
            return 401, {"error": "unauthorized"}
        if not hmac.compare_digest(sign(agent["secret"], ts, nonce, body), signature or ""):
            return 401, {"error": "unauthorized"}
        try:
            if abs(time.time() - int(ts)) > MAX_SKEW:
                return 401, {"error": "stale"}
        except ValueError:
            return 401, {"error": "unauthorized"}
        with self._lock:
            seen = self._nonces[agent_id]
            if nonce in seen:
                return 401, {"error": "replay"}
            seen.append(nonce)
        try:
            payload = json.loads(body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return 400, {"error": "bad json"}
        try:
            self.process(agent, payload)
        except Exception as e:
            logger.exception(f"[AGENT] traitement échoué ({agent_id}) : {e}")
            return 500, {"error": "processing failed"}
        return 200, {"ok": True, "interval": agent["interval_s"], "watch_paths": agent["watch_paths"],
                     "collect_logs": True, "server_time": int(time.time())}

    def process(self, agent: dict, p: dict):
        aid = agent["agent_id"]
        sysinfo = p.get("system") if isinstance(p.get("system"), dict) else {}
        self.db.execute("UPDATE agents SET last_seen = datetime('now'), os = COALESCE(?, os), version = ? WHERE agent_id = ?",
                        (sysinfo.get("os"), str(p.get("agent_version", ""))[:20], aid))
        host = self.sink.host_by_id(agent["host_id"])
        if host:
            self._store_usage(host["id"], aid, sysinfo)
            self.db.update_host_status(host["id"], "online", time.strftime("%Y-%m-%dT%H:%M:%S"))
            self.db.update_host_reach(host["id"], "agent")
        for kind in ("system", "processes", "services", "software", "ports", "users"):
            if kind in p:
                self.db.execute("INSERT OR REPLACE INTO agent_data (agent_id, kind, data) VALUES (?, ?, ?)",
                                (aid, kind, json.dumps(p[kind], ensure_ascii=False)[:1_500_000]))
        conns = p.get("connections")
        if isinstance(conns, list) and conns:                 # « qui parle à qui » (adresses et ports seulement)
            try:
                from core.flows import FlowStore, ingest_connections
                row = self.db.fetchone("SELECT ip_address FROM hosts WHERE id = ?", (agent["host_id"],)) if agent["host_id"] else None
                ingest_connections(FlowStore(self.db), conns, f"agent:{aid}", (row or {}).get("ip_address", ""))
            except Exception:
                pass
        fim = p.get("fim")
        if isinstance(fim, dict) and fim:
            clean = {str(k): v for k, v in fim.items() if isinstance(v, dict)}
            self.fim.compare(aid, clean, host=host, label=agent["name"])
        for entry in (p.get("logs") or [])[:1000]:
            if isinstance(entry, dict) and entry.get("message"):
                self.pipeline.ingest(str(entry["message"]), src_addr=(host or {}).get("name", ""), source=f"agent:{aid}",
                                     fields=entry.get("fields") if isinstance(entry.get("fields"), dict) else None,
                                     host=host)

    @staticmethod
    def _pct(v):
        try:
            f = float(v)
        except (TypeError, ValueError):
            return None
        return f if 0.0 <= f <= 100.0 else None                     # valeur aberrante : ignorée

    def _store_nic(self, host_id: int, s: dict):
        """Wi-Fi ou câble, nom de la carte et vitesse de liaison (jamais par-dessus un choix manuel)."""
        kind = s.get("net_kind")
        if kind not in ("wifi", "ethernet"):
            return
        import re as _re
        iface = _re.sub(r"[\x00-\x1f\x7f]", " ", str(s.get("net_iface") or ""))[:40].strip()
        try:
            speed = int(s.get("net_speed_mbps") or 0)
        except (TypeError, ValueError):
            speed = 0
        speed = speed if 1 <= speed <= 400000 else None
        self.db.execute("UPDATE hosts SET conn_type = ?, conn_detail = ?, conn_source = 'agent', link_mbps = COALESCE(?, link_mbps) "
                        "WHERE id = ? AND COALESCE(conn_source, '') != 'manual'", (kind, iface or None, speed, host_id))

    def _store_usage(self, host_id: int, aid: str, s: dict):
        """CPU / mémoire / disque et débit réseau remontés par l'agent → mêmes mesures que SNMP (affichées partout)."""
        self._store_nic(host_id, s)
        for key, metric in (("cpu_pct", "cpu_util"), ("mem_pct", "mem_used"), ("disk_pct", "disk_used")):
            v = self._pct(s.get(key))
            if v is not None:
                self.db.add_metric(host_id, metric, v, "%")
        try:
            rx, tx = int(s["net_rx_bytes"]), int(s["net_tx_bytes"])
        except (KeyError, TypeError, ValueError):
            return
        now = time.time()
        prev = self._net_prev.get(aid)
        self._net_prev[aid] = (now, rx, tx)
        if not prev or now - prev[0] < 1 or rx < prev[1] or tx < prev[2]:    # 1er relevé, ou compteur remis à zéro
            return
        dt = now - prev[0]
        self.db.add_metric(host_id, "bw_in", (rx - prev[1]) * 8 / dt / 1e6, "Mbps", "total")
        self.db.add_metric(host_id, "bw_out", (tx - prev[2]) * 8 / dt / 1e6, "Mbps", "total")

    def check_silent(self) -> list[str]:
        """Alerte (une fois) pour un agent muet depuis plus de 3 intervalles."""
        out = []
        for a in self.registry.list():
            if not a["enabled"] or not a["last_seen"]:
                continue
            row = self.db.fetchone("SELECT CAST(strftime('%s','now') - strftime('%s', ?) AS INTEGER) age", (a["last_seen"],))
            silent = row["age"] > 3 * int(a["interval_s"]) + 30
            key = f"agent_silent:{a['agent_id']}"
            if silent and not self.db.get_setting(key, ""):
                self.db.set_setting(key, "1")
                self.sink.emit("average", "agent_silent", f"L'agent « {a['name']} » ne répond plus depuis {row['age']} s",
                               host=self.sink.host_by_id(a["host_id"]))
                out.append(a["agent_id"])
            elif not silent and self.db.get_setting(key, ""):
                self.db.set_setting(key, "")
        return out
