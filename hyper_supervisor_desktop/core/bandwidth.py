"""
Procus Secure — débits : routeur / Wi-Fi / équipements, avec historique.

Sources (la meilleure disponible est affichée, jamais mélangée en silence) :
  • snmp    : compteurs d'interface relevés par la supervision (métriques bw_in / bw_out, Mbps) — EXACT ;
  • agent   : compteurs réseau de la machine remontés par l'agent Procus — EXACT ;
  • local   : compteurs réseau de CE poste (psutil) — EXACT ;
  • netflow : octets vus dans les flux (NetFlow / agents) entre deux relevés — ESTIMATION (flux observés seulement).
Débit « rx » = reçu par l'équipement, « tx » = émis par l'équipement (en bits/s).
"""
from __future__ import annotations

import time
from typing import Optional

from core import local_network as lnet

RETENTION_DAYS = 7
_LOCAL_MON = None


def fmt_bps(v: float) -> str:
    v = float(v or 0)
    for unit, div in (("Gb/s", 1e9), ("Mb/s", 1e6), ("kb/s", 1e3)):
        if v >= div:
            return f"{v / div:.1f} {unit}"
    return f"{v:.0f} b/s"


def fmt_rate(bps: float) -> str:
    """« 523.4 Mb/s (65.4 Mo/s) » : bits par seconde (usage réseau) et octets par seconde (usage courant)."""
    v = float(bps or 0)
    if v < 1e6:
        return fmt_bps(v)
    return f"{fmt_bps(v)} ({v / 8e6:.1f} Mo/s)"


class BandwidthManager:
    def __init__(self, db):
        self.db = db
        self._last_totals: dict[str, tuple[float, int, int]] = {}      # ip -> (t, rx_octets, tx_octets)

    # ───────── relevé ─────────
    def _put(self, ip: str, ts: int, rx: float, tx: float, source: str):
        self.db.execute("INSERT INTO bw_samples (ip, ts, rx_bps, tx_bps, source) VALUES (?,?,?,?,?)",
                        (ip, ts, max(0.0, rx), max(0.0, tx), source))

    def sample(self, now: Optional[float] = None) -> int:
        """Un relevé de toutes les sources. Retourne le nombre d'échantillons écrits."""
        now = now if now is not None else time.time()
        ts, n = int(now), 0
        exact: set[str] = set()
        # 1) SNMP : dernières valeurs bw_in / bw_out (Mbps) de moins de 15 min
        for h in self.db.fetchall("SELECT id, ip_address, agent_enabled FROM hosts"):
            r = {}
            for m in ("bw_in", "bw_out"):
                row = self.db.fetchone(
                    "SELECT value FROM metrics WHERE host_id = ? AND metric_name = ? AND interface = 'total' "
                    "AND collected_at >= datetime('now','-15 minutes') ORDER BY id DESC LIMIT 1", (h["id"], m))
                if row:
                    r[m] = row["value"]
            if r:
                self._put(h["ip_address"], ts, r.get("bw_in", 0) * 1e6, r.get("bw_out", 0) * 1e6,
                          "agent" if h.get("agent_enabled") else "snmp")
                exact.add(h["ip_address"]); n += 1
        # 2) ce poste (psutil)
        try:
            global _LOCAL_MON
            if _LOCAL_MON is None:
                _LOCAL_MON = lnet.BandwidthSampler()
            rx, tx = _LOCAL_MON.sample()
            ip = lnet.get_primary_ip()
            if ip and ip not in exact and (rx or tx or _LOCAL_MON._last):
                self._put(ip, ts, rx * 1e6, tx * 1e6, "local"); exact.add(ip); n += 1
        except Exception:
            pass
        # 3) flux : delta des octets cumulés par IP
        totals: dict[str, list[int]] = {}
        for r in self.db.fetchall("SELECT src_ip, dst_ip, bytes FROM flows_agg"):
            totals.setdefault(r["src_ip"], [0, 0])[1] += r["bytes"]          # émis
            totals.setdefault(r["dst_ip"], [0, 0])[0] += r["bytes"]          # reçu
        for ip, (rx_o, tx_o) in totals.items():
            prev = self._last_totals.get(ip)
            self._last_totals[ip] = (now, rx_o, tx_o)
            if prev is None or ip in exact:
                continue
            dt = now - prev[0]
            if dt < 1:
                continue
            drx, dtx = max(0, rx_o - prev[1]), max(0, tx_o - prev[2])       # purge des flux : jamais négatif
            self._put(ip, ts, drx * 8 / dt, dtx * 8 / dt, "netflow"); n += 1
        return n

    def purge(self, days: int = RETENTION_DAYS):
        self.db.execute("DELETE FROM bw_samples WHERE ts < ?", (int(time.time()) - days * 86400,))

    # ───────── lecture ─────────
    def current(self, window_s: int = 900) -> list[dict]:
        """Débit courant par équipement connu : dernier échantillon récent, trié par débit total décroissant."""
        since = int(time.time()) - window_s
        rows = self.db.fetchall(
            "SELECT b.ip, b.rx_bps, b.tx_bps, b.source, b.ts FROM bw_samples b "
            "JOIN (SELECT ip, MAX(id) mid FROM bw_samples WHERE ts >= ? GROUP BY ip) m ON m.mid = b.id", (since,))
        hosts = {h["ip_address"]: h for h in self.db.fetchall("SELECT id, name, ip_address, device_type FROM hosts")}
        out = []
        for r in rows:
            h = hosts.get(r["ip"])
            out.append({"ip": r["ip"], "name": h["name"] if h else r["ip"], "host_id": h["id"] if h else None,
                        "device_type": h["device_type"] if h else "", "known": bool(h),
                        "rx_bps": r["rx_bps"], "tx_bps": r["tx_bps"], "source": r["source"], "ts": r["ts"],
                        "exact": r["source"] in ("snmp", "agent", "local")})
        out.sort(key=lambda d: d["rx_bps"] + d["tx_bps"], reverse=True)
        return out

    def series(self, ip: str, hours: float = 1, buckets: int = 60) -> list[tuple[int, float, float]]:
        """[(epoch, rx_bps, tx_bps)] moyenné par tranche."""
        now = int(time.time())
        span = int(hours * 3600)
        step = max(1, span // buckets)
        rows = self.db.fetchall(
            "SELECT (ts / ?) * ? AS b, AVG(rx_bps) rx, AVG(tx_bps) tx FROM bw_samples "
            "WHERE ip = ? AND ts >= ? GROUP BY b ORDER BY b", (step, step, ip, now - span))
        return [(r["b"], r["rx"], r["tx"]) for r in rows]

    def gateways(self) -> list[dict]:
        """Routeurs / Wi-Fi / pare-feu / passerelles avec leur débit courant et le taux d'utilisation du lien."""
        cap = float(self.db.get_setting("bw_link_mbps", "100") or 100) * 1e6
        cur = {d["ip"]: d for d in self.current()}
        gw_ips = {n["gateway_ip"] for n in self.db.fetchall("SELECT gateway_ip FROM networks WHERE gateway_ip IS NOT NULL")}
        out = []
        for h in self.db.fetchall("SELECT id, name, ip_address, device_type FROM hosts"):
            if h["device_type"] in ("router", "ap", "firewall") or h["ip_address"] in gw_ips:
                d = cur.get(h["ip_address"])
                rx, tx = (d["rx_bps"], d["tx_bps"]) if d else (0.0, 0.0)
                out.append({"name": h["name"], "ip": h["ip_address"], "host_id": h["id"], "rx_bps": rx, "tx_bps": tx,
                            "source": d["source"] if d else "", "capacity_bps": cap,
                            "usage_pct": min(100.0, max(rx, tx) / cap * 100) if cap else 0.0, "has_data": bool(d)})
        return out

    def detail(self, ip: str) -> dict:
        """Fiche d'un équipement : débit, historique, principaux interlocuteurs, port de commutateur, état de blocage."""
        from core.netmap import NetMapper
        h = self.db.fetchone("SELECT * FROM hosts WHERE ip_address = ? ORDER BY id LIMIT 1", (ip,)) or {}
        cur = next((d for d in self.current() if d["ip"] == ip), None)
        peers = self.db.fetchall(
            "SELECT CASE WHEN src_ip = ? THEN dst_ip ELSE src_ip END AS peer, SUM(bytes) b, "
            "SUM(CASE WHEN src_ip = ? THEN bytes ELSE 0 END) sent FROM flows_agg WHERE src_ip = ? OR dst_ip = ? "
            "GROUP BY peer ORDER BY b DESC LIMIT 8", (ip, ip, ip, ip))
        role = self.db.fetchone("SELECT role FROM host_roles WHERE host_id = ?", (h.get("id"),)) if h else None
        where = NetMapper(self.db).where_is(h.get("mac_address") or "") if h.get("mac_address") else None
        blk = self.db.fetchone("SELECT * FROM device_blocks WHERE ip = ? AND status = 'blocked' ORDER BY id DESC LIMIT 1", (ip,))
        return {"host": h, "current": cur, "peers": peers, "role": (role or {}).get("role"), "port": where,
                "blocked": blk, "series_1h": self.series(ip, 1), "series_24h": self.series(ip, 24, 96)}
