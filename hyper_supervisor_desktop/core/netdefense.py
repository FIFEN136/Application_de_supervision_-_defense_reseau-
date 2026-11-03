"""
Procus Secure — détection d'attaques sur le réseau local : usurpation ARP et faux serveur DHCP.

ARP : la table ARP associe chaque IP à une adresse MAC. Un attaquant qui se fait passer pour la passerelle
(« ARP spoofing / empoisonnement ») change la MAC associée à son IP pour intercepter le trafic (man-in-the-middle).
Procus Secure mémorise les couples IP↔MAC et alerte quand ils changent.

DHCP : un faux serveur DHCP distribue de fausses passerelles/DNS. Procus Secure envoie un DHCPDISCOVER et écoute
TOUTES les offres : plusieurs serveurs, ou un serveur inconnu, déclenchent une alerte.
"""
from __future__ import annotations

import json
import os
import random
import socket
import struct
import time
import uuid
from typing import Optional

from loguru import logger

from core import local_network as lnet

INFRA_TYPES = {"router", "switch", "firewall", "ap", "server"}


class ArpWatcher:
    def __init__(self, db, sink):
        self.db, self.sink = db, sink

    def _gateways(self) -> set[str]:
        gws = set()
        try:
            g = lnet.get_default_gateway()
            if g:
                gws.add(g)
        except Exception:
            pass
        for r in self.db.fetchall("SELECT gateway_ip FROM networks WHERE gateway_ip IS NOT NULL"):
            gws.add(r["gateway_ip"])
        return gws

    def _history(self, ip: str) -> list[str]:
        try:
            return json.loads(self.db.get_setting(f"arp_hist:{ip}", "[]") or "[]")
        except ValueError:
            return []

    def _remember(self, ip: str, mac: str):
        hist = [m for m in self._history(ip) if m != mac] + [mac]
        self.db.set_setting(f"arp_hist:{ip}", json.dumps(hist[-5:]))

    def check(self, table: Optional[dict] = None) -> list[dict]:
        """Compare la table ARP à la mémoire. Retourne les constats (déjà enregistrés comme événements)."""
        table = table if table is not None else lnet.read_arp_table()
        gws = self._gateways()
        known = {r["ip"]: r for r in self.db.fetchall("SELECT * FROM arp_bindings")}
        gw_mac = {ip: known[ip]["mac"] for ip in gws if ip in known}
        findings = []
        for ip, mac in table.items():
            mac = mac.lower()
            is_gw = ip in gws
            prev = known.get(ip)
            host = self.sink.host_by_ip(ip)
            if prev is None:
                # nouvelle adresse : même MAC que la passerelle = usurpation d'adresse matérielle probable
                dup = [g for g, m in gw_mac.items() if m == mac and g != ip]
                if dup:
                    findings.append(self._alert(
                        "average", f"L'adresse {ip} utilise la même MAC ({mac}) que la passerelle {dup[0]} : "
                                   f"adresse matérielle usurpée ou équipement en double", ip, mac, host))
                self.db.execute("INSERT OR REPLACE INTO arp_bindings (ip, mac, is_gateway) VALUES (?, ?, ?)",
                                (ip, mac, int(is_gw)))
                self._remember(ip, mac)
                continue
            if prev["mac"] != mac:
                restored = mac in self._history(ip)
                if is_gw or prev["is_gateway"]:
                    if restored:
                        findings.append(self._alert("information", f"La passerelle {ip} est revenue à sa MAC "
                                                    f"connue ({mac}) — fin de l'anomalie ARP", ip, mac, host,
                                                    etype="arp_restored"))
                    else:
                        findings.append(self._alert(
                            "disaster", f"USURPATION ARP probable : la MAC de la passerelle {ip} est passée de "
                                        f"{prev['mac']} à {mac} — risque d'interception du trafic (man-in-the-middle)",
                            ip, mac, host, tags=["attack.credential_access", "attack.t1557.002"]))
                elif host:                                 # équipement supervisé (pas un simple client DHCP)
                    infra = (self.db.get_host_by_id(host["id"]) or {}).get("device_type") in INFRA_TYPES
                    findings.append(self._alert(
                        "high" if infra else "average",
                        f"La MAC de {host['name']} ({ip}) a changé : {prev['mac']} → {mac} "
                        f"(changement de carte réseau légitime, ou usurpation ARP)",
                        ip, mac, host, tags=["attack.t1557.002"]))
                self.db.execute("UPDATE arp_bindings SET mac = ?, is_gateway = ?, last_seen = datetime('now') "
                                "WHERE ip = ?", (mac, int(is_gw), ip))
                self._remember(ip, mac)
            else:
                self.db.execute("UPDATE arp_bindings SET last_seen = datetime('now') WHERE ip = ?", (ip,))
        return findings

    def _alert(self, severity, desc, ip, mac, host, tags=None, etype="arp_spoof") -> dict:
        self.sink.emit(severity, etype, desc, host=host, tags=tags, extra={"ip": ip, "mac": mac})
        return {"severity": severity, "type": etype, "ip": ip, "mac": mac, "description": desc}


# ───────────────────────── DHCP ─────────────────────────

MAGIC = b"\x63\x82\x53\x63"


def build_discover(xid: int, mac: bytes) -> bytes:
    hdr = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                      b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4, mac.ljust(16, b"\0"), b"\0" * 64, b"\0" * 128)
    opts = MAGIC + b"\x35\x01\x01" + b"\x37\x04\x01\x03\x06\x33" + b"\xff"      # DISCOVER, params demandés
    return hdr + opts


def parse_reply(data: bytes, xid: int) -> Optional[dict]:
    """Décode une OFFER/ACK DHCP ; None si ce n'est pas une réponse à notre requête."""
    if len(data) < 240 or data[0] != 2 or struct.unpack("!I", data[4:8])[0] != xid or data[236:240] != MAGIC:
        return None
    out = {"offered": socket.inet_ntoa(data[16:20]), "type": None, "server": None, "router": None,
           "dns": [], "mask": None, "lease": None}
    i = 240
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        val = data[i + 2:i + 2 + ln]
        if code == 53 and ln == 1:
            out["type"] = val[0]
        elif code == 54 and ln == 4:
            out["server"] = socket.inet_ntoa(val)
        elif code == 3 and ln >= 4:
            out["router"] = socket.inet_ntoa(val[:4])
        elif code == 6 and ln >= 4:
            out["dns"] = [socket.inet_ntoa(val[j:j + 4]) for j in range(0, ln - 3, 4)]
        elif code == 1 and ln == 4:
            out["mask"] = socket.inet_ntoa(val)
        elif code == 51 and ln == 4:
            out["lease"] = struct.unpack("!I", val)[0]
        i += 2 + ln
    if out["type"] not in (2, 5):
        return None
    out["server"] = out["server"] or None
    return out


class DhcpProbe:
    def __init__(self, db, sink):
        self.db, self.sink = db, sink

    def probe(self, timeout: float = 4.0, dest: tuple = ("255.255.255.255", 67), bind: tuple = ("", 68)) -> dict:
        """Envoie un DHCPDISCOVER et collecte toutes les offres. {"servers": [...], "error": str|None}"""
        xid = random.getrandbits(32)
        try:
            mac = uuid.getnode().to_bytes(6, "big")
        except OverflowError:
            mac = os.urandom(6)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        servers: dict[str, dict] = {}
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                sock.bind(bind)
            except OSError as e:
                return {"servers": [], "error": f"port DHCP client occupé ou privilèges insuffisants ({e.strerror or e})"}
            sock.sendto(build_discover(xid, mac), dest)
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                sock.settimeout(max(0.05, end - time.monotonic()))
                try:
                    data, addr = sock.recvfrom(2048)
                except socket.timeout:
                    break
                except OSError:
                    break
                r = parse_reply(data, xid)
                if r:
                    r["server"] = r["server"] or addr[0]
                    servers.setdefault(r["server"], r)
        except OSError as e:
            return {"servers": [], "error": str(e)}
        finally:
            sock.close()
        return {"servers": list(servers.values()), "error": None}

    def trusted(self) -> list[str]:
        try:
            return json.loads(self.db.get_setting("dhcp_trusted", "") or "[]")
        except ValueError:
            return []

    def trust(self, ips: list[str]):
        self.db.set_setting("dhcp_trusted", json.dumps(sorted(set(self.trusted()) | set(ips))))

    def check(self, **probe_kw) -> dict:
        res = self.probe(**probe_kw)
        servers = [s["server"] for s in res["servers"]]
        res["alerts"] = []
        if res["error"] or not servers:
            return res
        trusted = self.trusted()
        if not trusted:
            if len(servers) == 1:                         # apprentissage : un seul serveur répond → c'est le bon
                self.trust(servers)
                logger.info(f"[DHCP] serveur de référence appris : {servers[0]}")
                return res
            self.sink.emit("high", "rogue_dhcp",
                           f"{len(servers)} serveurs DHCP répondent sur le réseau ({', '.join(servers)}) : "
                           f"l'un d'eux est peut-être un faux serveur. Vérifiez puis marquez le bon comme fiable.",
                           tags=["attack.credential_access", "attack.t1557.003"])
            res["alerts"].append("multiple")
            return res
        rogue = [s for s in res["servers"] if s["server"] not in trusted]
        for s in rogue:
            self.sink.emit("disaster", "rogue_dhcp",
                           f"SERVEUR DHCP NON AUTORISÉ : {s['server']} propose {s['offered']} "
                           f"(passerelle {s['router'] or '?'}, DNS {', '.join(s['dns']) or '?'}) — "
                           f"serveur de confiance : {', '.join(trusted)}",
                           tags=["attack.credential_access", "attack.t1557.003"], extra={"ip": s["server"]})
            res["alerts"].append(s["server"])
        return res
