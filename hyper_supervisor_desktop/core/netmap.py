"""
Procus Secure — cartographie couches 2 et 3 par SNMP (v15, bloc 1). LECTURE SEULE.

Collecte, sur les équipements réseau supervisés : voisins LLDP, table MAC (FDB) des commutateurs, routes IPv4.
Sert à savoir OÙ une règle doit s'appliquer (quel équipement relie quel réseau) et sur quel port se trouve un
appareil donné (pour une future mise en quarantaine). Aucune écriture SNMP n'est jamais émise.
Limites : table de routes « ipRouteTable » (ancienne) seulement ; certains équipements n'exposent pas LLDP/FDB en
SNMPv2c ; la table MAC est limitée aux VLAN que l'équipement publie sous cette communauté.
"""
from __future__ import annotations

import contextlib
import asyncio
import ipaddress
from typing import Callable, Optional

from loguru import logger

OID_LLDP_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
OID_LLDP_PORTID = "1.0.8802.1.1.2.1.4.1.1.7"
OID_ROUTE_NH = "1.3.6.1.2.1.4.21.1.7"
OID_ROUTE_MASK = "1.3.6.1.2.1.4.21.1.11"
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
OID_BRIDGE_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
NETWORK_TYPES = ("router", "switch", "firewall", "ap", "unknown")


def snmp_walk_oids(ip: str, oid: str, community: str = "public", port: int = 161, version: str = "2c",
                   timeout: int = 2) -> list[tuple[str, str]]:
    """WALK retournant les OID COMPLETS [(oid, valeur)] (les tables à index multiples en ont besoin). [] si échec."""
    try:
        from pysnmp.hlapi.asyncio import (walkCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                                          ObjectType, ObjectIdentity)

        async def _walk():
            eng, out = SnmpEngine(), []
            try:
                walker = walkCmd(
                    eng, CommunityData(community, mpModel=0 if version == "1" else 1),
                    UdpTransportTarget((ip, port), timeout=timeout, retries=1), ContextData(),
                    ObjectType(ObjectIdentity(oid)), lexicographicMode=False)
                async with contextlib.aclosing(walker):             # fermeture propre du générateur (plus d'avertissement au « break »)
                    async for ei, es, _, vbs in walker:
                        if ei or es:
                            break
                        for name, val in vbs:
                            out.append((str(name), val.prettyPrint()))
                        if len(out) > 20000:
                            break
            finally:
                try:
                    eng.closeDispatcher()
                except Exception:
                    pass
            return out
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_walk())
        finally:
            loop.close()
    except Exception as e:
        logger.debug(f"[NETMAP] WALK {ip} {oid} : {e}")
        return []


def _suffix(full: str, base: str) -> list[str]:
    return full[len(base):].lstrip(".").split(".") if full.startswith(base) else []


def parse_lldp(names: list, portids: list) -> list[dict]:
    """Index = timeMark.localPort.remIndex ; retourne [{'local_port','remote_name','remote_port'}]."""
    ports = {}
    for oid, v in portids:
        s = _suffix(oid, OID_LLDP_PORTID)
        if len(s) >= 3:
            ports[(s[1], s[2])] = v
    out = []
    for oid, v in names:
        s = _suffix(oid, OID_LLDP_NAME)
        if len(s) >= 3 and v:
            out.append({"local_port": s[1], "remote_name": str(v)[:80], "remote_port": str(ports.get((s[1], s[2]), ""))[:60]})
    return out


def parse_routes(nexthops: list, masks: list) -> list[dict]:
    m = {}
    for oid, v in masks:
        s = _suffix(oid, OID_ROUTE_MASK)
        if len(s) == 4:
            m[".".join(s)] = v
    out = []
    for oid, v in nexthops:
        s = _suffix(oid, OID_ROUTE_NH)
        if len(s) != 4:
            continue
        dest = ".".join(s)
        try:
            ipaddress.ip_address(dest)
            mask = m.get(dest, "255.255.255.255")
            ipaddress.ip_address(mask)
            nh = v if v and v != "0.0.0.0" else ""
            if nh:
                ipaddress.ip_address(nh)
        except ValueError:
            continue
        out.append({"dest": dest, "mask": mask, "nexthop": nh})
    return out


def parse_fdb(ports: list, ifindex: list, ifnames: list) -> list[dict]:
    idx = {}
    for oid, v in ifindex:
        s = _suffix(oid, OID_BRIDGE_IFINDEX)
        if len(s) == 1:
            idx[s[0]] = v
    names = {}
    for oid, v in ifnames:
        s = _suffix(oid, OID_IFNAME)
        if len(s) == 1:
            names[s[0]] = v
    out = []
    for oid, v in ports:
        s = _suffix(oid, OID_FDB_PORT)
        if len(s) != 6 or not str(v).isdigit() or int(v) == 0:
            continue
        try:
            mac = ":".join(f"{int(x):02x}" for x in s)
        except ValueError:
            continue
        bp = str(v)
        port = names.get(idx.get(bp, ""), "") or f"port {bp}"
        out.append({"mac": mac, "port": port[:40]})
    return out


class NetMapper:
    def __init__(self, db, walker: Optional[Callable] = None):
        self.db = db
        self.walker = walker or snmp_walk_oids

    def _walk(self, host: dict, oid: str) -> list:
        return self.walker(host["ip_address"], oid, host.get("snmp_community") or "public",
                           int(host.get("snmp_port") or 161), host.get("snmp_version") or "2c")

    def collect_host(self, host: dict) -> dict:
        res = {"links": 0, "routes": 0, "fdb": 0}
        hid = host["id"]
        names, pids = self._walk(host, OID_LLDP_NAME), self._walk(host, OID_LLDP_PORTID)
        links = parse_lldp(names, pids)
        if links:                                            # une collecte vide ne supprime jamais l'existant
            self.db.execute("DELETE FROM net_links WHERE host_id = ?", (hid,))
            for l in links:
                self.db.execute("INSERT OR REPLACE INTO net_links (host_id, local_port, remote_name, remote_port) VALUES (?,?,?,?)",
                                (hid, l["local_port"], l["remote_name"], l["remote_port"]))
            res["links"] = len(links)
        routes = parse_routes(self._walk(host, OID_ROUTE_NH), self._walk(host, OID_ROUTE_MASK))
        if routes:
            self.db.execute("DELETE FROM net_routes WHERE host_id = ?", (hid,))
            for r in routes:
                self.db.execute("INSERT OR REPLACE INTO net_routes (host_id, dest, mask, nexthop) VALUES (?,?,?,?)",
                                (hid, r["dest"], r["mask"], r["nexthop"]))
            res["routes"] = len(routes)
        fdb = parse_fdb(self._walk(host, OID_FDB_PORT), self._walk(host, OID_BRIDGE_IFINDEX), self._walk(host, OID_IFNAME))
        if fdb:
            self.db.execute("DELETE FROM net_fdb WHERE host_id = ?", (hid,))
            for f in fdb:
                self.db.execute("INSERT OR REPLACE INTO net_fdb (host_id, mac, port) VALUES (?,?,?)", (hid, f["mac"], f["port"]))
            res["fdb"] = len(fdb)
        return res

    def collect_all(self) -> dict:
        total = {"hosts": 0, "links": 0, "routes": 0, "fdb": 0}
        for h in self.db.fetchall("SELECT * FROM hosts WHERE snmp_enabled = 1"):
            if (h.get("device_type") or "unknown") not in NETWORK_TYPES:
                continue
            try:
                r = self.collect_host(h)
            except Exception as e:
                logger.debug(f"[NETMAP] {h['name']} : {e}")
                continue
            if any(r.values()):
                total["hosts"] += 1
                for k in ("links", "routes", "fdb"):
                    total[k] += r[k]
        return total

    # ───────────── exploitation ─────────────
    def where_is(self, mac: str) -> Optional[dict]:
        """Commutateur et port d'un appareil : le port qui connaît le moins d'adresses MAC (port d'accès, pas liaison montante)."""
        mac = (mac or "").lower()
        rows = self.db.fetchall("SELECT host_id, port FROM net_fdb WHERE mac = ?", (mac,))
        best = None
        for r in rows:
            n = self.db.fetchone("SELECT COUNT(*) n FROM net_fdb WHERE host_id = ? AND port = ?", (r["host_id"], r["port"]))["n"]
            if best is None or n < best[0]:
                best = (n, r)
        if not best:
            return None
        h = self.db.get_host_by_id(best[1]["host_id"]) or {}
        return {"switch": h.get("name"), "switch_id": best[1]["host_id"], "port": best[1]["port"], "macs_on_port": best[0]}

    def enforcement_points(self) -> list[dict]:
        """Pour chaque réseau supervisé : l'équipement qui le relie au reste (candidat à l'application de règles)."""
        out = []
        for net in self.db.fetchall("SELECT * FROM networks"):
            gw = net.get("gateway_ip")
            dev = self.db.fetchone("SELECT id, name, device_type FROM hosts WHERE ip_address = ?", (gw,)) if gw else None
            out.append({"network": net["name"], "cidr": net["cidr"], "gateway_ip": gw,
                        "device": dev["name"] if dev else None, "device_id": dev["id"] if dev else None,
                        "device_type": dev["device_type"] if dev else None,
                        "can_enforce": bool(dev and dev["device_type"] in ("router", "firewall")),
                        "known": bool(dev)})
        return out
