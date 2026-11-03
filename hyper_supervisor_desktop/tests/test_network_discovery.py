"""Ajout d'un réseau (IP routeur / CIDR) : découverte, enregistrement, alertes, topologie."""
import asyncio
import json
import sqlite3

import pytest

from core import local_network as lnet
from core.network_setup import NetworkSetupWorker


def test_parse_input_router_ip_and_cidr_and_refusals():
    assert lnet.parse_network_input("192.168.1.1") == {"cidr": "192.168.1.0/24", "gateway_ip": "192.168.1.1", "num_hosts": 254}
    assert lnet.parse_network_input("10.1.2.0/23")["num_hosts"] == 510
    for bad in ("8.8.8.8", "192.168.0.0/16", "10.0.0.0/8", "127.0.0.1", "abc", "", "192.168.1.0/31", "::1"):
        with pytest.raises(ValueError):
            lnet.parse_network_input(bad)


def test_arp_parsing_all_platforms_and_vendors():
    txt = ("  192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic\n  192.168.1.255  ff-ff-ff-ff-ff-ff  static\n"
           "? (192.168.1.5) at b8:27:eb:11:22:33 on en0\n192.168.1.9 dev eth0 lladdr 02:00:00:00:00:01 REACHABLE\n"
           "192.168.1.7 dev eth0  FAILED\n224.0.0.22 01-00-5e-00-00-16 static")
    t = lnet.parse_arp_output(txt)
    assert t == {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "192.168.1.5": "b8:27:eb:11:22:33", "192.168.1.9": "02:00:00:00:00:01"}
    assert lnet.mac_vendor("b8:27:eb:11:22:33") == "Raspberry Pi"
    assert lnet.mac_vendor("02:00:00:00:00:01").startswith("Adresse privée")


def test_device_type_guess():
    g = lnet.guess_device_type
    assert g(set(), "", is_gateway=True) == "router"
    assert g({9100}) == "printer" and g({445, 3389}) == "workstation" and g({22, 80}) == "server"
    assert g(set(), "Adresse privée (smartphone / PC)") == "mobile" and g(set(), "") == "unknown"


def test_real_tcp_probe_finds_open_port(monkeypatch):
    async def run():
        srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        monkeypatch.setattr(lnet, "PROBE_PORTS", (port,))
        found = await lnet._discover_net_async(["127.0.0.1"], 0.5, 8)
        srv.close()
        return port, found
    port, found = asyncio.run(run())
    assert found and port in found[0]["open_ports"]


def _fake_discovery(monkeypatch, devices):
    monkeypatch.setattr(lnet, "_discover_net_async", lambda targets, t, c: _coro(
        [{"ip": ip, "latency_ms": 1.0, "open_ports": set(p)} for ip, p in devices.items()]))
    monkeypatch.setattr(lnet, "read_arp_table", lambda: {"192.168.7.50": "02:11:22:33:44:55",
                                                         "192.168.7.1": "24:a4:3c:00:00:01"})
    monkeypatch.setattr(lnet, "_reverse_dns", lambda ip: "")


async def _coro(v):
    return v


def test_discover_includes_arp_only_devices_and_router(monkeypatch):
    _fake_discovery(monkeypatch, {"192.168.7.20": [22, 80], "192.168.7.30": [445]})
    res = {d["ip"]: d for d in lnet.discover_network("192.168.7.1")}
    assert set(res) == {"192.168.7.1", "192.168.7.20", "192.168.7.30", "192.168.7.50"}
    assert res["192.168.7.1"]["device_type"] == "router"
    assert res["192.168.7.50"]["device_type"] == "mobile"        # vu uniquement par ARP (MAC aléatoire)
    assert res["192.168.7.20"]["device_type"] == "server" and res["192.168.7.30"]["device_type"] == "workstation"


def test_worker_registers_monitors_and_alerts_only_on_new_after_baseline(db, monkeypatch):
    devices = {"192.168.7.20": [22, 80]}
    _fake_discovery(monkeypatch, devices)
    nid = db.add_network("Bureau", "192.168.7.0/24", "192.168.7.1", "wifi")
    w = NetworkSetupWorker(db=db)
    alerts, done = [], []
    w.new_device.connect(alerts.append)
    w.network_discovered.connect(lambda *a: done.append(a))

    w.discover_network(nid)                                       # 1re découverte = référence
    hosts = [h for h in db.get_all_hosts() if h["network_id"] == nid]
    assert {h["ip_address"] for h in hosts} == {"192.168.7.1", "192.168.7.20", "192.168.7.50"}
    assert alerts == [] and done[0][:2] == (nid, 3)
    assert all(h["snmp_enabled"] == 0 and h["icmp_enabled"] == 1 for h in hosts)   # surveillés (ping/TCP), pas de SNMP forcé
    assert db.get_networks()[0]["host_count"] == 3

    devices["192.168.7.99"] = [3389]                              # un équipement inconnu apparaît
    w.rediscover_all()
    assert len(alerts) == 1 and alerts[0]["event_type"] == "new_device" and "192.168.7.99" in alerts[0]["description"]
    assert alerts[0]["severity"] == "average"                     # → déclenche les notifications
    assert any(e["event_type"] == "new_device" for e in db.get_events())
    w.rediscover_all()
    assert len(alerts) == 1                                       # pas de doublon


def test_auto_monitor_off_is_not_rediscovered(db, monkeypatch):
    _fake_discovery(monkeypatch, {})
    nid = db.add_network("Manuel", "192.168.7.0/24", None, "lan", auto_monitor=0)
    w = NetworkSetupWorker(db=db)
    w.rediscover_all()
    assert db.get_networks()[0]["last_discovery"] is None


def test_duplicate_network_rejected_and_delete(db):
    db.add_network("A", "10.9.0.0/24")
    with pytest.raises(__import__("database.crypto_db", fromlist=["x"]).INTEGRITY_ERRORS):
        db.add_network("B", "10.9.0.0/24")
    hid = db.add_host("h", "10.9.0.5")
    nid = db.get_networks()[0]["id"]
    db.update_host_identity(hid, network_id=nid)
    db.delete_network(nid)                                        # garde les équipements
    assert db.get_host_by_id(hid)["network_id"] is None
    nid2 = db.add_network("C", "10.8.0.0/24"); db.update_host_identity(hid, network_id=nid2)
    db.delete_network(nid2, delete_hosts=True)
    assert db.get_host_by_id(hid) is None


def test_migration_adds_columns_to_old_database(tmp_path):
    from database.db_manager import DatabaseManager
    p = str(tmp_path / "old.db")
    c = sqlite3.connect(p)
    c.executescript("CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT UNIQUE, ip_address TEXT, group_id INTEGER, "
                    "device_type TEXT, location TEXT, snmp_community TEXT, snmp_version TEXT, snmp_port INTEGER, "
                    "agent_enabled INTEGER, snmp_enabled INTEGER, icmp_enabled INTEGER, status TEXT, last_check TEXT, "
                    "created_at TEXT, updated_at TEXT);")
    c.commit(); c.close()
    d = DatabaseManager(p); d.initialize()
    cols = {r[1] for r in d._conn.execute("PRAGMA table_info(hosts)")}
    assert {"mac_address", "vendor", "network_id", "first_seen"} <= cols
    d.close()


def test_layout_clusters_gateway_center_and_links():
    from ui.widgets.topology_view import compute_layout
    nets = [{"id": 1, "name": "Wi-Fi", "cidr": "192.168.7.0/24", "gateway_ip": "192.168.7.1"},
            {"id": 2, "name": "Labo", "cidr": "10.0.0.0/24", "gateway_ip": None}]
    hosts = [{"id": 1, "ip_address": "192.168.7.1", "device_type": "router", "network_id": 1, "name": "gw"}]
    hosts += [{"id": 10 + i, "ip_address": f"192.168.7.{20+i}", "network_id": 1, "name": f"h{i}"} for i in range(30)]
    hosts += [{"id": 100 + i, "ip_address": f"10.0.0.{i+2}", "network_id": 2, "name": f"l{i}"} for i in range(3)]
    hosts += [{"id": 200, "ip_address": "172.16.0.9", "network_id": None, "name": "solo"}]
    L = compute_layout(hosts, nets)
    ids = [n["id"] for n in L["nodes"]]
    assert len(ids) == len(set(ids))                               # aucun doublon
    assert (1, 10) in L["links"] and len([l for l in L["links"] if l[0] == 1]) == 30   # tout relié au routeur
    assert any(n["kind"] == "hub" for n in L["nodes"])             # réseau sans routeur → nœud réseau virtuel
    assert len(L["clusters"]) == 3
    pos = {(round(n["x"]), round(n["y"])) for n in L["nodes"]}
    assert len(pos) == len(L["nodes"])                             # pas de superposition exacte


def test_topology_view_add_network_flow(db, qtbot, monkeypatch):
    from PyQt6.QtWidgets import QDialog
    from ui.widgets import topology_view as tv
    from PyQt6.QtWidgets import QMessageBox
    shown = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: shown.append(a[2]))
    v = tv.TopologyView(db=db); qtbot.addWidget(v)
    got = []
    v.network_scan_requested.connect(got.append)
    monkeypatch.setattr(tv.AddNetworkDialog, "exec", lambda self: (
        self._f_target.setText("192.168.50.1"), self._f_name.setText("Wi-Fi maison"),
        self._chk_auth.setChecked(True), self._validate(), QDialog.DialogCode.Accepted)[-1])
    v._add_network()
    n = db.get_networks()
    assert n[0]["cidr"] == "192.168.50.0/24" and n[0]["gateway_ip"] == "192.168.50.1" and n[0]["name"] == "Wi-Fi maison"
    assert got == [n[0]["id"]]
    v._add_network()                                               # doublon refusé, pas de 2e scan
    assert len(db.get_networks()) == 1 and len(got) == 1 and "déjà" in shown[-1]


def test_add_dialog_requires_authorization_and_valid_target(qtbot, monkeypatch):
    from ui.widgets import topology_view as tv
    from PyQt6.QtWidgets import QMessageBox
    msgs = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: msgs.append(a[2]))
    d = tv.AddNetworkDialog(); qtbot.addWidget(d)
    d._f_target.setText("8.8.8.8"); d._validate()
    assert "privé" in msgs[-1] and d.result() == 0
    d._f_target.setText("192.168.1.1"); d._validate()
    assert "autorisé" in msgs[-1] and d.result() == 0


def test_topology_view_shows_discovered_devices_and_live_status(db, qtbot):
    from ui.widgets.topology_view import TopologyView
    nid = db.add_network("Bureau", "192.168.7.0/24", "192.168.7.1")
    gw = db.add_host("gw", "192.168.7.1", device_type="router")
    ids = [db.add_host(f"pc{i}", f"192.168.7.{10+i}", device_type="workstation") for i in range(5)]
    for h in [gw] + ids:
        db.update_host_identity(h, network_id=nid)
    v = TopologyView(db=db); qtbot.addWidget(v); v.show()
    assert len(v._canvas._nodes) == 6
    db.update_host_status(ids[0], "offline", "2026-10-14T10:00:00")
    v.refresh_statuses()
    assert v._canvas._nodes[ids[0]]["host"]["status"] == "offline"
    v._show_detail(db.get_all_hosts()[0])
    assert v._detail_fields["Réseau"].text().startswith("Bureau")
