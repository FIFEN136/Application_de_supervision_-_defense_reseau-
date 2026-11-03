import socket, time
import pytest
from core.flows import (FlowStore, parse_netflow_v5, build_netflow_v5, NetflowCollector, ingest_connections, proto_name)
from core import classify, netmap
from core.netmap import NetMapper


def add_host(db, name, ip, dtype="unknown", mac=None, vendor=None):
    hid = db.execute("INSERT INTO hosts (name, ip_address, device_type) VALUES (?,?,?)", (name, ip, dtype)).lastrowid
    if mac or vendor:
        db.execute("UPDATE hosts SET mac_address=?, vendor=? WHERE id=?", (mac, vendor, hid))
    return hid


def test_flowstore_aggregates_and_ignores_garbage(db):
    fs = FlowStore(db)
    assert fs.add("192.168.1.10", "192.168.1.20", "tcp", 445, 1000, 10)
    assert fs.add("192.168.1.10", "192.168.1.20", 6, 445, 500, 5)
    assert not fs.add("192.168.1.10", "224.0.0.251", "udp", 5353)          # multicast
    assert not fs.add("pas-une-ip", "192.168.1.20", "tcp", 80)
    assert not fs.add("0.0.0.0", "192.168.1.20", "tcp", 80)
    row = db.fetchone("SELECT * FROM flows_agg")
    assert fs.count() == 1 and row["flows"] == 2 and row["bytes"] == 1500 and row["dst_port"] == 445
    assert fs.top(5, by="bytes; DROP TABLE hosts")[0]["bytes"] == 1500       # colonne en liste blanche
    assert proto_name(17) == "udp" and proto_name("ICMP") == "icmp" and proto_name(99) == "other"


def test_netflow_v5_parse_roundtrip_and_rejects_malformed():
    pkt = build_netflow_v5([{"src": "10.0.0.5", "dst": "10.0.0.9", "dport": 443, "proto": 6, "bytes": 1234, "packets": 3}])
    r = parse_netflow_v5(pkt)
    assert r == [{"src": "10.0.0.5", "dst": "10.0.0.9", "packets": 3, "bytes": 1234, "dport": 443, "proto": 6, "flows": 1}]
    assert parse_netflow_v5(pkt[:-1]) == [] and parse_netflow_v5(b"") == [] and parse_netflow_v5(b"\x00" * 100) == []
    sampled = parse_netflow_v5(build_netflow_v5([{"src": "10.0.0.5", "dst": "10.0.0.9", "bytes": 100, "packets": 1}], sampling=10))
    assert sampled[0]["bytes"] == 1000                                         # échantillonnage 1/10 rétabli


def test_netflow_collector_receives_real_udp_and_filters_exporters(db):
    fs = FlowStore(db)
    c = NetflowCollector(fs, port=0, bind="127.0.0.1"); assert c.start()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(build_netflow_v5([{"src": "10.1.1.1", "dst": "10.2.2.2", "dport": 22, "proto": 6}]), ("127.0.0.1", c.port))
    end = time.time() + 3
    while time.time() < end and fs.count() == 0: time.sleep(0.05)
    assert fs.count() == 1 and c.received == 1
    c.stop()
    c2 = NetflowCollector(FlowStore(db), port=0, bind="127.0.0.1", allowed={"10.9.9.9"}); assert c2.start()
    s.sendto(build_netflow_v5([{"src": "10.5.5.5", "dst": "10.6.6.6"}]), ("127.0.0.1", c2.port)); time.sleep(0.4)
    assert c2.refused == 1 and c2.received == 0
    c2.stop()


def test_collector_reports_busy_port_without_crash(db):
    b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); b.bind(("127.0.0.1", 0))
    c = NetflowCollector(FlowStore(db), port=b.getsockname()[1], bind="127.0.0.1")
    assert not c.start() and "indisponible" in c.error
    b.close()


def test_ingest_connections_direction(db):
    fs = FlowStore(db)
    n = ingest_connections(fs, [{"laddr": "10.0.0.2", "lport": 22, "raddr": "10.0.0.50", "rport": 51000, "dir": "in"},
                                {"laddr": "10.0.0.2", "lport": 40000, "raddr": "10.0.0.9", "rport": 443, "dir": "out"},
                                "garbage", {"laddr": "x"}], "agent:a1")
    assert n == 2
    rows = {(r["src_ip"], r["dst_ip"], r["dst_port"]) for r in fs.all()}
    assert rows == {("10.0.0.50", "10.0.0.2", 22), ("10.0.0.2", "10.0.0.9", 443)}


def test_classification_roles_manual_never_overwritten(db):
    h1 = add_host(db, "srv", "10.0.0.10", "server")
    h2 = add_host(db, "cam-hall", "10.0.0.11")
    h3 = add_host(db, "iot1", "10.0.0.12", vendor="Espressif (IoT)")
    h4 = add_host(db, "x", "10.0.0.13")
    db.execute("INSERT INTO port_states (host_id, port, protocol, state) VALUES (?,3389,'TCP','open')", (h4,))
    r = classify.classify_hosts(db)
    assert r["classified"] == 4
    assert [classify.role_of(db, h) for h in (h1, h2, h3, h4)] == ["server", "camera", "iot", "workstation"]
    classify.set_role(db, h4, "admin", "admin")
    r = classify.classify_hosts(db)
    assert classify.role_of(db, h4) == "admin" and r["kept_manual"] == 1
    with pytest.raises(ValueError): classify.set_role(db, h4, "pirate")
    with pytest.raises(ValueError): classify.set_role(db, 9999, "server")
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='host_role_set'")


def test_zones_sync_keep_manual_and_most_specific(db):
    db.execute("INSERT INTO networks (name, cidr, gateway_ip, kind) VALUES ('LAN','192.168.1.0/24','192.168.1.1','lan')")
    db.execute("INSERT INTO networks (name, cidr, gateway_ip, kind) VALUES ('Invités','192.168.50.0/24','192.168.50.1','wifi')")
    assert classify.sync_zones(db) == 2 and classify.sync_zones(db) == 0
    z = {r["name"]: r for r in db.fetchall("SELECT * FROM net_zones")}
    assert z["Invités"]["trust"] == 5 and z["LAN"]["trust"] == 60
    classify.set_zone(db, "Serveurs", "192.168.1.128/25", 90)
    assert classify.zone_of_ip(db, "192.168.1.200")["name"] == "Serveurs"
    assert classify.zone_of_ip(db, "192.168.1.20")["name"] == "LAN"
    assert classify.zone_of_ip(db, "8.8.8.8") is None and classify.zone_of_ip(db, "nope") is None
    for bad in (("", "10.0.0.0/8", 5), ("Z", "pas-un-reseau", 5), ("Z", "10.0.0.0/8", 150)):
        with pytest.raises(ValueError): classify.set_zone(db, *bad)


def fake_walker_factory(tables):
    def walker(ip, oid, comm, port, ver):
        return tables.get(oid, [])
    return walker


def test_netmap_parses_lldp_routes_fdb_and_locates_device(db):
    sw = add_host(db, "sw1", "192.168.1.2", "switch")
    t = {
        netmap.OID_LLDP_NAME: [(f"{netmap.OID_LLDP_NAME}.0.3.1", "core-router")],
        netmap.OID_LLDP_PORTID: [(f"{netmap.OID_LLDP_PORTID}.0.3.1", "Gi0/1")],
        netmap.OID_ROUTE_NH: [(f"{netmap.OID_ROUTE_NH}.0.0.0.0", "192.168.1.1"), (f"{netmap.OID_ROUTE_NH}.10.0.0.0", "0.0.0.0"),
                              (f"{netmap.OID_ROUTE_NH}.999.1.1.1", "x")],
        netmap.OID_ROUTE_MASK: [(f"{netmap.OID_ROUTE_MASK}.0.0.0.0", "0.0.0.0"), (f"{netmap.OID_ROUTE_MASK}.10.0.0.0", "255.0.0.0")],
        netmap.OID_FDB_PORT: [(f"{netmap.OID_FDB_PORT}.170.187.204.221.238.1", "5"), (f"{netmap.OID_FDB_PORT}.170.187.204.221.238.2", "1"),
                              (f"{netmap.OID_FDB_PORT}.170.187.204.221.238.3", "1")],
        netmap.OID_BRIDGE_IFINDEX: [(f"{netmap.OID_BRIDGE_IFINDEX}.5", "10005"), (f"{netmap.OID_BRIDGE_IFINDEX}.1", "10001")],
        netmap.OID_IFNAME: [(f"{netmap.OID_IFNAME}.10005", "Gi0/5"), (f"{netmap.OID_IFNAME}.10001", "Gi0/1")],
    }
    nm = NetMapper(db, fake_walker_factory(t))
    r = nm.collect_all()
    assert r == {"hosts": 1, "links": 1, "routes": 2, "fdb": 3}
    assert db.fetchone("SELECT remote_name, remote_port FROM net_links")["remote_name"] == "core-router"
    assert {(x["dest"], x["mask"], x["nexthop"]) for x in db.fetchall("SELECT * FROM net_routes")} == {
        ("0.0.0.0", "0.0.0.0", "192.168.1.1"), ("10.0.0.0", "255.0.0.0", "")}
    loc = nm.where_is("aa:bb:cc:dd:ee:01")
    assert loc["switch"] == "sw1" and loc["port"] == "Gi0/5" and loc["macs_on_port"] == 1       # port d'accès, pas l'uplink Gi0/1
    assert nm.where_is("00:00:00:00:00:99") is None
    # une collecte vide ne supprime pas l'existant
    NetMapper(db, fake_walker_factory({})).collect_all()
    assert db.fetchone("SELECT COUNT(*) n FROM net_fdb")["n"] == 3


def test_netmap_skips_non_network_devices_and_enforcement_points(db):
    add_host(db, "srv", "192.168.1.5", "server")
    called = []
    NetMapper(db, lambda *a: called.append(a) or []).collect_all()
    assert not called
    add_host(db, "gw", "192.168.1.1", "router")
    db.execute("INSERT INTO networks (name, cidr, gateway_ip) VALUES ('LAN','192.168.1.0/24','192.168.1.1')")
    db.execute("INSERT INTO networks (name, cidr, gateway_ip) VALUES ('Autre','10.9.0.0/24','10.9.0.1')")
    ep = {e["network"]: e for e in NetMapper(db).enforcement_points()}
    assert ep["LAN"]["can_enforce"] and ep["LAN"]["device"] == "gw"
    assert not ep["Autre"]["known"] and not ep["Autre"]["can_enforce"]
