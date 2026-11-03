import socket, time, pytest
from tests.snmp_agent import SnmpAgent
from core.monitor import MonitorWorker

def free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

@pytest.fixture()
def agent():
    counter = {"n": 0}
    def octets(): counter["n"] += 1_250_000; return counter["n"]       # +1,25 Mo à chaque lecture
    a = SnmpAgent(free_udp(), community="s3cret", values={
        (1,3,6,1,2,1,1,3,0): 123456,
        (1,3,6,1,2,1,25,3,3,1,2,1): 40, (1,3,6,1,2,1,25,3,3,1,2,2): 60,        # CPU moyen = 50 %
        (1,3,6,1,4,1,2021,4,5,0): 1_000_000, (1,3,6,1,4,1,2021,4,6,0): 250_000,   # RAM 75 % utilisée
        (1,3,6,1,2,1,2,2,1,2,1): "lo", (1,3,6,1,2,1,2,2,1,2,2): "eth0",
        (1,3,6,1,2,1,2,2,1,10,1): 999999, (1,3,6,1,2,1,2,2,1,10,2): octets,
        (1,3,6,1,2,1,2,2,1,16,1): 999999, (1,3,6,1,2,1,2,2,1,16,2): octets,
    })
    a.start(); yield a; a.stop()

def test_get_walk_and_wrong_community(agent):
    m = MonitorWorker()
    assert int(str(m._snmp_get("127.0.0.1", "1.3.6.1.4.1.2021.4.5.0", "s3cret", port=agent.port, timeout=1, retries=0))) == 1_000_000
    assert len(m._snmp_walk("127.0.0.1", "1.3.6.1.2.1.25.3.3.1.2", "s3cret", port=agent.port, timeout=1)) == 2
    assert m._snmp_get("127.0.0.1", "1.3.6.1.4.1.2021.4.5.0", "mauvaise", port=agent.port, timeout=1, retries=0) is None
    assert m._snmp_get("127.0.0.1", "1.3.6.1.9.9.9.0", "s3cret", port=agent.port, timeout=1, retries=0) is None   # OID absent
    assert m._snmp_get("127.0.0.1", "1.3.6.1.4.1.2021.4.5.0", "s3cret", port=free_udp(), timeout=1, retries=0) is None  # agent absent

def test_full_collection_cpu_mem_bandwidth(agent, db):
    hid = db.add_host("sw", "127.0.0.1", snmp_community="s3cret")
    m = MonitorWorker(db_manager=db); got = []
    m.metrics_ready.connect(got.append)
    m.collect_host_metrics(hid, "127.0.0.1", "sw", "s3cret", port=agent.port)       # 1er cycle : mémorise les compteurs
    assert got[0]["metrics"]["cpu_util"] == pytest.approx(50.0)
    assert got[0]["metrics"]["mem_used_pct"] == pytest.approx(75.0)
    assert "bw_in_mbps" not in got[0]["metrics"]                                    # pas de delta au 1er cycle
    time.sleep(1.0)
    m.collect_host_metrics(hid, "127.0.0.1", "sw", "s3cret", port=agent.port)       # 2e cycle : débit réel
    bw = got[1]["metrics"]
    assert bw["bw_in_mbps"] > 1 and bw["bw_out_mbps"] > 1                           # loopback 'lo' exclu, eth0 compté
    stored = {r["metric_name"] for r in db.fetchall("SELECT DISTINCT metric_name FROM metrics WHERE host_id=?", (hid,))}
    assert {"cpu_util", "mem_used", "bw_in", "bw_out"} <= stored
    assert db.get_bandwidth_series(hid, 1, 5)                                       # alimente le graphe du dashboard

def test_wrong_community_collects_nothing_but_does_not_crash(agent, db):
    hid = db.add_host("sw", "127.0.0.1"); m = MonitorWorker(db_manager=db); got = []
    m.metrics_ready.connect(got.append); logs = []; m.log_message.connect(lambda l, t: logs.append(t))
    m.collect_host_metrics(hid, "127.0.0.1", "sw", "faux", port=agent.port)
    assert got[0]["metrics"] == {} and any("aucune réponse SNMP" in t for t in logs)


def test_unreachable_then_online_transition(db, monkeypatch):
    """Hôte qui répond au ping mais SNMP muet -> 'unreachable' + événement ; SNMP rétabli -> 'online'."""
    import core.local_network as lnet
    port = free_udp()
    hid = db.add_host("sw2", "127.0.0.1", snmp_community="s3cret")
    db.execute("UPDATE hosts SET snmp_enabled=1, snmp_port=?, status='online' WHERE id=?", (port, hid))
    monkeypatch.setattr(lnet, "probe_host_ex", lambda ip, *a, **k: {"alive": True, "latency_ms": 1.0, "method": "tcp"})
    monkeypatch.setattr(lnet, "is_local_address", lambda ip: False)
    m = MonitorWorker(db_manager=db)
    m.collect_all()
    assert db.get_host_by_id(hid)["status"] == "unreachable"
    assert db.fetchone("SELECT 1 FROM events WHERE host_id=? AND event_type='snmp_down'", (hid,))
    a = SnmpAgent(port, community="s3cret", values={(1,3,6,1,2,1,1,3,0): 42}); a.start()
    try:
        m.collect_all()
    finally:
        a.stop()
    assert db.get_host_by_id(hid)["status"] == "online"
    assert db.fetchone("SELECT 1 FROM events WHERE host_id=? AND event_type='host_up'", (hid,))


def test_sfp_collection_and_low_rx_alert(db):
    base = "1.3.6.1.4.1.9.9.412.1.1.1.1"
    vals = {(1,3,6,1,4,1,9,9,412,1,1,1,1,6,1001): -55,     # RX -5.5 dBm (ok)
            (1,3,6,1,4,1,9,9,412,1,1,1,1,6,1002): -250,    # RX -25 dBm (perte de signal)
            (1,3,6,1,4,1,9,9,412,1,1,1,1,7,1001): -20,
            (1,3,6,1,4,1,9,9,412,1,1,1,1,7,1002): -30}
    a = SnmpAgent(free_udp(), community="s3cret", values=vals); a.start()
    try:
        hid = db.add_host("core", "127.0.0.1", snmp_community="s3cret")
        m = MonitorWorker(db_manager=db)
        import core.monitor as mon
        orig = m._snmp_walk
        m._snmp_walk = lambda ip, oid, comm, **kw: orig(ip, oid, comm, port=a.port, timeout=1, **{k: v for k, v in kw.items() if k not in ("port", "timeout")})
        m.collect_sfp_metrics(hid, "127.0.0.1", "core", "s3cret")
    finally:
        a.stop()
    rows = db.fetchall("SELECT interface, rx_power_dbm FROM sfp_metrics WHERE host_id=? ORDER BY interface", (hid,))
    assert len(rows) == 2 and sorted(r["rx_power_dbm"] for r in rows) == [-25.0, -5.5]
    assert db.fetchone("SELECT 1 FROM events WHERE host_id=? AND description LIKE '%Perte signal SFP%' AND severity='high'", (hid,))
