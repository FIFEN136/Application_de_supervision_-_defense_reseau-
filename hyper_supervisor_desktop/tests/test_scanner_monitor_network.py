import socket, sys, time, threading, pytest
from PyQt6.QtCore import QCoreApplication
from core.scanner import ScannerWorker
from core.monitor import MonitorWorker
from core import local_network as lnet


class Listener:
    """Vrai serveur TCP local qu'on peut ouvrir/fermer pour simuler un changement de port."""
    def __init__(self, port=0):
        self.port = port; self.sock = None; self.open()
    def open(self):
        self.sock = socket.socket(); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port)); self.sock.listen(50); self.port = self.sock.getsockname()[1]
    def close(self):
        self.sock.close(); self.sock = None

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

@pytest.fixture()
def env(db, security):
    hid = db.add_host("loc", "127.0.0.1")
    w = ScannerWorker(db_manager=db, security=security)
    changes, logs, done = [], [], []
    w.change_detected.connect(changes.append); w.log_message.connect(lambda l, m: logs.append((l, m)))
    w.scan_complete.connect(lambda h, r: done.append(h))
    return db, hid, w, changes, logs, done

def events(db): return db.fetchall("SELECT * FROM events WHERE event_type='port_change' ORDER BY id")

# ───────────── Scanner : états, baseline, changements ─────────────
def test_first_scan_creates_baseline_and_sets_online(env):
    db, hid, w, changes, logs, done = env
    L = Listener(); closed = free_port()
    w.scan_host(hid, "127.0.0.1", "loc", [L.port, closed])
    base = {r["port"]: r["state"] for r in db.fetchall("SELECT * FROM baselines WHERE host_id=?", (hid,))}
    assert base == {L.port: "open", closed: "closed"}
    assert not changes and not events(db) and done == ["loc"]
    assert db.get_host_by_id(hid)["status"] == "online"
    L.close()

def test_change_detection_dedup_and_recovery(env):
    db, hid, w, changes, *_ = env
    L = Listener(); ports = [L.port]
    w.scan_host(hid, "127.0.0.1", "loc", ports)                 # baseline : open
    L.close()
    w.scan_host(hid, "127.0.0.1", "loc", ports)                 # open → closed
    assert len(changes) == 1 and changes[0]["state_before"] == "open" and changes[0]["state_after"] == "closed"
    assert changes[0]["severity"] == "average" and len(events(db)) == 1
    w.scan_host(hid, "127.0.0.1", "loc", ports)                 # inchangé : pas de nouvel événement
    w.scan_host(hid, "127.0.0.1", "loc", ports)
    assert len(events(db)) == 1
    L.open()
    w.scan_host(hid, "127.0.0.1", "loc", ports)                 # retour à la baseline
    ev = events(db)
    assert len(ev) == 2 and ev[-1]["severity"] == "information" and "retour" in ev[-1]["description"]
    L.close()

def test_closed_to_open_is_disaster(env):
    db, hid, w, changes, *_ = env
    p = free_port()
    w.scan_host(hid, "127.0.0.1", "loc", [p])                   # baseline : closed
    L = Listener(p)
    w.scan_host(hid, "127.0.0.1", "loc", [p])
    assert changes and changes[0]["severity"] == "disaster"
    L.close()

def test_invalid_target_rejected(env):
    db, hid, w, changes, logs, done = env
    w.scan_host(hid, "evil; rm -rf /", "x", [80])
    assert not done and any(l == "ERROR" for l, _ in logs)

def test_scan_all_scans_every_host(env):
    db, hid, w, changes, logs, done = env
    db.add_host("loc2", "127.0.0.2")
    w.scan_all()
    assert sorted(done) == ["loc", "loc2"]                      # régression : avant, un seul hôte était scanné
    assert db.fetchone("SELECT COUNT(*) c FROM baselines WHERE host_id IN (SELECT id FROM hosts)")["c"] > 0

# ───────────── Moniteur ─────────────
def test_compute_rate_and_wrap():
    assert MonitorWorker.compute_rate((0, 0, 0), (10, 1_250_000, 2_500_000)) == pytest.approx((1.0, 2.0))
    r = MonitorWorker.compute_rate((0, 2**32 - 1000, 0), (1, 1000, 0))     # wrap compteur 32 bits
    assert r[0] == pytest.approx(2000 * 8 / 1e6)
    assert MonitorWorker.compute_rate((5, 0, 0), (5, 1, 1)) is None

def test_local_collection_persists_and_emits(db):
    hid = db.add_host("loc", lnet.get_primary_ip() or "127.0.0.1")
    m = MonitorWorker(db_manager=db); got = []
    m.metrics_ready.connect(got.append)
    time.sleep(0.2); m.collect_local_metrics(hid, "127.0.0.1", "loc")
    names = {r["metric_name"] for r in db.fetchall("SELECT DISTINCT metric_name FROM metrics WHERE host_id=?", (hid,))}
    assert {"cpu_util", "mem_used", "disk_used", "bw_in", "bw_out"} <= names
    assert got and got[0]["metrics"]["bw_in_mbps"] >= 0 and 0 <= got[0]["metrics"]["cpu_util"] <= 100

def test_thresholds_cooldown_and_setting(db):
    hid = db.add_host("loc", "10.9.9.9"); m = MonitorWorker(db_manager=db); alerts = []
    m.alert_triggered.connect(alerts.append)
    m._check_thresholds(hid, "loc", {"cpu_util": 95.0})
    m._check_thresholds(hid, "loc", {"cpu_util": 96.0})          # dans la période de grâce
    assert len(alerts) == 1 and alerts[0]["severity"] == "disaster"
    assert db.count_events() == 1
    db.set_setting("cpu_threshold", "50")
    m._check_thresholds(hid, "loc", {"cpu_util": 60.0})           # seuil réglable respecté
    assert alerts[-1]["severity"] == "average"
    db.set_setting("ram_threshold", "70"); m._check_thresholds(hid, "loc", {"mem_used_pct": 75.0})
    assert "Mémoire" in alerts[-1]["description"]

def test_host_down_up_transitions(db):
    hid = db.add_host("h", "10.9.9.9"); m = MonitorWorker(db_manager=db)
    host = db.get_host_by_id(hid)                                 # statut 'unknown'
    m._update_availability(host, False, 0)
    assert db.get_host_by_id(hid)["status"] == "offline" and db.count_events() == 0
    host["status"] = "online"; db.execute("UPDATE hosts SET failed_probes=0 WHERE id=?", (hid,))
    for _ in range(MonitorWorker.FLAP_THRESHOLD):               # anti-flapping : 3 échecs consécutifs
        m._update_availability(host, False, 0)
    assert db.get_events()[0]["event_type"] == "host_down" and db.get_events()[0]["severity"] == "high"
    host["status"] = "offline"; m._update_availability(host, True, 1.0)
    assert db.get_events()[0]["event_type"] == "host_up" and db.get_host_by_id(hid)["status"] == "online"

def test_collect_all_isolates_errors(db, monkeypatch):
    db.add_host("a", "127.0.0.1"); db.add_host("b", "127.0.0.2")
    m = MonitorWorker(db_manager=db); n = []
    m.cycle_done.connect(n.append)
    orig = m._collect_metrics
    def boom(h):
        if h["name"] == "a": raise RuntimeError("x")
        return orig(h)
    monkeypatch.setattr(m, "_collect_metrics", boom); m.collect_all()
    assert n == [1]                                               # 'a' en erreur n'empêche pas 'b'

# ───────────── Réseau local ─────────────
def test_primary_ip_and_interfaces():
    ip = lnet.get_primary_ip()
    if not ip: pytest.skip("pas de réseau")
    import ipaddress; ipaddress.IPv4Address(ip)
    assert any(i["ip"] == ip for i in lnet.get_local_interfaces()) and lnet.is_local_address(ip)
    assert lnet.get_primary_network()

@pytest.mark.skipif(sys.platform == "win32", reason="psutil ne compte pas l'interface de bouclage sous Windows : trafic 127.0.0.1 invisible")
def test_bandwidth_sampler_measures_real_traffic():
    s = lnet.BandwidthSampler(include_virtual=True); s.sample()
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    def sink():
        c, _ = srv.accept()
        while c.recv(65536): pass
    threading.Thread(target=sink, daemon=True).start()
    c = socket.create_connection(("127.0.0.1", port)); c.sendall(b"x" * 20_000_000); c.close()
    time.sleep(0.2); i, o = s.sample(); srv.close()
    assert i > 1 and o > 1                                        # ≥ ~20 MB transférés → plusieurs Mbps

def test_probe_and_scan_targets():
    assert lnet.probe_host("127.0.0.1")[0] is True
    raw = socket.socket(); raw.settimeout(0.5)
    try:
        raw.connect(("192.0.2.1", 80)); intercepted = True
    except ConnectionRefusedError:
        intercepted = True            # réseau/proxy qui répond pour tout (ex. bac à sable) → test non significatif
    except OSError:
        intercepted = False
    finally:
        raw.close()
    if not intercepted:
        assert lnet.probe_host("192.0.2.1", timeout=0.4, use_icmp=False)[0] is False   # TEST-NET : injoignable
    t = lnet._scan_targets("10.0.0.0/8", "10.1.2.3"); assert len(t) == 254 and t[0] == "10.1.2.1"
    with pytest.raises(ValueError): lnet._scan_targets("8.8.8.0/24", None)

def test_discover_and_register(db):
    found = lnet.discover_hosts("127.0.0.0/24", timeout=1.0)
    assert any(f["ip"] == "127.0.0.1" for f in found)
    added = lnet.register_discovered(db, found[:5]); assert added == 5
    assert lnet.register_discovered(db, found[:5]) == 0           # idempotent
    assert len({h["name"] for h in db.get_all_hosts()}) == 5

def test_ensure_local_hosts_idempotent(db):
    a = lnet.ensure_local_hosts(db); b = lnet.ensure_local_hosts(db)
    if a["ip"]:
        assert a["local"] == b["local"] and db.get_host_by_ip(a["ip"])["id"] == a["local"]
    n = db.fetchone("SELECT COUNT(*) c FROM hosts")["c"]; lnet.ensure_local_hosts(db)
    assert db.fetchone("SELECT COUNT(*) c FROM hosts")["c"] == n


def test_anti_flapping_needs_three_consecutive_failures(db):
    hid = db.add_host("f", "10.9.9.8"); m = MonitorWorker(db_manager=db)
    db.update_host_status(hid, "online", "2026-01-01T00:00:00")
    host = lambda: db.get_host_by_id(hid)
    m._update_availability(host(), False, 0); m._update_availability(host(), False, 0)
    assert host()["status"] == "online" and db.count_events() == 0         # 2 échecs : toujours en ligne, aucune alerte
    m._update_availability(host(), True, 1.0)                              # une réponse remet le compteur à zéro
    assert host()["failed_probes"] == 0
    m._update_availability(host(), False, 0); m._update_availability(host(), False, 0)
    assert host()["status"] == "online" and db.count_events() == 0
    db.execute("UPDATE hosts SET last_alive_ts = 1 WHERE id = ?", (hid,))      # silence ≥ délai de grâce (règle v16.6)
    m._update_availability(host(), False, 0)                               # 3e échec consécutif
    assert host()["status"] == "offline" and db.get_events()[0]["event_type"] == "host_down"
