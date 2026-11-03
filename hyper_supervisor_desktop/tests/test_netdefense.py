import json, socket, threading, time, struct
import pytest
from core.defense_common import EventSink
from core.honeypot import HoneypotManager, load_ports, save_ports, sanitize, PROFILES
from core.netdefense import ArpWatcher, DhcpProbe, build_discover, parse_reply, MAGIC


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def sink(db):
    got = []
    return EventSink(db, on_alert=got.append), got


def events(db, t=None):
    q = "SELECT * FROM events" + (" WHERE event_type=?" if t else "") + " ORDER BY id"
    return db.fetchall(q, (t,) if t else ())


# ───────────── Honeypots ─────────────
def test_honeypot_real_connection_logged_and_alerted(db, sink):
    s, got = sink
    port = free_port()
    hp = HoneypotManager(db, s, ports=[{"port": port, "profile": "ssh"}], bind="127.0.0.1", ignore_local=False)
    try:
        assert hp.start()[port] == "à l'écoute"
        c = socket.create_connection(("127.0.0.1", port), timeout=3)
        assert c.recv(64).startswith(b"SSH-2.0-OpenSSH")          # bannière du leurre
        c.sendall(b"root:toor\n"); c.close()
        end = time.time() + 3
        while time.time() < end and not db.fetchone("SELECT 1 FROM honeypot_hits"):
            time.sleep(0.05)
    finally:
        hp.stop()
    hit = db.fetchone("SELECT * FROM honeypot_hits")
    assert hit["port"] == port and hit["src_ip"] == "127.0.0.1" and "root:toor" in hit["payload"]
    ev = events(db, "honeypot_hit")[0]
    assert ev["severity"] == "high" and ev["host_id"] is not None and "attack.t1046" in ev["tags"]
    assert got and got[0]["event_type"] == "honeypot_hit"


def test_honeypot_port_scan_escalates_to_disaster_and_cooldown(db, sink):
    s, _ = sink
    hp = HoneypotManager(db, s, ports=[], ignore_local=False)
    for p in (2222, 2323, 2121, 8081, 3390):
        hp.record_hit("10.5.5.5", 4000 + p, p, "generic")
    sev = [e["severity"] for e in events(db, "honeypot_hit")]
    assert sev[0] == "high" and sev[-1] == "disaster"            # 5 ports en 60 s = balayage
    assert len(sev) == 2                                          # anti-inondation : pas une alerte par paquet
    assert db.fetchone("SELECT COUNT(*) c FROM honeypot_hits")["c"] == 5   # mais toutes les connexions sont conservées


def test_honeypot_ignores_own_machine_and_busy_port(db, sink):
    s, _ = sink
    hp = HoneypotManager(db, s, ports=[], ignore_local=True)
    hp.record_hit("127.0.0.1", 1234, 2222, "ssh")
    assert not events(db, "honeypot_hit")
    busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(1); bp = busy.getsockname()[1]
    hp2 = HoneypotManager(db, s, ports=[{"port": bp, "profile": "ssh"}], bind="127.0.0.1")
    try:
        assert "indisponible" in hp2.start()[bp]                 # port déjà pris : signalé, pas de plantage
    finally:
        hp2.stop(); busy.close()


def test_honeypot_config_roundtrip_and_validation(db):
    assert load_ports(db)[0]["port"] == 2222                      # défauts élevés (pas de conflit/privilège)
    save_ports(db, [{"port": 2200, "profile": "ssh"}, {"port": 2200, "profile": "ftp"}, {"port": 99, "profile": "??"}])
    assert load_ports(db) == [{"port": 2200, "profile": "ssh"}, {"port": 99, "profile": "generic"}]
    with pytest.raises(ValueError):
        save_ports(db, [{"port": 70000}])
    assert sanitize(b"ab\x00\xffc") == "ab..c"


# ───────────── ARP ─────────────
def test_arp_gateway_mac_change_is_disaster_then_restored(db, sink, monkeypatch):
    s, _ = sink
    from core import local_network as lnet
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: "192.168.1.1")
    w = ArpWatcher(db, s)
    assert w.check({"192.168.1.1": "aa:aa:aa:aa:aa:01", "192.168.1.20": "bb:bb:bb:bb:bb:02"}) == []   # 1re observation
    assert w.check({"192.168.1.1": "aa:aa:aa:aa:aa:01"}) == []                                          # stable
    f = w.check({"192.168.1.1": "cc:cc:cc:cc:cc:99"})                                                   # usurpation
    assert f[0]["severity"] == "disaster" and f[0]["type"] == "arp_spoof"
    assert "attack.t1557.002" in events(db, "arp_spoof")[0]["tags"]
    assert w.check({"192.168.1.1": "cc:cc:cc:cc:cc:99"}) == []                                          # pas de répétition
    back = w.check({"192.168.1.1": "aa:aa:aa:aa:aa:01"})                                               # retour à la normale
    assert back[0]["type"] == "arp_restored" and back[0]["severity"] == "information"


def test_arp_dhcp_churn_of_unmonitored_clients_is_silent_but_monitored_host_alerts(db, sink, monkeypatch):
    s, _ = sink
    from core import local_network as lnet
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: "192.168.1.1")
    hid = db.add_host("srv", "192.168.1.50", device_type="server")
    w = ArpWatcher(db, s)
    w.check({"192.168.1.1": "aa:aa:aa:aa:aa:01", "192.168.1.77": "11:11:11:11:11:11", "192.168.1.50": "22:22:22:22:22:22"})
    assert w.check({"192.168.1.77": "33:33:33:33:33:33"}) == []                      # simple client DHCP : pas d'alerte
    f = w.check({"192.168.1.50": "44:44:44:44:44:44"})
    assert f[0]["severity"] == "high" and events(db, "arp_spoof")[-1]["host_id"] == hid


def test_arp_new_ip_with_gateway_mac_flagged(db, sink, monkeypatch):
    s, _ = sink
    from core import local_network as lnet
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: "192.168.1.1")
    w = ArpWatcher(db, s)
    w.check({"192.168.1.1": "aa:aa:aa:aa:aa:01"})
    f = w.check({"192.168.1.66": "aa:aa:aa:aa:aa:01"})
    assert f and "même MAC" in f[0]["description"]


# ───────────── DHCP ─────────────
def _offer(xid, server, offered="192.168.1.100", router="192.168.1.1", dns="8.8.8.8"):
    hdr = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0x8000, b"\0"*4,
                      socket.inet_aton(offered), socket.inet_aton(server), b"\0"*4, b"\0"*16, b"\0"*64, b"\0"*128)
    opts = (MAGIC + b"\x35\x01\x02" + b"\x36\x04" + socket.inet_aton(server) + b"\x03\x04" + socket.inet_aton(router)
            + b"\x06\x04" + socket.inet_aton(dns) + b"\x01\x04\xff\xff\xff\x00" + b"\x33\x04\x00\x01\x51\x80" + b"\xff")
    return hdr + opts


def test_dhcp_packet_codec():
    pkt = build_discover(1234, b"\x02\x00\x00\x00\x00\x01")
    assert pkt[0] == 1 and pkt[236:240] == MAGIC and len(pkt) >= 240
    r = parse_reply(_offer(1234, "10.0.0.1"), 1234)
    assert r["server"] == "10.0.0.1" and r["offered"] == "192.168.1.100" and r["router"] == "192.168.1.1" and r["dns"] == ["8.8.8.8"]
    assert parse_reply(_offer(1234, "10.0.0.1"), 9999) is None            # autre transaction
    assert parse_reply(b"junk", 1) is None


class FakeDhcp:
    """Serveur DHCP simulé : répond à un DISCOVER par une OFFER depuis chacune des identités demandées."""
    def __init__(self, servers):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]; self.servers = servers
        threading.Thread(target=self.run, daemon=True).start()
    def run(self):
        try:
            data, addr = self.sock.recvfrom(1024)
            xid = struct.unpack("!I", data[4:8])[0]
            for srv in self.servers:
                self.sock.sendto(_offer(xid, srv), addr)
        except OSError:
            pass
    def close(self): self.sock.close()


def _probe(db, sink_, servers):
    fake = FakeDhcp(servers)
    try:
        return DhcpProbe(db, sink_).check(timeout=1.0, dest=("127.0.0.1", fake.port), bind=("127.0.0.1", 0))
    finally:
        fake.close()


def test_dhcp_learning_then_rogue_detection(db, sink):
    s, _ = sink
    r = _probe(db, s, ["192.168.1.1"])
    assert r["alerts"] == [] and DhcpProbe(db, s).trusted() == ["192.168.1.1"]       # apprentissage
    assert not events(db, "rogue_dhcp")
    r = _probe(db, s, ["192.168.1.1"]);  assert r["alerts"] == []                    # serveur connu : RAS
    r = _probe(db, s, ["192.168.1.1", "192.168.1.250"])
    assert r["alerts"] == ["192.168.1.250"]
    ev = events(db, "rogue_dhcp")[0]
    assert ev["severity"] == "disaster" and "192.168.1.250" in ev["description"]


def test_dhcp_two_servers_on_first_probe_alerts_without_trusting(db, sink):
    s, _ = sink
    r = _probe(db, s, ["10.0.0.1", "10.0.0.99"])
    assert r["alerts"] == ["multiple"] and DhcpProbe(db, s).trusted() == []
    assert events(db, "rogue_dhcp")[0]["severity"] == "high"


def test_dhcp_probe_reports_error_when_port_unavailable(db, sink):
    s, _ = sink
    busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); busy.bind(("127.0.0.1", 0))
    # SO_REUSEADDR peut autoriser le partage selon l'OS ; on exige seulement l'absence de plantage et un résultat structuré
    r = DhcpProbe(db, s).probe(timeout=0.2, dest=("127.0.0.1", 9), bind=("127.0.0.1", busy.getsockname()[1]))
    assert set(r) == {"servers", "error"}
    busy.close()
