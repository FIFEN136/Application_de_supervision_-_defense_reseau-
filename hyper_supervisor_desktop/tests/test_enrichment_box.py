import json
import struct
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from core import box_reader, device_info as di, enrichment as en
from tests.test_device_views import mk

BOX_JSON = [{"hosts": {"list": [
    {"macaddress": "9A:24:1C:BB:65:59", "ipaddress": "192.168.1.122", "hostname": "iPhone", "link": "WiFi 5", "active": 1,
     "wireless": {"band": "5GHz", "rssi0": -58, "txrate": 433}},
    {"macaddress": "3c:00:11:22:33:44", "ipaddress": "192.168.1.30", "hostname": "TV", "link": "Ethernet", "active": 1,
     "ethernet": {"physicalport": 3, "speed": 1000}},
    {"macaddress": "nope", "ipaddress": "1.1.1.1"}]}}]


# ───────────── analyseurs réseau ─────────────
def test_nbstat_parser():
    hdr = bytes(56) + bytes([2])
    n1 = b"MATHIEU-PC     " + b"\x00" + struct.pack(">H", 0x0400)
    n2 = b"WORKGROUP      " + b"\x00" + struct.pack(">H", 0x8400)       # nom de groupe ignoré
    assert en.parse_nbstat(hdr + n1 + n2) == "MATHIEU-PC"
    assert en.parse_nbstat(b"") is None and en.parse_nbstat(b"\xff" * 80) in (None, "")


def test_mdns_ptr_parser():
    q = en._qname("5.1.168.192.in-addr.arpa")
    name = en._qname("iPhone-de-Leo.local")
    pkt = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + q + struct.pack(">HHIH", 12, 1, 120, len(name)) + name
    assert en.parse_mdns_ptr(pkt) == "iPhone-de-Leo"
    assert en.parse_mdns_ptr(b"\x00" * 5) is None


def test_upnp_xml_and_xxe_refused():
    ok = "<root xmlns='urn:x'><device><friendlyName>Bbox TV</friendlyName><manufacturer>Sagemcom</manufacturer><modelName>TV-001</modelName></device></root>"
    assert en.parse_upnp_xml(ok) == {"friendly": "Bbox TV", "manufacturer": "Sagemcom", "model": "TV-001"}
    assert en.parse_upnp_xml('<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>') == {}
    assert en.parse_upnp_xml("pas du xml") == {}


def test_ttl_wifi_parsers():
    assert "Windows" in en.os_from_ttl(128) and "Linux" in en.os_from_ttl(64) and en.os_from_ttl(None) is None
    fr = ("État : connecté\nSSID : Bbox-1234\nCanal : 44\nRéception (Mbits/s) : 866\nSignal : 80%\n")
    w = en.parse_netsh_wlan(fr)
    assert w == {"ssid": "Bbox-1234", "rssi": -60, "band": "5", "link_mbps": 866}
    assert en.parse_netsh_wlan("État : déconnecté\n") is None and en.parse_netsh_wlan("") is None
    n = en.parse_nmcli_wifi("no:Autre:10:2412 MHz:10 Mbit/s\nyes:Maison:70:5180 MHz:300 Mbit/s\n")
    assert n == {"ssid": "Maison", "rssi": -65, "band": "5", "link_mbps": 300}


def test_private_only():
    assert en.reverse_dns("8.8.8.8") is None and en.netbios_name("8.8.8.8") is None and en.mdns_name("1.1.1.1") is None
    assert en.ping_ttl("pas une ip") is None


# ───────────── box ─────────────
def test_box_parse_tolerant():
    h = {x["mac"]: x for x in box_reader.parse_hosts(BOX_JSON)}
    assert set(h) == {"9a:24:1c:bb:65:59", "3c:00:11:22:33:44"}
    assert h["9a:24:1c:bb:65:59"]["type"] == "wifi" and h["9a:24:1c:bb:65:59"]["band"] == "5" and h["9a:24:1c:bb:65:59"]["rssi"] == -58
    assert h["3c:00:11:22:33:44"]["type"] == "ethernet" and h["3c:00:11:22:33:44"]["port"] == "3"
    assert box_reader.parse_hosts({"x": 1}) == [] and box_reader.parse_hosts(None) == []


@pytest.mark.parametrize("bad", ["", "8.8.8.8", "127.0.0.1", "a b"])
def test_box_address_must_be_local(bad):
    with pytest.raises(box_reader.BoxError):
        box_reader.check_box_address(bad)
    assert box_reader.check_box_address("http://192.168.1.254/") == "192.168.1.254"


def test_box_apply_keeps_manual(db):
    ph = mk(db, "iPhone", "192.168.1.122", "9a:24:1c:bb:65:59", "mobile", "online")
    tv = mk(db, "TV", "192.168.1.30", "3c:00:11:22:33:44", "tv", "online", conn_type="wifi", conn_source="manual")
    assert box_reader.apply_hosts(db, box_reader.parse_hosts(BOX_JSON)) == 1
    info = {i["name"]: i for i in di.build_all(db)}
    assert info["iPhone"]["conn"]["source"] == "box" and not info["iPhone"]["conn"]["probable"] and info["iPhone"]["rssi"] == -58
    assert info["iPhone"]["band"] == "5" and info["iPhone"]["quality"] == "Bon"
    assert info["TV"]["conn"]["source"] == "manual" and info["TV"]["conn"]["type"] == "wifi"          # le choix manuel gagne
    di.refresh_connection_info(db)                                                                    # le passage périodique ne l'efface pas
    assert db.get_host_by_id(ph)["conn_source"] == "box"


@pytest.fixture()
def fake_box():
    state = {"logged": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n).decode()
            if self.path == "/api/v1/login":
                ok = "password=secret" in body
                state["logged"] = ok
                self.send_response(200 if ok else 401)
                self.send_header("Set-Cookie", "BBOX_ID=abc; Path=/")
                self.end_headers()
                self.wfile.write(b"{}")
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

        def do_GET(self):
            if not state["logged"]:
                self.send_response(401); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(BOX_JSON).encode())
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_box_end_to_end_with_local_server(fake_box, monkeypatch):
    monkeypatch.setattr(box_reader, "check_box_address", lambda a: f"127.0.0.1:{fake_box}")       # le garde-fou « réseau privé » est testé plus haut
    ok, msg = box_reader.test_connection("x", "secret")
    assert ok and "2 appareil" in msg and "1 en Wi-Fi" in msg
    ok, msg = box_reader.test_connection("x", "mauvais")
    assert not ok and "refusé" in msg


def test_box_unreachable_message(monkeypatch):
    monkeypatch.setattr(box_reader, "check_box_address", lambda a: "127.0.0.1:1")
    ok, msg = box_reader.test_connection("x", "p")
    assert not ok and "injoignable" in msg.lower()


def test_box_password_encrypted_roundtrip(db):
    box_reader.save_settings(db, True, "192.168.1.254", "s3cret!")
    raw = db.get_setting("box_password")
    assert raw and "s3cret" not in raw
    assert box_reader.settings(db) == {"enabled": True, "address": "192.168.1.254", "password": "s3cret!"}
    box_reader.save_settings(db, True, "192.168.1.254", "")                       # vide = conserver
    assert box_reader.settings(db)["password"] == "s3cret!"
    assert box_reader.refresh_from_box(db) == 0                                    # box injoignable : jamais d'exception
    box_reader.save_settings(db, False, "192.168.1.254", "")
    assert box_reader.refresh_from_box(db) == 0


# ───────────── enrichissement ─────────────
def test_enrich_all_fills_and_respects_manual(db, monkeypatch):
    a = mk(db, "A", "192.168.1.20", "00:1a:2b:3c:4d:5e", "workstation", "online")
    b = mk(db, "B", "192.168.1.30", "3c:00:11:22:33:44", "tv", "online", model="MonModele")
    monkeypatch.setattr(en, "ssdp_discover", lambda *a, **k: {"192.168.1.30": {"model": "TV-001", "manufacturer": "Sagemcom"}})
    monkeypatch.setattr(en, "_one", lambda ip: {"dns": "a", "nb": "MATHIEU-PC" if ip.endswith(".20") else None, "mdns": None, "ttl": 128})
    monkeypatch.setattr(en, "local_wifi", lambda: {"ssid": "S", "rssi": -50, "band": "5", "link_mbps": 866})
    monkeypatch.setattr(di, "local_connection", lambda: {"type": "wifi", "detail": "Wi-Fi", "link_mbps": 1, "ip": "192.168.1.20"})
    assert en.enrich_all(db) == 2
    ha, hb = db.get_host_by_id(a), db.get_host_by_id(b)
    assert ha["dns_name"] == "MATHIEU-PC" and "Windows" in ha["os_guess"]
    assert (ha["rssi"], ha["wifi_band"], ha["link_mbps"]) == (-50, "5", 866)                       # Wi-Fi réel de ce PC
    assert hb["model"] == "MonModele" and hb["vendor"] == "Sagemcom"                               # modèle saisi jamais écrasé
    info = {i["name"]: i for i in di.build_all(db)}
    assert info["A"]["os"].startswith("Windows") and info["A"]["dns_name"] == "MATHIEU-PC"
    assert en.enrich_all(db, []) == 0


# ───────────── interface ─────────────
def test_details_hide_empty_rows_and_explain(qtbot, db):
    from PyQt6.QtWidgets import QLabel
    from ui.widgets.device_cards import DeviceCard
    mk(db, "Mystère", "192.168.1.77", "9a:24:1c:bb:00:01", "unknown", "online")
    info = di.build_all(db)[0]
    card = DeviceCard(info, "details")
    qtbot.addWidget(card)
    texts = [l.text() for l in card.findChildren(QLabel)]
    assert "—" not in texts
    assert any("Non disponible" in t for t in texts) and any("lecture de la box" in t for t in texts)
    assert not any(t == "Bande Wi-Fi" for t in texts)


def test_settings_box_section(qtbot, db, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    from ui.widgets.settings_view import SettingsView
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    v = SettingsView(db=db)
    qtbot.addWidget(v)
    v._box_enabled.setChecked(True); v._box_addr.setText("192.168.1.254"); v._box_pwd.setText("pw")
    v._save_box()
    assert box_reader.settings(db)["enabled"] and box_reader.settings(db)["password"] == "pw"
    v._box_addr.setText("8.8.8.8"); v._save_box()
    assert box_reader.settings(db)["address"] == "192.168.1.254"                  # adresse publique refusée
    v._on_box_result(False, "boom")
    assert "boom" in v._box_result.text()


def test_network_equipment_same_real_info_and_icons(qtbot, db):
    """Routeur / commutateur : mêmes informations réelles, pictogrammes du même style que le menu, page d'administration si le port web est ouvert."""
    from PyQt6.QtWidgets import QLabel
    from ui.icons import DEVICE_ICON_KEYS, ICONS, device_pixmap
    from ui.widgets.device_cards import DeviceCard
    rt = mk(db, "Bbox", "192.168.1.254", "4c:eb:bd:00:00:01", "router", "online", vendor="Sagemcom", model="F@st 5696", os_guess="Équipement réseau (probable)")
    db.execute("INSERT INTO port_states (host_id, port, protocol, state) VALUES (?, 80, 'tcp', 'open')", (rt,))
    sw = mk(db, "Switch", "192.168.1.2", "00:1a:2b:00:00:02", "switch", "online")
    info = {i["name"]: i for i in di.build_all(db)}
    assert info["Bbox"]["admin_url"] == "http://192.168.1.254" and info["Switch"]["admin_url"] is None
    card = DeviceCard(info["Bbox"], "details"); qtbot.addWidget(card)
    texts = [l.text() for l in card.findChildren(QLabel)]
    assert "Page d'administration" in texts and "Sagemcom" in texts and "—" not in texts
    for key in DEVICE_ICON_KEYS.values():
        assert key in ICONS and not device_pixmap(key.replace("dev_", ""), 20).isNull()


def test_map_nodes_use_svg_icons(qtbot, db):
    from PyQt6.QtWidgets import QGraphicsPixmapItem
    from ui.widgets.topology_view import TopologyCanvas
    mk(db, "Bbox", "192.168.1.254", "4c:eb:bd:00:00:01", "router", "online")
    mk(db, "Tel", "192.168.1.5", "9a:24:1c:00:00:05", "mobile", "online")
    c = TopologyCanvas()
    qtbot.addWidget(c)
    c.draw_topology(db.get_all_hosts(), db.get_networks(), {})
    assert sum(isinstance(i, QGraphicsPixmapItem) for i in c.scene().items()) >= 2


# ───────────── v16.2.1 : présence 30 s, type d'appareil, connexion aux équipements ─────────────
def test_presence_marks_offline_after_30s_and_back(db):
    from core import presence
    h = mk(db, "Tel", "192.168.1.50", "9a:24:1c:00:00:50", "workstation", "online")
    alive = {"v": True}
    probe = lambda host: alive["v"]
    assert presence.presence_step(db, 30, now=1000, probe=probe) == []
    alive["v"] = False
    assert presence.presence_step(db, 30, now=1010, probe=probe) == []              # 10 s : on attend
    assert db.get_host_by_id(h)["status"] == "online"
    assert presence.presence_step(db, 30, now=1029, probe=probe) == []              # 29 s : toujours en ligne
    ch = presence.presence_step(db, 30, now=1031, probe=probe)                      # 31 s : hors ligne, signalé
    assert [(c["old"], c["new"]) for c in ch] == [("online", "offline")] and db.get_host_by_id(h)["status"] == "offline"
    assert presence.presence_step(db, 30, now=1040, probe=probe, tick=1) == []      # pas de répétition
    alive["v"] = True
    ch = presence.presence_step(db, 30, now=1050, probe=probe, tick=3)
    assert [(c["old"], c["new"]) for c in ch] == [("offline", "online")]


def test_presence_error_does_not_mark_offline_and_grace_setting(db):
    from core import presence
    mk(db, "X", "192.168.1.51", "00:1a:2b:00:00:51", "workstation", "online")
    def boom(h): raise RuntimeError("x")
    presence.presence_step(db, 30, now=10, probe=boom)
    assert presence.presence_step(db, 30, now=500, probe=boom) == []
    assert presence.grace_seconds(db) == 30
    db.set_setting("presence_grace_s", "5"); assert presence.grace_seconds(db) == 10
    db.set_setting("presence_grace_s", "abc"); assert presence.grace_seconds(db) == 30


def test_monitor_presence_tick_emits_event(qapp, db, monkeypatch):
    from core.monitor import MonitorWorker
    from core import presence
    h = mk(db, "Tel", "192.168.1.50", "9a:24:1c:00:00:50", "mobile", "online", last_alive_ts=1)
    w = MonitorWorker(db)
    alerts = []
    w.alert_triggered.connect(alerts.append)
    monkeypatch.setattr(presence, "probe_alive", lambda host: False)
    for _ in range(3):                                   # 3 absences consécutives exigées
        w.presence_tick()
    assert db.get_host_by_id(h)["status"] == "offline"
    assert alerts and alerts[0]["event_type"] == "host_down" and "n'est plus connecté" in alerts[0]["description"]


def test_macbook_not_a_phone_but_iphone_is(db):
    host = {"device_type": "mobile", "type_source": None}
    assert di.infer_type(host, ["Mac"], set(), "Adresse privée") == "workstation"
    assert di.infer_type(host, ["MacBook-Air-de-Leo"], set(), "") == "workstation"
    assert di.infer_type(host, ["unknown"], {548, 7000}, "") == "workstation"            # AFP / AirPlay : un Mac
    assert di.infer_type(host, ["IPHONE_LEO"], {62078}, "") is None                      # reste téléphone
    assert di.infer_type({"device_type": "workstation"}, ["x"], {62078}, "") == "mobile"  # port lockdownd = iPhone
    assert di.infer_type({"device_type": "mobile", "type_source": "manual"}, ["Mac"], set(), "") is None
    assert di.infer_type({"device_type": "router"}, ["Mac"], set(), "") is None


def test_enrich_corrects_type_and_edit_marks_manual(db, monkeypatch):
    mac = mk(db, "Mac", "192.168.1.154", "32:58:b5:52:bc:a0", "mobile", "online")
    monkeypatch.setattr(en, "ssdp_discover", lambda *a, **k: {})
    monkeypatch.setattr(en, "_one", lambda ip: {"dns": None, "nb": None, "mdns": None, "ttl": 64, "ports": {7000}})
    monkeypatch.setattr(en, "local_wifi", lambda: None)
    en.enrich_all(db)
    assert db.get_host_by_id(mac)["device_type"] == "workstation"
    di.update_device_meta(db, mac, device_type="tv")
    assert db.get_host_by_id(mac)["device_type"] == "tv" and db.get_host_by_id(mac)["type_source"] == "manual"
    en.enrich_all(db)
    assert db.get_host_by_id(mac)["device_type"] == "tv"                                  # un choix manuel n'est jamais corrigé
    with pytest.raises(ValueError):
        di.update_device_meta(db, mac, device_type="frigo")


def test_device_link_guards_and_ssh_web_snmp_paths(db, monkeypatch):
    from core import device_link as dl
    for bad in ("127.0.0.1", "169.254.1.1", "0.0.0.0", "224.0.0.1", "abc", ""):
        with pytest.raises(dl.LinkError):
            dl.check_target(bad)
    with pytest.raises(dl.LinkError):
        dl.check_target("8.8.8.8")
    assert dl.check_target("8.8.8.8", True) == "8.8.8.8" and dl.check_target("192.168.1.254") == "192.168.1.254"
    fake = lambda cred, cmds, timeout=12.0, host="": (cred.update(host_key_seen="SHA256:abc") or [{"cmd": cmds[0], "rc": 0, "out": "Linux fw 6.1 x86_64\n"}])
    monkeypatch.setattr("core.config_backup.ssh_run_commands", fake)
    r = dl.connect(db, {"method": "ssh", "address": "192.168.1.1", "name": "Pare-feu", "kind": "firewall", "username": "admin", "secret": "pw",
                        "profile": "linux", "port": 22})
    h = db.get_host_by_id(r["host_id"])
    assert h["device_type"] == "firewall" and h["type_source"] == "manual" and "Linux fw" in h["model"]
    cred = db.fetchone("SELECT * FROM host_credentials WHERE host_id = ?", (h["id"],))
    assert cred["host_key"] == "SHA256:abc" and cred["secret_enc"] and "pw" != cred["secret_enc"]
    with pytest.raises(dl.LinkError, match="Nom d'utilisateur"):
        dl.connect(db, {"method": "ssh", "address": "192.168.1.1", "username": "", "secret": "x"}, save=False)
    with pytest.raises(dl.LinkError, match="Choisissez"):
        dl.connect(db, {"method": "", "address": "192.168.1.1"})
    monkeypatch.setattr(dl, "test_snmp", lambda *a, **k: {"ok": True, "info": "Cisco IOS", "name": "sw1", "message": "SNMP réussi"})
    r2 = dl.connect(db, {"method": "snmp", "address": "192.168.1.2", "kind": "switch", "community": "monsecret"})
    assert db.get_host_by_id(r2["host_id"])["snmp_enabled"] == 1
    assert db.fetchone("SELECT snmp_community c FROM hosts WHERE id = ?", (r2["host_id"],))["c"] != "monsecret"      # chiffrée en base


def test_device_link_web_with_local_server():
    import base64
    from core import device_link as dl

    class H(BaseHTTPRequestHandler):
        server_version, sys_version = "FakeOS", ""
        def log_message(self, *a): pass
        def do_GET(self):
            ok = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:pw").decode()
            self.send_response(200 if ok else 401); self.end_headers()
            self.wfile.write(b"<html><title>Routeur Test</title></html>")
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        r = dl.test_web("127.0.0.1", port, "http", "admin", "pw")
        assert "Routeur Test" in r["info"] and "FakeOS" in r["info"]
        with pytest.raises(dl.LinkError, match="refusé"):
            dl.test_web("127.0.0.1", port, "http", "admin", "faux")
        with pytest.raises(dl.LinkError):
            dl.test_web("127.0.0.1", port, "ftp", "a", "b")
    finally:
        srv.shutdown()


def test_connect_dialog_and_map_button(qtbot, db, monkeypatch):
    from ui.widgets.device_cards import ConnectDeviceDialog
    d = ConnectDeviceDialog(db, None)
    qtbot.addWidget(d)
    d.addr.setText("192.168.1.1"); d.method.setCurrentIndex(d.method.findData("snmp"))
    p = d.params()
    assert p["method"] == "snmp" and p["port"] == 161 and p["address"] == "192.168.1.1"
    d.method.setCurrentIndex(d.method.findData("ssh")); assert d.port.value() == 22
    d.addr.setText("8.8.8.8")
    d._run(False)
    qtbot.waitUntil(lambda: "hors de votre réseau local" in d.result.text(), timeout=5000)
    assert d.btn_test.isEnabled()


# ───────────── v16.5 : fin du yo-yo en ligne / hors ligne ─────────────
from core import liveness, presence as pres, local_network as lnet


def test_liveness_parsers_linux_and_windows_any_language():
    ln = "192.168.1.5 dev wlan0 lladdr aa:bb:cc:00:00:05 REACHABLE\n192.168.1.6 dev wlan0 lladdr aa:bb:cc:00:00:06 STALE\n192.168.1.7 dev wlan0  FAILED\nfe80::1 dev x lladdr 00:11:22:33:44:55 router STALE\n"
    assert liveness.parse_ip_neigh(ln) == {"192.168.1.5": "reachable", "192.168.1.6": "stale", "192.168.1.7": "dead"}
    ps = '"IPAddress","State"\n"192.168.1.5","Reachable"\n"192.168.1.6","Stale"\n"192.168.1.7","Unreachable"\n"192.168.1.8","Permanent"\n'
    assert liveness.parse_powershell_neighbors(ps) == {"192.168.1.5": "reachable", "192.168.1.6": "stale", "192.168.1.7": "dead", "192.168.1.8": "permanent"}
    assert liveness.parse_ip_neigh("n'importe quoi") == {} and liveness.parse_powershell_neighbors("") == {}


@pytest.mark.parametrize("state,arp,expected", [("reachable", False, True), ("permanent", False, True), ("dead", True, False),
                                                ("stale", True, None), (None, True, True), (None, False, False)])
def test_arp_verdict(monkeypatch, state, arp, expected):
    monkeypatch.setattr(liveness, "neighbor_states", lambda ttl=2.0: ({"192.168.1.5": state} if state else {}))
    assert liveness.arp_verdict("192.168.1.5", arp) is expected
    monkeypatch.setattr(liveness, "neighbor_states", lambda ttl=2.0: None)                # système sans état : ancien comportement
    assert liveness.arp_verdict("192.168.1.5", arp) is arp


def test_probe_stale_arp_is_unsure_not_alive_nor_dead(monkeypatch):
    monkeypatch.setattr(lnet, "ping_icmp", lambda ip, timeout_s=1.0: (False, 0.0))
    monkeypatch.setattr(lnet, "_probe_async", lambda ip, t: __import__("asyncio").sleep(0, result=(False, 0.0)))
    monkeypatch.setattr(lnet, "is_onlink", lambda ip: True)
    monkeypatch.setattr(lnet, "arp_cache", lambda ttl=4.0: {"192.168.1.45": "aa:bb"})
    monkeypatch.setattr(liveness, "nudge", lambda ips: None)
    monkeypatch.setattr(liveness, "neighbor_states", lambda ttl=2.0: {"192.168.1.45": "stale"})
    r = lnet.probe_host_ex("192.168.1.45")
    assert r["unsure"] and not r["alive"] and r["method"] == "arp-unsure"
    monkeypatch.setattr(liveness, "neighbor_states", lambda ttl=2.0: {"192.168.1.45": "reachable"})
    assert lnet.probe_host_ex("192.168.1.45")["alive"]
    monkeypatch.setattr(liveness, "neighbor_states", lambda ttl=2.0: {"192.168.1.45": "dead"})
    assert not lnet.probe_host_ex("192.168.1.45")["alive"]


def test_sleeping_phone_does_not_flap(db):
    """Scénario du journal : téléphone en veille (ni ping ni TCP) dont l'entrée ARP est ancienne → il ne doit JAMAIS changer d'état."""
    h = mk(db, "iPhone", "192.168.1.45", "9a:24:1c:00:00:45", "mobile", "online", last_alive_ts=0)
    changes = []
    for t in range(0, 600, 5):                           # 10 minutes de passages toutes les 5 s, verdict « inconnu »
        changes += pres.presence_step(db, 30, now=1000 + t, probe=lambda host: None, tick=t // 5)
    assert changes == [] and db.get_host_by_id(h)["status"] == "online"


def test_real_departure_detected_once_and_return_detected_once(db):
    h = mk(db, "Tel", "192.168.1.46", "9a:24:1c:00:00:46", "mobile", "online")
    verdict = {"v": True}
    seq = []
    for t in range(0, 300, 5):
        verdict["v"] = True if t < 60 or t >= 200 else False
        seq += [(c["old"], c["new"]) for c in pres.presence_step(db, 30, now=1000 + t, probe=lambda host: verdict["v"], tick=t // 5)]
    assert seq == [("online", "offline"), ("offline", "online")]                         # une seule sortie, un seul retour


def test_one_missed_ping_never_marks_offline(db):
    h = mk(db, "PC", "192.168.1.47", "00:1a:2b:00:00:47", "workstation", "online")
    for t, v in enumerate([True, False, True, False, True, False, False, True]):
        assert pres.presence_step(db, 10, now=1000 + t * 20, probe=lambda host, v=v: v) == []
    assert db.get_host_by_id(h)["status"] == "online"


def test_monitor_cycle_ignores_unsure_hosts(qapp, db, monkeypatch):
    from core.monitor import MonitorWorker
    h = mk(db, "Tel", "192.168.1.48", "9a:24:1c:00:00:48", "mobile", "online")
    monkeypatch.setattr(lnet, "probe_host_ex", lambda ip, timeout=0.8, use_icmp=True: {"alive": False, "latency_ms": 0.0, "method": "arp-unsure", "unsure": True})
    w = MonitorWorker(db)
    for _ in range(5):
        w.collect_all()
    assert db.get_host_by_id(h)["status"] == "online" and db.count_events() == 0


def test_windows_slow_powershell_never_blocks_and_never_stacks(monkeypatch):
    """PowerShell lent (> 8 s) : la lecture se fait en arrière-plan, sans bloquer ni empiler de processus."""
    import threading, time
    from core import liveness
    calls, gate = [], threading.Event()

    def slow():
        calls.append(1); gate.wait(5)
        return {"192.168.1.5": "reachable"}
    monkeypatch.setattr(liveness.platform, "system", lambda: "Windows")
    monkeypatch.setattr(liveness, "_read_states", slow)
    liveness._cache.update(t=0.0, states=None); liveness._refresh.update(running=False, fail_until=0.0)
    t0 = time.monotonic()
    assert liveness.neighbor_states(ttl=0) is None                       # rien de lu encore : illisible, mais immédiat
    assert liveness.neighbor_states(ttl=0) is None and time.monotonic() - t0 < 1.0
    time.sleep(0.2); assert len(calls) == 1                              # une seule lecture en cours
    gate.set(); time.sleep(0.5)
    assert liveness.neighbor_states(ttl=60) == {"192.168.1.5": "reachable"}
    # échec : pas de relance en boucle pendant 60 s
    liveness._cache.update(t=0.0, states=None); liveness._refresh.update(running=False, fail_until=0.0)
    monkeypatch.setattr(liveness, "_read_states", lambda: calls.append(2))
    liveness.neighbor_states(ttl=0); time.sleep(0.3); n = len(calls)
    liveness.neighbor_states(ttl=0); time.sleep(0.3)
    assert len(calls) == n
