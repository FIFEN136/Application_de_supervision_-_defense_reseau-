"""Tests v12 : mot de passe d'usine, UDP/bannière, regroupement des alertes."""
import socket, threading
import pytest
from core.notifier import NotificationDeduper
from core.scanner import ScannerWorker, DEFAULT_UDP_PORTS


def _ev(**kw):
    e = {"host_id": 1, "host_name": "srv", "severity": "high", "event_type": "host_down",
         "description": "Hôte srv hors ligne", "port": None}
    e.update(kw); return e


def test_duplicate_alerts_grouped_then_repeat_count_reported(db):
    d = NotificationDeduper(db); h = db.add_host("srv", "10.0.0.5")
    assert d.check(_ev(host_id=h)) == (True, 0)
    assert d.check(_ev(host_id=h)) == (False, 0) and d.check(_ev(host_id=h)) == (False, 0)
    assert d.check(_ev(host_id=h, severity="disaster"))[0] is True            # sévérité différente : pas un doublon
    assert d.check(_ev(host_id=h, description="autre message"))[0] is True
    db.execute("UPDATE notification_queue SET last_sent_at = datetime('now','-2 hours')")   # fenêtre écoulée
    send, repeats = d.check(_ev(host_id=h))
    assert send is True and repeats == 2                                        # 2 répétitions regroupées


def test_dedup_can_be_disabled(db):
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('notif_dedup_window','0')")
    d = NotificationDeduper(db)
    assert d.check(_ev())[0] and d.check(_ev())[0]


def test_dedup_never_blocks_on_db_error():
    class Broken:
        def fetchone(self, *a, **k): raise RuntimeError("boom")
    assert NotificationDeduper(Broken()).check(_ev()) == (True, 0)


def test_tcp_banner_and_version_stored(db, security):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    def serve():
        c, _ = srv.accept(); c.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"); c.close()
    threading.Thread(target=serve, daemon=True).start()
    hid = db.add_host("loc", "127.0.0.1")
    ScannerWorker(db_manager=db, security=security).scan_host(hid, "127.0.0.1", "loc", [port])
    row = db.fetchone("SELECT * FROM port_states WHERE host_id=? AND port=?", (hid, port))
    assert row["state"] == "open" and "OpenSSH" in row["service_version"] and row["service_banner"].startswith("SSH-2.0")
    srv.close()


def test_udp_scan_open_and_closed_without_tcp_collision(db, security):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("127.0.0.1", 0)); uport = u.getsockname()[1]
    def echo():
        data, addr = u.recvfrom(16); u.sendto(b"ok", addr)
    threading.Thread(target=echo, daemon=True).start()
    hid = db.add_host("loc", "127.0.0.1")
    w = ScannerWorker(db_manager=db, security=security)
    w.scan_host(hid, "127.0.0.1", "loc", [], udp_ports=[uport])
    row = db.fetchone("SELECT * FROM port_states WHERE host_id=? AND protocol='UDP'", (hid,))
    assert row["port"] == uport and row["state"] == "open"
    b = db.fetchone("SELECT protocol FROM baselines WHERE host_id=? AND port=?", (hid, uport))
    assert b["protocol"] == "UDP"
    u.close()


def test_tcp_and_udp_same_port_number_do_not_mix(db, security):
    hid = db.add_host("loc", "127.0.0.1")
    db.execute("INSERT INTO baselines (host_id, port, protocol, state) VALUES (?, 53, 'TCP', 'closed')", (hid,))
    w = ScannerWorker(db_manager=db, security=security); changes = []
    w.change_detected.connect(changes.append)
    w.scan_host(hid, "127.0.0.1", "loc", [53], udp_ports=[53])
    assert all(c["description"].startswith("Port 53/TCP") for c in changes)    # l'UDP 53 ne pollue pas la référence TCP 53


def test_default_udp_ports_defined():
    assert 161 in DEFAULT_UDP_PORTS and 123 in DEFAULT_UDP_PORTS


def test_factory_password_must_be_changed_but_changed_accounts_are_not(qapp, db, security):
    import main as M
    ctl = M.AppController(qapp, db, security)
    admin = security.authenticate("admin", "admin")
    assert ctl._must_change_password(admin) is True
    db.execute("UPDATE users SET password_hash=?, password_changed=1 WHERE login='admin'",
               (security.hash_password("Nouveau#Pass9"),))
    assert ctl._must_change_password(security.authenticate("admin", "Nouveau#Pass9")) is False
    # ancienne base : mot de passe déjà changé mais drapeau à 0 → pas de blocage
    db.execute("UPDATE users SET password_changed=0 WHERE login='admin'")
    assert ctl._must_change_password(security.authenticate("admin", "Nouveau#Pass9")) is False


def test_change_password_dialog_rules_and_audit(qapp, db, security):
    import main as M
    user = security.authenticate("admin", "admin")
    dlg = M.ChangePasswordDialog(user, security)
    def go(cur, new, conf):
        dlg._f_current.setText(cur); dlg._f_new.setText(new); dlg._f_confirm.setText(conf); dlg._try_change()
    go("admin", "court", "court");                 assert not dlg.is_success() and "8" in dlg._lbl_error.text()
    go("admin", "Abcdefg#12", "autre");            assert not dlg.is_success()
    go("faux", "Abcdefg#12", "Abcdefg#12");        assert not dlg.is_success()
    go("admin", "admin", "admin");                 assert not dlg.is_success()
    go("admin", "Abcdefg#12", "Abcdefg#12");       assert dlg.is_success()
    row = db.fetchone("SELECT * FROM users WHERE login='admin'")
    assert row["password_changed"] == 1 and security.verify_password("Abcdefg#12", row["password_hash"])
    assert security.authenticate("admin", "admin") is None
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='PASSWORD_CHANGED'")


def test_discovery_finds_stealth_neighbours_via_arp_nudge(monkeypatch):
    """Un appareil muet (ni ping ni TCP) n'apparaît qu'après la relance ARP : il doit figurer dans le résultat."""
    from core import local_network as lnet
    calls = {"nudge": 0}
    state = {"nudged": False}
    monkeypatch.setattr(lnet, "is_onlink", lambda ip: True)
    def fake_nudge(targets, settle_s=1.0):
        calls["nudge"] += 1; state["nudged"] = True; return len(targets)
    monkeypatch.setattr(lnet, "_arp_nudge", fake_nudge)
    monkeypatch.setattr(lnet, "read_arp_table",
                        lambda: {"10.250.250.77": "aa:bb:cc:00:11:22"} if state["nudged"] else {})
    monkeypatch.setattr(lnet, "resolve_name", lambda ip: "")
    res = lnet.discover_network("10.250.250.0/29", timeout=0.05)
    assert calls["nudge"] == 1
    assert res == [] or all(r["ip"] != "10.250.250.77" for r in res)      # hors du /29 : ignoré, jamais ajouté
    state["nudged"] = False
    monkeypatch.setattr(lnet, "read_arp_table",
                        lambda: {"10.250.250.5": "aa:bb:cc:00:11:22"} if state["nudged"] else {})
    res = lnet.discover_network("10.250.250.0/29", timeout=0.05)
    assert any(r["ip"] == "10.250.250.5" and r["mac"] == "aa:bb:cc:00:11:22" for r in res)


def test_arp_nudge_never_raises_and_counts():
    from core import local_network as lnet
    assert lnet._arp_nudge(["127.0.0.1", "127.0.0.2"], settle_s=0) == 2
    assert lnet._arp_nudge([], settle_s=0) == 0
