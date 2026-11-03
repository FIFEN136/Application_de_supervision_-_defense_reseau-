"""v16.6 : suppression complète d'un réseau, supervision de plusieurs réseaux indépendants, règle rouge/vert."""
import time

import pytest
from PyQt6.QtWidgets import QMessageBox

from core import presence


def _net_with_hosts(db, name, cidr, ips, status="online"):
    nid = db.add_network(name, cidr, None, "lan", 1, authorized_by="t")
    ids = []
    for ip in ips:
        h = db.add_host(f"h-{ip}", ip)
        db.update_host_identity(h, network_id=nid)
        db.execute("UPDATE hosts SET status=? WHERE id=?", (status, h))
        db.add_event(h, f"h-{ip}", "", "high", "host_down", "x")
        db.add_metric(h, "latency", 1.0, "ms")
        db.execute("INSERT INTO net_fdb (host_id, mac, port) VALUES (?,?,?)", (h, f"aa:bb:cc:00:00:{len(ids):02x}", "p1"))
        db.execute("INSERT INTO incidents (host_id, host_name, title, severity, updated_at) VALUES (?,?,?,?,datetime('now'))", (h, "h", "i", "high"))
        ids.append(h)
    return nid, ids


def _leftovers(db, ids):
    left = []
    for t in db.fetchall("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
        cols = {c["name"] for c in db.fetchall("PRAGMA table_info(" + t["name"] + ")")}
        if "host_id" in cols:
            for i in ids:
                n = db.fetchone("SELECT COUNT(*) c FROM " + t["name"] + " WHERE host_id = ?", (i,))["c"]
                if n:
                    left.append((t["name"], i, n))
    return left


def test_purge_removes_everything_of_the_network_and_nothing_else(db):
    a, ids_a = _net_with_hosts(db, "A", "10.1.0.0/24", ["10.1.0.5", "10.1.0.6"])
    b, ids_b = _net_with_hosts(db, "B", "10.2.0.0/24", ["10.2.0.5"])
    db.write_audit("admin", "TEST", "t", "garde-moi")
    res = db.purge_network(a)
    assert res["hosts"] == 2 and res["events"] >= 2
    assert db.fetchone("SELECT COUNT(*) c FROM networks WHERE id=?", (a,))["c"] == 0
    assert db.fetchone("SELECT COUNT(*) c FROM hosts WHERE network_id=?", (a,))["c"] == 0
    assert _leftovers(db, ids_a) == []
    assert db.fetchone("SELECT COUNT(*) c FROM hosts WHERE id=?", (ids_b[0],))["c"] == 1        # l'autre réseau est intact
    assert db.fetchone("SELECT COUNT(*) c FROM events WHERE host_id=?", (ids_b[0],))["c"] >= 1
    assert db.fetchone("SELECT COUNT(*) c FROM audit_logs WHERE action='TEST'")["c"] == 1         # l'audit n'est jamais effacé


def test_purge_is_all_or_nothing(db, monkeypatch):
    a, ids = _net_with_hosts(db, "A", "10.1.0.0/24", ["10.1.0.5"])
    stmts = list(db._PURGE_BY_HOST)
    stmts[10] = "DELETE FROM table_qui_nexiste_pas WHERE host_id = ?"
    monkeypatch.setattr(type(db), "_PURGE_BY_HOST", tuple(stmts))
    with pytest.raises(Exception):
        db.purge_network(a)
    assert db.fetchone("SELECT COUNT(*) c FROM hosts WHERE id=?", (ids[0],))["c"] == 1          # rien n'a été supprimé à moitié
    assert db.fetchone("SELECT COUNT(*) c FROM events WHERE host_id=?", (ids[0],))["c"] >= 1
    assert db.fetchone("SELECT COUNT(*) c FROM networks WHERE id=?", (a,))["c"] == 1


def test_overlapping_networks_are_refused_but_separate_ones_are_fine(db):
    db.add_network("A", "10.5.0.0/24")
    with pytest.raises(ValueError):
        db.add_network("B", "10.5.0.128/25")
    with pytest.raises(ValueError):
        db.add_network("C", "10.5.0.0/16")
    db.add_network("D", "10.6.0.0/24")                                                       # plusieurs réseaux distincts : OK
    assert len(db.get_networks()) == 2


def test_paused_network_is_not_probed_and_others_are(db):
    a, ids_a = _net_with_hosts(db, "A", "10.1.0.0/24", ["10.1.0.5"])
    b, ids_b = _net_with_hosts(db, "B", "10.2.0.0/24", ["10.2.0.5"])
    db.set_network_monitoring(a, enabled=False)
    probed = []
    presence.presence_step(db, 30, probe=lambda h: probed.append(h["ip_address"]) or True, tick=0)
    assert probed == ["10.2.0.5"]                                                            # A suspendu : jamais sondé
    db.set_network_monitoring(a, enabled=True)
    assert {h["id"] for h in db.active_hosts()} >= set(ids_a + ids_b)
    db.set_network_monitoring(b, every_s=5)
    assert db.get_networks()[1]["discover_every_s"] == 60                                    # borné à 1 minute minimum


def test_rediscovery_is_per_network_and_isolated(qapp, db, monkeypatch):
    from core.network_setup import NetworkSetupWorker
    a = db.add_network("A", "10.1.0.0/24", None, "lan", 1, authorized_by="t")
    b = db.add_network("B", "10.2.0.0/24", None, "lan", 1, authorized_by="t")
    c = db.add_network("C", "10.3.0.0/24", None, "lan", 1, authorized_by="t")
    db.set_network_monitoring(c, enabled=False)
    w = NetworkSetupWorker(db)
    seen = []

    def fake(nid):
        seen.append(nid)
        if nid == a:
            raise RuntimeError("réseau A en panne")
    monkeypatch.setattr(w, "discover_network", fake)
    w.rediscover_all()
    assert sorted(seen) == sorted([a, b])                                                     # C suspendu ; la panne de A n'arrête pas B
    db.execute("UPDATE networks SET last_discovery = datetime('now')")                        # tous viennent d'être faits
    seen.clear(); w.rediscover_due()
    assert seen == []                                                                         # planificateur : fréquence propre non écoulée
    db.execute("UPDATE networks SET last_discovery = datetime('now','-10 minutes') WHERE id = ?", (b,))
    w.rediscover_due()
    assert seen == [b]                                                                        # seul B est échu


def test_monitor_needs_silence_before_red(qapp, db):
    from core.monitor import MonitorWorker
    m = MonitorWorker(db)
    h = db.add_host("pc", "10.9.0.5")
    db.execute("UPDATE hosts SET status='online', last_alive_ts=?, failed_probes=5 WHERE id=?", (int(time.time()) - 3, h))
    m._update_availability(db.get_host_by_id(h), False, 0.0, method="none")
    assert db.get_host_by_id(h)["status"] == "online"                                         # 3 s de silence : toujours vert
    db.execute("UPDATE hosts SET last_alive_ts=?, failed_probes=5 WHERE id=?", (int(time.time()) - 300, h))
    m._update_availability(db.get_host_by_id(h), False, 0.0, method="none")
    assert db.get_host_by_id(h)["status"] == "offline"                                        # vraiment parti : rouge


def _patch_confirm(monkeypatch, label):
    monkeypatch.setattr(QMessageBox, "exec", lambda self: 0)
    monkeypatch.setattr(QMessageBox, "clickedButton",
                        lambda self: next(b for b in self.buttons() if b.text().startswith(label)))


def test_delete_dialog_asks_confirmation_then_removes_everything(qtbot, db, monkeypatch):
    from ui.widgets.topology_view import NetworksDialog
    a, ids = _net_with_hosts(db, "A", "10.1.0.0/24", ["10.1.0.5"])
    dlg = NetworksDialog(db, None); qtbot.addWidget(dlg)
    dlg._t.selectRow(0)
    _patch_confirm(monkeypatch, "Annuler")
    dlg._delete()
    assert db.fetchone("SELECT COUNT(*) c FROM networks")["c"] == 1                           # annulé : rien ne bouge
    _patch_confirm(monkeypatch, "Supprimer définitivement")
    dlg._delete()
    assert db.fetchone("SELECT COUNT(*) c FROM networks")["c"] == 0 and _leftovers(db, ids) == []
    assert db.fetchone("SELECT COUNT(*) c FROM audit_logs WHERE action='network_delete'")["c"] == 1


def test_map_network_selector_and_summary(qtbot, db):
    from ui.widgets.topology_view import TopologyView
    a, ids_a = _net_with_hosts(db, "A", "10.1.0.0/24", ["10.1.0.5", "10.1.0.6"])
    b, ids_b = _net_with_hosts(db, "B", "10.2.0.0/24", ["10.2.0.5"], status="offline")
    v = TopologyView(db=db); qtbot.addWidget(v); v.resize(1400, 800); v.show(); v.refresh()
    assert set(v._canvas._nodes) == set(ids_a + ids_b)
    assert v._summary._tiles["online"][0].text() == "2" and v._summary._tiles["offline"][0].text() == "1"
    v._net_combo.setCurrentIndex(v._net_combo.findData(b))                                    # un seul réseau affiché
    assert set(v._canvas._nodes) == set(ids_b) and v._summary._tiles["total"][0].text() == "1"
    db.purge_network(b)                                                                       # réseau supprimé : retour sur « tous »
    v.refresh()
    assert v._net is None and set(v._canvas._nodes) == set(ids_a)


def test_orphan_hosts_are_adopted_into_a_visible_deletable_network(db):
    """Cas réel : équipements sans réseau (« Réseau local » fantôme) rattachés à leur réseau supervisé, jamais recréés après suppression."""
    a = db.add_network("Réseau 192.168.1.0/24", "192.168.1.0/24", None, "lan", 1, authorized_by="t")
    inside = db.add_host("iPhone", "192.168.1.45")
    outside = db.add_host("Autre", "10.20.30.4")
    assert db.fetchone("SELECT network_id FROM hosts WHERE id=?", (inside,))["network_id"] is None
    assert db.adopt_orphan_hosts("10.20.30.0/24") == 2
    assert db.fetchone("SELECT network_id FROM hosts WHERE id=?", (inside,))["network_id"] == a
    net_out = db.fetchone("SELECT id, name FROM networks WHERE cidr='10.20.30.0/24'")
    assert net_out["name"] == "Réseau local"                                                  # visible et supprimable dans la liste
    assert db.fetchone("SELECT network_id FROM hosts WHERE id=?", (outside,))["network_id"] == net_out["id"]
    db.purge_network(net_out["id"])
    assert db.is_removed_network("10.20.30.0/24")
    again = db.add_host("Revenant", "10.20.30.9")
    assert db.adopt_orphan_hosts("10.20.30.0/24") == 0                                        # supprimé : n'est pas recréé tout seul
    assert db.fetchone("SELECT COUNT(*) c FROM networks WHERE cidr='10.20.30.0/24'")["c"] == 0
    db.add_network("Remis", "10.20.30.0/24")                                                  # l'utilisateur le veut de nouveau
    assert not db.is_removed_network("10.20.30.0/24")
    _ = again


def test_local_machine_is_not_reregistered_after_its_network_was_removed(db, monkeypatch):
    from core import local_network as ln
    monkeypatch.setattr(ln, "get_primary_ip", lambda: "10.50.0.7")
    monkeypatch.setattr(ln, "get_default_gateway", lambda: "10.50.0.1")
    monkeypatch.setattr(ln, "get_primary_network", lambda: "10.50.0.0/24")
    n = db.add_network("Local", "10.50.0.0/24", None, "lan", 1, authorized_by="t")
    db.purge_network(n)
    info = ln.ensure_local_hosts(db)
    assert info["local"] is None and db.fetchone("SELECT COUNT(*) c FROM hosts")["c"] == 0


def test_intermittent_phone_never_flaps_but_a_real_departure_is_detected(db):
    """Cas réel : téléphone qui ne répond qu'une minute sur deux. Il reste en ligne ; un vrai départ est tout de même détecté."""
    h = db.add_host("iPhone", "10.7.0.5")
    db.execute("UPDATE hosts SET status='online', device_type='mobile', last_alive_ts=? WHERE id=?", (1000, h))
    t, flips, last = 1000.0, 0, "online"
    for tick in range(0, 1800 // 5):                        # 30 minutes, un passage toutes les 5 s
        t += 5
        answers = (int(t) // 60) % 2 == 0                   # répond une minute sur deux
        presence.presence_step(db, 30, now=t, probe=lambda _h: True if answers else False, tick=tick)
        st = db.get_host_by_id(h)["status"]
        if st != last:
            flips += 1; last = st
    assert flips <= 1                                       # au plus une bascule en 30 minutes (au lieu d'un clignotement permanent)
    for tick in range(400):                                 # vrai départ : plus aucune réponse
        t += 5
        presence.presence_step(db, 30, now=t, probe=lambda _h: False, tick=tick)
    assert db.get_host_by_id(h)["status"] == "offline"


def test_required_silence_grows_with_flapping_and_sleepy_types():
    now = 10_000.0
    assert presence.required_silence_s({"device_type": "workstation"}, 30, now) == 30
    assert presence.required_silence_s({"device_type": "mobile"}, 30, now) == 120
    assert presence.required_silence_s({"device_type": "workstation", "flap_log": f"{now-100},{now-50}"}, 30, now) == 300
    assert presence.required_silence_s({"device_type": "workstation", "flap_log": ",".join(str(now - i * 20) for i in range(1, 5))}, 30, now) == 600
    assert presence.required_silence_s({"device_type": "workstation", "flap_log": f"{now-30000},{now-25000}"}, 30, now) == 30   # bascules vieilles de plus de 6 h : oubliées


def test_intermittent_workstation_settles_after_two_flips(db):
    h = db.add_host("PC", "10.7.0.6")
    db.execute("UPDATE hosts SET status='online', device_type='workstation', last_alive_ts=? WHERE id=?", (1000, h))
    import time as _t
    t, flips, last = _t.time(), 0, "online"                 # horloge réelle : les bascules sont datées comme en production
    db.execute("UPDATE hosts SET last_alive_ts=? WHERE id=?", (int(t), h))
    for tick in range(0, 3600 // 5):
        t += 5
        answers = (int(t) // 60) % 2 == 0
        presence.presence_step(db, 30, now=t, probe=lambda _h: True if answers else False, tick=tick)
        st = db.get_host_by_id(h)["status"]
        if st != last:
            flips += 1; last = st
    assert flips <= 3, flips


def test_proven_departure_is_fast_even_for_a_flappy_phone_but_plain_silence_is_not(db):
    """Preuve nette (ARP en échec) → hors ligne en 30 s à 2 min ; simple silence (téléphone en veille) → on attend."""
    h = db.add_host("iPhone", "10.8.0.5")
    db.execute("UPDATE hosts SET status='online', device_type='mobile', last_alive_ts=?, flap_log=? WHERE id=?",
               (1000, "900,950,980,990", h))
    t = 1000.0
    for tick in range(20):                                   # 100 s de simple silence : un téléphone capricieux reste en ligne
        t += 5
        presence.presence_step(db, 30, now=t, probe=lambda _h: False, tick=tick)
    assert db.get_host_by_id(h)["status"] == "online"
    for tick in range(20):                                   # l'ARP échoue maintenant (il est parti) : détection rapide
        t += 5
        presence.presence_step(db, 30, now=t, probe=lambda _h: "gone", tick=tick)
        if db.get_host_by_id(h)["status"] == "offline":
            break
    assert db.get_host_by_id(h)["status"] == "offline" and tick <= 8


def test_native_neighbor_table_parser_is_exact_and_refuses_odd_layouts():
    import socket, struct
    from core import liveness

    def row(ip, state):
        r = bytearray(88)
        struct.pack_into("<H", r, 0, 2); r[4:8] = socket.inet_aton(ip)
        struct.pack_into("<I", r, 72, 6); struct.pack_into("<I", r, 76, state)
        return bytes(r)
    buf = b"\x03\x00\x00\x00\x00\x00\x00\x00" + row("192.168.1.5", 5) + row("192.168.1.6", 4) + row("192.168.1.7", 1)
    assert liveness.parse_ip_net_table2(buf, 3) == {"192.168.1.5": "reachable", "192.168.1.6": "stale", "192.168.1.7": "dead"}
    assert liveness.parse_ip_net_table2(buf[:60], 3) == {}                                    # tampon tronqué
    bad = bytearray(buf); struct.pack_into("<I", bad, 8 + 76, 99)
    assert liveness.parse_ip_net_table2(bytes(bad), 3) == {}                                  # état aberrant : on ne s'y fie pas


def test_stable_device_with_proof_is_offline_in_30_seconds(db):
    h = db.add_host("PC", "10.8.0.9")
    db.execute("UPDATE hosts SET status='online', device_type='workstation', last_alive_ts=? WHERE id=?", (1000, h))
    t = 1000.0
    for tick in range(10):
        t += 5
        presence.presence_step(db, 30, now=t, probe=lambda _h: "gone", tick=tick)
    assert db.get_host_by_id(h)["status"] == "offline"
