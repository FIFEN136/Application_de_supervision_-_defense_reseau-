"""v11 : visibilité de tous les équipements (ARP, noms, latence par machine), messages de scan, migrations."""
import sqlite3, socket
import pytest
from core import local_network as lnet
from core.monitor import MonitorWorker
from core.scanner import ScannerWorker


def test_arp_only_host_stays_online(db, monkeypatch):
    """Un PC dont le pare-feu bloque ping ET TCP mais présent dans la table ARP n'est plus « rouge »."""
    monkeypatch.setattr(lnet, "is_local_address", lambda ip: False)
    monkeypatch.setattr(lnet, "ping_icmp", lambda ip, timeout_s=1.0: (False, 0.0))
    monkeypatch.setattr(lnet, "_probe_async", lambda ip, t, ports=None: _coro((False, 0.0)))
    monkeypatch.setattr(lnet, "is_onlink", lambda ip: True)
    monkeypatch.setattr(lnet, "arp_cache", lambda ttl=4.0: {"192.168.1.23": "aa:bb:cc:dd:ee:ff"})
    r = lnet.probe_host_ex("192.168.1.23")
    assert r["alive"] and r["method"] == "arp"
    assert lnet.probe_host_ex("192.168.1.99")["alive"] is False       # absent de l'ARP → vraiment hors ligne
    hid = db.add_host("pc", "192.168.1.23"); db.execute("UPDATE hosts SET snmp_enabled=0, status='offline' WHERE id=?", (hid,))
    MonitorWorker(db_manager=db).collect_all()
    h = db.get_host_by_id(hid)
    assert h["status"] == "online" and h["reach_method"] == "arp"


async def _coro(v):
    return v


def test_latency_metric_stored_per_host(db, monkeypatch):
    monkeypatch.setattr(lnet, "is_local_address", lambda ip: False)
    monkeypatch.setattr(lnet, "probe_host_ex", lambda ip, *a, **k: {"alive": True, "latency_ms": 12.5, "method": "icmp"})
    a = db.add_host("a", "10.0.0.1"); b = db.add_host("b", "10.0.0.2")
    db.execute("UPDATE hosts SET snmp_enabled=0")
    MonitorWorker(db_manager=db).collect_all()
    series = db.get_latency_series(24)
    assert set(series) == {"a", "b"}                                    # UNE courbe par machine, nommée
    assert {r["name"] for r in db.get_top_latency(5)} == {"a", "b"}


def test_friendly_names_and_rename():
    assert lnet.friendly_name("pc-bob", "workstation", "", "10.0.0.7") == "pc-bob"
    n = lnet.friendly_name("", "mobile", "", "192.168.1.154")
    assert n == "Mobile-154" and lnet.is_auto_name(n)
    assert not lnet.is_auto_name("DESKTOP-40119BE")


def test_register_renames_auto_named_host_and_flags_unknown(db):
    nid = db.add_network("N", "192.168.3.0/24")
    f = [{"ip": "192.168.3.5", "name": "", "mac": "aa:aa:aa:aa:aa:05", "vendor": "", "device_type": "mobile", "open_ports": []}]
    lnet.register_network_hosts(db, nid, f)                              # 1re découverte = référence
    h = db.get_host_by_ip("192.168.3.5")
    assert h["name"] == "Mobile-5" and h["approved"] == 1 and h["snmp_enabled"] == 0
    f[0]["name"] = "iPhone-de-Lea"
    lnet.register_network_hosts(db, nid, f)
    assert db.get_host_by_ip("192.168.3.5")["name"] == "iPhone-de-Lea"   # meilleur nom découvert → renommé
    res = lnet.register_network_hosts(db, nid, f + [{"ip": "192.168.3.6", "name": "", "mac": "", "vendor": "",
                                                      "device_type": "unknown", "open_ports": []}])
    assert len(res["added"]) == 1 and db.get_host_by_ip("192.168.3.6")["approved"] == 0   # nouveau après référence → inconnu


def test_local_machine_not_duplicated_when_ip_changes(db, monkeypatch):
    monkeypatch.setattr(lnet, "get_primary_ip", lambda: "192.168.1.10")
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: "192.168.1.1")
    lnet.ensure_local_hosts(db)
    monkeypatch.setattr(lnet, "get_primary_ip", lambda: "10.20.30.40")      # autre réseau
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: "10.20.30.1")
    lnet.ensure_local_hosts(db)
    locs = db.fetchall("SELECT * FROM hosts WHERE location=?", (lnet.LOCAL_LOCATION,))
    gws = db.fetchall("SELECT * FROM hosts WHERE location=?", (lnet.GATEWAY_LOCATION,))
    assert len(locs) == 1 and locs[0]["ip_address"] == "10.20.30.40"
    assert len(gws) == 1 and gws[0]["ip_address"] == "10.20.30.1"


def test_scan_console_message_is_explicit(db):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1); port = s.getsockname()[1]
    hid = db.add_host("srv", "127.0.0.1"); sc = ScannerWorker(db); logs = []
    sc.log_message.connect(lambda lvl, m: logs.append(m))
    try:
        sc.scan_host(hid, "127.0.0.1", "srv", [port, port + 1 if port < 65000 else port - 1], timeout=0.5)
    finally:
        s.close()
    done = [m for m in logs if m.startswith("Scan terminé")][0]
    assert "1 port(s) ouvert(s) sur 2 testés" in done and "aucun changement par rapport à la référence" in done


def test_migration_turns_snmp_off_for_auto_hosts(tmp_path):
    from database.db_manager import DatabaseManager
    path = str(tmp_path / "old.db")
    d = DatabaseManager(path); d.initialize()
    hid = d.add_host("gw", "192.168.1.1", location=lnet.GATEWAY_LOCATION)
    own = d.add_host("manuel", "192.168.1.50", location="Salle serveur")
    d.execute("UPDATE hosts SET snmp_enabled=1"); d.execute("DELETE FROM settings WHERE key='mig_auto_snmp_off'")
    d.close()
    d2 = DatabaseManager(path); d2.initialize()
    assert d2.get_host_by_id(hid)["snmp_enabled"] == 0                  # passerelle auto : plus « injoignable »
    assert d2.get_host_by_id(own)["snmp_enabled"] == 1                  # hôte saisi par l'utilisateur : inchangé
    d2.close()


def test_dashboard_has_latency_panels(db, qtbot):
    from ui.widgets.dashboard_view import DashboardView
    a = db.add_host("alpha", "10.0.0.1"); b = db.add_host("beta", "10.0.0.2")
    db.add_metric(a, "latency", 5.0, "ms"); db.add_metric(b, "latency", 40.0, "ms")
    v = DashboardView(db=db); qtbot.addWidget(v)
    assert len(v._lat_curves) == 2
    assert v._lat_rows[0][0].text() == "beta" and v._lat_rows[1][0].text() == "alpha"
    assert "SNMP" in v._lbl_cpu_hint.text() or "SNMP" in v._lbl_bw_hint.text()


def test_incidents_view_and_human_validation(db, qtbot, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    from ui.widgets.incidents_view import IncidentsView
    from core.automation import AutomationEngine
    h = db.add_host("srv", "10.5.5.5")
    db.add_event(h, "srv", "", "disaster", "port_change", "Port 3389/TCP : closed → open", port=3389, state_before="closed", state_after="open")
    eng = AutomationEngine(db); eng.run_pipeline()
    v = IncidentsView(db=db); qtbot.addWidget(v)
    assert v._table.rowCount() == 1 and v._table.item(0, 0).text().startswith("P")
    v._table.selectRow(0)
    assert "Chronologie" in v._sheet.toHtml() and v._actions.rowCount() == 1
    v._actions.selectRow(0)
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    shown = []
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: shown.append(a[2]))
    v._decide(True)
    assert db.fetchone("SELECT status FROM pending_actions")["status"] == "approved" and "netsh" in shown[0]
