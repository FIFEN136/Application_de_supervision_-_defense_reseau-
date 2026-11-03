import time
import pytest
from PyQt6.QtWidgets import QApplication
from ui.widgets.defense_view import DefenseView
from ui.widgets.incidents_view import IncidentsView
from core.defense import DefenseManager
from core.automation import AutomationEngine


@pytest.fixture()
def admin(security):
    assert security.authenticate("admin", "admin")
    return security


@pytest.fixture()
def view(qapp, db, admin):
    security = admin
    m = DefenseManager(db, security)
    v = DefenseView(db=db, security=security, manager=m)
    yield v, m
    m.stop()


def test_defense_view_builds_and_refreshes_with_data(view, db):
    v, m = view
    db.execute("INSERT INTO honeypot_hits (port, profile, src_ip, src_port, payload) VALUES (2222,'ssh','10.0.0.9',4000,'SSH-2.0')")
    db.execute("INSERT INTO arp_bindings (ip, mac, is_gateway) VALUES ('192.168.1.1','aa:bb:cc:dd:ee:ff',1)")
    v.refresh()
    assert v._hp_hits.rowCount() == 1 and v._arp_tbl.rowCount() == 1
    assert v._sg.rowCount() >= 11                       # règles Sigma intégrées
    assert v.tabs.count() == 7


def test_sigma_test_line_and_toggle(view, db):
    v, m = view
    from core.sigma_engine import seed_builtin_rules
    seed_builtin_rules(db); v.refresh()
    v._sg_line.setText("Failed password for root from 10.0.0.9 port 22 ssh2"); v._sg_test()
    assert "Correspond" in v._sg_out.text() or "Aucune" in v._sg_out.text()
    v._sg.selectRow(0); rid = v._sg_sel()
    before = db.fetchone("SELECT enabled FROM sigma_rules WHERE rule_id=?", (rid,))["enabled"]
    v._sg_toggle()
    assert db.fetchone("SELECT enabled FROM sigma_rules WHERE rule_id=?", (rid,))["enabled"] == 1 - before


def test_toggle_requires_permission(view, db, monkeypatch):
    v, m = view
    monkeypatch.setattr(v, "_allowed", lambda perm="can_manage_config": False)
    monkeypatch.setattr("PyQt6.QtWidgets.QMessageBox.warning", lambda *a, **k: None)
    v._toggle("defense_honeypot", True)
    assert not m.enabled("defense_honeypot")


def test_pipeline_opens_incident_and_proposes_for_new_event_types(db, security):
    from core.defense_common import EventSink
    sink = EventSink(db)
    sink.emit("disaster", "honeypot_hit", "Connexion sur le honeypot 2222 depuis 10.9.9.9")
    sink.emit("high", "rogue_dhcp", "Serveur DHCP non autorisé 10.1.1.1")
    eng = AutomationEngine(db, security)
    res = eng.run_pipeline() if hasattr(eng, "run_pipeline") else None
    assert db.fetchone("SELECT COUNT(*) n FROM incidents")["n"] >= 1
    kinds = {r["action_type"] for r in db.fetchall("SELECT action_type FROM pending_actions")}
    assert "block_ip" in kinds or "isolate_host" in kinds


def test_incidents_view_has_execution_controls_and_simulates(qapp, db, admin, monkeypatch):
    security = admin
    from core.defense_common import EventSink
    EventSink(db).emit("disaster", "honeypot_hit", "Connexion sur le honeypot 2222 depuis 10.9.9.9")
    eng = AutomationEngine(db, security); eng.run_pipeline()
    v = IncidentsView(db=db, security=security); v.refresh()
    v._table.selectRow(0)
    a = db.fetchone("SELECT * FROM pending_actions WHERE action_type='block_ip'")
    assert a, "action block_ip proposée"
    eng.decide_action(a["id"], True, who="admin")
    v._load_actions()
    for r in range(v._actions.rowCount()):
        if v._actions.item(r, 0).data(0x0100) == a["id"]:
            v._actions.selectRow(r)
    shown = []
    monkeypatch.setattr("PyQt6.QtWidgets.QMessageBox.information", lambda *x, **k: shown.append(x[2]))
    monkeypatch.setattr("PyQt6.QtWidgets.QMessageBox.warning", lambda *x, **k: shown.append(x[2]))
    assert v._b_sim.isEnabled()
    v._run_action(True)
    assert shown and db.fetchone("SELECT status FROM action_runs WHERE action_id=?", (a["id"],))["status"] == "simulated"
    v._run_action(False)                                                 # désactivé par défaut → rien d'exécuté
    assert db.fetchone("SELECT COUNT(*) n FROM action_runs WHERE status='ok'")["n"] == 0


def test_main_window_loads_defense_view(qapp, db, security):
    from ui.main_window import MainWindow
    w = MainWindow(db=db, security=security)
    assert "defense" in w._views and "defense" in w._nav_buttons and w.defense is not None
    for k in ("dashboard", "incidents", "hosts", "topology", "events", "console"):
        assert k in w._views
    w.close()
    from PyQt6 import sip
    QApplication.processEvents(); sip.delete(w); QApplication.processEvents()
