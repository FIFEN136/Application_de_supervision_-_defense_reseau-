import socket, time
import pytest
from PyQt6.QtCore import QCoreApplication
from PyQt6.QtWidgets import QMessageBox
from core.defense import DefenseManager
from core import assess, classify
from core.flows import FlowStore, build_netflow_v5
from ui.widgets.security_view import SecurityView
from tests.test_visibility import add_host
from tests.test_policy import net  # noqa: F401  (fixture réseau de test)


@pytest.fixture()
def env(qapp, db, security, net, monkeypatch):
    assert security.authenticate("admin", "admin")
    m = DefenseManager(db, security)
    v = SecurityView(db=db, security=security, manager=m)
    for fn in ("information", "warning"):
        monkeypatch.setattr(QMessageBox, fn, lambda *a, **k: None)
    yield v, m, db
    m.stop()


def free_udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def test_view_builds_with_data_and_three_tabs(env):
    v, m, db = env
    assess.run_assessment(db); v.refresh()
    assert v.tabs.count() == 4 and v._zones.rowCount() == 2 and v._roles.rowCount() == 6 and v._flows.rowCount() == 5
    assert v._enf.rowCount() == 2 and v._fnd.rowCount() >= 1


def test_policy_workflow_through_ui_objects(env):
    v, m, db = env
    v._do(lambda: m.policy.apply_template("isolate_guests"))
    v.refresh(); assert v._rules.rowCount() == 1
    v._rules.selectRow(0); v._rule_approve()
    assert db.fetchone("SELECT status FROM policy_rules")["status"] == "approved"
    v._show_sim(m.policy.simulate(include_drafts=True))
    txt = v._sim.toPlainText()
    assert "Simulation sur" in txt and "chemins critiques" in txt and "192.168.50.9" in txt
    v._rules.selectRow(0); v._rule_retire()
    assert db.fetchone("SELECT status FROM policy_rules")["status"] == "retired"


def test_refusal_is_shown_not_raised(env):
    v, m, db = env
    shown = []
    QMessageBox.warning = lambda *a, **k: shown.append(a[2])
    res = v._do(lambda: m.policy.create_rule({"name": "coupure", "src": "any", "dst": "role:network", "service": "ssh", "action": "deny"}))
    assert res is None and shown and "Coupure" in shown[0]


def test_findings_actions_in_ui(env, net):
    net_ids = net
    v, m, db = env
    db.execute("INSERT INTO port_states (host_id, port, protocol, state) VALUES (?,23,'TCP','open')", (net_ids["srv"],))
    assess.run_assessment(db); v.refresh()
    v._fnd.selectRow(0); fid = v._sel_finding()
    assert fid
    v._finding_detail(); assert "Telnet" in v._fdet.toPlainText() and "Recommandation" in v._fdet.toPlainText()
    v._finding_rule()
    assert db.fetchone("SELECT 1 FROM policy_rules WHERE source = ?", (f"finding:{fid}",))


def test_manager_netflow_toggle_alerts_and_status(env):
    v, m, db = env
    port = free_udp(); db.set_setting("netflow_port", str(port))
    m.set_enabled("defense_netflow", True, "admin")
    st = m.status()["netflow"]; assert st["running"] and st["enabled"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(build_netflow_v5([{"src": "10.1.1.1", "dst": "10.2.2.2", "dport": 22, "proto": 6}]), ("127.0.0.1", m.netflow.port))
    end = time.time() + 3
    while time.time() < end and m.flows.count() < 6: QCoreApplication.processEvents(); time.sleep(0.05)
    assert m.flows.count() == 6
    m.set_enabled("defense_netflow", False, "admin"); assert not m.status()["netflow"]["running"]


def test_manager_jobs_assess_netmap_flows_purge(env):
    v, m, db = env
    r = m.run_job("assess"); assert set(r) == {"new", "fixed", "open", "events"}
    m.netmap.walker = lambda *a: []                                  # pas de vrai SNMP dans les tests
    assert m.run_job("netmap") == {"hosts": 0, "links": 0, "routes": 0, "fdb": 0}
    assert isinstance(m.run_job("flows_local"), int)
    db.execute("UPDATE flows_agg SET last_seen = datetime('now','-40 days')")
    assert m.run_job("purge") is True and m.flows.count() == 0


def test_main_window_has_netsec_view(qapp, db, security):
    from ui.main_window import MainWindow
    from PyQt6 import sip
    from PyQt6.QtWidgets import QApplication
    w = MainWindow(db=db, security=security)
    assert "netsec" in w._views and "netsec" in w._nav_buttons
    for k in ("defense", "netsec", "incidents", "topology"): w._navigate(k)
    w.close(); QApplication.processEvents(); sip.delete(w); QApplication.processEvents()
