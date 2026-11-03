"""Écrans d'administration, rapports, console, topologie, widgets du Dashboard avec données."""
import os, pytest
from PyQt6.QtWidgets import QMessageBox, QDialog, QApplication, QFileDialog


@pytest.fixture(autouse=True)
def _cleanup_widgets(qapp):
    """Détruit les vues (et leurs QTimer) avant la fermeture de la base : aucun timer orphelin."""
    from PyQt6 import sip
    yield
    from PyQt6.QtCore import QEvent
    for w in QApplication.topLevelWidgets():
        if not sip.isdeleted(w):
            w.close(); w.deleteLater()
    QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    QApplication.processEvents()


@pytest.fixture()
def msgs(monkeypatch):
    log = []
    for n in ("warning", "information", "critical"):
        monkeypatch.setattr(QMessageBox, n, staticmethod(lambda *a, _n=n, **k: log.append((_n, a[1:])) or QMessageBox.StandardButton.Ok))
    monkeypatch.setattr(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    return log


class FakeDlg:
    def __init__(self, data): self._d = data
    def exec(self): return QDialog.DialogCode.Accepted
    def get_data(self): return self._d


def login(security, who="admin", pwd="admin"):
    u = security.authenticate(who, pwd); security.set_current_user(u); return u


# ---------------- Groupes ----------------
def test_group_crud_and_delete_guard(qapp, db, security, msgs, monkeypatch):
    login(security)
    from ui.widgets.admin import groups_view as gv
    v = gv.GroupsView(db=db, security=security)
    monkeypatch.setattr(gv, "GroupDialog", lambda *a, **k: FakeDlg({"name": "DMZ", "description": "d"}))
    v._add(); assert any(g["name"] == "DMZ" for g in db.get_host_groups())
    v._add(); assert msgs and msgs[-1][0] == "warning"          # doublon: pas de crash
    gid = next(g["id"] for g in db.get_host_groups() if g["name"] == "DMZ")
    db.add_host(name="h1", ip="10.9.9.9", group_id=gid)
    groups = {g["name"]: g for g in db.get_host_groups()}
    assert groups["DMZ"]["host_count"] == 1
    v._delete(gid)                                              # groupe non vide : refusé
    assert any(g["id"] == gid for g in db.get_host_groups())
    db.execute("DELETE FROM hosts WHERE group_id=?", (gid,))
    v._delete(gid)
    assert not any(g["id"] == gid for g in db.get_host_groups())


def test_group_counts_not_inflated_by_events(db):
    gid = db.execute("INSERT INTO host_groups (name) VALUES ('G')").lastrowid
    hid = db.add_host(name="x", ip="10.1.1.1", group_id=gid)
    hid = db.get_host_by_ip("10.1.1.1")["id"]
    for i in range(5):
        db.execute("INSERT INTO events (host_id,severity,event_type,description) VALUES (?,?,?,?)", (hid, "high", "t", "d%d" % i))
    g = next(g for g in db.get_host_groups() if g["name"] == "G")
    assert g["host_count"] == 1 and g["problem_count"] == 5


# ---------------- Utilisateurs ----------------
def test_users_rules(qapp, db, security, msgs, monkeypatch):
    login(security)
    from ui.widgets.admin import users_view as uv
    v = uv.UsersView(db=db, security=security)
    monkeypatch.setattr(uv, "UserDialog", lambda *a, **k: FakeDlg({"login": "bob", "full_name": "B", "role": "operator", "password": "secret1"}))
    v._add_user(); assert any(u["login"] == "bob" for u in db.get_users())
    n = len(msgs); v._add_user()                                 # login dupliqué : message, pas de crash
    assert len(msgs) == n + 1 and msgs[-1][0] == "warning"
    admin = next(u for u in db.get_users() if u["login"] == "admin")
    v._toggle_active(admin["id"], 0)                             # ni soi-même ni le dernier admin
    assert next(u for u in db.get_users() if u["login"] == "admin")["active"] == 1
    # un operator ne peut rien gérer
    u = db.get_users(); bob = next(x for x in u if x["login"] == "bob")
    security.set_current_user({"login": "bob", "role": "operator"})
    v._toggle_active(bob["id"], 0); assert next(x for x in db.get_users() if x["login"] == "bob")["active"] == 1
    v._edit_user(bob); v._add_user()
    assert not any(x["login"] == "bob" and x["role"] != "operator" for x in db.get_users())


# ---------------- Hôtes (admin) ----------------
def test_hosts_config_permissions_and_duplicates(qapp, db, security, msgs, monkeypatch):
    login(security)
    from ui.widgets.admin import hosts_config as hc
    v = hc.HostsConfigView(db=db, security=security)
    data = {"name": "srv1", "ip_address": "10.5.5.5", "snmp_community": "priv", "device_type": "server", "group_id": None, "location": "L"}
    monkeypatch.setattr(hc, "HostDialog", lambda *a, **k: FakeDlg(data))
    v._add_host(); h = db.get_host_by_ip("10.5.5.5"); assert h and h["snmp_community"] == "priv"
    raw = db.fetchone("SELECT snmp_community FROM hosts WHERE id=?", (h["id"],))["snmp_community"]
    assert "priv" not in raw                                      # chiffrée au repos
    v._add_host(); assert msgs[-1][0] == "warning"                # doublon géré
    data2 = dict(data, name="srv1b", location="Z")
    monkeypatch.setattr(hc, "HostDialog", lambda *a, **k: FakeDlg(data2))
    v._edit_host(h); assert db.get_host_by_ip("10.5.5.5")["location"] == "Z"
    security.set_current_user({"login": "ro", "role": "read-only"})
    data3 = dict(data, name="hack"); monkeypatch.setattr(hc, "HostDialog", lambda *a, **k: FakeDlg(data3))
    v._edit_host(h); v._delete_host(h["id"]); v._add_host()
    assert db.get_host_by_ip("10.5.5.5") and not db.fetchone("SELECT 1 FROM hosts WHERE name='hack'")


# ---------------- Médias ----------------
def test_media_test_button_really_sends(qapp, db, security, msgs, monkeypatch):
    login(security)
    from ui.widgets.admin.media_view import MediaView
    from core import notifier
    calls = []
    monkeypatch.setattr(notifier.NotifierManager, "test_media", lambda self, n: calls.append(n) or (True, "ok-reel"))
    v = MediaView(db=db, security=security)
    v._test_media("Email"); assert calls == ["Email"]
    assert "ok-reel" in msgs[-1][1][1]
    monkeypatch.setattr(notifier.NotifierManager, "test_media", lambda self, n: (False, "SMTP refusé"))
    v._test_media("Email"); assert msgs[-1][0] == "warning" and "SMTP refusé" in msgs[-1][1][1]


def test_media_test_unconfigured_is_honest(db):
    from core.notifier import NotifierManager
    ok, msg = NotifierManager(db).test_media("n'existe-pas")
    assert not ok and "introuvable" in msg


# ---------------- Export / Rapports / Console / Topologie ----------------
def test_exports_real_files(qapp, db, tmp_path):
    from utils.exporter import Exporter
    db.add_host(name="a", ip="10.2.2.2")
    hosts = db.get_all_hosts()
    pdf = tmp_path / "r.pdf"; Exporter.export_pdf(str(pdf), hosts, "Rapport")
    assert pdf.read_bytes()[:5] == b"%PDF-" and pdf.stat().st_size > 800
    Exporter.export_hosts_csv(str(tmp_path / "h.csv"), hosts)
    Exporter.export_json(str(tmp_path / "h.json"), hosts)
    assert "10.2.2.2" in (tmp_path / "h.csv").read_text() and "10.2.2.2" in (tmp_path / "h.json").read_text()
    # injection de formule CSV neutralisée ?
    Exporter.export_events_csv(str(tmp_path / "e.csv"), [{"id": 1, "host_name": "=cmd|' /C calc'!A0", "severity": "high", "event_type": "t", "description": "x", "occurred_at": "now", "acknowledged": 0}])
    assert not any(l.startswith("=") for l in (tmp_path / "e.csv").read_text().splitlines()[1:])


def test_reports_view_pdf_button(qapp, db, tmp_path, monkeypatch, msgs):
    from ui.widgets.reports_view import ReportsView
    db.add_host(name="a", ip="10.2.2.3")
    v = ReportsView(db=db); v.refresh()
    out = tmp_path / "x.pdf"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    v._export_pdf(); assert out.exists() and out.read_bytes()[:4] == b"%PDF"


def test_console_filter_pause_export(qapp, tmp_path, monkeypatch):
    from ui.widgets.console_view import ConsoleView
    c = ConsoleView(); c.append_log("INFO", "hello"); c.append_log("ERROR", "boom")
    assert "hello" in c._console.toPlainText() and "boom" in c._console.toPlainText()
    c._toggle_pause(True); c.append_log("INFO", "masque"); assert "masque" not in c._console.toPlainText()
    c._toggle_pause(False)
    out = tmp_path / "c.txt"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    c._export(); assert "boom" in out.read_text()


def test_topology_all_statuses_and_no_secret(qapp, db):
    from ui.widgets.topology_view import TopologyView
    for i, (st, ty) in enumerate([("online", "router"), ("offline", "switch"), ("unreachable", "server"), ("unknown", "ap")]):
        db.add_host(name=f"t{i}", ip=f"10.3.3.{i+1}", device_type=ty, snmp_community="SECRETCOMM")
        db.execute("UPDATE hosts SET status=? WHERE ip_address=?", (st, f"10.3.3.{i+1}"))
    v = TopologyView(db=db); v.refresh()
    assert len(v._canvas._nodes) == 4
    v._show_detail(db.get_all_hosts()[0])
    assert all("SECRETCOMM" not in l.text() for l in v._detail_fields.values())


# ---------------- Dashboard avec données ----------------
def test_dashboard_widgets_with_data(qapp, db):
    from ui.widgets.dashboard_view import DashboardView
    ids = {}
    for n, ip, st in (("a","10.0.0.1","online"),("b","10.0.0.2","online"),("c","10.0.0.3","offline"),
                      ("d","10.0.0.4","unreachable"),("e","10.0.0.5","unknown")):
        hid = db.add_host(n, ip); db.update_host_status(hid, st, "2026-10-13T10:00:00"); ids[n] = hid
    for sev in ("disaster", "high", "high", "average", "warning", "information"):
        db.add_event(ids["a"], "a", "", sev, "t", f"evt {sev}")
    for n, v in (("a", 95), ("b", 72), ("c", 10), ("d", 55), ("e", 30), ("a", 96)):
        db.add_metric(ids[n], "cpu_util", v, "%")
    db.add_metric(ids["a"], "bw_in", 12.5, "Mbps", "total"); db.add_metric(ids["a"], "bw_out", 3.0, "Mbps", "total")
    d = DashboardView(db=db); d.refresh(); QApplication.processEvents()
    assert [k._val_lbl.text() for k in (d._kpi_online, d._kpi_offline, d._kpi_unreachable)] == ["2", "1", "1"]
    assert d._kpi_problems._val_lbl.text() == "6"
    assert {k: l.text() for k, l in d._severity_bar._segments.items()}["high"] == "2"
    assert d._pbar_dispo.value() == 40
    names = [n.text() for n, b, p in d._cpu_rows if n.text()]
    assert len(names) == len(set(names)) and names[0] == "a"            # pas de doublon, valeur la plus récente
    assert d._tbl_problems.rowCount() == 6
    xs, ys = d._curve_in.getData()
    assert xs is not None and len(xs) >= 1 and max(ys) == pytest.approx(12.5)
    assert float(d._kpi_bw_in._val_lbl.text()) >= 0
    d.deleteLater()


def test_metrics_and_latest_views(qapp, db):
    from ui.widgets.metrics_view import MetricsView
    from ui.widgets.latest_data_view import LatestDataView
    hid = db.add_host("m", "10.7.7.7")
    for v in (1.0, 2.0, 3.0):
        db.add_metric(hid, "bw_in", v, "Mbps", "total"); db.add_metric(hid, "cpu_util", v * 10, "%")
    m = MetricsView(db=db); m.refresh()
    assert m._series and any(len(v) for v in m._series.values()) if isinstance(m._series, dict) else True
    l = LatestDataView(db=db); l.refresh(); assert l._table.rowCount() >= 1
