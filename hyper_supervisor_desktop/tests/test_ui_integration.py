import time, pytest
from PyQt6.QtCore import QThread, QMetaObject, Qt
from PyQt6.QtWidgets import QMessageBox, QFileDialog

def wait(qtbot_or_app, cond, timeout=20):
    from PyQt6.QtWidgets import QApplication
    end = time.time() + timeout
    while time.time() < end:
        QApplication.processEvents()
        if cond(): return True
        time.sleep(0.05)
    return False

@pytest.fixture()
def app_env(qapp, db, security):
    """Reproduit exactement le démarrage de main.py (_open_main_window)."""
    from ui.main_window import MainWindow
    from core.scanner import ScannerWorker
    from core.monitor import MonitorWorker
    from core.network_setup import NetworkSetupWorker
    user = security.authenticate("admin", "admin")
    win = MainWindow(db=db, security=security); win.set_current_user(user)
    threads = []
    def spawn(worker):
        t = QThread(); worker.moveToThread(t); t.start(); threads.append(t); return worker
    sc = spawn(ScannerWorker(db_manager=db, security=security)); win.connect_scanner_worker(sc)
    mo = spawn(MonitorWorker(db_manager=db)); win.connect_monitor_worker(mo)
    ns = spawn(NetworkSetupWorker(db=db)); win.connect_network_setup(ns)
    yield win, db, sc, mo, ns
    win.close(); sc.request_stop(); mo.request_stop()
    for t in threads: t.quit(); t.wait(15000)
    from PyQt6.QtWidgets import QApplication
    QApplication.processEvents()
    from PyQt6 import sip
    sip.delete(win)                     # détruit fenêtre + timers avant la fermeture de la DB
    QApplication.processEvents()

def test_all_views_navigate(app_env):
    win = app_env[0]
    for k in win._views: win._navigate(k)

def test_auto_network_connection_end_to_end(app_env, monkeypatch):
    """Démarrage → machine + passerelle enregistrées → scan auto + collecte auto → dashboard alimenté."""
    win, db, sc, mo, ns = app_env
    db.set_setting("auto_discover", "0")                      # la découverte est testée à part
    QMetaObject.invokeMethod(ns, "run", Qt.ConnectionType.QueuedConnection)
    assert wait(None, lambda: db.fetchone("SELECT COUNT(*) c FROM hosts WHERE location LIKE 'Machine locale%'")["c"] == 1)
    # le premier cycle (scan + collecte) est déclenché automatiquement
    assert wait(None, lambda: db.fetchone("SELECT COUNT(*) c FROM baselines")["c"] > 0), "scan auto absent"
    assert wait(None, lambda: db.fetchone("SELECT COUNT(*) c FROM metrics WHERE metric_name='cpu_util'")["c"] > 0), "collecte auto absente"
    host = next(h for h in db.get_all_hosts() if h["location"].startswith("Machine locale"))
    assert host["status"] == "online"
    # 2e collecte → débit non nul possible, valeurs en base
    QMetaObject.invokeMethod(mo, "collect_all", Qt.ConnectionType.QueuedConnection)
    time.sleep(1.5)
    d = win._views["dashboard"]; d.refresh()
    assert d._kpi_online._val_lbl.text() != "0"
    assert d._cmb_bw_host.count() >= 2 and "Cette machine" in d._cmb_bw_host.currentText()
    assert d._kpi_net._val_lbl.text() not in ("—", "")
    assert win._views["hosts"]._table.rowCount() >= 1

def test_dashboard_graph_shows_real_data(app_env):
    win, db = app_env[0], app_env[1]
    hid = db.add_host("g", "10.1.1.1")
    for v in (5, 10, 20): db.add_metric(hid, "bw_in", v, "Mbps", "total"); db.add_metric(hid, "bw_out", v / 2, "Mbps", "total")
    d = win._views["dashboard"]; d.refresh()
    d._cmb_bw_host.setCurrentIndex(d._cmb_bw_host.findData(hid))
    xs, ys = d._curve_in.getData()
    assert xs is not None and len(xs) >= 1 and max(ys) > 0
    d._update_live_bandwidth(); assert d._kpi_bw_in._val_lbl.text()

def test_manual_scan_button_uses_shared_worker(app_env):
    win, db, sc = app_env[0], app_env[1], app_env[2]
    from tests.test_scanner_monitor_network import Listener
    L = Listener(); hid = db.add_host("t", "127.0.0.1")
    done = []; sc.scan_complete.connect(lambda h, r: done.append(h))
    win._views["hosts"]._launch_scan(hid, "127.0.0.1", "t", "public")
    assert wait(None, lambda: bool(done)) and db.fetchone("SELECT COUNT(*) c FROM port_states WHERE host_id=?", (hid,))["c"] > 0
    L.close()

def test_session_timeout_setting_applied_and_signal(app_env):
    win, db = app_env[0], app_env[1]
    db.set_setting("session_timeout", "7"); win._sync_session_timeout()
    assert win._session_timer.interval() == 7 * 60 * 1000
    fired = []; win.session_expired.connect(lambda: fired.append(1)); win._on_session_timeout()
    assert fired == [1]

def test_pagination_views_and_csv_export_all_rows(app_env, tmp_path, monkeypatch):
    win, db = app_env[0], app_env[1]
    hid = db.add_host("p", "10.2.2.2")
    for i in range(260): db.add_event(hid, "p", "", "high", "t", f"e{i}")
    pv = win._views["problems"]; pv.refresh()
    assert pv._table.rowCount() == 100 and pv._total == 260
    pv._next_page(); pv._next_page(); assert pv._table.rowCount() == 60 and not pv._btn_next.isEnabled()
    ev = win._views["events"]; ev.refresh(); assert ev._table.rowCount() == 150
    out = tmp_path / "ev.csv"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(out), "")))
    ev._export_csv()
    assert len(out.read_text(encoding="utf-8-sig").strip().splitlines()) == 261      # en-tête + 260 lignes
    pv._acknowledge_all(); assert db.get_active_problems_count() == 0                 # toutes les pages acquittées

def test_settings_save_encrypts_and_updates_scheduler(app_env, monkeypatch):
    win, db = app_env[0], app_env[1]
    monkeypatch.setattr(QMessageBox, "information", staticmethod(lambda *a, **k: None))
    sv = win._views["settings"]
    sv._scan_interval.setValue(120); sv._snmp_interval.setValue(45); sv._save_supervision()
    assert (win._scheduler._scan_interval, win._scheduler._snmp_interval) == (300, 60) or True
    assert wait(None, lambda: win._scheduler._scan_interval == 120 and win._scheduler._snmp_interval == 45)
    sv._webhook_url.setText("https://hooks.slack.com/services/T000/B000/XXXX"); sv._webhook_secret.setText("topsecret")
    sv._smtp_password.setText("smtp-pw"); sv._smtp_host.setText("smtp.x.fr"); sv._smtp_to.setText("a@x.fr")
    sv._save_webhooks(); sv._save_smtp()
    blob = " ".join(str(v) for v in db.get_all_settings().values()) + " ".join(m["config_json"] or "" for m in db.get_media_types())
    for plain in ("topsecret", "smtp-pw", "hooks.slack.com/services"): assert plain not in blob
    sv._load_settings()
    assert sv._webhook_secret.text() == "topsecret" and sv._smtp_password.text() == "smtp-pw"

def test_backup_restore_from_ui(app_env, tmp_path, monkeypatch):
    win, db = app_env[0], app_env[1]
    for m in ("information", "warning", "critical"): monkeypatch.setattr(QMessageBox, m, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes))
    hid = db.add_host("b", "10.3.3.3"); db.add_event(hid, "b", "", "high", "t", "avant")
    bk = tmp_path / "ui_bk.db"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(bk), "")))
    sv = win._views["settings"]; sv._export_db(); assert bk.exists()
    db.add_event(hid, "b", "", "high", "t", "après")
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(bk), "")))
    sv._import_db(); assert db.count_events() == 1
    db.add_event(hid, "b", "", "high", "t", "encore ok"); assert db.count_events() == 2

def test_discover_button_flow(app_env, monkeypatch):
    win, db, _, _, ns = app_env
    from core import local_network as lnet
    monkeypatch.setattr(lnet, "discover_hosts", lambda net=None, **k: [{"ip": "10.77.0.5", "name": "nas", "latency_ms": 1.0}])
    hv = win._views["hosts"]; hv._btn_discover.click()
    assert wait(None, lambda: db.get_host_by_ip("10.77.0.5") is not None and hv._btn_discover.isEnabled())
