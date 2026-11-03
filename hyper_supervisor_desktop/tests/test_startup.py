"""Régression : le vrai chemin de démarrage de main.py (le crash ScannerWorker(db=...) n'était vu que là)."""
import time
from PyQt6.QtWidgets import QApplication, QMessageBox


def test_open_main_window_starts_all_workers(qapp, db, security, monkeypatch):
    import main as M
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    ctl = M.AppController(qapp, db, security)
    ctl._current_user = security.authenticate("admin", "admin")
    ctl._open_main_window()
    try:
        assert ctl._scanner_thread.isRunning() and ctl._monitor_thread.isRunning() and ctl._net_thread.isRunning()
        end = time.time() + 20
        while time.time() < end and not db.fetchone("SELECT COUNT(*) c FROM metrics")["c"]:
            QApplication.processEvents(); time.sleep(0.05)
        assert db.fetchone("SELECT COUNT(*) c FROM hosts")["c"] >= 1          # réseau détecté automatiquement
        assert db.fetchone("SELECT COUNT(*) c FROM metrics")["c"] > 0         # collecte automatique active
    finally:
        ctl._window.close(); ctl._stop_workers()
        QApplication.processEvents()
        from PyQt6 import sip
        sip.delete(ctl._window)
    assert not ctl._scanner_thread.isRunning() and not ctl._monitor_thread.isRunning()


def test_login_dialog_lockout_and_hint(qapp, db, security):
    import main as M
    dlg = M.LoginDialog(security)
    dlg._f_login.setText("admin")
    for _ in range(security.MAX_FAILED_ATTEMPTS):
        dlg._f_pwd.setText("mauvais"); dlg._try_login()
    dlg._f_pwd.setText("admin"); dlg._try_login()
    assert dlg.get_user() is None and "verrouillé" in dlg._lbl_error.text().lower() or "tentatives" in dlg._lbl_error.text().lower()


def test_automation_worker_runs_in_real_app(qapp, db, security, monkeypatch):
    """Le pipeline tourne dans son thread, depuis la vue Incidents, dans l'application réellement démarrée."""
    import main as M
    monkeypatch.setattr(QMessageBox, "warning", staticmethod(lambda *a, **k: None))
    ctl = M.AppController(qapp, db, security)
    ctl._current_user = security.authenticate("admin", "admin")
    ctl._open_main_window()
    try:
        assert ctl._auto_thread.isRunning() and "incidents" in ctl._window._views
        h = db.add_host("probe", "10.77.77.77")
        db.add_event(h, "probe", "", "disaster", "port_change", "Port 22/TCP : closed → open", port=22,
                     state_before="closed", state_after="open")
        ctl._window._views["incidents"]._btn_run.click()
        end = time.time() + 15
        while time.time() < end and not (db.fetchone("SELECT 1 FROM incidents") and db.fetchone("SELECT 1 FROM pipeline_runs")):
            QApplication.processEvents(); time.sleep(0.05)
        assert db.fetchone("SELECT 1 FROM incidents") and db.fetchone("SELECT 1 FROM pipeline_runs")
    finally:
        ctl._window.close(); ctl._stop_workers()
        QApplication.processEvents()
        from PyQt6 import sip
        sip.delete(ctl._window)
