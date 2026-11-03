"""Corrections v8 : diagnostic SMTP, colonne Médias, débit réseau, icônes/couleurs du dashboard."""
import json
import smtplib
import socket

from core import local_network as lnet
from core.notifier import NotifierManager, explain_smtp_error, validate_smtp_settings


def test_smtp_host_must_not_be_an_email_address():
    assert "nom d'hôte" in validate_smtp_settings("smtp@procus.com", 587, "a@b.com")
    assert validate_smtp_settings("smtp.gmail.com", 587, "a@b.com") is None
    assert validate_smtp_settings("smtp.gmail.com", 587, "pas-une-adresse")
    assert validate_smtp_settings("", 587, "a@b.com")


def test_smtp_error_is_explained_not_generic():
    assert "introuvable" in explain_smtp_error(socket.gaierror(11001, "x"), "smtp@procus.com", 587)
    msg = explain_smtp_error(smtplib.SMTPAuthenticationError(535, b"bad"), "smtp.gmail.com", 587)
    assert "mot de passe d'application" in msg
    assert "Délai" in explain_smtp_error(TimeoutError(), "h", 25)


def test_send_email_returns_the_real_reason(db):
    cfg = {"smtp_host": "serveur-inexistant.invalid", "smtp_port": 587,
           "smtp_to": "a@b.com", "smtp_from": "x <noreply@b.com>"}
    ok, why = NotifierManager(db)._send_email_ex({"severity": "high"}, cfg, "t")
    assert not ok and "introuvable" in why
    ok, why = NotifierManager(db)._send_email_ex({"severity": "high"}, {**cfg, "smtp_host": "a@b.com"}, "t")
    assert not ok and "nom d'hôte" in why


def test_media_test_explains_unconfigured_and_unsupported(db):
    mgr = NotifierManager(db)
    ok, msg = mgr.test_media("Email SMTP")
    assert not ok and "non configuré" in msg
    ok, msg = mgr.test_media("SMS Twilio")
    assert not ok


def test_media_view_shows_address_and_state(db, qtbot):
    from ui.widgets.admin.media_view import MediaView, media_summary
    db.execute("UPDATE media_types SET config_json=? WHERE name='Email SMTP'",
               (json.dumps({"smtp_host": "smtp.exemple.com", "smtp_port": 587, "smtp_to": "a@b.com"}),))
    addr, state = media_summary(next(m for m in db.get_media_types() if m["name"] == "Email SMTP"))
    assert addr == "smtp.exemple.com:587 → a@b.com" and state == "Configuré"
    v = MediaView(db=db); qtbot.addWidget(v)
    rows = {v._table.item(r, 1).text(): r for r in range(v._table.rowCount())}
    assert "configuré" in v._table.item(rows["Email SMTP"], 5).text()
    assert v._table.item(rows["Email SMTP"], 4).text().startswith("smtp.exemple.com")
    assert v._table.item(rows["Email SMTP"], 3).text()             # description renseignée


def test_bandwidth_uses_primary_nic_and_readable_units():
    assert lnet._is_physical_nic("Local Area Connection")          # avant : exclu à tort (préfixe « lo »)
    assert lnet._is_physical_nic("Wi-Fi") and lnet._is_physical_nic("Ethernet")
    assert not lnet._is_physical_nic("vEthernet (WSL)") and not lnet._is_physical_nic("lo")
    assert lnet.format_rate(0.16) == ("160", "Kb/s")
    assert lnet.format_rate(700) == ("700.0", "Mb/s")
    assert lnet.format_rate(1500) == ("1.50", "Gb/s")


def test_bandwidth_sample_above_link_speed_is_discarded(monkeypatch):
    s = lnet.BandwidthSampler()
    s._nic, s._nic_checked = "eth0", 1e12                          # interface figée pour le test
    monkeypatch.setattr(lnet, "link_speed_mbps", lambda nic=None: 100.0)
    seq = iter([(0, 0), (500_000_000, 0)])                         # 500 Mo en ~1 s ≫ lien 100 Mb/s
    monkeypatch.setattr(s, "_read", lambda: next(seq))
    s.sample()
    s._last = (s._last[0] - 1.0, 0, 0)
    assert s.sample() == (0.0, 0.0)


def test_alpha_helper_is_valid_qt_color():
    from ui.styles import alpha
    assert alpha("#8E44AD", "22") == "rgba(142, 68, 173, 0.13)"


def test_dashboard_icons_are_svg_pixmaps_like_the_sidebar(db, qtbot):
    from ui.widgets.dashboard_view import DashboardView
    d = DashboardView(db=db); qtbot.addWidget(d)
    for card in (d._kpi_online, d._kpi_offline, d._kpi_unreachable, d._kpi_problems,
                 d._kpi_bw_in, d._kpi_bw_out, d._kpi_net, d._kpi_gw):
        pm = card._icon_lbl.pixmap()
        assert pm is not None and not pm.isNull()
    d._kpi_bw_in.set_value("700.0", "Mb/s")
    assert d._kpi_bw_in._unit_lbl.text() == "Mb/s"


def test_splash_follows_real_progress_and_closes(qtbot):
    from ui.splash import SplashScreen
    s = SplashScreen(); s.start()
    s.set_progress(30, "Chargement de l'interface…"); s.set_progress(10, "ignoré")   # ne recule jamais
    assert s._target == 30 and s._text == "ignoré" or s._target == 30
    s.finish()
    assert not s.isVisible()


def test_main_window_reports_startup_progress(db, security, qtbot):
    from ui.main_window import MainWindow
    seen = []
    w = MainWindow(db=db, security=security, progress=lambda p, t: seen.append(p))
    qtbot.addWidget(w)
    assert seen == sorted(seen) and seen[-1] >= 50 and len(seen) >= 10      # progression réelle, par vue
    from PyQt6 import sip                                    # détruit la fenêtre et ses minuteurs avant la fermeture de la base
    from PyQt6.QtWidgets import QApplication
    w.close(); QApplication.processEvents(); sip.delete(w); QApplication.processEvents()
