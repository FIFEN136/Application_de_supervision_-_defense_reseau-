"""Service e-mail intégré : relais, envoi direct (MX), diagnostic, file d'attente."""
import json
import random
import socket
import struct
import threading

import pytest
from aiosmtpd.controller import Controller

from core import mailer
from core.notifier import NotifierManager, validate_smtp_settings

EVENT = {"severity": "high", "host_name": "srv-1", "description": "Port 22 ouvert", "port": 22,
         "state_before": "closed", "state_after": "open", "event_type": "port_change"}


class Inbox:
    def __init__(self): self.msgs = []
    async def handle_DATA(self, server, session, envelope):
        self.msgs.append((envelope.mail_from, list(envelope.rcpt_tos), envelope.content.decode("utf-8", "replace")))
        return "250 OK"


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def smtp():
    box, port = Inbox(), free_port()
    c = Controller(box, hostname="127.0.0.1", port=port); c.start()
    yield box, port
    c.stop()


def set_email(db, cfg):
    db.execute("UPDATE media_types SET active=1, config_json=? WHERE name='Email SMTP'", (json.dumps(cfg),))
    db.execute("UPDATE media_types SET active=0 WHERE name != 'Email SMTP'")


class FakeDns(threading.Thread):
    """Serveur DNS UDP minimal : répond à toute requête MX avec la liste donnée."""
    def __init__(self, mx, rcode=0):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.3); self.mx, self.rcode, self.stop = mx, rcode, False
        self.port = self.sock.getsockname()[1]
    def run(self):
        while not self.stop:
            try: data, addr = self.sock.recvfrom(512)
            except OSError: continue
            q_end = data.index(b"\x00", 12) + 5
            ans = b""
            for pref, host in self.mx:
                rd = struct.pack("!H", pref) + b"".join(bytes([len(l)]) + l.encode() for l in host.split(".")) + b"\x00"
                ans += b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 60, len(rd)) + rd
            hdr = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0], 0x8180 | self.rcode, 1, len(self.mx), 0, 0)
            self.sock.sendto(hdr + data[12:q_end] + ans, addr)
    def close(self): self.stop = True; self.join(1); self.sock.close()


@pytest.fixture()
def dns():
    made = []
    def make(mx, rcode=0):
        d = FakeDns(mx, rcode); d.start(); made.append(d); return d
    yield make
    for d in made: d.close()


# ───────────── DNS ─────────────
def test_resolve_mx_orders_by_preference_and_falls_back(dns):
    d = dns([(20, "mx2.exemple.fr"), (10, "mx1.exemple.fr")])
    assert mailer.resolve_mx("exemple.fr", [("127.0.0.1", d.port)]) == ["mx1.exemple.fr", "mx2.exemple.fr"]
    d2 = dns([])
    assert mailer.resolve_mx("sans-mx.fr", [("127.0.0.1", d2.port)]) == ["sans-mx.fr"]      # repli RFC 5321
    d3 = dns([], rcode=3)
    assert mailer.resolve_mx("inconnu.fr", [("127.0.0.1", d3.port)]) == ["inconnu.fr"]
    for bad in ("", "a..b", "x" * 64 + ".fr", "é" * 300):
        with pytest.raises(ValueError):
            mailer.resolve_mx(bad, [("127.0.0.1", 9)])
    with pytest.raises(OSError):
        mailer.resolve_mx("exemple.fr", [("127.0.0.1", free_port())], timeout=0.2)


def test_dns_parser_survives_garbage():
    rnd = random.Random(7)
    for _ in range(400):
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 120)))
        try:
            assert isinstance(mailer.parse_mx_response(blob, 1), list)
        except ValueError:
            pass
    loop = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c" + b"\x00\x0f\x00\x01"   # pointeur sur lui-même
    with pytest.raises(ValueError):
        mailer.parse_mx_response(loop, 1)


# ───────────── envoi ─────────────
def test_relay_via_notifier_and_security_rules(db, smtp):
    box, port = smtp
    set_email(db, {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "a@x.fr", "smtp_to": "b@x.fr"})
    assert NotifierManager(db).send_all(EVENT) == ["Email SMTP"] and len(box.msgs) == 1
    set_email(db, {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "a@x.fr", "smtp_to": "b@x.fr",
                   "smtp_user": "u", "smtp_password": "p"})
    ok, detail = NotifierManager(db)._send_email_ex(dict(EVENT, event_type="test"), {"smtp_host": "127.0.0.1", "smtp_port": port,
        "smtp_from": "a@x.fr", "smtp_to": "b@x.fr", "smtp_user": "u", "smtp_password": "p"}, "t")
    assert not ok and "STARTTLS" in detail                          # identifiants jamais envoyés en clair
    ok, detail = NotifierManager(db)._send_email_ex(dict(EVENT, event_type="test"), {"smtp_host": "127.0.0.1", "smtp_port": port,
        "smtp_security": "starttls", "smtp_from": "a@x.fr", "smtp_to": "b@x.fr"}, "t")
    assert not ok and "STARTTLS" in detail                          # mode imposé : refus clair


def test_direct_mode_needs_no_smtp_server(db, smtp, dns):
    box, port = smtp
    d = dns([(5, "127.0.0.1")])
    cfg = {"mail_mode": "direct", "direct_port": port, "nameservers": [("127.0.0.1", d.port)],
           "smtp_to": "alice@exemple.fr, bob@exemple.fr", "smtp_from": ""}
    assert validate_smtp_settings("", 587, cfg["smtp_to"], "direct") is None
    assert validate_smtp_settings("", 587, cfg["smtp_to"]) is not None
    ok, detail = NotifierManager(db)._send_email_ex(EVENT, cfg, "direct")
    assert ok, detail
    assert len(box.msgs) == 1 and sorted(box.msgs[0][1]) == ["alice@exemple.fr", "bob@exemple.fr"]
    assert "directement" in detail


def test_friendly_messages_are_plain_french():
    import smtplib, ssl
    assert "mot de passe d'application" in mailer.friendly(smtplib.SMTPAuthenticationError(535, b"x"))
    assert "certificat" in mailer.friendly(ssl.SSLCertVerificationError())
    assert "introuvable" in mailer.friendly(socket.gaierror(), "smtp.x.fr")
    assert "bloque" in mailer.friendly(TimeoutError(), "smtp.x.fr", 25)
    assert "Connexion refusée" in mailer.friendly(ConnectionRefusedError(), "h", 1)
    assert mailer.is_transient(ConnectionRefusedError()) and not mailer.is_transient(smtplib.SMTPAuthenticationError(535, b""))


def test_presets_are_complete():
    for name, p in mailer.PRESETS.items():
        assert p["host"] and 1 <= p["port"] <= 65535 and p["security"] in mailer.SECURITY_CHOICES and p["help"], name


# ───────────── diagnostic ─────────────
def test_diagnose_relay_success_and_failures(smtp):
    box, port = smtp
    base = {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "a@x.fr", "smtp_to": "b@x.fr"}
    steps = mailer.diagnose(base)
    assert all(s["ok"] for s in steps) and [s["step"] for s in steps][:3] == ["Destinataire", "Adresse du serveur", f"Connexion au port {port}"]
    assert not box.msgs                                              # simple vérification : aucun message envoyé
    st = mailer.diagnose(dict(base, smtp_port=free_port()))
    assert not st[-1]["ok"] and "pare-feu" in st[-1]["advice"] and st[-1]["step"].startswith("Connexion")
    st = mailer.diagnose(dict(base, smtp_host="nom-qui-nexiste-pas.invalid"))
    assert not st[-1]["ok"] and st[-1]["step"] == "Adresse du serveur"
    assert not mailer.diagnose(dict(base, smtp_to=""))[-1]["ok"]
    assert not mailer.diagnose(dict(base, smtp_host=""))[-1]["ok"]
    sent = mailer.diagnose(base, send_test=True, build_message=lambda: ("t", "Subject: t\r\n\r\ncorps", ["b@x.fr"]))
    assert sent[-1]["step"] == "Envoi du message de test" and sent[-1]["ok"] and len(box.msgs) == 1


def test_diagnose_direct_mode(smtp, dns):
    box, port = smtp
    d = dns([(1, "127.0.0.1")])
    cfg = {"mail_mode": "direct", "direct_port": port, "nameservers": [("127.0.0.1", d.port)], "smtp_to": "x@exemple.fr"}
    st = mailer.diagnose(cfg)
    assert all(s["ok"] for s in st) and any("Recherche" in s["step"] for s in st)
    st = mailer.diagnose(dict(cfg, direct_port=free_port()))
    assert not st[-1]["ok"] and "port 25" in st[-1]["advice"]


# ───────────── file d'attente ─────────────
def test_alert_is_queued_when_network_down_then_resent(db):
    port = free_port()                                              # personne n'écoute : panne passagère
    cfg = {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "a@x.fr", "smtp_to": "b@x.fr"}
    set_email(db, cfg)
    nm = NotifierManager(db)
    assert nm.send_all(EVENT) == []
    box = mailer.Outbox(db)
    assert box.count_pending() == 1 and "renvoyée" in nm._send_email_ex(EVENT, cfg, "x")[1]
    assert box.count_pending() == 2
    res = box.flush(cfg)                                            # pas encore dû (attente 1 min) → conservé
    assert res["kept"] == 2 and res["sent"] == 0
    res = box.flush(cfg, force=True)                                # toujours en panne → reste en file, essai compté
    assert res["kept"] == 2 and db.fetchone("SELECT MIN(attempts) a FROM mail_outbox")["a"] == 2
    inbox = Inbox(); c = Controller(inbox, hostname="127.0.0.1", port=port); c.start()
    try:
        res = nm.flush_outbox(force=True)
    finally:
        c.stop()
    assert res["sent"] == 2 and len(inbox.msgs) == 2 and box.count_pending() == 0
    assert db.fetchone("SELECT COUNT(*) n FROM mail_outbox WHERE raw != ''")["n"] == 0      # contenu effacé après envoi


def test_test_mail_and_config_errors_are_not_queued(db, smtp):
    box, port = smtp
    cfg = {"smtp_host": "127.0.0.1", "smtp_port": free_port(), "smtp_from": "a@x.fr", "smtp_to": "b@x.fr"}
    NotifierManager(db)._send_email_ex(dict(EVENT, event_type="test"), cfg, "t")
    assert mailer.Outbox(db).count_pending() == 0                   # un test manuel n'est jamais mis en file
    NotifierManager(db)._send_email_ex(EVENT, dict(cfg, smtp_from="pas-une-adresse", smtp_user=""), "t")
    assert mailer.Outbox(db).count_pending() == 0


def test_outbox_gives_up_after_max_attempts_and_is_bounded(db):
    o = mailer.Outbox(db)
    mid = o.enqueue("a@x.fr", ["b@x.fr"], "Subject: x\r\n\r\ny", "x")
    db.execute("UPDATE mail_outbox SET attempts = ? WHERE id = ?", (mailer.MAX_ATTEMPTS - 1, mid))
    res = o.flush({"smtp_host": "127.0.0.1", "smtp_port": free_port()}, force=True)
    assert res["failed"] == 1 and db.fetchone("SELECT status FROM mail_outbox WHERE id=?", (mid,))["status"] == "failed"
    for _ in range(505):
        o.enqueue("a@x.fr", ["b@x.fr"], "raw", "s")
    assert o.count_pending() <= 500
    o.purge()


# ───────────── interface : onglet « Notifications SMTP » ─────────────
def test_settings_tab_presets_modes_save_and_diagnose(qapp, db, smtp, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    from ui.widgets.settings_view import SettingsView
    box, port = smtp
    shown = []
    for fn in ("information", "warning"):
        monkeypatch.setattr(QMessageBox, fn, lambda parent, title, text, *a, **k: shown.append((title, text)))
    v = SettingsView(db=db)
    i = v._smtp_preset.findData("Gmail"); v._smtp_preset.setCurrentIndex(i)
    assert v._smtp_host.text() == "smtp.gmail.com" and v._smtp_port.value() == 587 and v._smtp_security.currentData() == "starttls"
    assert "mot de passe d'application" in v._mail_help.text()
    v._mail_mode.setCurrentIndex(v._mail_mode.findData("direct"))
    assert not v._smtp_host.isEnabled() and "Aucun compte" in v._mail_help.text()
    v._mail_mode.setCurrentIndex(v._mail_mode.findData("relay"))
    assert v._smtp_host.isEnabled()
    v._smtp_host.setText("127.0.0.1"); v._smtp_port.setValue(port)
    v._smtp_from.setText("a@x.fr"); v._smtp_to.setText("b@x.fr")
    v._smtp_security.setCurrentIndex(v._smtp_security.findData("auto"))
    v._save_smtp()
    assert db.get_setting("mail_mode") == "relay" and db.get_setting("smtp_security") == "auto"
    cfg = json.loads(db.fetchone("SELECT config_json FROM media_types WHERE name='Email SMTP'")["config_json"])
    assert cfg["smtp_host"] == "127.0.0.1" and cfg["mail_mode"] == "relay" and cfg["smtp_verify_tls"] is True
    shown.clear(); v._diagnose_smtp()
    assert shown and "OK — " in shown[0][1] and "Tout est en ordre" in shown[0][1]
    shown.clear(); v._smtp_port.setValue(free_port()); v._diagnose_smtp()
    assert "ÉCHEC — " in shown[0][1] and "pare-feu" in shown[0][1]
    shown.clear(); v._smtp_port.setValue(port); v._test_smtp()
    assert "E-mail envoyé" in shown[0][1] and len(box.msgs) == 1
    mailer.Outbox(db).enqueue("a@x.fr", ["b@x.fr"], "Subject: x\r\n\r\ny", "x")
    v._refresh_queue_label(); assert "1 e-mail" in v._queue_lbl.text()
    shown.clear(); v._retry_outbox()
    assert "Envoyés : 1" in shown[0][1] and len(box.msgs) == 2
