import json, hmac, hashlib, threading, http.server, json as _j
import pytest
from aiosmtpd.controller import Controller
from core.notifier import NotifierManager
from core.security import CryptoHelper

EVENT = {"severity": "disaster", "host_name": "srv<script>x</script>", "description": "Port 3389/TCP : closed → open",
         "port": 3389, "state_before": "closed", "state_after": "open", "event_type": "port_change"}

class Inbox:
    def __init__(self): self.msgs = []
    async def handle_DATA(self, server, session, envelope):
        self.msgs.append(envelope.content.decode("utf-8", "replace")); return "250 OK"

@pytest.fixture()
def smtp():
    import socket
    t = socket.socket(); t.bind(("127.0.0.1", 0)); port = t.getsockname()[1]; t.close()
    box = Inbox(); c = Controller(box, hostname="127.0.0.1", port=port); c.start()
    yield box, port
    c.stop()

class Hook(http.server.BaseHTTPRequestHandler):
    got = []
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        Hook.got.append((self.path, dict(self.headers), body)); self.send_response(200); self.end_headers()
    def log_message(self, *a): pass

@pytest.fixture()
def http_srv(db):
    db.set_setting("webhook_allow_internal", "127.0.0.1")        # serveur de test local : exception explicite (anti-SSRF)
    Hook.got = []; s = http.server.HTTPServer(("127.0.0.1", 0), Hook)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_address[1]}"
    s.shutdown()

def set_media(db, name, cfg):
    db.execute("UPDATE media_types SET active=1, config_json=? WHERE name=?", (json.dumps(cfg), name))

def test_email_sent_html_escaped_no_tls_relay(db, smtp):
    box, port = smtp
    set_media(db, "Email SMTP", {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "a@x.fr", "smtp_to": "b@x.fr, c@x.fr"})
    db.execute("UPDATE media_types SET active=0 WHERE name='Slack NOC'")
    sent = NotifierManager(db).send_all(EVENT)
    assert sent == ["Email SMTP"] and len(box.msgs) == 1
    import email
    msg = email.message_from_string(box.msgs[0])
    html_part = next(p for p in msg.walk() if p.get_content_type() == "text/html").get_payload(decode=True).decode()
    assert "<script>" not in html_part and "&lt;script&gt;" in html_part   # injection HTML neutralisée
    assert html_part.count("Changement</td>") == 1

def test_email_refuses_authenticated_plaintext(db, smtp):
    box, port = smtp                                              # serveur sans STARTTLS
    set_media(db, "Email SMTP", {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_user": "u",
                                 "smtp_password": CryptoHelper.encrypt("pw"), "smtp_from": "a@x.fr", "smtp_to": "b@x.fr"})
    db.execute("UPDATE media_types SET active=0 WHERE name='Slack NOC'")
    assert NotifierManager(db).send_all(EVENT) == [] and not box.msgs   # jamais d'identifiants en clair

def test_webhook_hmac_signature_and_encrypted_secret(db, http_srv):
    secret = "s3cr3t-hook"
    set_media(db, "PagerDuty", {"webhook_url": CryptoHelper.encrypt(http_srv + "/hook"),
                                "webhook_secret": CryptoHelper.encrypt(secret)})
    db.execute("UPDATE media_types SET active=0 WHERE name IN ('Slack NOC','Email SMTP')")
    cfg_raw = db.fetchone("SELECT config_json FROM media_types WHERE name='PagerDuty'")["config_json"]
    assert secret not in cfg_raw and "127.0.0.1" not in cfg_raw     # rien en clair en base
    assert NotifierManager(db).send_all(EVENT) == ["PagerDuty"]
    path, headers, body = Hook.got[0]
    assert path == "/hook"
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert headers["X-Hub-Signature-256"] == expected               # signature vérifiable côté récepteur
    assert json.loads(body)["severity"] == "disaster"

def test_slack_block_kit(db, http_srv):
    set_media(db, "Slack NOC", {"webhook_url": http_srv + "/slack"})
    db.execute("UPDATE media_types SET active=0 WHERE name='Email SMTP'")
    assert NotifierManager(db).send_all(EVENT) == ["Slack NOC"]
    payload = json.loads(Hook.got[0][2])
    assert payload["attachments"][0]["blocks"][0]["type"] == "header"

def test_severity_filter_and_bad_urls(db, http_srv):
    set_media(db, "Slack NOC", {"webhook_url": http_srv})
    n = NotifierManager(db)
    assert n.send_all({**EVENT, "severity": "information"}) == [] and not Hook.got   # pas de spam info
    set_media(db, "Slack NOC", {"webhook_url": "file:///etc/passwd"})
    assert "Slack NOC" not in n.send_all(EVENT)                      # schéma file:// refusé
    set_media(db, "Slack NOC", {"webhook_url": "http://127.0.0.1:1/x"})
    assert "Slack NOC" not in n.send_all(EVENT)                      # serveur HS : pas d'exception

def test_test_media(db, http_srv):
    set_media(db, "Slack NOC", {"webhook_url": http_srv})
    ok, msg = NotifierManager(db).test_media("Slack NOC"); assert ok
    assert NotifierManager(db).test_media("Inconnu")[0] is False
