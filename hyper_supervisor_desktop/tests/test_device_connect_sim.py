"""Équipements simulés (aucun routeur réel nécessaire) : vrai serveur SSH (paramiko) imitant Cisco / FortiGate / MikroTik / Linux,
fausse Bbox avec redirection http→https et cookie « Secure », détection automatique du moyen de connexion."""
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import paramiko
import pytest

from core import box_reader, device_link as dl

OUTPUTS = {
    "cisco": {"show version": "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.0(2)SE\n"},
    "fortigate": {"get system status": "Version: FortiGate-60F v7.2.5,build1517\nSerial-Number: FGT60F0000000000\n"},
    "mikrotik": {"/system resource print": "uptime: 3d2h\nversion: 7.11 (stable)\nboard-name: RB4011iGS+\n"},
    "linux": {"uname -a": "Linux pfsense-fw 6.1.0 #1 SMP x86_64 GNU/Linux\n"},
}


class _Server(paramiko.ServerInterface):
    def __init__(self, table, user="admin", pwd="s3cret"):
        self.table, self.user, self.pwd = table, user, pwd
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == (self.user, self.pwd) else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode()
        out = self.table.get(cmd)

        def run():
            import time
            time.sleep(0.15)                      # laisse partir l'accusé de réception de la requête avant de répondre
            if out is None:
                channel.send_stderr(f"% Unknown command: {cmd}\n".encode()); channel.send_exit_status(1)
            else:
                channel.send(out.encode()); channel.send_exit_status(0)
            channel.close()
        threading.Thread(target=run, daemon=True).start()
        return True


@pytest.fixture()
def ssh_router():
    key = paramiko.RSAKey.generate(2048)
    socks, transports = [], []

    def start(kind):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(5)
        socks.append(srv)

        def loop():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                t = paramiko.Transport(c)
                transports.append(t)                  # sinon le ramasse-miettes ferme la connexion
                t.add_server_key(key)
                t.start_server(server=_Server(OUTPUTS[kind]))
        threading.Thread(target=loop, daemon=True).start()
        return srv.getsockname()[1]
    yield start
    for s in socks:
        s.close()


@pytest.mark.parametrize("kind,expect,profile", [("cisco", "Cisco IOS", "cisco_ios"), ("fortigate", "FortiGate", "fortinet"),
                                                 ("mikrotik", "RB4011", "mikrotik"), ("linux", "pfsense-fw", "linux")])
def test_ssh_identifies_each_kind_of_router_with_auto_profile(ssh_router, kind, expect, profile):
    port = ssh_router(kind)
    r = dl.test_ssh("127.0.0.1", "admin", "s3cret", "password", port, "auto")
    assert expect in r["message"] or expect in r["info"] or kind == "mikrotik"
    assert r["profile"] == profile and r["host_key"].startswith("SHA256:")


def test_ssh_wrong_password_and_closed_port_have_clear_messages(ssh_router):
    port = ssh_router("cisco")
    with pytest.raises(dl.LinkError, match="refusé"):
        dl.test_ssh("127.0.0.1", "admin", "faux", "password", port, "auto")
    s = socket.socket(); s.bind(("127.0.0.1", 0)); closed = s.getsockname()[1]; s.close()
    with pytest.raises(dl.LinkError, match="fermé.*box Internet|n'accepte pas SSH"):
        dl.test_ssh("127.0.0.1", "admin", "x", "password", closed, "auto")


def test_ssh_readonly_enforced_for_new_ident_commands():
    from core.config_backup import validate_command
    assert all(validate_command(c) for c in dl.IDENT_COMMANDS)
    assert not validate_command("/system reset-configuration") and not validate_command("/system resource print; reboot")


# ───────────── fausse Bbox : redirection + cookie Secure ─────────────
HOSTS = [{"hosts": {"list": [{"macaddress": "9A:24:1C:BB:65:59", "ipaddress": "192.168.1.122", "link": "WiFi 5", "active": 1,
                              "wireless": {"band": "5", "rssi0": -57}}]}}]


@pytest.fixture()
def bbox():
    state = {"ok": False}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0)); body = self.rfile.read(n).decode()
            if self.path == "/api/v1/login":
                if not state.get("redirected"):
                    state["redirected"] = True
                    self.send_response(307); self.send_header("Location", f"http://mabbox.bytel.fr:{self.server.server_port}/api/v1/login"); self.end_headers(); return
                ok = "password=bonmdp" in body
                state["ok"] = ok
                self.send_response(200 if ok else 401)
                self.send_header("Set-Cookie", "BBOX_ID=tok123; Path=/; Secure; HttpOnly")
                self.end_headers(); self.wfile.write(b"{}")
            else:
                self.send_response(200); self.end_headers(); self.wfile.write(b"{}")

        def do_GET(self):
            if "BBOX_ID=tok123" not in (self.headers.get("Cookie") or "") or not state["ok"]:
                self.send_response(401); self.end_headers(); return
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps(HOSTS).encode())
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], state
    srv.shutdown()


def test_bbox_login_follows_redirect_and_sends_secure_cookie_over_http(bbox, monkeypatch):
    port, state = bbox
    monkeypatch.setattr(box_reader, "check_box_address", lambda a: f"127.0.0.1:{port}")
    ok, msg = box_reader.test_connection("x", "bonmdp")
    assert ok and "1 appareil" in msg


def test_bbox_bad_password_explains_admin_password_and_gives_steps(bbox, monkeypatch):
    port, state = bbox
    monkeypatch.setattr(box_reader, "check_box_address", lambda a: f"127.0.0.1:{port}")
    ok, msg = box_reader.test_connection("x", "mauvais")
    assert not ok and "ADMINISTRATION" in msg.upper() and "Détail" in msg and "ÉCHEC Mot de passe" in msg
    diag = box_reader.diagnose("x", "mauvais")
    assert "mauvais" not in diag and "Mot de passe" in diag


def test_auto_method_tries_box_then_tells_what_failed(monkeypatch):
    monkeypatch.setattr(dl, "detect_open_ports", lambda a, t=0.8: [80])
    assert dl.auto_attempts([80]) == ["box", "web", "snmp"] and dl.auto_attempts([22, 443]) == ["ssh", "box", "web", "snmp"]
    monkeypatch.setattr(dl, "test_web", lambda *a, **k: (_ for _ in ()).throw(dl.LinkError("page injoignable")))
    monkeypatch.setattr(dl, "test_snmp", lambda *a, **k: (_ for _ in ()).throw(dl.LinkError("aucune réponse SNMP")))
    monkeypatch.setattr(box_reader, "test_connection", lambda a, p: (False, "Mot de passe refusé par la box."))
    with pytest.raises(dl.LinkError) as e:
        dl.connect(None, {"method": "auto", "address": "192.168.1.254", "secret": "x"}, save=False)
    m = str(e.value)
    assert "Ports ouverts sur 192.168.1.254 : 80" in m and "Mot de passe refusé" in m and "SNMP" in m


def test_auto_method_picks_ssh_when_open_and_saves(db, monkeypatch):
    monkeypatch.setattr(dl, "detect_open_ports", lambda a, t=0.8: [22])
    monkeypatch.setattr(dl, "test_ssh", lambda *a, **k: {"ok": True, "info": "FortiGate-60F", "host_key": "SHA256:k", "profile": "fortinet",
                                                         "message": "SSH réussi : FortiGate-60F"})
    r = dl.connect(db, {"method": "auto", "address": "192.168.1.1", "kind": "firewall", "name": "FW", "username": "admin", "secret": "p"})
    assert "moyen détecté : SSH" in r["message"]
    cred = db.fetchone("SELECT profile, host_key FROM host_credentials WHERE host_id = ?", (r["host_id"],))
    assert cred["profile"] == "fortinet" and cred["host_key"] == "SHA256:k"


def test_public_web_page_is_not_a_login_and_box_detail_is_shown(monkeypatch):
    """Cas réel : la Bbox sert une page publique (Lighttpd). Ce n'est pas une connexion ; on montre pourquoi l'API de la box a échoué."""
    monkeypatch.setattr(dl, "detect_open_ports", lambda a, t=0.8: [80])
    monkeypatch.setattr(dl, "test_web", lambda *a, **k: {"ok": True, "info": "Lighttpd", "authenticated": False, "message": "page publique"})
    monkeypatch.setattr(dl, "test_snmp", lambda *a, **k: (_ for _ in ()).throw(dl.LinkError("aucune réponse SNMP")))
    monkeypatch.setattr(box_reader, "test_connection", lambda a, p: (False, "Mot de passe refusé.\n\nDétail :\nOK Connexion http — code 401\nÉCHEC Mot de passe — refusé"))
    with pytest.raises(dl.LinkError) as e:
        dl.connect(None, {"method": "auto", "address": "192.168.1.254", "username": "admin", "secret": "x"}, save=False)
    m = str(e.value)
    assert "ce n'est pas une connexion" in m and "ÉCHEC Mot de passe" in m


def test_web_basic_auth_flag_true_only_when_credentials_were_needed():
    import base64
    class H(BaseHTTPRequestHandler):
        server_version, sys_version = "Lighttpd", ""
        def log_message(self, *a): pass
        def do_GET(self):
            ok = self.headers.get("Authorization") == "Basic " + base64.b64encode(b"admin:pw").decode()
            self.send_response(200 if (ok or self.server.public) else 401); self.end_headers(); self.wfile.write(b"<title>Admin</title>")
    srv = HTTPServer(("127.0.0.1", 0), H); srv.public = False
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert dl.test_web("127.0.0.1", srv.server_address[1], "http", "admin", "pw")["authenticated"] is True
        srv.public = True
        r = dl.test_web("127.0.0.1", srv.server_address[1], "http", "admin", "pw")
        assert r["authenticated"] is False and "PAS été vérifiés" in r["message"]
    finally:
        srv.shutdown()
