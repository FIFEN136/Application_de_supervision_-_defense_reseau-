import socket, threading, time
import pytest
import paramiko
from core.defense_common import EventSink
from core.config_backup import ConfigBackupManager, validate_command, mask_secrets, HostKeyChanged, ssh_run_commands
from core.action_runner import ActionRunner, ActionRefused


# ───────────── serveur SSH de test (vrai protocole SSH, paramiko côté serveur) ─────────────
_HOSTKEY = paramiko.RSAKey.generate(2048)


class _Srv(paramiko.ServerInterface):
    def __init__(self, outputs):
        self.outputs = outputs; self.seen_cmds = []
    def check_auth_password(self, u, p):
        return paramiko.AUTH_SUCCESSFUL if (u, p) == ("admin", "s3cret") else paramiko.AUTH_FAILED
    def get_allowed_auths(self, u): return "password"
    def check_channel_request(self, kind, cid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_channel_exec_request(self, ch, command):
        cmd = command.decode(); self.seen_cmds.append(cmd)
        out, rc = self.outputs.get(cmd, (f"commande inconnue: {cmd}\n", 1))
        def reply():
            time.sleep(0.15)                      # un vrai équipement confirme la commande avant de répondre
            ch.send(out.encode()); ch.send_exit_status(rc); ch.shutdown_write(); ch.close()
        threading.Thread(target=reply, daemon=True).start()
        return True


class SshServer:
    def __init__(self, outputs, hostkey=None):
        self.outputs = outputs; self.hostkey = hostkey or _HOSTKEY
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(5)
        self.port = self.sock.getsockname()[1]; self.srv = _Srv(outputs); self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()
    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn); t.add_server_key(self.hostkey)
            try:
                t.start_server(server=self.srv)
            except Exception:
                pass
    def close(self):
        self._stop = True; self.sock.close()


RUNNING = "hostname R1\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\nenable secret 5 $1$abc$HASH\nsnmp-server community PUBLIC123 RO\n"


@pytest.fixture()
def env(db, security):
    got = []
    sink = EventSink(db, on_alert=got.append)
    hid = db.add_host("R1", "127.0.0.1", device_type="router")
    return db, sink, got, hid


def _cred(mgr, hid, port, **kw):
    mgr.set_credentials(hid, "admin", "s3cret", port=port, profile="cisco_ios", **kw)


# ───────────── sauvegarde de configuration ─────────────
def test_backup_first_unchanged_changed_with_diff_and_masking(env):
    db, sink, got, hid = env
    outs = {"show running-config": ("! Last configuration change at 10:00\n" + RUNNING, 0)}
    srv = SshServer(outs)
    try:
        mgr = ConfigBackupManager(db, sink); _cred(mgr, hid, srv.port)
        assert mgr.backup_host(hid)["status"] == "first"
        assert mgr.get_credentials(hid)["host_key"].startswith("SHA256:")            # clé d'hôte mémorisée (TOFU)
        outs["show running-config"] = ("! Last configuration change at 11:30\n" + RUNNING, 0)   # seule l'heure change
        assert mgr.backup_host(hid)["status"] == "unchanged"                          # bruit ignoré
        outs["show running-config"] = (RUNNING + "ip route 0.0.0.0 0.0.0.0 10.9.9.9\nsnmp-server community NEWSECRET RW\n", 0)
        r = mgr.backup_host(hid)
        assert r["status"] == "changed" and r["added"] == 2 and r["removed"] == 0
        ev = db.fetchone("SELECT * FROM events WHERE event_type='config_change'")
        assert ev["severity"] == "high" and "NEWSECRET" not in ev["description"] and "***" in ev["description"]
        h = mgr.history(hid); assert len(h) == 2
        d = mgr.diff(h[1]["id"], h[0]["id"])
        assert "+ip route 0.0.0.0 0.0.0.0 10.9.9.9" in d and "NEWSECRET" not in d       # secrets masqués dans le diff
    finally:
        srv.close()


def test_secrets_and_configs_encrypted_at_rest(env):
    db, sink, got, hid = env
    srv = SshServer({"show running-config": (RUNNING, 0)})
    try:
        mgr = ConfigBackupManager(db, sink); _cred(mgr, hid, srv.port); mgr.backup_host(hid)
    finally:
        srv.close()
    raw = db.fetchone("SELECT secret_enc FROM host_credentials")["secret_enc"]
    assert "s3cret" not in raw
    assert "PUBLIC123" not in db.fetchone("SELECT content FROM config_backups")["content"]
    assert mgr.get_credentials(hid)["has_secret"] and "secret" not in mgr.get_credentials(hid)   # jamais renvoyé sans demande


def test_hostkey_change_refused_and_alerted(env):
    db, sink, got, hid = env
    s1 = SshServer({"show running-config": (RUNNING, 0)})
    mgr = ConfigBackupManager(db, sink); _cred(mgr, hid, s1.port)
    assert mgr.backup_host(hid)["status"] == "first"
    s1.close()
    s2 = SshServer({"show running-config": ("hostname EVIL\n", 0)}, hostkey=paramiko.RSAKey.generate(2048))
    try:
        db.execute("UPDATE host_credentials SET port = ?", (s2.port,))
        r = mgr.backup_host(hid)
        assert r["status"] == "error" and r.get("hostkey_changed")
        assert db.fetchone("SELECT severity FROM events WHERE event_type='ssh_hostkey_changed'")["severity"] == "disaster"
        assert len(mgr.history(hid)) == 1                                              # rien n'a été sauvegardé
        mgr.forget_host_key(hid)                                                        # après vérification humaine
        assert mgr.backup_host(hid)["status"] == "changed"
    finally:
        s2.close()


def test_bad_password_and_unreachable_are_clean_errors(env):
    db, sink, got, hid = env
    srv = SshServer({"show running-config": (RUNNING, 0)})
    try:
        mgr = ConfigBackupManager(db, sink)
        mgr.set_credentials(hid, "admin", "mauvais", port=srv.port, profile="cisco_ios")
        r = mgr.backup_host(hid); assert r["status"] == "error" and "Authentication" in r["error"]
    finally:
        srv.close()
    mgr.set_credentials(hid, "admin", "", port=1, profile="cisco_ios")                  # conserve l'ancien secret
    assert mgr.backup_host(hid)["status"] == "error"
    assert ConfigBackupManager(db, sink).backup_host(9999)["status"] == "error"


def test_only_read_only_commands_allowed(env):
    db, sink, got, hid = env
    for ok in ("show running-config", "show ip route | include 10.0", "display current-configuration", "/export",
               "cat /etc/hosts", "ip -br addr", "uname -a"):
        assert validate_command(ok), ok
    for bad in ("configure terminal", "reload", "show run; reload", "show run && reboot", "cat /etc/shadow > /tmp/x",
                "rm -rf /", "ip addr add 1.2.3.4/24 dev eth0", "show `id`", "show $(id)", "", "x" * 300,
                "cat ../../etc/passwd", "show run | tee /tmp/x"):
        assert not validate_command(bad), bad
    mgr = ConfigBackupManager(db, sink)
    with pytest.raises(ValueError):
        mgr.set_credentials(hid, "u", "p", profile="custom", commands=["reload"])
    with pytest.raises(ValueError):
        mgr.set_credentials(hid, "u", "p", profile="custom")                            # personnalisé sans commande
    assert "***" in mask_secrets("enable secret 5 $1$abc$HASH") and "HASH" not in mask_secrets("enable secret 5 $1$abc$HASH")


def test_mikrotik_and_linux_profile_normalization(env):
    assert ConfigBackupManager.normalize("# jan/02/2026 10:00:00 by RouterOS 7.1\n/ip address\nadd x\n\n", "mikrotik") == "/ip address\nadd x"


# ───────────── exécution des actions ─────────────
def _action(db, hid, target, atype="block_ip", status="approved"):
    return db.execute("INSERT INTO pending_actions (host_id, host_name, action_type, target, reason, plan, status) "
                      "VALUES (?, 'h', ?, ?, 'test', 'plan', ?)", (hid, atype, target, status)).lastrowid


@pytest.fixture()
def runner_env(db, security, monkeypatch):
    from core import local_network as lnet
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(lnet, "get_local_addresses", lambda: {"192.168.1.10"})
    security.authenticate("admin", "admin")
    sink = EventSink(db)
    calls = []
    def local(argv): calls.append(argv); return 0, "ok"
    r = ActionRunner(db, security, sink, local_runner=local, system="Linux")
    hid = db.add_host("victime", "192.168.1.50")
    return db, security, r, calls, hid


def test_execution_guardrails_in_order(runner_env):
    db, sec, r, calls, hid = runner_env
    aid = _action(db, hid, "10.9.9.9", status="pending")
    with pytest.raises(ActionRefused, match="APPROUVÉE"): r.execute(aid)
    db.execute("UPDATE pending_actions SET status='approved' WHERE id=?", (aid,))
    with pytest.raises(ActionRefused, match="désactivée"): r.execute(aid)                # interrupteur général OFF par défaut
    assert calls == []
    sim = r.execute(aid, simulate=True)                                                  # la simulation, elle, est permise
    assert sim["status"] == "simulated" and calls == [] and "iptables" in sim["command"]
    r.set_enabled(True)
    ok = r.execute(aid)
    assert ok["status"] == "ok" and calls == [["iptables", "-I", "INPUT", "-s", "10.9.9.9", "-j", "DROP"],
                                              ["iptables", "-I", "OUTPUT", "-d", "10.9.9.9", "-j", "DROP"]]
    with pytest.raises(ActionRefused, match="déjà été exécutée"): r.execute(aid)
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='action_executed_ok'")


def test_rollback_restores_and_is_audited(runner_env):
    db, sec, r, calls, hid = runner_env
    r.set_enabled(True); aid = _action(db, hid, "10.9.9.9")
    run = r.execute(aid); calls.clear()
    rb = r.rollback(run["run_id"])
    assert rb["status"] == "rolled_back" and calls[0][1] == "-D"
    assert db.fetchone("SELECT status FROM action_runs WHERE id=?", (run["run_id"],))["status"] == "rolled_back"
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='action_rolled_back'")
    with pytest.raises(ActionRefused): r.rollback(run["run_id"])                         # déjà annulée


def test_protected_and_invalid_targets_refused(runner_env):
    db, sec, r, calls, hid = runner_env
    r.set_enabled(True)
    for bad in ("192.168.1.1", "192.168.1.10", "127.0.0.1", "224.0.0.1", "0.0.0.0", "pas-une-ip", "10.0.0.1; rm -rf /",
                "10.0.0.1:99999", "10.0.0.1:abc"):
        with pytest.raises(ActionRefused): r.execute(_action(db, hid, bad))
    with pytest.raises(ActionRefused, match="pas exécutable"): r.execute(_action(db, hid, "10.9.9.9", atype="isolate_host"))
    assert calls == []


def test_partial_failure_rolls_back_applied_steps(runner_env):
    db, sec, r, calls, hid = runner_env
    seq = iter([(0, "ok"), (1, "boom"), (0, "ok")])
    r.local_runner = lambda argv: (calls.append(argv), next(seq))[1]
    r.set_enabled(True)
    res = r.execute(_action(db, hid, "10.9.9.9"))
    assert res["status"] == "failed" and "annulation" in res["output"]
    assert calls[-1][1] == "-D"                                                          # l'étape 1 a été défaite


def test_viewer_role_cannot_execute(runner_env):
    db, sec, r, calls, hid = runner_env
    r.set_enabled(True); aid = _action(db, hid, "10.9.9.9")
    sec._current_user = {"login": "lecteur", "role": "read-only"}
    with pytest.raises(ActionRefused, match="rôle"): r.execute(aid)


def test_remote_port_block_over_real_ssh(runner_env):
    db, sec, r, calls, hid = runner_env
    srv = SshServer({"sudo -n iptables -I INPUT -p tcp --dport 3389 -j DROP": ("", 0),
                     "sudo -n iptables -D INPUT -p tcp --dport 3389 -j DROP": ("", 0)})
    try:
        db.execute("UPDATE hosts SET ip_address = '192.168.1.77' WHERE id = ?", (hid,))   # équipement distant (IP privée)
        real = r.ssh_runner
        def to_test_server(cred, cmds, **kw):                  # le « réseau » : on joint le serveur SSH de test
            return real({**cred, "address": "127.0.0.1"}, cmds, **kw)
        r.ssh_runner = to_test_server
        ConfigBackupManager(db, r.sink).set_credentials(hid, "admin", "s3cret", port=srv.port, profile="linux")
        r.set_enabled(True); aid = _action(db, hid, "192.168.1.77:3389")
        res = r.execute(aid)
        assert res["status"] == "ok" and res["kind"] == "remote_block_port"
        assert "sudo -n iptables -I INPUT -p tcp --dport 3389 -j DROP" in srv.srv.seen_cmds
        assert r.rollback(res["run_id"])["status"] == "rolled_back"
        with pytest.raises(ActionRefused, match="SSH"):                                    # fermer le port SSH = se couper l'accès
            r.execute(_action(db, hid, f"192.168.1.77:{srv.port}"))
        db.execute("UPDATE host_credentials SET profile = 'cisco_ios'")
        with pytest.raises(ActionRefused, match="Linux"): r.execute(_action(db, hid, "192.168.1.77:8080"))
        db.execute("DELETE FROM host_credentials")
        with pytest.raises(ActionRefused, match="accès SSH"): r.execute(_action(db, hid, "192.168.1.77:8080"))
    finally:
        srv.close()
