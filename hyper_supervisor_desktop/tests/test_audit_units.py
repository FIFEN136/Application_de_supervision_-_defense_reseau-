"""Audit v15.1 — tests unitaires complémentaires : robustesse des analyseurs (entrées hostiles), validation,
authentification des agents, travailleur réseau, EventSink, boucle du gestionnaire de défense."""
import json
import random
import threading
import time

import pytest

from core import local_network as lnet
from core.agent_server import AgentServer, sign
from core.defense import DefenseManager
from core.defense_common import EventSink, is_valid_ip, safe_json
from core.flows import parse_netflow_v5, build_netflow_v5
from core.log_pipeline import LogPipeline, extract_fields, parse_syslog
from core.network_setup import NetworkSetupWorker
from core.notifier import NotifierManager, NotificationDeduper, validate_smtp_settings
from core.security import InputValidator
from core.sigma_engine import RuleError, parse_rule

rnd = random.Random(1234)


# ───────────── validation des entrées ─────────────
INJECTIONS = ["'; DROP TABLE hosts;--", "1 OR 1=1", "<script>alert(1)</script>", "$(reboot)", "`id`", "a" * 500,
              "../../etc/passwd", "x\x00y"]


@pytest.mark.parametrize("bad", INJECTIONS)
def test_validators_reject_hostile_input(bad):
    for fn in (InputValidator.name, InputValidator.login, InputValidator.snmp_community):
        try:
            out = fn(bad)
        except ValueError:
            continue
        assert out == bad.strip() and len(out) <= 128            # accepté seulement si inoffensif et borné
        assert not any(c in out for c in "';<>`$\x00")
    with pytest.raises(ValueError):
        InputValidator.ip_address(bad)


@pytest.mark.parametrize("bad", ["a\nb", "a\rb", "a\tb", "ligne1\n[ERROR] faux journal"])
def test_names_cannot_forge_log_lines(bad):
    with pytest.raises(ValueError):
        InputValidator.name(bad)


def test_validators_accept_normal_values():
    assert InputValidator.name("Switch-Étage 1 (A)") == "Switch-Étage 1 (A)"
    assert InputValidator.ip_address("192.168.1.0/24") == "192.168.1.0/24"
    assert InputValidator.ip_address("srv-01.local") == "srv-01.local"
    assert InputValidator.login("jean.dupont") == "jean.dupont" and InputValidator.snmp_community("") == "public"
    assert InputValidator.safe_limit(50) == 50
    for bad in (0, 10_001, -1):
        with pytest.raises(ValueError):
            InputValidator.safe_limit(bad)


def test_sql_parameters_neutralise_injection(db):
    evil = "x'); DROP TABLE hosts;--"
    hid = db.add_host(evil, "10.0.0.5")
    assert db.get_host_by_id(hid)["name"] == evil
    assert db.fetchone("SELECT COUNT(*) n FROM hosts")["n"] >= 1
    assert db.get_host_by_ip("10.0.0.5' OR '1'='1") is None


# ───────────── analyseurs : jamais d'exception sur des octets hostiles ─────────────
def test_netflow_parser_survives_random_and_truncated_data():
    good = build_netflow_v5([{"src": "10.0.0.1", "dst": "10.0.0.2", "proto": 6, "dport": 80, "bytes": 10, "packets": 1}])
    assert parse_netflow_v5(good)
    for n in range(0, len(good)):
        assert isinstance(parse_netflow_v5(good[:n]), list)      # tronqué à chaque longueur
    for _ in range(300):
        blob = bytes(rnd.getrandbits(8) for _ in range(rnd.randint(0, 200)))
        assert isinstance(parse_netflow_v5(blob), list)
    bad = bytearray(good); bad[2:4] = (60000).to_bytes(2, "big")  # nombre d'enregistrements mensonger
    assert isinstance(parse_netflow_v5(bytes(bad)), list)


def test_syslog_and_field_extraction_on_hostile_lines():
    assert parse_syslog(b"<34>sshd[1]: Failed password for root from 1.2.3.4") .startswith("sshd")
    assert parse_syslog(b"\xff\xfe\x00garbage") is not None
    for line in ("", "a" * 100_000, "from " + "9" * 5000, "\x00" * 50, "Invalid user " + "é" * 300):
        assert isinstance(extract_fields(line), dict)
    f = extract_fields("Failed password for invalid user bob from 203.0.113.9 port 22")
    assert f["src_ip"] == "203.0.113.9" and f["user"] == "bob"


@pytest.mark.parametrize("text", ["", "- - -", "title: x", "detection: 5", "!!python/object/apply:os.system ['id']",
                                  "title: t\ndetection:\n  selection: {a: 1}\n  condition: selection and (",
                                  "title: t\ndetection:\n  selection: {a: 1}\n  condition: __import__('os')",
                                  "title: t\ndetection:\n  condition: nope"])
def test_sigma_rejects_malformed_or_dangerous_rules(text):
    with pytest.raises((RuleError, ValueError)):
        parse_rule(text)


# ───────────── agents : authentification ─────────────
@pytest.fixture()
def server(db):
    sink = EventSink(db)
    return AgentServer(db, sink, LogPipeline(db, sink), port=0, bind="127.0.0.1")


def _post(srv, agent, body, ts=None, nonce=None, secret=None, agent_id=None):
    ts = str(int(time.time())) if ts is None else ts
    nonce = nonce or f"n{rnd.getrandbits(40)}"
    sig = sign(secret or agent["secret"], ts, nonce, body)
    return srv.handle_report(agent_id or agent["agent_id"], ts, nonce, sig, body)


def test_agent_auth_rejections_are_uniform(server):
    ag = server.registry.enroll("poste")
    body = json.dumps({"hostname": "x"}).encode()
    assert _post(server, ag, body)[0] == 200
    # inconnu / mauvais secret : même réponse (pas d'énumération)
    assert _post(server, ag, body, agent_id="ag_inconnu") == (401, {"error": "unauthorized"})
    assert _post(server, ag, body, secret="mauvais") == (401, {"error": "unauthorized"})
    assert _post(server, ag, body, agent_id=None, secret="x")[0] == 401
    assert _post(server, ag, body, ts="abc") [0] == 401
    assert _post(server, ag, body, ts=str(int(time.time()) - 3600))[1] == {"error": "stale"}
    assert _post(server, ag, b"{pas json")[0] == 400 and _post(server, ag, b"[1,2]")[0] == 400
    n = "same-nonce"
    assert _post(server, ag, body, nonce=n)[0] == 200
    assert _post(server, ag, body, nonce=n)[1] == {"error": "replay"}
    # signature altérée d'un seul bit
    ts = str(int(time.time())); sig = sign(ag["secret"], ts, "z1", body)
    flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
    assert server.handle_report(ag["agent_id"], ts, "z1", flipped, body)[0] == 401
    server.registry.revoke(ag["agent_id"])
    assert _post(server, ag, body)[0] == 401                     # agent révoqué


def test_agent_payload_fuzz_never_crashes_server(server):
    ag = server.registry.enroll("poste")
    for payload in ({}, {"logs": "pas une liste"}, {"logs": [1, None, {"message": 5}]}, {"fim": [[1]]},
                    {"connections": "x"}, {"connections": [{"laddr": "pas-ip", "raddr": None}]},
                    {"hostname": "é" * 10_000}, {"net": {"x": float("inf")}}):
        code, _ = _post(server, ag, json.dumps(payload, default=str).encode())
        assert code in (200, 400, 500)


# ───────────── notifications ─────────────
@pytest.mark.parametrize("url,ok", [("https://hooks.example.com/x", True), ("http://10.0.0.1:8080/h", True),
                                    ("file:///etc/passwd", False), ("ftp://x/y", False), ("javascript:alert(1)", False),
                                    ("gopher://x", False), ("https://", False), ("", False)])
def test_webhook_url_scheme_whitelist(url, ok):
    assert NotifierManager._valid_url(url) is ok


def test_smtp_settings_validation():
    assert "vide" in validate_smtp_settings("", 25, "a@b.fr")
    assert "adresse e-mail" in validate_smtp_settings("a@b.fr", 25, "a@b.fr")
    assert "Port" in validate_smtp_settings("smtp.x.fr", 70000, "a@b.fr")
    assert "destinataire" in validate_smtp_settings("smtp.x.fr", 25, "").lower()
    assert "invalide" in validate_smtp_settings("smtp.x.fr", 25, "pas-une-adresse")
    assert validate_smtp_settings("smtp.x.fr", 587, "a@b.fr, c@d.fr") is None


def test_dedupe_key_is_stable_and_discriminating():
    e = {"event_type": "port_open", "host_id": 3, "host_name": "h", "port": 22, "severity": "high", "description": "d"}
    k1, k2 = NotificationDeduper.make_key(e), NotificationDeduper.make_key(dict(e))
    assert k1 == k2 and k1[1] == 3 and len(k1[0]) == 40
    assert NotificationDeduper.make_key(dict(e, port=23))[0] != k1[0]


# ───────────── EventSink ─────────────
def test_event_sink_defaults_and_resilience(db):
    seen = []
    sink = EventSink(db, on_alert=lambda ev: seen.append(ev))
    eid = sink.emit("nimportequoi", "t_test", "desc")            # sévérité inconnue → warning
    assert eid and db.fetchone("SELECT severity FROM events WHERE id=?", (eid,))["severity"] == "warning"
    assert seen and seen[0]["event_type"] == "t_test"
    boom = EventSink(db, on_alert=lambda ev: 1 / 0)               # une alerte en erreur ne casse pas la détection
    assert boom.emit("high", "t_test2", "d") > 0
    class BadDb:
        def __getattr__(self, n):
            raise RuntimeError("base fermée")
    assert EventSink(BadDb()).emit("high", "x", "d", host={"id": 1, "name": "h"}) == 0
    assert is_valid_ip("10.0.0.1") and not is_valid_ip("10.0.0.256") and not is_valid_ip("")
    assert json.loads(safe_json({"a": {1, 2} and "x", "b": object})) ["a"] == "x"


# ───────────── travailleur réseau ─────────────
@pytest.fixture()
def worker(qapp, db, monkeypatch):
    w = NetworkSetupWorker(db)
    log, fin, nd, newdev = [], [], [], []
    w.log_message.connect(lambda lvl, m: log.append((lvl, m)))
    w.finished.connect(fin.append)
    w.network_discovered.connect(lambda *a: nd.append(a))
    w.new_device.connect(newdev.append)
    monkeypatch.setattr(lnet, "ensure_local_hosts", lambda db: {"ip": "192.168.7.5", "gateway_ip": "192.168.7.1", "local": None})
    monkeypatch.setattr(lnet, "get_primary_network", lambda: "192.168.7.0/24")
    monkeypatch.setattr(lnet, "discover_hosts", lambda net: [{"ip": "192.168.7.20", "name": "nas"}])
    return w, log, fin, nd, newdev


def test_worker_run_and_discover(worker, db):
    w, log, fin, nd, newdev = worker
    w.run()
    assert fin == [1] and db.get_host_by_ip("192.168.7.20")
    db.set_setting("auto_discover", "0")
    w.run(); assert fin[-1] == 0
    w.discover(); assert fin[-1] == 0                             # déjà connu → 0 nouveau
    assert any("Machine locale" in m for _, m in log)


def test_worker_errors_are_reported_not_raised(worker, monkeypatch):
    w, log, fin, nd, newdev = worker
    monkeypatch.setattr(lnet, "ensure_local_hosts", lambda db: (_ for _ in ()).throw(RuntimeError("carte absente")))
    w.run(); w.discover()
    assert fin == [0, 0] and sum(1 for lvl, _ in log if lvl == "ERROR") == 2


def test_worker_network_discovery_alerts_only_after_baseline(worker, db, monkeypatch):
    w, log, fin, nd, newdev = worker
    nid = db.execute("INSERT INTO networks (name, cidr, gateway_ip, kind) VALUES ('Wifi','10.8.0.0/24','10.8.0.1','wifi')").lastrowid
    state = {"found": [{"ip": "10.8.0.10", "name": "a", "device_type": "unknown", "mac": "aa:bb:cc:00:00:01"}]}
    monkeypatch.setattr(lnet, "discover_network", lambda cidr, gw: state["found"])
    w.discover_network(nid)                                       # 1re découverte = référence : pas d'alerte
    assert nd[-1][1] == 1 and newdev == []
    db.execute("UPDATE networks SET last_discovery = datetime('now') WHERE id = ?", (nid,))
    state["found"] = state["found"] + [{"ip": "10.8.0.11", "name": "b", "device_type": "unknown", "mac": "aa:bb:cc:00:00:02"}]
    w.discover_network(nid)
    assert len(newdev) == 1 and newdev[0]["event_type"] == "new_device" and "10.8.0.11" in newdev[0]["description"]
    assert db.fetchone("SELECT 1 FROM events WHERE event_type='new_device'")
    w.discover_network(9999)                                      # réseau inconnu : sans effet
    monkeypatch.setattr(lnet, "discover_network", lambda *a: (_ for _ in ()).throw(RuntimeError("x")))
    w.discover_network(nid); assert nd[-1] == (nid, 0, 0)
    w.rediscover_all()


# ───────────── boucle du gestionnaire de défense ─────────────
class _Stop:
    """Événement d'arrêt factice : N tours puis arrêt."""
    def __init__(self, turns): self.turns = turns
    def wait(self, _t): self.turns -= 1; return self.turns < 0
    def is_set(self): return False
    def set(self): self.turns = -1


def test_scheduler_loop_runs_due_jobs_and_survives_failures(qapp, db, security, monkeypatch):
    assert security.authenticate("admin", "admin")
    m = DefenseManager(db, security)
    ran, spawned = [], []
    monkeypatch.setattr(m, "_due", lambda name, every: True)
    monkeypatch.setattr(m, "enabled", lambda s: True)
    monkeypatch.setattr(m, "_spawn_netmap", lambda: spawned.append(1))
    db.set_setting("config_backup_interval_h", "1")

    def fake(name):
        ran.append(name)
        if name == "arp":
            raise RuntimeError("panne simulée")
    monkeypatch.setattr(m, "run_job", fake)
    m._stop = _Stop(1)
    m._loop()
    assert {"arp", "dhcp", "fim", "backup", "assess", "flows_local", "silent", "bandwidth", "purge"} <= set(ran)
    assert spawned == [1] and "netmap" not in ran                  # le relevé SNMP part dans son propre thread
    m._stop = threading.Event()
    m.stop()


def test_scheduler_respects_disabled_services(qapp, db, security, monkeypatch):
    m = DefenseManager(db, security)
    ran = []
    db.set_setting("config_backup_interval_h", "0")               # sauvegarde périodique désactivée
    db.set_setting("db_backup_interval_h", "0")
    monkeypatch.setattr(m, "_due", lambda n, e: True)
    monkeypatch.setattr(m, "enabled", lambda s: False)
    monkeypatch.setattr(m, "run_job", lambda n: ran.append(n))
    m._stop = _Stop(1); m._loop()
    assert set(ran) == {"bandwidth", "mail", "devinfo", "enrich", "purge"}                      # seules les tâches non optionnelles tournent
    m._stop = threading.Event(); m.stop()


def test_database_files_are_owner_only(db):
    import os, stat
    if os.name != "posix":
        pytest.skip("permissions POSIX")
    for suffix in ("", "-wal", "-shm"):
        path = db.db_path + suffix
        if os.path.exists(path):
            assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path


# ───────────── limites connues du journal d'audit (documentées par des tests « xfail ») ─────────────
def _tamper_setup(security, db, n=4):
    assert security.authenticate("admin", "admin")
    for i in range(n):
        db.write_audit("admin", f"ACTION_{i}", "cible", "détail")
    assert security.verify_audit()["ok"]


def test_audit_chain_detects_deleted_middle_line(security, db):
    _tamper_setup(security, db)
    db.execute("DELETE FROM audit_logs WHERE action = 'ACTION_1'")
    r = security.verify_audit()
    assert not r["ok"] and any("chaîne rompue" in p for p in r["problems"]) and security.verify_db_integrity() is False


def test_audit_chain_detects_deleted_last_lines_and_forged_rewrite(security, db):
    _tamper_setup(security, db)
    db.execute("DELETE FROM audit_logs WHERE id = (SELECT MAX(id) FROM audit_logs)")
    r = security.verify_audit()
    assert not r["ok"] and any("fin du journal" in p for p in r["problems"])


def test_audit_chain_detects_altered_and_inserted_lines(security, db):
    _tamper_setup(security, db)
    db.execute("UPDATE audit_logs SET detail='falsifié' WHERE action='ACTION_2'")
    assert any("altérée" in p for p in security.verify_audit()["problems"])
    db.execute("UPDATE audit_logs SET detail='détail' WHERE action='ACTION_2'")
    assert security.verify_audit()["ok"]
    db.execute("INSERT INTO audit_logs (username, action, target, detail, hmac, logged_at, prev_hmac, chain_v) "
               "VALUES ('x','FAUX','','', 'abc', datetime('now'), 'zzz', 2)")
    assert not security.verify_audit()["ok"]


def test_audit_anchor_cannot_be_reset_without_the_key(security, db):
    import json, os
    _tamper_setup(security, db)
    anchor = json.loads(db.get_setting("audit_anchor"))
    anchor["n"] = 1                                               # falsification de l'ancre
    db.set_setting("audit_anchor", json.dumps(anchor))
    assert any("falsifiée" in p for p in security.verify_audit()["problems"])
    db.set_setting("audit_anchor", "")                            # ancre supprimée
    assert any("absente" in p for p in security.verify_audit()["problems"])


def test_audit_anchor_copy_outside_database(security, db):
    import json, os
    _tamper_setup(security, db)
    path = os.path.join(os.path.dirname(db.db_path), ".audit_anchor")
    assert os.path.exists(path)
    stale = json.loads(open(path).read()); stale["n"] += 5
    open(path, "w").write(json.dumps(stale))
    assert any("hors de la base" in p for p in security.verify_audit()["problems"])


def test_legacy_audit_rows_still_verify_then_chain_continues(security, db):
    import hashlib, hmac as _h
    assert security.authenticate("admin", "admin")
    key = db._get_hmac_key()
    ts = "2026-01-01T00:00:00"
    sig = _h.new(key, f"old|ACTION|t|d|{ts}".encode(), hashlib.sha256).hexdigest()
    db.execute("INSERT INTO audit_logs (username, action, target, detail, ip_source, hmac, logged_at) VALUES ('old','ACTION','t','d','',?,?)", (sig, ts))
    db.execute("DELETE FROM audit_logs WHERE chain_v = 2")        # base « d'avant le chaînage »
    db.set_setting("audit_anchor", "")
    assert security.verify_audit()["ok"]                          # ancre posée automatiquement
    db.write_audit("admin", "NOUVEAU", "", "")
    assert security.verify_audit()["ok"] and db.fetchone("SELECT chain_v FROM audit_logs ORDER BY id DESC LIMIT 1")["chain_v"] == 2


def test_audit_concurrent_writers_keep_one_chain(security, db):
    import threading
    assert security.authenticate("admin", "admin")
    def w(i):
        for k in range(15):
            db.write_audit("t", f"A{i}", str(k), "")
    ts = [threading.Thread(target=w, args=(i,)) for i in range(4)]
    [t.start() for t in ts]; [t.join() for t in ts]
    r = security.verify_audit()
    assert r["ok"], r["problems"][:3]


def test_login_lockout_survives_restart(db):
    from core.security import SecurityManager
    s1 = SecurityManager(db)
    for _ in range(s1.MAX_FAILED_ATTEMPTS):
        s1.authenticate("admin", "bad")
    assert s1.lockout_remaining("admin") > 0
    s2 = SecurityManager(db)                                     # « redémarrage »
    assert s2.lockout_remaining("admin") > 0
    assert s2.authenticate("admin", "admin") is None             # même bon mot de passe : refusé tant que verrouillé
    db.execute("UPDATE login_failures SET locked_until = 1")
    assert s2.authenticate("admin", "admin") and s2.lockout_remaining("admin") == 0
    assert db.fetchone("SELECT COUNT(*) n FROM login_failures")["n"] == 0     # réussite : compteur effacé


def test_failed_attempts_count_across_restarts_and_table_is_bounded(db):
    from core.security import SecurityManager
    for i in range(SecurityManager.MAX_FAILED_ATTEMPTS - 1):
        SecurityManager(db).authenticate("admin", "bad")         # une nouvelle instance à chaque essai
    assert SecurityManager(db).lockout_remaining("admin") == 0
    SecurityManager(db).authenticate("admin", "bad")
    assert SecurityManager(db).lockout_remaining("admin") > 0
    s = SecurityManager(db)
    for i in range(1100):
        s._register_failure(f"fantome{i}")
    assert db.fetchone("SELECT COUNT(*) n FROM login_failures")["n"] <= 1000


# ───────────── v16 : charge système des agents, débit reçu ─────────────
def test_agent_usage_becomes_metrics_and_rates(server, db):
    hid = db.add_host("pc-agent", "192.168.9.9")
    ag = server.registry.enroll("pc", host_id=hid)
    def report(**s):
        return _post(server, ag, json.dumps({"system": dict({"hostname": "pc", "os": "linux"}, **s)}).encode())[0]
    assert report(cpu_pct=42.5, mem_pct=61.0, disk_pct=70.0, net_rx_bytes=1000, net_tx_bytes=500) == 200
    m = {r["metric_name"]: r["value"] for r in db.fetchall("SELECT metric_name, value FROM metrics WHERE host_id=?", (hid,))}
    assert m["cpu_util"] == 42.5 and m["mem_used"] == 61.0 and m["disk_used"] == 70.0 and "bw_in" not in m   # 1er relevé : pas de débit
    t0, rx0, tx0 = server._net_prev[ag["agent_id"]]
    server._net_prev[ag["agent_id"]] = (t0 - 10, rx0, tx0)                    # 10 s plus tôt
    assert report(cpu_pct=999, mem_pct="x", net_rx_bytes=1000 + 12_500_000, net_tx_bytes=500 + 1_250_000) == 200
    bw = {r["metric_name"]: r["value"] for r in db.fetchall("SELECT metric_name, value FROM metrics WHERE host_id=? AND interface='total'", (hid,))}
    assert abs(bw["bw_in"] - 10.0) < 0.5 and abs(bw["bw_out"] - 1.0) < 0.1    # Mbps
    assert db.fetchone("SELECT COUNT(*) n FROM metrics WHERE host_id=? AND metric_name='cpu_util'", (hid,))["n"] == 1   # 999 refusé
    from core.bandwidth import BandwidthManager
    BandwidthManager(db).sample()
    cur = next(d for d in BandwidthManager(db).current() if d["ip"] == "192.168.9.9")
    assert cur["source"] == "agent" and cur["exact"] and abs(cur["rx_bps"] - 10e6) < 5e5


def test_fmt_rate_shows_bits_and_bytes():
    from core.bandwidth import fmt_rate
    assert fmt_rate(500e6) == "500.0 Mb/s (62.5 Mo/s)" and fmt_rate(800) == "800 b/s"


def test_dashboard_rx_card_and_hosts_cells(qapp, db, monkeypatch):
    from ui.widgets.dashboard_view import DashboardView
    from ui.widgets.hosts_view import HostsView
    db.add_host("nas", "192.168.9.20")
    db.execute("INSERT INTO bw_samples (ip, ts, rx_bps, tx_bps, source) VALUES ('192.168.9.20', ?, 5e8, 1e6, 'agent')", (int(time.time()),))
    d = DashboardView(db=db)
    try:
        d._refresh_rx()
        row = next(r for r in d._rx_bars.rows if r["ip"] == "192.168.9.20")
        assert row["rx_bps"] == 5e8 and row["tx_bps"] == 0.0 and d._rx_bars.rx_only
        d._rx_bars.grab()
    finally:
        d._timer.stop(); d._live_timer.stop()
    cell = HostsView._usage_cell(None, {})
    assert "agent" in cell.toolTip().lower()
    assert HostsView._usage_cell(55.4, {}).toolTip() == ""


def test_database_backup_job_rotates_and_is_valid(qapp, db, security, tmp_path):
    m = DefenseManager(db, security)
    db.set_setting("db_backup_dir", str(tmp_path / "bk")); db.set_setting("db_backup_keep", "2")
    import time
    for _ in range(3):
        path = m.backup_database(); time.sleep(1.1)
    files = sorted((tmp_path / "bk").glob("procus_*.db"))
    assert len(files) == 2 and str(files[-1]) == path
    assert db.validate_backup(path, db._key_hex)[0]


def _legacy_rows(db, key, n):
    import hashlib, hmac as _h
    db.execute("DELETE FROM audit_logs")
    for i in range(n):
        ts = f"2026-01-0{i+1}T00:00:00"
        msg = f"admin|A{i}|t|d|{ts}".encode()
        db.execute("INSERT INTO audit_logs (username, action, target, detail, hmac, logged_at, chain_v) VALUES (?,?,?,?,?,?,NULL)",
                   ("admin", f"A{i}", "t", "d", _h.new(key, msg, hashlib.sha256).hexdigest(), ts))
    db.set_setting("audit_anchor", ""); db.set_setting("audit_legacy_resealed", "")


def test_legacy_rows_signed_with_other_key_are_resealed_and_traced(security, db):
    _legacy_rows(db, b"\x07" * 32, 9)                                   # ancienne clé inconnue (ex. trousseau d'une ancienne version)
    assert security.verify_audit()["ok"]
    assert db.fetchone("SELECT COUNT(*) c FROM audit_logs WHERE action='AUDIT_RESEAL'")["c"] == 1


def test_single_tampered_legacy_row_is_still_detected(security, db):
    _legacy_rows(db, db._get_hmac_key(), 5)
    db.execute("UPDATE audit_logs SET detail='x' WHERE id=(SELECT MIN(id) FROM audit_logs)")
    assert not security.verify_audit()["ok"]                             # une seule ligne fausse : pas de re-signature


def test_first_rows_with_lost_key_then_valid_rows_are_resealed_once_and_traced(security, db):
    """Cas réel : 9 premières lignes d'une ancienne clé perdue, les suivantes valides avec la clé actuelle."""
    import hashlib, hmac as _h
    key = db._get_hmac_key()
    _legacy_rows(db, b"\x09" * 32, 9)
    for i in range(9, 14):
        ts = f"2026-02-0{i-8}T00:00:00"
        db.execute("INSERT INTO audit_logs (username, action, target, detail, hmac, logged_at, chain_v) VALUES (?,?,?,?,?,?,NULL)",
                   ("admin", f"B{i}", "t", "d", _h.new(key, f"admin|B{i}|t|d|{ts}".encode(), hashlib.sha256).hexdigest(), ts))
    assert security.verify_audit()["ok"]
    row = db.fetchone("SELECT detail FROM audit_logs WHERE action='AUDIT_RESEAL'")
    assert row and "anciennes signatures" in row["detail"]
    assert security.verify_audit()["ok"]


def test_tampered_row_in_the_middle_is_not_masked_by_prefix_reseal(security, db):
    import hashlib, hmac as _h
    key = db._get_hmac_key()
    _legacy_rows(db, b"\x09" * 32, 4)
    for i in range(4, 10):
        ts = f"2026-02-0{i-3}T00:00:00"
        sig = _h.new(key, f"admin|B{i}|t|d|{ts}".encode(), hashlib.sha256).hexdigest()
        db.execute("INSERT INTO audit_logs (username, action, target, detail, hmac, logged_at, chain_v) VALUES (?,?,?,?,?,?,NULL)",
                   ("admin", f"B{i}", "t", "d" if i != 6 else "falsifié", sig, ts))
    assert not security.verify_audit()["ok"]
