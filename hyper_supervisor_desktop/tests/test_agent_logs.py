import importlib.util, json, os, socket, ssl, sys, time, threading
import pytest
from core.defense_common import EventSink
from core.fim import FimEngine, snapshot, hash_file, is_sensitive, check_local
from core.sigma_engine import (SigmaEngine, parse_rule, RuleError, BUILTIN_RULES, seed_builtin_rules)
from core.log_pipeline import LogPipeline, SyslogReceiver, extract_fields, parse_syslog
from core.agent_server import (AgentServer, AgentRegistry, sign, generate_self_signed, cert_fingerprint)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("procus_agent", os.path.join(ROOT, "agent", "procus_agent.py"))
agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)


@pytest.fixture()
def sink(db):
    return EventSink(db)


def ev(db, t):
    return db.fetchall("SELECT * FROM events WHERE event_type=? ORDER BY id", (t,))


# ───────────── FIM ─────────────
def test_fim_baseline_then_modified_created_deleted(db, sink, tmp_path):
    a = tmp_path / "a.conf"; a.write_text("v1"); b = tmp_path / "shadow"; b.write_text("root:x")
    fim = FimEngine(db, sink)
    r = fim.compare("ag1", snapshot([str(a), str(b)]))
    assert r["baseline_created"] and not ev(db, "fim_change")                     # 1re observation = référence
    assert fim.compare("ag1", snapshot([str(a), str(b)]))["changes"] == []        # stable
    a.write_text("v2"); b.write_text("root:HACK")
    r = fim.compare("ag1", snapshot([str(a), str(b)]))
    sev = {c["path"]: c["severity"] for c in r["changes"]}
    assert sev[str(a)] == "average" and sev[str(b)] == "high"                     # « shadow » est sensible
    assert fim.compare("ag1", snapshot([str(a), str(b)]))["changes"] == []        # alerté UNE fois
    b.unlink(); n = tmp_path / "new.sh"; n.write_text("#!/bin/sh")
    kinds = {c["change"] for c in fim.compare("ag1", snapshot([str(a), str(b), str(n)]))["changes"]}
    assert kinds == {"deleted", "created"}
    assert hash_file(str(tmp_path / "nope")) == {"missing": True} and is_sensitive("/etc/ssh/sshd_config")


def test_fim_unreadable_file_is_not_a_change(db, sink, tmp_path):
    f = tmp_path / "x"; f.write_text("1"); fim = FimEngine(db, sink)
    fim.compare("a", snapshot([str(f)]))
    assert fim.compare("a", {str(f): {"error": "PermissionError"}})["changes"] == []


def test_fim_local_self_protection_and_upgrade_rebaseline(db, sink, tmp_path, monkeypatch):
    from core import fim as fimmod
    f = tmp_path / "code.py"; f.write_text("print(1)")
    monkeypatch.setattr(fimmod, "app_code_paths", lambda: [str(f)])
    assert check_local(db, sink)["baseline_created"]
    assert check_local(db, sink)["changes"] == []
    f.write_text("print('backdoor')")
    assert check_local(db, sink)["changes"][0]["change"] == "modified"
    assert ev(db, "fim_change")[0]["host_id"] is not None
    db.set_setting("fim_local_version", "13.0"); f.write_text("print('mise à jour')")      # mise à jour de Procus : pas d'alerte
    assert check_local(db, sink)["baseline_created"] and len(ev(db, "fim_change")) == 1


# ───────────── Sigma ─────────────
def test_all_builtin_rules_load_and_seed_is_idempotent(db):
    seed_builtin_rules(db); seed_builtin_rules(db)
    assert db.fetchone("SELECT COUNT(*) c FROM sigma_rules")["c"] == len(BUILTIN_RULES)
    db.execute("UPDATE sigma_rules SET enabled = 0 WHERE rule_id = 'procus_sudo_failure'")
    seed_builtin_rules(db)                                                           # ne réactive pas une règle désactivée
    assert db.fetchone("SELECT enabled FROM sigma_rules WHERE rule_id='procus_sudo_failure'")["enabled"] == 0
    assert len(SigmaEngine.from_db(db).rules) == len(BUILTIN_RULES) - 1


def test_sigma_modifiers_and_conditions():
    r = parse_rule("""
title: t
level: high
detection:
  a:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains|all: [whoami, '/priv']
  b:
    User: SYSTEM
  c:
    - Image|startswith: C:\\Temp
    - Image|re: 'evil\\d+'
  condition: a and not b or c
""")
    m = lambda **f: r.matches({k.lower(): v for k, v in f.items()}, "")
    assert m(Image="C:\\Windows\\CMD.EXE", CommandLine="WHOAMI /priv")                 # casse ignorée
    assert not m(Image="C:\\Windows\\cmd.exe", CommandLine="whoami /priv", User="system")
    assert not m(Image="C:\\Windows\\cmd.exe", CommandLine="whoami")                  # |all : les deux mots requis
    assert m(Image="C:\\Temp\\x.exe") and m(Image="d:\\evil42.exe") and not m(Image="d:\\fine.exe")
    k = parse_rule("title: k\ndetection:\n  kw: [mimikatz, 'sekurlsa']\n  condition: kw")
    assert k.matches({}, "run SEKURLSA::logonpasswords") and not k.matches({}, "hello")
    o = parse_rule("title: o\ndetection:\n  s1: {a: 1}\n  s2: {b: 2}\n  condition: 1 of s*")
    assert o.matches({"b": "2"}, "") and not o.matches({"b": "3"}, "")
    al = parse_rule("title: o\ndetection:\n  s1: {a: 1}\n  s2: {b: 2}\n  condition: all of them")
    assert al.matches({"a": 1, "b": 2}, "") and not al.matches({"a": 1}, "")


def test_unsupported_or_broken_rules_rejected_loudly():
    bad = {
        "title: x\ndetection:\n  s: {a: 1}\n  condition: s | count() > 3": "agrégation",
        "title: x\ndetection:\n  s: {a|base64: 1}\n  condition: s": "modificateur",
        "title: x\ndetection:\n  s: {a: 1}\n  condition: inconnue": "inconnue",
        "title: x\ndetection:\n  s: {a: 1}\n  condition: (s": "parenth",
        "detection:\n  s: {a: 1}\n  condition: s": "title",
        "title: x\nlevel: urgent\ndetection:\n  s: {a: 1}\n  condition: s": "level",
        "title: x\ndetection:\n  s: {a: 1}\n  condition: s\nthreshold: {count: 0, timeframe: 5}": "threshold",
        "title: x\ndetection: [": "YAML",
    }
    for text, hint in bad.items():
        with pytest.raises(RuleError) as e:
            r = parse_rule(text); r.matches({"a": 1, "s": 1}, "")                       # modificateur inconnu levé à l'évaluation
        assert hint.lower() in str(e.value).lower(), (hint, str(e.value))


def test_threshold_counts_per_group_within_window_then_cools_down():
    eng = SigmaEngine([parse_rule(BUILTIN_RULES[0])])
    def fail(ip, t): return eng.evaluate("Failed password for root from %s port 22" % ip, {"src_ip": ip}, now=t)
    assert all(not fail("10.0.0.5", 100 + i) for i in range(4))                        # 4 échecs : rien
    assert fail("10.0.0.6", 104) == []                                                  # autre IP : compteur séparé
    hit = fail("10.0.0.5", 105)
    assert len(hit) == 1 and hit[0]["count"] == 5
    assert fail("10.0.0.5", 106) == []                                                  # pas de rafale d'alertes
    assert not [fail("10.0.0.7", 1000 + i * 100) for i in range(5)][-1]                # trop espacés : hors fenêtre


# ───────────── journaux ─────────────
def test_extract_fields_and_syslog_parsing():
    f = extract_fields("sshd[812]: Failed password for invalid user bob from 203.0.113.9 port 4242 ssh2")
    assert f["src_ip"] == "203.0.113.9" and f["user"] == "bob" and f["program"] == "sshd"
    assert parse_syslog(b"<38>Oct 16 10:00:00 srv sshd[1]: Accepted\x00\n") == "Oct 16 10:00:00 srv sshd[1]: Accepted"
    assert extract_fields("rien d'utile") == {}


def test_bruteforce_through_pipeline_creates_event_with_mitre_tags(db, sink):
    hid = db.add_host("srv", "10.0.0.50")
    lp = LogPipeline(db, sink)
    for i in range(5):
        lp.ingest(f"sshd[1]: Failed password for root from 203.0.113.9 port {4000+i} ssh2", src_addr="10.0.0.50")
    e = ev(db, "sigma_match")
    assert len(e) == 1 and e[0]["host_id"] == hid and e[0]["severity"] == "high"
    assert "203.0.113.9" in e[0]["description"] and "5 occurrences" in e[0]["description"]
    assert "attack.t1110.001" in e[0]["tags"] and "sigma:procus_ssh_bruteforce" in e[0]["tags"]
    assert db.fetchone("SELECT COUNT(*) c FROM log_events")["c"] == 5
    lp.ingest("sshd[1]: Accepted password for root from 10.0.0.9 port 22 ssh2", src_addr="10.0.0.50")
    assert len(ev(db, "sigma_match")) == 2                                              # connexion root réussie


def test_log_retention_purge_and_rule_reload(db, sink):
    lp = LogPipeline(db, sink)
    lp.ingest("hello", src_addr="1.1.1.1")
    db.execute("UPDATE log_events SET received_at = datetime('now','-30 days')")
    lp.purge(14); assert db.fetchone("SELECT COUNT(*) c FROM log_events")["c"] == 0
    db.execute("UPDATE sigma_rules SET enabled=0"); lp.reload_rules(); assert lp.engine.rules == []


def test_syslog_receiver_end_to_end_cisco(db, sink):
    db.add_host("sw1", "127.0.0.1")
    lp = LogPipeline(db, sink)
    rx = SyslogReceiver(lp, port=0, bind="127.0.0.1"); assert rx.start()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<189>1234: *Mar 1 00:01:02: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.9)", ("127.0.0.1", rx.port))
        end = time.time() + 3
        while time.time() < end and not ev(db, "sigma_match"):
            time.sleep(0.05)
    finally:
        rx.stop()
    e = ev(db, "sigma_match")[0]
    assert e["severity"] == "warning" and "Cisco" in e["description"] and rx.received == 1


def test_syslog_port_busy_reported_not_crashing(db, sink):
    busy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); busy.bind(("127.0.0.1", 0))
    rx = SyslogReceiver(LogPipeline(db, sink), port=busy.getsockname()[1], bind="127.0.0.1")
    assert rx.start() is False and "indisponible" in rx.error
    busy.close()


# ───────────── agents ─────────────
def _server(db, sink, tls=False, tmp=None):
    lp = LogPipeline(db, sink)
    cert = key = fp = None
    if tls:
        cert, key = str(tmp / "c.pem"), str(tmp / "k.pem"); fp = generate_self_signed(cert, key)
    srv = AgentServer(db, sink, lp, port=0, bind="127.0.0.1", certfile=cert, keyfile=key)
    assert srv.start(), srv.error
    return srv, fp


def _cfg(srv, enrolled, fp=None):
    return {"server": f"{'https' if srv.tls else 'http'}://127.0.0.1:{srv.port}", "agent_id": enrolled["agent_id"],
            "secret": enrolled["secret"], "server_fingerprint": fp}


def test_enroll_secret_encrypted_and_listed_without_secret(db):
    hid = db.add_host("srv", "10.0.0.5")
    e = AgentRegistry(db).enroll("Serveur web", host_id=hid, os_name="linux")
    assert db.fetchone("SELECT secret_enc FROM agents")["secret_enc"] != e["secret"] and e["secret"] not in str(AgentRegistry(db).list())
    assert db.get_host_by_id(hid)["agent_enabled"] == 1
    assert "/etc/shadow" in AgentRegistry(db).get(e["agent_id"])["watch_paths"]
    with pytest.raises(ValueError): AgentRegistry(db).enroll("  ")


def test_agent_report_roundtrip_http_inventory_fim_logs(db, sink, tmp_path):
    hid = db.add_host("srv", "127.0.0.1")
    e = AgentRegistry(db).enroll("srv", host_id=hid, watch_paths=[]); srv, _ = _server(db, sink)
    watched = tmp_path / "sshd_config"; watched.write_text("PermitRootLogin no")
    try:
        cfg = _cfg(srv, e)
        p = {"agent_version": "1.0", "system": {"os": "linux", "hostname": "srv"}, "processes": [{"name": "nginx"}],
             "ports": [{"port": 80, "proto": "tcp"}], "fim": agent.fim_snapshot([str(watched)]),
             "logs": [{"message": f"sshd[1]: Failed password for root from 198.51.100.7 port {i} ssh2"} for i in range(5)]}
        r = agent.post_report(cfg, p)
        assert r["ok"] and r["interval"] == 60
        watched.write_text("PermitRootLogin yes")
        p["fim"] = agent.fim_snapshot([str(watched)]); p["logs"] = []
        agent.post_report(cfg, p)
    finally:
        srv.stop()
    assert json.loads(db.fetchone("SELECT data FROM agent_data WHERE kind='processes'")["data"])[0]["name"] == "nginx"
    assert db.get_host_by_id(hid)["status"] == "online" and db.get_host_by_id(hid)["reach_method"] == "agent"
    assert ev(db, "fim_change")[0]["severity"] == "high" and "sshd_config" in ev(db, "fim_change")[0]["description"]
    assert ev(db, "sigma_match")[0]["host_id"] == hid
    assert db.fetchone("SELECT last_seen FROM agents")["last_seen"]


def test_agent_https_with_pinned_fingerprint_and_wrong_pin_refused(db, sink, tmp_path):
    e = AgentRegistry(db).enroll("a"); srv, fp = _server(db, sink, tls=True, tmp=tmp_path)
    try:
        assert agent.post_report(_cfg(srv, e, fp), {"system": {}})["ok"]
        assert agent.post_report(_cfg(srv, e, fp.upper()), {"system": {}})["ok"]
        with pytest.raises(ssl.SSLError): agent.post_report(_cfg(srv, e, "00" * 32), {"system": {}})   # faux serveur
        with pytest.raises(ssl.SSLError): agent.post_report(_cfg(srv, e, None), {"system": {}})        # pas d'empreinte = refus
    finally:
        srv.stop()
    assert cert_fingerprint(str(tmp_path / "c.pem")) == fp


def _raw_post(srv, headers, body):
    import http.client
    c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
    try:
        c.request("POST", "/api/v1/report", body=body, headers={"Content-Length": str(len(body)), **headers})
        r = c.getresponse(); return (r.status, r.read())
    except (BrokenPipeError, ConnectionError):       # Linux : reset/broken pipe ; Windows : ConnectionAbortedError (10053)
        return (0, b"")                    # le serveur a refusé sans lire le corps : connexion coupée
    finally:
        c.close()


def test_server_rejects_forgery_replay_stale_and_garbage(db, sink):
    e = AgentRegistry(db).enroll("a"); srv, _ = _server(db, sink)
    try:
        body = json.dumps({"system": {}}).encode(); ts = str(int(time.time())); good = sign(e["secret"], ts, "n1", body)
        H = lambda **k: {"X-Procus-Agent": e["agent_id"], "X-Procus-Timestamp": ts, "X-Procus-Nonce": "n1",
                         "X-Procus-Signature": good, **k}
        assert _raw_post(srv, H(), body)[0] == 200
        assert _raw_post(srv, H(), body)[0] == 401                                              # rejeu du même nonce
        assert _raw_post(srv, H(**{"X-Procus-Nonce": "n2"}), body)[0] == 401                    # signature ≠ nonce
        assert _raw_post(srv, H(**{"X-Procus-Nonce": "n3", "X-Procus-Signature": sign("autre", ts, "n3", body)}), body)[0] == 401
        assert _raw_post(srv, H(**{"X-Procus-Agent": "ag_inconnu"}), body)[0] == 401
        old = str(int(time.time()) - 3600)
        assert _raw_post(srv, H(**{"X-Procus-Timestamp": old, "X-Procus-Nonce": "n4", "X-Procus-Signature": sign(e["secret"], old, "n4", body)}), body)[0] == 401
        junk = b"pas du json"
        assert _raw_post(srv, H(**{"X-Procus-Nonce": "n5", "X-Procus-Signature": sign(e["secret"], ts, "n5", junk)}), junk)[0] == 400
        big = b"x" * (2 * 1024 * 1024 + 1)
        assert _raw_post(srv, H(), big)[0] in (413, 0)                                           # refusé avant lecture
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5); c.request("GET", "/api/v1/report"); assert c.getresponse().status == 405; c.close()
        db.execute("UPDATE agents SET enabled = 0")
        assert _raw_post(srv, H(**{"X-Procus-Nonce": "n6", "X-Procus-Signature": sign(e["secret"], ts, "n6", body)}), body)[0] == 401
    finally:
        srv.stop()


def test_agent_main_once_with_config_file(db, sink, tmp_path):
    e = AgentRegistry(db).enroll("a", watch_paths=[]); srv, fp = _server(db, sink, tls=True, tmp=tmp_path)
    try:
        cfgp = tmp_path / "agent_config.json"; cfgp.write_text(json.dumps(_cfg(srv, e, fp)))
        assert agent.main(["--config", str(cfgp), "--once"]) == 0
    finally:
        srv.stop()
    assert db.fetchone("SELECT 1 FROM agent_data WHERE kind='system'") and (tmp_path / "agent_config.state.json").exists()


def test_agent_silent_alert_once_and_clear(db, sink):
    hid = db.add_host("srv", "10.0.0.5"); e = AgentRegistry(db).enroll("srv", host_id=hid)
    srv = AgentServer(db, sink, LogPipeline(db, sink))
    db.execute("UPDATE agents SET last_seen = datetime('now','-1 hour')")
    assert srv.check_silent() == [e["agent_id"]] and srv.check_silent() == []              # une seule alerte
    db.execute("UPDATE agents SET last_seen = datetime('now')"); srv.check_silent()
    db.execute("UPDATE agents SET last_seen = datetime('now','-1 hour')")
    assert srv.check_silent() == [e["agent_id"]]                                            # ré-armée après retour


def test_agent_collectors_run_and_never_include_command_lines():
    assert agent.collect_system()["hostname"]
    procs = agent.collect_processes()
    assert procs and all("cmdline" not in p and "args" not in p for p in procs)
    assert isinstance(agent.collect_ports(), list) and isinstance(agent.collect_software(), list)


def test_agent_tail_starts_at_end_then_reads_new_lines_and_handles_rotation(tmp_path):
    f = tmp_path / "auth.log"; f.write_text("ancien 1\nancien 2\n"); st = {}
    assert agent.tail_new_lines(str(f), st) == []                                            # pas d'historique au 1er passage
    with open(f, "a") as fh: fh.write("nouveau 1\nnouveau 2\n")
    assert agent.tail_new_lines(str(f), st) == ["nouveau 1", "nouveau 2"]
    assert agent.tail_new_lines(str(f), st) == []
    f.write_text("après rotation\n")                                                        # fichier tronqué
    assert agent.tail_new_lines(str(f), st) == ["après rotation"]


WIN_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID>
<EventRecordID>77</EventRecordID><Computer>PC1</Computer></System><EventData><Data Name='TargetUserName'>bob</Data>
<Data Name='IpAddress'>203.0.113.50</Data></EventData></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4625</EventID>
<EventRecordID>78</EventRecordID><Computer>PC1</Computer></System><EventData><Data Name='TargetUserName'>bob</Data>
<Data Name='IpAddress'>-</Data></EventData></Event>"""


def test_windows_event_xml_parsing_and_sigma_bruteforce(db, sink):
    evs = agent.parse_wevtutil_xml(WIN_XML)
    assert [e["record_id"] for e in evs] == [77, 78] and evs[0]["fields"]["IpAddress"] == "203.0.113.50"
    assert evs[1]["fields"]["IpAddress"] == ""                                              # « - » n'est pas une adresse
    lp = LogPipeline(db, sink)
    for i in range(5):
        lp.ingest("Windows EventID 4625 bob", src_addr="10.0.0.2", source="agent:x",
                  fields={"EventID": 4625, "IpAddress": "203.0.113.50"})
    assert ev(db, "sigma_match")[0]["severity"] == "high"
