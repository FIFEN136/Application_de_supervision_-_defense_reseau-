"""Scénarios de bout en bout v14 : une détection réelle traverse tout le pipeline."""
import json, os, socket, time, importlib.util
import pytest
from PyQt6.QtCore import QCoreApplication
from core.defense import DefenseManager
from core.automation import AutomationEngine
from core.honeypot import save_ports
from core.sigma_engine import seed_builtin_rules

spec = importlib.util.spec_from_file_location("procus_agent", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent", "procus_agent.py"))
agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)


def free_port(udp=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def pump(cond, t=4):
    end = time.time() + t
    while time.time() < end and not cond():
        QCoreApplication.processEvents(); time.sleep(0.05)
    return cond()


@pytest.fixture()
def env(qapp, db, security):
    assert security.authenticate("admin", "admin")
    m = DefenseManager(db, security); yield m, db, security; m.stop()


def test_e2e_honeypot_to_incident_to_action_simulation(env):
    m, db, sec = env
    port, port2 = free_port(), free_port(); save_ports(db, [{"port": port, "profile": "ssh"}, {"port": port2, "profile": "telnet"}])
    m.honeypots.bind, m.honeypots.ignore_local = "127.0.0.1", False
    m.set_enabled("defense_honeypot", True, "admin")
    for i in range(6):                                   # balayage : 6 connexions sur 2 leurres
        c = socket.create_connection(("127.0.0.1", (port, port2)[i % 2]), timeout=3); c.recv(16); c.close()
    assert pump(lambda: db.fetchone("SELECT COUNT(*) n FROM honeypot_hits")["n"] >= 6)
    assert db.fetchone("SELECT COUNT(*) n FROM events WHERE event_type='honeypot_hit' AND severity='disaster'")["n"] >= 1
    eng = AutomationEngine(db, sec); eng.run_pipeline()
    inc = db.fetchone("SELECT * FROM incidents ORDER BY id DESC")
    assert inc and inc["priority_label"].startswith(("P1", "P2"))
    act = db.fetchone("SELECT * FROM pending_actions WHERE action_type IN ('block_ip','isolate_host')")
    assert act and act["status"] == "pending"
    eng.decide_action(act["id"], True, who="admin")
    if act["action_type"] == "block_ip":                 # source = 127.0.0.1 : garde-fou obligatoire
        from core.action_runner import ActionRefused
        with pytest.raises(ActionRefused):
            m.runner.execute(act["id"], simulate=True)
    # même scénario avec une source distante : proposition → approbation → simulation → rien d'exécuté
    m.honeypots.ignore_local = True
    for i in range(6):
        m.honeypots.record_hit("10.77.7.7", 4000 + i, (port, port2)[i % 2], "ssh", b"SSH-2.0-x")
    eng.run_pipeline()
    act2 = db.fetchone("SELECT * FROM pending_actions WHERE action_type='block_ip' AND target='10.77.7.7'")
    assert act2, "blocage de la source proposé"
    eng.decide_action(act2["id"], True, who="admin")
    r = m.runner.execute(act2["id"], simulate=True)
    assert r["status"] == "simulated" and "10.77.7.7" in r["command"]
    assert db.fetchone("SELECT COUNT(*) n FROM action_runs WHERE status='ok'")["n"] == 0
    with pytest.raises(Exception):                       # exécution réelle désactivée par défaut
        m.runner.execute(act2["id"], simulate=False)


def test_e2e_agent_report_fim_and_sigma_log_alerts(env, tmp_path):
    m, db, sec = env
    seed_builtin_rules(db); m.pipeline.reload_rules()
    db.set_setting("agent_port", str(free_port())); m.set_enabled("defense_agents", True)
    f = tmp_path / "secret.conf"; f.write_text("v1")
    e = m.registry.enroll("srv", watch_paths=[str(f)], os_name="linux")
    cfg = m.agent_config(e, "127.0.0.1")
    payload = lambda lines: {"system": {"os": "linux"}, "fim": agent.fim_snapshot([str(f)]), "logs": lines}
    assert agent.post_report(cfg, payload([]))["ok"]                       # 1er rapport : référence
    assert db.fetchone("SELECT COUNT(*) n FROM events WHERE event_type='fim_change'")["n"] == 0
    f.write_text("v2-tampered")
    assert agent.post_report(cfg, payload([{"message": "sshd[1]: Failed password for root from 10.0.0.9 port 22 ssh2"}]))["ok"]
    assert db.fetchone("SELECT COUNT(*) n FROM events WHERE event_type='fim_change'")["n"] == 1
    assert db.fetchone("SELECT COUNT(*) n FROM log_events")["n"] >= 1
    bad = dict(cfg, secret="faux")
    try:
        r = agent.post_report(bad, payload([])); rejected = not r.get("ok")
    except Exception:
        rejected = True                                  # secret erroné : le serveur refuse (401)
    assert rejected


def test_e2e_syslog_udp_triggers_sigma_bruteforce(env):
    m, db, sec = env
    seed_builtin_rules(db); m.pipeline.reload_rules()
    port = free_port(udp=True); db.set_setting("syslog_port", str(port))
    m.syslog = None
    m.set_enabled("defense_syslog", True)
    assert m.status()["syslog"]["running"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(12):
        s.sendto(b"<38>Oct 17 10:00:0%d srv sshd[99]: Failed password for root from 10.0.0.9 port 22 ssh2" % (i % 10), ("127.0.0.1", port))
    assert pump(lambda: db.fetchone("SELECT COUNT(*) n FROM events WHERE event_type='sigma_match'")["n"] >= 1)
    assert m.status()["syslog"]["received"] >= 1


def test_e2e_arp_gateway_spoof_disaster_and_rogue_dhcp(env, monkeypatch):
    m, db, sec = env
    from core import local_network as lnet
    gw = "192.168.9.1"
    monkeypatch.setattr(lnet, "get_default_gateway", lambda: gw, raising=False)
    monkeypatch.setattr(m.arp, "_gateways", lambda: {gw})
    m.arp.check({gw: "aa:aa:aa:aa:aa:01"})
    r = m.arp.check({gw: "bb:bb:bb:bb:bb:99"})
    assert any(x["severity"] == "disaster" for x in r)
    assert db.fetchone("SELECT COUNT(*) n FROM events WHERE event_type='arp_spoof' AND severity='disaster'")["n"] >= 1
    db.set_setting("dhcp_trusted", json.dumps(["192.168.9.1"]))
    monkeypatch.setattr(m.dhcp, "probe", lambda **k: {"servers": [{"server": "192.168.9.66", "offered": "192.168.9.50", "router": "192.168.9.66", "dns": ["1.2.3.4"]}], "error": None})
    res = m.dhcp.check()
    assert res["alerts"] and db.fetchone("SELECT COUNT(*) n FROM events WHERE event_type='rogue_dhcp' AND severity='disaster'")["n"] >= 1


def test_e2e_audit_trail_and_no_secret_leak(env):
    m, db, sec = env
    h = db.fetchone("SELECT id FROM hosts") or {"id": m.sink.local_host()[0]}
    m.config.set_credentials(h["id"], "root", "SuperSecret!42", "password", 22, "linux")
    raw = db.fetchone("SELECT secret_enc FROM host_credentials WHERE host_id=?", (h["id"],))["secret_enc"]
    assert "SuperSecret" not in raw
    e = m.registry.enroll("x"); raw2 = db.fetchone("SELECT secret_enc FROM agents")["secret_enc"]
    assert e["secret"] not in raw2
    dump = " ".join(str(r) for r in db.fetchall("SELECT * FROM events")) + " ".join(str(r) for r in db.fetchall("SELECT * FROM audit_logs"))
    assert "SuperSecret" not in dump and e["secret"] not in dump
