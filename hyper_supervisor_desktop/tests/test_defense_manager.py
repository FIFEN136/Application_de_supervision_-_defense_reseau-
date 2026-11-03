import json, socket, time, os
import pytest
from PyQt6.QtCore import QCoreApplication
from core.defense import DefenseManager, DEFAULTS
from core.honeypot import save_ports
from core import agent_server as ags
import importlib.util
spec = importlib.util.spec_from_file_location("procus_agent", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent", "procus_agent.py"))
agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def mgr(qapp, db, security):
    m = DefenseManager(db, security)
    yield m
    m.stop()


def test_safe_defaults_services_that_open_ports_are_off(mgr):
    st = mgr.status()
    assert not st["honeypot"]["enabled"] and not st["agents"]["enabled"] and not st["syslog"]["enabled"] and not st["actions"]["enabled"]
    assert st["arp"]["enabled"] and st["dhcp"]["enabled"] and st["fim"]["enabled"]
    assert not st["honeypot"]["running"] and not st["agents"]["running"]


def test_defaults_do_not_override_existing_choices(db, security, qapp):
    db.set_setting("defense_arp", "0")
    m = DefenseManager(db, security)
    assert not m.enabled("defense_arp")


def test_honeypot_toggle_starts_and_stops_and_alert_signal(mgr, db):
    port = free_port(); save_ports(db, [{"port": port, "profile": "ssh"}])
    got = []; mgr.alert.connect(got.append)
    mgr.honeypots.bind = "127.0.0.1"; mgr.honeypots.ignore_local = False
    mgr.set_enabled("defense_honeypot", True, "admin")
    assert mgr.honeypots.running and mgr.status()["honeypot"]["detail"][port] == "à l'écoute"
    c = socket.create_connection(("127.0.0.1", port), timeout=3); c.recv(32); c.close()
    end = time.time() + 3
    while time.time() < end and not got:
        QCoreApplication.processEvents(); time.sleep(0.05)
    assert got and got[0]["event_type"] == "honeypot_hit"
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='defense_honeypot_on'")
    mgr.set_enabled("defense_honeypot", False, "admin")
    assert not mgr.honeypots.running
    with pytest.raises(OSError): socket.create_connection(("127.0.0.1", port), timeout=1)


def test_agent_server_toggle_tls_cert_generated_and_config_has_pinned_fingerprint(mgr, db):
    db.set_setting("agent_port", str(free_port()))
    mgr.set_enabled("defense_agents", True)
    assert mgr.status()["agents"]["running"] and mgr.status()["agents"]["tls"]
    e = mgr.registry.enroll("poste", watch_paths=[])
    cfg = mgr.agent_config(e, server_host="127.0.0.1")
    assert cfg["server"].startswith("https://127.0.0.1:") and len(cfg["server_fingerprint"]) == 64
    assert agent.post_report(cfg, {"system": {"os": "linux"}})["ok"]                       # agent réel ↔ serveur réel
    assert db.fetchone("SELECT last_seen FROM agents")["last_seen"]
    mgr.set_enabled("defense_agents", False)
    assert not mgr.status()["agents"]["running"]


def test_port_conflict_is_reported_in_status_not_raised(mgr, db):
    busy = socket.socket(); busy.bind(("0.0.0.0", 0)); busy.listen(1)
    db.set_setting("agent_port", str(busy.getsockname()[1]))
    mgr.set_enabled("defense_agents", True)
    assert not mgr.status()["agents"]["running"] and "indisponible" in mgr.status()["agents"]["error"]
    busy.close()


def test_run_jobs_and_scheduler_thread_lifecycle(mgr, db, monkeypatch):
    from core import local_network as lnet
    monkeypatch.setattr(lnet, "read_arp_table", lambda: {"192.168.7.1": "aa:aa:aa:aa:aa:01"})
    mgr.run_job("arp")
    assert db.fetchone("SELECT mac FROM arp_bindings WHERE ip='192.168.7.1'")["mac"] == "aa:aa:aa:aa:aa:01"
    assert mgr.run_job("fim")["baseline_created"] is True
    assert mgr.run_job("backup") == [] and mgr.run_job("purge") is True
    with pytest.raises(ValueError): mgr.run_job("inconnu")
    mgr.start(); assert mgr._thread.is_alive()
    mgr.stop(); assert mgr._thread is None
