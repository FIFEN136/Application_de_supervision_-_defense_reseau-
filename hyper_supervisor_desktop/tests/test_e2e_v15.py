"""Bout en bout v15 : un agent réel rapporte des connexions → flux → constat de segmentation → règle recommandée →
simulation d'impact → approbation (avec garde-fou anti-blocage). Aucun équipement n'est modifié."""
import os, socket, time, importlib.util
import pytest
from PyQt6.QtCore import QCoreApplication
from core.defense import DefenseManager
from core import assess, classify, policy
from core.flows import build_netflow_v5
from tests.test_visibility import add_host
from tests.test_policy import net  # noqa: F401

spec = importlib.util.spec_from_file_location("procus_agent", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent", "procus_agent.py"))
agent = importlib.util.module_from_spec(spec); spec.loader.exec_module(agent)


def free(udp=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


@pytest.fixture()
def env(qapp, db, security, net):
    assert security.authenticate("admin", "admin")
    m = DefenseManager(db, security); yield m, db, net; m.stop()


def test_agent_connections_to_policy_simulation(env):
    m, db, h = env
    db.set_setting("agent_port", str(free())); m.set_enabled("defense_agents", True)
    e = m.registry.enroll("srv", host_id=h["srv"], watch_paths=[])
    cfg = m.agent_config(e, "127.0.0.1")
    conns = [{"laddr": "192.168.1.10", "lport": 445, "raddr": "192.168.50.9", "rport": 50111, "proto": "tcp", "dir": "in"},
             {"laddr": "192.168.1.10", "lport": 40000, "raddr": "192.168.1.1", "rport": 53, "proto": "tcp", "dir": "out"}]
    assert agent.post_report(cfg, {"system": {"os": "linux"}, "connections": conns})["ok"]
    rows = {(r["src_ip"], r["dst_ip"], r["dst_port"]) for r in db.fetchall("SELECT * FROM flows_agg WHERE source LIKE 'agent:%'")}
    assert ("192.168.50.9", "192.168.1.10", 445) in rows                      # invité → serveur SMB, vu depuis le serveur lui-même
    res = assess.run_assessment(db, m.sink)
    f = db.fetchone("SELECT * FROM assess_findings WHERE fkey = 'seg:zone:Invités>LAN'")
    assert f and "tcp/445" in f["detail"]
    rid = m.policy.from_finding(f["id"])
    sim = m.policy.simulate()
    assert sim["denied_flows"] >= 1 and any(d["src"] == "192.168.50.9" and d["port"] == 445 for d in sim["denied_top"])
    assert sim["lockout"] == []                                                # la règle proposée ne coupe pas la supervision
    m.policy.approve_rule(rid)
    assert db.fetchone("SELECT status FROM policy_rules WHERE id=?", (rid,))["status"] == "approved"
    # une règle dangereuse issue d'un constat est refusée à l'approbation
    with pytest.raises(policy.PolicyError, match="Coupure"):
        m.policy.create_rule({"name": "dangereux", "src": "any", "dst": "host:%d" % h["sw"], "service": "any", "action": "deny"})
    # rien n'a été exécuté nulle part
    assert db.fetchone("SELECT COUNT(*) n FROM action_runs")["n"] == 0


def test_netflow_to_flows_to_unused_rule_warning(env):
    m, db, h = env
    db.set_setting("netflow_port", str(free(udp=True))); m.set_enabled("defense_netflow", True)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(build_netflow_v5([{"src": "192.168.1.30", "dst": "192.168.1.10", "dport": 3389, "proto": 6, "bytes": 9000, "packets": 40}]),
             ("127.0.0.1", m.netflow.port))
    end = time.time() + 3
    while time.time() < end and not db.fetchone("SELECT 1 FROM flows_agg WHERE dst_port=3389"):
        QCoreApplication.processEvents(); time.sleep(0.05)
    m.policy.create_rule({"name": "caméra→serveur RDP", "src": "role:camera", "dst": "role:server", "service": "rdp", "action": "deny", "position": 10})
    m.policy.create_rule({"name": "règle morte", "src": "ip:10.200.0.0/16", "dst": "any", "service": "tcp/9", "action": "deny", "position": 20})
    s2 = m.policy.simulate()
    per = {r["name"]: r["flows"] for r in s2["per_rule"]}
    assert per["caméra→serveur RDP"] == 1 and per["règle morte"] == 0
    assert any("règle morte" in w for w in s2["warnings"])


def test_whole_chain_leaves_existing_features_untouched(env):
    """Les nouvelles tables n'altèrent pas les anciennes : hôtes, ports, événements restent lisibles et cohérents."""
    m, db, h = env
    n_hosts = db.fetchone("SELECT COUNT(*) n FROM hosts")["n"]
    assess.run_assessment(db, m.sink); m.policy.apply_template("isolate_guests")
    assert db.fetchone("SELECT COUNT(*) n FROM hosts")["n"] == n_hosts
    assert db.fetchone("SELECT name FROM hosts WHERE id=?", (h["srv"],))["name"] == "srv"
    for t in ("incidents", "pending_actions", "config_snapshots", "baselines", "events"):
        db.fetchone(f"SELECT COUNT(*) n FROM {t}")
