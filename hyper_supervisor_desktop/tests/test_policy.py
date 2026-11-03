import json
import pytest
from core import policy, classify, assess
from core.policy import PolicyManager, PolicyError
from core.flows import FlowStore
from tests.test_visibility import add_host


@pytest.fixture()
def net(db, monkeypatch):
    """LAN 192.168.1.0/24 (confiance 60), invités 192.168.50.0/24 (5) ; passerelle, commutateur, serveur, caméra, poste admin."""
    monkeypatch.setattr(policy.lnet, "get_primary_ip", lambda: "192.168.1.100")
    monkeypatch.setattr(policy.lnet, "get_default_gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(policy.lnet, "is_local_address", lambda ip: ip == "192.168.1.100")
    db.execute("INSERT INTO networks (name, cidr, gateway_ip, kind) VALUES ('LAN','192.168.1.0/24','192.168.1.1','lan')")
    db.execute("INSERT INTO networks (name, cidr, gateway_ip, kind) VALUES ('Invités','192.168.50.0/24','192.168.50.1','wifi')")
    h = {"gw": add_host(db, "gw", "192.168.1.1", "router"), "sw": add_host(db, "sw", "192.168.1.2", "switch"),
         "srv": add_host(db, "srv", "192.168.1.10", "server"), "cam": add_host(db, "cam-1", "192.168.1.30"),
         "me": add_host(db, "ma-machine", "192.168.1.100", "workstation"), "adm": add_host(db, "admin-pc", "192.168.1.101", "workstation")}
    classify.sync_zones(db); classify.classify_hosts(db)
    classify.set_role(db, h["adm"], "admin"); classify.set_role(db, h["me"], "admin")
    fs = FlowStore(db)
    fs.add("192.168.50.9", "192.168.1.10", "tcp", 445, 1000, 10, flows=5)
    fs.add("192.168.50.9", "8.8.8.8", "tcp", 443, 5000, 50, flows=20)
    fs.add("192.168.1.30", "192.168.1.10", "tcp", 445, 500, 5, flows=3)
    fs.add("192.168.1.30", "192.168.1.10", "udp", 53, 50, 1, flows=10)
    fs.add("192.168.1.101", "192.168.1.2", "tcp", 22, 300, 3, flows=2)
    return h


def test_service_parsing_and_cover():
    assert policy.canonical_service("SSH") == "tcp/22" and policy.canonical_service("dns") == "udp/53,tcp/53"
    assert policy.canonical_service("tcp/80-443") == "tcp/80-443" and policy.canonical_service("tcp/22,udp/161") == "tcp/22,udp/161"
    for bad in ("", "tcp", "tcp/0", "tcp/70000", "tcp/90-80", "gre/1", "any,tcp/22", "tcp/abc"):
        with pytest.raises(PolicyError): policy.parse_service(bad)
    web = policy.parse_service("tcp/80-443")
    assert policy.service_matches(web, "tcp", 200) and not policy.service_matches(web, "udp", 200) and not policy.service_matches(web, "tcp", 444)
    assert policy.service_matches(policy.parse_service("icmp"), "icmp", 0) and policy.service_matches(policy.parse_service("any"), "other", 0)
    assert policy.services_cover(policy.parse_service("tcp/1-1000"), policy.parse_service("ssh,https"))
    assert not policy.services_cover(policy.parse_service("ssh"), policy.parse_service("any"))


def test_selectors_validation_and_matching(db, net):
    for bad in ("zone:Inconnue", "role:pirate", "host:999", "host:abc", "ip:pas-une-ip", "n'importe quoi", "zone:"):
        with pytest.raises(PolicyError): policy.parse_selector(db, bad)
    ctx = policy.Context(db)
    assert ctx.match(policy.parse_selector(db, "zone:Invités"), "192.168.50.9") and not ctx.match(policy.parse_selector(db, "zone:LAN"), "192.168.50.9")
    assert ctx.match(policy.parse_selector(db, "role:server"), "192.168.1.10") and not ctx.match(policy.parse_selector(db, "role:server"), "192.168.1.30")
    assert ctx.match(policy.parse_selector(db, "ip:192.168.1.0/24"), "192.168.1.77") and ctx.match(policy.parse_selector(db, f"host:{net['srv']}"), "192.168.1.10")
    assert not ctx.match(policy.parse_selector(db, "role:server"), "8.8.8.8")


def test_first_match_wins_and_default(db, net):
    pm = PolicyManager(db)
    pm.create_rule({"name": "autoriser SMB admin", "src": "role:admin", "dst": "role:server", "service": "smb", "action": "allow", "position": 10})
    pm.create_rule({"name": "interdire SMB", "src": "any", "dst": "role:server", "service": "smb", "action": "deny", "position": 20})
    for r in pm.rules(): pm.approve_rule(r["id"])
    rules = [policy.CompiledRule(db, r) for r in policy.effective_rows(db, False)]
    ctx = policy.Context(db)
    assert policy.decide(rules, ctx, "192.168.1.101", "192.168.1.10", "tcp", 445)[0] == "allow"
    a, r = policy.decide(rules, ctx, "192.168.50.9", "192.168.1.10", "tcp", 445)
    assert a == "deny" and r.row["name"] == "interdire SMB"
    assert policy.decide(rules, ctx, "192.168.50.9", "192.168.1.10", "tcp", 80)[0] == "allow"          # aucune règle : défaut
    db.set_setting("policy_default", "deny")
    assert policy.decide(rules, ctx, "192.168.50.9", "192.168.1.10", "tcp", 80, policy.default_action(db))[0] == "deny"


def test_lockout_guard_refuses_cutting_supervision_paths(db, net):
    pm = PolicyManager(db)
    with pytest.raises(PolicyError, match="Coupure de supervision SSH"):
        pm.create_rule({"name": "mauvaise idée", "src": "any", "dst": "role:network", "service": "ssh", "action": "deny"})
    with pytest.raises(PolicyError, match="Coupure"):
        pm.create_rule({"name": "tout bloquer", "src": "any", "dst": "any", "service": "any", "action": "deny"})
    with pytest.raises(PolicyError, match="Coupure de supervision SNMP"):
        pm.create_rule({"name": "pas de snmp", "src": "ip:192.168.1.100", "dst": "host:%d" % net["sw"], "service": "snmp", "action": "deny"})
    deny_admin = {"name": "admin réservée", "src": "any", "dst": "role:network", "service": "ssh,telnet,snmp", "action": "deny", "position": 400}
    # autoriser seulement Procus ne suffit pas : le poste d'administration protégé serait coupé
    pm.create_rule({"name": "supervision", "src": "ip:192.168.1.100", "dst": "role:network", "service": "ssh,snmp,icmp", "action": "allow", "position": 10})
    with pytest.raises(PolicyError, match="administration SSH depuis un poste protégé"):
        pm.create_rule(deny_admin)
    pm.create_rule({"name": "poste admin", "src": "role:admin", "dst": "role:network", "service": "ssh,snmp", "action": "allow", "position": 20})
    pm.create_rule(deny_admin)                                           # maintenant acceptable
    # refus par défaut : tout est coupé tant qu'aucune autorisation n'est approuvée
    db.set_setting("policy_default", "deny")
    issues = policy.lockout_issues(db, [])
    assert issues and "action par défaut" in issues[0]["message"]


def test_approval_flow_order_four_eyes_and_edit_resets(db, net):
    pm = PolicyManager(db)
    classify.set_role(db, net["me"], "workstation")          # cette machine n'est protégée que par la règle de supervision
    ids = pm.apply_template("mgmt_admin_only")
    assert len(ids) == 3
    with pytest.raises(PolicyError, match="Coupure"):                                       # le « refuser » ne peut pas passer avant les « autoriser »
        pm.approve_rule(ids[2])
    assert pm.approve_many(ids) == sorted(ids, key=lambda i: db.fetchone("SELECT position FROM policy_rules WHERE id=?", (i,))["position"])
    assert {r["status"] for r in pm.rules()} == {"approved"}
    with pytest.raises(PolicyError, match="déjà en place"): pm.apply_template("mgmt_admin_only")
    # retirer l'autorisation de supervision rouvrirait la coupure : refusé
    sup = db.fetchone("SELECT id FROM policy_rules WHERE name LIKE 'Supervision Procus%'")["id"]
    with pytest.raises(PolicyError, match="Impossible"): pm.retire_rule(sup)
    with pytest.raises(PolicyError, match="Impossible"): pm.set_enabled(sup, False)
    # modifier une règle approuvée la remet en brouillon
    adm = db.fetchone("SELECT * FROM policy_rules WHERE name LIKE 'Administration depuis%'")
    pm.update_rule(adm["id"], {"name": adm["name"], "src": adm["src"], "dst": adm["dst"], "service": "ssh", "action": "allow", "position": 60})
    assert db.fetchone("SELECT status FROM policy_rules WHERE id=?", (adm["id"],))["status"] == "draft"
    # double validation
    db.set_setting("policy_four_eyes", "1")
    with pytest.raises(PolicyError, match="Double validation"): pm.approve_rule(adm["id"])
    db.execute("UPDATE policy_rules SET created_by='autre' WHERE id=?", (adm["id"],)); pm.approve_rule(adm["id"])
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='policy_rule_approved'")


def test_permissions_required(db, net, security):
    assert security.authenticate("admin", "admin")
    pm = PolicyManager(db, security)
    class Deny:
        def has_permission(self, p): return False
        def get_current_user(self): return {"login": "lecteur"}
    with pytest.raises(PolicyError, match="can_manage_config"):
        PolicyManager(db, Deny()).create_rule({"name": "x", "action": "deny", "src": "any", "dst": "any", "service": "telnet"})
    rid = pm.create_rule({"name": "ok", "src": "any", "dst": "any", "service": "telnet", "action": "deny"})
    assert db.fetchone("SELECT created_by FROM policy_rules WHERE id=?", (rid,))["created_by"] == "admin"


def test_normalize_rejects_bad_input(db, net):
    pm = PolicyManager(db)
    base = {"name": "r", "src": "any", "dst": "any", "service": "telnet", "action": "deny"}
    for bad in ({"name": " "}, {"action": "drop"}, {"service": "xyz"}, {"src": "zone:nope"}, {"position": 0}, {"position": 99999}, {"expires_at": "demain"}):
        with pytest.raises(PolicyError): pm.create_rule({**base, **bad})
    with pytest.raises(PolicyError): pm.update_rule(999, base)
    with pytest.raises(PolicyError): pm.approve_rule(999)
    with pytest.raises(PolicyError): pm.retire_rule(999)


def test_validation_warnings_shadow_broad(db, net):
    pm = PolicyManager(db)
    a = pm.create_rule({"name": "A", "src": "zone:Invités", "dst": "zone:LAN", "service": "any", "action": "deny", "position": 10}); pm.approve_rule(a)
    w = pm.validate({"name": "B", "src": "zone:Invités", "dst": "role:server", "service": "smb", "action": "deny", "position": 20})
    assert [i["code"] for i in w] == ["shadowed"] and "couvre déjà" in w[0]["message"]
    w = pm.validate({"name": "C", "src": "zone:Invités", "dst": "role:server", "service": "smb", "action": "allow", "position": 20})
    assert w and "jamais appliquée" in w[0]["message"]
    w = pm.validate({"name": "tout", "src": "any", "dst": "any", "service": "any", "action": "allow", "position": 900})
    assert any(i["code"] == "too_broad" for i in w)
    assert pm.validate({"name": "D", "src": "role:camera", "dst": "role:server", "service": "smb", "action": "deny", "position": 30}) == []


def test_simulation_counts_hits_impact_and_default(db, net):
    pm = PolicyManager(db)
    pm.create_rule({"name": "invités→LAN", "src": "zone:Invités", "dst": "zone:LAN", "service": "any", "action": "deny", "position": 10})
    pm.create_rule({"name": "jamais utilisée", "src": "ip:10.99.0.0/16", "dst": "any", "service": "tcp/1", "action": "deny", "position": 20})
    s = pm.simulate()
    assert s["flows_total"] == 40 and s["denied_flows"] == 5 and s["allowed_flows"] == 35 and s["denied_pct"] == 12
    per = {r["name"]: r for r in s["per_rule"]}
    assert per["invités→LAN"]["flows"] == 5 and per["jamais utilisée"]["flows"] == 0
    assert s["denied_top"][0]["src_name"] == "192.168.50.9" and s["denied_top"][0]["dst_name"] == "srv" and s["denied_top"][0]["port"] == 445
    assert any("aucun flux" in w for w in s["warnings"]) and any("srv" in w for w in s["warnings"])
    s2 = pm.simulate(include_drafts=False)                       # brouillons : non en vigueur
    assert s2["denied_flows"] == 0 and s2["rules"] == 0
    assert s["lockout"] == []
    db.set_setting("policy_default", "deny")
    assert pm.simulate(include_drafts=False)["denied_pct"] == 100 and pm.simulate(include_drafts=False)["lockout"]


def test_templates_and_findings_to_rules_end_to_end(db, net):
    pm = PolicyManager(db)
    g = pm.apply_template("isolate_guests")
    assert len(g) == 1 and db.fetchone("SELECT src, dst FROM policy_rules WHERE id=?", (g[0],)) == {"src": "zone:Invités", "dst": "zone:LAN"}
    assert len(pm.apply_template("iot_no_lan")) == 8 and len(pm.apply_template("block_insecure")) == 3
    with pytest.raises(PolicyError): pm.apply_template("inconnu")
    db.execute("UPDATE net_zones SET trust = 50 WHERE name='Invités'")
    with pytest.raises(PolicyError, match="Aucune zone"):
        PolicyManager(db).apply_template("isolate_guests") if not policy._zones(db, low=10) else pytest.fail("zone invités attendue absente")
    # constat → règle recommandée → simulation montre l'impact du flux observé
    assess.run_assessment(db)
    f = db.fetchone("SELECT id FROM assess_findings WHERE fkey = 'seg:role:camera>server'")
    rid = pm.from_finding(f["id"])
    assert db.fetchone("SELECT source FROM policy_rules WHERE id=?", (rid,))["source"] == f"finding:{f['id']}"
    with pytest.raises(PolicyError, match="existe déjà"): pm.from_finding(f["id"])
    nohint = db.fetchone("SELECT id FROM assess_findings WHERE rule_hint IS NULL")
    if nohint:
        with pytest.raises(PolicyError): pm.from_finding(nohint["id"])
    txt = policy.rules_as_text(db, pm.rules())
    assert any("REFUSER" in t and "Caméra" in t for t in txt)


def test_expired_rules_and_disabled_rules_ignored(db, net):
    pm = PolicyManager(db)
    r1 = pm.create_rule({"name": "expirée", "src": "zone:Invités", "dst": "any", "service": "tcp/443", "action": "deny", "expires_at": "2000-01-01"})
    r2 = pm.create_rule({"name": "valide", "src": "zone:Invités", "dst": "any", "service": "tcp/443", "action": "deny"})
    assert [r["id"] for r in policy.effective_rows(db, True)] == [r2]
    pm.set_enabled(r2, False)
    assert policy.effective_rows(db, True) == []
