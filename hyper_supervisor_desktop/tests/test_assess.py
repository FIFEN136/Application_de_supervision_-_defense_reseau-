import json
import pytest
from core import assess, classify
from core.defense_common import EventSink
from tests.test_visibility import add_host


def port(db, hid, p, proto="TCP", banner=None, ver=None):
    db.execute("INSERT INTO port_states (host_id, port, protocol, state, service_banner, service_version) VALUES (?,?,?,'open',?,?)",
               (hid, p, proto, banner, ver))


def keys(db, status="open"):
    return {r["fkey"]: r for r in db.fetchall("SELECT * FROM assess_findings WHERE status=?", (status,))}


def test_version_comparison_edge_cases():
    v = assess.vtuple
    assert v("9.6p1") == (9, 6, 1) and v("2.4.49") < v("2.4.50") and v("1.0.1") < v("1.0.1e") < v("1.0.1g") < v("1.0.2")
    assert v("9.8p1") > v("9.7p1") > v("8.5p1") > v("7.7")
    assert assess.parse_product("SSH-2.0-OpenSSH_9.6p1 Ubuntu") == ("openssh", "9.6p1")
    assert assess.parse_product("220 (vsFTPd 2.3.4)") == ("vsftpd", "2.3.4")
    assert assess.parse_product("Server: Apache/2.4.49 (Unix)") == ("apache", "2.4.49")
    assert assess.parse_product("rien d'utile") is None


@pytest.mark.parametrize("prod,ver,expected", [
    ("vsftpd", "2.3.4", {"CVE-2011-2523"}), ("vsftpd", "3.0.5", set()),
    ("openssh", "9.7p1", {"CVE-2024-6387"}), ("openssh", "9.8p1", set()), ("openssh", "8.4p1", set()),
    ("openssh", "7.4", {"CVE-2018-15473"}), ("openssh", "7.8", set()),
    ("apache", "2.4.49", {"CVE-2021-41773", "CVE-2021-42013"}), ("apache", "2.4.50", {"CVE-2021-42013"}), ("apache", "2.4.51", set()),
    ("openssl", "1.0.1f", {"CVE-2014-0160"}), ("openssl", "1.0.1g", set()), ("exim", "4.91", {"CVE-2019-10149"}), ("exim", "4.92", set()),
])
def test_cve_matching_boundaries(db, prod, ver, expected):
    assert {c["cve"] for c in assess.match_cves(db, prod, ver)} == expected


def test_findings_exposure_cve_snmp_unapproved_and_no_duplicates(db):
    srv = add_host(db, "srv", "192.168.1.10", "server")
    sw = add_host(db, "sw", "192.168.1.2", "switch")
    port(db, srv, 23); port(db, srv, 22, banner="SSH-2.0-OpenSSH_9.7p1"); port(db, srv, 21, banner="220 (vsFTPd 2.3.4)")
    port(db, sw, 80); port(db, srv, 80)                                     # 80 : constat seulement sur un équipement réseau
    port(db, srv, 161, "UDP")
    db.execute("INSERT INTO hosts (name, ip_address, approved) VALUES ('inconnu','192.168.1.77',0)")
    r1 = assess.run_assessment(db)
    k = keys(db)
    assert f"exp:{srv}:23/TCP" in k and k[f"exp:{srv}:23/TCP"]["severity"] == "critical"
    assert f"cve:CVE-2024-6387:{srv}:22" in k and f"cve:CVE-2011-2523:{srv}:21" in k
    assert f"exp:{sw}:80/TCP" in k and f"exp:{srv}:80/TCP" not in k
    assert any(x.startswith("snmp:") for x in k) and any(x.startswith("unapproved:") for x in k)
    assert "À VÉRIFIER" in k[f"cve:CVE-2024-6387:{srv}:22"]["detail"]
    n = db.fetchone("SELECT COUNT(*) n FROM assess_findings")["n"]
    r2 = assess.run_assessment(db)
    assert db.fetchone("SELECT COUNT(*) n FROM assess_findings")["n"] == n and r2["new"] == 0 and r1["new"] == n
    hint = json.loads(k[f"exp:{srv}:23/TCP"]["rule_hint"])
    assert hint == {"name": "Bloquer Telnet vers srv", "src": "any", "dst": f"host:{srv}", "service": "tcp/23", "action": "deny"}


def test_fixed_reopen_and_accepted_lifecycle(db):
    srv = add_host(db, "srv", "192.168.1.10", "server")
    port(db, srv, 23); assess.run_assessment(db)
    fid = db.fetchone("SELECT id FROM assess_findings WHERE fkey LIKE 'exp:%'")["id"]
    with pytest.raises(ValueError): assess.set_status(db, fid, "accepted", "")           # justification obligatoire
    with pytest.raises(ValueError): assess.set_status(db, fid, "fixed", "x")
    with pytest.raises(ValueError): assess.set_status(db, 999, "open")
    assess.set_status(db, fid, "accepted", "équipement isolé, migration prévue en janvier", "admin")
    assess.run_assessment(db)
    assert db.fetchone("SELECT status FROM assess_findings WHERE id=?", (fid,))["status"] == "accepted"
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='finding_accepted'")
    assess.set_status(db, fid, "open", "", "admin")
    db.execute("DELETE FROM port_states")                                                # service fermé
    r = assess.run_assessment(db)
    assert r["fixed"] == 1 and db.fetchone("SELECT status FROM assess_findings WHERE id=?", (fid,))["status"] == "fixed"
    port(db, srv, 23)                                                                    # il revient
    r = assess.run_assessment(db)
    assert db.fetchone("SELECT status FROM assess_findings WHERE id=?", (fid,))["status"] == "open" and r["new"] == 1


def test_segmentation_findings_from_flows(db):
    db.execute("INSERT INTO networks (name, cidr, kind) VALUES ('LAN','192.168.1.0/24','lan')")
    db.execute("INSERT INTO networks (name, cidr, kind) VALUES ('Invités','192.168.50.0/24','wifi')")
    srv = add_host(db, "srv", "192.168.1.10", "server"); cam = add_host(db, "cam-1", "192.168.1.30")
    from core.flows import FlowStore
    fs = FlowStore(db)
    fs.add("192.168.50.9", "192.168.1.10", "tcp", 445, 1000, 10)
    fs.add("192.168.50.9", "192.168.1.10", "udp", 53, 10)                                 # DNS : ignoré
    fs.add("192.168.1.30", "192.168.1.10", "tcp", 445, 500, 5)
    assess.run_assessment(db)
    k = keys(db)
    zone = k["seg:zone:Invités>LAN"]; role = k["seg:role:camera>server"]
    assert "tcp/445" in zone["detail"] and "udp/53" not in zone["detail"]
    assert role["severity"] == "high"
    assert json.loads(zone["rule_hint"]) == {"name": "Isoler Invités de LAN", "src": "zone:Invités", "dst": "zone:LAN", "service": "any", "action": "deny"}
    assert json.loads(role["rule_hint"])["src"] == "role:camera"


def test_events_only_for_new_critical_high_and_capped(db):
    srv = add_host(db, "srv", "192.168.1.10", "server")
    for p in (23, 512, 513, 514, 2375, 21, 5900, 6379, 27017, 9200, 11211):             # 11 constats critiques/élevés
        port(db, srv, p)
    got = []
    sink = EventSink(db, on_alert=got.append)
    r = assess.run_assessment(db, sink, max_events=10)
    assert r["events"] == 10 and len(got) == 10 and all(e["event_type"] == "vulnerability_found" for e in got)
    assert {e["severity"] for e in got} <= {"disaster", "high"}
    got.clear(); assess.run_assessment(db, sink)
    assert got == []                                                                       # pas de répétition


def test_import_cves_validation_and_use(db, tmp_path):
    f = tmp_path / "cve.json"
    f.write_text(json.dumps([{"cve": "CVE-2099-0001", "product": "monsoft", "min": "1.0", "max": "1.4", "sev": "high", "title": "Test"},
                             {"cve": "pas-un-cve", "product": "x", "min": "1", "max": "2", "sev": "high"},
                             {"cve": "CVE-2099-0002", "product": "y", "min": "1", "max": "2", "sev": "énorme"}]))
    assert assess.import_cves(db, str(f), "admin") == 1
    assert {c["cve"] for c in assess.match_cves(db, "monsoft", "1.2")} == {"CVE-2099-0001"} and not assess.match_cves(db, "monsoft", "1.5")
    bad = tmp_path / "bad.json"; bad.write_text('{"a":1}')
    with pytest.raises(ValueError): assess.import_cves(db, str(bad))
    empty = tmp_path / "e.json"; empty.write_text("[]")
    with pytest.raises(ValueError): assess.import_cves(db, str(empty))
    db.set_setting("cve_extra", "pas du json")
    assert assess.match_cves(db, "openssh", "7.4")                                          # une base importée corrompue ne casse rien
