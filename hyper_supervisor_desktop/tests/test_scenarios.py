"""
Scénarios reproductibles (matériel réel : sockets TCP loopback, agent SNMP de test, base SQLite).
Chaque scénario vérifie le résultat ET la qualité de la preuve conservée.
"""
import json, socket, time, pytest
from core import local_network as lnet
from core.automation import AutomationEngine
from core.monitor import MonitorWorker
from core.network_setup import NetworkSetupWorker
from core.scanner import ScannerWorker
from tests.snmp_agent import SnmpAgent


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def listen(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8); return s


def dev(ip, mac, name="", t="pc", vendor="Dell"):
    return {"ip": ip, "mac": mac, "name": name, "vendor": vendor, "device_type": t, "latency_ms": 1.0, "open_ports": []}


# ── Scénario 1 : équipement inconnu dans un segment surveillé ─────────────────────────
def test_scenario1_unknown_device(db, monkeypatch):
    nid = db.add_network("Bureau", "192.168.50.0/24", "192.168.50.1")
    eng = AutomationEngine(db)
    eng.authorize_network(nid, "admin")
    state = {"found": [dev("192.168.50.1", "aa:aa:aa:00:00:01", "box", "router"),
                       dev("192.168.50.10", "aa:aa:aa:00:00:10", "pc-compta")]}
    monkeypatch.setattr(lnet, "discover_network", lambda cidr, gw=None, **k: state["found"])
    w = NetworkSetupWorker(db); alerts = []
    w.new_device.connect(alerts.append)
    w.discover_network(nid)                                   # 1re passe = référence : AUCUNE alerte
    assert alerts == [] and eng.reference_status()["unapproved"] == []
    state["found"] = state["found"] + [dev("192.168.50.77", "de:ad:be:ef:00:77", "", "unknown", "")]
    w.discover_network(nid)                                   # un inconnu apparaît
    assert len(alerts) == 1 and alerts[0]["state_after"] == "présent"
    unk = eng.reference_status()["unapproved"]
    assert [h["ip_address"] for h in unk] == ["192.168.50.77"]
    out = eng.run_pipeline()
    s = out["steps"]
    assert s["5_correlation"]["incidents_opened"] == 1
    inc = db.fetchone("SELECT * FROM incidents")
    assert inc["priority_label"].startswith(("P1", "P2", "P3")) and inc["host_name"]
    acts = eng.pending_actions()
    assert [a["action_type"] for a in acts] == ["isolate_host"] and "de:ad:be:ef:00:77" in acts[0]["plan"]
    eng.approve_device(unk[0]["id"], "admin")                 # l'humain l'ajoute au référentiel
    assert eng.reference_status()["unapproved"] == []


# ── Scénario 2 : port fermé (baseline) devenu ouvert ───────────────────────────────────
def test_scenario2_closed_port_becomes_open(db):
    p_open, p_closed = free_port(), free_port()
    keep = listen(p_open)
    hid = db.add_host("srv", "127.0.0.1")
    sc = ScannerWorker(db)
    sc.scan_host(hid, "127.0.0.1", "srv", [p_open, p_closed], timeout=0.5)     # baseline automatique
    assert {r["port"]: r["state"] for r in db.fetchall("SELECT port,state FROM baselines WHERE host_id=?", (hid,))} \
        == {p_open: "open", p_closed: "closed"}
    assert db.fetchall("SELECT 1 FROM events WHERE event_type='port_change'") == []   # rien à signaler
    sc.scan_host(hid, "127.0.0.1", "srv", [p_open, p_closed], timeout=0.5)     # inchangé : 0 faux positif
    assert db.fetchall("SELECT 1 FROM events WHERE event_type='port_change'") == []
    rogue = listen(p_closed)
    try:
        t0 = time.perf_counter()
        sc.scan_host(hid, "127.0.0.1", "srv", [p_open, p_closed], timeout=0.5)
        delay = time.perf_counter() - t0
    finally:
        rogue.close(); keep.close()
    ev = db.fetchone("SELECT * FROM events WHERE event_type='port_change'")
    assert ev["severity"] == "disaster" and (ev["state_before"], ev["state_after"]) == ("closed", "open") and ev["port"] == p_closed
    assert delay < 3
    eng = AutomationEngine(db); eng.run_pipeline()
    a = eng.pending_actions()[0]
    assert a["action_type"] == "block_ip" and str(p_closed) in a["plan"] and a["status"] == "pending"


# ── Scénario 3 : configuration d'un routeur modifiée entre deux collectes ─────────────
def test_scenario3_router_config_change(db):
    cfg = {"name": "eth0", "routes": "10.0.0.1"}
    port = free_port(socket.SOCK_DGRAM)
    agent = SnmpAgent(port, community="s3cret", values={
        (1,3,6,1,2,1,2,2,1,2,1): lambda: cfg["name"], (1,3,6,1,2,1,4,20,1,1,1): "192.168.1.1",
        (1,3,6,1,2,1,4,21,1,7,1): lambda: cfg["routes"]})
    agent.start()
    try:
        hid = db.add_host("rtr", "127.0.0.1", device_type="router", snmp_community="s3cret")
        db.execute("UPDATE hosts SET snmp_port=?, snmp_enabled=1 WHERE id=?", (port, hid))
        eng = AutomationEngine(db, snmp=MonitorWorker(db_manager=db))
        r1 = eng.collect_configs()
        assert r1 and r1[0].get("baseline") and not db.fetchall("SELECT 1 FROM events WHERE event_type='config_change'")
        assert eng.collect_configs()[0]["changed"] is False                  # identique : pas de faux positif
        cfg["name"], cfg["routes"] = "eth0-HACKED", "203.0.113.9"        # modification
        r3 = eng.collect_configs()[0]
    finally:
        agent.stop()
    assert r3["changed"] and any("interfaces" in d and "eth0-HACKED" in d for d in r3["diff"]) and any("203.0.113.9" in d for d in r3["diff"])
    ev = db.fetchone("SELECT * FROM events WHERE event_type='config_change'")
    assert ev["severity"] == "high" and "eth0-HACKED" in ev["description"]
    assert len(db.fetchall("SELECT 1 FROM config_snapshots WHERE host_id=?", (hid,))) == 2   # avant ET après conservés
    eng.run_pipeline()
    sheet = eng.investigation_sheet(db.fetchone("SELECT id FROM incidents")["id"])
    assert any("eth0-HACKED" in d for d in sheet["config_diff"])
    assert eng.pending_actions()[0]["action_type"] == "modify_config"


# ── Scénario 4 : plusieurs alertes sur un même équipement groupées, preuves intactes ──
def test_scenario4_correlation_keeps_evidence(db):
    hid = db.add_host("srv-db", "10.1.1.5"); db.execute("UPDATE hosts SET criticality=5 WHERE id=?", (hid,))
    other = db.add_host("autre", "10.1.1.6")
    ids = [db.add_event(hid, "srv-db", "", sev, typ, desc, port=port) for sev, typ, desc, port in [
        ("disaster", "port_change", "Port 3306/TCP : closed → open", 3306),
        ("high", "port_change", "Port 3389/TCP : closed → open", 3389),
        ("high", "host_down", "Hôte srv-db hors ligne", None),
        ("warning", "threshold", "CPU 93 %", None)]]
    db.add_event(other, "autre", "", "warning", "threshold", "CPU 91 %")
    before = db.fetchall("SELECT * FROM events ORDER BY id")
    eng = AutomationEngine(db); eng.run_pipeline()
    incs = db.fetchall("SELECT * FROM incidents ORDER BY priority DESC")
    assert len(incs) == 2                                               # 4 événements → 1 incident ; l'autre hôte → le sien
    big = incs[0]
    assert big["host_name"] == "srv-db" and big["event_count"] == 4 and big["severity"] == "disaster"
    assert big["priority"] > incs[1]["priority"] and big["priority_label"].startswith("P1")
    assert db.fetchall("SELECT * FROM events ORDER BY id") == before    # aucune perte, aucune modification
    sheet = eng.investigation_sheet(big["id"])
    assert sheet["evidence_ids"] == ids and all(str(p) in big["summary"] for p in (3306, 3389))
    eng.run_pipeline()                                                  # idempotent : pas de doublon
    assert len(db.fetchall("SELECT * FROM incidents")) == 2 and db.fetchone("SELECT COUNT(*) AS n FROM incident_events")["n"] == 5


# ── Scénario 5 : rapport périodique automatique construit depuis les données stockées ─
def test_scenario5_periodic_report_from_real_data(db, tmp_path):
    h = db.add_host("srv", "10.2.2.2")
    db.add_event(h, "srv", "", "high", "host_down", "Hôte srv hors ligne")
    db.set_setting("report_dir", str(tmp_path / "rep"))
    eng = AutomationEngine(db)
    assert eng.report_due() is True                                     # jamais généré
    out = eng.run_pipeline()
    paths = out["steps"]["7_resultat"]["report"]
    data = json.loads(open(paths["json"], encoding="utf-8").read())
    assert data["totals"]["hosts"] == 1 and data["totals"]["events"] == 1 and data["totals"]["incidents"] == 1
    assert data["events"][0]["description"] == "Hôte srv hors ligne"
    assert "incidents.csv" in paths["csv"] and eng.report_due() is False   # prochain rapport dans 24 h
    db.set_setting("auto_report_enabled", "0")
    db.set_setting("auto_report_last", "2000-01-01T00:00:00")
    assert eng.report_due() is False                                    # désactivé


# ── Pipeline : périmètre, validation humaine ────────────────────────────────────────────
def test_pipeline_perimeter_and_human_validation(db):
    db.add_network("Autorisé", "192.168.9.0/24"); db.add_network("Non autorisé", "192.168.8.0/24")
    eng = AutomationEngine(db)
    eng.authorize_network(db.fetchone("SELECT id FROM networks WHERE name='Autorisé'")["id"], "admin")
    calls = []
    out = eng.run_pipeline(discover=lambda n: calls.append(n["name"]) or {"new": 0})
    assert calls == ["Autorisé"]                                        # le réseau non autorisé n'est JAMAIS touché
    assert out["steps"]["1_decouverte"]["ignored_unauthorized"] == 1
    assert [k[0] for k in sorted(out["steps"])] == list("12345678")
    assert out["steps"]["8_validation_humaine"]["executed_automatically"] == 0
    h = db.add_host("x", "10.3.3.3")
    aid = eng.propose_action("block_ip", db.get_host_by_id(h), "test", "plan exact", target="10.3.3.3")
    assert eng.propose_action("block_ip", db.get_host_by_id(h), "test", "plan", target="10.3.3.3") is None   # pas de doublon
    done = eng.decide_action(aid, True, "admin", "ok")
    assert done["status"] == "approved" and eng.decide_action(aid, False, "admin") is None   # décision unique
    assert db.fetchone("SELECT 1 FROM audit_logs WHERE action='action_approved'")


@pytest.mark.parametrize("tz", ["Europe/Paris", "America/New_York", "Asia/Tokyo"])
def test_correlation_is_timezone_independent(db, tz, monkeypatch):
    """Régression : updated_at écrit en UTC puis lu en heure locale faisait vieillir l'incident de l'écart de fuseau."""
    import time as _t
    if not hasattr(_t, "tzset"):
        pytest.skip("tzset indisponible (Windows) : couvert par le test de scénario 4 en fuseau local")
    monkeypatch.setenv("TZ", tz); _t.tzset()
    try:
        hid = db.add_host("h", "10.2.2.2")
        for d in ("a", "b", "c"):
            db.add_event(hid, "h", "", "high", "port_change", d, port=22)
            AutomationEngine(db).run_pipeline()
        assert len(db.fetchall("SELECT * FROM incidents")) == 1
    finally:
        monkeypatch.delenv("TZ"); _t.tzset()
