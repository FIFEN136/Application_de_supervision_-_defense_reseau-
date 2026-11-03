"""
Procus Secure — banc d'essai reproductible (5 scénarios).  Usage :  python -m tools.benchmark [--out docs/BENCHMARK.md]

Mesure UNIQUEMENT Procus Secure, sur matériel réel de la machine (sockets loopback, agent SNMP de test, SQLite).
Aucun chiffre n'est inventé pour d'autres outils : la section « comparaison » est un protocole à rejouer.
"""
import argparse, json, os, socket, sys, tempfile, time
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psutil
from database.db_manager import DatabaseManager
from core import local_network as lnet
from core.automation import AutomationEngine
from core.monitor import MonitorWorker
from core.network_setup import NetworkSetupWorker
from core.scanner import ScannerWorker
from tests.snmp_agent import SnmpAgent

PROC = psutil.Process()


def free(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def listen(port):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(8); return s


class Meter:
    def __enter__(self):
        self.c0, self.t0, self.m0 = sum(PROC.cpu_times()[:2]), time.perf_counter(), PROC.memory_info().rss
        return self

    def __exit__(self, *a):
        self.wall = time.perf_counter() - self.t0
        self.cpu_s = sum(PROC.cpu_times()[:2]) - self.c0
        self.rss_mb = PROC.memory_info().rss / 1e6
        self.d_rss_mb = (PROC.memory_info().rss - self.m0) / 1e6


def new_db():
    d = DatabaseManager(os.path.join(tempfile.mkdtemp(), "bench.db")); d.initialize(); return d


def evidence_score(sheet, required):
    ok = sum(1 for k in required if k(sheet))
    return ok, len(required)


COMMON = [lambda s: s["host"] and s["host"]["ip_address"], lambda s: s["events"],
          lambda s: all(e["occurred_at"] for e in s["events"]), lambda s: s["incident"]["priority_label"],
          lambda s: s["evidence_ids"]]


def s1():
    db = new_db(); eng = AutomationEngine(db)
    found = [{"ip": "192.168.50.1", "name": "box", "mac": "aa:aa:aa:00:00:01", "vendor": "X", "device_type": "router", "open_ports": []}]
    lnet.discover_network = lambda cidr, gw=None, **k: found
    t0 = time.perf_counter()
    nid = db.add_network("Bureau", "192.168.50.0/24", "192.168.50.1", authorized_by="bench")
    w = NetworkSetupWorker(db); alerts = []; w.new_device.connect(alerts.append)
    w.discover_network(nid)
    config_s = time.perf_counter() - t0
    idle = db.fetchone("SELECT COUNT(*) n FROM events")["n"]
    found.append({"ip": "192.168.50.77", "name": "", "mac": "de:ad:be:ef:00:77", "vendor": "", "device_type": "unknown", "open_ports": []})
    with Meter() as m:
        t1 = time.perf_counter(); w.discover_network(nid); detect = time.perf_counter() - t1
        eng.run_pipeline()
    inc = db.fetchone("SELECT id FROM incidents"); sheet = eng.investigation_sheet(inc["id"])
    ok, n = evidence_score(sheet, COMMON + [lambda s: s["host"]["mac_address"], lambda s: s["actions"]])
    return dict(name="1. Équipement inconnu", config_s=config_s, detect_s=detect, false_pos=idle, cpu_s=m.cpu_s,
                rss_mb=m.rss_mb, evidence=f"{ok}/{n}", understand="1 fiche : IP + MAC + priorité + action proposée",
                alerts=len(alerts))


def s2():
    db = new_db(); eng = AutomationEngine(db); a, b = free(), free(); keep = listen(a)
    hid = db.add_host("srv", "127.0.0.1"); sc = ScannerWorker(db)
    t0 = time.perf_counter(); sc.scan_host(hid, "127.0.0.1", "srv", [a, b], timeout=0.5); config_s = time.perf_counter() - t0
    for _ in range(3):
        sc.scan_host(hid, "127.0.0.1", "srv", [a, b], timeout=0.5)
    fp = db.fetchone("SELECT COUNT(*) n FROM events")["n"]
    rogue = listen(b)
    with Meter() as m:
        t1 = time.perf_counter(); sc.scan_host(hid, "127.0.0.1", "srv", [a, b], timeout=0.5); detect = time.perf_counter() - t1
        eng.run_pipeline()
    rogue.close(); keep.close()
    sheet = eng.investigation_sheet(db.fetchone("SELECT id FROM incidents")["id"])
    ok, n = evidence_score(sheet, COMMON + [lambda s: s["ports"], lambda s: s["events"][0]["state_before"] == "closed", lambda s: s["actions"]])
    return dict(name="2. Port fermé → ouvert", config_s=config_s, detect_s=detect, false_pos=fp, cpu_s=m.cpu_s, rss_mb=m.rss_mb,
                evidence=f"{ok}/{n}", understand="1 fiche : « closed → open » + commande de blocage prête")


def s3():
    cfg = {"n": "eth0", "r": "10.0.0.1"}; port = free(socket.SOCK_DGRAM)
    ag = SnmpAgent(port, community="s3cret", values={(1,3,6,1,2,1,2,2,1,2,1): lambda: cfg["n"], (1,3,6,1,2,1,4,21,1,7,1): lambda: cfg["r"]}); ag.start()
    try:
        db = new_db(); hid = db.add_host("rtr", "127.0.0.1", device_type="router", snmp_community="s3cret")
        db.execute("UPDATE hosts SET snmp_port=?, snmp_enabled=1 WHERE id=?", (port, hid))
        eng = AutomationEngine(db, snmp=MonitorWorker(db_manager=db))
        t0 = time.perf_counter(); eng.collect_configs(); config_s = time.perf_counter() - t0
        eng.collect_configs(); fp = db.fetchone("SELECT COUNT(*) n FROM events")["n"]
        cfg["n"], cfg["r"] = "eth0-X", "203.0.113.9"
        with Meter() as m:
            t1 = time.perf_counter(); eng.collect_configs(); detect = time.perf_counter() - t1; eng.run_pipeline()
    finally:
        ag.stop()
    sheet = eng.investigation_sheet(db.fetchone("SELECT id FROM incidents")["id"])
    ok, n = evidence_score(sheet, COMMON + [lambda s: s["config_diff"], lambda s: db.fetchone("SELECT COUNT(*) n FROM config_snapshots")["n"] == 2])
    return dict(name="3. Config routeur modifiée", config_s=config_s, detect_s=detect, false_pos=fp, cpu_s=m.cpu_s, rss_mb=m.rss_mb,
                evidence=f"{ok}/{n}", understand="1 fiche : diff avant/après champ par champ")


def s4():
    db = new_db(); eng = AutomationEngine(db); h = db.add_host("srv-db", "10.1.1.5")
    for sev, t, d in [("disaster", "port_change", "3306 closed→open"), ("high", "port_change", "3389 closed→open"),
                      ("high", "host_down", "hors ligne"), ("warning", "threshold", "CPU 93 %")]:
        db.add_event(h, "srv-db", "", sev, t, d)
    before = db.fetchall("SELECT * FROM events")
    with Meter() as m:
        t1 = time.perf_counter(); eng.run_pipeline(); detect = time.perf_counter() - t1
    sheet = eng.investigation_sheet(db.fetchone("SELECT id FROM incidents")["id"])
    lost = 0 if db.fetchall("SELECT * FROM events") == before and len(sheet["evidence_ids"]) == 4 else 1
    return dict(name="4. Alertes groupées", config_s=0.0, detect_s=detect, false_pos=0, cpu_s=m.cpu_s, rss_mb=m.rss_mb,
                evidence=f"{len(sheet['evidence_ids'])}/4 preuves conservées, perte={lost}",
                understand=f"4 alertes → {db.fetchone('SELECT COUNT(*) n FROM incidents')['n']} incident")


def s5():
    db = new_db(); eng = AutomationEngine(db); h = db.add_host("srv", "10.2.2.2")
    db.add_event(h, "srv", "", "high", "host_down", "hors ligne"); db.set_setting("report_dir", tempfile.mkdtemp())
    with Meter() as m:
        t1 = time.perf_counter(); out = eng.run_pipeline(); detect = time.perf_counter() - t1
    p = out["steps"]["7_resultat"]["report"]; data = json.load(open(p["json"], encoding="utf-8"))
    match = data["totals"]["events"] == db.fetchone("SELECT COUNT(*) n FROM events")["n"] and data["totals"]["hosts"] == 1
    return dict(name="5. Rapport périodique", config_s=0.0, detect_s=detect, false_pos=0, cpu_s=m.cpu_s, rss_mb=m.rss_mb,
                evidence=f"fichiers={sorted(p)}, chiffres = base : {match}", understand="rapport JSON/CSV/PDF issu de la base")


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="docs/BENCHMARK.md"); a = ap.parse_args()
    rows = [f() for f in (s1, s2, s3, s4, s5)]
    md = ["# Banc d'essai Procus Secure (mesures réelles)\n",
          f"Machine : {psutil.cpu_count()} cœurs, {psutil.virtual_memory().total/1e9:.1f} Go RAM · {time.strftime('%Y-%m-%d %H:%M')}\n",
          "| Scénario | Config initiale (s) | Délai de détection (s) | Faux positifs (cycles sans changement) | CPU (s) | RAM process (Mo) | Qualité de preuve | Compréhension |",
          "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        md.append(f"| {r['name']} | {r['config_s']:.2f} | {r['detect_s']:.2f} | {r['false_pos']} | {r['cpu_s']:.2f} | {r['rss_mb']:.0f} | {r['evidence']} | {r['understand']} |")
    md += ["", "Délai de détection = temps entre le changement et la présence de l'événement/incident dans la base (cycle déclenché à la main ; "
           "scénario 1 : la découverte réseau est simulée (le balayage réel d'un /24 dure plusieurs secondes) ; "
           "en production il s'ajoute l'intervalle de planification : scan 300 s, supervision 60 s, pipeline 120 s par défaut).", "",
           "## Comparaison avec d'autres outils — PROTOCOLE (non mesuré ici)", "",
           "Nmap, Zabbix, etc. n'ont pas pu être exécutés dans l'environnement de test : aucun chiffre n'est donné pour eux. Pour comparer, rejouez les 5 scénarios ",
           "avec chaque outil et notez les mêmes 6 mesures :", "",
           "| Mesure | Comment la relever |", "|---|---|",
           "| Temps de configuration initial | chronomètre : de l'installation à la 1re surveillance active |",
           "| Délai de détection | horodatage du changement vs apparition de l'alerte |",
           "| Faux positifs | nombre d'alertes sur 24 h sans aucun changement réel |",
           "| CPU / RAM | Gestionnaire des tâches ou `psutil` sur le processus de l'outil |",
           "| Qualité de preuve | cases cochées : IP, MAC, horodatage, avant/après, lien vers événements d'origine |",
           "| Temps pour comprendre | chronomètre : de la notification à « je sais quoi faire » |", "",
           "Éléments qualitatifs (conception, pas mesures) : un scanner comme Nmap détecte un port ouvert mais ne garde ni historique ni corrélation ; "
           "une plateforme comme Zabbix est très complète mais demande davantage de configuration (agents, templates, déclencheurs). "
           "HSR vise une mise en route rapide (saisir un réseau) avec preuves et priorités pré-assemblées ; il couvre moins de protocoles."]
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    open(a.out, "w", encoding="utf-8").write("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
