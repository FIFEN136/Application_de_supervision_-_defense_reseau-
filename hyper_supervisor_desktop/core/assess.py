"""
Procus Secure — évaluation de la sécurité du réseau (v15, bloc 2). LECTURE SEULE : exploite les données déjà collectées
(ports, bannières, inventaire, flux), aucune sonde supplémentaire, aucun test de mot de passe.

Constats : exposition de services à risque · versions à failles connues (extrait local de CVE) · SNMP par défaut ·
équipements non approuvés · segmentation (trafic d'une zone peu fiable vers une zone plus fiable, d'un objet connecté vers
un serveur). Chaque constat porte une recommandation et, si possible, un brouillon de règle de filtrage (bloc 3).

Limites assumées :
  • la base CVE fournie est un EXTRAIT (failles très connues) : elle ne remplace pas un scanner de vulnérabilités ;
    elle peut être complétée par un fichier JSON (import_cves) ;
  • la version vient de la bannière : les distributions Linux corrigent souvent sans changer la version annoncée,
    un constat « faille connue » est donc à VÉRIFIER (le texte le dit) ;
  • un constat marqué « corrigé » signifie seulement « n'est plus détecté ».
"""
from __future__ import annotations

import json
import re
from typing import Optional

from core import classify

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_TO_EVENT = {"critical": "disaster", "high": "high", "medium": "average", "low": "warning"}

# port, protocole → (service, gravité, recommandation, rôles concernés ou None = tous)
RISKY_PORTS = {
    (23, "TCP"): ("Telnet", "critical", "Désactiver Telnet et utiliser SSH : les mots de passe circulent en clair.", None),
    (21, "TCP"): ("FTP", "high", "Remplacer FTP par SFTP/FTPS : identifiants et fichiers circulent en clair.", None),
    (69, "UDP"): ("TFTP", "high", "Désactiver TFTP (aucune authentification) ou le limiter à un poste d'administration.", None),
    (512, "TCP"): ("rexec", "critical", "Désactiver les services r* (rexec/rlogin/rsh), obsolètes et non sûrs.", None),
    (513, "TCP"): ("rlogin", "critical", "Désactiver les services r* (rexec/rlogin/rsh), obsolètes et non sûrs.", None),
    (514, "TCP"): ("rsh", "critical", "Désactiver les services r* (rexec/rlogin/rsh), obsolètes et non sûrs.", None),
    (5900, "TCP"): ("VNC", "high", "Limiter VNC à un poste d'administration ou le passer dans un tunnel chiffré.", None),
    (2375, "TCP"): ("API Docker non protégée", "critical", "Ne jamais exposer l'API Docker sans TLS : elle donne le contrôle de la machine.", None),
    (3389, "TCP"): ("Bureau à distance (RDP)", "medium", "Limiter RDP aux postes d'administration ; activer l'authentification réseau (NLA).", None),
    (445, "TCP"): ("Partage Windows (SMB)", "medium", "Limiter SMB au réseau interne concerné ; désactiver SMBv1.", None),
    (161, "UDP"): ("SNMP", "medium", "Limiter SNMP au serveur de supervision ; préférer SNMPv3.", None),
    (1433, "TCP"): ("Base SQL Server", "medium", "Restreindre l'accès aux serveurs applicatifs.", None),
    (3306, "TCP"): ("Base MySQL/MariaDB", "medium", "Restreindre l'accès aux serveurs applicatifs.", None),
    (5432, "TCP"): ("Base PostgreSQL", "medium", "Restreindre l'accès aux serveurs applicatifs.", None),
    (6379, "TCP"): ("Redis", "high", "Redis n'a pas d'authentification par défaut : restreindre l'accès et activer un mot de passe.", None),
    (27017, "TCP"): ("MongoDB", "high", "Restreindre l'accès et activer l'authentification.", None),
    (9200, "TCP"): ("Elasticsearch", "high", "Restreindre l'accès et activer l'authentification.", None),
    (11211, "TCP"): ("Memcached", "high", "Restreindre l'accès : aucun contrôle d'accès intégré.", None),
    (80, "TCP"): ("Administration web non chiffrée", "medium", "Activer HTTPS pour l'administration et désactiver HTTP.", {"network"}),
    (8080, "TCP"): ("Administration web non chiffrée", "medium", "Activer HTTPS pour l'administration et désactiver HTTP.", {"network"}),
}
HARMLESS_PORTS = {53, 123, 67, 68, 5353, 1900, 137, 138}      # services d'infrastructure : pas de constat de segmentation
LOW_TRUST_ROLES = {"iot", "camera", "guest", "mobile", "printer"}
HIGH_VALUE_ROLES = {"server", "admin", "network"}

# extrait local : (cve, produit, min incl., max incl./excl., gravité, titre, remarque)
CVE_DB = [
    {"cve": "CVE-2011-2523", "product": "vsftpd", "min": "2.3.4", "max": "2.3.4", "sev": "critical",
     "title": "vsftpd 2.3.4 : porte dérobée (accès administrateur à distance)", "note": ""},
    {"cve": "CVE-2024-6387", "product": "openssh", "min": "8.5p1", "max": "9.8p1", "max_excl": True, "sev": "high",
     "title": "OpenSSH « regreSSHion » : exécution de code à distance sans authentification (Linux/glibc)",
     "note": "Les distributions corrigent souvent sans changer la version : vérifier le paquet installé."},
    {"cve": "CVE-2018-15473", "product": "openssh", "min": "0", "max": "7.7", "sev": "medium",
     "title": "OpenSSH ≤ 7.7 : énumération des comptes utilisateurs", "note": "Corrigé en 7.8 ; vérifier les rétroportages de la distribution."},
    {"cve": "CVE-2021-41773", "product": "apache", "min": "2.4.49", "max": "2.4.49", "sev": "critical",
     "title": "Apache httpd 2.4.49 : traversée de chemin pouvant mener à l'exécution de code", "note": ""},
    {"cve": "CVE-2021-42013", "product": "apache", "min": "2.4.49", "max": "2.4.50", "sev": "critical",
     "title": "Apache httpd 2.4.49–2.4.50 : traversée de chemin et exécution de code (correctif incomplet)", "note": ""},
    {"cve": "CVE-2014-0160", "product": "openssl", "min": "1.0.1", "max": "1.0.1f", "sev": "critical",
     "title": "OpenSSL « Heartbleed » : lecture de la mémoire du serveur (clés, mots de passe)", "note": ""},
    {"cve": "CVE-2019-10149", "product": "exim", "min": "4.87", "max": "4.91", "sev": "critical",
     "title": "Exim 4.87–4.91 : exécution de commandes à distance", "note": ""},
    {"cve": "CVE-2015-3306", "product": "proftpd", "min": "1.3.5", "max": "1.3.5", "sev": "high",
     "title": "ProFTPD 1.3.5 : copie de fichiers sans authentification (module mod_copy)",
     "note": "Seulement si le module mod_copy est activé."},
]
BANNER_PATTERNS = [
    ("openssh", re.compile(r"OpenSSH[_ /-]([0-9][0-9a-z.]*)", re.I)),
    ("apache", re.compile(r"Apache(?:/| )([0-9][0-9.]*)", re.I)),
    ("vsftpd", re.compile(r"vsftpd[ /]([0-9][0-9.]*)", re.I)),
    ("proftpd", re.compile(r"ProFTPD[ /]([0-9][0-9a-z.]*)", re.I)),
    ("exim", re.compile(r"Exim[ /]([0-9][0-9.]*)", re.I)),
    ("openssl", re.compile(r"OpenSSL[ /]([0-9][0-9a-z.]*)", re.I)),
]


def vtuple(v: str) -> tuple:
    """'9.6p1' → (9,6,1) ; '1.0.1e' → (1,0,1,5) : permet de comparer des versions de logiciels."""
    out = []
    # une lettre suivie d'un chiffre (« p1 » d'OpenSSH portable) n'est qu'un séparateur ; « 1.0.1e » (OpenSSL) compte
    for num, let in re.findall(r"(\d+)|([a-z])(?!\d)", (v or "").lower()):
        out.append(int(num) if num else ord(let) - 96)
    return tuple(out)


def parse_product(banner: str, version: str = "") -> Optional[tuple[str, str]]:
    for prod, rx in BANNER_PATTERNS:
        m = rx.search(banner or "")
        if m:
            return prod, m.group(1).rstrip(".")
    return None


def _extra_cves(db) -> list:
    try:
        data = json.loads(db.get_setting("cve_extra", "") or "[]")
        return [c for c in data if isinstance(c, dict) and c.get("cve") and c.get("product") and c.get("sev") in SEV_RANK]
    except (ValueError, TypeError):
        return []


def import_cves(db, path: str, who: str = "système") -> int:
    """Complète l'extrait local avec un fichier JSON [{cve, product, min, max, [max_excl], sev, title, note}]."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Le fichier doit contenir une liste de failles.")
    ok = []
    for c in data:
        if not (isinstance(c, dict) and re.fullmatch(r"CVE-\d{4}-\d{4,}", str(c.get("cve", "")))
                and c.get("product") and c.get("sev") in SEV_RANK and c.get("min") is not None and c.get("max") is not None):
            continue
        ok.append({k: c[k] for k in ("cve", "product", "min", "max", "sev", "title", "note", "max_excl") if k in c})
    if not ok:
        raise ValueError("Aucune entrée valide (champs : cve, product, min, max, sev, title).")
    raw = json.dumps(ok, ensure_ascii=False)
    if len(raw) > 2_000_000:
        raise ValueError("Fichier trop volumineux (2 Mo maximum).")
    db.set_setting("cve_extra", raw)
    db.write_audit(who, "cve_import", path, f"{len(ok)} entrée(s)")
    return len(ok)


def match_cves(db, product: str, version: str) -> list[dict]:
    v = vtuple(version)
    out = []
    for c in CVE_DB + _extra_cves(db):
        if c["product"].lower() != product.lower():
            continue
        lo, hi = vtuple(str(c["min"])), vtuple(str(c["max"]))
        if v >= lo and (v < hi if c.get("max_excl") else v <= hi):
            out.append(c)
    return out


def _open_ports(db) -> list[dict]:
    return db.fetchall(
        "SELECT ps.*, h.name AS host_name, h.ip_address FROM port_states ps JOIN hosts h ON h.id = ps.host_id "
        "JOIN (SELECT host_id, port, protocol, MAX(id) mid FROM port_states GROUP BY host_id, port, protocol) m ON m.mid = ps.id "
        "WHERE ps.state = 'open'")


def _F(fkey, host_id, category, severity, title, detail, reco, hint=None):
    return {"fkey": fkey, "host_id": host_id, "category": category, "severity": severity, "title": title,
            "detail": detail, "recommendation": reco, "rule_hint": json.dumps(hint, ensure_ascii=False) if hint else None}


def compute_findings(db) -> list[dict]:
    out = []
    roles = {r["host_id"]: r["role"] for r in db.fetchall("SELECT host_id, role FROM host_roles")}
    hosts = {h["id"]: h for h in db.fetchall("SELECT * FROM hosts")}
    # 1. exposition + versions
    for p in _open_ports(db):
        hid, port, proto = p["host_id"], p["port"], (p.get("protocol") or "TCP").upper()
        role = roles.get(hid, "unknown")
        risky = RISKY_PORTS.get((port, proto))
        if risky and (risky[3] is None or role in risky[3]):
            svc, sev, reco, _ = risky
            out.append(_F(f"exp:{hid}:{port}/{proto}", hid, "exposure", sev, f"{svc} accessible sur {p['host_name']} ({port}/{proto.lower()})",
                          f"Le port {port}/{proto.lower()} de {p['host_name']} ({p['ip_address']}) répond.", reco,
                          {"name": f"Bloquer {svc} vers {p['host_name']}", "src": "any", "dst": f"host:{hid}",
                           "service": f"{proto.lower()}/{port}", "action": "deny"}))
        banner = p.get("service_banner") or ""
        prod = parse_product(banner, p.get("service_version") or "")
        if prod:
            for c in match_cves(db, *prod):
                out.append(_F(f"cve:{c['cve']}:{hid}:{port}", hid, "vulnerability", c["sev"],
                              f"{c['cve']} — {c['title']}",
                              f"{p['host_name']} annonce « {banner[:60]} » sur {port}/{proto.lower()} (version annoncée {prod[1]}). "
                              f"À VÉRIFIER : la bannière peut être trompeuse ou corrigée par la distribution. {c.get('note', '')}".strip(),
                              "Mettre à jour le logiciel vers une version corrigée ; en attendant, limiter l'accès au port.",
                              {"name": f"Limiter {prod[0]} sur {p['host_name']}", "src": "any", "dst": f"host:{hid}",
                               "service": f"{proto.lower()}/{port}", "action": "deny"}))
    # 2. hygiène : SNMP par défaut, équipements non approuvés
    for h in hosts.values():
        if h.get("snmp_enabled") and (h.get("snmp_community") or "").lower() in ("public", "private"):
            comm = h["snmp_community"].lower()
            out.append(_F(f"snmp:{h['id']}", h["id"], "hygiene", "high" if comm == "private" else "medium",
                          f"Communauté SNMP par défaut « {comm} » sur {h['name']}",
                          "La communauté par défaut est connue de tous : elle permet de lire (et parfois modifier) la configuration.",
                          "Changer la communauté SNMP (ou passer en SNMPv3) puis la mettre à jour dans Procus."))
        if h.get("approved") == 0:
            out.append(_F(f"unapproved:{h['id']}", h["id"], "hygiene", "medium", f"Équipement non approuvé : {h['name']} ({h['ip_address']})",
                          "Cet équipement est apparu sur le réseau sans avoir été validé.",
                          "Vérifier son propriétaire puis l'approuver, ou le déconnecter."))
    # 3. segmentation d'après les flux observés
    ip_host = {h["ip_address"]: h["id"] for h in hosts.values()}
    zones = {z["name"]: z for z in db.fetchall("SELECT * FROM net_zones")}
    zz, rr = {}, {}
    for f in db.fetchall("SELECT * FROM flows_agg"):
        if f["dst_port"] in HARMLESS_PORTS or f["proto"] == "icmp":
            continue
        zs, zd = classify.zone_of_ip(db, f["src_ip"]), classify.zone_of_ip(db, f["dst_ip"])
        if zs and zd and zs["name"] != zd["name"] and zd["trust"] - zs["trust"] >= 30:
            e = zz.setdefault((zs["name"], zd["name"]), {"flows": 0, "svc": {}})
            e["flows"] += f["flows"]
            k = f"{f['proto']}/{f['dst_port']}"
            e["svc"][k] = e["svc"].get(k, 0) + f["flows"]
        hs, hd = ip_host.get(f["src_ip"]), ip_host.get(f["dst_ip"])
        rs, rd = roles.get(hs), roles.get(hd)
        if rs in LOW_TRUST_ROLES and rd in HIGH_VALUE_ROLES:
            e = rr.setdefault((rs, rd), {"flows": 0, "svc": {}})
            e["flows"] += f["flows"]
            k = f"{f['proto']}/{f['dst_port']}"
            e["svc"][k] = e["svc"].get(k, 0) + f["flows"]

    def top(svc):
        return ", ".join(f"{k} ({v})" for k, v in sorted(svc.items(), key=lambda kv: -kv[1])[:5])
    for (a, b), e in zz.items():
        out.append(_F(f"seg:zone:{a}>{b}", None, "segmentation", "medium",
                      f"Trafic de la zone « {a} » (confiance {zones[a]['trust']}) vers « {b} » (confiance {zones[b]['trust']})",
                      f"{e['flows']} flux observés. Services : {top(e['svc'])}.",
                      "Autoriser seulement les services nécessaires ; la simulation montre l'effet avant toute décision.",
                      {"name": f"Isoler {a} de {b}", "src": f"zone:{a}", "dst": f"zone:{b}", "service": "any", "action": "deny"}))
    for (a, b), e in rr.items():
        out.append(_F(f"seg:role:{a}>{b}", None, "segmentation", "high" if a in ("iot", "camera", "guest") else "medium",
                      f"Des équipements « {classify.ROLES[a]} » communiquent avec des « {classify.ROLES[b]} »",
                      f"{e['flows']} flux observés. Services : {top(e['svc'])}.",
                      "Un objet connecté ou un invité n'a normalement pas à joindre vos serveurs : n'autoriser que le strict nécessaire.",
                      {"name": f"{classify.ROLES[a]} → {classify.ROLES[b]}", "src": f"role:{a}", "dst": f"role:{b}",
                       "service": "any", "action": "deny"}))
    return out


def run_assessment(db, sink=None, max_events: int = 10) -> dict:
    """Recalcule les constats (idempotent) : nouveaux, toujours présents, « corrigés » (plus détectés)."""
    classify.sync_zones(db)
    classify.classify_hosts(db)
    current = {f["fkey"]: f for f in compute_findings(db)}
    new_ids = []
    for k, f in current.items():
        old = db.fetchone("SELECT id, status FROM assess_findings WHERE fkey = ?", (k,))
        if not old:
            fid = db.execute(
                "INSERT INTO assess_findings (fkey, host_id, category, severity, title, detail, recommendation, rule_hint) VALUES (?,?,?,?,?,?,?,?)",
                (k, f["host_id"], f["category"], f["severity"], f["title"], f["detail"], f["recommendation"], f["rule_hint"])).lastrowid
            new_ids.append(fid)
        else:
            status = "open" if old["status"] == "fixed" else old["status"]
            if old["status"] == "fixed":
                new_ids.append(old["id"])
            db.execute("UPDATE assess_findings SET severity=?, title=?, detail=?, recommendation=?, rule_hint=?, status=?, last_seen=datetime('now') WHERE id=?",
                       (f["severity"], f["title"], f["detail"], f["recommendation"], f["rule_hint"], status, old["id"]))
    fixed = 0
    for r in db.fetchall("SELECT id, fkey FROM assess_findings WHERE status = 'open'"):
        if r["fkey"] not in current:
            db.execute("UPDATE assess_findings SET status='fixed', last_seen=datetime('now') WHERE id=?", (r["id"],))
            fixed += 1
    sent = 0
    if sink:
        for fid in new_ids:
            f = db.fetchone("SELECT * FROM assess_findings WHERE id = ?", (fid,))
            if f and f["severity"] in ("critical", "high") and sent < max_events:
                host = db.get_host_by_id(f["host_id"]) if f["host_id"] else None
                sink.emit(SEV_TO_EVENT[f["severity"]], "vulnerability_found", f["title"], host=host,
                          tags=[f"assess:{f['category']}"])
                sent += 1
    counts = {s: db.fetchone("SELECT COUNT(*) n FROM assess_findings WHERE status='open' AND severity=?", (s,))["n"] for s in SEV_RANK}
    return {"new": len(new_ids), "fixed": fixed, "open": counts, "events": sent}


def list_findings(db, status: Optional[str] = None) -> list[dict]:
    q, p = "SELECT f.*, h.name AS host_name FROM assess_findings f LEFT JOIN hosts h ON h.id = f.host_id", ()
    if status in ("open", "accepted", "fixed"):
        q, p = q + " WHERE f.status = ?", (status,)
    rows = db.fetchall(q + " ORDER BY f.id DESC", p)
    return sorted(rows, key=lambda r: (-SEV_RANK.get(r["severity"], 0), r["id"]))


def set_status(db, finding_id: int, status: str, note: str = "", who: str = "système"):
    if status not in ("open", "accepted"):
        raise ValueError("Statut modifiable : open ou accepted (« corrigé » est automatique).")
    f = db.fetchone("SELECT id, title FROM assess_findings WHERE id = ?", (finding_id,))
    if not f:
        raise ValueError("Constat introuvable.")
    if status == "accepted" and not note.strip():
        raise ValueError("Un risque accepté doit être justifié (note obligatoire).")
    db.execute("UPDATE assess_findings SET status = ?, note = ? WHERE id = ?", (status, note.strip(), finding_id))
    db.write_audit(who, f"finding_{status}", f"finding:{finding_id}", f"{f['title']} — {note.strip()}")
