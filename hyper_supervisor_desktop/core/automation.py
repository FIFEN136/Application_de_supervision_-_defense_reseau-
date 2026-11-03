"""
Procus Secure — Pipeline d'automatisation (8 étapes)
Procus Tech

  1. Découverte      périmètre explicitement autorisé uniquement (networks.authorized_at)
  2. Référentiel     équipements observés comparés à la liste attendue (approuvés, baseline de ports)
  3. Collecte        scans / SNMP déjà planifiés + empreinte de configuration des routeurs
  4. Détection       écarts significatifs (nouveaux événements depuis le dernier passage)
  5. Corrélation     regroupement des événements d'un même équipement en UN incident (preuves conservées)
  6. Priorisation    score 0-100 : règles configurables + sévérité + criticité de l'équipement
  7. Résultat        fiche d'investigation, notification, rapport périodique
  8. Validation      actions potentiellement perturbatrices PROPOSÉES, jamais exécutées sans accord humain

Principe de sécurité : HSR n'exécute AUCUNE action perturbatrice. Une action approuvée produit seulement
le plan/la commande exacte à appliquer, tracée dans le journal d'audit (HMAC).
"""
from __future__ import annotations

import csv
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from loguru import logger

SEV_ORDER = ["information", "resolved", "warning", "average", "high", "disaster"]
SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

DEFAULT_RULES = {
    "sev": {"disaster": 60, "high": 45, "average": 30, "warning": 15, "information": 5, "resolved": 0},
    "crit_weight": 6,                       # × criticité de l'équipement (1..5)
    "bonus": {"config_change": 10, "new_device": 8, "port_change": 6, "host_down": 4,
              "honeypot_hit": 12, "arp_spoof": 14, "rogue_dhcp": 14, "fim_change": 10, "sigma_match": 8,
              "ssh_hostkey_changed": 14, "vulnerability_found": 6},
    "count_bonus": 2, "count_cap": 5,       # +2 par événement supplémentaire (max 5)
    "p1": 80, "p2": 60, "p3": 40,           # seuils des libellés de priorité
    "min_severity": "warning",              # en dessous : rattaché seulement à un incident déjà ouvert
    "correlation_window_min": 60,
}
ALWAYS_OPEN = {"config_change", "new_device", "honeypot_hit", "arp_spoof", "rogue_dhcp", "fim_change",
               "sigma_match", "ssh_hostkey_changed"}      # ouvrent un incident quelle que soit la sévérité

PRIORITY_LABELS = {1: "P1 · Critique", 2: "P2 · Élevée", 3: "P3 · Moyenne", 4: "P4 · Faible"}

OID_SYSDESCR, OID_SYSNAME = "1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"
OID_SYSCONTACT, OID_SYSLOCATION = "1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.6.0"
OID_IFDESCR, OID_IPADDR, OID_ROUTE_NH = "1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.4.20.1.1", "1.3.6.1.2.1.4.21.1.7"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


class AutomationEngine:
    def __init__(self, db, security=None, snmp=None, notify: Optional[Callable[[dict], None]] = None):
        """snmp : objet exposant _snmp_get / _snmp_walk (MonitorWorker). notify(dict) : callback de notification."""
        self.db = db
        self.security = security
        self.snmp = snmp
        self.notify = notify

    # ───────────────────────── réglages ─────────────────────────

    def rules(self) -> dict:
        rules = json.loads(json.dumps(DEFAULT_RULES))
        try:
            custom = json.loads(self.db.get_setting("auto_rules", "") or "{}")
            for k, v in custom.items():
                if isinstance(v, dict) and isinstance(rules.get(k), dict):
                    rules[k].update(v)
                else:
                    rules[k] = v
        except (ValueError, TypeError):
            logger.warning("[Auto] auto_rules invalide : règles par défaut utilisées")
        return rules

    def save_rules(self, rules: dict):
        self.db.set_setting("auto_rules", json.dumps(rules, ensure_ascii=False))

    def _user(self) -> str:
        u = self.security.get_current_user() if self.security else None
        return (u or {}).get("login") or "système"

    def _audit(self, action: str, target: str = "", detail: str = ""):
        try:
            self.db.write_audit(self._user(), action, target, detail)
        except Exception as e:                       # l'audit ne doit jamais bloquer le pipeline
            logger.warning(f"[Auto] audit : {e}")

    # ───────────────────────── priorisation ─────────────────────────

    def compute_priority(self, severity: str, criticality: int, event_types=(), count: int = 1) -> tuple[int, str]:
        r = self.rules()
        score = r["sev"].get(severity, 0) + int(criticality or 3) * r["crit_weight"]
        for t in set(event_types):
            score += r["bonus"].get(t, 0)
        score += min(max(count - 1, 0), r["count_cap"]) * r["count_bonus"]
        score = max(0, min(100, int(score)))
        level = 1 if score >= r["p1"] else 2 if score >= r["p2"] else 3 if score >= r["p3"] else 4
        return score, PRIORITY_LABELS[level]

    # ───────────────────────── étape 1-2 : découverte & référentiel ─────────────────────────

    def authorized_networks(self) -> list:
        return self.db.fetchall("SELECT * FROM networks WHERE authorized_at IS NOT NULL AND auto_monitor = 1")

    def authorize_network(self, network_id: int, who: str = None):
        who = who or self._user()
        self.db.execute("UPDATE networks SET authorized_by = ?, authorized_at = ? WHERE id = ?",
                        (who, _now(), network_id))
        self._audit("network_authorized", f"network:{network_id}", f"Périmètre autorisé par {who}")

    def reference_status(self) -> dict:
        unapproved = self.db.fetchall(
            "SELECT id, name, ip_address, mac_address, vendor FROM hosts WHERE COALESCE(approved,1) = 0")
        no_baseline = self.db.fetchall(
            "SELECT h.id, h.name FROM hosts h WHERE NOT EXISTS (SELECT 1 FROM baselines b WHERE b.host_id = h.id) "
            "AND h.ip_address IS NOT NULL")
        return {"total": (self.db.fetchone("SELECT COUNT(*) AS n FROM hosts") or {}).get("n", 0),
                "unapproved": unapproved, "without_baseline": no_baseline}

    def approve_device(self, host_id: int, who: str = None):
        """Ajoute l'équipement au référentiel (l'inconnu devient « attendu »)."""
        h = self.db.get_host_by_id(host_id)
        if not h:
            return False
        self.db.execute("UPDATE hosts SET approved = 1 WHERE id = ?", (host_id,))
        self.db.write_audit(who or self._user(), "device_approved", f"host:{host_id}",
                            f"{h['name']} ({h['ip_address']}) ajouté au référentiel")
        return True

    # ───────────────────────── étape 3 : configuration des routeurs ─────────────────────────

    def _collect_config(self, host: dict) -> Optional[dict]:
        if not self.snmp:
            return None
        ip = host["ip_address"]
        comm = host.get("snmp_community") or "public"
        port = int(host.get("snmp_port") or 161)
        ver = str(host.get("snmp_version") or "2c")
        get = lambda oid: self.snmp._snmp_get(ip, oid, comm, port=port, timeout=1, retries=0, version=ver)
        walk = lambda oid: self.snmp._snmp_walk(ip, oid, comm, port=port, timeout=1, version=ver)
        name = get(OID_SYSNAME)
        descr = get(OID_SYSDESCR)
        if name is None and descr is None:
            return None                                # agent muet : rien à comparer (pas de faux changement)
        cfg = {"sysName": str(name or ""), "sysDescr": str(descr or ""),
               "sysContact": str(get(OID_SYSCONTACT) or ""), "sysLocation": str(get(OID_SYSLOCATION) or "")}
        for key, oid in (("interfaces", OID_IFDESCR), ("addresses", OID_IPADDR), ("routes", OID_ROUTE_NH)):
            w = walk(oid)
            cfg[key] = sorted(str(v) for v in (w or {}).values())
        return cfg

    @staticmethod
    def diff_config(old: dict, new: dict) -> list[str]:
        out = []
        for k in sorted(set(old) | set(new)):
            a, b = old.get(k), new.get(k)
            if a == b:
                continue
            if isinstance(a, list) or isinstance(b, list):
                a, b = a or [], b or []
                add, rem = [x for x in b if x not in a], [x for x in a if x not in b]
                if add:
                    out.append(f"{k} : + {', '.join(add)}")
                if rem:
                    out.append(f"{k} : − {', '.join(rem)}")
            else:
                out.append(f"{k} : « {a} » → « {b} »")
        return out

    def check_config(self, host: dict) -> Optional[dict]:
        """Instantané SNMP + comparaison au précédent. Le 1er instantané est la référence (aucune alerte)."""
        cfg = self._collect_config(host)
        if cfg is None:
            return None
        content = json.dumps(cfg, sort_keys=True, ensure_ascii=False)
        fp = hashlib.sha256(content.encode()).hexdigest()[:16]
        last = self.db.fetchone("SELECT * FROM config_snapshots WHERE host_id = ? ORDER BY id DESC LIMIT 1",
                                (host["id"],))
        if last and last["fingerprint"] == fp:
            return {"changed": False, "fingerprint": fp}
        snap = self.db.execute("INSERT INTO config_snapshots (host_id, fingerprint, content) VALUES (?, ?, ?)",
                               (host["id"], fp, content)).lastrowid
        if not last:
            return {"changed": False, "fingerprint": fp, "baseline": True, "snapshot_id": snap}
        diff = self.diff_config(json.loads(last["content"]), cfg)
        desc = (f"Configuration modifiée sur {host['name']} ({host['ip_address']}) : " + " ; ".join(diff))[:900]
        ev = self.db.add_event(host_id=host["id"], host_name=host["name"], group_name="", severity="high",
                               event_type="config_change", description=desc,
                               state_before=last["fingerprint"], state_after=fp)
        return {"changed": True, "fingerprint": fp, "diff": diff, "event_id": ev, "snapshot_id": snap,
                "previous_snapshot_id": last["id"]}

    def collect_configs(self) -> list:
        res = []
        for h in self.db.get_all_hosts():
            if not h.get("snmp_enabled", 1) or not h.get("ip_address"):
                continue
            if h.get("device_type") not in ("router", "switch", "firewall", "gateway", "access_point", "unknown", None, ""):
                continue
            try:
                r = self.check_config(h)
                if r:
                    res.append({"host": h["name"], **r})
            except Exception as e:
                logger.warning(f"[Auto] config {h.get('name')} : {e}")
        return res

    # ───────────────────────── étapes 4-6 : détection, corrélation, priorisation ─────────────────────────

    def new_events(self) -> list:
        last = int(self.db.get_setting("auto_last_event_id", "0") or 0)
        return self.db.fetchall("SELECT * FROM events WHERE id > ? AND host_id IS NOT NULL ORDER BY id", (last,))

    def correlate(self) -> dict:
        """Regroupe les nouveaux événements par équipement. Aucun événement n'est supprimé ni fusionné :
        l'incident ne fait que POINTER vers les événements d'origine (preuves intactes)."""
        r = self.rules()
        window = int(r["correlation_window_min"]) * 60
        min_rank = SEV_RANK.get(r["min_severity"], 2)
        events = self.new_events()
        touched: dict[int, dict] = {}
        for ev in events:
            hid = ev["host_id"]
            inc = self.db.fetchone(
                "SELECT * FROM incidents WHERE host_id = ? AND status != 'closed' ORDER BY id DESC LIMIT 1", (hid,))
            if inc:
                age = time.time() - time.mktime(time.strptime(inc["updated_at"][:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))
                if age > window:
                    inc = None
            significant = SEV_RANK.get(ev["severity"], 0) >= min_rank or ev["event_type"] in ALWAYS_OPEN
            if inc is None and not significant:
                continue
            if inc is None:
                iid = self.db.execute(
                    "INSERT INTO incidents (host_id, host_name, title, severity, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (hid, ev["host_name"], ev["description"][:120], ev["severity"], _now())).lastrowid     # heure locale, comme la lecture
                created = True
            else:
                iid, created = inc["id"], False
            self.db.execute("INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                            (iid, ev["id"]))
            touched.setdefault(iid, {"created": created})["created"] |= created
        if events:
            self.db.set_setting("auto_last_event_id", str(events[-1]["id"]))
        opened, updated = [], []
        for iid, meta in touched.items():
            info = self._refresh_incident(iid)
            (opened if meta["created"] else updated).append(info)
        return {"events_seen": len(events), "opened": opened, "updated": updated}

    def _refresh_incident(self, iid: int) -> dict:
        evs = self.db.fetchall(
            "SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id "
            "WHERE ie.incident_id = ? ORDER BY e.id", (iid,))
        inc = self.db.fetchone("SELECT * FROM incidents WHERE id = ?", (iid,))
        host = self.db.get_host_by_id(inc["host_id"]) or {}
        sev = max((e["severity"] for e in evs), key=lambda s: SEV_RANK.get(s, 0), default=inc["severity"])
        types = [e["event_type"] for e in evs]
        crit = host.get("criticality") or 3
        if host and host.get("approved") == 0:
            crit = max(crit, 4)                           # équipement inconnu : traité comme sensible
        score, label = self.compute_priority(sev, crit, types, len(evs))
        by_type: dict[str, int] = {}
        for t in types:
            by_type[t] = by_type.get(t, 0) + 1
        title = evs[0]["description"][:100] if len(evs) == 1 else \
            f"{inc['host_name']} : {len(evs)} événements corrélés ({', '.join(f'{n}× {t}' for t, n in by_type.items())})"
        summary = "\n".join(f"[{e['occurred_at']}] {e['severity'].upper()} · {e['description']}" for e in evs)
        self.db.execute(
            "UPDATE incidents SET severity=?, priority=?, priority_label=?, title=?, summary=?, event_count=?, "
            "updated_at=? WHERE id=?", (sev, score, label, title, summary, len(evs), _now(), iid))
        info = {"id": iid, "host": inc["host_name"], "host_id": inc["host_id"], "severity": sev,
                "priority": score, "priority_label": label, "title": title, "event_count": len(evs)}
        if self.notify and score >= self.rules()["p2"] and SEV_RANK.get(sev, 0) >= SEV_RANK["average"]:
            try:
                self.notify({**info, "kind": "incident"})
            except Exception as e:
                logger.warning(f"[Auto] notification : {e}")
        return info

    # ───────────────────────── étape 8 : actions soumises à validation ─────────────────────────

    def propose_action(self, action_type: str, host: dict, reason: str, plan: str,
                       incident_id: int = None, target: str = "") -> Optional[int]:
        dup = self.db.fetchone(
            "SELECT id FROM pending_actions WHERE host_id = ? AND action_type = ? AND COALESCE(target,'') = ? "
            "AND status = 'pending'", (host["id"], action_type, target))
        if dup:
            return None
        aid = self.db.execute(
            "INSERT INTO pending_actions (incident_id, host_id, host_name, action_type, target, reason, plan) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (incident_id, host["id"], host["name"], action_type, target, reason, plan)).lastrowid
        self._audit("action_proposed", f"host:{host['id']}", f"{action_type} — {reason}")
        return aid

    def propose_for_incidents(self, incident_ids) -> list:
        made = []
        for iid in incident_ids:
            inc = self.db.fetchone("SELECT * FROM incidents WHERE id = ?", (iid,))
            if not inc or not inc["host_id"]:
                continue
            host = self.db.get_host_by_id(inc["host_id"])
            if not host:
                continue
            evs = self.db.fetchall(
                "SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id WHERE ie.incident_id = ?",
                (iid,))
            ip = host["ip_address"]
            for e in evs:
                if e["event_type"] == "new_device" and host.get("approved") == 0:
                    a = self.propose_action(
                        "isolate_host", host,
                        f"Équipement inconnu {ip} ({host.get('mac_address') or 'MAC ?'}) apparu sur le réseau",
                        f"1) Vérifier l'équipement physiquement ou auprès de son propriétaire.\n"
                        f"2) Si illégitime : placer son port/borne en quarantaine (VLAN isolé) ou couper l'accès Wi-Fi "
                        f"pour la MAC {host.get('mac_address') or '(à relever)'}.\n"
                        f"3) Sinon : « Approuver » l'équipement dans HSR pour l'ajouter au référentiel.",
                        iid, target=ip)
                    if a:
                        made.append(a)
                elif e["event_type"] == "port_change" and e["state_after"] == "open" and e["severity"] in ("disaster", "high"):
                    port = e.get("port")
                    a = self.propose_action(
                        "block_ip", host,
                        f"Port {port}/TCP ouvert sur {host['name']} alors qu'il était {e['state_before']} dans la référence",
                        f"Windows : netsh advfirewall firewall add rule name=\"HSR-bloque-{port}\" dir=in "
                        f"action=block protocol=TCP localport={port}\n"
                        f"Linux   : iptables -A INPUT -p tcp --dport {port} -j DROP\n"
                        f"Ou arrêter le service qui écoute sur {ip}:{port}, puis relancer un scan HSR.",
                        iid, target=f"{ip}:{port}")
                    if a:
                        made.append(a)
                elif e["event_type"] in ("honeypot_hit", "arp_spoof", "rogue_dhcp", "fim_change", "sigma_match",
                                         "ssh_hostkey_changed") and e["severity"] in ("disaster", "high"):
                    a = self._propose_defense(e, host, iid)
                    if a:
                        made.append(a)
                elif e["event_type"] == "config_change":
                    snap = self.db.fetchone(
                        "SELECT id FROM config_snapshots WHERE host_id = ? ORDER BY id DESC LIMIT 1 OFFSET 1",
                        (host["id"],))
                    a = self.propose_action(
                        "modify_config", host,
                        f"Configuration de {host['name']} modifiée : {e['description'][:200]}",
                        f"Comparer avec l'instantané précédent #{snap['id'] if snap else '?'} (Incidents → fiche) et, "
                        f"si le changement n'est pas autorisé, restaurer la configuration sauvegardée du routeur.",
                        iid, target=ip)
                    if a:
                        made.append(a)
        return made

    def _propose_defense(self, e: dict, host: dict, iid: int):
        """Actions proposées pour les détections de la défense active (v13/14). Toujours soumises à validation humaine."""
        import re
        t, ip = e["event_type"], host["ip_address"]
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", e.get("description") or "")
        if t == "honeypot_hit" and m:
            src = m.group(1)
            return self.propose_action(
                "block_ip", host, f"Connexion(s) suspecte(s) sur un honeypot depuis {src}",
                f"Bloquer {src} au pare-feu (exécutable depuis Incidents si l'exécution réelle est activée) :\n"
                f"Windows : netsh advfirewall firewall add rule name=\"Procus-bloque-{src}\" dir=in action=block remoteip={src}\n"
                f"Linux   : iptables -I INPUT -s {src} -j DROP\nPuis identifier la machine {src} (un poste infecté ?).",
                iid, target=src)
        plans = {
            "arp_spoof": ("Usurpation ARP probable : le trafic peut être intercepté.",
                          "1) Identifier la machine qui possède la nouvelle MAC (table du commutateur).\n"
                          "2) Isoler son port. 3) Activer « Dynamic ARP Inspection » / port-security si disponible."),
            "rogue_dhcp": ("Serveur DHCP non autorisé détecté.",
                           "1) Repérer le port du commutateur d'où répond le serveur.\n"
                           "2) Le couper ; activer « DHCP snooping » sur le commutateur."),
            "fim_change": ("Fichier sensible modifié.", "1) Comparer avec la sauvegarde. 2) Si non autorisé : restaurer et investiguer l'accès."),
            "sigma_match": ("Règle de détection de journaux déclenchée.", "1) Lire les journaux concernés. 2) Réinitialiser les accès si compromission."),
            "ssh_hostkey_changed": ("Clé SSH de l'équipement changée.",
                                    "1) Vérifier que l'équipement n'a pas été remplacé. 2) Sinon : possible interception, isoler le lien."),
        }
        if t not in plans:
            return None
        reason, plan = plans[t]
        return self.propose_action("isolate_host", host, f"{reason} ({host['name']})", plan, iid, target=ip)

    def decide_action(self, action_id: int, approve: bool, who: str = None, note: str = "") -> Optional[dict]:
        """Validation humaine. Approuver NE LANCE RIEN : le plan exact est renvoyé pour application manuelle."""
        a = self.db.fetchone("SELECT * FROM pending_actions WHERE id = ?", (action_id,))
        if not a or a["status"] != "pending":
            return None
        who = who or self._user()
        status = "approved" if approve else "rejected"
        self.db.execute("UPDATE pending_actions SET status=?, decided_by=?, decided_at=?, decision_note=? WHERE id=?",
                        (status, who, _now(), note, action_id))
        self.db.write_audit(who, f"action_{status}", f"host:{a['host_id']}",
                            f"{a['action_type']} ({a['target']}) — {note or a['reason']}")
        return {**a, "status": status, "decided_by": who}

    def pending_actions(self) -> list:
        return self.db.fetchall("SELECT * FROM pending_actions WHERE status = 'pending' ORDER BY id DESC")

    # ───────────────────────── étape 7 : fiche d'investigation & rapport ─────────────────────────

    def investigation_sheet(self, incident_id: int) -> Optional[dict]:
        inc = self.db.fetchone("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if not inc:
            return None
        events = self.db.fetchall(
            "SELECT e.* FROM events e JOIN incident_events ie ON ie.event_id = e.id "
            "WHERE ie.incident_id = ? ORDER BY e.id", (incident_id,))
        host = self.db.get_host_by_id(inc["host_id"]) if inc["host_id"] else None
        sheet = {"incident": inc, "events": events, "host": None, "ports": [], "config_diff": [],
                 "actions": self.db.fetchall("SELECT * FROM pending_actions WHERE incident_id = ? ORDER BY id",
                                             (incident_id,)),
                 "evidence_ids": [e["id"] for e in events]}
        if host:
            host.pop("snmp_community", None)
            sheet["host"] = host
            sheet["ports"] = self.db.fetchall(
                "SELECT b.port, b.protocol, b.state AS baseline, (SELECT ps.state FROM port_states ps WHERE ps.host_id=b.host_id "
                "AND ps.port=b.port AND COALESCE(ps.protocol,'TCP')=COALESCE(b.protocol,'TCP') "
                "ORDER BY ps.id DESC LIMIT 1) AS current FROM baselines b "
                "WHERE b.host_id = ? ORDER BY b.protocol, b.port", (host["id"],))
            snaps = self.db.fetchall("SELECT * FROM config_snapshots WHERE host_id = ? ORDER BY id DESC LIMIT 2",
                                     (host["id"],))
            if len(snaps) == 2:
                sheet["config_diff"] = self.diff_config(json.loads(snaps[1]["content"]), json.loads(snaps[0]["content"]))
        return sheet

    def close_incident(self, incident_id: int, who: str = None, acknowledge_only: bool = False):
        who = who or self._user()
        if acknowledge_only:
            self.db.execute("UPDATE incidents SET status='acknowledged', updated_at=? WHERE id=?", (_now(), incident_id))
        else:
            self.db.execute("UPDATE incidents SET status='closed', closed_at=?, updated_at=? WHERE id=?",
                            (_now(), _now(), incident_id))
        self._audit("incident_acknowledged" if acknowledge_only else "incident_closed", f"incident:{incident_id}")

    def report_dir(self) -> Path:
        d = self.db.get_setting("report_dir", "") or str(Path.home() / ".procus_hsr" / "reports")
        p = Path(d)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def generate_report(self, hours: int = 24, out_dir: Optional[str] = None) -> dict:
        """Rapport construit UNIQUEMENT à partir des données stockées (hôtes, événements, incidents, métriques)."""
        from utils.exporter import Exporter
        out = Path(out_dir) if out_dir else self.report_dir()
        out.mkdir(parents=True, exist_ok=True)
        since = f"-{int(hours)} hours"
        hosts = self.db.get_all_hosts()
        for h in hosts:
            h.pop("snmp_community", None)
        events = self.db.fetchall("SELECT * FROM events WHERE occurred_at >= datetime('now', ?) ORDER BY id DESC", (since,))
        incidents = self.db.fetchall("SELECT * FROM incidents WHERE opened_at >= datetime('now', ?) "
                                     "OR status != 'closed' ORDER BY priority DESC", (since,))
        actions = self.db.fetchall("SELECT * FROM pending_actions WHERE requested_at >= datetime('now', ?) "
                                   "ORDER BY id DESC", (since,))
        by_sev: dict[str, int] = {}
        for e in events:
            by_sev[e["severity"]] = by_sev.get(e["severity"], 0) + 1
        data = {"generated_at": _now(), "period_hours": hours,
                "totals": {"hosts": len(hosts), "online": sum(1 for h in hosts if h.get("status") == "online"),
                           "events": len(events), "incidents": len(incidents),
                           "pending_actions": sum(1 for a in actions if a["status"] == "pending"),
                           "unapproved_devices": sum(1 for h in hosts if h.get("approved") == 0)},
                "events_by_severity": by_sev, "incidents": incidents, "events": events, "actions": actions,
                "hosts": [{k: h.get(k) for k in ("id", "name", "ip_address", "device_type", "status", "mac_address",
                                                 "vendor", "criticality", "approved", "last_check")} for h in hosts]}
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = {}
        paths["json"] = str(out / f"rapport_hsr_{stamp}.json")
        Exporter.export_json(paths["json"], data)
        paths["csv"] = str(out / f"rapport_hsr_{stamp}_incidents.csv")
        with open(paths["csv"], "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(["id", "priorité", "score", "sévérité", "équipement", "statut", "événements", "titre", "ouvert"])
            for i in incidents:
                w.writerow([i["id"], i["priority_label"], i["priority"], i["severity"], i["host_name"],
                            i["status"], i["event_count"], i["title"], i["opened_at"]])
        try:
            paths["pdf"] = str(out / f"rapport_hsr_{stamp}.pdf")
            Exporter.export_pdf(paths["pdf"], hosts, title=f"Rapport périodique HSR ({hours} h)", events=events[:200])
        except Exception as e:                       # reportlab absent : JSON + CSV suffisent
            paths.pop("pdf", None)
            logger.warning(f"[Auto] PDF non généré : {e}")
        self.db.set_setting("auto_report_last", _now())
        self.db.set_setting("auto_report_last_path", paths["json"])
        self._audit("report_generated", "report", f"{hours} h — {paths['json']}")
        return {"paths": paths, "totals": data["totals"]}

    def report_due(self) -> bool:
        if self.db.get_setting("auto_report_enabled", "1") != "1":
            return False
        hours = float(self.db.get_setting("auto_report_interval_h", "24") or 24)
        last = self.db.get_setting("auto_report_last", "")
        if not last:
            return True
        try:
            age = time.time() - time.mktime(time.strptime(last[:19].replace("T", " "), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            return True
        return age >= hours * 3600

    # ───────────────────────── pipeline complet ─────────────────────────

    def run_pipeline(self, discover: Optional[Callable[[dict], dict]] = None, force_report: bool = False) -> dict:
        """Exécute les 8 étapes. `discover(network_row) -> {"new": n}` est injecté (réseau réel) ; absent en test."""
        t0 = time.perf_counter()
        steps: dict[str, dict] = {}

        nets = self.authorized_networks()                                                      # 1
        disc = []
        for n in nets:
            try:
                disc.append({"network": n["name"], **(discover(n) if discover else {"skipped": True})})
            except Exception as e:
                disc.append({"network": n["name"], "error": str(e)})
        total_nets = (self.db.fetchone("SELECT COUNT(*) AS n FROM networks") or {}).get("n", 0)
        steps["1_decouverte"] = {"authorized": len(nets), "ignored_unauthorized": total_nets - len(nets), "runs": disc}

        ref = self.reference_status()                                                          # 2
        steps["2_referentiel"] = {"hosts": ref["total"], "unapproved": [h["name"] for h in ref["unapproved"]],
                                  "without_baseline": len(ref["without_baseline"])}

        cfg = self.collect_configs()                                                           # 3
        steps["3_collecte"] = {"config_checked": len(cfg), "config_changed": [c["host"] for c in cfg if c.get("changed")]}

        pending_before = len(self.new_events())                                                # 4
        steps["4_detection"] = {"new_events": pending_before}

        corr = self.correlate()                                                                # 5
        steps["5_correlation"] = {"incidents_opened": len(corr["opened"]), "incidents_updated": len(corr["updated"])}

        touched = [i["id"] for i in corr["opened"] + corr["updated"]]                          # 6
        ranked = sorted(corr["opened"] + corr["updated"], key=lambda i: -i["priority"])
        steps["6_priorisation"] = {"ranking": [{"id": i["id"], "host": i["host"], "priority": i["priority"],
                                                "label": i["priority_label"]} for i in ranked]}

        report = None                                                                          # 7
        if force_report or self.report_due():
            try:
                report = self.generate_report(int(float(self.db.get_setting("auto_report_interval_h", "24") or 24)))
            except Exception as e:
                logger.exception(e)
                report = {"error": str(e)}
        steps["7_resultat"] = {"sheets": touched, "report": (report or {}).get("paths")}

        made = self.propose_for_incidents(touched)                                             # 8
        steps["8_validation_humaine"] = {"actions_proposed": len(made),
                                         "waiting_for_human": len(self.pending_actions()),
                                         "executed_automatically": 0}
        dur = int((time.perf_counter() - t0) * 1000)
        self.db.execute("INSERT INTO pipeline_runs (finished_at, steps, duration_ms) VALUES (?, ?, ?)",
                        (_now(), json.dumps(steps, ensure_ascii=False), dur))
        return {"steps": steps, "duration_ms": dur}


# ─────────────────────────────────────────────────────────────────
# Worker Qt (thread dédié) — appelé par le scheduler
# ─────────────────────────────────────────────────────────────────
try:
    from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

    class AutomationWorker(QObject):
        log_message = pyqtSignal(str, str)
        pipeline_done = pyqtSignal(dict)
        incident_alert = pyqtSignal(dict)           # P1/P2 → notifications

        def __init__(self, db=None, security=None, parent=None):
            super().__init__(parent)
            self.db, self.security = db, security
            self._busy = False

        @pyqtSlot()
        def run_pipeline(self):
            if not self.db or self._busy:
                return
            self._busy = True
            try:
                from core.monitor import MonitorWorker
                eng = AutomationEngine(self.db, self.security, snmp=MonitorWorker(),
                                       notify=self.incident_alert.emit)

                out = eng.run_pipeline(discover=None)      # la découverte réseau est déjà planifiée séparément
                s = out["steps"]
                self.log_message.emit(
                    "INFO", f"[Pipeline] {s['5_correlation']['incidents_opened']} incident(s) ouvert(s), "
                            f"{s['8_validation_humaine']['waiting_for_human']} action(s) en attente de validation "
                            f"({out['duration_ms']} ms)")
                self.pipeline_done.emit(out)
            except Exception as e:
                logger.exception(e)
                self.log_message.emit("ERROR", f"[Pipeline] {e}")
            finally:
                self._busy = False
except ImportError:                                  # moteur utilisable sans Qt (tests, scripts)
    pass
