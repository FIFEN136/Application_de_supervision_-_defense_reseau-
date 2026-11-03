"""
Procus Secure — politique de filtrage par INTENTION, avec contrôle anti-blocage et simulation d'impact (v15, bloc 3).

IMPORTANT : ce module ne modifie AUCUN équipement. Il sert à écrire, valider et simuler des règles ; l'application sur
un pare-feu ou un commutateur est une étape ultérieure, distincte et validée par un humain.

Modèle : une règle = source → destination, service, action (allow/deny), priorité. La PREMIÈRE règle qui correspond
s'applique ; sans correspondance, l'action par défaut s'applique (« allow » par défaut, réglage policy_default).
Sélecteurs : any · zone:<nom> · role:<rôle> · host:<id> · ip:<adresse ou réseau>.
Services : any · icmp · tcp/445 · udp/53 · tcp/80-443 · listes séparées par des virgules · noms (ssh, rdp, smb, dns…).

Garde-fous :
  • contrôle anti-blocage : des CHEMINS CRITIQUES (cette machine → équipements réseau en SSH/SNMP/ICMP, agents → Procus,
    postes d'administration → équipements) doivent rester ouverts avec la politique proposée, sinon la règle est refusée ;
  • les règles passent par brouillon → approuvée (droit can_manage_config ; double validation en option) ;
  • tout est inscrit dans le journal d'audit.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from typing import Optional

from core import classify
from core import local_network as lnet

PRESETS = {
    "ssh": ["tcp/22"], "telnet": ["tcp/23"], "ftp": ["tcp/21"], "http": ["tcp/80"], "https": ["tcp/443"],
    "web": ["tcp/80", "tcp/443"], "rdp": ["tcp/3389"], "smb": ["tcp/445"], "dns": ["udp/53", "tcp/53"], "ntp": ["udp/123"],
    "snmp": ["udp/161"], "syslog": ["udp/514"], "tftp": ["udp/69"], "rsh": ["tcp/512-514"], "vnc": ["tcp/5900"],
    "icmp": ["icmp"], "mysql": ["tcp/3306"], "postgres": ["tcp/5432"], "mssql": ["tcp/1433"],
}
AGENT_PORT = 8765


class PolicyError(ValueError):
    pass


# ───────────── services ─────────────
def parse_service(text: str) -> list[tuple]:
    text = (text or "").strip().lower()
    if not text:
        raise PolicyError("Service requis (any, tcp/445, ssh…).")
    toks = []
    for t in (x.strip() for x in text.split(",")):
        toks += PRESETS.get(t, [t])
    out = []
    for t in toks:
        if t == "any":
            out.append(("any", 0, 65535))
        elif t == "icmp":
            out.append(("icmp", 0, 0))
        else:
            proto, _, ports = t.partition("/")
            if proto not in ("tcp", "udp") or not ports:
                raise PolicyError(f"Service invalide : « {t} » (attendu : tcp/445, udp/53, tcp/80-443, ssh…).")
            try:
                lo, _, hi = ports.partition("-")
                lo, hi = int(lo), int(hi or lo)
            except ValueError:
                raise PolicyError(f"Port invalide dans « {t} ».") from None
            if not (1 <= lo <= hi <= 65535):
                raise PolicyError(f"Ports hors limites dans « {t} » (1 à 65535).")
            out.append((proto, lo, hi))
    if any(o[0] == "any" for o in out) and len(out) > 1:
        raise PolicyError("« any » ne peut pas être combiné avec d'autres services.")
    return out


def canonical_service(text: str) -> str:
    parts = []
    for p, lo, hi in parse_service(text):
        parts.append("any" if p == "any" else "icmp" if p == "icmp" else f"{p}/{lo}" + (f"-{hi}" if hi != lo else ""))
    return ",".join(parts)


def service_matches(spec: list, proto: str, dport: int) -> bool:
    for p, lo, hi in spec:
        if p == "any":
            return True
        if p == proto and (p == "icmp" or lo <= int(dport) <= hi):
            return True
    return False


def services_cover(a: list, b: list) -> bool:
    if any(x[0] == "any" for x in a):
        return True
    return all(y[0] != "any" and any(x[0] == y[0] and x[1] <= y[1] and y[2] <= x[2] for x in a) for y in b)


# ───────────── sélecteurs ─────────────
def parse_selector(db, text: str) -> tuple[str, str]:
    text = (text or "").strip()
    if text == "any":
        return ("any", "")
    kind, _, val = text.partition(":")
    val = val.strip()
    if kind == "zone":
        if not db.fetchone("SELECT 1 FROM net_zones WHERE name = ?", (val,)):
            raise PolicyError(f"Zone inconnue : « {val} ».")
    elif kind == "role":
        if val not in classify.ROLES:
            raise PolicyError(f"Rôle inconnu : « {val} ».")
    elif kind == "host":
        if not val.isdigit() or not db.get_host_by_id(int(val)):
            raise PolicyError(f"Équipement inconnu : « {val} ».")
    elif kind == "ip":
        try:
            val = str(ipaddress.ip_network(val, strict=False))
        except ValueError:
            raise PolicyError(f"Adresse ou réseau invalide : « {val} ».") from None
    else:
        raise PolicyError(f"Sélecteur invalide : « {text} » (any, zone:, role:, host:, ip:).")
    return (kind, val)


def selector_text(sel: tuple) -> str:
    return "any" if sel[0] == "any" else f"{sel[0]}:{sel[1]}"


def describe_selector(db, text: str) -> str:
    kind, _, val = (text or "any").partition(":")
    if kind == "any":
        return "tout"
    if kind == "zone":
        return f"zone « {val} »"
    if kind == "role":
        return f"rôle « {classify.ROLES.get(val, val)} »"
    if kind == "host":
        h = db.get_host_by_id(int(val)) if val.isdigit() else None
        return f"équipement « {h['name'] if h else val} »"
    return val


class Context:
    """Résolution des adresses → (zone, rôle, équipement) avec cache."""
    def __init__(self, db):
        self.db = db
        self._hosts = {h["ip_address"]: h for h in db.fetchall("SELECT id, name, ip_address, device_type FROM hosts")}
        self._roles = {r["host_id"]: r["role"] for r in db.fetchall("SELECT host_id, role FROM host_roles")}
        self._cache: dict = {}
        self._nets: dict = {}

    def info(self, ip: str) -> dict:
        if ip not in self._cache:
            h = self._hosts.get(ip)
            z = classify.zone_of_ip(self.db, ip)
            self._cache[ip] = {"zone": z["name"] if z else None, "host": h, "host_id": h["id"] if h else None,
                               "role": self._roles.get(h["id"]) if h else None, "name": h["name"] if h else ip}
        return self._cache[ip]

    def match(self, sel: tuple, ip: str) -> bool:
        kind, val = sel
        if kind == "any":
            return True
        i = self.info(ip)
        if kind == "zone":
            return i["zone"] == val
        if kind == "role":
            return i["role"] == val
        if kind == "host":
            return i["host_id"] == int(val)
        try:
            net = self._nets.get(val) or self._nets.setdefault(val, ipaddress.ip_network(val, strict=False))
            return ipaddress.ip_address(ip) in net
        except ValueError:
            return False


# ───────────── règles ─────────────
class CompiledRule:
    def __init__(self, db, row: dict):
        self.row = row
        self.id = row["id"]
        self.src, self.dst = parse_selector(db, row["src"]), parse_selector(db, row["dst"])
        self.service = parse_service(row["service"])
        self.action = row["action"]

    def matches(self, ctx: Context, src: str, dst: str, proto: str, dport: int) -> bool:
        return (service_matches(self.service, proto, dport) and ctx.match(self.src, src) and ctx.match(self.dst, dst))


def _expired(row: dict, now: Optional[datetime] = None) -> bool:
    if not row.get("expires_at"):
        return False
    try:
        return datetime.fromisoformat(str(row["expires_at"])) < (now or datetime.now())
    except ValueError:
        return False


def effective_rows(db, include_drafts: bool, extra: Optional[dict] = None, exclude_id: Optional[int] = None) -> list[dict]:
    statuses = ("approved", "draft") if include_drafts else ("approved",)
    rows = [r for r in db.fetchall("SELECT * FROM policy_rules WHERE enabled = 1 AND status IN (%s)" % ",".join("?" * len(statuses)), statuses)  # nosec B608 - seuls des « ? » sont formatés
            if not _expired(r) and r["id"] != exclude_id]
    if extra:
        rows.append(extra)
    return sorted(rows, key=lambda r: (int(r.get("position") or 100), int(r.get("id") or 10**9)))


def default_action(db) -> str:
    return "deny" if db.get_setting("policy_default", "allow") == "deny" else "allow"


def decide(rules: list, ctx: Context, src, dst, proto, dport, default="allow"):
    for r in rules:
        if r.matches(ctx, src, dst, proto, dport):
            return r.action, r
    return default, None


# ───────────── contrôle anti-blocage ─────────────
def protected_context(db) -> dict:
    hosts = db.fetchall("SELECT * FROM hosts")
    roles = {r["host_id"]: r["role"] for r in db.fetchall("SELECT host_id, role FROM host_roles")}
    local = {h["ip_address"] for h in hosts if lnet.is_local_address(h["ip_address"])}
    pip = lnet.get_primary_ip()
    if pip:
        local.add(pip)
    gws = {n["gateway_ip"] for n in db.fetchall("SELECT gateway_ip FROM networks") if n["gateway_ip"]}
    gw = lnet.get_default_gateway()
    if gw:
        gws.add(gw)
    devices = {h["ip_address"] for h in hosts if h["device_type"] in ("router", "switch", "firewall", "ap")} | gws
    agents = {h["ip_address"] for h in hosts if h.get("agent_enabled")}
    admins = {h["ip_address"] for h in hosts if roles.get(h["id"]) == "admin"}
    for tok in (db.get_setting("policy_protected", "") or "").split(","):
        tok = tok.strip()
        try:
            admins.add(str(ipaddress.ip_address(tok)))
        except ValueError:
            pass
    return {"local": local, "devices": devices - local, "agents": agents - local, "admins": admins - local}


def critical_paths(db) -> list[tuple]:
    pc = protected_context(db)
    paths = []
    for l in pc["local"]:
        for n in pc["devices"]:
            paths += [(l, n, "tcp", 22, "supervision SSH (sauvegarde de configuration)"), (l, n, "udp", 161, "supervision SNMP"),
                      (l, n, "icmp", 0, "supervision ICMP (ping)")]
        for a in pc["agents"]:
            paths.append((a, l, "tcp", AGENT_PORT, "rapports des agents vers Procus"))
    for d in pc["admins"]:
        for n in pc["devices"]:
            paths.append((d, n, "tcp", 22, "administration SSH depuis un poste protégé"))
    return paths[:2000]


def lockout_issues(db, rows: list[dict]) -> list[dict]:
    """Chemins critiques refusés par l'ensemble de règles `rows` (déjà ordonné)."""
    ctx = Context(db)
    rules = [CompiledRule(db, r) for r in rows]
    dflt = default_action(db)
    out = []
    for src, dst, proto, port, why in critical_paths(db):
        act, rule = decide(rules, ctx, src, dst, proto, port, dflt)
        if act == "deny":
            who = f"la règle « {rule.row['name']} »" if rule else "l'action par défaut (refuser)"
            out.append({"level": "error", "code": "lockout",
                        "message": f"Coupure de {why} : {src} → {dst} ({proto}{'/' + str(port) if port else ''}) serait refusé par {who}."})
    return out[:20]


# ───────────── gestionnaire ─────────────
class PolicyManager:
    def __init__(self, db, security=None):
        self.db, self.security = db, security

    # --- droits / audit ---
    def _user(self) -> str:
        try:
            return (self.security.get_current_user() or {}).get("login") or "système"
        except Exception:
            return "système"

    def _need(self):
        if self.security is not None and not self.security.has_permission("can_manage_config"):
            raise PolicyError("Votre rôle ne permet pas de modifier la politique (droit « can_manage_config »).")

    def _audit(self, action, target, detail=""):
        try:
            self.db.write_audit(self._user(), action, target, detail)
        except Exception:
            pass

    # --- validation ---
    @staticmethod
    def _position(value) -> int:
        if value in (None, ""):
            return 100
        try:
            return int(value)
        except (TypeError, ValueError):
            raise PolicyError("Priorité invalide (nombre de 1 à 9999).") from None

    def normalize(self, data: dict) -> dict:
        name = (data.get("name") or "").strip()
        if not name:
            raise PolicyError("Nom de règle requis.")
        action = (data.get("action") or "").lower()
        if action not in ("allow", "deny"):
            raise PolicyError("Action invalide (allow ou deny).")
        out = {"name": name[:120], "src": selector_text(parse_selector(self.db, data.get("src", "any"))),
               "dst": selector_text(parse_selector(self.db, data.get("dst", "any"))),
               "service": canonical_service(data.get("service", "any")), "action": action,
               "comment": (data.get("comment") or "")[:500], "position": self._position(data.get("position")),
               "expires_at": (data.get("expires_at") or None), "source": data.get("source") or "manual"}
        if not 1 <= out["position"] <= 9999:
            raise PolicyError("Priorité hors limites (1 à 9999).")
        if out["expires_at"]:
            try:
                datetime.fromisoformat(str(out["expires_at"]))
            except ValueError:
                raise PolicyError("Date d'expiration invalide (AAAA-MM-JJ ou AAAA-MM-JJ HH:MM).") from None
        return out

    def validate(self, data: dict, rule_id: Optional[int] = None, include_drafts: bool = False) -> list[dict]:
        """Problèmes de la règle dans la politique qui serait EN VIGUEUR (règles approuvées + celle-ci).
        include_drafts=True : politique PRÉVUE (brouillons compris), utilisée à la création ; l'approbation, elle,
        contrôle la politique réellement en vigueur."""
        rule = self.normalize(data)
        cand = dict(rule, id=rule_id or 10**9, enabled=1, status="approved")
        rows = effective_rows(self.db, include_drafts, extra=cand, exclude_id=rule_id)
        issues = lockout_issues(self.db, rows) if rule["action"] == "deny" or default_action(self.db) == "deny" else []
        ctx = Context(self.db)
        mine = CompiledRule(self.db, cand)
        universe = self._universe()
        mine_src = {ip for ip in universe if ctx.match(mine.src, ip)}
        mine_dst = {ip for ip in universe if ctx.match(mine.dst, ip)}
        for r in rows:
            if r is cand:
                continue
            o = CompiledRule(self.db, r)
            before = (int(r["position"]), int(r["id"])) < (rule["position"], cand["id"])
            same_src = (o.src == mine.src) or (mine_src and mine_src <= {ip for ip in universe if ctx.match(o.src, ip)}) or o.src[0] == "any"
            same_dst = (o.dst == mine.dst) or (mine_dst and mine_dst <= {ip for ip in universe if ctx.match(o.dst, ip)}) or o.dst[0] == "any"
            if before and same_src and same_dst and services_cover(o.service, mine.service):
                if o.action == mine.action:
                    issues.append({"level": "warning", "code": "shadowed", "message": f"Règle inutile : « {r['name']} » (plus prioritaire) couvre déjà ce trafic."})
                else:
                    issues.append({"level": "warning", "code": "shadowed", "message": f"Règle jamais appliquée : « {r['name']} » (plus prioritaire, action opposée) décide avant elle."})
                break
        if rule["action"] == "allow" and rule["src"] == "any" and rule["dst"] == "any" and rule["service"] == "any":
            issues.append({"level": "warning", "code": "too_broad", "message": "Autorise absolument tout : cette règle annule l'intérêt du filtrage."})
        if rule["action"] == "deny" and rule["src"] == "any" and rule["dst"] == "any" and rule["service"] == "any":
            issues.append({"level": "warning", "code": "too_broad", "message": "Bloque absolument tout : risque de coupure totale."})
        return issues

    def _universe(self) -> set:
        u = {h["ip_address"] for h in self.db.fetchall("SELECT ip_address FROM hosts")}
        for f in self.db.fetchall("SELECT src_ip, dst_ip FROM flows_agg LIMIT 5000"):
            u.add(f["src_ip"]); u.add(f["dst_ip"])
        return u

    # --- CRUD ---
    def create_rule(self, data: dict) -> int:
        self._need()
        rule = self.normalize(data)
        errs = [i for i in self.validate(rule, include_drafts=True) if i["level"] == "error"]
        if errs:
            raise PolicyError(errs[0]["message"])
        rid = self.db.execute(
            "INSERT INTO policy_rules (position, name, src, dst, service, action, comment, source, expires_at, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (rule["position"], rule["name"], rule["src"], rule["dst"], rule["service"], rule["action"], rule["comment"],
             rule["source"], rule["expires_at"], self._user())).lastrowid
        self._audit("policy_rule_created", f"rule:{rid}", f"{rule['action']} {rule['src']}→{rule['dst']} {rule['service']}")
        return rid

    def update_rule(self, rule_id: int, data: dict):
        self._need()
        old = self.db.fetchone("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
        if not old:
            raise PolicyError("Règle introuvable.")
        if old["status"] == "retired":
            raise PolicyError("Une règle retirée ne peut plus être modifiée.")
        rule = self.normalize(data)
        errs = [i for i in self.validate(rule, rule_id, include_drafts=True) if i["level"] == "error"]
        if errs:
            raise PolicyError(errs[0]["message"])
        # toute modification d'une règle approuvée la ramène en brouillon : elle doit être revalidée
        self.db.execute("UPDATE policy_rules SET position=?, name=?, src=?, dst=?, service=?, action=?, comment=?, expires_at=?, "
                        "status='draft', approved_by=NULL, updated_at=datetime('now') WHERE id=?",
                        (rule["position"], rule["name"], rule["src"], rule["dst"], rule["service"], rule["action"],
                         rule["comment"], rule["expires_at"], rule_id))
        self._audit("policy_rule_updated", f"rule:{rule_id}", rule["name"])

    def approve_rule(self, rule_id: int):
        self._need()
        r = self.db.fetchone("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
        if not r or r["status"] != "draft":
            raise PolicyError("Seule une règle en brouillon peut être approuvée.")
        if self.db.get_setting("policy_four_eyes", "0") == "1" and r["created_by"] == self._user():
            raise PolicyError("Double validation activée : la règle doit être approuvée par une autre personne que son auteur.")
        errs = [i for i in self.validate(r, rule_id) if i["level"] == "error"]
        if errs:
            raise PolicyError(errs[0]["message"])
        self.db.execute("UPDATE policy_rules SET status='approved', approved_by=?, updated_at=datetime('now') WHERE id=?", (self._user(), rule_id))
        self._audit("policy_rule_approved", f"rule:{rule_id}", r["name"])

    def _check_without(self, rule_id: int, r: dict):
        """Retirer ou désactiver une règle approuvée ne doit pas rouvrir/fermer un chemin critique."""
        if r["status"] == "approved" and r["enabled"]:
            errs = lockout_issues(self.db, effective_rows(self.db, False, exclude_id=rule_id))
            if errs:
                raise PolicyError("Impossible : " + errs[0]["message"])

    def approve_many(self, ids: list) -> list[int]:
        """Approuve dans l'ordre de priorité (les « autoriser » prioritaires avant les « refuser »)."""
        rows = [self.db.fetchone("SELECT id, position FROM policy_rules WHERE id = ?", (i,)) for i in ids]
        done = []
        for r in sorted([r for r in rows if r], key=lambda r: (r["position"], r["id"])):
            self.approve_rule(r["id"])
            done.append(r["id"])
        return done

    def retire_rule(self, rule_id: int):
        self._need()
        r = self.db.fetchone("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
        if not r:
            raise PolicyError("Règle introuvable.")
        self._check_without(rule_id, r)
        if r["status"] == "draft":
            self.db.execute("DELETE FROM policy_rules WHERE id = ?", (rule_id,))
            self._audit("policy_rule_deleted", f"rule:{rule_id}", r["name"])
        else:
            self.db.execute("UPDATE policy_rules SET status='retired', updated_at=datetime('now') WHERE id=?", (rule_id,))
            self._audit("policy_rule_retired", f"rule:{rule_id}", r["name"])

    def set_enabled(self, rule_id: int, on: bool):
        self._need()
        r = self.db.fetchone("SELECT * FROM policy_rules WHERE id = ?", (rule_id,))
        if not r:
            raise PolicyError("Règle introuvable.")
        if not on:
            self._check_without(rule_id, r)
        self.db.execute("UPDATE policy_rules SET enabled=?, updated_at=datetime('now') WHERE id=?", (1 if on else 0, rule_id))
        self._audit("policy_rule_enabled" if on else "policy_rule_disabled", f"rule:{rule_id}")

    def rules(self) -> list[dict]:
        return self.db.fetchall("SELECT * FROM policy_rules WHERE status != 'retired' ORDER BY position, id")

    # --- recommandations et modèles ---
    def from_finding(self, finding_id: int) -> int:
        self._need()
        f = self.db.fetchone("SELECT * FROM assess_findings WHERE id = ?", (finding_id,))
        if not f or not f["rule_hint"]:
            raise PolicyError("Ce constat n'a pas de règle suggérée.")
        if self.db.fetchone("SELECT 1 FROM policy_rules WHERE source = ? AND status != 'retired'", (f"finding:{finding_id}",)):
            raise PolicyError("Une règle existe déjà pour ce constat.")
        hint = json.loads(f["rule_hint"])
        hint.update(source=f"finding:{finding_id}", comment=f"Recommandation : {f['title']}", position=500)
        return self.create_rule(hint)

    def apply_template(self, name: str) -> list[int]:
        self._need()
        if name not in TEMPLATES:
            raise PolicyError("Modèle inconnu.")
        drafts = TEMPLATES[name]["build"](self.db)
        if not drafts:
            raise PolicyError(TEMPLATES[name]["empty"])
        made = []
        try:
            for d in drafts:
                d = dict(d, source=f"template:{name}")
                if self.db.fetchone("SELECT 1 FROM policy_rules WHERE source = ? AND name = ? AND status != 'retired'", (d["source"], d["name"])):
                    continue
                made.append(self.create_rule(d))
        except PolicyError:
            for rid in made:                                   # tout ou rien : pas de modèle à moitié créé
                self.db.execute("DELETE FROM policy_rules WHERE id = ?", (rid,))
            raise
        if not made:
            raise PolicyError("Ce modèle est déjà en place.")
        return made

    # --- simulation ---
    def simulate(self, include_drafts: bool = True, top: int = 15) -> dict:
        rows = effective_rows(self.db, include_drafts)
        rules = [CompiledRule(self.db, r) for r in rows]
        ctx = Context(self.db)
        dflt = default_action(self.db)
        hits = {r.id: {"flows": 0, "bytes": 0} for r in rules}
        tot = {"allowed_flows": 0, "denied_flows": 0, "allowed_bytes": 0, "denied_bytes": 0}
        denied: dict = {}
        impacted: dict = {}
        for f in self.db.fetchall("SELECT * FROM flows_agg"):
            act, rule = decide(rules, ctx, f["src_ip"], f["dst_ip"], f["proto"], f["dst_port"], dflt)
            if rule:
                hits[rule.id]["flows"] += f["flows"]; hits[rule.id]["bytes"] += f["bytes"]
            if act == "deny":
                tot["denied_flows"] += f["flows"]; tot["denied_bytes"] += f["bytes"]
                k = (f["src_ip"], f["dst_ip"], f["proto"], f["dst_port"])
                e = denied.setdefault(k, {"flows": 0, "bytes": 0, "rule": rule.row["name"] if rule else "action par défaut"})
                e["flows"] += f["flows"]; e["bytes"] += f["bytes"]
                for ip in (f["src_ip"], f["dst_ip"]):
                    i = ctx.info(ip)
                    imp = impacted.setdefault(ip, {"name": i["name"], "role": i["role"], "zone": i["zone"], "flows": 0})
                    imp["flows"] += f["flows"]
            else:
                tot["allowed_flows"] += f["flows"]; tot["allowed_bytes"] += f["bytes"]
        total = tot["allowed_flows"] + tot["denied_flows"]
        warnings = []
        for r in rules:
            if hits[r.id]["flows"] == 0 and r.row.get("id"):
                warnings.append(f"« {r.row['name']} » ne correspond à aucun flux observé (inutile, ou trafic rare).")
        if total and tot["denied_flows"] / total > 0.3:
            warnings.append(f"Cette politique refuserait {100 * tot['denied_flows'] // total} % du trafic observé : vérifiez qu'aucun usage légitime n'est coupé.")
        crit = [i for i in impacted.values() if i["role"] in ("server", "network", "admin")]
        if crit:
            warnings.append("Équipements sensibles touchés : " + ", ".join(sorted({i["name"] for i in crit})[:8]) + ".")
        return {"rules": len(rules), "flows_total": total, "default": dflt,
                **tot, "denied_pct": (100 * tot["denied_flows"] // total) if total else 0,
                "per_rule": [{"id": r.id, "name": r.row["name"], "action": r.action, **hits[r.id]} for r in rules],
                "denied_top": [{"src": k[0], "dst": k[1], "proto": k[2], "port": k[3], "src_name": ctx.info(k[0])["name"],
                                "dst_name": ctx.info(k[1])["name"], **v}
                               for k, v in sorted(denied.items(), key=lambda kv: -kv[1]["flows"])[:top]],
                "impacted": sorted(impacted.values(), key=lambda i: -i["flows"])[:top],
                "lockout": lockout_issues(self.db, rows), "warnings": warnings}


# ───────────── modèles ─────────────
def _zones(db, low=None, high=None):
    return [z["name"] for z in db.fetchall("SELECT name, trust FROM net_zones ORDER BY trust")
            if (low is None or z["trust"] <= low) and (high is None or z["trust"] >= high)]


def _t_guests(db):
    out = []
    for g in _zones(db, low=10):
        for z in _zones(db, high=40):
            out.append({"name": f"Isoler {g} de {z}", "src": f"zone:{g}", "dst": f"zone:{z}", "service": "any", "action": "deny",
                        "position": 200, "comment": "Les invités n'accèdent qu'à Internet, jamais au réseau interne."})
    return out


def _t_iot(db):
    out = []
    for r in ("iot", "camera"):
        out.append({"name": f"{classify.ROLES[r]} : DNS/NTP autorisés", "src": f"role:{r}", "dst": "any", "service": "dns,ntp",
                    "action": "allow", "position": 100})
        for d in ("server", "workstation", "admin"):
            out.append({"name": f"{classify.ROLES[r]} → {classify.ROLES[d]} interdit", "src": f"role:{r}", "dst": f"role:{d}",
                        "service": "any", "action": "deny", "position": 200,
                        "comment": "Un objet connecté n'a pas à joindre vos serveurs et postes."})
    return out


def _t_insecure(db):
    return [{"name": "Interdire Telnet", "src": "any", "dst": "any", "service": "telnet", "action": "deny", "position": 300,
             "comment": "Mots de passe en clair."},
            {"name": "Interdire TFTP", "src": "any", "dst": "any", "service": "tftp", "action": "deny", "position": 300},
            {"name": "Interdire les services r* (rsh, rlogin, rexec)", "src": "any", "dst": "any", "service": "rsh", "action": "deny", "position": 300}]


def _t_mgmt(db):
    pc = protected_context(db)
    out = []
    for l in sorted(pc["local"]):
        out.append({"name": f"Supervision Procus ({l}) vers équipements réseau", "src": f"ip:{l}", "dst": "role:network",
                    "service": "ssh,snmp,icmp", "action": "allow", "position": 50})
    out.append({"name": "Administration depuis les postes d'administration", "src": "role:admin", "dst": "role:network",
                "service": "ssh,https,snmp", "action": "allow", "position": 60})
    out.append({"name": "Administration réseau réservée", "src": "any", "dst": "role:network", "service": "ssh,telnet,snmp",
                "action": "deny", "position": 400, "comment": "Seuls Procus et les postes d'administration gèrent les équipements."})
    return out


TEMPLATES = {
    "isolate_guests": {"title": "Isoler les invités du réseau interne", "build": _t_guests,
                       "empty": "Aucune zone « invités » (confiance ≤ 10) à isoler : créez-en une dans Zones.",
                       "description": "Interdit aux zones peu fiables (invités) d'atteindre les zones internes."},
    "iot_no_lan": {"title": "Empêcher objets connectés et caméras d'atteindre serveurs et postes", "build": _t_iot,
                   "empty": "Aucune règle à créer.", "description": "Autorise DNS/NTP, interdit le reste vers serveurs, postes et administration."},
    "block_insecure": {"title": "Interdire les protocoles non sûrs (Telnet, TFTP, rsh)", "build": _t_insecure,
                       "empty": "Aucune règle à créer.", "description": "Ferme les protocoles qui font circuler les mots de passe en clair."},
    "mgmt_admin_only": {"title": "Réserver l'administration réseau à Procus et aux postes d'administration", "build": _t_mgmt,
                        "empty": "Aucune règle à créer.",
                        "description": "Autorise d'abord Procus et les postes d'admin, puis interdit l'administration à tous les autres."},
}


def rules_as_text(db, rows: list[dict]) -> list[str]:
    out = []
    for r in rows:
        verb = "AUTORISER" if r["action"] == "allow" else "REFUSER"
        out.append(f"{r['position']:>4}. {verb} {describe_selector(db, r['src'])} → {describe_selector(db, r['dst'])} "
                   f"[{r['service']}] — {r['name']} ({'approuvée' if r['status'] == 'approved' else 'brouillon'})")
    return out
