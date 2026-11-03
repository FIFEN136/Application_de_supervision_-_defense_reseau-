"""
Procus Secure — règles de trafic « pour tout le monde ».

Une règle se compose en 4 choix, en français : [Autoriser / Interdire] [qui ?] [à accéder à qui ?] [pour faire quoi ?].
Rien n'est envoyé aux équipements : la règle est vérifiée (anti-blocage), simulée sur le trafic observé, puis enregistrée dans
la politique de filtrage. Les EXCEPTIONS (autoriser) passent avant les INTERDICTIONS, ce que l'utilisateur attend.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from core import classify
from core.policy import (CompiledRule, Context, PolicyError, PolicyManager, TEMPLATES, canonical_service, describe_selector)

PLURAL = {"server": "Les serveurs", "workstation": "Les ordinateurs", "network": "Les équipements réseau (routeur, switch, Wi-Fi)",
          "printer": "Les imprimantes", "camera": "Les caméras", "iot": "Les objets connectés", "mobile": "Les téléphones et tablettes",
          "guest": "Les invités", "admin": "Les postes d'administration"}

WHAT = [("Tout type de connexion", "any"),
        ("Navigation sur Internet (sites web)", "web"),
        ("Fichiers partagés Windows (SMB)", "smb"),
        ("Bureau à distance (RDP)", "rdp"),
        ("Administration à distance (SSH)", "ssh"),
        ("Transfert de fichiers (FTP)", "ftp"),
        ("Telnet (ancien et non sécurisé)", "telnet"),
        ("Noms de sites (DNS)", "dns"),
        ("Supervision (SNMP)", "snmp"),
        ("Bases de données (MySQL, PostgreSQL, SQL Server)", "mysql,postgres,mssql"),
        ("Ping (tester si un appareil répond)", "icmp")]
WHAT_LABEL = {svc: label for label, svc in WHAT}


def who_choices(db) -> list[tuple[str, str]]:
    """[(texte affiché, sélecteur)] : tous, zones, types d'appareils présents, appareils précis."""
    out = [("Tous les appareils", "any")]
    for z in db.fetchall("SELECT name FROM net_zones ORDER BY trust"):
        out.append((f"Les appareils de la zone « {z['name']} »", f"zone:{z['name']}"))
    present = {r["role"] for r in db.fetchall("SELECT DISTINCT role FROM host_roles")}
    for role, label in PLURAL.items():
        if role in present:
            out.append((label, f"role:{role}"))
    for h in db.fetchall("SELECT id, name, ip_address FROM hosts ORDER BY name"):
        out.append((f"L'appareil « {h['name']} » ({h['ip_address']})", f"host:{h['id']}"))
    return out


def who_label(db, selector: str) -> str:
    kind, _, val = (selector or "any").partition(":")
    if kind == "any":
        return "tous les appareils"
    if kind == "role":
        return PLURAL.get(val, classify.ROLES.get(val, val)).lower()
    if kind == "zone":
        return f"les appareils de la zone « {val} »"
    if kind == "host":
        h = db.get_host_by_id(int(val)) if val.isdigit() else None
        return f"l'appareil « {h['name']} »" if h else f"l'appareil {val}"
    return f"le réseau {val}" if "/" in val and not val.endswith(("/32", "/128")) else f"l'adresse {val.split('/')[0]}"


def service_label(service: str) -> str:
    canon = canonical_service(service)
    for label, svc in WHAT:
        if canonical_service(svc) == canon:
            return label[0].lower() + label[1:]
    return f"le service {canon}"


def _to(target: str) -> str:
    """« à les serveurs » → « aux serveurs »."""
    return "aux " + target[4:] if target.startswith("les ") else "à " + target


def custom_service(proto: str, port: int) -> str:
    proto = (proto or "tcp").lower()
    if proto not in ("tcp", "udp"):
        raise PolicyError("Protocole inconnu (TCP ou UDP).")
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise PolicyError("Le port doit être un nombre entre 1 et 65535.") from None
    if not 1 <= port <= 65535:
        raise PolicyError("Le port doit être un nombre entre 1 et 65535.")
    return f"{proto}/{port}"


def custom_who(text: str) -> str:
    try:
        return "ip:" + str(ipaddress.ip_network((text or "").strip(), strict=False))
    except ValueError:
        raise PolicyError("Adresse invalide : saisissez une adresse comme 192.168.1.20 ou un réseau comme 192.168.1.0/24.") from None


def build(db, action: str, src: str, dst: str, service: str) -> dict:
    """Règle prête pour PolicyManager. Les exceptions (autoriser) sont évaluées avant les interdictions."""
    if action not in ("allow", "deny"):
        raise PolicyError("Choisissez Autoriser ou Interdire.")
    data = {"action": action, "src": src, "dst": dst, "service": service,
            "position": 50 if action == "allow" else 100, "source": "simple",
            "comment": "Créée avec l'assistant de règles simples."}
    data["name"] = sentence(db, data, short=True)[:120]
    return data


def sentence(db, d: dict, short: bool = False) -> str:
    verb = "Autoriser" if d["action"] == "allow" else "Interdire"
    s, t = who_label(db, d["src"]), who_label(db, d["dst"])
    what = service_label(d["service"])
    if short:
        return f"{verb} {s} → {t} ({what})"
    t = _to(t)
    s = s[0].upper() + s[1:]
    if d["action"] == "allow":
        return f"{s} pourront accéder {t} : {what}." if s.lower().startswith(("les", "tous")) else f"{s} pourra accéder {t} : {what}."
    return (f"{s} ne pourront plus accéder {t} : {what}." if s.lower().startswith(("les", "tous"))
            else f"{s} ne pourra plus accéder {t} : {what}.")


def preview(db, pm: PolicyManager, data: dict) -> dict:
    """Effet de la règle AVANT de l'ajouter : problèmes éventuels et trafic observé concerné."""
    rule = pm.normalize(data)
    issues = pm.validate(rule, include_drafts=True)
    cand = dict(rule, id=10**9, enabled=1, status="approved")
    cr, ctx = CompiledRule(db, cand), Context(db)
    flows = nbytes = 0
    pairs: dict = {}
    for f in db.fetchall("SELECT * FROM flows_agg"):
        if cr.matches(ctx, f["src_ip"], f["dst_ip"], f["proto"], f["dst_port"]):
            flows += f["flows"]; nbytes += f["bytes"]
            k = (ctx.info(f["src_ip"])["name"], ctx.info(f["dst_ip"])["name"])
            pairs[k] = pairs.get(k, 0) + f["flows"]
    top = [f"{a} → {b}" for (a, b), _ in sorted(pairs.items(), key=lambda kv: -kv[1])[:4]]
    return {"flows": flows, "bytes": nbytes, "top": top, "errors": [i["message"] for i in issues if i["level"] == "error"],
            "warnings": [i["message"] for i in issues if i["level"] != "error"]}


def add(db, pm: PolicyManager, data: dict) -> dict:
    """Crée la règle et l'approuve si possible. Retourne {'id','status','note'}."""
    rid = pm.create_rule(data)
    try:
        pm.approve_rule(rid)
        return {"id": rid, "status": "approved", "note": "Règle ajoutée et active dans la politique."}
    except PolicyError as e:
        return {"id": rid, "status": "draft", "note": f"Règle enregistrée mais pas encore active : {e}"}


def plain_rules(db, pm: PolicyManager) -> list[dict]:
    out = []
    for r in pm.rules():
        text = sentence(db, r)
        if r["status"] != "approved":
            state = "À approuver"
        elif not r["enabled"]:
            state = "Désactivée"
        else:
            state = "Active"
        out.append({"id": r["id"], "text": text, "state": state, "action": r["action"], "enabled": bool(r["enabled"]),
                    "status": r["status"], "model": r["source"] != "simple" and r["source"].startswith("template:")})
    return out


def template_cards() -> list[dict]:
    return [{"key": k, "title": v["title"], "description": v["description"]} for k, v in TEMPLATES.items()]


def apply_template(pm: PolicyManager, key: str) -> int:
    ids = pm.apply_template(key)
    try:
        pm.approve_many(ids)
    except PolicyError:
        pass
    return len(ids)
