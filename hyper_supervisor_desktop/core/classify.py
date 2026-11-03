"""
Procus Secure — rôles des équipements et zones réseau (v15, bloc 1).

Les règles de filtrage visent des GROUPES (zone, rôle), jamais des adresses IP isolées. Ce module :
  • déduit un rôle par équipement (heuristique : type connu, ports ouverts, fabricant, nom) ;
  • ne remplace JAMAIS un rôle choisi à la main ;
  • crée une zone par réseau supervisé (confiance estimée d'après le type de réseau : Wi-Fi/invités = faible).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional

ROLES = {
    "server": "Serveur", "workstation": "Poste de travail", "network": "Équipement réseau", "printer": "Imprimante",
    "camera": "Caméra", "iot": "Objet connecté", "mobile": "Mobile / tablette", "guest": "Invité",
    "admin": "Poste d'administration", "unknown": "Inconnu",
}
TYPE_TO_ROLE = {"router": "network", "switch": "network", "ap": "network", "firewall": "network", "ups": "iot",
                "server": "server", "workstation": "workstation", "printer": "printer", "mobile": "mobile", "iot": "iot",
                "camera": "camera"}
CAMERA_PORTS = {554, 8554, 37777, 8000}
_CAMERA_NAME = re.compile(r"cam|nvr|dvr|hikvision|dahua|reolink", re.I)


def infer_role(device_type: str, open_ports: set, vendor: str = "", name: str = "") -> tuple[str, str]:
    """(rôle, raison)."""
    ports = set(open_ports or [])
    if _CAMERA_NAME.search(name or "") or (ports & CAMERA_PORTS and not ports & {22, 3389, 445}):
        return "camera", "nom ou ports de flux vidéo"
    t = (device_type or "unknown").lower()
    if t in TYPE_TO_ROLE:
        return TYPE_TO_ROLE[t], f"type « {t} »"
    if ports & {9100, 515, 631}:
        return "printer", "ports d'impression"
    if ports & {3389, 445, 135, 139, 5900}:
        return "workstation", "ports de poste Windows"
    if ports & {22, 80, 443, 8080, 3306, 5432, 1433, 25, 53}:
        return "server", "services serveur ouverts"
    v = vendor or ""
    if v.startswith("Adresse privée"):
        return "mobile", "adresse MAC aléatoire"
    if v.startswith("Espressif") or v == "Raspberry Pi":
        return "iot", f"fabricant {v}"
    return "unknown", "aucun indice"


def classify_hosts(db) -> dict:
    """Met à jour les rôles automatiques. Retourne {'classified': n, 'kept_manual': n}."""
    done = kept = 0
    for h in db.fetchall("SELECT * FROM hosts"):
        cur = db.fetchone("SELECT source FROM host_roles WHERE host_id = ?", (h["id"],))
        if cur and cur["source"] == "manual":
            kept += 1
            continue
        ports = {p["port"] for p in db.fetchall(
            "SELECT port FROM port_states WHERE host_id = ? AND state = 'open' AND UPPER(protocol) = 'TCP'", (h["id"],))}
        role, _ = infer_role(h.get("device_type"), ports, h.get("vendor") or "", h.get("name") or "")
        db.execute("INSERT INTO host_roles (host_id, role, source) VALUES (?, ?, 'auto') "
                   "ON CONFLICT(host_id) DO UPDATE SET role = excluded.role, updated_at = datetime('now')", (h["id"], role))
        done += 1
    return {"classified": done, "kept_manual": kept}


def set_role(db, host_id: int, role: str, who: str = "système"):
    if role not in ROLES:
        raise ValueError(f"Rôle inconnu : {role}")
    if not db.get_host_by_id(host_id):
        raise ValueError("Équipement introuvable.")
    db.execute("INSERT INTO host_roles (host_id, role, source) VALUES (?, ?, 'manual') "
               "ON CONFLICT(host_id) DO UPDATE SET role = excluded.role, source = 'manual', updated_at = datetime('now')",
               (host_id, role))
    db.write_audit(who, "host_role_set", f"host:{host_id}", role)


def role_of(db, host_id: int) -> str:
    r = db.fetchone("SELECT role FROM host_roles WHERE host_id = ?", (host_id,))
    return r["role"] if r else "unknown"


# ───────────── zones ─────────────
def default_trust(kind: str, name: str = "") -> int:
    text = f"{kind} {name}".lower()
    if any(w in text for w in ("invit", "guest", "public")):
        return 5
    if "wifi" in text or "wi-fi" in text:
        return 30
    return 60


def sync_zones(db) -> int:
    """Une zone par réseau supervisé (n'écrase pas les zones créées ou modifiées à la main). Retourne le nombre créé."""
    n = 0
    for net in db.fetchall("SELECT * FROM networks"):
        if db.fetchone("SELECT 1 FROM net_zones WHERE cidr = ?", (net["cidr"],)):
            continue
        name = net["name"]
        if db.fetchone("SELECT 1 FROM net_zones WHERE name = ?", (name,)):
            name = f"{name} ({net['cidr']})"
        db.execute("INSERT INTO net_zones (name, cidr, trust, kind, auto) VALUES (?, ?, ?, ?, 1)",
                   (name, net["cidr"], default_trust(net.get("kind", "lan"), net["name"]), net.get("kind", "lan")))
        n += 1
    return n


def set_zone(db, name: str, cidr: str, trust: int, kind: str = "lan", who: str = "système") -> int:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ValueError("Réseau invalide (exemple : 192.168.1.0/24).") from None
    if not name.strip():
        raise ValueError("Nom de zone requis.")
    if not 0 <= int(trust) <= 100:
        raise ValueError("La confiance doit être comprise entre 0 et 100.")
    db.execute("INSERT INTO net_zones (name, cidr, trust, kind, auto) VALUES (?, ?, ?, ?, 0) "
               "ON CONFLICT(name) DO UPDATE SET cidr = excluded.cidr, trust = excluded.trust, kind = excluded.kind, auto = 0",
               (name.strip(), str(net), int(trust), kind))
    db.write_audit(who, "zone_set", name.strip(), f"{net} confiance {trust}")
    return db.fetchone("SELECT id FROM net_zones WHERE name = ?", (name.strip(),))["id"]


def zone_of_ip(db, ip: str) -> Optional[dict]:
    """Zone la plus précise contenant l'adresse."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best = None
    for z in db.fetchall("SELECT * FROM net_zones"):
        try:
            net = ipaddress.ip_network(z["cidr"], strict=False)
        except ValueError:
            continue
        if a in net and (best is None or net.prefixlen > best[0]):
            best = (net.prefixlen, z)
    return best[1] if best else None
