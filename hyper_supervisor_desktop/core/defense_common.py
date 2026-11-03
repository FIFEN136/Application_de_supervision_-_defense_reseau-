"""
Procus Secure — noyau commun de la défense active (v13/v14).

Chaque détection (honeypot, ARP, DHCP, FIM, journaux Sigma, sauvegarde de configuration…) passe par un
EventSink : l'événement est ENREGISTRÉ en base (preuve) puis diffusé aux notifications. Il est rattaché à
un équipement pour que le pipeline d'automatisation (corrélation → incident → priorité) le voie.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Callable, Optional

from loguru import logger

from core import local_network as lnet

SEVERITIES = ("disaster", "high", "average", "warning", "information")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class EventSink:
    def __init__(self, db, on_alert: Optional[Callable[[dict], None]] = None):
        self.db = db
        self.on_alert = on_alert
        self._local_id: Optional[int] = None

    # ── équipement auquel rattacher l'événement ──
    def local_host(self) -> tuple[Optional[int], str]:
        """La machine qui exécute Procus Secure (hôte des honeypots, de la surveillance ARP/DHCP…)."""
        if self._local_id is None:
            try:
                self._local_id = lnet.ensure_local_hosts(self.db).get("local")
            except Exception as e:
                logger.debug(f"[DEF] hôte local indisponible : {e}")
        if self._local_id:
            h = self.db.get_host_by_id(self._local_id) or {}
            return self._local_id, h.get("name", "Machine locale")
        row = self.db.fetchone("SELECT id, name FROM hosts ORDER BY id LIMIT 1")
        return (row["id"], row["name"]) if row else (None, "Procus Secure")

    def host_by_ip(self, ip: str) -> Optional[dict]:
        if not ip:
            return None
        h = self.db.fetchone("SELECT id, name FROM hosts WHERE ip_address = ? ORDER BY id LIMIT 1", (ip,))
        return h

    def host_by_id(self, host_id: Optional[int]) -> Optional[dict]:
        return self.db.fetchone("SELECT id, name FROM hosts WHERE id = ?", (host_id,)) if host_id else None

    # ── enregistrement ──
    def emit(self, severity: str, event_type: str, description: str, host: Optional[dict] = None,
             port: Optional[int] = None, tags: Optional[list] = None, extra: Optional[dict] = None) -> int:
        if severity not in SEVERITIES:
            severity = "warning"
        if not host or not host.get("id"):
            hid, hname = self.local_host()
            host = {"id": hid, "name": hname}
        try:
            eid = self.db.add_event(host_id=host["id"], host_name=host["name"], group_name="",
                                    severity=severity, event_type=event_type, description=description,
                                    port=port, tags=tags)
        except Exception as e:                       # une détection ne doit jamais faire tomber son service
            logger.error(f"[DEF] enregistrement impossible ({event_type}) : {e}")
            return 0
        if self.on_alert:
            try:
                self.on_alert({"host_id": host["id"], "host_name": host["name"], "severity": severity,
                               "event_type": event_type, "description": description, "port": port,
                               "state_before": "", "state_after": "", "event_id": eid, **(extra or {})})
            except Exception as e:
                logger.debug(f"[DEF] notification ignorée : {e}")
        return eid


def safe_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


APP_VERSION = "16.7"          # sert aussi à ré-initialiser la référence d'intégrité de Procus lors d'une mise à jour
