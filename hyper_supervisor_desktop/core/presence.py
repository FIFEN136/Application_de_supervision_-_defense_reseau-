"""
Procus Secure — présence rapide des appareils (carte réseau).

Un appareil « en ligne » qui ne donne AUCUN signe de vie pendant `presence_grace_s` secondes (30 par défaut) passe
immédiatement « hors ligne » : il devient rouge sur la carte et un événement est enregistré. Il repasse « en ligne »
dès qu'il répond de nouveau. Signes de vie : ping, connexion TCP (même refusée) ; l'ancienne entrée ARP ne compte pas
pour un appareil qui répond d'habitude au ping (elle reste en mémoire plusieurs minutes après son départ).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from loguru import logger

DEFAULT_GRACE_S = 30
MIN_GRACE_S, MAX_GRACE_S = 10, 600


def grace_seconds(db) -> int:
    try:
        return max(MIN_GRACE_S, min(MAX_GRACE_S, int(db.get_setting("presence_grace_s", str(DEFAULT_GRACE_S)))))
    except (TypeError, ValueError):
        return DEFAULT_GRACE_S


FLAP_WINDOW_S = 21600                                    # mémoire des bascules : 6 h (un appareil capricieux le reste, il ne « guérit » pas en 10 min)
SLEEPY_TYPES = ("mobile", "iot", "tv")                   # appareils qui se mettent en veille et répondent par intermittence


def required_silence_s(host: dict, base_s: int, now: Optional[float] = None) -> int:
    """
    Silence exigé avant « hors ligne » : le délai de base (30 s) pour un appareil stable ; plus long pour un téléphone ou
    un objet connecté (veille radio) et pour tout appareil qui a basculé 2 fois ou plus dans les 6 dernières heures.
    Résultat : un appareil est soit en ligne, soit hors ligne, sans clignoter.
    """
    now = time.time() if now is None else now
    need = base_s
    if (host.get("device_type") or "").lower() in SLEEPY_TYPES:
        need = max(need, 120)
    recent = [float(x) for x in (host.get("flap_log") or "").split(",") if x.replace(".", "", 1).isdigit()
              and now - float(x) <= FLAP_WINDOW_S]
    if len(recent) >= 4:
        need = max(need, 600)
    elif len(recent) >= 2:
        need = max(need, 300)
    return need


_HARD: dict = {}                                         # id appareil → passages consécutifs avec preuve nette de départ
MIN_MISSES = 3                                           # passages « absent » consécutifs avant hors ligne


def probe_alive(host: dict) -> Optional[bool]:
    """True présent · False absent · None inconnu (même juge que la supervision : core/liveness.py)."""
    from core import local_network as lnet
    r = lnet.probe_host_ex(host["ip_address"], timeout=0.8)
    if r.get("hard") and not r["alive"]:
        return "gone"                                    # preuve nette de départ (ARP en échec) : voir presence_step
    if r.get("unsure"):
        return None
    return bool(r["alive"])


def presence_step(db, grace_s: int, now: Optional[float] = None, probe: Optional[Callable[[dict], Optional[bool]]] = None,
                  tick: int = 0, workers: int = 16) -> list[dict]:
    """Un passage. Retourne les changements [{host, old, new, silent_s}]. Hors ligne seulement si silence ≥ grace_s ET ≥ 3 absences
    consécutives ; « inconnu » ne compte ni comme présent ni comme absent. Les hors ligne ne sont resondés qu'un passage sur 3."""
    now = time.time() if now is None else now
    probe = probe or probe_alive
    hosts = [h for h in db.active_hosts() if h.get("ip_address")]      # réseaux suspendus : ignorés
    todo = [h for h in hosts if (h.get("status") or "unknown") in ("online", "unknown", "unreachable") or tick % 3 == 0]
    if not todo:
        return []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        verdicts = list(ex.map(lambda h: _safe(probe, h), todo))
    changes = []
    for h, ok in zip(todo, verdicts):
        hard = ok == "gone"                              # preuve nette de départ (l'ARP échoue, ce que fait un appareil parti)
        if hard:
            ok = False
            _HARD[h["id"]] = _HARD.get(h["id"], 0) + 1
        elif ok is not None:
            _HARD[h["id"]] = 0                           # une réponse, ou un simple silence : pas de preuve nette
        status = h.get("status") or "unknown"
        last = h.get("last_alive_ts")
        if ok is True:
            db.execute("UPDATE hosts SET last_alive_ts = ?, failed_probes = 0 WHERE id = ?", (int(now), h["id"]))
            if status == "offline":
                db.update_host_status(h["id"], "online", _iso(now), at=now)
                changes.append({"host": h, "old": status, "new": "online", "silent_s": 0})
            continue
        if ok is None:
            if last is None:
                db.execute("UPDATE hosts SET last_alive_ts = ? WHERE id = ?", (int(now), h["id"]))
            continue
        if last is None:                                # première observation : on part de maintenant (pas de fausse alerte au démarrage)
            db.execute("UPDATE hosts SET last_alive_ts = ? WHERE id = ?", (int(now), h["id"]))
            continue
        misses = min(int(h.get("failed_probes") or 0) + 1, 99)
        silent = now - float(last)
        need = required_silence_s(h, grace_s, now)         # simple silence : prudent (téléphones et appareils capricieux)
        if _HARD.get(h["id"], 0) >= 2:                      # départ PROUVÉ (ARP en échec 2 passages de suite) : rapide
            need = grace_s if need <= 120 else 120          # un appareil déjà capricieux attend tout de même 2 min
        if status == "online" and silent >= need and misses >= MIN_MISSES:
            db.execute("UPDATE hosts SET failed_probes = 99 WHERE id = ?", (h["id"],))
            db.update_host_status(h["id"], "offline", _iso(now), at=now)
            changes.append({"host": h, "old": status, "new": "offline", "silent_s": int(silent)})
        elif status != "offline":
            db.execute("UPDATE hosts SET failed_probes = ? WHERE id = ?", (misses, h["id"]))
    return changes


def _safe(probe, h) -> Optional[bool]:
    try:
        v = probe(h)
        return v if v in (None, "gone") else bool(v)
    except Exception as e:
        logger.debug(f"[PRESENCE] {h.get('ip_address')} : {e}")
        return None                                      # en cas de doute : inconnu, on ne change rien


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))
