"""
Procus Secure — « cet appareil est-il vraiment là ? » : un seul juge pour toute l'application.

Cause du bug « les appareils se connectent / se déconnectent sans arrêt » : deux juges en désaccord. La supervision (toutes les
4 min) acceptait une ancienne entrée de la table ARP comme preuve de présence ; la présence rapide (30 s) la refusait. Un téléphone
en veille (qui ne répond ni au ping ni au TCP) passait donc « en ligne » puis « hors ligne » en boucle.

Règle unique, par appareil, à chaque passage :
  · ping ou connexion TCP réussis                       → PRÉSENT (preuve forte)
  · voisin ARP à l'état « Reachable » (confirmé)         → PRÉSENT (un téléphone en veille répond aux requêtes ARP)
  · voisin « Incomplete / Failed / Unreachable » ou absent après sollicitation → ABSENT (preuve forte)
  · voisin « Stale / Delay / Probe » (ancien, non confirmé) → INCONNU : on ne change RIEN (ni en ligne, ni hors ligne)
Un appareil n'est déclaré hors ligne qu'après ≥ 3 passages absents consécutifs ET le délai de silence réglé (30 s).
"""
from __future__ import annotations

import platform
import subprocess  # nosec B404 - commandes système fixes
import threading
import time
from typing import Optional

from loguru import logger

STATE_WORDS = {"reachable": "reachable", "permanent": "permanent", "stale": "stale", "delay": "stale", "probe": "stale",
               "incomplete": "dead", "failed": "dead", "unreachable": "dead", "noarp": "permanent"}
_lock = threading.Lock()
_cache: dict = {"t": 0.0, "states": None}


def parse_ip_neigh(text: str) -> dict[str, str]:
    """`ip neigh` (Linux) : « 192.168.1.5 dev wlan0 lladdr aa:bb:… REACHABLE »."""
    out = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if parts and parts[0].count(".") == 3 and parts[-1].lower() in STATE_WORDS:
            out[parts[0]] = STATE_WORDS[parts[-1].lower()]
    return out


def parse_powershell_neighbors(text: str) -> dict[str, str]:
    """`Get-NetNeighbor … | ConvertTo-Csv` (Windows) : états en ANGLAIS quelle que soit la langue du système."""
    out = {}
    for line in (text or "").splitlines():
        cells = [c.strip().strip('"') for c in line.split(",")]
        if len(cells) >= 2 and cells[0].count(".") == 3 and cells[1].lower() in STATE_WORDS:
            out[cells[0]] = STATE_WORDS[cells[1].lower()]
    return out



# ───────────── lecture NATIVE de la table des voisins (Windows) : instantanée, indépendante de la langue ─────────────
NL_STATE = {0: "dead", 1: "dead", 2: "stale", 3: "stale", 4: "stale", 5: "reachable", 6: "permanent"}   # NL_NEIGHBOR_STATE
_ROW2 = 88                                                # taille de MIB_IPNET_ROW2 (x64)


def parse_ip_net_table2(buf: bytes, count: int, offset: int = 8) -> dict[str, str]:
    """
    Décode un tableau de MIB_IPNET_ROW2 (GetIpNetTable2). Disposition : adresse SOCKADDR_INET (28 o) · index (4) · LUID (8) ·
    adresse physique (32) · longueur (4) · ÉTAT (4, offset 76) · drapeaux (1) · durée (4). Toute incohérence → {} (on retombe
    sur PowerShell) : jamais de verdict fondé sur une lecture douteuse.
    """
    import socket
    import struct
    out: dict[str, str] = {}
    for i in range(count):
        base = offset + i * _ROW2
        row = buf[base:base + _ROW2]
        if len(row) < _ROW2:
            return {}
        family = struct.unpack_from("<H", row, 0)[0]
        if family != 2:                                   # IPv4 seulement
            continue
        state = struct.unpack_from("<I", row, 76)[0]
        phys_len = struct.unpack_from("<I", row, 72)[0]
        if state > 7 or phys_len > 32:
            return {}                                     # disposition inattendue : on ne s'y fie pas
        out[socket.inet_ntoa(row[4:8])] = NL_STATE.get(state, "stale")
    return out


def _read_states_native() -> Optional[dict[str, str]]:
    try:
        import ctypes
        from ctypes import wintypes
        iphlpapi = ctypes.windll.iphlpapi
        ptr = ctypes.c_void_p()
        if iphlpapi.GetIpNetTable2(2, ctypes.byref(ptr)) != 0 or not ptr.value:        # AF_INET
            return None
        try:
            count = ctypes.cast(ptr, ctypes.POINTER(wintypes.ULONG)).contents.value
            if count > 10000:
                return None
            raw = ctypes.string_at(ptr.value, 8 + count * _ROW2)
            return parse_ip_net_table2(raw, count) or None
        finally:
            iphlpapi.FreeMibTable(ptr)
    except Exception as e:                               # nosec B110 - repli PowerShell
        logger.debug(f"[LIVE] lecture native des voisins indisponible : {e}")
        return None

_refresh = {"running": False, "fail_until": 0.0}
MAX_AGE_S = 120.0                    # au-delà, l'état lu est considéré périmé (on repasse en « illisible »)


def _read_states() -> Optional[dict[str, str]]:
    sysname, states = platform.system(), None
    try:
        if sysname == "Windows":
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",       # nosec B603 B607
                                "Get-NetNeighbor -AddressFamily IPv4 | Select-Object IPAddress,State | ConvertTo-Csv -NoTypeInformation"],
                               capture_output=True, text=True, timeout=30, errors="ignore",
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0:
                states = parse_powershell_neighbors(r.stdout)
        elif sysname == "Linux":
            r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=5, errors="ignore")      # nosec B603 B607
            if r.returncode == 0:
                states = parse_ip_neigh(r.stdout)
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug(f"[LIVE] état des voisins illisible : {e}")
    return states


def _background_refresh():
    try:
        states = _read_states()
        with _lock:
            if states is not None:
                _cache.update(t=time.monotonic(), states=states)
            else:
                _refresh["fail_until"] = time.monotonic() + 60       # on ne relance pas PowerShell en boucle s'il échoue
    finally:
        with _lock:
            _refresh["running"] = False


def neighbor_states(ttl: float = 2.0) -> Optional[dict[str, str]]:
    """
    {ip: reachable|stale|dead|permanent}. None si l'état n'est pas lisible sur ce système (ancien comportement).
    Sous Windows, PowerShell peut mettre plus de 8 s à démarrer : la lecture se fait en ARRIÈRE-PLAN et on renvoie la
    dernière lecture réussie (au plus MAX_AGE_S) ; aucun appel n'attend PowerShell, aucun n'empile de lecture.
    """
    now = time.monotonic()
    with _lock:
        age = now - _cache["t"]
        if platform.system() == "Linux" and age < ttl:
            return _cache["states"]
    if platform.system() == "Windows":
        native_states = _read_states_native()               # instantané ; sinon repli sur PowerShell en arrière-plan
        if native_states is not None:
            with _lock:
                _cache.update(t=time.monotonic(), states=native_states)
            return native_states
    if platform.system() == "Linux":                                  # `ip neigh` est instantané : lecture directe
        states = _read_states()
        with _lock:
            _cache.update(t=time.monotonic(), states=states)
        return states
    with _lock:
        if age >= ttl and not _refresh["running"] and now >= _refresh["fail_until"]:
            _refresh["running"] = True
            threading.Thread(target=_background_refresh, daemon=True, name="liveness-neigh").start()
        return _cache["states"] if (_cache["states"] is not None and age < MAX_AGE_S) else None


def nudge(ips: list[str]) -> None:
    """Oblige le système à reconfirmer ces voisins (requête ARP) ; le résultat se lit au passage suivant. Ne lève jamais."""
    try:
        from core.local_network import _arp_nudge
        _arp_nudge(list(ips), settle_s=0)
    except Exception as e:
        logger.debug(f"[LIVE] sollicitation ARP : {e}")


def arp_hard_dead(ip: str) -> bool:
    """Preuve NETTE de départ : l'état du voisin est lisible et indique « échec / injoignable » (un appareil en veille, lui,
    répond encore à l'ARP et reste « Reachable » ou « Stale »)."""
    st = neighbor_states()
    return bool(st) and st.get(ip) == "dead"


def arp_verdict(ip: str, arp_present: bool) -> Optional[bool]:
    """True présent · False absent · None inconnu. `arp_present` : l'IP figure dans la table ARP simple (repli ancien comportement)."""
    st = neighbor_states()
    if st is None:
        return True if arp_present else False
    s = st.get(ip)
    if s in ("reachable", "permanent"):
        return True
    if s == "dead":
        return False
    if s == "stale":
        return None
    return True if arp_present else False                         # aucune information d'état : la table ARP simple décide
