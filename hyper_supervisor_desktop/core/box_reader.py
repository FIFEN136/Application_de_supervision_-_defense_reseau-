"""
Procus Secure — lecture FACULTATIVE de la box (Bbox) : Wi-Fi/Ethernet réel, bande, signal et port de chaque appareil.

Désactivée par défaut. Lecture seule, réseau local uniquement (adresse privée exigée), mot de passe chiffré (CryptoHelper).
L'analyse de la réponse est tolérante : elle cherche, où qu'ils soient, des enregistrements portant une adresse MAC, et dit
clairement ce qu'elle a trouvé ou non. Aucune donnée n'est inventée.
"""
from __future__ import annotations

import http.cookiejar
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from loguru import logger

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class BoxError(Exception):
    pass


def check_box_address(addr: str) -> str:
    """Adresse IP privée (ou nom local) uniquement : jamais d'Internet."""
    a = (addr or "").strip().replace("http://", "").replace("https://", "").strip("/")
    if not a:
        raise BoxError("Adresse de la box manquante (souvent 192.168.1.254).")
    try:
        ip = ipaddress.ip_address(a)
        if not ip.is_private or ip.is_loopback:
            raise BoxError("L'adresse de la box doit être une adresse du réseau local (ex. 192.168.1.254).")
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,60}", a):
            raise BoxError("Adresse invalide.")
    return a


def _norm_mac(s) -> Optional[str]:
    m = str(s or "").strip().lower().replace("-", ":")
    return m if MAC_RE.match(m) else None


def parse_hosts(payload) -> list[dict]:
    """Liste normalisée [{mac, ip, name, type, band, rssi, port, link_mbps, active}] depuis une réponse JSON de la box."""
    recs = []

    def walk(o):
        if isinstance(o, dict):
            if any(k.lower() in ("macaddress", "mac") for k in o) and _norm_mac(o.get("macaddress") or o.get("mac")):
                recs.append(o)
            else:
                for v in o.values():
                    walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(payload)
    out = []
    for r in recs:
        link = str(r.get("link") or r.get("interface") or r.get("type") or "").lower()
        wl = r.get("wireless") if isinstance(r.get("wireless"), dict) else {}
        eth = r.get("ethernet") if isinstance(r.get("ethernet"), dict) else {}
        is_wifi = "wifi" in link or "wi-fi" in link or "wlan" in link or "wireless" in link or bool(wl)
        is_eth = "ethernet" in link or "lan" in link and not is_wifi or bool(eth)
        band = str(wl.get("band") or "")
        m = re.search(r"(2\.4|5|6)\s*(?:g|ghz)?", band or link)
        rssi = wl.get("rssi0") if wl.get("rssi0") is not None else wl.get("rssi")
        port = eth.get("physicalport") or eth.get("port")
        speed = eth.get("speed") or wl.get("txrate") or wl.get("rate")
        try:
            rssi = int(rssi) if rssi not in (None, "") else None
        except (TypeError, ValueError):
            rssi = None
        try:
            speed = int(float(speed)) if speed not in (None, "") else None
        except (TypeError, ValueError):
            speed = None
        out.append({
            "mac": _norm_mac(r.get("macaddress") or r.get("mac")), "ip": str(r.get("ipaddress") or r.get("ip") or ""),
            "name": str(r.get("hostname") or r.get("name") or "")[:60],
            "type": "wifi" if is_wifi else "ethernet" if is_eth else None,
            "band": m.group(1) if (is_wifi and m) else None, "rssi": rssi if rssi is not None and -100 <= rssi <= 0 else None,
            "port": str(port) if port not in (None, "") else None, "link_mbps": speed,
            "active": str(r.get("active", "1")).lower() not in ("0", "false", "no"),
        })
    return out


class BoxReader:
    """Client de l'API locale de la box. Cookies et redirections gérés à la main : les redirections http→https de la box ne perdent
    plus la connexion, et un cookie « Secure » est quand même renvoyé (la box répond en http sur le réseau local)."""
    CANDIDATES = (("http", 80), ("https", 443))

    def __init__(self, address: str, password: str, timeout: float = 6.0):
        self.addr = check_box_address(address)
        self.password = password or ""
        self.timeout = timeout
        self.cookies: dict[str, str] = {}
        self.base = self.CANDIDATES[0]
        self.steps: list[dict] = []
        if ":" in self.addr:                                  # « adresse:port » : un seul essai, sur ce port (http)
            host, _, port = self.addr.rpartition(":")
            self.CANDIDATES = (("http", int(port)),) if port.isdigit() else self.CANDIDATES
            self.addr = host

    def _step(self, name: str, ok: bool, detail: str = ""):
        self.steps.append({"step": name, "ok": ok, "detail": detail})

    def _http(self, scheme: str, port: int, method: str, path: str, data: Optional[dict] = None, hops: int = 3):
        import http.client
        host = self.addr
        body = urllib.parse.urlencode(data) if data is not None else None
        hdr = {"Accept": "application/json", "User-Agent": "ProcusSecure"}
        if body is not None:
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookies:
            hdr["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False                    # certificat auto-signé de la box ; adresse privée imposée
            ctx.verify_mode = ssl.CERT_NONE               # nosec B501
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        try:
            conn.request(method, path, body=body, headers=hdr)
            r = conn.getresponse()
            raw = r.read(2_000_000)
            for sc in r.headers.get_all("Set-Cookie") or []:
                nv = sc.split(";", 1)[0]
                if "=" in nv:
                    k, v = nv.split("=", 1)
                    self.cookies[k.strip()] = v.strip()
            status, loc = r.status, r.headers.get("Location")
        finally:
            conn.close()
        if status in (301, 302, 303, 307, 308) and loc and hops > 0:
            u = urllib.parse.urlparse(loc)
            ns = u.scheme or scheme
            np = u.port or (443 if ns == "https" else 80)
            npath = (u.path or "/") + (("?" + u.query) if u.query else "")
            return self._http(ns, np, method, npath, data, hops - 1)        # même adresse IP, on ignore le nom d'hôte de la redirection
        return status, raw.decode("utf-8", "ignore")

    def login(self) -> tuple[str, int]:
        last = ""
        for scheme, port in self.CANDIDATES:
            try:
                st, body = self._http(scheme, port, "POST", "/api/v1/login", {"password": self.password, "remember": "1"})
            except (OSError, ValueError) as e:
                self._step(f"Connexion {scheme}://{self.addr}:{port}", False, f"{type(e).__name__} — port fermé ou box injoignable")
                last = type(e).__name__
                continue
            self._step(f"Connexion {scheme}://{self.addr}:{port}", True, f"la box répond (code {st})")
            if st in (200, 204):
                self._step("Mot de passe", True, "accepté")
                self.base = (scheme, port)
                return scheme, port
            if st in (401, 403):
                self._step("Mot de passe", False, "refusé : c'est le mot de passe d'ADMINISTRATION de la box (pas celui du Wi-Fi)")
                raise BoxError("Mot de passe refusé par la box. Utilisez le mot de passe d'administration (celui de mabbox.bytel.fr), pas celui du Wi-Fi.")
            if st == 429:
                raise BoxError("La box bloque temporairement les essais (trop de tentatives). Attendez 5 à 10 minutes puis réessayez.")
            if st == 404:
                self._step("Interface de la box", False, "adresse trouvée mais ce n'est pas l'API Bbox (code 404)")
                last = "404"
                continue
            last = f"code {st}"
        raise BoxError(f"Box injoignable ou interface locale non disponible ({last}). Vérifiez l'adresse (ipconfig → Passerelle par défaut) et que vous êtes sur le Wi-Fi/câble de cette box.")

    def read_hosts(self) -> list[dict]:
        scheme, port = self.login()
        for path in ("/api/v1/hosts", "/api/v1/hosts/lan"):
            try:
                st, body = self._http(scheme, port, "GET", path)
                self._step(f"Liste des appareils {path}", st == 200, f"code {st}")
                if st != 200:
                    continue
                hosts = parse_hosts(json.loads(body or "null"))
            except (OSError, ValueError) as e:
                self._step(f"Liste des appareils {path}", False, type(e).__name__)
                continue
            if hosts:
                self._step("Appareils reconnus", True, f"{len(hosts)}")
                return hosts
            self._step("Appareils reconnus", False, "réponse reçue mais format non reconnu")
        raise BoxError("La box répond mais n'expose pas la liste des appareils (ou son format n'est pas reconnu). Copiez le diagnostic pour que je l'adapte.")

    def logout(self):
        try:
            self._http(self.base[0], self.base[1], "POST", "/api/v1/logout", {})
        except Exception:
            pass


def diagnose(address: str, password: str) -> str:
    """Diagnostic pas à pas, sans mot de passe, copiable."""
    r = None
    try:
        r = BoxReader(address, password)
        hosts = r.read_hosts()
        r.logout()
        r._step("Résultat", True, f"{len(hosts)} appareil(s) lu(s)")
    except BoxError as e:
        if r:
            r._step("Résultat", False, str(e))
    except Exception as e:
        if r:
            r._step("Résultat", False, f"erreur {type(e).__name__}")
    return "\n".join(f"{'OK    ' if s['ok'] else 'ÉCHEC '} {s['step']} — {s['detail']}" for s in (r.steps if r else []))


# ───────────── réglages et application ─────────────
def settings(db) -> dict:
    from core.security import CryptoHelper
    pwd = db.get_setting("box_password", "")
    try:
        pwd = CryptoHelper.decrypt(pwd) if pwd else ""
    except Exception:
        pwd = ""
    return {"enabled": db.get_setting("box_enabled", "0") == "1", "address": db.get_setting("box_address", ""), "password": pwd}


def save_settings(db, enabled: bool, address: str, password: str) -> None:
    from core.security import CryptoHelper
    if address.strip():
        address = check_box_address(address)
    token = CryptoHelper.encrypt(password) if password else ""
    if password and token == password:
        raise BoxError("Chiffrement indisponible : mot de passe non enregistré.")
    db.set_setting("box_enabled", "1" if enabled else "0")
    db.set_setting("box_address", address.strip())
    if password or not enabled:
        db.set_setting("box_password", token)


def test_connection(address: str, password: str) -> tuple[bool, str]:
    try:
        r = BoxReader(address, password)
    except BoxError as e:
        return False, str(e)
    try:
        hosts = r.read_hosts()
        r.logout()
    except BoxError as e:
        return False, str(e) + "\n\nDétail :\n" + "\n".join(f"{'OK' if x['ok'] else 'ÉCHEC'} {x['step']} — {x['detail']}" for x in r.steps)
    n_w, n_e = sum(h["type"] == "wifi" for h in hosts), sum(h["type"] == "ethernet" for h in hosts)
    return True, f"Connexion réussie : {len(hosts)} appareil(s) lus ({n_w} en Wi-Fi, {n_e} en Ethernet)."


def apply_hosts(db, boxhosts: list[dict]) -> int:
    """Écrit la connexion réelle lue sur la box (sans écraser un choix manuel). Retourne le nombre de fiches modifiées."""
    by_mac = {h["mac"]: h for h in boxhosts if h.get("mac")}
    n = 0
    for h in db.get_all_hosts():
        b = by_mac.get((h.get("mac_address") or "").lower())
        if not b or not b["type"] or h.get("conn_source") == "manual":
            continue
        detail = f"port {b['port']}" if b["type"] == "ethernet" and b["port"] else (f"Wi-Fi {b['band']} GHz" if b["band"] else "")
        new = (b["type"], detail, "box", b["rssi"], b["band"], b["link_mbps"])
        old = (h.get("conn_type"), h.get("conn_detail") or "", h.get("conn_source"), h.get("rssi"), h.get("wifi_band"), h.get("link_mbps"))
        if new != old:
            db.execute("UPDATE hosts SET conn_type = ?, conn_detail = ?, conn_source = 'box', rssi = ?, wifi_band = ?, link_mbps = ? WHERE id = ?",
                       (b["type"], detail, b["rssi"], b["band"], b["link_mbps"], h["id"]))
            n += 1
    return n


def refresh_from_box(db) -> int:
    s = settings(db)
    if not s["enabled"] or not s["address"]:
        return 0
    try:
        r = BoxReader(s["address"], s["password"])
        hosts = r.read_hosts()
        r.logout()
    except BoxError as e:
        logger.warning(f"[BOX] {e}")
        return 0
    return apply_hosts(db, hosts)
