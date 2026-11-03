"""
Procus Secure — garde-fou réseau pour les appels sortants (anti-SSRF).

Un webhook/Slack ne doit pas pouvoir viser le réseau interne (127.0.0.1, 192.168.x, 10.x, 169.254.169.254 « métadonnées cloud »…).
Exception volontaire : l'administrateur peut autoriser des hôtes/réseaux internes précis dans le réglage « webhook_allow_internal »
(ex. « 192.168.1.50, 10.0.0.0/24, mattermost.local »). Les redirections HTTP ne sont jamais suivies.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urlparse


def _parse_allow(allow: str) -> tuple[set, list]:
    names, nets = set(), []
    for tok in (allow or "").replace(";", ",").split(","):
        tok = tok.strip().lower()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok, strict=False))
        except ValueError:
            names.add(tok)
    return names, nets


def _forbidden(ip) -> bool:
    return (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or (ip.version == 6 and ip.ipv4_mapped is not None and _forbidden(ip.ipv4_mapped)))


def check_url(url: str, allow_internal: str = "") -> tuple[bool, str]:
    """(ok, raison). Toutes les adresses résolues doivent être publiques, sauf liste d'autorisation."""
    u = urlparse(url or "")
    if u.scheme not in ("http", "https") or not u.hostname:
        return False, "Seules les adresses http:// ou https:// sont acceptées."
    if u.username or u.password:
        return False, "Les identifiants dans l'adresse ne sont pas acceptés."
    host = u.hostname.lower()
    names, nets = _parse_allow(allow_internal)
    try:
        infos = socket.getaddrinfo(host, u.port or (443 if u.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError:
        return False, f"Nom introuvable : {host}"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if _forbidden(ip) and not (host in names or any(ip in n for n in nets)):
            return False, (f"Adresse interne refusée ({ip}). Pour l'autoriser, ajoutez-la dans le réglage "
                           f"« Hôtes internes autorisés pour les webhooks ».")
    return True, ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def open_url(req: urllib.request.Request, timeout: float = 10):
    """urlopen sans suivi des redirections (une redirection pourrait ramener vers une adresse interne)."""
    return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)
