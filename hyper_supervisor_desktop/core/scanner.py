"""
HSR — Moteur de scan asynchrone des ports TCP
Procus Tech

Fonctionnalités :
  - Scan TCP asynchrone (asyncio) — ne bloque pas l'interface
  - Détection 3 états : ouvert / fermé / filtré
  - Gestion de la baseline (état de référence)
  - Détection des changements vs baseline → génération d'événements
  - Classification INFO / WARNING / CRITICAL
  - Ports sensibles prédéfinis (RDP, SSH, Telnet, etc.)
"""
import asyncio
import socket
import sys
from datetime import datetime
from loguru import logger

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot


# Ports TCP sensibles — tout changement d'état = CRITICAL
SENSITIVE_PORTS = {
    21, 22, 23, 25, 80, 110, 143, 389, 443, 445,
    1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443
}

# Classification des changements
SEVERITY_MAP = {
    ("closed", "open"):    "disaster",   # port fermé → ouvert : critique maximum
    ("filtered", "open"):  "high",       # filtré → ouvert : grave
    ("open", "closed"):    "average",    # ouvert → fermé : moyen
    ("open", "filtered"):  "warning",    # ouvert → filtré : avertissement
}


class PortScanResult:
    __slots__ = ("host", "ip", "port", "protocol", "state", "latency_ms", "service_banner", "service_version", "scanned_at")

    def __init__(self, host: str, ip: str, port: int, state: str, latency_ms: float,
                 protocol: str = "TCP", service_banner: str = None, service_version: str = None):
        self.host = host
        self.ip = ip
        self.port = port
        self.protocol = protocol
        self.state = state
        self.latency_ms = latency_ms
        self.service_banner = service_banner
        self.service_version = service_version
        self.scanned_at = datetime.now().isoformat(timespec='seconds')

    def __repr__(self):
        banner_info = f" ({self.service_version})" if self.service_version else ""
        return f"<Port {self.ip}:{self.port}/{self.protocol} → {self.state} ({self.latency_ms:.1f}ms){banner_info}>"


class ScannerWorker(QObject):
    """
    Worker Qt qui exécute les scans dans un QThread séparé.
    Émet des signaux vers l'UI principale (thread-safe).
    """
    # Signaux
    result_ready    = pyqtSignal(dict)      # un résultat de port
    scan_complete   = pyqtSignal(str, list) # (host_id, résultats)
    change_detected = pyqtSignal(dict)      # un changement vs baseline
    log_message     = pyqtSignal(str, str)  # (level, message)
    progress        = pyqtSignal(int, int)  # (done, total)
    cycle_done      = pyqtSignal()          # fin d'un scan automatique complet

    def __init__(self, db_manager=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.security = security
        self._running = False
        self._stop = False

    def request_stop(self):
        """Arrêt demandé : le cycle s'interrompt entre deux hôtes (thread-safe)."""
        self._stop = True

    # ─────────────────────────────────────────
    # Slots appelables depuis l'UI / le scheduler (exécutés dans le QThread du worker)
    # ─────────────────────────────────────────

    @pyqtSlot(int, str, str)
    def request_scan(self, host_id: int, ip: str, host_name: str):
        """Scan d'un hôte à la demande (bouton « Scan »)."""
        self.scan_host(host_id, ip, host_name, DEFAULT_SCAN_PORTS, udp_ports=DEFAULT_UDP_PORTS)

    @pyqtSlot()
    def scan_all(self):
        """Scan automatique (scheduler) : tous les hôtes supervisés, l'un après l'autre."""
        if not self.db:
            return
        self._stop = False
        hosts = [h for h in self.db.get_all_hosts() if h.get("ip_address")]
        self.log_message.emit("INFO", f"[Scan auto] {len(hosts)} hôte(s) à scanner")
        try:
            for i, h in enumerate(hosts, 1):
                if self._stop:
                    break
                try:
                    self.scan_host(h["id"], h["ip_address"], h["name"], DEFAULT_SCAN_PORTS,
                                   udp_ports=DEFAULT_UDP_PORTS)
                except Exception as e:                  # un hôte en erreur ne bloque pas les autres
                    self.log_message.emit("ERROR", f"[Scan auto] {h.get('name')} : {e}")
                    logger.exception(e)
                self.progress.emit(i, len(hosts))
        finally:
            self.cycle_done.emit()

    def scan_host(self, host_id: int, ip: str, host_name: str,
                  ports: list[int], timeout: float = 1.0, udp_ports: list[int] | None = None):
        """Scanne un hôte (TCP + UDP), compare à la baseline, persiste et notifie les changements."""
        if self.security and not self.security.validate_scan_target(ip):
            self.log_message.emit("ERROR", f"Cible invalide rejetée : {ip}")
            return

        self.log_message.emit(
            "INFO",
            f"Scan démarré : {host_name} ({ip}) — {len(ports)} ports TCP"
            + (f" + {len(udp_ports)} ports UDP" if udp_ports else "")
        )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            # Scan TCP
            results_tcp = loop.run_until_complete(self._async_scan(ip, ports, timeout))
            # Scan UDP (plus rapide, moins complet)
            results_udp = (loop.run_until_complete(self._async_scan_udp(ip, udp_ports, timeout))
                           if udp_ports else [])
            results = results_tcp + results_udp
        finally:
            loop.close()

        changes = []
        if self.db:
            baseline = {
                (row["port"], (row["protocol"] or "TCP").upper()): row["state"]
                for row in self.db.fetchall(
                    "SELECT port, protocol, state FROM baselines WHERE host_id = ?", (host_id,)
                )
            }
            # État du scan précédent (avant d'insérer celui-ci) → évite de ré-alerter à chaque scan
            previous = {
                (row["port"], (row["protocol"] or "TCP").upper()): row["state"]
                for row in self.db.fetchall("""
                    SELECT port, protocol, state FROM port_states
                    WHERE id IN (SELECT MAX(id) FROM port_states
                                 WHERE host_id = ? GROUP BY port, protocol)
                """, (host_id,))
            }

            # Persistance de l'état courant (TCP + UDP + bannière + version)
            for r in results:
                self.db.execute(
                    "INSERT INTO port_states "
                    "(host_id, port, protocol, state, latency_ms, service_banner, service_version) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (host_id, r.port, r.protocol, r.state, r.latency_ms,
                     r.service_banner, r.service_version),
                )
                self.result_ready.emit({
                    "host_name": host_name, "ip": ip, "port": r.port, "protocol": r.protocol,
                    "state": r.state, "latency_ms": r.latency_ms,
                    "service_banner": r.service_banner, "service_version": r.service_version,
                })

            # Statut de l'hôte : une réponse (ouverte OU refusée/RST) prouve qu'il est en ligne
            current = (self.db.get_host_by_id(host_id) or {}).get("status", "unknown")
            if current in ("unknown", "offline") and any(r.state in ("open", "closed") for r in results):
                self.db.update_host_status(
                    host_id, "online", datetime.now().isoformat(timespec="seconds")
                )

            if not baseline and results:
                # Point 4 : première observation → baseline automatique
                for r in results:
                    self.db.execute(
                        "INSERT OR REPLACE INTO baselines (host_id, port, protocol, state) VALUES (?, ?, ?, ?)",
                        (host_id, r.port, r.protocol, r.state),
                    )
                self.log_message.emit(
                    "INFO", f"[Baseline] Créée automatiquement pour {host_name} : {len(results)} ports"
                )
            else:
                for r in results:
                    key = (r.port, r.protocol)
                    base = baseline.get(key)
                    prev = previous.get(key)
                    if base is None:
                        continue
                    if r.protocol == "UDP" and "open" not in (r.state, base):
                        continue        # UDP : « filtré » vs « fermé » n'est pas fiable → on n'alerte que sur « ouvert »
                    if r.state != base and r.state != prev:
                        severity = SEVERITY_MAP.get((base, r.state), "information")
                        if r.port in SENSITIVE_PORTS and severity not in ("disaster", "high"):
                            severity = "high"
                        description = f"Port {r.port}/{r.protocol} : {base} → {r.state}"
                    elif r.state == base and prev is not None and prev != base:
                        severity = "information"
                        description = f"Port {r.port}/{r.protocol} : retour à la baseline ({base})"
                    else:
                        continue

                    change = {
                        "host_id": host_id, "host_name": host_name, "port": r.port,
                        "state_before": prev if prev is not None else base,
                        "state_after": r.state, "severity": severity,
                        "description": description, "event_type": "port_change",
                        "occurred_at": datetime.now().isoformat(timespec="seconds"),
                    }
                    changes.append(change)
                    self.db.add_event(
                        host_id=host_id, host_name=host_name, group_name="",
                        severity=severity, event_type="port_change",
                        description=description, port=r.port,
                        state_before=change["state_before"], state_after=r.state,
                    )
                    self.change_detected.emit(change)
                    self.log_message.emit(
                        severity.upper(),
                        f"[CHANGEMENT] {host_name}:{r.port}/{r.protocol} {change['state_before']}→{r.state}",
                    )

        self.scan_complete.emit(host_name, results)
        open_res = sorted((r for r in results if r.state == "open"), key=lambda r: (r.protocol, r.port))
        opened = [r.port for r in open_res]
        def _lbl(r):
            return f"{r.port}/{r.protocol.lower()}" + (f" {r.service_version}" if r.service_version else "")
        shown = ", ".join(_lbl(r) for r in open_res[:12]) + ("…" if len(open_res) > 12 else "")
        chg = (f"{len(changes)} changement(s) détecté(s) par rapport à la référence"
               if changes else "aucun changement par rapport à la référence")
        self.log_message.emit(
            "INFO",
            f"Scan terminé : {host_name} — {len(opened)} port(s) ouvert(s) sur {len(results)} testés"
            f"{' (' + shown + ')' if opened else ''} · {chg}"
        )

    async def _async_scan(self, ip: str, ports: list[int],
                          timeout: float) -> list[PortScanResult]:
        """Scan TCP asynchrone parallèle."""
        if sys.platform == "win32" and (ip.startswith("127.") or ip == "::1"):
            timeout = max(timeout, 3.0)      # Windows met ~2 s à refuser une connexion locale : sinon « filtré » au lieu de « fermé »
        tasks = [self._check_port(ip, p, timeout) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, PortScanResult)]

    async def _async_scan_udp(self, ip: str, ports: list[int],
                              timeout: float) -> list[PortScanResult]:
        """Scan UDP asynchrone (simplifié : timeouts = filtered)."""
        tasks = [self._check_port_udp(ip, p, timeout) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, PortScanResult)]

    async def _check_port(self, ip: str, port: int,
                          timeout: float) -> PortScanResult:
        """Teste l'état d'un port TCP et extrait la bannière si possible."""
        start = asyncio.get_event_loop().time()
        banner = None
        version = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )

            # Tenter de lire une bannière (certains services la pushent)
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                if data:
                    banner = data.decode('utf-8', errors='ignore').strip()
                    # Extraire la version depuis la bannière
                    version = self._extract_version(banner)
            except (asyncio.TimeoutError, Exception):
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency = (asyncio.get_event_loop().time() - start) * 1000
            return PortScanResult(ip, ip, port, "open", latency,
                                  protocol="TCP", service_banner=banner, service_version=version)

        except asyncio.TimeoutError:
            latency = timeout * 1000
            return PortScanResult(ip, ip, port, "filtered", latency, protocol="TCP")

        except (ConnectionRefusedError, OSError):
            latency = (asyncio.get_event_loop().time() - start) * 1000
            return PortScanResult(ip, ip, port, "closed", latency, protocol="TCP")

    async def _check_port_udp(self, ip: str, port: int,
                              timeout: float) -> PortScanResult:
        """Teste un port UDP (simplifié : voir s'il y a une réponse)."""
        loop = asyncio.get_event_loop()
        start = loop.time()

        def _probe() -> str:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(b"\x00", (ip, port))
                sock.recvfrom(1024)
                return "open"                       # une réponse UDP = service actif
            except socket.timeout:
                return "filtered"                   # silence = ouvert|filtré (UDP ne permet pas de trancher)
            except OSError:
                return "closed"                     # ICMP « port unreachable » reçu
            finally:
                sock.close()

        try:
            state = await loop.run_in_executor(None, _probe)   # ne bloque pas la boucle (10 ports en parallèle)
        except Exception:
            state = "filtered"
        return PortScanResult(ip, ip, port, state, (loop.time() - start) * 1000, protocol="UDP")

    @staticmethod
    def _extract_version(banner: str) -> str:
        """Extrait la version depuis une bannière de service."""
        import re
        # Patterns courants : OpenSSH_7.4, Apache/2.4.41, PostgreSQL 10.5, etc.
        patterns = [
            r'(OpenSSH[_\s]+[\d\.]+)',
            r'(Apache[/\s]+[\d\.]+)',
            r'(nginx[/\s]+[\d\.]+)',
            r'(PostgreSQL[\s]+[\d\.]+)',
            r'(MySQL[\s]+[\d\.]+)',
            r'(Microsoft[_\s]*IIS[\s/]+[\d\.]+)',
            r'(Cisco[\s]+[\d\.]+)',
            r'(version[\s]+[\d\.]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        # Retourner la première partie avant un espace/tiret
        return banner.split()[0] if banner else None

    def create_baseline(self, host_id: int):
        """
        Prend une photo de l'état actuel des ports comme baseline.
        Écrase la baseline précédente pour cet hôte.
        """
        if self.db is None:
            return
        latest_states = self.db.fetchall("""
            SELECT port, COALESCE(protocol, 'TCP') AS protocol, state FROM port_states
            WHERE id IN (SELECT MAX(id) FROM port_states WHERE host_id = ? GROUP BY port, protocol)
        """, (host_id,))

        self.db.execute("DELETE FROM baselines WHERE host_id = ?", (host_id,))
        for row in latest_states:
            self.db.execute(
                "INSERT INTO baselines (host_id, port, protocol, state) VALUES (?, ?, ?, ?)",
                (host_id, row["port"], row["protocol"], row["state"])
            )
        self.log_message.emit(
            "INFO",
            f"Baseline créée pour host_id={host_id} : {len(latest_states)} ports"
        )

    # ─────────────────────────────────────────
    # Scan ICMP (ping) via socket
    # ─────────────────────────────────────────

    @staticmethod
    async def ping_host(ip: str, timeout: float = 1.5) -> tuple[bool, float]:
        """
        Ping rapide via tentative de connexion TCP/80 ou TCP/443.
        Retourne (disponible, latence_ms).
        (Ping ICMP réel nécessiterait des droits root)
        """
        for port in (80, 443, 22, 443):
            start = asyncio.get_event_loop().time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=timeout
                )
                writer.close()
                latency = (asyncio.get_event_loop().time() - start) * 1000
                return True, latency
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                continue
        return False, timeout * 1000


# Ports par défaut pour un scan rapide (MVP)
# Ports TCP à scanner
DEFAULT_SCAN_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 161,
    389, 443, 445, 636, 993, 995, 1433, 1521,
    3306, 3389, 5432, 5900, 8080, 8443, 8888
]

# Ports UDP courants à scanner
DEFAULT_UDP_PORTS = [
    53, 123, 161, 162, 389, 500, 514, 1900, 5353, 5405
]
