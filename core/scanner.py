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
from datetime import datetime
from typing import Callable
from loguru import logger

from PyQt6.QtCore import QObject, pyqtSignal, QThread


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
    __slots__ = ("host", "ip", "port", "state", "latency_ms", "scanned_at")

    def __init__(self, host: str, ip: str, port: int, state: str, latency_ms: float):
        self.host = host
        self.ip = ip
        self.port = port
        self.state = state
        self.latency_ms = latency_ms
        self.scanned_at = datetime.now().isoformat(timespec='seconds')

    def __repr__(self):
        return f"<Port {self.ip}:{self.port} → {self.state} ({self.latency_ms:.1f}ms)>"


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

    def __init__(self, db_manager=None, security=None, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self.security = security
        self._running = False

    def scan_host(self, host_id: int, ip: str, host_name: str,
                  ports: list[int], timeout: float = 1.0):
        """Lance le scan d'un hôte (appelé depuis QThread)."""
        if self.security and not self.security.validate_scan_target(ip):
            self.log_message.emit("ERROR", f"Cible invalide rejetée : {ip}")
            return

        self.log_message.emit("INFO", f"Scan démarré : {host_name} ({ip}) — {len(ports)} ports")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(
            self._async_scan(ip, ports, timeout)
        )
        loop.close()

        # Comparaison avec baseline
        changes = []
        if self.db:
            baseline = {
                row["port"]: row["state"]
                for row in self.db.fetchall(
                    "SELECT port, state FROM baselines WHERE host_id = ?", (host_id,)
                )
            }

            for r in results:
                self.result_ready.emit({
                    "host_name": host_name,
                    "ip": ip,
                    "port": r.port,
                    "state": r.state,
                    "latency_ms": r.latency_ms,
                })

                # Sauvegarde état courant
                self.db.execute("""
                    INSERT INTO port_states (host_id, port, state, latency_ms)
                    VALUES (?, ?, ?, ?)
                """, (host_id, r.port, r.state, r.latency_ms))

                # Détection changement
                if r.port in baseline and baseline[r.port] != r.state:
                    state_before = baseline[r.port]
                    state_after = r.state
                    severity = SEVERITY_MAP.get(
                        (state_before, state_after), "information"
                    )
                    if r.port in SENSITIVE_PORTS and severity not in ("disaster", "high"):
                        severity = "high"

                    description = (
                        f"Port {r.port}/TCP : {state_before} → {state_after}"
                    )
                    change = {
                        "host_id": host_id,
                        "host_name": host_name,
                        "port": r.port,
                        "state_before": state_before,
                        "state_after": state_after,
                        "severity": severity,
                        "description": description,
                    }
                    changes.append(change)
                    self.change_detected.emit(change)

                    # Persistance événement
                    self.db.add_event(
                        host_id=host_id, host_name=host_name, group_name="",
                        severity=severity, event_type="port_change",
                        description=description, port=r.port,
                        state_before=state_before, state_after=state_after,
                    )
                    self.log_message.emit(
                        severity.upper(),
                        f"[CHANGEMENT] {host_name}:{r.port} {state_before}→{state_after}"
                    )

        self.scan_complete.emit(host_name, results)
        self.log_message.emit(
            "INFO",
            f"Scan terminé : {host_name} — {len(results)} ports / {len(changes)} changements"
        )

    async def _async_scan(self, ip: str, ports: list[int],
                          timeout: float) -> list[PortScanResult]:
        """Scan TCP asynchrone parallèle."""
        tasks = [self._check_port(ip, p, timeout) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, PortScanResult)]

    async def _check_port(self, ip: str, port: int,
                          timeout: float) -> PortScanResult:
        """Teste l'état d'un port TCP."""
        start = asyncio.get_event_loop().time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency = (asyncio.get_event_loop().time() - start) * 1000
            return PortScanResult(ip, ip, port, "open", latency)

        except asyncio.TimeoutError:
            latency = timeout * 1000
            return PortScanResult(ip, ip, port, "filtered", latency)

        except (ConnectionRefusedError, OSError):
            latency = (asyncio.get_event_loop().time() - start) * 1000
            return PortScanResult(ip, ip, port, "closed", latency)

    def create_baseline(self, host_id: int):
        """
        Prend une photo de l'état actuel des ports comme baseline.
        Écrase la baseline précédente pour cet hôte.
        """
        if self.db is None:
            return
        latest_states = self.db.fetchall("""
            SELECT port, state FROM port_states
            WHERE host_id = ?
              AND scanned_at = (
                  SELECT MAX(scanned_at) FROM port_states ps2
                  WHERE ps2.host_id = port_states.host_id AND ps2.port = port_states.port
              )
        """, (host_id,))

        self.db.execute("DELETE FROM baselines WHERE host_id = ?", (host_id,))
        for row in latest_states:
            self.db.execute(
                "INSERT INTO baselines (host_id, port, state) VALUES (?, ?, ?)",
                (host_id, row["port"], row["state"])
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
DEFAULT_SCAN_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 161,
    389, 443, 445, 636, 993, 995, 1433, 1521,
    3306, 3389, 5432, 5900, 8080, 8443, 8888
]
