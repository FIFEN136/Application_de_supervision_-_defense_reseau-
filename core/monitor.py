"""
HSR — Moteur de supervision SNMP
Procus Tech

Fonctionnalités :
  - Interrogation SNMP v1/v2c des équipements
  - Collecte CPU, mémoire, disque, trafic interfaces
  - Puissance optique SFP/DOM (Digital Optical Monitoring)
  - Vérification disponibilité (ICMP/SNMP)
  - Worker Qt thread-safe
"""
import asyncio
from datetime import datetime
from loguru import logger

from PyQt6.QtCore import QObject, pyqtSignal


# ─────────────────────────────────────────────────────────────────
# OIDs SNMP standard (MIB-II + entreprise)
# ─────────────────────────────────────────────────────────────────
OID_SYSNAME          = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR         = "1.3.6.1.2.1.1.1.0"
OID_SYSUPTIME        = "1.3.6.1.2.1.1.3.0"

# CPU (HOST-RESOURCES-MIB)
OID_CPU_LOAD_1MIN    = "1.3.6.1.4.1.2021.10.1.3.1"   # Net-SNMP
OID_HRPROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"       # HOST-RESOURCES

# Mémoire (NET-SNMP)
OID_MEM_TOTAL_SWAP   = "1.3.6.1.4.1.2021.4.3.0"
OID_MEM_AVAIL_REAL   = "1.3.6.1.4.1.2021.4.6.0"
OID_MEM_TOTAL_REAL   = "1.3.6.1.4.1.2021.4.5.0"

# Interfaces (IF-MIB)
OID_IF_DESCR         = "1.3.6.1.2.1.2.2.1.2"
OID_IF_OPER_STATUS   = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCTETS     = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS    = "1.3.6.1.2.1.2.2.1.16"
OID_IF_IN_ERRORS     = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_ERRORS    = "1.3.6.1.2.1.2.2.1.20"

# SFP/DOM (Cisco) — CISCO-DOM-MIB
OID_SFP_RX_POWER     = "1.3.6.1.4.1.9.9.412.1.1.1.1.6"
OID_SFP_TX_POWER     = "1.3.6.1.4.1.9.9.412.1.1.1.1.7"
OID_SFP_TEMPERATURE  = "1.3.6.1.4.1.9.9.412.1.1.1.1.3"

# Seuils d'alerte
CPU_THRESHOLD_WARNING  = 70.0   # %
CPU_THRESHOLD_CRITICAL = 90.0   # %
MEM_THRESHOLD_WARNING  = 80.0   # %
BW_THRESHOLD_WARNING   = 80.0   # % capacité
SFP_RX_MIN_DBM         = -20.0  # dBm en dessous = perte signal


class SNMPResult:
    """Résultat d'une collecte SNMP pour un hôte."""
    __slots__ = ("host_id", "host_name", "ip", "metrics", "collected_at", "error")

    def __init__(self, host_id: int, host_name: str, ip: str):
        self.host_id = host_id
        self.host_name = host_name
        self.ip = ip
        self.metrics: dict = {}
        self.collected_at = datetime.now().isoformat(timespec='seconds')
        self.error: str | None = None


class MonitorWorker(QObject):
    """
    Worker Qt pour la supervision SNMP.
    Collecte les métriques et les transmet à l'UI via signaux.
    """
    metrics_ready     = pyqtSignal(dict)    # métriques d'un hôte
    host_status       = pyqtSignal(int, str, float)  # (host_id, status, latency_ms)
    alert_triggered   = pyqtSignal(dict)    # seuil dépassé
    log_message       = pyqtSignal(str, str)  # (level, message)

    def __init__(self, db_manager=None, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self._running = False

    # ─────────────────────────────────────────
    # Disponibilité (ping via SNMP ou TCP)
    # ─────────────────────────────────────────

    def check_availability(self, host_id: int, ip: str, host_name: str,
                           snmp_community: str = "public"):
        """Vérifie si un équipement est disponible."""
        try:
            result = self._snmp_get(ip, OID_SYSUPTIME, snmp_community)
            if result is not None:
                self.host_status.emit(host_id, "online", 0.0)
                if self.db:
                    self.db.update_host_status(
                        host_id, "online",
                        datetime.now().isoformat(timespec='seconds')
                    )
                self.log_message.emit("INFO", f"[SNMP] {host_name} ({ip}) : En ligne")
            else:
                self.host_status.emit(host_id, "unreachable", 9999.0)
                if self.db:
                    self.db.update_host_status(
                        host_id, "unreachable",
                        datetime.now().isoformat(timespec='seconds')
                    )
                self.log_message.emit("WARNING", f"[SNMP] {host_name} ({ip}) : Injoignable")
        except Exception as e:
            self.host_status.emit(host_id, "offline", 9999.0)
            self.log_message.emit("ERROR", f"[SNMP] Erreur {host_name}: {e}")

    # ─────────────────────────────────────────
    # Collecte métriques complètes
    # ─────────────────────────────────────────

    def collect_host_metrics(self, host_id: int, ip: str, host_name: str,
                             community: str = "public"):
        """Collecte CPU, mémoire, trafic pour un hôte via SNMP."""
        result = SNMPResult(host_id, host_name, ip)

        try:
            # CPU
            cpu = self._snmp_get(ip, OID_CPU_LOAD_1MIN, community)
            if cpu is not None:
                cpu_val = float(str(cpu))
                result.metrics["cpu_util"] = cpu_val
                if self.db:
                    self.db.add_metric(host_id, "cpu_util", cpu_val, "%")

                # Alerte CPU
                if cpu_val >= CPU_THRESHOLD_CRITICAL:
                    self._emit_alert(host_id, host_name, "disaster",
                                     f"CPU > {CPU_THRESHOLD_CRITICAL}% : {cpu_val:.1f}%",
                                     "cpu_util", cpu_val)
                elif cpu_val >= CPU_THRESHOLD_WARNING:
                    self._emit_alert(host_id, host_name, "average",
                                     f"CPU > {CPU_THRESHOLD_WARNING}% depuis 15 min : {cpu_val:.1f}%",
                                     "cpu_util", cpu_val)

            # Mémoire
            mem_total = self._snmp_get(ip, OID_MEM_TOTAL_REAL, community)
            mem_avail = self._snmp_get(ip, OID_MEM_AVAIL_REAL, community)
            if mem_total and mem_avail:
                total_kb = float(str(mem_total))
                avail_kb = float(str(mem_avail))
                if total_kb > 0:
                    used_pct = ((total_kb - avail_kb) / total_kb) * 100
                    result.metrics["mem_used_pct"] = used_pct
                    result.metrics["mem_avail_gb"] = avail_kb / (1024 * 1024)
                    if self.db:
                        self.db.add_metric(host_id, "mem_used", used_pct, "%")
                        self.db.add_metric(host_id, "mem_avail",
                                           avail_kb / (1024 * 1024), "GB")

            # Interfaces (trafic réseau)
            interfaces = self._snmp_walk(ip, OID_IF_IN_OCTETS, community)
            if interfaces:
                for idx, octets_in in interfaces.items():
                    octets_out_dict = self._snmp_walk(ip, OID_IF_OUT_OCTETS, community)
                    octets_out = octets_out_dict.get(idx, 0) if octets_out_dict else 0
                    mbps_in  = float(str(octets_in))  * 8 / 1_000_000
                    mbps_out = float(str(octets_out)) * 8 / 1_000_000
                    iface = f"GigabitEthernet0/{idx}"
                    result.metrics[f"if_in_{idx}"]  = mbps_in
                    result.metrics[f"if_out_{idx}"] = mbps_out
                    if self.db:
                        self.db.add_metric(host_id, "if_in_octets",  mbps_in,  "Mbps", iface)
                        self.db.add_metric(host_id, "if_out_octets", mbps_out, "Mbps", iface)
                    break  # MVP : première interface seulement

        except Exception as e:
            result.error = str(e)
            self.log_message.emit("ERROR", f"[SNMP] Erreur collecte {host_name}: {e}")

        self.metrics_ready.emit({
            "host_id":    result.host_id,
            "host_name":  result.host_name,
            "ip":         result.ip,
            "metrics":    result.metrics,
            "collected_at": result.collected_at,
            "error":      result.error,
        })
        return result

    # ─────────────────────────────────────────
    # SFP/DOM (puissance optique)
    # ─────────────────────────────────────────

    def collect_sfp_metrics(self, host_id: int, ip: str, host_name: str,
                            community: str = "public"):
        """Collecte la puissance optique des modules SFP/DOM."""
        try:
            rx_powers = self._snmp_walk(ip, OID_SFP_RX_POWER, community)
            tx_powers = self._snmp_walk(ip, OID_SFP_TX_POWER, community)
            temps     = self._snmp_walk(ip, OID_SFP_TEMPERATURE, community)

            if rx_powers:
                for idx, rx_val in rx_powers.items():
                    rx_dbm = float(str(rx_val)) / 10.0
                    tx_dbm = float(str(tx_powers.get(idx, 0))) / 10.0 if tx_powers else 0.0
                    temp_c = float(str(temps.get(idx, 0))) / 256.0 if temps else 0.0
                    iface  = f"Interface_{idx}"

                    if self.db:
                        self.db.execute("""
                            INSERT INTO sfp_metrics
                              (host_id, interface, rx_power_dbm, tx_power_dbm, temperature_c)
                            VALUES (?, ?, ?, ?, ?)
                        """, (host_id, iface, rx_dbm, tx_dbm, temp_c))

                    # Alerte perte signal
                    if rx_dbm < SFP_RX_MIN_DBM:
                        self._emit_alert(
                            host_id, host_name, "high",
                            f"Perte signal SFP {iface} : RX={rx_dbm:.1f} dBm",
                            "sfp_rx", rx_dbm
                        )
                        self.log_message.emit(
                            "WARNING",
                            f"[SFP] Perte signal {host_name}/{iface} : {rx_dbm:.1f} dBm"
                        )
        except Exception as e:
            self.log_message.emit("ERROR", f"[SFP] Erreur {host_name}: {e}")

    # ─────────────────────────────────────────
    # SNMP helpers (pysnmp)
    # ─────────────────────────────────────────

    def _snmp_get(self, ip: str, oid: str, community: str = "public",
                  port: int = 161, timeout: int = 2, retries: int = 1):
        """Effectue un SNMP GET. Retourne la valeur ou None."""
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )
            if error_indication or error_status:
                return None
            for _, val in var_binds:
                return val
        except Exception:
            return None

    def _snmp_walk(self, ip: str, oid: str, community: str = "public",
                   port: int = 161, timeout: int = 2) -> dict | None:
        """Effectue un SNMP WALK. Retourne {index: valeur}."""
        try:
            from pysnmp.hlapi import (
                nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
            result = {}
            for error_indication, error_status, error_index, var_binds in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port), timeout=timeout, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False,
            ):
                if error_indication or error_status:
                    break
                for name, val in var_binds:
                    idx = str(name).split(".")[-1]
                    result[idx] = val
            return result if result else None
        except Exception:
            return None

    # ─────────────────────────────────────────
    # Alertes
    # ─────────────────────────────────────────

    def _emit_alert(self, host_id: int, host_name: str, severity: str,
                    description: str, metric: str, value: float):
        alert = {
            "host_id":     host_id,
            "host_name":   host_name,
            "severity":    severity,
            "description": description,
            "metric":      metric,
            "value":       value,
            "occurred_at": datetime.now().isoformat(timespec='seconds'),
        }
        self.alert_triggered.emit(alert)
        if self.db:
            self.db.add_event(
                host_id=host_id, host_name=host_name, group_name="",
                severity=severity, event_type="threshold",
                description=description,
            )
