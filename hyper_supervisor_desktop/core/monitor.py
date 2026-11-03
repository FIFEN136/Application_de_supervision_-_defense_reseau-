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
import contextlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from loguru import logger

from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot

from core import local_network as lnet


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
OID_SS_CPU_IDLE      = "1.3.6.1.4.1.2021.11.11.0"   # UCD : % CPU inactif
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
    Worker Qt pour la supervision (SNMP + machine locale).
    Collecte les métriques, les persiste en base et les transmet à l'UI via signaux.
    """
    metrics_ready     = pyqtSignal(dict)    # métriques d'un hôte
    host_status       = pyqtSignal(int, str, float)  # (host_id, status, latency_ms)
    alert_triggered   = pyqtSignal(dict)    # seuil dépassé / hôte down
    log_message       = pyqtSignal(str, str)  # (level, message)
    cycle_done        = pyqtSignal(int)     # nombre d'hôtes traités

    FLAP_THRESHOLD = 3        # échecs consécutifs avant « hors ligne » (anti-flapping)
    ALERT_COOLDOWN_S = 1800   # une même alerte n'est re-notifiée qu'au bout de 30 min

    def __init__(self, db_manager=None, parent=None):
        super().__init__(parent)
        self.db = db_manager
        self._running = False
        self._stop = False
        self._sampler = lnet.BandwidthSampler()
        self._sampler.sample()                      # amorçage : le 1er delta sera valide
        self._prev_octets: dict[int, tuple[float, int, int]] = {}   # host_id → (t, in, out)
        self._last_alert: dict[tuple, float] = {}
        self._presence_busy, self._presence_n = False, 0

    # ─────────────────────────────────────────
    # Cycle complet (déclenché par le scheduler)
    # ─────────────────────────────────────────

    def request_stop(self):
        """Demande l'arrêt du cycle en cours (thread-safe : simple drapeau lu entre deux hôtes)."""
        self._stop = True

    @pyqtSlot()
    def collect_all(self):
        """
        Cycle complet : sondes de disponibilité EN PARALLÈLE (16 à la fois, un /24 reste rapide),
        puis collecte des métriques des hôtes vivants, l'un après l'autre.
        """
        if not self.db:
            return
        self._stop = False
        hosts = [h for h in self.db.active_hosts() if h.get("ip_address")]      # réseaux suspendus : ignorés
        done = 0
        try:
            def probe(h):
                r = lnet.probe_host_ex(h["ip_address"])
                alive = r["alive"]
                snmp_ok = None                      # None = SNMP non attendu pour cet hôte
                if alive and self._snmp_expected(h):
                    snmp_ok = self._snmp_alive(h)
                return alive, r["latency_ms"], snmp_ok, r["method"]
            with ThreadPoolExecutor(max_workers=16) as ex:
                probes = list(ex.map(probe, hosts))
            for h, (alive, latency, snmp_ok, method) in zip(hosts, probes):
                if self._stop:
                    break
                if method == "arp-unsure":                  # preuve insuffisante : on ne change pas l'état (évite le yo-yo en ligne / hors ligne)
                    done += 1
                    continue
                try:
                    status = None
                    if alive and snmp_ok is False:
                        status = "unreachable"      # répond au ping/TCP mais le SNMP est muet
                    self._update_availability(h, alive, latency, status=status, method=method)
                    if alive:
                        self._collect_metrics(h)
                    done += 1
                except Exception as e:              # un hôte en erreur ne bloque pas les autres
                    self.log_message.emit("ERROR", f"[Monitor] {h.get('name')} : {e}")
                    logger.exception(e)
        finally:
            self.cycle_done.emit(done)

    @pyqtSlot()
    def presence_tick(self):
        """Présence rapide : hors ligne après `presence_grace_s` (30 s) sans signe de vie ; signalé tout de suite."""
        if not self.db or self._presence_busy:
            return
        self._presence_busy = True
        try:
            from core import presence
            self._presence_n += 1
            for c in presence.presence_step(self.db, presence.grace_seconds(self.db), tick=self._presence_n):
                h, new = c["host"], c["new"]
                name, ip = h.get("name", ""), h.get("ip_address", "")
                self.host_status.emit(h["id"], new, 9999.0 if new == "offline" else 0.0)
                if new == "offline":
                    self._record_event(h["id"], name, "high", "host_down",
                                       f"{name} ({ip}) n'est plus connecté au réseau (aucune réponse depuis {c['silent_s']} s)")
                else:
                    self._record_event(h["id"], name, "information", "host_up", f"Hôte {name} ({ip}) de nouveau en ligne")
        except Exception as e:
            logger.exception(e)
        finally:
            self._presence_busy = False

    @staticmethod
    def _snmp_expected(host: dict) -> bool:
        return bool(host.get("snmp_enabled", 1)) and not lnet.is_local_address(host["ip_address"])

    def _snmp_alive(self, host: dict) -> bool:
        return self._snmp_get(
            host["ip_address"], OID_SYSUPTIME, host.get("snmp_community") or "public",
            port=int(host.get("snmp_port") or 161), timeout=1, retries=1,
            version=str(host.get("snmp_version") or "2c")) is not None

    def collect_host(self, host: dict):
        """Disponibilité + métriques d'un seul hôte."""
        r = lnet.probe_host_ex(host["ip_address"])
        alive, latency = r["alive"], r["latency_ms"]
        self._update_availability(host, alive, latency, method=r["method"])
        if alive:
            self._collect_metrics(host)

    def _collect_metrics(self, host: dict):
        host_id, ip, name = host["id"], host["ip_address"], host["name"]
        if lnet.is_local_address(ip):
            self.collect_local_metrics(host_id, ip, name)
        elif host.get("snmp_enabled", 1):
            self.collect_host_metrics(
                host_id, ip, name, host.get("snmp_community") or "public",
                port=int(host.get("snmp_port") or 161),
                version=str(host.get("snmp_version") or "2c"),
            )

    # ─────────────────────────────────────────
    # Disponibilité
    # ─────────────────────────────────────────

    def _update_availability(self, host: dict, alive: bool, latency: float, status: str = None,
                             method: str = None):
        host_id, ip, name = host["id"], host["ip_address"], host["name"]

        old = (host.get("status") or "unknown")
        # ── Anti-flapping : un hôte vu « en ligne » n'est déclaré hors ligne qu'après FLAP_THRESHOLD échecs consécutifs ──
        prev_fail, row = 0, {}
        if self.db:
            row = self.db.get_host_by_id(host_id) or {}
            prev_fail = int(row.get("failed_probes") or 0)
        failed_probes = 0 if alive else min(prev_fail + 1, 99)
        if self.db:
            self.db.execute("UPDATE hosts SET failed_probes = ? WHERE id = ?", (failed_probes, host_id))
            if alive:
                self.db.execute("UPDATE hosts SET last_alive_ts = ? WHERE id = ?", (int(time.time()), host_id))

        if self.db and method:
            self.db.update_host_reach(host_id, method)
            # Latence réelle (ICMP/TCP) : alimente le graphe « latence par équipement » du dashboard
            if alive and method in ("icmp", "tcp") and latency and latency > 0:
                self.db.add_metric(host_id, "latency", round(float(latency), 2), "ms")

        now = datetime.now().isoformat(timespec="seconds")
        silent_ok = True                                  # règle unique : rouge seulement après silence ≥ délai de grâce (30 s par défaut)
        if not alive and not status and old == "online" and self.db:
            try:
                from core import presence
                last = row.get("last_alive_ts")
                silent_ok = (not last) or (time.time() - int(last) >= presence.required_silence_s(row, presence.grace_seconds(self.db)))
            except Exception:
                silent_ok = True
        if not alive and not status and old == "online" and (failed_probes < self.FLAP_THRESHOLD or not silent_ok):
            # Échec isolé : on garde « en ligne », on note seulement la vérification (pas d'événement, pas d'alerte)
            if self.db:
                self.db.update_host_status(host_id, "online", now)
            self.log_message.emit("INFO", f"[Monitor] {name} ({ip}) : sans réponse "
                                          f"({failed_probes}/{self.FLAP_THRESHOLD}) — confirmation en cours")
            return

        new = status or ("online" if alive else "offline")
        if self.db:
            self.db.update_host_status(host_id, new, now)
        self.host_status.emit(host_id, new, latency if alive else 9999.0)

        if old == new:
            return
        # La présence rapide (30 s) a déjà changé cet état et enregistré l'événement : pas de doublon
        if row.get("status") == new and ((new == "offline" and prev_fail >= 99) or new == "online"):
            return
        if new == "offline" and old != "unknown":
            self._record_event(host_id, name, "high", "host_down",
                               f"Hôte {name} ({ip}) hors ligne ({failed_probes} vérifications consécutives sans réponse)")
        elif new == "unreachable" and old in ("online", "unknown"):
            self._record_event(host_id, name, "warning", "snmp_down",
                               f"Hôte {name} ({ip}) répond mais le SNMP est injoignable")
        elif new == "online" and old in ("offline", "unreachable"):
            self._record_event(host_id, name, "information", "host_up",
                               f"Hôte {name} ({ip}) de nouveau en ligne")
        self.log_message.emit("INFO" if new == "online" else "WARNING",
                              f"[Monitor] {name} ({ip}) : {new}")

    def check_availability(self, host_id: int, ip: str, host_name: str,
                           snmp_community: str = "public"):
        """Compatibilité : vérification manuelle d'un hôte."""
        host = (self.db.get_host_by_id(host_id) if self.db else None) or {
            "id": host_id, "ip_address": ip, "name": host_name}
        r = lnet.probe_host_ex(ip)
        self._update_availability(host, r["alive"], r["latency_ms"], method=r["method"])
        return r["alive"]

    # ─────────────────────────────────────────
    # Machine locale (psutil) — aucune configuration SNMP requise
    # ─────────────────────────────────────────

    def collect_local_metrics(self, host_id: int, ip: str, host_name: str):
        """CPU / RAM / disque / bande passante réels de la machine qui exécute l'application."""
        result = SNMPResult(host_id, host_name, ip)
        try:
            m = lnet.collect_local_metrics()
            result.metrics.update(m)
            in_mbps, out_mbps = self._sampler.sample()
            result.metrics["bw_in_mbps"] = in_mbps
            result.metrics["bw_out_mbps"] = out_mbps
            if self.db:
                if "cpu_util" in m:
                    self.db.add_metric(host_id, "cpu_util", m["cpu_util"], "%")
                if "mem_used_pct" in m:
                    self.db.add_metric(host_id, "mem_used", m["mem_used_pct"], "%")
                    self.db.add_metric(host_id, "mem_avail", m["mem_avail_gb"], "GB")
                if "disk_used_pct" in m:
                    self.db.add_metric(host_id, "disk_used", m["disk_used_pct"], "%")
                self.db.add_metric(host_id, "bw_in", in_mbps, "Mbps", "total")
                self.db.add_metric(host_id, "bw_out", out_mbps, "Mbps", "total")
            self._check_thresholds(host_id, host_name, m)
        except Exception as e:
            result.error = str(e)
            self.log_message.emit("ERROR", f"[Local] Erreur collecte {host_name}: {e}")
        self._emit_metrics(result)
        return result

    # ─────────────────────────────────────────
    # Collecte SNMP
    # ─────────────────────────────────────────

    def collect_host_metrics(self, host_id: int, ip: str, host_name: str,
                             community: str = "public", port: int = 161,
                             version: str = "2c"):
        """Collecte CPU, mémoire et bande passante d'un équipement via SNMP."""
        result = SNMPResult(host_id, host_name, ip)
        kw = {"port": port, "version": version}
        try:
            # Pré-test rapide : un équipement muet ne doit pas coûter ~20 s de timeouts par cycle
            if self._snmp_get(ip, OID_SYSUPTIME, community, port=port, timeout=1,
                              retries=1, version=version) is None:
                self.log_message.emit(
                    "WARNING", f"[SNMP] {host_name} ({ip}) : aucune réponse SNMP (communauté/port ?)")
                self._emit_metrics(result)
                return result
            cpu = self._cpu_percent(ip, community, kw)
            if cpu is not None:
                result.metrics["cpu_util"] = cpu
                if self.db:
                    self.db.add_metric(host_id, "cpu_util", cpu, "%")

            mem_total = self._snmp_get(ip, OID_MEM_TOTAL_REAL, community, **kw)
            mem_avail = self._snmp_get(ip, OID_MEM_AVAIL_REAL, community, **kw)
            if mem_total is not None and mem_avail is not None:
                total_kb, avail_kb = float(str(mem_total)), float(str(mem_avail))
                if total_kb > 0:
                    used_pct = (total_kb - avail_kb) / total_kb * 100
                    result.metrics["mem_used_pct"] = used_pct
                    result.metrics["mem_avail_gb"] = avail_kb / (1024 * 1024)
                    if self.db:
                        self.db.add_metric(host_id, "mem_used", used_pct, "%")
                        self.db.add_metric(host_id, "mem_avail", avail_kb / (1024 * 1024), "GB")

            rates = self._bandwidth_rates(host_id, ip, community, kw)
            if rates:
                result.metrics["bw_in_mbps"], result.metrics["bw_out_mbps"] = rates
                if self.db:
                    self.db.add_metric(host_id, "bw_in", rates[0], "Mbps", "total")
                    self.db.add_metric(host_id, "bw_out", rates[1], "Mbps", "total")

            self._check_thresholds(host_id, host_name, result.metrics)
            host_row = self.db.get_host_by_id(host_id) if self.db else None
            if host_row and (host_row.get("device_type") or "") in ("switch", "router", "firewall"):
                self.collect_sfp_metrics(host_id, ip, host_name, community)   # puissance optique DOM
            if not result.metrics:
                self.log_message.emit(
                    "WARNING", f"[SNMP] {host_name} ({ip}) : aucune réponse SNMP (communauté/port ?)")
        except Exception as e:
            result.error = str(e)
            self.log_message.emit("ERROR", f"[SNMP] Erreur collecte {host_name}: {e}")

        self._emit_metrics(result)
        return result

    def _cpu_percent(self, ip: str, community: str, kw: dict):
        """CPU % : moyenne hrProcessorLoad, sinon 100 − ssCpuIdle (UCD)."""
        loads = self._snmp_walk(ip, OID_HRPROCESSOR_LOAD, community,
                                port=kw["port"], version=kw["version"])
        if loads:
            vals = [float(str(v)) for v in loads.values()]
            return sum(vals) / len(vals)
        idle = self._snmp_get(ip, OID_SS_CPU_IDLE, community, **kw)
        if idle is not None:
            return max(0.0, 100.0 - float(str(idle)))
        return None

    def _bandwidth_rates(self, host_id: int, ip: str, community: str, kw: dict):
        """
        Débit (Mbps) = Δoctets × 8 / Δt, somme des interfaces hors loopback.
        Les compteurs IF-MIB sont cumulatifs : le 1er passage ne fait que mémoriser.
        """
        ins = self._snmp_walk(ip, OID_IF_IN_OCTETS, community, port=kw["port"], version=kw["version"])
        if not ins:
            return None
        outs = self._snmp_walk(ip, OID_IF_OUT_OCTETS, community, port=kw["port"], version=kw["version"]) or {}
        descr = self._snmp_walk(ip, OID_IF_DESCR, community, port=kw["port"], version=kw["version"]) or {}
        total_in = total_out = 0
        for idx, v in ins.items():
            if str(descr.get(idx, "")).lower().startswith("lo"):
                continue
            total_in += int(str(v))
            total_out += int(str(outs.get(idx, 0)))
        now = time.monotonic()
        prev = self._prev_octets.get(host_id)
        self._prev_octets[host_id] = (now, total_in, total_out)
        if prev is None:
            return None
        return self.compute_rate(prev, (now, total_in, total_out))

    @staticmethod
    def compute_rate(prev: tuple, cur: tuple, wrap: int = 2 ** 32) -> tuple[float, float] | None:
        """Débit entre deux relevés (t, in_octets, out_octets). Gère le wrap des compteurs 32 bits."""
        dt = cur[0] - prev[0]
        if dt <= 0:
            return None
        d_in = cur[1] - prev[1]
        d_out = cur[2] - prev[2]
        if d_in < 0:
            d_in += wrap
        if d_out < 0:
            d_out += wrap
        return d_in * 8 / dt / 1_000_000, d_out * 8 / dt / 1_000_000

    # ─────────────────────────────────────────
    # Seuils & événements
    # ─────────────────────────────────────────

    def _threshold(self, key: str, default: float) -> float:
        try:
            return float(self.db.get_setting(key, str(default))) if self.db else default
        except (TypeError, ValueError):
            return default

    def _check_thresholds(self, host_id: int, host_name: str, m: dict):
        cpu = m.get("cpu_util")
        if cpu is not None:
            warn = self._threshold("cpu_threshold", CPU_THRESHOLD_WARNING)
            crit = max(CPU_THRESHOLD_CRITICAL, warn + 5)
            if cpu >= crit:
                self._emit_alert(host_id, host_name, "disaster",
                                 f"CPU critique (> {crit:.0f}%) : {cpu:.1f}%", "cpu_util", cpu)
            elif cpu >= warn:
                self._emit_alert(host_id, host_name, "average",
                                 f"CPU élevé (> {warn:.0f}%) : {cpu:.1f}%", "cpu_util", cpu)
        mem = m.get("mem_used_pct")
        if mem is not None:
            warn = self._threshold("ram_threshold", MEM_THRESHOLD_WARNING)
            if mem >= warn:
                self._emit_alert(host_id, host_name, "average",
                                 f"Mémoire élevée (> {warn:.0f}%) : {mem:.1f}%", "mem_used", mem)

    def _emit_metrics(self, result: "SNMPResult"):
        self.metrics_ready.emit({
            "host_id":      result.host_id,
            "host_name":    result.host_name,
            "ip":           result.ip,
            "metrics":      result.metrics,
            "collected_at": result.collected_at,
            "error":        result.error,
        })

    def _record_event(self, host_id: int, host_name: str, severity: str,
                      event_type: str, description: str):
        """Persiste un événement + émet alert_triggered (→ notifications)."""
        if self.db:
            self.db.add_event(host_id=host_id, host_name=host_name, group_name="",
                              severity=severity, event_type=event_type,
                              description=description)
        self.alert_triggered.emit({
            "host_id": host_id, "host_name": host_name, "severity": severity,
            "event_type": event_type, "description": description,
            "occurred_at": datetime.now().isoformat(timespec="seconds"),
        })

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

    @staticmethod
    def _snmp_run(coro):
        """Exécute une coroutine pysnmp dans une boucle dédiée (le worker vit dans un QThread)."""
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    @staticmethod
    def _snmp_close(engine):
        try:
            engine.closeDispatcher()
        except Exception:
            try:
                engine.transportDispatcher.closeDispatcher()
            except Exception:
                pass

    def _snmp_get(self, ip: str, oid: str, community: str = "public",
                  port: int = 161, timeout: int = 2, retries: int = 1,
                  version: str = "2c"):
        """SNMP GET (pysnmp 6.2 asyncio). Retourne la valeur ou None."""
        try:
            from pysnmp.hlapi.asyncio import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )

            async def _get():
                eng = SnmpEngine()
                try:
                    ei, es, _, vbs = await getCmd(
                        eng, CommunityData(community, mpModel=0 if version == "1" else 1),
                        UdpTransportTarget((ip, port), timeout=timeout, retries=retries),
                        ContextData(), ObjectType(ObjectIdentity(oid)),
                    )
                    if ei or es:
                        return None
                    for _, val in vbs:
                        if val.__class__.__name__ in ("NoSuchObject", "NoSuchInstance", "EndOfMibView"):
                            return None
                        return val
                finally:
                    self._snmp_close(eng)

            return self._snmp_run(_get())
        except Exception as e:
            logger.debug(f"[SNMP] GET {ip} {oid} : {e}")
            return None

    def _snmp_walk(self, ip: str, oid: str, community: str = "public",
                   port: int = 161, timeout: int = 2, version: str = "2c") -> dict | None:
        """SNMP WALK du sous-arbre `oid`. Retourne {index: valeur} ou None."""
        try:
            from pysnmp.hlapi.asyncio import (
                walkCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )

            async def _walk():
                eng = SnmpEngine()
                result = {}
                try:
                    walker = walkCmd(
                        eng, CommunityData(community, mpModel=0 if version == "1" else 1),
                        UdpTransportTarget((ip, port), timeout=timeout, retries=1),
                        ContextData(), ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False,
                    )
                    async with contextlib.aclosing(walker):         # ferme le générateur même après « break » (plus d'avertissement « Task was destroyed »)
                        async for ei, es, _, vbs in walker:
                            if ei or es:
                                break
                            for name, val in vbs:
                                result[str(name).split(".")[-1]] = val
                finally:
                    self._snmp_close(eng)
                return result

            res = self._snmp_run(_walk())
            return res if res else None
        except Exception as e:
            logger.debug(f"[SNMP] WALK {ip} {oid} : {e}")
            return None

    # ─────────────────────────────────────────
    # Alertes
    # ─────────────────────────────────────────

    def _emit_alert(self, host_id: int, host_name: str, severity: str,
                    description: str, metric: str, value: float):
        """Alerte de seuil, avec période de grâce pour ne pas spammer événements et notifications."""
        key = (host_id, metric, severity)
        now = time.monotonic()
        last = self._last_alert.get(key)
        if last is not None and now - last < self.ALERT_COOLDOWN_S:
            return
        self._last_alert[key] = now
        self._record_event(host_id, host_name, severity, "threshold", description)
