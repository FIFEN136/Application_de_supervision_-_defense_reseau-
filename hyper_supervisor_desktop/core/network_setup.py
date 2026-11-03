"""
Procus Secure — Connexion automatique au réseau de la machine
Procus Tech

Worker Qt exécuté dans son propre QThread :
  1. enregistre la machine locale et la passerelle comme hôtes supervisés,
  2. (optionnel, réglage « auto_discover ») balaie le sous-réseau et ajoute les hôtes actifs,
  3. signale la fin pour déclencher immédiatement un premier scan + une première collecte.
"""
from PyQt6.QtCore import QObject, pyqtSignal, pyqtSlot
from loguru import logger

from core import local_network as lnet


class NetworkSetupWorker(QObject):
    log_message = pyqtSignal(str, str)
    finished    = pyqtSignal(int)          # nombre d'hôtes ajoutés par la découverte
    network_discovered = pyqtSignal(int, int, int)   # network_id, nouveaux, total vus
    new_device  = pyqtSignal(dict)         # alerte « équipement inconnu apparu » (→ notifications)

    def __init__(self, db=None, parent=None):
        super().__init__(parent)
        self.db = db

    @pyqtSlot()
    def run(self):
        """Enregistrement local + découverte automatique (si activée)."""
        added = 0
        try:
            info = lnet.ensure_local_hosts(self.db)
            if info["ip"]:
                self.log_message.emit(
                    "INFO", f"[Réseau] Machine locale : {info['ip']} — passerelle : "
                            f"{info['gateway_ip'] or 'inconnue'}")
            else:
                self.log_message.emit("WARNING", "[Réseau] Aucune interface réseau active détectée")
            self._adopt()
            if self.db.get_setting("auto_discover", "1") == "1":
                added = self._discover()
                self._adopt()
        except Exception as e:
            logger.exception(e)
            self.log_message.emit("ERROR", f"[Réseau] Initialisation : {e}")
        self.finished.emit(added)

    @pyqtSlot()
    def discover(self):
        """Découverte à la demande (bouton « Découvrir le réseau »)."""
        added = 0
        try:
            lnet.ensure_local_hosts(self.db)
            added = self._discover()
        except Exception as e:
            logger.exception(e)
            self.log_message.emit("ERROR", f"[Réseau] Découverte : {e}")
        self.finished.emit(added)

    def _adopt(self):
        """Tout équipement doit appartenir à un réseau visible (et supprimable) dans « Réseaux supervisés »."""
        try:
            n = self.db.adopt_orphan_hosts(lnet.get_primary_network())
            if n:
                self.log_message.emit("INFO", f"[Réseau] {n} équipement(s) rattaché(s) à leur réseau")
        except Exception as e:
            logger.error(f"[Réseau] rattachement : {e}")

    def _discover(self) -> int:
        net = lnet.get_primary_network()
        if not net or self.db.is_removed_network(net):
            return 0
        self.log_message.emit("INFO", f"[Réseau] Découverte du sous-réseau {net} …")
        found = lnet.discover_hosts(net)
        added = lnet.register_discovered(self.db, found)
        self.log_message.emit(
            "INFO", f"[Réseau] {len(found)} hôte(s) actif(s), {added} nouveau(x) ajouté(s)")
        return added

    # ─────────────────────────────────────────
    # Réseaux saisis par l'administrateur (routeur / Wi-Fi / sous-réseau)
    # ─────────────────────────────────────────

    @pyqtSlot(int)
    def discover_network(self, network_id: int):
        """Découvre (ou redécouvre) un réseau enregistré, ajoute les équipements, alerte sur les nouveaux."""
        try:
            net = self.db.fetchone("SELECT * FROM networks WHERE id = ?", (network_id,))
            if not net:
                return
            first_time = not net.get("last_discovery")
            self.log_message.emit("INFO", f"[Réseau] Découverte de « {net['name']} » ({net['cidr']}) …")
            found = lnet.discover_network(net["cidr"], net.get("gateway_ip"))
            res = lnet.register_network_hosts(self.db, network_id, found, net.get("gateway_ip"))
            added = res["added"]
            self.log_message.emit(
                "INFO", f"[Réseau] « {net['name']} » : {len(found)} équipement(s) actif(s), "
                        f"{len(added)} nouveau(x)")
            if not first_time:                          # après la 1re découverte (référence) : alerte
                for h in added:
                    self._alert_new_device(net, h)
            self._adopt()
            self.network_discovered.emit(network_id, len(added), len(found))
        except Exception as e:
            logger.exception(e)
            self.log_message.emit("ERROR", f"[Réseau] Découverte du réseau {network_id} : {e}")
            self.network_discovered.emit(network_id, 0, 0)

    @pyqtSlot()
    def rediscover_all(self):
        """Redécouvre tout de suite tous les réseaux actifs (réseaux suspendus ignorés)."""
        self._rediscover(only_due=False)

    @pyqtSlot()
    def rediscover_due(self):
        """Appelé par le planificateur : seuls les réseaux dont la fréquence propre est écoulée sont redécouverts."""
        self._rediscover(only_due=True)

    def _rediscover(self, only_due: bool):
        """
        Redécouverte périodique : chaque réseau suivi a sa propre fréquence et son propre fil d'exécution ; un réseau
        suspendu, lent ou en panne ne retarde ni ne perturbe les autres.
        """
        try:
            from concurrent.futures import ThreadPoolExecutor
            due = []
            for net in self.db.fetchall("SELECT id, paused, discover_every_s, last_discovery FROM networks WHERE auto_monitor = 1"):
                if net.get("paused"):
                    continue
                age = self.db.fetchone("SELECT CAST(strftime('%s','now') AS INTEGER) - CAST(strftime('%s', ?) AS INTEGER) AS a",
                                       (net.get("last_discovery"),))["a"] if net.get("last_discovery") else None
                if not only_due or age is None or age >= int(net.get("discover_every_s") or 300) - 5:
                    due.append(net["id"])
            if not due:
                return
            def one(nid):
                try:
                    self.discover_network(nid)
                except Exception as e:                          # la panne d'un réseau n'arrête jamais les autres
                    logger.error(f"[Réseau] redécouverte {nid} : {e}")
            if len(due) == 1:
                one(due[0])
                return
            with ThreadPoolExecutor(max_workers=min(4, len(due))) as ex:      # plusieurs réseaux : en parallèle, chacun isolé
                list(ex.map(one, due))
        except Exception as e:
            logger.exception(e)

    def _alert_new_device(self, net: dict, host: dict):
        desc = (f"Nouvel équipement sur « {net['name']} » : {host['ip']}"
                + (f" ({host['mac']})" if host.get("mac") else "")
                + f" — type probable : {host['device_type']}")
        event = {"host_id": host["id"], "host_name": host["name"], "severity": "average",
                 "event_type": "new_device", "description": desc,
                 "state_before": "absent", "state_after": "présent"}
        try:
            self.db.add_event(host["id"], host["name"], net["name"], "average", "new_device",
                              desc, state_before="absent", state_after="présent")
        except Exception as e:
            logger.error(f"[Réseau] événement nouvel équipement : {e}")
        self.new_device.emit(event)
