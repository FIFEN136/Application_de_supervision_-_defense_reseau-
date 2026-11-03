# Banc d'essai Procus Secure (mesures réelles)

Machine : 2 cœurs, 8.4 Go RAM · 2026-10-15 16:29

| Scénario | Config initiale (s) | Délai de détection (s) | Faux positifs (cycles sans changement) | CPU (s) | RAM process (Mo) | Qualité de preuve | Compréhension |
|---|---|---|---|---|---|---|---|
| 1. Équipement inconnu | 0.04 | 0.00 | 0 | 0.09 | 63 | 7/7 | 1 fiche : IP + MAC + priorité + action proposée |
| 2. Port fermé → ouvert | 0.01 | 0.00 | 0 | 0.01 | 64 | 8/8 | 1 fiche : « closed → open » + commande de blocage prête |
| 3. Config routeur modifiée | 0.69 | 0.65 | 0 | 1.18 | 114 | 7/7 | 1 fiche : diff avant/après champ par champ |
| 4. Alertes groupées | 0.00 | 0.02 | 0 | 0.02 | 114 | 4/4 preuves conservées, perte=0 | 4 alertes → 1 incident |
| 5. Rapport périodique | 0.00 | 0.01 | 0 | 0.01 | 114 | fichiers=['csv', 'json', 'pdf'], chiffres = base : True | rapport JSON/CSV/PDF issu de la base |

Délai de détection = temps entre le changement et la présence de l'événement/incident dans la base (cycle déclenché à la main ; scénario 1 : la découverte réseau est simulée (le balayage réel d'un /24 dure plusieurs secondes) ; en production il s'ajoute l'intervalle de planification : scan 300 s, supervision 60 s, pipeline 120 s par défaut).

## Comparaison avec d'autres outils — PROTOCOLE (non mesuré ici)

Nmap, Zabbix, etc. n'ont pas pu être exécutés dans l'environnement de test : aucun chiffre n'est donné pour eux. Pour comparer, rejouez les 5 scénarios 
avec chaque outil et notez les mêmes 6 mesures :

| Mesure | Comment la relever |
|---|---|
| Temps de configuration initial | chronomètre : de l'installation à la 1re surveillance active |
| Délai de détection | horodatage du changement vs apparition de l'alerte |
| Faux positifs | nombre d'alertes sur 24 h sans aucun changement réel |
| CPU / RAM | Gestionnaire des tâches ou `psutil` sur le processus de l'outil |
| Qualité de preuve | cases cochées : IP, MAC, horodatage, avant/après, lien vers événements d'origine |
| Temps pour comprendre | chronomètre : de la notification à « je sais quoi faire » |

Éléments qualitatifs (conception, pas mesures) : un scanner comme Nmap détecte un port ouvert mais ne garde ni historique ni corrélation ; une plateforme comme Zabbix est très complète mais demande davantage de configuration (agents, templates, déclencheurs). HSR vise une mise en route rapide (saisir un réseau) avec preuves et priorités pré-assemblées ; il couvre moins de protocoles.