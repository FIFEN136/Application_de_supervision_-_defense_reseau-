# Procus Secure — DevOps, installation et exploitation

## Intégration continue
`.github/workflows/ci.yml` : tests complets sous **Linux et Windows** (Qt hors écran), `ruff`, `bandit`, `pip-audit`, SBOM CycloneDX,
et — sur une étiquette `vX.Y` — construction PyInstaller Windows.

## Dépendances
`requirements.txt` (bornes) ; `requirements.lock` (versions testées). Pour des installations vérifiées par hachage :
`pip-compile --generate-hashes requirements.txt -o requirements.lock` puis `pip install --require-hashes -r requirements.lock`.

## Installateur signé (à faire sur un poste Windows disposant du certificat)
1. `pyinstaller --noconfirm --windowed --name ProcusSecure main.py`
2. `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /f certificat.pfx dist\ProcusSecure\ProcusSecure.exe`
3. (option) empaqueter avec Inno Setup puis signer aussi l'installateur.
La signature exige un certificat de signature de code : elle ne peut pas être produite sans lui.

## Chiffrement de la base
SQLCipher s'il est installé, sinon mode « fichier chiffré » : base en mémoire, fichier AES-256-GCM écrit de façon atomique au plus 15 s après une modification et à la fermeture. `PROCUS_DB_MODE=file` force ce mode ; `PROCUS_DB_ENCRYPT=0` le désactive pour une base neuve.

## Sauvegarde et restauration
Tâche automatique « dbbackup » : copie **chiffrée** de la base toutes les 24 h (réglages `db_backup_interval_h`, `db_backup_keep`, `db_backup_dir`),
vérifiée après écriture, 7 exemplaires conservés (`~/.procus_hsr/backups`). La clé de chiffrement est dans le trousseau du système
(ou `~/.procus_hsr/keys`) : **sauvegardez-la séparément**, sans elle les copies sont illisibles. Restauration : Paramètres → Restaurer.

## Journal applicatif
`~/.procus_hsr/logs/procus.log` : 5 Mo par fichier, 10 fichiers compressés, secrets masqués.

## Réseau
Serveur d'agents : réglage `agent_bind` (défaut `0.0.0.0` ; mettre l'adresse du réseau de gestion pour restreindre), limite de 600 requêtes/min par IP,
64 connexions simultanées. Webhooks : adresses internes refusées sauf liste `webhook_allow_internal`; redirections non suivies.
Pare-feu local : si le blocage via iptables est utilisé, donnez au compte du service un sudoers restreint, par exemple
`procus ALL=(root) NOPASSWD: /usr/sbin/iptables -A INPUT -s * -j DROP, /usr/sbin/iptables -D INPUT -s * -j DROP`.

## Test sous Windows
Lancer la CI (job windows-latest), puis sur un poste réel : `python -m pytest -q`, démarrage `python main.py`, vérifier l'état de chiffrement
(DPAPI/trousseau) et le journal. Ce chemin n'a pas été exécuté sur Windows ici.
