"""
HSR — Modèles de données (schéma SQLite/SQLCipher)
Procus Tech

Tables :
  - hosts          : équipements supervisés
  - host_groups    : groupes d'hôtes
  - port_states    : états des ports (scan TCP)
  - baselines      : état de référence des ports
  - events         : événements détectés (sévérité INFO/WARNING/CRITICAL/DISASTER)
  - audit_logs     : journal d'audit infalsifiable (HMAC)
  - users          : utilisateurs (RBAC)
  - media_types    : types de médias (SMTP, Slack, SMS, Webhook)
  - templates      : templates de supervision
  - metrics        : métriques SNMP horodatées (bande passante, CPU, RAM, disque)
  - sfp_metrics    : puissance optique SFP/DOM
"""

SCHEMA_SQL = """
-- ─────────────────────────────────────────
-- Groupes d'hôtes
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS host_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- Équipements supervisés
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS hosts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    ip_address      TEXT    NOT NULL,
    group_id        INTEGER REFERENCES host_groups(id),
    device_type     TEXT    DEFAULT 'unknown',  -- router, switch, server, ap, firewall, ups
    location        TEXT,
    snmp_community  TEXT    DEFAULT 'public',
    snmp_version    TEXT    DEFAULT '2c',
    snmp_port       INTEGER DEFAULT 161,
    agent_enabled   INTEGER DEFAULT 0,
    snmp_enabled    INTEGER DEFAULT 1,
    icmp_enabled    INTEGER DEFAULT 1,
    status          TEXT    DEFAULT 'unknown',   -- online, offline, unreachable, degraded
    failed_probes   INTEGER DEFAULT 0,          -- compte des échecs ICMP/ARP consécutifs (anti-flapping)
    last_check      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- Réseaux supervisés (LAN, Wi-Fi, derrière un routeur) saisis par l'administrateur
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS networks (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL UNIQUE,
    cidr           TEXT    NOT NULL UNIQUE,
    gateway_ip     TEXT,
    kind           TEXT    DEFAULT 'lan',      -- lan, wifi, router
    auto_monitor   INTEGER DEFAULT 1,          -- redécouverte périodique
    last_discovery TEXT,
    authorized_by  TEXT,                       -- qui a autorisé le périmètre
    authorized_at  TEXT,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- États des ports TCP/UDP (scan)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS port_states (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id          INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port             INTEGER NOT NULL,
    protocol         TEXT    DEFAULT 'TCP',      -- TCP ou UDP
    state            TEXT    NOT NULL,           -- open, closed, filtered
    latency_ms       REAL,
    service_banner   TEXT,                       -- bannière du service (ex: OpenSSH_7.4)
    service_version  TEXT,                       -- version extraite (ex: 7.4)
    scanned_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_port_states_host ON port_states(host_id, port);

-- ─────────────────────────────────────────
-- Baseline (état de référence)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS baselines (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    DEFAULT 'TCP',
    state       TEXT    NOT NULL,  -- état référence : open/closed/filtered
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    created_by  INTEGER REFERENCES users(id),
    UNIQUE(host_id, port, protocol)
);

-- ─────────────────────────────────────────
-- Événements / Problèmes
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER REFERENCES hosts(id),
    host_name       TEXT,
    group_name      TEXT,
    severity        TEXT    NOT NULL,   -- disaster, high, average, warning, information, resolved
    event_type      TEXT    NOT NULL,   -- port_change, host_down, snmp_alert, threshold, resolved
    description     TEXT    NOT NULL,
    port            INTEGER,
    interface       TEXT,
    state_before    TEXT,
    state_after     TEXT,
    tags            TEXT,               -- JSON array ex: ["scope:réseau","dc:Lyon-DC2"]
    acknowledged    INTEGER DEFAULT 0,
    acknowledged_by TEXT,
    acknowledged_at TEXT,
    duration_sec    INTEGER,
    occurred_at     TEXT    NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_host      ON events(host_id);
CREATE INDEX IF NOT EXISTS idx_events_occurred  ON events(occurred_at);

-- ─────────────────────────────────────────
-- Journal d'audit (infalsifiable — HMAC-SHA256)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER REFERENCES users(id),
    username    TEXT,
    action      TEXT    NOT NULL,
    target      TEXT,
    detail      TEXT,
    ip_source   TEXT,
    hmac        TEXT    NOT NULL,   -- HMAC-SHA256 de (empreinte précédente|user|action|target|detail|ts) : journal CHAÎNÉ
    logged_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    prev_hmac   TEXT,               -- empreinte de la ligne précédente (v16)
    chain_v     INTEGER             -- 2 = chaîné ; NULL = ancienne ligne (signée seule)
);

-- ─────────────────────────────────────────
-- Utilisateurs (RBAC)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    login           TEXT    NOT NULL UNIQUE,
    full_name       TEXT,
    role            TEXT    NOT NULL DEFAULT 'read-only',  -- super-admin, operator, read-only
    group_name      TEXT,
    password_hash   TEXT    NOT NULL,
    password_changed INTEGER DEFAULT 0,      -- 0=mot de passe par défaut, 1=changé par utilisateur
    active          INTEGER DEFAULT 1,
    last_login      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- Templates de supervision
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS templates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT,
    item_count      INTEGER DEFAULT 0,
    trigger_count   INTEGER DEFAULT 0,
    graph_count     INTEGER DEFAULT 0,
    config_json     TEXT,   -- JSON de configuration des items/triggers
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- Métriques SNMP (CPU, RAM, disque, trafic)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    metric_name TEXT    NOT NULL,   -- cpu_util, mem_used, disk_used, if_in_octets, if_out_octets
    interface   TEXT,               -- nom de l'interface (ex: GigabitEthernet0/0)
    value       REAL    NOT NULL,
    unit        TEXT,               -- %, GB, Mbps, conn, etc.
    collected_at TEXT   NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_metrics_host_name ON metrics(host_id, metric_name, collected_at);

-- ─────────────────────────────────────────
-- Métriques SFP/DOM (puissance optique)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sfp_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    interface       TEXT    NOT NULL,
    tx_power_dbm    REAL,
    rx_power_dbm    REAL,
    temperature_c   REAL,
    voltage_v       REAL,
    collected_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- Types de médias (alertes)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS media_types (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    type        TEXT    NOT NULL,   -- email, sms, webhook
    config_json TEXT,               -- SMTP host/port, webhook URL, etc. (chiffré)
    active      INTEGER DEFAULT 1,
    used_by     INTEGER DEFAULT 0
);

-- ─────────────────────────────────────────
-- Paramètres système
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- ─────────────────────────────────────────
-- Automatisation : incidents corrélés, actions soumises à validation, instantanés de configuration
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    host_name    TEXT,
    title        TEXT NOT NULL,
    severity     TEXT NOT NULL,            -- sévérité maximale des événements groupés
    priority     INTEGER NOT NULL DEFAULT 0,   -- 0..100 (règles + sévérité + criticité)
    priority_label TEXT,                   -- P1 critique … P4 faible
    status       TEXT NOT NULL DEFAULT 'open',  -- open, acknowledged, closed
    summary      TEXT,
    event_count  INTEGER DEFAULT 0,
    opened_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_host   ON incidents(host_id);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id    INTEGER NOT NULL REFERENCES events(id)    ON DELETE CASCADE,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS pending_actions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id  INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    host_id      INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    host_name    TEXT,
    action_type  TEXT NOT NULL,            -- isolate_host, block_ip, modify_config, apply_patch
    target       TEXT,
    reason       TEXT,
    plan         TEXT,                     -- commande / procédure exacte préparée (jamais exécutée par HSR)
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending, approved, rejected
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    decided_by   TEXT,
    decided_at   TEXT,
    decision_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON pending_actions(status);

CREATE TABLE IF NOT EXISTS config_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    content     TEXT NOT NULL,             -- JSON des paramètres collectés (SNMP)
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cfg_host ON config_snapshots(host_id, id);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    steps       TEXT,                      -- JSON : résultat de chacune des 8 étapes
    duration_ms INTEGER
);

-- ─────────────────────────────────────────
-- File de notification (dédupliquage)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notification_queue (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            INTEGER,
    host_id             INTEGER,
    event_hash          TEXT NOT NULL,         -- hash de (event_type, host_id, description)
    notification_count  INTEGER DEFAULT 1,
    last_sent_at        TEXT NOT NULL DEFAULT (datetime('now')),
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(event_hash, host_id)
);
CREATE INDEX IF NOT EXISTS idx_notif_sent ON notification_queue(last_sent_at);

-- ─────────────────────────────────────────
-- Défense active (v13/v14)
-- ─────────────────────────────────────────
-- Connexions reçues par les honeypots (leurres)
CREATE TABLE IF NOT EXISTS honeypot_hits (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    port      INTEGER NOT NULL,
    profile   TEXT,
    src_ip    TEXT    NOT NULL,
    src_port  INTEGER,
    payload   TEXT,                        -- premiers octets reçus (imprimables, tronqués)
    seen_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_hp_seen ON honeypot_hits(seen_at);

-- Correspondances IP -> MAC observées (détection d'usurpation ARP)
CREATE TABLE IF NOT EXISTS arp_bindings (
    ip         TEXT PRIMARY KEY,
    mac        TEXT NOT NULL,
    is_gateway INTEGER DEFAULT 0,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Accès SSH aux équipements (secrets chiffrés Fernet) pour sauvegarde de configuration / actions
CREATE TABLE IF NOT EXISTS host_credentials (
    host_id     INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    secret_enc  TEXT,                      -- mot de passe OU clé privée (chiffré)
    auth_type   TEXT DEFAULT 'password',   -- password, key
    port        INTEGER DEFAULT 22,
    profile     TEXT DEFAULT 'linux',      -- cisco_ios, juniper, mikrotik, fortinet, huawei, linux, custom
    commands    TEXT,                      -- JSON : commandes de lecture (profil custom)
    host_key    TEXT,                      -- empreinte SHA256 de la clé d'hôte (confiance à la 1re connexion)
    backup_enabled INTEGER DEFAULT 1,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Accès web / API aux équipements (secret chiffré)
CREATE TABLE IF NOT EXISTS device_logins (
    host_id     INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    method      TEXT DEFAULT 'web',
    port        INTEGER DEFAULT 443,
    scheme      TEXT DEFAULT 'https',
    username    TEXT,
    secret_enc  TEXT,
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Historique des configurations sauvegardées (une ligne par version distincte)
CREATE TABLE IF NOT EXISTS config_backups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    fingerprint  TEXT NOT NULL,
    content      TEXT NOT NULL,
    size         INTEGER,
    lines_added  INTEGER DEFAULT 0,
    lines_removed INTEGER DEFAULT 0,
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cfgb_host ON config_backups(host_id, id);

-- Exécutions réelles d'actions validées (avec commande d'annulation)
CREATE TABLE IF NOT EXISTS action_runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id    INTEGER REFERENCES pending_actions(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL,            -- local_block_ip, remote_block_port
    command      TEXT NOT NULL,
    rollback     TEXT,
    status       TEXT NOT NULL,            -- ok, failed, rolled_back, simulated
    output       TEXT,
    executed_by  TEXT,
    started_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_runs_action ON action_runs(action_id);

-- Agents légers installés sur les machines
CREATE TABLE IF NOT EXISTS agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id    TEXT NOT NULL UNIQUE,
    host_id     INTEGER REFERENCES hosts(id) ON DELETE SET NULL,
    name        TEXT,
    secret_enc  TEXT NOT NULL,             -- secret HMAC (chiffré Fernet)
    os          TEXT,
    version     TEXT,
    watch_paths TEXT,                      -- JSON : fichiers surveillés (FIM)
    interval_s  INTEGER DEFAULT 60,
    enabled     INTEGER DEFAULT 1,
    enrolled_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT
);
CREATE TABLE IF NOT EXISTS agent_data (
    agent_id     TEXT NOT NULL,
    kind         TEXT NOT NULL,            -- processes, services, software, ports, users, system
    data         TEXT NOT NULL,            -- JSON
    collected_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, kind)
);

-- Intégrité des fichiers (FIM) : référence par agent ('local' = cette machine)
CREATE TABLE IF NOT EXISTS fim_baseline (
    agent_id   TEXT NOT NULL,
    path       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    size       INTEGER,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (agent_id, path)
);

-- Journaux reçus (agents, syslog) et règles de détection (format Sigma)
CREATE TABLE IF NOT EXISTS log_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER,
    source      TEXT,                      -- syslog, agent:<id>
    src_addr    TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now')),
    message     TEXT NOT NULL,
    fields      TEXT                       -- JSON
);
CREATE INDEX IF NOT EXISTS idx_log_recv ON log_events(received_at);
CREATE TABLE IF NOT EXISTS sigma_rules (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id   TEXT NOT NULL UNIQUE,
    title     TEXT NOT NULL,
    level     TEXT,
    enabled   INTEGER DEFAULT 1,
    builtin   INTEGER DEFAULT 0,
    yaml      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# ─────────────────────────────────────────
# Données initiales (seed)
# ─────────────────────────────────────────
SEED_SQL = """
-- Utilisateur admin par défaut (mot de passe modifié au premier lancement)
INSERT OR IGNORE INTO users (login, full_name, role, group_name, password_hash)
VALUES ('admin', 'Administrateur', 'super-admin', 'Administrateurs', '__CHANGE_ME__');

-- Templates de base
INSERT OR IGNORE INTO templates (name, description, item_count, trigger_count, graph_count)
VALUES
  ('Template Net Cisco IOS',      'Supervision équipements Cisco IOS',    45, 18, 12),
  ('Template OS Linux by Zabbix', 'Supervision serveurs Linux',           89, 34, 22),
  ('Template OS Windows',         'Supervision serveurs Windows',         76, 28, 18),
  ('Template Net Juniper JunOS',  'Supervision équipements Juniper',      38, 14, 10),
  ('Template App Nginx',          'Supervision service Nginx',            22,  8,  6),
  ('Template DB PostgreSQL',      'Supervision base PostgreSQL',          51, 20, 14),
  ('Template App Docker',         'Supervision conteneurs Docker',        34, 12,  8),
  ('Template Net Fortinet',       'Supervision Fortinet/FortiGate',       42, 16, 10);

-- Types de médias par défaut
INSERT OR IGNORE INTO media_types (name, type, active)
VALUES
  ('Email SMTP',  'email',   1),
  ('Slack NOC',   'webhook', 1),
  ('SMS Twilio',  'sms',     1),
  ('PagerDuty',   'webhook', 0);

-- ───────── v15 : sécurité réseau (visibilité, évaluation, politique) ─────────
CREATE TABLE IF NOT EXISTS flows_agg (
    src_ip     TEXT NOT NULL,
    dst_ip     TEXT NOT NULL,
    proto      TEXT NOT NULL,                 -- tcp, udp, icmp, other
    dst_port   INTEGER NOT NULL DEFAULT 0,
    flows      INTEGER NOT NULL DEFAULT 0,
    bytes      INTEGER NOT NULL DEFAULT 0,
    packets    INTEGER NOT NULL DEFAULT 0,
    source     TEXT,                          -- netflow, agent:<id>, local
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (src_ip, dst_ip, proto, dst_port)
);
CREATE INDEX IF NOT EXISTS idx_flows_last ON flows_agg(last_seen);

CREATE TABLE IF NOT EXISTS net_links (          -- voisins LLDP
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    local_port  TEXT NOT NULL,
    remote_name TEXT NOT NULL,
    remote_port TEXT NOT NULL DEFAULT '',
    seen_at     TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (host_id, local_port, remote_name, remote_port)
);
CREATE TABLE IF NOT EXISTS net_routes (
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    dest     TEXT NOT NULL,
    mask     TEXT NOT NULL,
    nexthop  TEXT NOT NULL DEFAULT '',
    seen_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (host_id, dest, mask, nexthop)
);
CREATE TABLE IF NOT EXISTS net_fdb (            -- table MAC des commutateurs
    host_id  INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    mac      TEXT NOT NULL,
    port     TEXT NOT NULL,
    seen_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (host_id, mac)
);

CREATE TABLE IF NOT EXISTS host_roles (
    host_id    INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    role       TEXT NOT NULL,                 -- server, workstation, network, printer, camera, iot, mobile, guest, admin, unknown
    source     TEXT NOT NULL DEFAULT 'auto',  -- auto, manual (un choix manuel n'est jamais écrasé)
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS net_zones (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT NOT NULL UNIQUE,
    cidr  TEXT NOT NULL,
    trust INTEGER NOT NULL DEFAULT 50,        -- 0 = hostile (invités, Internet) … 100 = très sûre (serveurs)
    kind  TEXT NOT NULL DEFAULT 'lan',
    auto  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS assess_findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    fkey           TEXT NOT NULL UNIQUE,      -- clé stable : un même constat n'est jamais dupliqué
    host_id        INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
    category       TEXT NOT NULL,             -- exposure, vulnerability, segmentation, hygiene
    severity       TEXT NOT NULL,             -- critical, high, medium, low
    title          TEXT NOT NULL,
    detail         TEXT,
    recommendation TEXT,
    rule_hint      TEXT,                      -- JSON : règle suggérée (brouillon de politique)
    status         TEXT NOT NULL DEFAULT 'open',   -- open, accepted, fixed
    note           TEXT,
    first_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON assess_findings(status, severity);

CREATE TABLE IF NOT EXISTS policy_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    position   INTEGER NOT NULL DEFAULT 100,  -- ordre d'évaluation : la première règle qui correspond s'applique
    name       TEXT NOT NULL,
    src        TEXT NOT NULL DEFAULT 'any',   -- any | zone:<nom> | role:<rôle> | host:<id> | ip:<cidr>
    dst        TEXT NOT NULL DEFAULT 'any',
    service    TEXT NOT NULL DEFAULT 'any',   -- any | tcp/445 | udp/53 | tcp/80-443 | nom (ssh, rdp…)
    action     TEXT NOT NULL,                 -- allow, deny
    comment    TEXT,
    source     TEXT NOT NULL DEFAULT 'manual',     -- manual, template:<nom>, finding:<id>
    status     TEXT NOT NULL DEFAULT 'draft',      -- draft, approved, retired
    enabled    INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT,
    created_by TEXT,
    approved_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- Débits par équipement (v15.1), équipements retirés, blocages d'accès
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bw_samples (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ip      TEXT NOT NULL,
    ts      INTEGER NOT NULL,              -- epoch (s)
    rx_bps  REAL NOT NULL DEFAULT 0,       -- reçu par l'équipement (bits/s)
    tx_bps  REAL NOT NULL DEFAULT 0,       -- émis par l'équipement (bits/s)
    source  TEXT NOT NULL DEFAULT ''       -- snmp, local, netflow
);
CREATE INDEX IF NOT EXISTS idx_bw_ip_ts ON bw_samples(ip, ts);

CREATE TABLE IF NOT EXISTS ignored_devices (
    ip         TEXT PRIMARY KEY,
    mac        TEXT,
    name       TEXT,
    reason     TEXT,
    removed_by TEXT,
    removed_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS device_blocks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ip         TEXT NOT NULL,
    mac        TEXT,
    name       TEXT,
    gateway_id INTEGER,
    status     TEXT NOT NULL,              -- simulated, blocked, failed, lifted
    command    TEXT,
    rollback   TEXT,
    output     TEXT,
    reason     TEXT,
    by_user    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    lifted_at  TEXT
);

-- ───────── v16 : file d'attente des e-mails d'alerte ─────────
CREATE TABLE IF NOT EXISTS mail_outbox (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope_from TEXT NOT NULL,
    to_addrs      TEXT NOT NULL,
    subject       TEXT,
    raw           TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',   -- pending, sent, failed
    attempts      INTEGER NOT NULL DEFAULT 0,
    next_try      TEXT,
    last_error    TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ───────── v16 : verrouillage de connexion persistant ─────────
CREATE TABLE IF NOT EXISTS login_failures (
    login        TEXT PRIMARY KEY,
    count        INTEGER NOT NULL DEFAULT 0,
    locked_until REAL    NOT NULL DEFAULT 0
);

-- Paramètres système par défaut
INSERT OR IGNORE INTO settings (key, value) VALUES
  ('scan_interval',          '300'),
  ('snmp_interval',          '60'),
  ('session_timeout',        '30'),
  ('cpu_threshold',          '80'),
  ('ram_threshold',          '85'),
  ('default_snmp_community', 'public'),
  ('smtp_host',              ''),
  ('smtp_port',              '587'),
  ('smtp_user',              ''),
  ('smtp_password',          ''),
  ('smtp_from',              ''),
  ('smtp_to',                ''),
  ('webhook_url',            ''),
  ('webhook_secret',         '');

-- Groupe d'hôtes par défaut
INSERT OR IGNORE INTO host_groups (name, description)
VALUES
  ('Datacenter Paris-DC1',   'Datacenter principal Paris'),
  ('Datacenter Lyon-DC2',    'Datacenter secondaire Lyon'),
  ('Réseau cœur',            'Infrastructure réseau cœur'),
  ('Serveurs applicatifs',   'Serveurs applications métier'),
  ('Serveurs base de données','Serveurs SGBD'),
  ('Sécurité périmétrique',  'Firewalls et équipements périmétrique'),
  ('Réseau Wi-Fi',           'Points d''accès sans fil'),
  ('Équipements imprimantes','Imprimantes et MFP');
"""
