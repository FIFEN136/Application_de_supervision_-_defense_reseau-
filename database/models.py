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
    last_check      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ─────────────────────────────────────────
-- États des ports TCP (scan)
-- ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS port_states (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    DEFAULT 'TCP',
    state       TEXT    NOT NULL,  -- open, closed, filtered
    latency_ms  REAL,
    scanned_at  TEXT    NOT NULL DEFAULT (datetime('now'))
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
    hmac        TEXT    NOT NULL,   -- HMAC-SHA256 de (id|user|action|target|detail|ts)
    logged_at   TEXT    NOT NULL DEFAULT (datetime('now'))
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
