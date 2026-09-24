const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const config = require('../config');

// Ensure data directories exist
const dataDir = path.dirname(config.dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
if (!fs.existsSync(config.uploadsDir)) {
  fs.mkdirSync(config.uploadsDir, { recursive: true });
}
if (!fs.existsSync(config.packagesDir)) {
  fs.mkdirSync(config.packagesDir, { recursive: true });
}

// Initialize SQLite database
const db = new Database(config.dbPath);

// Enable WAL (Write-Ahead Logging) mode for maximum concurrency and reliability
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

// Create Schema
const initSchema = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS secrets (
      id TEXT PRIMARY KEY,
      ciphertext TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      salt TEXT NOT NULL,
      integrity_hash TEXT NOT NULL,
      secret_type TEXT NOT NULL,
      title TEXT,
      description TEXT,
      sensitivity TEXT NOT NULL DEFAULT 'Normal',
      max_views INTEGER NOT NULL DEFAULT 1,
      views_remaining INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      security_policy TEXT NOT NULL,
      is_zero_trace INTEGER DEFAULT 0,
      fragmentation_mode TEXT DEFAULT 'OFF',
      fragments_json TEXT,
      dead_man_switch_hours REAL DEFAULT 0,
      dead_man_confirmed_at INTEGER DEFAULT 0,
      dual_consent_required INTEGER DEFAULT 0,
      dual_consent_status TEXT DEFAULT 'NONE',
      destruction_record TEXT,
      policy_version INTEGER DEFAULT 1
    );

    CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets(expires_at);
    CREATE INDEX IF NOT EXISTS idx_secrets_status ON secrets(status);

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      secret_id TEXT,
      event_type TEXT NOT NULL,
      details TEXT NOT NULL,
      ip_masked TEXT,
      user_agent TEXT,
      risk_level TEXT DEFAULT 'LOW',
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_events_secret_id ON security_events(secret_id);
    CREATE INDEX IF NOT EXISTS idx_events_created_at ON security_events(created_at);

    CREATE TABLE IF NOT EXISTS viewing_sessions (
      session_id TEXT PRIMARY KEY,
      secret_id TEXT NOT NULL,
      token TEXT NOT NULL,
      receiver_identity TEXT,
      device_fingerprint TEXT,
      ip_address TEXT,
      started_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      viewing_duration_seconds INTEGER NOT NULL,
      status TEXT DEFAULT 'ACTIVE',
      FOREIGN KEY(secret_id) REFERENCES secrets(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_secret_id ON viewing_sessions(secret_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON viewing_sessions(token);

    CREATE TABLE IF NOT EXISTS security_incidents (
      id TEXT PRIMARY KEY,
      incident_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'MEDIUM',
      correlated_events_count INTEGER DEFAULT 1,
      description TEXT NOT NULL,
      status TEXT DEFAULT 'OPEN',
      secret_id TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS canary_secrets (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      canary_type TEXT NOT NULL,
      synthetic_token TEXT NOT NULL,
      environment TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      access_count INTEGER DEFAULT 0,
      last_triggered_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS vault_files (
      id TEXT PRIMARY KEY,
      filename TEXT NOT NULL,
      original_name TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      mime_type TEXT NOT NULL,
      sha256_hash TEXT NOT NULL,
      classification TEXT NOT NULL DEFAULT 'CONFIDENTIAL',
      sensitivity_signals TEXT,
      encrypted_path TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      salt TEXT NOT NULL,
      owner TEXT NOT NULL DEFAULT 'SecurityAdmin',
      current_version INTEGER DEFAULT 1,
      is_locked INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_files_hash ON vault_files(sha256_hash);

    CREATE TABLE IF NOT EXISTS file_versions (
      id TEXT PRIMARY KEY,
      file_id TEXT NOT NULL,
      version_number INTEGER NOT NULL,
      sha256_hash TEXT NOT NULL,
      encrypted_path TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      salt TEXT NOT NULL,
      file_size INTEGER NOT NULL,
      change_summary TEXT,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(file_id) REFERENCES vault_files(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS file_shares (
      id TEXT PRIMARY KEY,
      file_id TEXT NOT NULL,
      token TEXT NOT NULL,
      recipient TEXT,
      permission TEXT DEFAULT 'VIEW',
      max_views INTEGER DEFAULT 1,
      views_remaining INTEGER DEFAULT 1,
      expires_at INTEGER NOT NULL,
      status TEXT DEFAULT 'ACTIVE',
      created_at INTEGER NOT NULL,
      FOREIGN KEY(file_id) REFERENCES vault_files(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS universal_packages (
      package_id TEXT PRIMARY KEY,
      secret_id TEXT NOT NULL,
      package_name TEXT NOT NULL,
      package_file_path TEXT NOT NULL,
      delivery_methods TEXT NOT NULL,
      integrity_fingerprint TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS vault_system_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);

  // Ensure default system state exists
  const checkLock = db.prepare('SELECT value FROM vault_system_state WHERE key = ?').get('vault_locked');
  if (!checkLock) {
    db.prepare('INSERT INTO vault_system_state (key, value, updated_at) VALUES (?, ?, ?)').run('vault_locked', '0', Date.now());
  }
};

initSchema();

module.exports = db;
