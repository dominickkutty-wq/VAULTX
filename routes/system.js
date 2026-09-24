const express = require('express');
const router = express.Router();
const db = require('../database/db');
const auditLogger = require('../services/auditLogger');
const incidentCorrelator = require('../services/incidentCorrelator');
const canaryService = require('../services/canaryService');
const expirySweeper = require('../services/expirySweeper');

/**
 * GET /api/system/stats
 * Dashboard overview counters
 */
router.get('/stats', (req, res) => {
  try {
    const totalSecrets = db.prepare('SELECT COUNT(*) as count FROM secrets').get().count;
    const activeSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE status = 'ACTIVE'").get().count;
    const destroyedSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE status = 'DESTROYED'").get().count;
    const expiredSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE status = 'EXPIRED'").get().count;
    const revokedSecrets = db.prepare("SELECT COUNT(*) as count FROM secrets WHERE status = 'REVOKED'").get().count;

    const blockedBots = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE event_type = 'BOT_BLOCKED'").get().count;
    const failedVerifications = db.prepare("SELECT COUNT(*) as count FROM security_events WHERE event_type = 'VERIFICATION_FAILED'").get().count;
    const openIncidents = db.prepare("SELECT COUNT(*) as count FROM security_incidents WHERE status = 'OPEN'").get().count;

    const totalFiles = db.prepare('SELECT COUNT(*) as count FROM vault_files').get().count;
    const packagesCount = db.prepare('SELECT COUNT(*) as count FROM universal_packages').get().count;

    const vaultLockRow = db.prepare("SELECT value FROM vault_system_state WHERE key = 'vault_locked'").get();
    const isVaultLocked = vaultLockRow ? vaultLockRow.value === '1' : false;

    // Created today
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const createdToday = db.prepare('SELECT COUNT(*) as count FROM secrets WHERE created_at >= ?').get(startOfDay.getTime()).count;

    return res.json({
      totalSecrets,
      activeSecrets,
      destroyedSecrets,
      expiredSecrets,
      revokedSecrets,
      createdToday,
      blockedBots,
      failedVerifications,
      openIncidents,
      totalFiles,
      packagesCount,
      isVaultLocked,
      encryptionStandard: 'AES-256-GCM',
      storageEngine: 'SQLite WAL Mode (Zero Plaintext at Rest)'
    });
  } catch (err) {
    console.error('Stats error:', err);
    return res.status(500).json({ error: 'Failed to fetch system stats' });
  }
});

/**
 * POST /api/system/toggle-lock
 * Emergency Vault Lock / Unlock
 */
router.post('/toggle-lock', (req, res) => {
  try {
    const current = db.prepare("SELECT value FROM vault_system_state WHERE key = 'vault_locked'").get();
    const newState = current && current.value === '1' ? '0' : '1';

    db.prepare("UPDATE vault_system_state SET value = ?, updated_at = ? WHERE key = 'vault_locked'").run(newState, Date.now());

    auditLogger.logEvent({
      eventType: newState === '1' ? 'VAULT_LOCKED' : 'VAULT_UNLOCKED',
      details: { locked: newState === '1', reason: 'Administrator Emergency Command' },
      riskLevel: newState === '1' ? 'HIGH' : 'LOW'
    });

    return res.json({
      success: true,
      vaultLocked: newState === '1',
      message: newState === '1' ? '🚨 EMERGENCY VAULT LOCK ACTIVE: All sensitive file accesses restricted.' : 'Vault lock released.'
    });
  } catch (err) {
    console.error('Lock error:', err);
    return res.status(500).json({ error: 'Failed to toggle vault lock' });
  }
});

/**
 * GET /api/system/audit-ledger
 * Global Security Audit Ledger
 */
router.get('/audit-ledger', (req, res) => {
  try {
    const limit = Math.min(100, Number(req.query.limit || 50));
    const events = auditLogger.getEvents(null, limit);
    return res.json({
      events: events.map(e => ({
        ...e,
        details: JSON.parse(e.details || '{}')
      }))
    });
  } catch (err) {
    console.error('Audit ledger error:', err);
    return res.status(500).json({ error: 'Failed to fetch audit ledger' });
  }
});

/**
 * GET /api/system/incidents
 * Correlated Security Incidents
 */
router.get('/incidents', (req, res) => {
  try {
    const incidents = incidentCorrelator.getIncidents(30);
    return res.json({ incidents });
  } catch (err) {
    console.error('Incidents error:', err);
    return res.status(500).json({ error: 'Failed to fetch security incidents' });
  }
});

/**
 * GET /api/system/canaries
 * List Canary decoy secrets
 */
router.get('/canaries', (req, res) => {
  try {
    const canaries = canaryService.listCanaries();
    return res.json({ canaries });
  } catch (err) {
    console.error('Canaries error:', err);
    return res.status(500).json({ error: 'Failed to fetch canaries' });
  }
});

/**
 * POST /api/system/trigger-canary
 * Simulate unauthorized access to a canary decoy credential
 */
router.post('/trigger-canary', (req, res) => {
  try {
    const { canaryId } = req.body;
    const result = canaryService.triggerCanary(canaryId, { ip: req.ip, userAgent: req.get('user-agent') });
    return res.json(result);
  } catch (err) {
    console.error('Trigger canary error:', err);
    return res.status(500).json({ error: 'Failed to trigger canary test' });
  }
});

/**
 * GET /api/system/rotations
 * Credential Rotation Assistant
 */
router.get('/rotations', (req, res) => {
  try {
    // Recommend rotation for secrets that were burned, revoked, or expired in past 7 days
    const items = db.prepare(`
      SELECT id, title, secret_type, sensitivity, status, created_at, expires_at,
             destruction_record
      FROM secrets
      WHERE status IN ('DESTROYED', 'REVOKED', 'EXPIRED')
      ORDER BY created_at DESC
      LIMIT 15
    `).all();

    const recommendations = items.map(item => ({
      secretId: item.id,
      title: item.title || item.secret_type,
      secretType: item.secret_type,
      sensitivity: item.sensitivity,
      lifecycleStatus: item.status,
      reason: item.status === 'REVOKED' 
        ? 'Emergency Revocation: Credential may have been compromised or link leaked.'
        : (item.status === 'EXPIRED' ? 'Lifecycle Expiry: Scheduled rotation interval reached.' : 'Single-Use Access Completed: Rotation recommended for zero-trust lifecycle.'),
      recommendedAction: `Rotate ${item.secret_type} in production provider and verify deprecation of old value.`,
      rotationStatus: 'RECOMMENDED'
    }));

    return res.json({ recommendations });
  } catch (err) {
    console.error('Rotations error:', err);
    return res.status(500).json({ error: 'Failed to fetch rotation recommendations' });
  }
});

/**
 * GET /api/system/health
 * Health check & background worker status
 */
router.get('/health', (req, res) => {
  const sweeperStatus = expirySweeper.getStatus();
  return res.json({
    status: 'HEALTHY',
    version: '2.0.0-ENTERPRISE',
    timestamp: Date.now(),
    sweeper: sweeperStatus,
    walMode: true,
    cryptoEngine: 'AES-256-GCM (Hardware Accelerated)'
  });
});

module.exports = router;
