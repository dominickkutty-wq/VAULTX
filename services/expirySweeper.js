const db = require('../database/db');
const auditLogger = require('./auditLogger');
const config = require('../config');

class ExpirySweeper {
  constructor() {
    this.intervalId = null;
    this.lastRun = null;
    this.sweptCount = 0;
  }

  start() {
    if (this.intervalId) return;

    this.intervalId = setInterval(() => {
      this.sweep();
    }, config.sweeperIntervalMs || 10000);

    console.log(`🛡️ [VaultX Sweeper] Background TTL & Dead-Man sweeper started (Interval: ${config.sweeperIntervalMs / 1000}s)`);
  }

  stop() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
  }

  /**
   * Sweeps expired secrets and triggered dead-man switches
   */
  sweep() {
    this.lastRun = Date.now();
    try {
      const now = Date.now();

      // 1. Sweep TTL-expired secrets
      const expiredSecrets = db.prepare(`
        SELECT id, integrity_hash, is_zero_trace, policy_version, title 
        FROM secrets 
        WHERE status = 'ACTIVE' AND expires_at <= ?
      `).all(now);

      for (const secret of expiredSecrets) {
        this.processDestruction(secret.id, 'TTL_EXPIRED', secret.integrity_hash, secret.is_zero_trace, secret.policy_version);
        this.sweptCount++;
      }

      // 2. Sweep Dead-Man Switch expired secrets
      const deadManSecrets = db.prepare(`
        SELECT id, integrity_hash, is_zero_trace, policy_version, dead_man_switch_hours, dead_man_confirmed_at
        FROM secrets 
        WHERE status = 'ACTIVE' AND dead_man_switch_hours > 0 AND (dead_man_confirmed_at + (dead_man_switch_hours * 3600000)) <= ?
      `).all(now);

      for (const secret of deadManSecrets) {
        this.processDestruction(secret.id, 'DEAD_MAN_SWITCH_UNCONFIRMED', secret.integrity_hash, secret.is_zero_trace, secret.policy_version);
        this.sweptCount++;
      }

      // 3. Clean up expired viewing sessions
      db.prepare(`
        UPDATE viewing_sessions 
        SET status = 'EXPIRED' 
        WHERE status = 'ACTIVE' AND expires_at <= ?
      `).run(now);

    } catch (err) {
      console.error('🛡️ [VaultX Sweeper] Error during sweep:', err.message);
    }
  }

  /**
   * Atomically process destruction of a secret
   */
  processDestruction(secretId, reason, integrityHash, isZeroTrace, policyVersion = 1) {
    const destructionRecord = auditLogger.createDestructionRecord(secretId, reason, integrityHash, policyVersion);

    const deleteOrWipe = db.transaction(() => {
      // Invalidate sessions
      db.prepare("UPDATE viewing_sessions SET status = 'EXPIRED' WHERE secret_id = ?").run(secretId);

      if (isZeroTrace) {
        // Zero-trace mode: permanently wipe cryptographic ciphertext and payload columns immediately
        db.prepare(`
          UPDATE secrets 
          SET status = 'EXPIRED',
              ciphertext = '',
              iv = '',
              auth_tag = '',
              salt = '',
              fragments_json = NULL,
              destruction_record = ?
          WHERE id = ?
        `).run(JSON.stringify(destructionRecord), secretId);

        auditLogger.enforceZeroTrace(secretId);
      } else {
        db.prepare(`
          UPDATE secrets 
          SET status = 'EXPIRED',
              ciphertext = '',
              iv = '',
              auth_tag = '',
              salt = '',
              fragments_json = NULL,
              destruction_record = ?
          WHERE id = ?
        `).run(JSON.stringify(destructionRecord), secretId);
      }

      auditLogger.logEvent({
        secretId,
        eventType: 'SECRET_EXPIRED',
        details: { reason, proofHash: destructionRecord.proofHash }
      });
    });

    deleteOrWipe();
  }

  getStatus() {
    return {
      active: !!this.intervalId,
      intervalSeconds: config.sweeperIntervalMs / 1000,
      lastRun: this.lastRun,
      sweptCount: this.sweptCount
    };
  }
}

module.exports = new ExpirySweeper();
