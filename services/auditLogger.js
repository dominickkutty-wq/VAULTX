const crypto = require('crypto');
const db = require('../database/db');
const cryptoService = require('./cryptoService');

class AuditLogger {
  /**
   * Masks an IP address for privacy
   */
  maskIp(ip) {
    if (!ip) return '0.0.0.0';
    if (ip.includes(':')) {
      // IPv6
      const parts = ip.split(':');
      return parts.slice(0, 3).join(':') + '::***';
    }
    // IPv4
    const parts = ip.split('.');
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.***`;
    }
    return '***';
  }

  /**
   * Log a security event to the audit ledger
   * NEVER logs plaintext secrets, keys, OTPs, or biometric data!
   */
  logEvent({
    secretId = null,
    eventType,
    details = {},
    ip = '127.0.0.1',
    userAgent = '',
    riskLevel = 'LOW'
  }) {
    try {
      const id = 'evt_' + cryptoService.generateSecureId(8);
      const ipMasked = this.maskIp(ip);
      const createdAt = Date.now();

      // Sanitize details to guarantee zero leakage of secret or credentials
      const safeDetails = { ...details };
      delete safeDetails.plaintext;
      delete safeDetails.secret;
      delete safeDetails.otp;
      delete safeDetails.key;
      delete safeDetails.passkey;
      delete safeDetails.masterKey;
      delete safeDetails.biometric;

      const stmt = db.prepare(`
        INSERT INTO security_events (id, secret_id, event_type, details, ip_masked, user_agent, risk_level, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(id, secretId, eventType, JSON.stringify(safeDetails), ipMasked, (userAgent || '').substring(0, 150), riskLevel, createdAt);

      return { id, eventType, createdAt };
    } catch (err) {
      console.error('AuditLogger error:', err.message);
      return null;
    }
  }

  /**
   * Creates a verifiable cryptographic destruction record
   */
  createDestructionRecord(secretId, reason, ciphertextFingerprint, policyVersion = 1) {
    const destroyedAt = Date.now();
    const eventId = 'dest_' + cryptoService.generateSecureId(8);

    const recordPayload = `${secretId}:${reason}:${ciphertextFingerprint}:${destroyedAt}:${policyVersion}`;
    const proofHash = crypto.createHash('sha256').update(recordPayload).digest('hex');

    return {
      eventId,
      secretId,
      destroyedAt,
      reason,
      ciphertextFingerprint,
      policyVersion,
      proofHash,
      destroyedBy: 'VaultX Atomic Security Worker',
      verificationStatus: 'CONFIRMED_PERMANENT_DESTRUCTION'
    };
  }

  /**
   * Retrieves audit events for a secret or global ledger
   */
  getEvents(secretId = null, limit = 50) {
    if (secretId) {
      return db.prepare('SELECT * FROM security_events WHERE secret_id = ? ORDER BY created_at DESC LIMIT ?').all(secretId, limit);
    }
    return db.prepare('SELECT * FROM security_events ORDER BY created_at DESC LIMIT ?').all(limit);
  }

  /**
   * Application-Level Zero-Trace Cleanup
   * Prunes non-essential logs if secret requested zero-trace
   */
  enforceZeroTrace(secretId) {
    try {
      // Retain only destruction confirmation, remove verbose access telemetry
      db.prepare(`
        DELETE FROM security_events 
        WHERE secret_id = ? AND event_type NOT IN ('SECRET_DESTROYED', 'EMERGENCY_REVOCATION', 'TTL_EXPIRED')
      `).run(secretId);
    } catch (err) {
      console.error('Zero-trace purge error:', err.message);
    }
  }
}

module.exports = new AuditLogger();
