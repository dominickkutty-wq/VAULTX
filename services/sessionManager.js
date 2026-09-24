const db = require('../database/db');
const cryptoService = require('./cryptoService');
const auditLogger = require('./auditLogger');

class SessionManager {
  /**
   * Create a new short-lived viewing session after successful verification
   */
  createSession({
    secretId,
    receiverIdentity = 'Anonymous Receiver',
    deviceFingerprint = 'standard-browser',
    ip = '127.0.0.1',
    durationSeconds = 60
  }) {
    const sessionId = 'ses_' + cryptoService.generateSecureId(10);
    const token = cryptoService.generateSecureId(16);
    const now = Date.now();
    const expiresAt = now + (durationSeconds * 1000);

    const stmt = db.prepare(`
      INSERT INTO viewing_sessions (session_id, secret_id, token, receiver_identity, device_fingerprint, ip_address, started_at, expires_at, viewing_duration_seconds, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
    `);

    stmt.run(sessionId, secretId, token, receiverIdentity, deviceFingerprint, ip, now, expiresAt, durationSeconds);

    auditLogger.logEvent({
      secretId,
      eventType: 'VIEWING_STARTED',
      details: { sessionId, durationSeconds, receiverIdentity },
      ip
    });

    return {
      sessionId,
      token,
      expiresAt,
      durationSeconds
    };
  }

  /**
   * Continuous Session Validation: checks token validity, expiry, secret status, and sender revocation
   */
  validateSession(sessionId, token) {
    if (!sessionId || !token) {
      return { valid: false, reason: 'MISSING_SESSION_CREDENTIALS' };
    }

    const session = db.prepare(`
      SELECT s.*, sec.status AS secret_status, sec.expires_at AS secret_expires_at
      FROM viewing_sessions s
      JOIN secrets sec ON s.secret_id = sec.id
      WHERE s.session_id = ? AND s.token = ?
    `).get(sessionId, token);

    if (!session) {
      return { valid: false, reason: 'SESSION_NOT_FOUND' };
    }

    if (session.status !== 'ACTIVE') {
      return { valid: false, reason: `SESSION_${session.status}` };
    }

    // Check if secret was revoked or destroyed by sender
    if (session.secret_status === 'REVOKED') {
      db.prepare('UPDATE viewing_sessions SET status = ? WHERE session_id = ?').run('REVOKED', sessionId);
      return { valid: false, reason: 'SECRET_REVOKED_BY_SENDER' };
    }

    if (session.secret_status === 'DESTROYED') {
      // If secret was destroyed as part of atomic burn, session can continue only until viewing timer ends
    }

    // Check session expiry timer
    const now = Date.now();
    if (now >= session.expires_at) {
      db.prepare('UPDATE viewing_sessions SET status = ? WHERE session_id = ?').run('EXPIRED', sessionId);
      return { valid: false, reason: 'SESSION_TIMER_EXPIRED' };
    }

    const secondsRemaining = Math.max(0, Math.ceil((session.expires_at - now) / 1000));
    return {
      valid: true,
      secondsRemaining,
      secretId: session.secret_id
    };
  }

  /**
   * Invalidate all active sessions for a secret (e.g. upon emergency kill switch)
   */
  invalidateSecretSessions(secretId, reason = 'REVOKED') {
    db.prepare('UPDATE viewing_sessions SET status = ? WHERE secret_id = ? AND status = ?')
      .run(reason, secretId, 'ACTIVE');
  }

  /**
   * Close a viewing session manually or when time ends
   */
  terminateSession(sessionId) {
    const session = db.prepare('SELECT * FROM viewing_sessions WHERE session_id = ?').get(sessionId);
    if (session) {
      db.prepare('UPDATE viewing_sessions SET status = ? WHERE session_id = ?').run('BURNED', sessionId);
      auditLogger.logEvent({
        secretId: session.secret_id,
        eventType: 'VIEWING_ENDED',
        details: { sessionId }
      });
    }
  }
}

module.exports = new SessionManager();
