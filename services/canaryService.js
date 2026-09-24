const db = require('../database/db');
const cryptoService = require('./cryptoService');
const auditLogger = require('./auditLogger');
const incidentCorrelator = require('./incidentCorrelator');

class CanaryService {
  constructor() {
    this.seedDefaultCanaries();
  }

  seedDefaultCanaries() {
    const count = db.prepare('SELECT COUNT(*) as count FROM canary_secrets').get().count;
    if (count === 0) {
      this.createCanary('AWS Production Root Key', 'API_KEY', 'AWS_AKIA_' + cryptoService.generateSecureId(8).toUpperCase(), 'Cloud Infrastructure');
      this.createCanary('PostgreSQL Production Database Credential', 'PASSWORD', 'pg_root_' + cryptoService.generateSecureId(10), 'Production Database');
      this.createCanary('Stripe Live Restricted Key', 'API_KEY', 'rk_live_' + cryptoService.generateSecureId(12), 'Payment Gateway');
    }
  }

  createCanary(name, canaryType, syntheticToken, environment) {
    const id = 'can_' + cryptoService.generateSecureId(8);
    const now = Date.now();

    db.prepare(`
      INSERT INTO canary_secrets (id, name, canary_type, synthetic_token, environment, created_at, access_count)
      VALUES (?, ?, ?, ?, ?, ?, 0)
    `).run(id, name, canaryType, syntheticToken, environment, now);

    return { id, name, canaryType, environment };
  }

  /**
   * Trigger canary detection when synthetic token is accessed or touched
   */
  triggerCanary(canaryId, context = {}) {
    const canary = db.prepare('SELECT * FROM canary_secrets WHERE id = ?').get(canaryId);
    if (!canary) return { detected: false };

    const now = Date.now();
    db.prepare('UPDATE canary_secrets SET access_count = access_count + 1, last_triggered_at = ? WHERE id = ?').run(now, canaryId);

    // Log high risk audit event
    auditLogger.logEvent({
      secretId: canaryId,
      eventType: 'CANARY_DECOY_ACCESSED',
      details: {
        canaryName: canary.name,
        canaryType: canary.canary_type,
        environment: canary.environment,
        context
      },
      ip: context.ip || '127.0.0.1',
      riskLevel: 'HIGH'
    });

    // Create immediate high-severity incident
    incidentCorrelator.correlate({
      incidentType: 'CANARY_DECOY_TRIGGERED',
      severity: 'CRITICAL',
      secretId: canaryId,
      description: `Decoy credential "${canary.name}" (${canary.environment}) was accessed. Potential unauthorized surveillance or insider threat.`,
      ip: context.ip || '127.0.0.1'
    });

    return {
      detected: true,
      canaryName: canary.name,
      alert: 'HIGH_PRIORITY_SECURITY_INCIDENT_CREATED'
    };
  }

  listCanaries() {
    return db.prepare('SELECT id, name, canary_type, environment, created_at, access_count, last_triggered_at FROM canary_secrets ORDER BY created_at DESC').all();
  }
}

module.exports = new CanaryService();
