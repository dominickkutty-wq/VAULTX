const db = require('../database/db');
const cryptoService = require('./cryptoService');

class IncidentCorrelator {
  /**
   * Correlates recent signals and creates or updates a security incident
   */
  correlate({
    incidentType,
    severity = 'MEDIUM',
    secretId = null,
    description,
    ip = '127.0.0.1'
  }) {
    try {
      const now = Date.now();
      const lookback = now - 300000; // 5 minutes lookback for active incidents

      // Check if an existing open incident of same type on this secret exists
      const existing = secretId 
        ? db.prepare('SELECT * FROM security_incidents WHERE secret_id = ? AND incident_type = ? AND status = ? AND created_at > ?').get(secretId, incidentType, 'OPEN', lookback)
        : null;

      if (existing) {
        db.prepare('UPDATE security_incidents SET correlated_events_count = correlated_events_count + 1, severity = ?, description = ? WHERE id = ?')
          .run(severity, description, existing.id);
        return existing.id;
      }

      const id = 'inc_' + cryptoService.generateSecureId(8);
      db.prepare(`
        INSERT INTO security_incidents (id, incident_type, severity, correlated_events_count, description, status, secret_id, created_at)
        VALUES (?, ?, ?, 1, ?, 'OPEN', ?, ?)
      `).run(id, incidentType, severity, description, secretId, now);

      return id;
    } catch (err) {
      console.error('IncidentCorrelator error:', err.message);
      return null;
    }
  }

  /**
   * Get recent incidents
   */
  getIncidents(limit = 20) {
    return db.prepare('SELECT * FROM security_incidents ORDER BY created_at DESC LIMIT ?').all(limit);
  }
}

module.exports = new IncidentCorrelator();
