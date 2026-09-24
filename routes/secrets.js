const express = require('express');
const router = express.Router();
const QRCode = require('qrcode');
const db = require('../database/db');
const cryptoService = require('../services/cryptoService');
const policyEngine = require('../services/policyEngine');
const fragmentationService = require('../services/fragmentationService');
const sessionManager = require('../services/sessionManager');
const auditLogger = require('../services/auditLogger');
const config = require('../config');

/**
 * POST /api/secrets
 * Creates a new secure, ephemeral secret
 */
router.post('/', async (req, res) => {
  try {
    const {
      secret,
      secretType = 'Custom Secret',
      title = 'Ephemeral Secret',
      description = '',
      sensitivity = 'Normal',
      policy = {},
      deliveryChannels = ['Secure Link']
    } = req.body;

    if (!secret || typeof secret !== 'string' || secret.trim().length === 0) {
      return res.status(400).json({ error: 'Secret content is required and cannot be empty' });
    }

    const secretId = cryptoService.generateSecureId(10);
    const now = Date.now();

    // Calculate expiry based on policy
    const expiryMinutes = policy?.viewing?.expiryMinutes || 10;
    const expiresAt = now + (expiryMinutes * 60 * 1000);
    const maxViews = policy?.viewing?.maxViews || 1;

    // Check fragmentation mode
    const fragmentationMode = policy?.advanced?.fragmentationMode || 'OFF';
    let fragmentsJson = null;
    let fragmentsList = null;

    if (fragmentationMode !== 'OFF') {
      fragmentsList = fragmentationService.fragmentSecret(secret, fragmentationMode);
      fragmentsJson = JSON.stringify(fragmentsList);
    }

    // Encrypt the main payload using AES-256-GCM
    // In fragmentation mode, ciphertext stores encrypted reference or master container
    const encrypted = cryptoService.encrypt(secret, `vaultx-id-${secretId}`);

    const isZeroTrace = policy?.advanced?.privacyMode === 'ZERO_TRACE' ? 1 : 0;
    const deadManHours = Number(policy?.advanced?.deadManSwitchHours || 0);
    const dualConsentRequired = policy?.advanced?.dualConsentRequired ? 1 : 0;
    const dualConsentStatus = dualConsentRequired ? 'PENDING' : 'NONE';

    const stmt = db.prepare(`
      INSERT INTO secrets (
        id, ciphertext, iv, auth_tag, salt, integrity_hash, secret_type, title, description,
        sensitivity, max_views, views_remaining, created_at, expires_at, status,
        security_policy, is_zero_trace, fragmentation_mode, fragments_json,
        dead_man_switch_hours, dead_man_confirmed_at, dual_consent_required,
        dual_consent_status, policy_version
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `);

    stmt.run(
      secretId,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag,
      encrypted.salt,
      encrypted.integrityHash,
      secretType,
      title,
      description,
      sensitivity,
      maxViews,
      maxViews,
      now,
      expiresAt,
      JSON.stringify(policy),
      isZeroTrace,
      fragmentationMode,
      fragmentsJson,
      deadManHours,
      deadManHours > 0 ? now : 0,
      dualConsentRequired,
      dualConsentStatus
    );

    // Generate secure receiver canonical URL and alternative local/LAN URLs
    const baseUrl = config.resolveBaseUrl(req);
    const viewUrl = `${baseUrl}/view/${secretId}`;
    const lanUrl = `${config.getLanBaseUrl()}/view/${secretId}`;
    const localUrl = `${config.getLocalBaseUrl()}/view/${secretId}`;

    console.log(`🛡️ [VaultX Diagnostic] LINK_GENERATION: ID=${secretId} Canonical=${viewUrl} LAN=${lanUrl} Local=${localUrl}`);

    // Generate QR code pointing ONLY to the secure URL (never contains plaintext secret!)
    const qrCodeDataUrl = await QRCode.toDataURL(viewUrl, {
      errorCorrectionLevel: 'H',
      margin: 2,
      color: {
        dark: '#00F0FF',
        light: '#070B14'
      }
    });

    // Coverage score
    const coverage = policyEngine.calculateConfigurationCoverage(policy);

    // Audit log (never logs plaintext!)
    auditLogger.logEvent({
      secretId,
      eventType: 'SECRET_CREATED',
      details: {
        secretType,
        sensitivity,
        maxViews,
        expiryMinutes,
        fragmentationMode,
        dualConsentRequired: !!dualConsentRequired,
        deadManHours,
        integrityHash: encrypted.integrityHash,
        coverageScore: coverage.coverageFraction
      },
      ip: req.ip,
      userAgent: req.get('user-agent')
    });

    return res.status(201).json({
      success: true,
      id: secretId,
      viewUrl,
      lanUrl,
      localUrl,
      canonicalPath: `/view/${secretId}`,
      qrCodeDataUrl,
      integrityHash: encrypted.integrityHash,
      secretType,
      title,
      sensitivity,
      expiresAt,
      maxViews,
      coverageScore: coverage.coverageFraction,
      coverageDetails: coverage.details,
      fragmentationStatus: fragmentationMode !== 'OFF' ? `${fragmentationMode} (${fragmentsList ? fragmentsList.length : 0} Encrypted Fragments)` : 'OFF',
      dualConsentRequired: !!dualConsentRequired,
      deadManHours
    });
  } catch (err) {
    console.error('Error creating secret:', err);
    return res.status(500).json({ error: 'Internal security engine error creating secret' });
  }
});

/**
 * GET /api/secrets
 * List all active/recent secrets for Sender Dashboard
 * Returns ONLY safe metadata. NEVER returns ciphertext or plaintext!
 */
router.get('/', (req, res) => {
  try {
    const secrets = db.prepare(`
      SELECT id, secret_type, title, description, sensitivity, max_views, views_remaining,
             created_at, expires_at, status, is_zero_trace, fragmentation_mode,
             dead_man_switch_hours, dead_man_confirmed_at, dual_consent_required,
             dual_consent_status, integrity_hash, policy_version
      FROM secrets
      ORDER BY created_at DESC
      LIMIT 100
    `).all();

    return res.json({ secrets });
  } catch (err) {
    console.error('Error listing secrets:', err);
    return res.status(500).json({ error: 'Failed to retrieve secrets metadata' });
  }
});

/**
 * GET /api/secrets/:id/status
 * Detailed Sender Delivery Status & receipt
 */
router.get('/:id/status', (req, res) => {
  try {
    const { id } = req.params;
    const secret = db.prepare(`
      SELECT id, secret_type, title, sensitivity, max_views, views_remaining,
             created_at, expires_at, status, security_policy, is_zero_trace,
             fragmentation_mode, dual_consent_status, destruction_record, integrity_hash
      FROM secrets WHERE id = ?
    `).get(id);

    if (!secret) {
      return res.status(404).json({ error: 'Secret record not found or already purged' });
    }

    const policy = JSON.parse(secret.security_policy || '{}');
    const events = auditLogger.getEvents(id, 20);
    const sessions = db.prepare('SELECT session_id, receiver_identity, started_at, viewing_duration_seconds, status FROM viewing_sessions WHERE secret_id = ?').all(id);

    return res.json({
      secret: {
        ...secret,
        policySummary: policy
      },
      events,
      sessions,
      destructionProof: secret.destruction_record ? JSON.parse(secret.destruction_record) : null
    });
  } catch (err) {
    console.error('Error getting delivery status:', err);
    return res.status(500).json({ error: 'Failed to retrieve delivery receipt' });
  }
});

/**
 * POST /api/secrets/:id/revoke
 * Emergency Kill Switch / Revoke Access ("🔥 DESTROY NOW")
 */
router.post('/:id/revoke', (req, res) => {
  try {
    const { id } = req.params;
    const secret = db.prepare('SELECT * FROM secrets WHERE id = ?').get(id);

    if (!secret) {
      return res.status(404).json({ error: 'Secret not found or already destroyed' });
    }

    const destructionRecord = auditLogger.createDestructionRecord(id, 'SENDER_EMERGENCY_KILL_SWITCH', secret.integrity_hash, secret.policy_version);

    const killTx = db.transaction(() => {
      // Invalidate all active viewing sessions
      sessionManager.invalidateSecretSessions(id, 'REVOKED');

      // Permanently wipe or mark destroyed
      if (secret.is_zero_trace) {
        db.prepare(`
          UPDATE secrets 
          SET status = 'REVOKED',
              ciphertext = '',
              iv = '',
              auth_tag = '',
              salt = '',
              fragments_json = NULL,
              views_remaining = 0,
              destruction_record = ?
          WHERE id = ?
        `).run(JSON.stringify(destructionRecord), id);

        auditLogger.enforceZeroTrace(id);
      } else {
        db.prepare(`
          UPDATE secrets 
          SET status = 'REVOKED',
              ciphertext = '',
              iv = '',
              auth_tag = '',
              salt = '',
              fragments_json = NULL,
              views_remaining = 0,
              destruction_record = ?
          WHERE id = ?
        `).run(JSON.stringify(destructionRecord), id);
      }

      auditLogger.logEvent({
        secretId: id,
        eventType: 'EMERGENCY_REVOCATION',
        details: { reason: 'Sender triggered emergency kill switch', proofHash: destructionRecord.proofHash },
        riskLevel: 'LOW'
      });
    });

    killTx();

    return res.json({
      success: true,
      message: 'Secret immediately and permanently revoked. All active viewing sessions terminated.',
      destructionRecord
    });
  } catch (err) {
    console.error('Error revoking secret:', err);
    return res.status(500).json({ error: 'Failed to execute emergency kill switch' });
  }
});

/**
 * POST /api/secrets/:id/dual-consent
 * Sender approves or rejects pending dual-consent request
 */
router.post('/:id/dual-consent', (req, res) => {
  try {
    const { id } = req.params;
    const { decision } = req.body; // 'APPROVED' | 'REJECTED'

    if (!['APPROVED', 'REJECTED'].includes(decision)) {
      return res.status(400).json({ error: 'Invalid decision. Must be APPROVED or REJECTED' });
    }

    const secret = db.prepare('SELECT id, status, dual_consent_status FROM secrets WHERE id = ?').get(id);
    if (!secret || secret.status !== 'ACTIVE') {
      return res.status(404).json({ error: 'Secret not active or not found' });
    }

    db.prepare('UPDATE secrets SET dual_consent_status = ? WHERE id = ?').run(decision, id);

    auditLogger.logEvent({
      secretId: id,
      eventType: decision === 'APPROVED' ? 'DUAL_CONSENT_APPROVED' : 'DUAL_CONSENT_REJECTED',
      details: { decision }
    });

    return res.json({ success: true, dualConsentStatus: decision });
  } catch (err) {
    console.error('Dual consent error:', err);
    return res.status(500).json({ error: 'Failed to update dual consent status' });
  }
});

/**
 * POST /api/secrets/:id/dead-man-confirm
 * Sender confirms check-in for Dead-Man Switch
 */
router.post('/:id/dead-man-confirm', (req, res) => {
  try {
    const { id } = req.params;
    const now = Date.now();

    const result = db.prepare('UPDATE secrets SET dead_man_confirmed_at = ? WHERE id = ? AND dead_man_switch_hours > 0').run(now, id);
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Secret with dead-man switch not found' });
    }

    auditLogger.logEvent({
      secretId: id,
      eventType: 'DEAD_MAN_CONFIRMED',
      details: { confirmedAt: now }
    });

    return res.json({ success: true, message: 'Dead-man switch timer successfully reset' });
  } catch (err) {
    console.error('Dead man confirm error:', err);
    return res.status(500).json({ error: 'Failed to confirm dead man switch' });
  }
});

/**
 * POST /api/secrets/:id/break-glass
 * Controlled Break-Glass Emergency Access
 */
router.post('/:id/break-glass', (req, res) => {
  try {
    const { id } = req.params;
    const { reason, authorizedRole = 'SecurityAdmin' } = req.body;

    if (!reason || reason.trim().length < 5) {
      return res.status(400).json({ error: 'A justified operational reason is required for Break-Glass emergency access' });
    }

    const secret = db.prepare('SELECT * FROM secrets WHERE id = ?').get(id);
    if (!secret || secret.status !== 'ACTIVE') {
      return res.status(404).json({ error: 'Secret not available or already burned' });
    }

    auditLogger.logEvent({
      secretId: id,
      eventType: 'BREAK_GLASS_TRIGGERED',
      details: { reason, authorizedRole },
      riskLevel: 'HIGH'
    });

    return res.json({
      success: true,
      message: 'Break-glass emergency authorization logged. Session elevated.',
      authorizedRole
    });
  } catch (err) {
    console.error('Break glass error:', err);
    return res.status(500).json({ error: 'Break glass procedure failed' });
  }
});

module.exports = router;
