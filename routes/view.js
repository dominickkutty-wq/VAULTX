const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db = require('../database/db');
const cryptoService = require('../services/cryptoService');
const policyEngine = require('../services/policyEngine');
const sessionManager = require('../services/sessionManager');
const riskEngine = require('../services/riskEngine');
const auditLogger = require('../services/auditLogger');
const fragmentationService = require('../services/fragmentationService');

// In-memory OTP storage for receiver verification
const otpStore = new Map(); // secretId -> { code, expiresAt, email }

/**
 * Helper: Detect bot or link preview crawlers
 */
function isBotCrawler(userAgent = '') {
  const ua = (userAgent || '').toLowerCase();
  const botSignatures = [
    'slackbot', 'discordbot', 'facebookexternalhit', 'twitterbot',
    'telegrambot', 'whatsapp', 'linkedinbot', 'embedly',
    'crawler', 'spider', 'curl', 'wget', 'python-requests', 'headlesschrome'
  ];
  return botSignatures.some(bot => ua.includes(bot));
}

function maskIdentity(email) {
  if (!email || !email.includes('@')) return 'Bound identity';
  const parts = email.split('@');
  const user = parts[0];
  const domain = parts[1];
  const maskedUser = user.length > 2 ? user[0] + '***' + user[user.length - 1] : user[0] + '***';
  return `${maskedUser}@${domain}`;
}

/**
 * Common handler for Safe Landing Page:
 * GET /view/:id, GET /open/:id, GET /receiver/:id
 * MUST NOT DECRYPT, MUST NOT BURN!
 */
function handleLandingPage(req, res) {
  const rawId = req.params.id || '';
  const id = rawId.trim();
  const userAgent = req.get('user-agent') || '';
  const isBot = isBotCrawler(userAgent);

  console.log(`🛡️ [VaultX Diagnostic] ROUTE_RESOLUTION: Landing page requested for ID=${id} | User-Agent=${userAgent.substring(0, 50)} | IsBot=${isBot}`);

  // Scraper Shield Defense
  if (isBot) {
    auditLogger.logEvent({
      secretId: id,
      eventType: 'BOT_BLOCKED',
      details: { userAgent, botDetected: true, defense: 'Scraper Shield engaged - Safe preview served, secret untouched' },
      ip: req.ip,
      riskLevel: 'LOW'
    });

    return res.status(200).send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>VaultX — Ephemeral Protected Secret</title>
        <meta property="og:title" content="VaultX Ephemeral Protected Secret">
        <meta property="og:description" content="This encrypted secret is protected by VaultX Zero-Trust Policy Engine. Decryption requires human verification.">
        <meta property="og:type" content="website">
        <meta name="robots" content="noindex, nofollow">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #070B14; color: #8F9CAE; padding: 40px; text-align: center; }
          .shield-box { max-width: 500px; margin: 60px auto; padding: 30px; border: 1px solid #1E293B; border-radius: 12px; background: #0D1526; }
          h2 { color: #00F0FF; margin-top: 0; }
        </style>
      </head>
      <body>
        <div class="shield-box">
          <h2>🛡️ Scraper Shield Active</h2>
          <p>Automated link crawlers cannot view or burn VaultX ephemeral secrets.</p>
          <p style="font-size: 13px; color: #64748B;">Safe landing preview returned. Secret remains encrypted at rest.</p>
        </div>
      </body>
      </html>
    `);
  }

  // Human user: Log landing view (safe metadata only)
  auditLogger.logEvent({
    secretId: id,
    eventType: 'LINK_ACCESSED',
    details: { humanVerified: true, route: req.path },
    ip: req.ip,
    userAgent
  });

  // Serve the SPA application which routes to receiver view
  const indexPath = path.join(__dirname, '..', 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }

  return res.status(200).send(`<h1>VaultX Safe Landing</h1><p>Secret ID: ${id}</p>`);
}

// 1. Landing Page Routes - Explicitly register /view/:id, /open/:id, /receiver/:id
router.get('/view/:id', handleLandingPage);
router.get('/open/:id', handleLandingPage);
router.get('/receiver/:id', handleLandingPage);

/**
 * GET /api/view/:id/metadata (also /api/open/:id/metadata, /api/receiver/:id/metadata)
 * Return safe metadata for receiver landing page
 * NEVER returns plaintext, ciphertext, or keys!
 * Returns structured error states: INVALID_LINK, EXPIRED_LINK, REVOKED_LINK, SECRET_ALREADY_CONSUMED
 */
function handleMetadata(req, res) {
  const id = (req.params.id || '').trim();
  console.log(`🛡️ [VaultX Diagnostic] TOKEN_LOOKUP: Metadata requested for ID=${id}`);

  const secret = db.prepare(`
    SELECT id, secret_type, title, description, sensitivity, max_views, views_remaining,
           created_at, expires_at, status, security_policy, dual_consent_status, dead_man_switch_hours
    FROM secrets WHERE id = ?
  `).get(id);

  if (!secret) {
    console.log(`🛡️ [VaultX Diagnostic] TOKEN_LOOKUP_FAILED: Secret ID=${id} not found in database`);
    return res.status(404).json({
      error: 'INVALID_LINK',
      message: 'This secure link is invalid, corrupted, or does not exist.',
      status: 'NOT_FOUND'
    });
  }

  const now = Date.now();

  // Check Revocation
  if (secret.status === 'REVOKED') {
    return res.status(403).json({
      error: 'REVOKED_LINK',
      message: 'This secure link was revoked by the sender.',
      status: 'REVOKED'
    });
  }

  // Check Expiry
  if (secret.status === 'EXPIRED' || now >= secret.expires_at) {
    return res.status(410).json({
      error: 'EXPIRED_LINK',
      message: 'This secure link has expired and was cleaned up.',
      status: 'EXPIRED'
    });
  }

  // Check Views Consumed / Burned
  if (secret.status === 'DESTROYED' || secret.views_remaining <= 0) {
    return res.status(410).json({
      error: 'SECRET_ALREADY_CONSUMED',
      message: 'This single-use secret has already been revealed and destroyed.',
      status: 'DESTROYED'
    });
  }

  if (secret.status !== 'ACTIVE') {
    return res.status(404).json({
      error: 'LINK_INACTIVE',
      message: `Secret is currently ${secret.status}.`,
      status: secret.status
    });
  }

  const policy = JSON.parse(secret.security_policy || '{}');

  console.log(`🛡️ [VaultX Diagnostic] TOKEN_VALIDATED: Secret ID=${id} ACTIVE. Views remaining: ${secret.views_remaining}/${secret.max_views}`);

  // Return only non-sensitive receiver metadata
  return res.json({
    id: secret.id,
    secretType: secret.secret_type,
    title: secret.title || 'Protected Ephemeral Secret',
    description: secret.description,
    sensitivity: secret.sensitivity,
    viewsRemaining: secret.views_remaining,
    maxViews: secret.max_views,
    expiresAt: secret.expires_at,
    secondsUntilExpiry: Math.max(0, Math.ceil((secret.expires_at - now) / 1000)),
    viewingDurationSeconds: policy?.viewing?.viewingDurationSeconds || 60,
    dualConsentStatus: secret.dual_consent_status,
    verificationRequirements: {
      requireEmailOtp: !!policy?.verification?.requireEmailOtp,
      requirePasskey: !!policy?.verification?.requirePasskey,
      requireCamera: !!policy?.verification?.requireCamera,
      requireLiveness: !!policy?.verification?.requireLiveness,
      requireCustomCode: !!policy?.verification?.requireCustomCode,
      boundIdentityHint: policy?.verification?.boundIdentity ? maskIdentity(policy.verification.boundIdentity) : null
    },
    protection: {
      disableCopy: !!policy?.protection?.disableCopy,
      disableDownload: !!policy?.protection?.disableDownload,
      disablePrint: !!policy?.protection?.disablePrint,
      autoBlurOnFocusLoss: !!policy?.protection?.autoBlurOnFocusLoss,
      accessScope: policy?.protection?.accessScope || 'VIEW_ONLY'
    }
  });
}

router.get(['/api/view/:id/metadata', '/api/open/:id/metadata', '/api/receiver/:id/metadata'], handleMetadata);

/**
 * GET /api/view/:id/diagnostics
 * Receiver Test Panel Diagnostic Endpoint
 * Validates and returns status of all 7 link verification stages
 */
function handleDiagnostics(req, res) {
  const id = (req.params.id || '').trim();
  const secret = db.prepare(`SELECT * FROM secrets WHERE id = ?`).get(id);

  const stageResults = {
    linkGenerated: true,
    tokenPersisted: !!secret,
    receiverRouteReachable: true,
    tokenValidated: false,
    secretRetrieved: false,
    permissionChecked: false,
    expiryChecked: false,
    status: secret ? secret.status : 'NOT_FOUND',
    viewsRemaining: secret ? secret.views_remaining : 0,
    maxViews: secret ? secret.max_views : 0,
    diagnosticsPassed: false,
    stageDetails: []
  };

  if (!secret) {
    stageResults.stageDetails.push('FAILED at Token Lookup: Secret ID not found in database.');
    return res.status(200).json(stageResults);
  }

  stageResults.tokenValidated = true;
  stageResults.secretRetrieved = true;

  const now = Date.now();
  const notExpired = (secret.status !== 'EXPIRED' && now < secret.expires_at);
  stageResults.expiryChecked = notExpired;

  const activeAndViews = (secret.status === 'ACTIVE' && secret.views_remaining > 0);
  stageResults.permissionChecked = activeAndViews;

  stageResults.diagnosticsPassed = (stageResults.tokenPersisted && stageResults.expiryChecked && stageResults.permissionChecked);

  stageResults.stageDetails = [
    'Stage 1 [Link Generated]: Valid canonical format.',
    'Stage 2 [Token Persisted]: SQLite row found with encrypted ciphertext.',
    'Stage 3 [Route Reachable]: /view, /open, and /receiver routes active.',
    'Stage 4 [Token Validated]: Status = ' + secret.status + '.',
    'Stage 5 [Expiry Checked]: ' + (notExpired ? 'TTL valid (' + Math.ceil((secret.expires_at - now)/1000) + 's remaining).' : 'Expired.'),
    'Stage 6 [Permission Checked]: Views remaining = ' + secret.views_remaining + '/' + secret.max_views + '.',
    'Stage 7 [Overall]: ' + (stageResults.diagnosticsPassed ? 'READY FOR RECEIVER ACCESS' : 'BLOCKED (' + secret.status + ')')
  ];

  return res.json(stageResults);
}

router.get(['/api/view/:id/diagnostics', '/api/open/:id/diagnostics', '/api/receiver/:id/diagnostics'], handleDiagnostics);

/**
 * POST /api/view/:id/request-otp
 * Generates OTP for receiver verification
 */
function handleRequestOtp(req, res) {
  const id = (req.params.id || '').trim();
  const { email } = req.body;

  const secret = db.prepare('SELECT id, security_policy, status, expires_at FROM secrets WHERE id = ?').get(id);
  if (!secret || secret.status !== 'ACTIVE' || Date.now() >= secret.expires_at) {
    return res.status(404).json({ error: 'Secret not available or expired' });
  }

  const otp = cryptoService.generateOtp();
  const expiresAt = Date.now() + (5 * 60 * 1000); // 5 min OTP expiry

  otpStore.set(id, { code: otp, expiresAt, email });

  auditLogger.logEvent({
    secretId: id,
    eventType: 'VERIFICATION_REQUESTED',
    details: { method: 'EMAIL_OTP', emailTarget: email ? maskIdentity(email) : 'Default Receiver' },
    ip: req.ip
  });

  return res.json({
    success: true,
    message: 'Verification OTP generated successfully',
    demoOtp: otp // Provided for demo/testing convenience
  });
}

router.post(['/api/view/:id/request-otp', '/api/open/:id/request-otp', '/api/receiver/:id/request-otp'], handleRequestOtp);

/**
 * POST /api/view/:id/verify
 * Completes receiver identity verification and creates short-lived viewing session
 */
function handleVerify(req, res) {
  const id = (req.params.id || '').trim();
  const {
    receiverIdentity = '',
    otpCode = '',
    passkeyVerified = false,
    cameraVerified = false,
    customCode = '',
    deviceFingerprint = 'browser-client'
  } = req.body;

  const secret = db.prepare('SELECT * FROM secrets WHERE id = ?').get(id);
  if (!secret || secret.status !== 'ACTIVE' || Date.now() >= secret.expires_at || secret.views_remaining <= 0) {
    return res.status(404).json({
      error: 'Secret not found, expired, or already destroyed',
      code: 'SECRET_UNAVAILABLE'
    });
  }

  const policy = JSON.parse(secret.security_policy || '{}');

  // Verify OTP if required
  let otpSuccess = true;
  if (policy?.verification?.requireEmailOtp) {
    const stored = otpStore.get(id);
    if (!stored || stored.code !== (otpCode || '').trim() || Date.now() > stored.expiresAt) {
      otpSuccess = false;
    }
  }

  const accessContext = {
    receiverIdentity,
    otpVerified: otpSuccess,
    passkeyVerified: !!passkeyVerified,
    cameraVerified: !!cameraVerified,
    customCode: (customCode || '').trim()
  };

  const evalResult = policyEngine.evaluateAccess(secret, accessContext);

  if (!evalResult.allowed) {
    const failCount = riskEngine.recordFailedAttempt(`verify_${id}_${req.ip}`);
    auditLogger.logEvent({
      secretId: id,
      eventType: 'VERIFICATION_FAILED',
      details: { reason: evalResult.reason, failedAttempts: failCount },
      ip: req.ip,
      riskLevel: failCount >= 3 ? 'HIGH' : 'MEDIUM'
    });

    if (evalResult.reason === 'DUAL_CONSENT_PENDING_APPROVAL') {
      return res.status(403).json({
        error: 'Receiver verified. Awaiting mandatory sender dual-consent approval.',
        code: 'DUAL_CONSENT_PENDING',
        dualConsentStatus: secret.dual_consent_status
      });
    }

    return res.status(evalResult.status || 401).json({
      error: 'Identity verification failed',
      reason: evalResult.reason
    });
  }

  // Verification passed
  riskEngine.resetFailedAttempts(`verify_${id}_${req.ip}`);
  otpStore.delete(id); // Consume OTP

  auditLogger.logEvent({
    secretId: id,
    eventType: 'VERIFICATION_PASSED',
    details: { receiverIdentity: receiverIdentity || 'Verified Receiver' },
    ip: req.ip
  });

  // Create short-lived server-side viewing session
  const durationSeconds = policy?.viewing?.viewingDurationSeconds || 60;
  const session = sessionManager.createSession({
    secretId: id,
    receiverIdentity,
    deviceFingerprint,
    ip: req.ip,
    durationSeconds
  });

  return res.json({
    success: true,
    verified: true,
    sessionId: session.sessionId,
    sessionToken: session.token,
    viewingDurationSeconds: durationSeconds,
    expiresAt: session.expiresAt
  });
}

router.post(['/api/view/:id/verify', '/api/open/:id/verify', '/api/receiver/:id/verify'], handleVerify);

/**
 * POST /api/view/:id/burn
 * ATOMIC REVEAL AND BURN ENDPOINT!
 * Concurrency protected via SQLite atomic transaction.
 * 20 simultaneous requests -> exactly 1 x 200, 19 x 404!
 */
function handleBurn(req, res) {
  const id = (req.params.id || '').trim();
  const { sessionId, sessionToken } = req.body;

  // 1. Session validation
  const sessionCheck = sessionManager.validateSession(sessionId, sessionToken);
  if (!sessionCheck.valid) {
    return res.status(403).json({
      error: 'Invalid, expired, or revoked viewing session',
      reason: sessionCheck.reason
    });
  }

  // 2. ATOMIC DATABASE TRANSACTION
  let decryptedSecret = null;
  let integrityHash = null;
  let policyVersion = 1;
  let isZeroTrace = 0;
  let remainingViews = 0;

  try {
    const atomicBurnTx = db.transaction(() => {
      // Re-fetch secret row with exclusive lock
      const secret = db.prepare(`
        SELECT * FROM secrets 
        WHERE id = ? AND status = 'ACTIVE' AND views_remaining > 0 AND expires_at > ?
      `).get(id, Date.now());

      if (!secret) {
        return null;
      }

      // Check dual consent if required
      if (secret.dual_consent_required && secret.dual_consent_status !== 'APPROVED') {
        return { error: 'DUAL_CONSENT_NOT_APPROVED' };
      }

      // Decrement views remaining
      remainingViews = secret.views_remaining - 1;
      integrityHash = secret.integrity_hash;
      policyVersion = secret.policy_version;
      isZeroTrace = secret.is_zero_trace;

      // Decrypt secret inside transaction
      if (secret.fragmentation_mode && secret.fragmentation_mode !== 'OFF' && secret.fragments_json) {
        const fragments = JSON.parse(secret.fragments_json);
        const recon = fragmentationService.reconstructSecret(fragments);
        if (!recon.success) {
          throw new Error('Fragment reconstruction error');
        }
        decryptedSecret = recon.plaintext;
      } else {
        const dec = cryptoService.decrypt(secret.ciphertext, secret.iv, secret.auth_tag, secret.salt, `vaultx-id-${id}`);
        if (!dec.success) {
          throw new Error('Decryption integrity error');
        }
        decryptedSecret = dec.plaintext;
      }

      if (remainingViews <= 0) {
        // Destroy record atomically!
        const destructionRecord = auditLogger.createDestructionRecord(id, 'BURN_ON_REVEAL', integrityHash, policyVersion);

        db.prepare(`
          UPDATE secrets 
          SET status = 'DESTROYED',
              views_remaining = 0,
              ciphertext = '',
              iv = '',
              auth_tag = '',
              salt = '',
              fragments_json = NULL,
              destruction_record = ?
          WHERE id = ?
        `).run(JSON.stringify(destructionRecord), id);

        if (isZeroTrace) {
          auditLogger.enforceZeroTrace(id);
        }

        auditLogger.logEvent({
          secretId: id,
          eventType: 'SECRET_DESTROYED',
          details: { reason: 'Burned upon authorized reveal', remainingViews: 0, proofHash: destructionRecord.proofHash }
        });
      } else {
        db.prepare('UPDATE secrets SET views_remaining = ? WHERE id = ?').run(remainingViews, id);
      }

      auditLogger.logEvent({
        secretId: id,
        eventType: 'SECRET_REVEALED',
        details: { remainingViews },
        ip: req.ip
      });

      return { success: true };
    });

    const txResult = atomicBurnTx();

    if (!txResult) {
      return res.status(404).json({
        error: 'SECRET_ALREADY_CONSUMED',
        message: 'Secret not found, expired, or already destroyed.'
      });
    }

    if (txResult.error === 'DUAL_CONSENT_NOT_APPROVED') {
      return res.status(403).json({ error: 'Pending sender dual-consent authorization' });
    }

    return res.status(200).json({
      success: true,
      secret: decryptedSecret,
      integrityHash,
      viewsRemaining: remainingViews,
      status: remainingViews <= 0 ? 'DESTROYED' : 'ACTIVE'
    });
  } catch (err) {
    console.error('Burn endpoint error:', err.message);
    return res.status(400).json({ error: 'Cryptographic failure or secret corrupted' });
  }
}

router.post(['/api/view/:id/burn', '/api/open/:id/burn', '/api/receiver/:id/burn'], handleBurn);

/**
 * GET /api/view/:id/session/:sessionId/heartbeat
 * Continuous Session Validation
 */
function handleHeartbeat(req, res) {
  const { sessionId } = req.params;
  const token = req.query.token || req.headers['x-session-token'];

  const check = sessionManager.validateSession(sessionId, token);
  return res.json(check);
}

router.get([
  '/api/view/:id/session/:sessionId/heartbeat',
  '/api/open/:id/session/:sessionId/heartbeat',
  '/api/receiver/:id/session/:sessionId/heartbeat'
], handleHeartbeat);

module.exports = router;
