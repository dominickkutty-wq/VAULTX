const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const db = require('../database/db');
const cryptoService = require('../services/cryptoService');
const auditLogger = require('../services/auditLogger');
const config = require('../config');

/**
 * POST /api/packages/create
 * Creates a Universal Secure Package (.vx) for physical or multi-channel delivery
 */
router.post('/create', (req, res) => {
  try {
    const {
      secretId,
      packageName = 'vaultx-export.vx',
      deliveryMethods = ['USB', 'Email', 'QR']
    } = req.body;

    const secret = db.prepare('SELECT * FROM secrets WHERE id = ?').get(secretId);
    if (!secret || secret.status !== 'ACTIVE') {
      return res.status(404).json({ error: 'Active secret not found for package creation' });
    }

    const packageId = 'VX-' + cryptoService.generateSecureId(8).toUpperCase();
    const policy = JSON.parse(secret.security_policy || '{}');

    // Create Universal .vx Container Format
    const packageData = {
      vaultx_package_version: '2.0-UNIVERSAL',
      package_id: packageId,
      secret_id: secret.id,
      package_name: packageName,
      created_at: Date.now(),
      expires_at: secret.expires_at,
      secret_type: secret.secret_type,
      sensitivity: secret.sensitivity,
      delivery_channels: deliveryMethods,
      integrity_fingerprint: secret.integrity_hash,
      policy_reference: {
        max_views: secret.max_views,
        requires_identity_binding: !!policy?.verification?.boundIdentity,
        requires_otp: !!policy?.verification?.requireEmailOtp,
        requires_passkey: !!policy?.verification?.requirePasskey,
        requires_camera: !!policy?.verification?.requireCamera,
        privacy_mode: policy?.advanced?.privacyMode || 'STANDARD'
      },
      // Cryptographic container - AES-256-GCM. ZERO plaintext!
      crypto_container: {
        cipher: 'aes-256-gcm',
        ciphertext: secret.ciphertext,
        iv: secret.iv,
        auth_tag: secret.auth_tag,
        salt: secret.salt
      }
    };

    const packageJson = JSON.stringify(packageData, null, 2);
    const packageFilePath = path.join(config.packagesDir, `${packageId}.vx`);
    fs.writeFileSync(packageFilePath, packageJson);

    // Save record to universal_packages table
    db.prepare(`
      INSERT INTO universal_packages (package_id, secret_id, package_name, package_file_path, delivery_methods, integrity_fingerprint, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(packageId, secret.id, packageName, packageFilePath, JSON.stringify(deliveryMethods), secret.integrity_hash, Date.now());

    auditLogger.logEvent({
      secretId: secret.id,
      eventType: 'PACKAGE_CREATED',
      details: { packageId, packageName, deliveryMethods, integrityFingerprint: secret.integrity_hash }
    });

    return res.status(201).json({
      success: true,
      packageId,
      packageName,
      downloadUrl: `/api/packages/${packageId}/download`,
      packageData
    });
  } catch (err) {
    console.error('Error creating universal package:', err);
    return res.status(500).json({ error: 'Failed to create universal secure package' });
  }
});

/**
 * GET /api/packages/:packageId/download
 * Download .vx package file
 */
router.get('/:packageId/download', (req, res) => {
  const { packageId } = req.params;
  const pkg = db.prepare('SELECT * FROM universal_packages WHERE package_id = ?').get(packageId);

  if (!pkg || !fs.existsSync(pkg.package_file_path)) {
    return res.status(404).json({ error: 'Package file not found' });
  }

  auditLogger.logEvent({
    secretId: pkg.secret_id,
    eventType: 'PACKAGE_EXPORTED',
    details: { packageId }
  });

  res.setHeader('Content-Disposition', `attachment; filename="${pkg.package_name || packageId + '.vx'}"`);
  res.setHeader('Content-Type', 'application/json');
  return res.sendFile(path.resolve(pkg.package_file_path));
});

/**
 * POST /api/packages/open
 * Process an opened/uploaded .vx package, verify integrity and link to VaultX authorization
 */
router.post('/open', (req, res) => {
  try {
    const { packageContent } = req.body;
    let pkg;

    try {
      pkg = typeof packageContent === 'string' ? JSON.parse(packageContent) : packageContent;
    } catch (e) {
      return res.status(400).json({ error: 'Corrupt or invalid .vx package format' });
    }

    if (!pkg.package_id || !pkg.crypto_container || !pkg.secret_id) {
      return res.status(400).json({ error: 'Malformed VaultX package. Missing cryptographic container.' });
    }

    // Check if secret exists on server
    const secret = db.prepare('SELECT * FROM secrets WHERE id = ?').get(pkg.secret_id);
    if (!secret) {
      return res.status(404).json({
        error: 'Associated secret not found on VaultX server (may have been destroyed, revoked, or expired)',
        code: 'SECRET_PURGED'
      });
    }

    if (secret.status !== 'ACTIVE') {
      return res.status(403).json({
        error: `Secret is ${secret.status}. Access blocked.`,
        status: secret.status
      });
    }

    // Verify package integrity fingerprint against server-side secret
    const packageIntegrityValid = (pkg.integrity_fingerprint === secret.integrity_hash);
    if (!packageIntegrityValid) {
      auditLogger.logEvent({
        secretId: secret.id,
        eventType: 'INTEGRITY_CHECK_FAILED',
        details: { packageId: pkg.package_id, reason: 'Fingerprint mismatch' },
        riskLevel: 'HIGH'
      });
      return res.status(400).json({
        error: 'PACKAGE INTEGRITY FAILED: Package has been modified or corrupted.',
        code: 'INTEGRITY_FAILED'
      });
    }

    // Verify crypto container matches
    if (pkg.crypto_container.ciphertext !== secret.ciphertext ||
        pkg.crypto_container.iv !== secret.iv ||
        pkg.crypto_container.auth_tag !== secret.auth_tag) {
      return res.status(400).json({
        error: 'PACKAGE INTEGRITY FAILED: Ciphertext or IV modified.',
        code: 'INTEGRITY_FAILED'
      });
    }

    auditLogger.logEvent({
      secretId: secret.id,
      eventType: 'PACKAGE_OPEN_ATTEMPT',
      details: { packageId: pkg.package_id, integrity: 'VERIFIED' }
    });

    return res.json({
      success: true,
      packageId: pkg.package_id,
      secretId: secret.id,
      integrityVerified: true,
      status: secret.status,
      viewsRemaining: secret.views_remaining,
      expiresAt: secret.expires_at,
      viewUrl: `/view/${secret.id}`,
      policy: JSON.parse(secret.security_policy || '{}')
    });
  } catch (err) {
    console.error('Open package error:', err);
    return res.status(500).json({ error: 'Error opening package' });
  }
});

/**
 * GET /api/packages
 * List all universal packages
 */
router.get('/', (req, res) => {
  const packages = db.prepare(`
    SELECT p.package_id, p.package_name, p.delivery_methods, p.created_at,
           s.id as secret_id, s.secret_type, s.sensitivity, s.status, s.expires_at, s.views_remaining
    FROM universal_packages p
    JOIN secrets s ON p.secret_id = s.id
    ORDER BY p.created_at DESC
  `).all();

  return res.json({
    packages: packages.map(p => ({
      ...p,
      delivery_methods: JSON.parse(p.delivery_methods || '[]')
    }))
  });
});

module.exports = router;
