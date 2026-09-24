const express = require('express');
const router = express.Router();
const multer = require('multer');
const crypto = require('crypto');
const fileSecurityGateway = require('../services/fileSecurityGateway');
const cryptoService = require('../services/cryptoService');
const auditLogger = require('../services/auditLogger');
const db = require('../database/db');

// Multer memory storage for direct in-memory encryption before disk write
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 } // 25MB max for prototype
});

/**
 * POST /api/files/import
 * Universal Secure File Import & Encryption
 */
router.post('/import', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const {
      source = 'Local Computer',
      owner = 'SecurityAdmin',
      classification = null
    } = req.body;

    const result = fileSecurityGateway.importFile({
      buffer: req.file.buffer,
      originalName: req.file.originalname,
      mimeType: req.file.mimetype,
      owner,
      source,
      userClassification: classification
    });

    return res.status(201).json({
      success: true,
      file: result
    });
  } catch (err) {
    console.error('File import error:', err);
    return res.status(500).json({ error: 'Failed to import and encrypt file' });
  }
});

/**
 * POST /api/files/check-duplicate
 * Checks if a hash exists in vault
 */
router.post('/check-duplicate', (req, res) => {
  const { sha256Hash } = req.body;
  if (!sha256Hash) return res.status(400).json({ error: 'Hash required' });

  const duplicate = fileSecurityGateway.checkDuplicate(sha256Hash);
  return res.json({ duplicate: !!duplicate, existingFile: duplicate });
});

/**
 * GET /api/files
 * List all files in the vault
 */
router.get('/', (req, res) => {
  try {
    const files = fileSecurityGateway.listFiles(req.query);
    return res.json({ files });
  } catch (err) {
    console.error('List files error:', err);
    return res.status(500).json({ error: 'Failed to retrieve vault files' });
  }
});

/**
 * GET /api/files/:id
 * Get file details, version history, and audit timeline
 */
router.get('/:id', (req, res) => {
  try {
    const details = fileSecurityGateway.getFileDetails(req.params.id);
    if (!details) {
      return res.status(404).json({ error: 'File not found in vault' });
    }
    return res.json(details);
  } catch (err) {
    console.error('Get file details error:', err);
    return res.status(500).json({ error: 'Failed to get file details' });
  }
});

/**
 * GET /api/files/:id/view
 * Secure In-Memory Document Viewer (Decrypted for authorized view-only session)
 */
router.get('/:id/view', (req, res) => {
  try {
    const result = fileSecurityGateway.getDecryptedFile(req.params.id, { accessType: 'VIEW' });
    if (!result.success) {
      return res.status(result.status || 400).json({ error: result.error });
    }

    const isText = result.mimeType.startsWith('text/') ||
                   result.mimeType.includes('json') ||
                   result.mimeType.includes('javascript') ||
                   result.fileInfo.filename.endsWith('.env') ||
                   result.fileInfo.filename.endsWith('.txt') ||
                   result.fileInfo.filename.endsWith('.md');

    if (isText) {
      return res.json({
        success: true,
        filename: result.fileInfo.filename,
        classification: result.fileInfo.classification,
        mimeType: result.mimeType,
        integrityVerified: true,
        textPreview: result.buffer.toString('utf8')
      });
    }

    // Binary preview (e.g. image / PDF representation)
    res.setHeader('Content-Type', result.mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${result.fileInfo.filename}"`);
    return res.send(result.buffer);
  } catch (err) {
    console.error('File view error:', err);
    return res.status(500).json({ error: 'Failed to decrypt file for viewing' });
  }
});

/**
 * GET /api/files/:id/download
 * Controlled file download
 */
router.get('/:id/download', (req, res) => {
  try {
    const result = fileSecurityGateway.getDecryptedFile(req.params.id, { accessType: 'DOWNLOAD' });
    if (!result.success) {
      return res.status(result.status || 400).json({ error: result.error });
    }

    res.setHeader('Content-Type', result.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${result.fileInfo.filename}"`);
    return res.send(result.buffer);
  } catch (err) {
    console.error('File download error:', err);
    return res.status(500).json({ error: 'Failed to download file' });
  }
});

/**
 * POST /api/files/:id/version
 * Upload a new version of the file
 */
router.post('/:id/version', upload.single('file'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    const { changeSummary = 'Updated version' } = req.body;

    const result = fileSecurityGateway.addVersion(req.params.id, req.file.buffer, changeSummary);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }
    return res.json(result);
  } catch (err) {
    console.error('File add version error:', err);
    return res.status(500).json({ error: 'Failed to add file version' });
  }
});

/**
 * POST /api/files/:id/restore-version
 * Restore an older version
 */
router.post('/:id/restore-version', (req, res) => {
  try {
    const { versionNumber } = req.body;
    if (!versionNumber) return res.status(400).json({ error: 'Version number required' });

    const result = fileSecurityGateway.restoreVersion(req.params.id, Number(versionNumber));
    if (!result.success) return res.status(400).json({ error: result.error });

    return res.json(result);
  } catch (err) {
    console.error('Restore version error:', err);
    return res.status(500).json({ error: 'Failed to restore file version' });
  }
});

/**
 * POST /api/files/:id/share
 * Create a temporary secure sharing link
 */
router.post('/:id/share', (req, res) => {
  try {
    const { id } = req.params;
    const { recipient = 'External Recipient', permission = 'VIEW', expiryMinutes = 30, maxViews = 1 } = req.body;

    const file = db.prepare('SELECT id, filename FROM vault_files WHERE id = ?').get(id);
    if (!file) return res.status(404).json({ error: 'File not found' });

    const shareId = 'shr_' + cryptoService.generateSecureId(8);
    const token = cryptoService.generateSecureId(16);
    const now = Date.now();
    const expiresAt = now + (Number(expiryMinutes) * 60 * 1000);

    db.prepare(`
      INSERT INTO file_shares (id, file_id, token, recipient, permission, max_views, views_remaining, expires_at, status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
    `).run(shareId, id, token, recipient, permission, maxViews, maxViews, expiresAt, now);

    auditLogger.logEvent({
      secretId: id,
      eventType: 'FILE_SHARED',
      details: { shareId, recipient, permission, expiryMinutes }
    });

    return res.json({
      success: true,
      shareId,
      token,
      shareUrl: `/share/${token}`,
      expiresAt,
      permission
    });
  } catch (err) {
    console.error('Share file error:', err);
    return res.status(500).json({ error: 'Failed to create file share' });
  }
});

module.exports = router;
