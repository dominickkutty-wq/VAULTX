const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../database/db');
const cryptoService = require('./cryptoService');
const auditLogger = require('./auditLogger');
const config = require('../config');

class FileSecurityGateway {
  /**
   * Sensitive content inspection patterns (Regex)
   */
  scanContentForSensitiveSignals(contentString) {
    const signals = [];

    // Credit Card Numbers (Luhn-like sequence check)
    const cardRegex = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/;
    if (cardRegex.test(contentString)) {
      signals.push('Payment Card Number Detected');
    }

    // SSN / National Identity format
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/;
    if (ssnRegex.test(contentString)) {
      signals.push('National Identity / SSN Pattern Detected');
    }

    // API Keys / Secrets / Tokens
    const apiKeyRegex = /(?:api[_-]?key|secret|token|bearer|auth|client_secret|password|access_key)[\s:=]+['"]?([a-zA-Z0-9_\-\.]{16,})['"]?/i;
    if (apiKeyRegex.test(contentString)) {
      signals.push('Embedded API Key / Access Token Detected');
    }

    // Private Certificates / RSA Keys
    if (contentString.includes('BEGIN PRIVATE KEY') || contentString.includes('BEGIN RSA PRIVATE KEY') || contentString.includes('BEGIN OPENSSH PRIVATE KEY')) {
      signals.push('Private Cryptographic Key Material Detected');
    }

    // Bank Account / Routing Number patterns
    const bankRegex = /(?:iban|account[_-]?number|routing[_-]?number)[\s:=]+['"]?([A-Z0-9]{8,34})['"]?/i;
    if (bankRegex.test(contentString)) {
      signals.push('Banking / Financial Account Identifier Detected');
    }

    return signals;
  }

  /**
   * Determine classification based on detected signals and user input
   */
  classifySensitivity(signals = [], userOverride = null) {
    if (userOverride) return userOverride;
    if (signals.some(s => s.includes('Cryptographic') || s.includes('Payment Card') || s.includes('Identity'))) {
      return 'HIGHLY_CONFIDENTIAL';
    }
    if (signals.length > 0) {
      return 'CONFIDENTIAL';
    }
    return 'INTERNAL';
  }

  /**
   * Checks if an identical file hash already exists in the vault
   */
  checkDuplicate(sha256Hash) {
    const existing = db.prepare('SELECT id, filename, classification, created_at FROM vault_files WHERE sha256_hash = ?').get(sha256Hash);
    return existing || null;
  }

  /**
   * Import & Encrypt a file into the Vault
   */
  importFile({
    buffer,
    originalName,
    mimeType = 'application/octet-stream',
    owner = 'SecurityAdmin',
    source = 'Local Computer',
    userClassification = null
  }) {
    // 1. Calculate SHA-256 hash of original file buffer
    const sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');

    // 2. Check for duplicate
    const duplicate = this.checkDuplicate(sha256Hash);

    // 3. Scan content for sensitive patterns if text-based
    let sensitivitySignals = [];
    const isText = mimeType.startsWith('text/') || mimeType.includes('json') || mimeType.includes('yaml') || mimeType.includes('javascript') || mimeType.includes('xml') || originalName.endsWith('.env') || originalName.endsWith('.txt') || originalName.endsWith('.csv') || originalName.endsWith('.md');
    
    if (isText) {
      const textContent = buffer.toString('utf8', 0, Math.min(buffer.length, 100000)); // scan up to first 100KB
      sensitivitySignals = this.scanContentForSensitiveSignals(textContent);
    }

    const classification = this.classifySensitivity(sensitivitySignals, userClassification);

    // 4. Encrypt file buffer with AES-256-GCM
    const fileId = 'vf_' + cryptoService.generateSecureId(8);
    const salt = crypto.randomBytes(16);
    const secretKey = cryptoService.deriveSecretKey(salt, 'vaultx-file-encryption');
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    const encryptedBuffer = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // 5. Store encrypted file on disk
    const encryptedPath = path.join(config.uploadsDir, `${fileId}.enc`);
    fs.writeFileSync(encryptedPath, encryptedBuffer);

    const now = Date.now();

    // 6. Record file in database
    const stmt = db.prepare(`
      INSERT INTO vault_files (
        id, filename, original_name, file_size, mime_type, sha256_hash, 
        classification, sensitivity_signals, encrypted_path, iv, auth_tag, 
        salt, owner, current_version, is_locked, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
    `);

    stmt.run(
      fileId, originalName, originalName, buffer.length, mimeType, sha256Hash,
      classification, JSON.stringify(sensitivitySignals), encryptedPath,
      iv.toString('hex'), authTag.toString('hex'), salt.toString('hex'),
      owner, now, now
    );

    // 7. Record Version 1 in file_versions
    const versionId = 'ver_' + cryptoService.generateSecureId(8);
    db.prepare(`
      INSERT INTO file_versions (id, file_id, version_number, sha256_hash, encrypted_path, iv, auth_tag, salt, file_size, change_summary, created_at)
      VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 'Initial secure vault import', ?)
    `).run(versionId, fileId, sha256Hash, encryptedPath, iv.toString('hex'), authTag.toString('hex'), salt.toString('hex'), buffer.length, now);

    // 8. Log Audit Event
    auditLogger.logEvent({
      secretId: fileId,
      eventType: 'FILE_IMPORTED',
      details: {
        filename: originalName,
        source,
        fileSize: buffer.length,
        sha256Hash,
        classification,
        sensitivitySignalsCount: sensitivitySignals.length,
        isDuplicate: !!duplicate
      }
    });

    return {
      fileId,
      filename: originalName,
      fileSize: buffer.length,
      sha256Hash,
      classification,
      sensitivitySignals,
      duplicate
    };
  }

  /**
   * Retrieves and decrypts a file for secure viewing or controlled download
   */
  getDecryptedFile(fileId, userContext = {}) {
    const file = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(fileId);
    if (!file) {
      return { success: false, error: 'FILE_NOT_FOUND', status: 404 };
    }

    if (file.is_locked) {
      return { success: false, error: 'FILE_LOCKED_BY_ADMIN', status: 423 };
    }

    // Check system emergency lock
    const sysLock = db.prepare('SELECT value FROM vault_system_state WHERE key = ?').get('vault_locked');
    if (sysLock && sysLock.value === '1') {
      return { success: false, error: 'VAULT_SYSTEM_LOCKED', status: 423 };
    }

    if (!fs.existsSync(file.encrypted_path)) {
      return { success: false, error: 'ENCRYPTED_FILE_MISSING', status: 404 };
    }

    const encryptedBuffer = fs.readFileSync(file.encrypted_path);
    const salt = Buffer.from(file.salt, 'hex');
    const iv = Buffer.from(file.iv, 'hex');
    const authTag = Buffer.from(file.authTag || file.auth_tag, 'hex');

    try {
      const secretKey = cryptoService.deriveSecretKey(salt, 'vaultx-file-encryption');
      const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, iv);
      decipher.setAuthTag(authTag);

      const decryptedBuffer = Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);

      // Verify SHA-256 integrity of decrypted buffer matches recorded hash
      const checkHash = crypto.createHash('sha256').update(decryptedBuffer).digest('hex');
      const integrityVerified = (checkHash === file.sha256_hash);

      if (!integrityVerified) {
        auditLogger.logEvent({
          secretId: fileId,
          eventType: 'INTEGRITY_CHECK_FAILED',
          details: { filename: file.filename, recordedHash: file.sha256_hash, actualHash: checkHash },
          riskLevel: 'HIGH'
        });
        return { success: false, error: 'FILE_INTEGRITY_MISMATCH', status: 400 };
      }

      auditLogger.logEvent({
        secretId: fileId,
        eventType: 'FILE_ACCESSED',
        details: { filename: file.filename, accessType: userContext.accessType || 'VIEW' }
      });

      return {
        success: true,
        fileInfo: file,
        buffer: decryptedBuffer,
        mimeType: file.mime_type,
        integrityVerified: true
      };
    } catch (err) {
      auditLogger.logEvent({
        secretId: fileId,
        eventType: 'FILE_TAMPER_DETECTED',
        details: { filename: file.filename },
        riskLevel: 'HIGH'
      });
      return { success: false, error: 'FILE_TAMPERED_OR_CORRUPT', status: 400 };
    }
  }

  /**
   * Adds a new version of a file
   */
  addVersion(fileId, buffer, changeSummary = 'Updated file version') {
    const file = db.prepare('SELECT * FROM vault_files WHERE id = ?').get(fileId);
    if (!file) return { success: false, error: 'FILE_NOT_FOUND' };

    const newVersionNum = file.current_version + 1;
    const sha256Hash = crypto.createHash('sha256').update(buffer).digest('hex');

    const salt = crypto.randomBytes(16);
    const secretKey = cryptoService.deriveSecretKey(salt, 'vaultx-file-encryption');
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    const encryptedBuffer = Buffer.concat([cipher.update(buffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const versionId = 'ver_' + cryptoService.generateSecureId(8);
    const versionPath = path.join(config.uploadsDir, `${fileId}_v${newVersionNum}.enc`);
    fs.writeFileSync(versionPath, encryptedBuffer);

    const now = Date.now();

    const updateTx = db.transaction(() => {
      db.prepare(`
        INSERT INTO file_versions (id, file_id, version_number, sha256_hash, encrypted_path, iv, auth_tag, salt, file_size, change_summary, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(versionId, fileId, newVersionNum, sha256Hash, versionPath, iv.toString('hex'), authTag.toString('hex'), salt.toString('hex'), buffer.length, changeSummary, now);

      db.prepare(`
        UPDATE vault_files 
        SET current_version = ?,
            sha256_hash = ?,
            file_size = ?,
            encrypted_path = ?,
            iv = ?,
            auth_tag = ?,
            salt = ?,
            updated_at = ?
        WHERE id = ?
      `).run(newVersionNum, sha256Hash, buffer.length, versionPath, iv.toString('hex'), authTag.toString('hex'), salt.toString('hex'), now, fileId);

      auditLogger.logEvent({
        secretId: fileId,
        eventType: 'FILE_VERSION_ADDED',
        details: { version: newVersionNum, sha256Hash, changeSummary }
      });
    });

    updateTx();
    return { success: true, versionNumber: newVersionNum, sha256Hash };
  }

  /**
   * Restore an older version of a file
   */
  restoreVersion(fileId, versionNumber) {
    const version = db.prepare('SELECT * FROM file_versions WHERE file_id = ? AND version_number = ?').get(fileId, versionNumber);
    if (!version) return { success: false, error: 'VERSION_NOT_FOUND' };

    const now = Date.now();
    db.prepare(`
      UPDATE vault_files 
      SET current_version = ?,
          sha256_hash = ?,
          file_size = ?,
          encrypted_path = ?,
          iv = ?,
          auth_tag = ?,
          salt = ?,
          updated_at = ?
      WHERE id = ?
    `).run(version.version_number, version.sha256_hash, version.file_size, version.encrypted_path, version.iv, version.auth_tag, version.salt, now, fileId);

    auditLogger.logEvent({
      secretId: fileId,
      eventType: 'FILE_VERSION_RESTORED',
      details: { restoredToVersion: versionNumber }
    });

    return { success: true, restoredVersion: versionNumber };
  }

  /**
   * List files in the vault
   */
  listFiles(filter = {}) {
    let query = 'SELECT id, filename, original_name, file_size, mime_type, sha256_hash, classification, sensitivity_signals, owner, current_version, is_locked, created_at, updated_at FROM vault_files';
    const params = [];

    if (filter.classification) {
      query += ' WHERE classification = ?';
      params.push(filter.classification);
    }
    query += ' ORDER BY created_at DESC';

    const files = db.prepare(query).all(...params);
    return files.map(f => ({
      ...f,
      sensitivity_signals: JSON.parse(f.sensitivity_signals || '[]')
    }));
  }

  /**
   * Get file security details including versions and events
   */
  getFileDetails(fileId) {
    const file = db.prepare('SELECT id, filename, original_name, file_size, mime_type, sha256_hash, classification, sensitivity_signals, owner, current_version, is_locked, created_at, updated_at FROM vault_files WHERE id = ?').get(fileId);
    if (!file) return null;

    const versions = db.prepare('SELECT id, version_number, sha256_hash, file_size, change_summary, created_at FROM file_versions WHERE file_id = ? ORDER BY version_number DESC').all(fileId);
    const events = db.prepare('SELECT * FROM security_events WHERE secret_id = ? ORDER BY created_at DESC LIMIT 20').all(fileId);

    return {
      file: {
        ...file,
        sensitivity_signals: JSON.parse(file.sensitivity_signals || '[]')
      },
      versions,
      events
    };
  }
}

module.exports = new FileSecurityGateway();
