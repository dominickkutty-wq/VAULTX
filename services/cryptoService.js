const crypto = require('crypto');
const config = require('../config');

class CryptoService {
  constructor() {
    this.masterKey = config.masterKeyBuffer;
  }

  /**
   * Derive a unique 32-byte encryption key for a specific secret using HKDF
   * @param {Buffer} salt - 16 bytes random salt
   * @param {string} info - Contextual string
   * @returns {Buffer} 32-byte derived key
   */
  deriveSecretKey(salt, info = 'vaultx-secret-encryption') {
    return crypto.hkdfSync('sha256', this.masterKey, salt, Buffer.from(info), 32);
  }

  /**
   * Encrypts a plaintext string or buffer using AES-256-GCM
   * @param {string|Buffer} plaintext 
   * @param {string} aad - Optional Additional Authenticated Data
   * @returns {Object} { ciphertext, iv, authTag, salt, integrityHash }
   */
  encrypt(plaintext, aad = '') {
    if (plaintext === undefined || plaintext === null) {
      throw new Error('Plaintext payload is required for encryption');
    }

    const payloadBuffer = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    
    // Calculate SHA-256 integrity fingerprint of the plaintext BEFORE encryption
    const integrityHash = crypto.createHash('sha256').update(payloadBuffer).digest('hex');

    // Generate unique 16-byte cryptographically random salt for subkey derivation
    const salt = crypto.randomBytes(16);
    const secretKey = this.deriveSecretKey(salt);

    // Generate unique 12-byte cryptographically random IV (NIST recommended for GCM)
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', secretKey, iv);
    
    if (aad) {
      cipher.setAAD(Buffer.from(aad, 'utf8'));
    }

    const encrypted = Buffer.concat([cipher.update(payloadBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return {
      ciphertext: encrypted.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      salt: salt.toString('hex'),
      integrityHash
    };
  }

  /**
   * Decrypts an AES-256-GCM ciphertext
   * @param {string} ciphertextHex 
   * @param {string} ivHex 
   * @param {string} authTagHex 
   * @param {string} saltHex 
   * @param {string} aad - Optional Additional Authenticated Data
   * @returns {Object} { success: boolean, plaintext?: string, error?: string }
   */
  decrypt(ciphertextHex, ivHex, authTagHex, saltHex, aad = '') {
    try {
      if (!ciphertextHex || !ivHex || !authTagHex || !saltHex) {
        return { success: false, error: 'MISSING_CRYPTO_PARAMS' };
      }

      const salt = Buffer.from(saltHex, 'hex');
      const iv = Buffer.from(ivHex, 'hex');
      const authTag = Buffer.from(authTagHex, 'hex');
      const ciphertext = Buffer.from(ciphertextHex, 'hex');

      const secretKey = this.deriveSecretKey(salt);
      const decipher = crypto.createDecipheriv('aes-256-gcm', secretKey, iv);

      if (aad) {
        decipher.setAAD(Buffer.from(aad, 'utf8'));
      }

      decipher.setAuthTag(authTag);

      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      const plaintext = decrypted.toString('utf8');

      return {
        success: true,
        plaintext
      };
    } catch (err) {
      // Never leak stack trace or internal cryptographic failure specifics
      // GCM authentication failure happens if ciphertext, IV, or authTag was tampered
      return {
        success: false,
        error: 'INTEGRITY_VERIFICATION_FAILED_OR_TAMPERED'
      };
    }
  }

  /**
   * Generates a high-entropy URL-safe random identifier
   * @param {number} bytes - Number of random bytes
   * @returns {string} URL-safe base64url or hex identifier
   */
  generateSecureId(bytes = 12) {
    return crypto.randomBytes(bytes).toString('base64url');
  }

  /**
   * Generates a 6-digit cryptographically secure numeric OTP
   */
  generateOtp() {
    const num = crypto.randomInt(100000, 999999);
    return num.toString();
  }

  /**
   * Generate an integrity hash of any data
   */
  hash(data) {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    return crypto.createHash('sha256').update(buf).digest('hex');
  }
}

module.exports = new CryptoService();
