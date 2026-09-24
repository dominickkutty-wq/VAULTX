const cryptoService = require('./cryptoService');

class FragmentationService {
  /**
   * Split plaintext into fragments based on security mode
   * @param {string} plaintext 
   * @param {string} mode - 'OFF' | 'BASIC' (2) | 'HIGH' (3) | 'CRITICAL' (4)
   * @returns {Array<Object>|null} Array of independently encrypted fragments
   */
  fragmentSecret(plaintext, mode = 'OFF') {
    if (!mode || mode === 'OFF') {
      return null;
    }

    let numFragments = 2;
    if (mode === 'HIGH') numFragments = 3;
    if (mode === 'CRITICAL') numFragments = 4;

    const len = plaintext.length;
    const chunkSize = Math.max(1, Math.ceil(len / numFragments));
    const fragments = [];

    for (let i = 0; i < numFragments; i++) {
      const start = i * chunkSize;
      const end = Math.min(len, start + chunkSize);
      const piece = start < len ? plaintext.slice(start, end) : '';

      // Encrypt each fragment independently with its own salt, IV, and authTag
      const encrypted = cryptoService.encrypt(piece, `fragment-index-${i}`);
      fragments.push({
        index: i,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        authTag: encrypted.authTag,
        salt: encrypted.salt,
        length: piece.length
      });
    }

    return fragments;
  }

  /**
   * Reconstruct plaintext from encrypted fragments in controlled memory
   * @param {Array<Object>} fragments 
   * @returns {Object} { success: boolean, plaintext?: string, error?: string }
   */
  reconstructSecret(fragments) {
    if (!Array.isArray(fragments) || fragments.length === 0) {
      return { success: false, error: 'NO_FRAGMENTS_PROVIDED' };
    }

    // Sort by fragment index to ensure correct ordering
    const sorted = [...fragments].sort((a, b) => a.index - b.index);
    let reconstructed = '';

    for (const frag of sorted) {
      const res = cryptoService.decrypt(frag.ciphertext, frag.iv, frag.authTag, frag.salt, `fragment-index-${frag.index}`);
      if (!res.success) {
        return { success: false, error: 'FRAGMENT_DECRYPTION_FAILED' };
      }
      reconstructed += res.plaintext;
    }

    return {
      success: true,
      plaintext: reconstructed
    };
  }
}

module.exports = new FragmentationService();
