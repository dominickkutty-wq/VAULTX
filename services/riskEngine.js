class RiskEngine {
  constructor() {
    // In-memory sliding window counters for rate limiting & anomalous activity detection
    this.failedAttempts = new Map(); // key -> { count, lastAttempt }
    this.requestRates = new Map();    // ip -> timestamps[]
  }

  /**
   * Tracks an attempt and returns anomalous status
   */
  recordFailedAttempt(key) {
    const now = Date.now();
    const entry = this.failedAttempts.get(key) || { count: 0, lastAttempt: now };
    
    // Reset window if last attempt was older than 10 minutes
    if (now - entry.lastAttempt > 600000) {
      entry.count = 1;
    } else {
      entry.count += 1;
    }
    entry.lastAttempt = now;
    this.failedAttempts.set(key, entry);

    return entry.count;
  }

  resetFailedAttempts(key) {
    this.failedAttempts.delete(key);
  }

  /**
   * Tracks request frequency from an IP
   */
  trackRequestRate(ip) {
    const now = Date.now();
    const windowMs = 10000; // 10 seconds window
    const list = this.requestRates.get(ip) || [];
    
    // Filter out timestamps outside window
    const recent = list.filter(ts => now - ts < windowMs);
    recent.push(now);
    this.requestRates.set(ip, recent);

    return recent.length;
  }

  /**
   * Evaluates Risk Level based on context and signals
   * @param {Object} signals 
   * @returns {Object} { riskLevel: 'LOW'|'MEDIUM'|'HIGH', reasons: string[], requireAdditionalAuth: boolean, block: boolean }
   */
  evaluateRisk({
    ip = '127.0.0.1',
    secretId = null,
    userAgent = '',
    failedAttemptsCount = 0,
    isNewDevice = false,
    isBotSignature = false,
    concurrentAttemptDetected = false,
    tamperDetected = false
  }) {
    const reasons = [];
    let score = 0; // 0-30: LOW, 31-70: MEDIUM, 71+: HIGH

    const reqFreq = this.trackRequestRate(ip);
    if (reqFreq > 25) {
      score += 40;
      reasons.push('Excessive request burst frequency detected');
    }

    if (isBotSignature) {
      score += 15;
      reasons.push('Scraper / Link-Preview Bot User-Agent signature');
    }

    if (failedAttemptsCount >= 3) {
      score += 50;
      reasons.push(`${failedAttemptsCount} repeated failed authentication attempts`);
    } else if (failedAttemptsCount > 0) {
      score += 20;
      reasons.push('Recent failed verification attempt');
    }

    if (isNewDevice) {
      score += 25;
      reasons.push('Unrecognized client device / browser context');
    }

    if (concurrentAttemptDetected) {
      score += 35;
      reasons.push('Simultaneous concurrent access attempt on single-use secret');
    }

    if (tamperDetected) {
      score += 80;
      reasons.push('Cryptographic authentication tag mismatch (tampering detected)');
    }

    let riskLevel = 'LOW';
    let requireAdditionalAuth = false;
    let block = false;

    if (score >= 70) {
      riskLevel = 'HIGH';
      block = true;
    } else if (score >= 30) {
      riskLevel = 'MEDIUM';
      requireAdditionalAuth = true;
    }

    return {
      score,
      riskLevel,
      reasons,
      requireAdditionalAuth,
      block
    };
  }
}

module.exports = new RiskEngine();
