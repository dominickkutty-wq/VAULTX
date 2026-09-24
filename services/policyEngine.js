class PolicyEngine {
  /**
   * Predefined Security Presets
   */
  getPresets() {
    return {
      QUICK_SHARE: {
        name: 'Quick Share',
        description: 'Rapid, single-use secret with OTP protection and 10-minute lifetime',
        level: 'Basic',
        verification: {
          requireEmailOtp: true,
          requirePasskey: false,
          requireCamera: false,
          requireLiveness: false,
          requireCustomCode: false,
          boundIdentity: ''
        },
        viewing: {
          maxViews: 1,
          expiryMinutes: 10,
          viewingDurationSeconds: 120,
          autoBurnOnExpire: true,
          autoBlurOnFocusLoss: false
        },
        protection: {
          accessScope: 'VIEW_COPY',
          disableCopy: false,
          disableSelect: false,
          disableDownload: true,
          disablePrint: true,
          scraperShield: true,
          deviceTrust: 'ANY_VERIFIED'
        },
        advanced: {
          privacyMode: 'STANDARD',
          fragmentationMode: 'OFF',
          dualConsentRequired: false,
          deadManSwitchHours: 0
        }
      },
      SECURE: {
        name: 'Secure',
        description: 'Zero-trust protected secret with OTP + Passkey and copy prevention',
        level: 'Enhanced',
        verification: {
          requireEmailOtp: true,
          requirePasskey: true,
          requireCamera: false,
          requireLiveness: false,
          requireCustomCode: false,
          boundIdentity: ''
        },
        viewing: {
          maxViews: 1,
          expiryMinutes: 5,
          viewingDurationSeconds: 60,
          autoBurnOnExpire: true,
          autoBlurOnFocusLoss: true
        },
        protection: {
          accessScope: 'VIEW_ONLY',
          disableCopy: true,
          disableSelect: true,
          disableDownload: true,
          disablePrint: true,
          scraperShield: true,
          deviceTrust: 'FIRST_VERIFIED_ONLY'
        },
        advanced: {
          privacyMode: 'MINIMAL_HISTORY',
          fragmentationMode: 'BASIC',
          dualConsentRequired: false,
          deadManSwitchHours: 0
        }
      },
      HIGHLY_SENSITIVE: {
        name: 'Highly Sensitive',
        description: 'Biometric passkey + camera consent verification with 60s viewing window',
        level: 'High',
        verification: {
          requireEmailOtp: true,
          requirePasskey: true,
          requireCamera: true,
          requireLiveness: true,
          requireCustomCode: false,
          boundIdentity: ''
        },
        viewing: {
          maxViews: 1,
          expiryMinutes: 5,
          viewingDurationSeconds: 60,
          autoBurnOnExpire: true,
          autoBlurOnFocusLoss: true
        },
        protection: {
          accessScope: 'VIEW_ONLY',
          disableCopy: true,
          disableSelect: true,
          disableDownload: true,
          disablePrint: true,
          scraperShield: true,
          deviceTrust: 'FIRST_VERIFIED_ONLY'
        },
        advanced: {
          privacyMode: 'ZERO_TRACE',
          fragmentationMode: 'HIGH',
          dualConsentRequired: false,
          deadManSwitchHours: 0
        }
      },
      CRITICAL_ZERO_TRACE: {
        name: 'Critical / Zero-Trace',
        description: 'Full multi-factor binding, camera verification, encrypted fragmentation, and zero-trace purge',
        level: 'Critical',
        verification: {
          requireEmailOtp: true,
          requirePasskey: true,
          requireCamera: true,
          requireLiveness: true,
          requireCustomCode: true,
          boundIdentity: ''
        },
        viewing: {
          maxViews: 1,
          expiryMinutes: 3,
          viewingDurationSeconds: 45,
          autoBurnOnExpire: true,
          autoBlurOnFocusLoss: true
        },
        protection: {
          accessScope: 'VIEW_ONLY',
          disableCopy: true,
          disableSelect: true,
          disableDownload: true,
          disablePrint: true,
          scraperShield: true,
          deviceTrust: 'FIRST_VERIFIED_ONLY'
        },
        advanced: {
          privacyMode: 'ZERO_TRACE',
          fragmentationMode: 'CRITICAL',
          dualConsentRequired: true,
          deadManSwitchHours: 24
        }
      }
    };
  }

  /**
   * Calculates Configuration Coverage Score (e.g. 7/8 Protections active)
   * Explanatory completeness indicator, NEVER presented as "100% secure"
   */
  calculateConfigurationCoverage(policy) {
    const checks = [
      { name: 'Encryption at Rest (AES-256-GCM)', active: true },
      { name: 'Identity Binding / Verification', active: !!(policy?.verification?.boundIdentity || policy?.verification?.requireEmailOtp) },
      { name: 'Hardware / Passkey Authentication', active: !!policy?.verification?.requirePasskey },
      { name: 'Camera & Liveness Verification', active: !!policy?.verification?.requireCamera },
      { name: 'Atomic Single-View / TTL Limits', active: (policy?.viewing?.maxViews <= 1) && (policy?.viewing?.expiryMinutes <= 15) },
      { name: 'Copy / Download Restrictions', active: !!(policy?.protection?.disableCopy && policy?.protection?.disableDownload) },
      { name: 'Scraper Bot Shield Active', active: policy?.protection?.scraperShield !== false },
      { name: 'Application-Level Zero-Trace', active: policy?.advanced?.privacyMode === 'ZERO_TRACE' },
      { name: 'Encrypted Secret Fragmentation', active: policy?.advanced?.fragmentationMode && policy?.advanced?.fragmentationMode !== 'OFF' },
      { name: 'Dual-Consent Sender Authorization', active: !!policy?.advanced?.dualConsentRequired }
    ];

    const activeCount = checks.filter(c => c.active).length;
    return {
      activeCount,
      totalCount: checks.length,
      coverageFraction: `${activeCount}/${checks.length}`,
      details: checks
    };
  }

  /**
   * Validate if access request satisfies policy rules
   */
  evaluateAccess(secret, accessContext = {}) {
    const policy = typeof secret.security_policy === 'string' 
      ? JSON.parse(secret.security_policy) 
      : secret.security_policy;

    // Check status
    if (secret.status === 'EXPIRED') {
      return { allowed: false, reason: 'SECRET_EXPIRED', status: 404 };
    }
    if (secret.status === 'DESTROYED') {
      return { allowed: false, reason: 'SECRET_ALREADY_DESTROYED', status: 404 };
    }
    if (secret.status === 'REVOKED') {
      return { allowed: false, reason: 'SECRET_REVOKED_BY_SENDER', status: 403 };
    }
    if (secret.status !== 'ACTIVE') {
      return { allowed: false, reason: 'SECRET_INACTIVE', status: 404 };
    }

    // Check TTL
    if (Date.now() >= secret.expires_at) {
      return { allowed: false, reason: 'SECRET_EXPIRED', status: 404 };
    }

    // Check views remaining
    if (secret.views_remaining <= 0) {
      return { allowed: false, reason: 'NO_VIEWS_REMAINING', status: 404 };
    }

    // Check Dual Consent if required
    if (secret.dual_consent_required && secret.dual_consent_status !== 'APPROVED') {
      return { 
        allowed: false, 
        reason: 'DUAL_CONSENT_PENDING_APPROVAL', 
        status: 403,
        details: { dualConsentStatus: secret.dual_consent_status }
      };
    }

    // Check Dead-Man Switch
    if (secret.dead_man_switch_hours > 0) {
      const deadline = secret.dead_man_confirmed_at + (secret.dead_man_switch_hours * 3600000);
      if (Date.now() > deadline) {
        return { allowed: false, reason: 'DEAD_MAN_SWITCH_TRIGGERED', status: 404 };
      }
    }

    // Check Identity Binding
    if (policy?.verification?.boundIdentity) {
      const bound = policy.verification.boundIdentity.trim().toLowerCase();
      const provided = (accessContext.receiverIdentity || '').trim().toLowerCase();
      if (!provided || provided !== bound) {
        return { allowed: false, reason: 'IDENTITY_MISMATCH', status: 403 };
      }
    }

    // Check OTP verification if required
    if (policy?.verification?.requireEmailOtp && !accessContext.otpVerified) {
      return { allowed: false, reason: 'EMAIL_OTP_REQUIRED', status: 401 };
    }

    // Check Passkey if required
    if (policy?.verification?.requirePasskey && !accessContext.passkeyVerified) {
      return { allowed: false, reason: 'PASSKEY_VERIFICATION_REQUIRED', status: 401 };
    }

    // Check Camera verification if required
    if (policy?.verification?.requireCamera && !accessContext.cameraVerified) {
      return { allowed: false, reason: 'CAMERA_VERIFICATION_REQUIRED', status: 401 };
    }

    // Check Custom code if required
    if (policy?.verification?.requireCustomCode && policy?.verification?.customCodeValue) {
      if (accessContext.customCode !== policy.verification.customCodeValue) {
        return { allowed: false, reason: 'INVALID_VERIFICATION_CODE', status: 403 };
      }
    }

    return { allowed: true, policy };
  }

  /**
   * What-If Simulator logic
   */
  simulateScenario(policy, scenario) {
    const coverage = this.calculateConfigurationCoverage(policy);
    
    switch (scenario) {
      case 'LINK_LEAKED':
        return {
          scenario: 'Secret link is leaked publicly in Slack or Discord',
          detection: 'Unknown receiver or external bot attempts access',
          policyCheck: policy?.verification?.boundIdentity || policy?.verification?.requireEmailOtp ? 'IDENTITY_PROTECTED' : 'LINK_ACCESSIBLE',
          action: policy?.verification?.boundIdentity 
            ? 'Access BLOCKED: Identity binding requires specific verified recipient.' 
            : (policy?.verification?.requireEmailOtp 
                ? 'Access BLOCKED: OTP code was sent only to authorized recipient inbox.' 
                : 'Safe landing returned. No secret decrypted without human reveal action.'),
          finalState: 'SECRET_PROTECTED',
          riskLevel: 'LOW'
        };

      case 'BOT_PREVIEW':
        return {
          scenario: 'Link-expanding crawler (Slackbot / Discordbot / Twitterbot) loads URL',
          detection: 'User-Agent matches known scraper / crawler signature',
          policyCheck: 'Scraper Shield: ACTIVE',
          action: 'GET request served with safe metadata only. Decryption and burn endpoints are NOT triggered.',
          finalState: 'SECRET_INTACT_AND_SAFE',
          riskLevel: 'LOW'
        };

      case 'NEW_DEVICE':
        return {
          scenario: 'Receiver accesses link from an unfamiliar secondary laptop or browser',
          detection: 'Device fingerprint does not match first verified device',
          policyCheck: policy?.protection?.deviceTrust || 'FIRST_VERIFIED_ONLY',
          action: policy?.protection?.deviceTrust === 'FIRST_VERIFIED_ONLY' 
            ? 'Access BLOCKED: Sender restricted viewing to first verified device only.' 
            : 'Re-authentication required: Receiver must complete multi-factor verification again.',
          finalState: 'REQUIRES_REAUTHENTICATION',
          riskLevel: 'MEDIUM'
        };

      case 'FAILED_OTP':
        return {
          scenario: 'Unauthorized party guesses or enters incorrect OTP code 3+ times',
          detection: 'Multiple failed OTP verification events on single secret',
          policyCheck: 'Risk Engine: Anomaly & Brute-force threshold exceeded',
          action: 'Risk level elevated to HIGH. Session temporarily throttled/locked. Audit incident generated.',
          finalState: 'ACCESS_RESTRICTED',
          riskLevel: 'HIGH'
        };

      case 'CONCURRENT_RACE':
        return {
          scenario: '20 simultaneous requests attempt to read single-use (max_views=1) secret',
          detection: 'Concurrent HTTP threads hit burn endpoint in parallel',
          policyCheck: 'Atomic SQLite Transaction with WAL mode lock',
          action: 'Exactly 1 request atomically claims the remaining view. 19 requests receive 404 Not Found.',
          finalState: 'ATOMIC_DESTRUCTION_SUCCESSFUL',
          riskLevel: 'LOW'
        };

      case 'TAMPERED_CIPHERTEXT':
        return {
          scenario: 'Attacker or corrupt storage modifies ciphertext, IV, or authentication tag',
          detection: 'AES-256-GCM decipher.final() tag verification failure',
          policyCheck: 'Cryptographic Integrity Check: FAILED',
          action: 'Decryption aborted cleanly. No secret revealed. No stack trace leaked. Safe 400 error returned.',
          finalState: 'INTEGRITY_TAMPER_PROTECTED',
          riskLevel: 'HIGH'
        };

      case 'EXPIRED_LINK':
        return {
          scenario: 'Receiver attempts to open link after configured expiry TTL has passed',
          detection: 'Current timestamp > expires_at (or background sweeper purged record)',
          policyCheck: 'Lifecycle Policy: EXPIRED',
          action: 'Access denied with safe 404 message. Plaintext is inaccessible.',
          finalState: 'CLEANED_UP_AND_UNAVAILABLE',
          riskLevel: 'LOW'
        };

      case 'SENDER_REVOCATION':
        return {
          scenario: 'Sender triggers Emergency Kill Switch ("🔥 DESTROY NOW")',
          detection: 'Administrative revocation signal received from authenticated sender',
          policyCheck: 'Status updated to REVOKED / DESTROYED',
          action: 'All active sessions invalidated immediately. Server-side secret destroyed permanently.',
          finalState: 'REVOKED_IMMEDIATELY',
          riskLevel: 'LOW'
        };

      case 'TAB_BLUR':
        return {
          scenario: 'Receiver switches tabs or browser loses focus while secret is visible',
          detection: 'HTML5 window.onblur / visibilitychange event triggered',
          policyCheck: policy?.protection?.autoBlurOnFocusLoss ? 'AUTO_BLUR_ACTIVE' : 'STANDARD',
          action: policy?.protection?.autoBlurOnFocusLoss 
            ? 'Screen instantly blurs secret content with privacy shield until tab regains active focus.' 
            : 'Session continues with countdown timer.',
          finalState: 'PRIVACY_SHIELDED',
          riskLevel: 'LOW'
        };

      default:
        return {
          scenario: 'Standard Authorized Access',
          detection: 'Verified identity and valid session',
          policyCheck: 'All checks passed',
          action: 'Single-use reveal allowed during active session window.',
          finalState: 'AUTHORIZED',
          riskLevel: 'LOW'
        };
    }
  }
}

module.exports = new PolicyEngine();
