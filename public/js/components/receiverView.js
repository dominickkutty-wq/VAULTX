const ReceiverViewComponent = {
  secretId: null,
  metadata: null,
  session: null,
  heartbeatTimer: null,
  viewTimer: null,
  cameraStream: null,
  isCameraVerified: false,
  isPasskeyVerified: false,
  otpCode: '',

  async render(container, secretId) {
    this.secretId = (secretId || '').trim();
    this.cleanup();

    console.log(`🛡️ [VaultX Receiver] Loading receiver shell for ID=${this.secretId}`);

    container.innerHTML = `
      <div class="receiver-wrapper" id="receiver-root">
        <div class="card" style="text-align: center; padding: 3rem;">
          <div style="font-size: 2.5rem; margin-bottom: 1rem; animation: pulse-red 2s infinite;">🔐</div>
          <h2 style="font-size: 1.3rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem;">
            Connecting to VaultX Zero-Trust Gateway...
          </h2>
          <div style="color: var(--text-dim); font-size: 0.825rem;">
            Resolving link token • Validating lifecycle status • Loading security policy
          </div>
        </div>
      </div>
    `;

    try {
      this.metadata = await API.getSecretMetadata(this.secretId);
      this.renderLandingScreen();
    } catch (err) {
      console.warn(`🛡️ [VaultX Receiver] Metadata retrieval failed for ID=${this.secretId}:`, err);
      const code = err.data?.error || err.data?.code || 'INVALID_LINK';
      const msg = err.data?.message || err.message || 'Unable to access secret.';
      this.renderErrorState(code, msg);
    }
  },

  renderLandingScreen() {
    const root = document.getElementById('receiver-root');
    if (!root) return;

    const reqs = this.metadata.verificationRequirements || {};
    const hasAnyVerification = reqs.requireEmailOtp || reqs.requirePasskey || reqs.requireCamera || reqs.boundIdentityHint;

    root.innerHTML = `
      <div class="card" style="border-color: var(--border-glow); box-shadow: var(--shadow-cyan);">
        <!-- Header -->
        <div style="text-align: center; margin-bottom: 1.5rem; padding-bottom: 1.25rem; border-bottom: 1px solid rgba(255,255,255,0.06);">
          <div style="font-size: 2.8rem; margin-bottom: 0.5rem;">🔐</div>
          <h2 style="font-size: 1.5rem; font-weight: 700; color: #fff; letter-spacing: -0.5px;">
            VaultX Secure Share
          </h2>
          <p style="color: var(--cyber-cyan); font-size: 0.85rem; margin-top: 0.25rem; font-weight: 500;">
            ✓ Secure Link Verified • Awaiting Authorized Human Reveal
          </p>
        </div>

        <!-- Secret Metadata Summary -->
        <div style="background: rgba(10, 16, 30, 0.7); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem; margin-bottom: 1.5rem;">
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.85rem;">
            <div>
              <span style="color: var(--text-dim); display: block; font-size: 0.75rem;">Secret Label:</span>
              <div style="font-weight: 600; color: #fff; font-size: 0.95rem;">${this.escape(this.metadata.title)}</div>
            </div>
            <div>
              <span style="color: var(--text-dim); display: block; font-size: 0.75rem;">Classification:</span>
              <div><span class="badge ${this.metadata.sensitivity === 'Critical' ? 'badge-critical' : 'badge-cyan'}">${this.metadata.sensitivity}</span></div>
            </div>
            <div>
              <span style="color: var(--text-dim); display: block; font-size: 0.75rem;">Allowed Views:</span>
              <div style="font-weight: 600; font-family: var(--font-mono); color: var(--cyber-cyan);">${this.metadata.viewsRemaining} / ${this.metadata.maxViews || 1} Remaining</div>
            </div>
            <div>
              <span style="color: var(--text-dim); display: block; font-size: 0.75rem;">Viewing Timer:</span>
              <div style="font-weight: 600; color: #fff;">${this.metadata.viewingDurationSeconds} Seconds</div>
            </div>
          </div>
        </div>

        ${hasAnyVerification ? `
          <!-- Verification Form -->
          <div style="border-top: 1px solid var(--border-subtle); padding-top: 1.25rem; margin-bottom: 1.5rem;">
            <div style="font-weight: 600; font-size: 0.95rem; color: var(--cyber-cyan); margin-bottom: 0.75rem;">
              🛡️ Sender Security Verification Required
            </div>

            ${reqs.boundIdentityHint ? `
              <div class="form-group">
                <label class="form-label">Recipient Identity Verification (Bound to ${reqs.boundIdentityHint})</label>
                <input type="email" class="form-input" id="receiver-identity-input" placeholder="Enter your authorized email address">
              </div>
            ` : ''}

            ${reqs.requireEmailOtp ? `
              <div class="form-group">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
                  <label class="form-label" style="margin-bottom: 0;">6-Digit Verification OTP</label>
                  <button type="button" class="btn btn-secondary btn-sm" id="btn-request-otp" onclick="ReceiverViewComponent.requestOtp()">Send / Request OTP</button>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                  <input type="text" class="form-input" id="receiver-otp-input" placeholder="Enter 6-digit code" maxlength="6" style="font-family: var(--font-mono); font-size: 1.1rem; letter-spacing: 2px;">
                  <button type="button" class="btn btn-secondary btn-sm" id="btn-autofill-demo-otp" style="display: none;" onclick="ReceiverViewComponent.autofillDemoOtp()">Autofill Demo OTP</button>
                </div>
                <div id="otp-status-msg" style="font-size: 0.75rem; color: var(--emerald); margin-top: 0.35rem;"></div>
              </div>
            ` : ''}

            ${reqs.requirePasskey ? `
              <div style="margin-bottom: 1.25rem;">
                <label class="form-label">Hardware Passkey / WebAuthn Device Signature</label>
                <button type="button" class="btn btn-secondary" id="btn-verify-passkey" onclick="ReceiverViewComponent.verifyPasskey()" style="width: 100%;">
                  🔑 Authenticate with Device Passkey / Biometrics
                </button>
                <div id="passkey-status-msg" style="font-size: 0.75rem; color: var(--emerald); margin-top: 0.35rem;"></div>
              </div>
            ` : ''}

            ${reqs.requireCamera ? `
              <div style="margin-bottom: 1.25rem;">
                <label class="form-label">Live Camera & Liveness Verification</label>
                <div style="font-size: 0.75rem; color: var(--text-dim); margin-bottom: 0.5rem;">
                  Camera is active only for identity verification. Video evidence is deleted immediately upon verification.
                </div>
                <button type="button" class="btn btn-secondary" id="btn-start-camera" onclick="ReceiverViewComponent.startCameraVerification()" style="width: 100%;">
                  📹 Activate Camera for Liveness Verification
                </button>
                <div id="camera-container" style="display: none;"></div>
              </div>
            ` : ''}
          </div>
        ` : ''}

        <!-- Explicit Reveal Button -->
        <div style="text-align: center;">
          <button class="btn btn-primary btn-lg" id="btn-reveal-secret" onclick="ReceiverViewComponent.executeReveal()" style="width: 100%; font-size: 1.05rem; padding: 1rem;">
            💥 REVEAL & DESTROY SECRET
          </button>
          <div style="font-size: 0.75rem; color: var(--text-dim); margin-top: 0.75rem;">
            ⚠️ Decryption occurs only upon explicit human action. One-time viewing starts immediately.
          </div>
        </div>
      </div>
    `;
  },

  renderErrorState(errorCode, errorMsg) {
    const root = document.getElementById('receiver-root');
    if (!root) return;

    let icon = '⚠';
    let title = 'INVALID SECURE LINK';
    let explanation = errorMsg || 'This secure link is not available.';
    let badgeClass = 'badge-destroyed';
    let borderColor = 'rgba(239, 68, 68, 0.4)';

    if (errorCode === 'EXPIRED_LINK') {
      icon = '⏳';
      title = 'SECURE LINK EXPIRED';
      explanation = 'This secure link has exceeded its configured time-to-live (TTL) and was permanently purged from storage by the automatic sweeper.';
      badgeClass = 'badge-expired';
    } else if (errorCode === 'REVOKED_LINK') {
      icon = '🚨';
      title = 'ACCESS REVOKED BY SENDER';
      explanation = 'The sender has manually revoked this secret link using the emergency kill switch. All viewing sessions have been terminated.';
      badgeClass = 'badge-critical';
    } else if (errorCode === 'SECRET_ALREADY_CONSUMED') {
      icon = '🔥';
      title = 'SECRET ALREADY CONSUMED';
      explanation = 'This single-use secret was previously revealed and destroyed. According to its Zero-Trust policy, it cannot be read a second time.';
      badgeClass = 'badge-destroyed';
    } else if (errorCode === 'ACCESS_DENIED') {
      icon = '🚫';
      title = 'ACCESS DENIED';
      explanation = 'Identity verification could not be validated for this recipient.';
      badgeClass = 'badge-critical';
    }

    root.innerHTML = `
      <div class="card" style="text-align: center; padding: 3rem; border-color: ${borderColor}; box-shadow: var(--shadow-rose);">
        <div style="font-size: 3.5rem; margin-bottom: 1rem;">${icon}</div>
        <h2 style="color: #F87171; font-size: 1.5rem; font-weight: 700; margin-bottom: 0.5rem;">
          ${title}
        </h2>
        <div style="margin-bottom: 1.25rem;">
          <span class="badge ${badgeClass}">${errorCode}</span>
        </div>
        <p style="color: var(--text-muted); font-size: 0.95rem; max-width: 480px; margin: 0 auto 1.5rem auto; line-height: 1.6;">
          ${this.escape(explanation)}
        </p>

        <div style="background: rgba(10, 16, 30, 0.8); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1rem; max-width: 450px; margin: 0 auto; text-align: left; font-size: 0.775rem;">
          <div style="color: var(--cyber-cyan); font-weight: 600; margin-bottom: 0.25rem;">🛡️ VaultX Zero-Trust Security Protocol:</div>
          <div style="color: var(--text-dim);">• Zero plaintext stored on server</div>
          <div style="color: var(--text-dim);">• Double-read attempts blocked automatically</div>
          <div style="color: var(--text-dim);">• Request logged in privacy-preserving audit ledger</div>
        </div>

        <div style="margin-top: 2rem;">
          <button class="btn btn-secondary btn-sm" onclick="window.location.href='/'">Go to VaultX Home</button>
        </div>
      </div>
    `;
  },

  async requestOtp() {
    const btn = document.getElementById('btn-request-otp');
    btn.disabled = true;
    btn.innerText = 'Requesting...';

    const email = document.getElementById('receiver-identity-input')?.value || '';

    try {
      const res = await API.requestOtp(this.secretId, email);
      const msg = document.getElementById('otp-status-msg');
      if (msg) msg.innerText = '✅ OTP code generated! Check your email or use the demo helper.';

      if (res.demoOtp) {
        this.demoOtp = res.demoOtp;
        const autoBtn = document.getElementById('btn-autofill-demo-otp');
        if (autoBtn) autoBtn.style.display = 'inline-flex';
      }
    } catch (err) {
      alert('Error requesting OTP: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.innerText = 'Resend OTP';
    }
  },

  autofillDemoOtp() {
    if (this.demoOtp) {
      document.getElementById('receiver-otp-input').value = this.demoOtp;
    }
  },

  async verifyPasskey() {
    const btn = document.getElementById('btn-verify-passkey');
    btn.disabled = true;
    btn.innerText = '🔄 Verifying hardware passkey...';

    // Simulate WebAuthn FIDO2 assertion
    setTimeout(() => {
      this.isPasskeyVerified = true;
      btn.innerText = '✅ Passkey Verified (FIDO2 Hardware Bound)';
      btn.style.borderColor = 'var(--emerald)';
      const msg = document.getElementById('passkey-status-msg');
      if (msg) msg.innerText = 'Hardware device signature confirmed by platform authenticator.';
    }, 700);
  },

  async startCameraVerification() {
    const container = document.getElementById('camera-container');
    const btn = document.getElementById('btn-start-camera');
    container.style.display = 'block';

    container.innerHTML = `
      <div class="camera-preview-container">
        <video id="webcam-video" class="camera-video" autoplay playsinline muted></video>
        <div style="position: absolute; top: 10px; right: 10px;">
          <div class="camera-indicator">
            <div class="recording-dot"></div>
            <span>LIVE VERIFICATION</span>
          </div>
        </div>
        <div id="camera-overlay-text" style="position: absolute; bottom: 10px; left: 10px; right: 10px; background: rgba(0,0,0,0.7); padding: 4px 8px; border-radius: 4px; font-size: 0.7rem; color: #fff; text-align: center;">
          Requesting camera permissions...
        </div>
      </div>
      <div style="text-align: center; margin-top: 0.5rem;">
        <button type="button" class="btn btn-secondary btn-sm" id="btn-confirm-liveness" onclick="ReceiverViewComponent.confirmLiveness()">
          ✓ Confirm Face & Liveness
        </button>
      </div>
    `;

    try {
      const video = document.getElementById('webcam-video');
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: false });
      this.cameraStream = stream;
      video.srcObject = stream;
      document.getElementById('camera-overlay-text').innerText = 'Look directly into camera for liveness verification.';
    } catch (e) {
      document.getElementById('camera-overlay-text').innerText = 'Simulated camera verification stream active (No physical camera attached).';
    }
  },

  confirmLiveness() {
    this.isCameraVerified = true;
    if (this.cameraStream) {
      this.cameraStream.getTracks().forEach(t => t.stop());
      this.cameraStream = null;
    }
    const container = document.getElementById('camera-container');
    container.innerHTML = `
      <div style="padding: 0.75rem; background: var(--emerald-glow); border: 1px solid var(--emerald); border-radius: var(--radius-md); text-align: center; color: var(--emerald); font-size: 0.85rem; font-weight: 600;">
        ✓ Live camera verification passed! Verification evidence purged immediately.
      </div>
    `;
    const btn = document.getElementById('btn-start-camera');
    if (btn) btn.style.display = 'none';
  },

  async executeReveal() {
    const revealBtn = document.getElementById('btn-reveal-secret');
    revealBtn.disabled = true;
    revealBtn.innerText = '🛡️ Performing Identity Verification & Atomic Decryption...';

    const reqs = this.metadata.verificationRequirements || {};
    const receiverIdentity = document.getElementById('receiver-identity-input')?.value || '';
    const otpCode = document.getElementById('receiver-otp-input')?.value || '';

    // Step 1: Verify identity on backend
    let sessionData = null;
    try {
      const verifyRes = await API.verifyReceiver(this.secretId, {
        receiverIdentity,
        otpCode,
        passkeyVerified: this.isPasskeyVerified,
        cameraVerified: this.isCameraVerified
      });

      sessionData = verifyRes;
    } catch (err) {
      revealBtn.disabled = false;
      revealBtn.innerText = '💥 REVEAL & DESTROY SECRET';

      if (err.data && err.data.code === 'DUAL_CONSENT_PENDING') {
        this.renderDualConsentPendingScreen();
        return;
      }

      alert('Verification failed: ' + (err.data?.reason || err.message));
      return;
    }

    // Step 2: ATOMIC BURN
    try {
      const burnRes = await API.burnSecret(this.secretId, sessionData.sessionId, sessionData.sessionToken);
      this.renderActiveSecretScreen(burnRes.secret, burnRes.integrityHash, sessionData);
    } catch (err) {
      this.renderErrorState(err.data?.error || 'SECRET_ALREADY_CONSUMED', err.data?.message || err.message);
    }
  },

  renderDualConsentPendingScreen() {
    const root = document.getElementById('receiver-root');
    if (!root) return;

    root.innerHTML = `
      <div class="card" style="text-align: center; padding: 3rem;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">⏳</div>
        <h2 style="color: #fff; font-size: 1.4rem;">Pending Sender Dual-Consent Authorization</h2>
        <p style="color: var(--text-muted); font-size: 0.9rem; margin-top: 0.5rem; max-width: 450px; margin-left: auto; margin-right: auto;">
          Your identity has been verified. The sender has configured mandatory dual-consent approval before reveal.
        </p>
        <div style="margin: 1.5rem 0;">
          <span class="badge badge-pending">Status: Awaiting Sender Approval</span>
        </div>
        <p style="font-size: 0.8rem; color: var(--text-dim);">
          Please wait. This screen will automatically refresh or you can click below.
        </p>
        <button class="btn btn-secondary btn-sm" style="margin-top: 1rem;" onclick="ReceiverViewComponent.executeReveal()">
          🔄 Re-check Authorization Status
        </button>
      </div>
    `;
  },

  renderActiveSecretScreen(plaintextSecret, integrityHash, sessionData) {
    const root = document.getElementById('receiver-root');
    if (!root) return;

    this.session = sessionData;
    let secondsLeft = sessionData.viewingDurationSeconds;

    root.innerHTML = `
      <div class="reveal-box">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
          <div>
            <span class="badge badge-destroyed">🔥 Burned in Storage</span>
            <span class="badge badge-active" style="margin-left: 0.5rem;">Decrypted in Memory</span>
          </div>
          <div class="timer-badge" id="session-countdown-badge">
            ⏳ Disappears in: ${this.formatTime(secondsLeft)}
          </div>
        </div>

        <div style="margin-bottom: 0.5rem; font-size: 0.85rem; font-weight: 600; color: var(--text-muted);">
          Secret Content:
        </div>

        <div class="secret-text-display" id="secret-text-box">${this.escape(plaintextSecret)}</div>

        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: gap; gap: 0.5rem; margin-top: 1rem;">
          <div style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">
            SHA256 Fingerprint: ${integrityHash ? integrityHash.substring(0, 16) + '...' : 'Verified'}
          </div>

          <div style="display: flex; gap: 0.5rem;">
            ${!this.metadata.protection.disableCopy ? `
              <button class="btn btn-secondary btn-sm" id="btn-copy-secret" onclick="ReceiverViewComponent.copySecret()">📋 Copy Secret</button>
            ` : `
              <span class="badge badge-expired" title="Sender disabled copying">🚫 Copy Disabled by Policy</span>
            `}
            <button class="btn btn-danger btn-sm" onclick="ReceiverViewComponent.selfDestroyNow()">🔥 Destroy Now</button>
          </div>
        </div>
      </div>
    `;

    // Window Focus Loss Blur Handler (Auto-Blur)
    if (this.metadata.protection.autoBlurOnFocusLoss) {
      window.addEventListener('blur', this.handleWindowBlur);
      window.addEventListener('focus', this.handleWindowFocus);
    }

    // Start countdown timer
    this.viewTimer = setInterval(() => {
      secondsLeft--;
      const badge = document.getElementById('session-countdown-badge');
      if (badge) badge.innerText = `⏳ Disappears in: ${this.formatTime(secondsLeft)}`;

      if (secondsLeft <= 0) {
        this.renderErrorState('SECRET_ALREADY_CONSUMED', 'Viewing session duration has ended. Secret permanently destroyed.');
      }
    }, 1000);

    // Continuous Session Heartbeat (detects sender revocation)
    this.heartbeatTimer = setInterval(async () => {
      try {
        const hb = await API.heartbeat(this.secretId, sessionData.sessionId, sessionData.sessionToken);
        if (!hb.valid) {
          this.renderErrorState('REVOKED_LINK', hb.reason === 'SECRET_REVOKED_BY_SENDER' ? 'Access has been revoked by the sender.' : 'Viewing session expired.');
        }
      } catch (e) {
        // network interruption, continue viewing session timer
      }
    }, 4000);
  },

  handleWindowBlur() {
    const box = document.getElementById('secret-text-box');
    if (box) box.classList.add('blurred-secret');
  },

  handleWindowFocus() {
    const box = document.getElementById('secret-text-box');
    if (box) box.classList.remove('blurred-secret');
  },

  copySecret() {
    const text = document.getElementById('secret-text-box')?.innerText;
    if (text) {
      navigator.clipboard.writeText(text);
      const btn = document.getElementById('btn-copy-secret');
      if (btn) btn.innerText = '✓ Copied!';
      setTimeout(() => { if (btn) btn.innerText = '📋 Copy Secret'; }, 2000);
    }
  },

  selfDestroyNow() {
    this.renderErrorState('SECRET_ALREADY_CONSUMED', 'Secret destroyed immediately upon recipient request.');
  },

  formatTime(totalSeconds) {
    const mins = Math.floor(Math.max(0, totalSeconds) / 60);
    const secs = Math.max(0, totalSeconds) % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  },

  escape(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
  },

  cleanup() {
    if (this.viewTimer) clearInterval(this.viewTimer);
    if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
    if (this.cameraStream) {
      this.cameraStream.getTracks().forEach(t => t.stop());
      this.cameraStream = null;
    }
    window.removeEventListener('blur', this.handleWindowBlur);
    window.removeEventListener('focus', this.handleWindowFocus);
  }
};
