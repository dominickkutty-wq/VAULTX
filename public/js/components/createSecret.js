const CreateSecretComponent = {
  currentPreset: 'SECURE',

  render(container) {
    container.innerHTML = `
      <div style="max-width: 900px; margin: 0 auto;">
        <div style="margin-bottom: 1.5rem;">
          <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            🔐 Create Secure Ephemeral Secret
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            Configure military-grade AES-256-GCM encryption with customizable Zero-Trust policy enforcement
          </p>
        </div>

        <!-- Presets Selection -->
        <div class="card" style="margin-bottom: 1.5rem;">
          <div class="card-header">
            <div>
              <div class="card-title">⚡ Security Classification Presets</div>
              <div class="card-subtitle">Choose a baseline security profile or customize individual controls below</div>
            </div>
          </div>
          <div class="preset-grid">
            <div class="preset-card" id="preset-quick" onclick="CreateSecretComponent.applyPreset('QUICK_SHARE')">
              <div class="preset-name">🟢 Quick Share</div>
              <div class="preset-desc">OTP • 10-min TTL • 1 View • Basic Protection</div>
            </div>
            <div class="preset-card active" id="preset-secure" onclick="CreateSecretComponent.applyPreset('SECURE')">
              <div class="preset-name">🔵 Secure</div>
              <div class="preset-desc">OTP + Passkey • 5-min TTL • Copy Disabled • Device Binding</div>
            </div>
            <div class="preset-card" id="preset-high" onclick="CreateSecretComponent.applyPreset('HIGHLY_SENSITIVE')">
              <div class="preset-name">🟠 Highly Sensitive</div>
              <div class="preset-desc">Passkey + Camera • 60s View Timer • Auto-Blur • Auto-Burn</div>
            </div>
            <div class="preset-card" id="preset-critical" onclick="CreateSecretComponent.applyPreset('CRITICAL_ZERO_TRACE')">
              <div class="preset-name">🔴 Critical / Zero-Trace</div>
              <div class="preset-desc">Multi-Factor • Camera • Fragmentation • Zero-Trace Purge</div>
            </div>
          </div>

          <!-- Configuration Coverage Indicator -->
          <div class="coverage-box">
            <div class="coverage-header">
              <span style="color: var(--text-muted);">Security Configuration Coverage</span>
              <span id="coverage-score-text" style="color: var(--cyber-cyan); font-family: var(--font-mono);">7 / 10 Active</span>
            </div>
            <div class="coverage-bar">
              <div class="coverage-fill" id="coverage-fill-bar" style="width: 70%;"></div>
            </div>
            <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.4rem;">
              *Explanatory configuration completeness indicator. VaultX guarantees zero permanent storage of plaintext.
            </div>
          </div>
        </div>

        <!-- Secret Ingestion Form -->
        <div class="card" style="margin-bottom: 1.5rem;">
          <div class="card-header">
            <div class="card-title">📝 Secret Payload & Metadata</div>
            <span class="badge badge-cyan">Encrypted in RAM before Storage</span>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
            <div class="form-group">
              <label class="form-label">Secret Type</label>
              <select class="form-select" id="secret-type">
                <option value="Password">Password / Master Credential</option>
                <option value="API Key" selected>API Key / Service Token</option>
                <option value="Access Token">OAuth / Bearer Token</option>
                <option value="Private Certificate">Private Key / TLS Certificate</option>
                <option value=".env">.env Configuration File</option>
                <option value="Custom Secret">Custom Secret Payload</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">Sensitivity Classification</label>
              <select class="form-select" id="secret-sensitivity" onchange="CreateSecretComponent.updateCoverage()">
                <option value="Normal">Normal</option>
                <option value="High" selected>High</option>
                <option value="Critical">Critical</option>
              </select>
            </div>
          </div>

          <div class="form-group">
            <label class="form-label">Optional Label / Title</label>
            <input type="text" class="form-input" id="secret-title" placeholder="e.g. AWS Production Cluster Deployment Key">
          </div>

          <div class="form-group">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.45rem;">
              <label class="form-label" style="margin-bottom: 0;">Sensitive Content (Plaintext)</label>
              <button type="button" class="btn btn-secondary btn-sm" id="btn-toggle-mask" onclick="CreateSecretComponent.toggleMask()" style="padding: 2px 8px; font-size: 0.75rem;">👁️ Hide Content</button>
            </div>
            <textarea class="form-textarea" id="secret-content" placeholder="Paste sensitive API key, password, certificate or credentials here..." rows="4"></textarea>
            <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.35rem;">
              Plaintext is processed strictly in-memory, encrypted with AES-256-GCM, and immediately wiped from sender RAM.
            </div>
          </div>
        </div>

        <!-- Security Policy Builder -->
        <div class="card" style="margin-bottom: 1.5rem;">
          <div class="card-header">
            <div class="card-title">🛡️ Security Policy Builder</div>
            <button type="button" class="btn btn-secondary btn-sm" onclick="CreateSecretComponent.testDraftPolicy()">⚡ Test Policy in Simulator</button>
          </div>

          <!-- Section 1: Receiver Verification -->
          <div style="margin-bottom: 1.25rem;">
            <div style="font-size: 0.85rem; font-weight: 700; color: var(--cyber-cyan); margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px;">
              1. Receiver Identity & Verification Requirements
            </div>
            
            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Require Email OTP</span>
                <span class="toggle-desc">Receiver must supply 6-digit one-time passcode</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-otp" checked onchange="CreateSecretComponent.updateCoverage()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Require Passkey / WebAuthn Biometrics</span>
                <span class="toggle-desc">Enforce hardware-bound FIDO2 device authentication</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-passkey" checked onchange="CreateSecretComponent.updateCoverage()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Require Camera & Liveness Verification</span>
                <span class="toggle-desc">Consent-based live receiver camera verification with recording indicator</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-camera" onchange="CreateSecretComponent.updateCoverage()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="form-group" style="margin-top: 0.85rem;">
              <label class="form-label">Bind to Specific Receiver Identity (Optional)</label>
              <input type="email" class="form-input" id="policy-bound-identity" placeholder="e.g. chief-officer@enterprise.vault" oninput="CreateSecretComponent.updateCoverage()">
              <span style="font-size: 0.72rem; color: var(--text-dim);">If set, access fails closed unless the receiver verifies matching email address.</span>
            </div>
          </div>

          <!-- Section 2: Viewing Lifecycle & Expiry -->
          <div style="margin-bottom: 1.25rem; border-top: 1px solid rgba(255,255,255,0.05); padding-top: 1rem;">
            <div style="font-size: 0.85rem; font-weight: 700; color: var(--cyber-cyan); margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px;">
              2. Viewing Session & Destruction Lifecycle
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
              <div class="form-group">
                <label class="form-label">Maximum Views Allowed</label>
                <select class="form-select" id="policy-max-views">
                  <option value="1" selected>1 View (Strict One-Time Read)</option>
                  <option value="2">2 Views</option>
                  <option value="3">3 Views</option>
                  <option value="5">5 Views</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Link Expiration (TTL)</label>
                <select class="form-select" id="policy-expiry-minutes">
                  <option value="3">3 Minutes</option>
                  <option value="5" selected>5 Minutes</option>
                  <option value="10">10 Minutes</option>
                  <option value="30">30 Minutes</option>
                  <option value="60">1 Hour</option>
                  <option value="1440">24 Hours</option>
                </select>
              </div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
              <div class="form-group">
                <label class="form-label">Viewing Session Timer</label>
                <select class="form-select" id="policy-duration-seconds">
                  <option value="30">30 Seconds</option>
                  <option value="45">45 Seconds</option>
                  <option value="60" selected>60 Seconds (1 Minute)</option>
                  <option value="120">2 Minutes</option>
                  <option value="300">5 Minutes</option>
                </select>
              </div>
              <div class="form-group">
                <label class="form-label">Access Scope</label>
                <select class="form-select" id="policy-access-scope">
                  <option value="VIEW_ONLY" selected>View Only (Copy & Download Blocked)</option>
                  <option value="VIEW_COPY">View + Copy Allowed</option>
                  <option value="FULL">View + Copy + Download</option>
                </select>
              </div>
            </div>

            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Auto-Blur Screen on Window Focus Loss</span>
                <span class="toggle-desc">Instantly shields secret if tab switches or browser loses active focus</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-autoblur" checked onchange="CreateSecretComponent.updateCoverage()">
                <span class="slider"></span>
              </label>
            </div>
          </div>

          <!-- Section 3: Next-Gen Innovation & Advanced Safeguards -->
          <div style="border-top: 1px solid rgba(255,255,255,0.05); padding-top: 1rem;">
            <div style="font-size: 0.85rem; font-weight: 700; color: var(--cyber-cyan); margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.5px;">
              3. Next-Gen Zero-Trust Innovation Controls
            </div>

            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Dual-Consent Sender Authorization</span>
                <span class="toggle-desc">Secret reveal remains locked until sender explicitly approves pending request</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-dual-consent" onchange="CreateSecretComponent.updateCoverage()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Secret Fragmentation Engine</span>
                <span class="toggle-desc">Splits payload into multiple independently encrypted fragments in memory</span>
              </div>
              <select class="form-select" id="policy-fragmentation" style="width: 170px;" onchange="CreateSecretComponent.updateCoverage()">
                <option value="OFF">OFF</option>
                <option value="BASIC" selected>BASIC (2 Frags)</option>
                <option value="HIGH">HIGH (3 Frags)</option>
                <option value="CRITICAL">CRITICAL (4 Frags)</option>
              </select>
            </div>

            <div class="toggle-item">
              <div class="toggle-info">
                <span class="toggle-title">Application-Level Zero-Trace Mode</span>
                <span class="toggle-desc">Zero plaintext in DB, telemetry purge upon destruction</span>
              </div>
              <label class="switch">
                <input type="checkbox" id="policy-zero-trace" checked onchange="CreateSecretComponent.updateCoverage()">
                <span class="slider"></span>
              </label>
            </div>

            <div class="form-group" style="margin-top: 0.85rem;">
              <label class="form-label">Dead-Man Switch Interval (Hours, 0 = Disabled)</label>
              <input type="number" class="form-input" id="policy-dead-man" value="0" min="0" max="720" placeholder="0 (disabled)" oninput="CreateSecretComponent.updateCoverage()">
              <span style="font-size: 0.72rem; color: var(--text-dim);">If sender does not confirm check-in within interval, secret is automatically destroyed.</span>
            </div>
          </div>
        </div>

        <!-- Submit Button -->
        <div style="text-align: right; margin-bottom: 3rem;">
          <button type="button" class="btn btn-primary btn-lg" id="btn-submit-secret" onclick="CreateSecretComponent.submitSecret()" style="width: 100%;">
            🔐 Encrypt & Create Secure Secret
          </button>
        </div>
      </div>
    `;

    this.applyPreset('SECURE');
  },

  applyPreset(presetKey) {
    this.currentPreset = presetKey;
    document.querySelectorAll('.preset-card').forEach(c => c.classList.remove('active'));

    if (presetKey === 'QUICK_SHARE') {
      document.getElementById('preset-quick')?.classList.add('active');
      document.getElementById('policy-otp').checked = true;
      document.getElementById('policy-passkey').checked = false;
      document.getElementById('policy-camera').checked = false;
      document.getElementById('policy-max-views').value = '1';
      document.getElementById('policy-expiry-minutes').value = '10';
      document.getElementById('policy-duration-seconds').value = '120';
      document.getElementById('policy-access-scope').value = 'VIEW_COPY';
      document.getElementById('policy-autoblur').checked = false;
      document.getElementById('policy-dual-consent').checked = false;
      document.getElementById('policy-fragmentation').value = 'OFF';
      document.getElementById('policy-zero-trace').checked = false;
      document.getElementById('policy-dead-man').value = '0';
      document.getElementById('secret-sensitivity').value = 'Normal';
    } else if (presetKey === 'SECURE') {
      document.getElementById('preset-secure')?.classList.add('active');
      document.getElementById('policy-otp').checked = true;
      document.getElementById('policy-passkey').checked = true;
      document.getElementById('policy-camera').checked = false;
      document.getElementById('policy-max-views').value = '1';
      document.getElementById('policy-expiry-minutes').value = '5';
      document.getElementById('policy-duration-seconds').value = '60';
      document.getElementById('policy-access-scope').value = 'VIEW_ONLY';
      document.getElementById('policy-autoblur').checked = true;
      document.getElementById('policy-dual-consent').checked = false;
      document.getElementById('policy-fragmentation').value = 'BASIC';
      document.getElementById('policy-zero-trace').checked = true;
      document.getElementById('policy-dead-man').value = '0';
      document.getElementById('secret-sensitivity').value = 'High';
    } else if (presetKey === 'HIGHLY_SENSITIVE') {
      document.getElementById('preset-high')?.classList.add('active');
      document.getElementById('policy-otp').checked = true;
      document.getElementById('policy-passkey').checked = true;
      document.getElementById('policy-camera').checked = true;
      document.getElementById('policy-max-views').value = '1';
      document.getElementById('policy-expiry-minutes').value = '5';
      document.getElementById('policy-duration-seconds').value = '60';
      document.getElementById('policy-access-scope').value = 'VIEW_ONLY';
      document.getElementById('policy-autoblur').checked = true;
      document.getElementById('policy-dual-consent').checked = false;
      document.getElementById('policy-fragmentation').value = 'HIGH';
      document.getElementById('policy-zero-trace').checked = true;
      document.getElementById('policy-dead-man').value = '0';
      document.getElementById('secret-sensitivity').value = 'Critical';
    } else if (presetKey === 'CRITICAL_ZERO_TRACE') {
      document.getElementById('preset-critical')?.classList.add('active');
      document.getElementById('policy-otp').checked = true;
      document.getElementById('policy-passkey').checked = true;
      document.getElementById('policy-camera').checked = true;
      document.getElementById('policy-max-views').value = '1';
      document.getElementById('policy-expiry-minutes').value = '3';
      document.getElementById('policy-duration-seconds').value = '45';
      document.getElementById('policy-access-scope').value = 'VIEW_ONLY';
      document.getElementById('policy-autoblur').checked = true;
      document.getElementById('policy-dual-consent').checked = true;
      document.getElementById('policy-fragmentation').value = 'CRITICAL';
      document.getElementById('policy-zero-trace').checked = true;
      document.getElementById('policy-dead-man').value = '24';
      document.getElementById('secret-sensitivity').value = 'Critical';
    }

    this.updateCoverage();
  },

  updateCoverage() {
    let score = 3; // base encryption, single view, scraper shield
    if (document.getElementById('policy-otp')?.checked) score++;
    if (document.getElementById('policy-passkey')?.checked) score++;
    if (document.getElementById('policy-camera')?.checked) score++;
    if (document.getElementById('policy-bound-identity')?.value.trim()) score++;
    if (document.getElementById('policy-autoblur')?.checked) score++;
    if (document.getElementById('policy-dual-consent')?.checked) score++;
    if (document.getElementById('policy-fragmentation')?.value !== 'OFF') score++;
    if (document.getElementById('policy-zero-trace')?.checked) score++;

    score = Math.min(10, score);
    const scoreText = document.getElementById('coverage-score-text');
    const fillBar = document.getElementById('coverage-fill-bar');
    if (scoreText) scoreText.innerText = `${score} / 10 Active`;
    if (fillBar) fillBar.style.width = `${score * 10}%`;
  },

  toggleMask() {
    const textarea = document.getElementById('secret-content');
    const btn = document.getElementById('btn-toggle-mask');
    if (textarea.style.webkitTextSecurity === 'disc') {
      textarea.style.webkitTextSecurity = 'none';
      btn.innerText = '👁️ Hide Content';
    } else {
      textarea.style.webkitTextSecurity = 'disc';
      btn.innerText = '👁️ Show Content';
    }
  },

  buildPolicyObject() {
    return {
      verification: {
        requireEmailOtp: document.getElementById('policy-otp').checked,
        requirePasskey: document.getElementById('policy-passkey').checked,
        requireCamera: document.getElementById('policy-camera').checked,
        boundIdentity: document.getElementById('policy-bound-identity').value.trim()
      },
      viewing: {
        maxViews: Number(document.getElementById('policy-max-views').value),
        expiryMinutes: Number(document.getElementById('policy-expiry-minutes').value),
        viewingDurationSeconds: Number(document.getElementById('policy-duration-seconds').value),
        autoBurnOnExpire: true,
        autoBlurOnFocusLoss: document.getElementById('policy-autoblur').checked
      },
      protection: {
        accessScope: document.getElementById('policy-access-scope').value,
        disableCopy: document.getElementById('policy-access-scope').value === 'VIEW_ONLY',
        disableDownload: true,
        disablePrint: true,
        scraperShield: true,
        deviceTrust: 'FIRST_VERIFIED_ONLY'
      },
      advanced: {
        privacyMode: document.getElementById('policy-zero-trace').checked ? 'ZERO_TRACE' : 'STANDARD',
        fragmentationMode: document.getElementById('policy-fragmentation').value,
        dualConsentRequired: document.getElementById('policy-dual-consent').checked,
        deadManSwitchHours: Number(document.getElementById('policy-dead-man').value || 0)
      }
    };
  },

  async testDraftPolicy() {
    const policy = this.buildPolicyObject();
    try {
      const res = await API.testPolicy(policy);
      App.showPolicySimulationModal(res);
    } catch (err) {
      alert('Policy simulation error: ' + err.message);
    }
  },

  async submitSecret() {
    const secret = document.getElementById('secret-content').value;
    if (!secret || secret.trim().length === 0) {
      alert('Please enter sensitive secret content to encrypt.');
      document.getElementById('secret-content').focus();
      return;
    }

    const payload = {
      secret: secret.trim(),
      secretType: document.getElementById('secret-type').value,
      title: document.getElementById('secret-title').value.trim() || undefined,
      sensitivity: document.getElementById('secret-sensitivity').value,
      policy: this.buildPolicyObject()
    };

    const submitBtn = document.getElementById('btn-submit-secret');
    submitBtn.disabled = true;
    submitBtn.innerText = '🛡️ Encrypting with AES-256-GCM & Generating Keys...';

    try {
      const result = await API.createSecret(payload);
      // Immediately clear the sensitive textarea
      document.getElementById('secret-content').value = '';
      App.showSecretCreatedModal(result);
    } catch (err) {
      alert('Failed to create secure secret: ' + err.message);
    } finally {
      submitBtn.disabled = false;
      submitBtn.innerText = '🔐 Encrypt & Create Secure Secret';
    }
  }
};
