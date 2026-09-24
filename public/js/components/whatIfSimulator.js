const WhatIfSimulatorComponent = {
  render(container) {
    container.innerHTML = `
      <div style="max-width: 950px; margin: 0 auto;">
        <div style="margin-bottom: 1.5rem;">
          <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            🔮 What-If Security Simulator
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            Simulate threat vectors and policy edge-cases against the real VaultX Policy Engine
          </p>
        </div>

        <div class="card" style="margin-bottom: 1.5rem;">
          <div class="card-header">
            <div class="card-title">Select Security Scenario to Simulate</div>
            <span class="badge badge-cyan">Real Engine Evaluation</span>
          </div>

          <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 0.75rem; margin-bottom: 1.5rem;">
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('LINK_LEAKED')">
              <div class="preset-name">1. Link Leaked Publicly</div>
              <div class="preset-desc">What if secret link is posted to Slack / Discord?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('BOT_PREVIEW')">
              <div class="preset-name">2. Crawler / Bot Preview</div>
              <div class="preset-desc">What if Slackbot or Discord crawler crawls URL?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('NEW_DEVICE')">
              <div class="preset-name">3. Unfamiliar / New Device</div>
              <div class="preset-desc">What if link is opened from an untrusted laptop?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('FAILED_OTP')">
              <div class="preset-name">4. Repeated Failed OTPs</div>
              <div class="preset-desc">What if attacker brute-forces 3+ incorrect OTPs?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('CONCURRENT_RACE')">
              <div class="preset-name">5. 20 Concurrent Requests</div>
              <div class="preset-desc">What if 20 requests attempt to read single-use secret?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('TAMPERED_CIPHERTEXT')">
              <div class="preset-name">6. Tampered Ciphertext</div>
              <div class="preset-desc">What if ciphertext or IV is modified in transit?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('EXPIRED_LINK')">
              <div class="preset-name">7. Expired Link</div>
              <div class="preset-desc">What if receiver clicks link after configured TTL?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('SENDER_REVOCATION')">
              <div class="preset-name">8. Emergency Revocation</div>
              <div class="preset-desc">What if sender triggers "🔥 DESTROY NOW"?</div>
            </button>
            <button class="preset-card" onclick="WhatIfSimulatorComponent.runScenario('TAB_BLUR')">
              <div class="preset-name">9. Browser Tab Switches</div>
              <div class="preset-desc">What if receiver switches window during viewing?</div>
            </button>
          </div>
        </div>

        <!-- Simulation Output Box -->
        <div id="simulation-output-card" class="card" style="display: none; border-color: var(--border-glow); box-shadow: var(--shadow-cyan);">
          <div class="card-header">
            <div class="card-title" id="sim-title">Simulation Result</div>
            <span class="badge badge-active" id="sim-risk-badge">LOW RISK</span>
          </div>

          <div style="display: flex; flex-direction: column; gap: 1rem;">
            <div style="padding: 1rem; background: rgba(0,0,0,0.4); border-radius: 8px;">
              <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Scenario</div>
              <div style="font-size: 1rem; color: #fff; font-weight: 600; margin-top: 0.2rem;" id="sim-scenario-text">—</div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
              <div style="padding: 0.85rem; background: rgba(0,0,0,0.3); border-radius: 8px; border-left: 3px solid var(--cyber-cyan);">
                <div style="font-size: 0.725rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Detection Mechanism</div>
                <div style="font-size: 0.85rem; color: var(--text-main); margin-top: 0.2rem;" id="sim-detection-text">—</div>
              </div>
              <div style="padding: 0.85rem; background: rgba(0,0,0,0.3); border-radius: 8px; border-left: 3px solid var(--emerald);">
                <div style="font-size: 0.725rem; text-transform: uppercase; color: var(--text-dim); font-weight: 700;">Policy Engine Evaluation</div>
                <div style="font-size: 0.85rem; color: var(--text-main); margin-top: 0.2rem;" id="sim-policy-text">—</div>
              </div>
            </div>

            <div style="padding: 1rem; background: rgba(0, 240, 255, 0.05); border: 1px solid var(--border-glow); border-radius: 8px;">
              <div style="font-size: 0.75rem; text-transform: uppercase; color: var(--cyber-cyan); font-weight: 700;">Enforced Security Action</div>
              <div style="font-size: 0.95rem; color: #fff; font-weight: 600; margin-top: 0.25rem;" id="sim-action-text">—</div>
            </div>

            <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 1rem; background: rgba(0,0,0,0.5); border-radius: 8px;">
              <span style="font-size: 0.8rem; color: var(--text-muted);">Guaranteed Final State:</span>
              <span class="badge badge-active" id="sim-final-state-badge" style="font-size: 0.85rem;">PROTECTED</span>
            </div>
          </div>
        </div>
      </div>
    `;
  },

  async runScenario(scenarioKey) {
    const defaultPolicy = {
      verification: { requireEmailOtp: true, requirePasskey: true, boundIdentity: 'officer@enterprise.vault' },
      viewing: { maxViews: 1, expiryMinutes: 5, viewingDurationSeconds: 60 },
      protection: { disableCopy: true, scraperShield: true, autoBlurOnFocusLoss: true, deviceTrust: 'FIRST_VERIFIED_ONLY' },
      advanced: { privacyMode: 'ZERO_TRACE' }
    };

    try {
      const res = await API.simulateWhatIf(defaultPolicy, scenarioKey);
      const sim = res.simulation;

      const card = document.getElementById('simulation-output-card');
      card.style.display = 'block';

      document.getElementById('sim-title').innerText = sim.scenario;
      document.getElementById('sim-scenario-text').innerText = sim.scenario;
      document.getElementById('sim-detection-text').innerText = sim.detection;
      document.getElementById('sim-policy-text').innerText = sim.policyCheck;
      document.getElementById('sim-action-text').innerText = sim.action;

      const riskBadge = document.getElementById('sim-risk-badge');
      riskBadge.innerText = sim.riskLevel + ' RISK';
      riskBadge.className = 'badge ' + (sim.riskLevel === 'HIGH' ? 'badge-critical' : (sim.riskLevel === 'MEDIUM' ? 'badge-pending' : 'badge-active'));

      const stateBadge = document.getElementById('sim-final-state-badge');
      stateBadge.innerText = sim.finalState;
      stateBadge.className = 'badge badge-cyan';

      card.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
      alert('Simulation error: ' + err.message);
    }
  }
};
