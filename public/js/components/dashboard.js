const DashboardComponent = {
  async render(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div>
          <h1 style="font-size: 1.6rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            🛡️ Security Operations Center
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            Zero-Trust Ephemeral Secret Vault & File Security Gateway Overview
          </p>
        </div>
        <div style="display: flex; gap: 0.75rem;">
          <button class="btn btn-secondary btn-sm" onclick="App.navigateTo('lab')">🔬 Security Lab</button>
          <button class="btn btn-primary btn-sm" onclick="App.navigateTo('create')">+ Create Secure Secret</button>
        </div>
      </div>

      <!-- Stats Grid -->
      <div class="stats-grid" id="dashboard-stats-grid">
        <div class="stat-card"><div class="stat-label">Loading Metrics...</div></div>
      </div>

      <!-- Data Lifecycle Visualizer -->
      <div class="card" style="margin-bottom: 1.5rem;">
        <div class="card-header">
          <div>
            <div class="card-title">🔄 Zero-Trust Data Lifecycle Pipeline</div>
            <div class="card-subtitle">Cryptographic state transitions from ingestion to permanent atomic destruction</div>
          </div>
          <span class="badge badge-cyan">AES-256-GCM Hardware Encrypted</span>
        </div>
        <div class="lifecycle-flow">
          <div class="flow-step completed">
            <div class="flow-icon">📝</div>
            <div class="flow-label">1. Ingest</div>
            <span style="font-size: 0.65rem; color: var(--emerald);">Plaintext in RAM</span>
          </div>
          <div class="flow-arrow">➔</div>
          <div class="flow-step completed">
            <div class="flow-icon">🔐</div>
            <div class="flow-label">2. Encrypt</div>
            <span style="font-size: 0.65rem; color: var(--cyber-cyan);">HKDF + 256-GCM</span>
          </div>
          <div class="flow-arrow">➔</div>
          <div class="flow-step active">
            <div class="flow-icon">💾</div>
            <div class="flow-label">3. Store</div>
            <span style="font-size: 0.65rem; color: var(--cyber-cyan);">Ciphertext in DB</span>
          </div>
          <div class="flow-arrow">➔</div>
          <div class="flow-step">
            <div class="flow-icon">🛡️</div>
            <div class="flow-label">4. Verify</div>
            <span style="font-size: 0.65rem; color: var(--text-dim);">OTP / Passkey / Cam</span>
          </div>
          <div class="flow-arrow">➔</div>
          <div class="flow-step">
            <div class="flow-icon">👁️</div>
            <div class="flow-label">5. Reveal</div>
            <span style="font-size: 0.65rem; color: var(--amber);">Active Timer</span>
          </div>
          <div class="flow-arrow">➔</div>
          <div class="flow-step">
            <div class="flow-icon">🔥</div>
            <div class="flow-label">6. Atomic Burn</div>
            <span style="font-size: 0.65rem; color: #F87171;">Wipe & Destruct</span>
          </div>
          <div class="flow-arrow">➔</div>
          <div class="flow-step">
            <div class="flow-icon">🧹</div>
            <div class="flow-label">7. Zero-Trace</div>
            <span style="font-size: 0.65rem; color: var(--text-dim);">Memory Purge</span>
          </div>
        </div>
      </div>

      <!-- Secret Health & Active Inventory Grid -->
      <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 1.5rem;">
        <div class="card">
          <div class="card-header">
            <div class="card-title">📊 Secret Health & Active Inventory</div>
            <button class="btn btn-secondary btn-sm" onclick="App.navigateTo('secrets')">View All Secrets</button>
          </div>
          <div class="table-responsive">
            <table class="data-table" id="dashboard-secrets-table">
              <thead>
                <tr>
                  <th>Secret Title</th>
                  <th>Type</th>
                  <th>Sensitivity</th>
                  <th>Status</th>
                  <th>Remaining Views</th>
                  <th>Expires In</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr><td colspan="7" style="text-align: center; color: var(--text-dim);">Loading secrets...</td></tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="card">
          <div class="card-header">
            <div class="card-title">⚠️ Threat & Anomaly Signals</div>
            <span class="badge badge-active">Live Shield</span>
          </div>
          <div id="dashboard-signals-list" style="display: flex; flex-direction: column; gap: 0.75rem;">
            <div style="color: var(--text-dim); font-size: 0.85rem;">Loading threat indicators...</div>
          </div>
          <div style="margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border-subtle);">
            <button class="btn btn-secondary btn-sm" style="width: 100%;" onclick="App.navigateTo('incidents')">Open Incident Ledger</button>
          </div>
        </div>
      </div>
    `;

    await this.loadStats();
    await this.loadSecrets();
  },

  async loadStats() {
    try {
      const stats = await API.getStats();
      const grid = document.getElementById('dashboard-stats-grid');
      if (!grid) return;

      grid.innerHTML = `
        <div class="stat-card">
          <div class="stat-label">Active Secrets</div>
          <div class="stat-value" style="color: var(--cyber-cyan);">${stats.activeSecrets}</div>
          <div class="stat-sub">${stats.totalSecrets} total in lifetime</div>
        </div>
        <div class="stat-card emerald">
          <div class="stat-label">Created Today</div>
          <div class="stat-value" style="color: var(--emerald);">${stats.createdToday}</div>
          <div class="stat-sub">Fresh cryptographic sessions</div>
        </div>
        <div class="stat-card rose">
          <div class="stat-label">Atomic Burned</div>
          <div class="stat-value" style="color: #F87171;">${stats.destroyedSecrets}</div>
          <div class="stat-sub">Zero-trace purged</div>
        </div>
        <div class="stat-card amber">
          <div class="stat-label">Expired Cleaned</div>
          <div class="stat-value" style="color: var(--amber);">${stats.expiredSecrets}</div>
          <div class="stat-sub">Background sweeper wiped</div>
        </div>
        <div class="stat-card purple">
          <div class="stat-label">Shield Defenses</div>
          <div class="stat-value" style="color: var(--purple);">${stats.blockedBots}</div>
          <div class="stat-sub">Crawlers & scrapers blocked</div>
        </div>
        <div class="stat-card ${stats.isVaultLocked ? 'rose' : ''}">
          <div class="stat-label">Vault Lock Status</div>
          <div class="stat-value" style="font-size: 1.25rem; color: ${stats.isVaultLocked ? '#EF4444' : 'var(--emerald)'};">
            ${stats.isVaultLocked ? '🔒 LOCKED' : '🟢 OPERATIONAL'}
          </div>
          <div class="stat-sub">${stats.totalFiles} encrypted files</div>
        </div>
      `;

      // Update navbar lock button state
      const lockBtn = document.getElementById('btn-global-vault-lock');
      if (lockBtn) {
        if (stats.isVaultLocked) {
          lockBtn.classList.add('locked');
          lockBtn.innerHTML = '🚨 VAULT LOCKED';
        } else {
          lockBtn.classList.remove('locked');
          lockBtn.innerHTML = '🔒 Lock Vault';
        }
      }

      // Threat signals summary
      const signalsList = document.getElementById('dashboard-signals-list');
      if (signalsList) {
        signalsList.innerHTML = `
          <div style="padding: 0.75rem; background: rgba(0, 240, 255, 0.05); border-left: 3px solid var(--cyber-cyan); border-radius: 4px;">
            <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main);">Scraper Shield</div>
            <div style="font-size: 0.75rem; color: var(--text-dim);">${stats.blockedBots} bot preview requests neutralized without burning.</div>
          </div>
          <div style="padding: 0.75rem; background: rgba(245, 158, 11, 0.05); border-left: 3px solid var(--amber); border-radius: 4px;">
            <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main);">Verification Guard</div>
            <div style="font-size: 0.75rem; color: var(--text-dim);">${stats.failedVerifications} unauthorized or incorrect receiver attempts blocked.</div>
          </div>
          <div style="padding: 0.75rem; background: rgba(239, 68, 68, 0.05); border-left: 3px solid var(--rose); border-radius: 4px;">
            <div style="font-size: 0.8rem; font-weight: 600; color: var(--text-main);">Active Correlated Incidents</div>
            <div style="font-size: 0.75rem; color: var(--text-dim);">${stats.openIncidents} anomalous pattern incidents currently recorded.</div>
          </div>
        `;
      }
    } catch (err) {
      console.error('Failed to load dashboard stats:', err);
    }
  },

  async loadSecrets() {
    try {
      const res = await API.getSecrets();
      const tbody = document.querySelector('#dashboard-secrets-table tbody');
      if (!tbody) return;

      if (!res.secrets || res.secrets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">No secrets created yet. Click "+ Create Secure Secret" above.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.secrets.slice(0, 6).map(s => {
        const now = Date.now();
        const minsLeft = Math.max(0, Math.ceil((s.expires_at - now) / 60000));
        let badgeClass = 'badge-active';
        if (s.status === 'DESTROYED') badgeClass = 'badge-destroyed';
        else if (s.status === 'EXPIRED') badgeClass = 'badge-expired';
        else if (s.status === 'REVOKED') badgeClass = 'badge-critical';

        return `
          <tr>
            <td>
              <div style="font-weight: 600; color: #fff;">${this.escape(s.title || s.secret_type)}</div>
              <div style="font-size: 0.7rem; color: var(--text-dim); font-family: var(--font-mono);">${s.id}</div>
            </td>
            <td><span class="badge badge-cyan">${s.secret_type}</span></td>
            <td>
              <span class="badge ${s.sensitivity === 'Critical' ? 'badge-critical' : (s.sensitivity === 'High' ? 'badge-pending' : 'badge-active')}">
                ${s.sensitivity}
              </span>
            </td>
            <td><span class="badge ${badgeClass}">${s.status}</span></td>
            <td style="font-family: var(--font-mono);">${s.views_remaining} / ${s.max_views}</td>
            <td style="font-size: 0.8rem; color: var(--text-muted);">${s.status === 'ACTIVE' ? `${minsLeft} min` : '—'}</td>
            <td>
              <div style="display: flex; gap: 0.4rem;">
                <button class="btn btn-secondary btn-sm" onclick="App.showDeliveryReceipt('${s.id}')">Receipt</button>
                ${s.status === 'ACTIVE' ? `
                  <button class="btn btn-danger btn-sm" onclick="ActiveSecretsComponent.triggerRevoke('${s.id}')">Revoke</button>
                ` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load secrets:', err);
    }
  },

  escape(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
  }
};
