const ActiveSecretsComponent = {
  async render(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div>
          <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            📜 Active Secrets & Delivery Ledger
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            Authoritative lifecycle tracking, dual-consent authorization, and emergency revocation controls
          </p>
        </div>
        <button class="btn btn-primary btn-sm" onclick="App.navigateTo('create')">+ Create Secret</button>
      </div>

      <div class="card">
        <div class="table-responsive">
          <table class="data-table" id="all-secrets-table">
            <thead>
              <tr>
                <th>Secret Label / ID</th>
                <th>Type</th>
                <th>Sensitivity</th>
                <th>Status</th>
                <th>Dual Consent</th>
                <th>Dead-Man Switch</th>
                <th>Views</th>
                <th>Expires In</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading active secrets...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    await this.loadAllSecrets();
  },

  async loadAllSecrets() {
    try {
      const res = await API.getSecrets();
      const tbody = document.querySelector('#all-secrets-table tbody');
      if (!tbody) return;

      if (!res.secrets || res.secrets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 2rem;">No secrets found.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.secrets.map(s => {
        const now = Date.now();
        const minsLeft = Math.max(0, Math.ceil((s.expires_at - now) / 60000));
        let badgeClass = 'badge-active';
        if (s.status === 'DESTROYED') badgeClass = 'badge-destroyed';
        else if (s.status === 'EXPIRED') badgeClass = 'badge-expired';
        else if (s.status === 'REVOKED') badgeClass = 'badge-critical';

        // Dual consent status badge
        let dualBadge = '<span style="color: var(--text-dim); font-size: 0.75rem;">—</span>';
        if (s.dual_consent_required) {
          if (s.dual_consent_status === 'APPROVED') {
            dualBadge = `<span class="badge badge-active">Approved</span>`;
          } else if (s.dual_consent_status === 'PENDING') {
            dualBadge = `
              <div style="display: flex; gap: 0.3rem; align-items: center;">
                <span class="badge badge-pending">Pending</span>
                <button class="btn btn-primary btn-sm" style="padding: 2px 6px; font-size: 0.65rem;" onclick="ActiveSecretsComponent.handleDualConsent('${s.id}', 'APPROVED')">Approve</button>
                <button class="btn btn-danger btn-sm" style="padding: 2px 6px; font-size: 0.65rem;" onclick="ActiveSecretsComponent.handleDualConsent('${s.id}', 'REJECTED')">Reject</button>
              </div>
            `;
          } else if (s.dual_consent_status === 'REJECTED') {
            dualBadge = `<span class="badge badge-destroyed">Rejected</span>`;
          }
        }

        // Dead-man switch badge
        let deadManBadge = '<span style="color: var(--text-dim); font-size: 0.75rem;">—</span>';
        if (s.dead_man_switch_hours > 0 && s.status === 'ACTIVE') {
          const deadline = s.dead_man_confirmed_at + (s.dead_man_switch_hours * 3600000);
          const hoursLeft = Math.max(0, ((deadline - now) / 3600000).toFixed(1));
          deadManBadge = `
            <div style="display: flex; gap: 0.3rem; align-items: center;">
              <span class="badge badge-pending" style="font-family: var(--font-mono);">${hoursLeft}h Left</span>
              <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 0.65rem;" onclick="ActiveSecretsComponent.confirmDeadMan('${s.id}')">Check-In</button>
            </div>
          `;
        }

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
            <td>${dualBadge}</td>
            <td>${deadManBadge}</td>
            <td style="font-family: var(--font-mono);">${s.views_remaining} / ${s.max_views}</td>
            <td style="font-size: 0.8rem; color: var(--text-muted);">${s.status === 'ACTIVE' ? `${minsLeft} min` : '—'}</td>
            <td>
              <div style="display: flex; gap: 0.4rem;">
                <button class="btn btn-secondary btn-sm" onclick="App.showDeliveryReceipt('${s.id}')">Receipt</button>
                <button class="btn btn-secondary btn-sm" onclick="App.openViewLink('${s.id}')" title="Test View Link">Open</button>
                ${s.status === 'ACTIVE' ? `
                  <button class="btn btn-danger btn-sm" onclick="ActiveSecretsComponent.triggerRevoke('${s.id}')">Revoke</button>
                ` : ''}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load active secrets:', err);
    }
  },

  async triggerRevoke(secretId) {
    if (!confirm(`Are you sure you want to permanently REVOKE secret ${secretId}?\nAll active viewing sessions will immediately terminate and ciphertext will be permanently wiped.`)) {
      return;
    }

    try {
      const res = await API.revokeSecret(secretId);
      alert(res.message);
      this.loadAllSecrets();
      DashboardComponent.loadStats();
    } catch (err) {
      alert('Revocation failed: ' + err.message);
    }
  },

  async handleDualConsent(secretId, decision) {
    try {
      await API.approveDualConsent(secretId, decision);
      this.loadAllSecrets();
    } catch (err) {
      alert('Dual consent error: ' + err.message);
    }
  },

  async confirmDeadMan(secretId) {
    try {
      const res = await API.confirmDeadMan(secretId);
      alert(res.message);
      this.loadAllSecrets();
    } catch (err) {
      alert('Dead man confirm error: ' + err.message);
    }
  },

  escape(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
  }
};
