const IncidentsComponent = {
  async render(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div>
          <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            🚨 Incident Ledger & Threat Intelligence
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            Security Event Correlation • Canary Decoy Traps • Credential Rotation Assistant
          </p>
        </div>
        <button class="btn btn-secondary btn-sm" onclick="IncidentsComponent.refreshAll()">🔄 Refresh</button>
      </div>

      <!-- Incidents & Canaries Grid -->
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 1.5rem;">
        <!-- Correlated Security Incidents -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">⚠️ Correlated Security Incidents</div>
            <span class="badge badge-critical" id="incident-count-badge">0 Open</span>
          </div>
          <div id="incidents-list" style="display: flex; flex-direction: column; gap: 0.75rem; max-height: 320px; overflow-y: auto;">
            <div style="color: var(--text-dim); font-size: 0.85rem;">Loading incidents...</div>
          </div>
        </div>

        <!-- Canary Decoy Traps -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">🪤 Synthetic Canary Decoys</div>
            <span class="badge badge-cyan">Intrusion Detection</span>
          </div>
          <div id="canaries-list" style="display: flex; flex-direction: column; gap: 0.75rem; max-height: 320px; overflow-y: auto;">
            <div style="color: var(--text-dim); font-size: 0.85rem;">Loading canaries...</div>
          </div>
        </div>
      </div>

      <!-- Credential Rotation Assistant -->
      <div class="card" style="margin-bottom: 1.5rem;">
        <div class="card-header">
          <div>
            <div class="card-title">🔄 Credential Rotation Assistant</div>
            <div class="card-subtitle">Zero-Trust recommendation engine for burned, revoked, or expired secrets</div>
          </div>
        </div>
        <div class="table-responsive">
          <table class="data-table" id="rotations-table">
            <thead>
              <tr>
                <th>Secret Title / Type</th>
                <th>Lifecycle Status</th>
                <th>Trigger Reason</th>
                <th>Recommended Action</th>
                <th>Rotation Status</th>
              </tr>
            </thead>
            <tbody>
              <tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading rotation assistant...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Global Security Event Audit Ledger -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">📜 Privacy-Preserving Security Audit Ledger</div>
            <div class="card-subtitle">Masked IP telemetry, zero secret exposure, verifiable cryptographic events</div>
          </div>
        </div>
        <div class="table-responsive">
          <table class="data-table" id="audit-ledger-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Target Secret / Resource</th>
                <th>Risk Level</th>
                <th>Masked Client IP</th>
                <th>Safe Metadata Details</th>
              </tr>
            </thead>
            <tbody>
              <tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading audit events...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    await this.refreshAll();
  },

  async refreshAll() {
    await this.loadIncidents();
    await this.loadCanaries();
    await this.loadRotations();
    await this.loadAuditLedger();
  },

  async loadIncidents() {
    try {
      const res = await API.getIncidents();
      const list = document.getElementById('incidents-list');
      const badge = document.getElementById('incident-count-badge');
      if (!list) return;

      const openCount = (res.incidents || []).filter(i => i.status === 'OPEN').length;
      if (badge) badge.innerText = `${openCount} Open`;

      if (!res.incidents || res.incidents.length === 0) {
        list.innerHTML = `<div style="color: var(--text-dim); font-size: 0.85rem; padding: 1rem; text-align: center;">No security incidents recorded. System normal.</div>`;
        return;
      }

      list.innerHTML = res.incidents.map(inc => `
        <div style="padding: 0.85rem; background: rgba(0,0,0,0.3); border-left: 3px solid ${inc.severity === 'CRITICAL' ? 'var(--rose)' : 'var(--amber)'}; border-radius: 6px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.25rem;">
            <span style="font-weight: 600; color: #fff; font-size: 0.85rem;">${this.escape(inc.incident_type)}</span>
            <span class="badge ${inc.severity === 'CRITICAL' ? 'badge-critical' : 'badge-pending'}">${inc.severity}</span>
          </div>
          <div style="font-size: 0.775rem; color: var(--text-muted);">${this.escape(inc.description)}</div>
          <div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 0.35rem;">
            Correlated Events: ${inc.correlated_events_count} • Recorded: ${new Date(inc.created_at).toLocaleTimeString()}
          </div>
        </div>
      `).join('');
    } catch (e) {
      console.error('Failed to load incidents:', e);
    }
  },

  async loadCanaries() {
    try {
      const res = await API.getCanaries();
      const list = document.getElementById('canaries-list');
      if (!list) return;

      if (!res.canaries || res.canaries.length === 0) {
        list.innerHTML = `<div style="color: var(--text-dim); font-size: 0.85rem;">No canaries found.</div>`;
        return;
      }

      list.innerHTML = res.canaries.map(can => `
        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 6px; font-size: 0.85rem;">
          <div>
            <div style="font-weight: 600; color: #fff;">${this.escape(can.name)}</div>
            <div style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">${can.synthetic_token}</div>
            <div style="font-size: 0.7rem; color: var(--text-muted);">${can.environment} • Hits: ${can.access_count}</div>
          </div>
          <button class="btn btn-danger btn-sm" style="padding: 3px 8px; font-size: 0.725rem;" onclick="IncidentsComponent.triggerCanary('${can.id}')">
            ⚠️ Trigger Intrusion
          </button>
        </div>
      `).join('');
    } catch (e) {
      console.error('Failed to load canaries:', e);
    }
  },

  async triggerCanary(canaryId) {
    try {
      const res = await API.triggerCanary(canaryId);
      alert(`🚨 CANARY TRIGGERED!\nIntrusion alert logged for decoy "${res.canaryName}". Critical incident correlated.`);
      this.refreshAll();
    } catch (e) {
      alert('Error triggering canary: ' + e.message);
    }
  },

  async loadRotations() {
    try {
      const res = await API.getRotations();
      const tbody = document.querySelector('#rotations-table tbody');
      if (!tbody) return;

      if (!res.recommendations || res.recommendations.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 1.5rem;">No credentials currently requiring rotation.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.recommendations.map(r => `
        <tr>
          <td>
            <div style="font-weight: 600; color: #fff;">${this.escape(r.title)}</div>
            <div style="font-size: 0.7rem; color: var(--text-dim);">${r.secretType} • ${r.sensitivity}</div>
          </td>
          <td><span class="badge ${r.lifecycleStatus === 'REVOKED' ? 'badge-critical' : 'badge-destroyed'}">${r.lifecycleStatus}</span></td>
          <td style="font-size: 0.8rem; color: var(--text-muted);">${this.escape(r.reason)}</td>
          <td style="font-size: 0.8rem; color: var(--cyber-cyan);">${this.escape(r.recommendedAction)}</td>
          <td><span class="badge badge-pending">Rotation Pending</span></td>
        </tr>
      `).join('');
    } catch (e) {
      console.error('Failed to load rotations:', e);
    }
  },

  async loadAuditLedger() {
    try {
      const res = await API.getAuditLedger();
      const tbody = document.querySelector('#audit-ledger-table tbody');
      if (!tbody) return;

      if (!res.events || res.events.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 2rem;">No audit events recorded yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.events.slice(0, 25).map(e => `
        <tr>
          <td style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">${new Date(e.created_at).toLocaleTimeString()}</td>
          <td><span class="badge badge-cyan">${e.event_type}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${e.secret_id || 'System / Global'}</td>
          <td><span class="badge ${e.risk_level === 'HIGH' ? 'badge-critical' : (e.risk_level === 'MEDIUM' ? 'badge-pending' : 'badge-active')}">${e.risk_level}</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">${e.ip_masked}</td>
          <td style="font-size: 0.75rem; color: var(--text-muted); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
            ${this.escape(JSON.stringify(e.details))}
          </td>
        </tr>
      `).join('');
    } catch (e) {
      console.error('Failed to load audit ledger:', e);
    }
  },

  escape(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
  }
};
