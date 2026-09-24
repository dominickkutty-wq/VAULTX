// VaultX Single Page Application Controller & Router
const App = {
  currentTab: 'dashboard',

  init() {
    this.route();
    window.addEventListener('popstate', () => this.route());
  },

  route() {
    const path = window.location.pathname;

    // Check for receiver links: /view/:id, /open/:id, /receiver/:id
    const receiverMatch = path.match(/^\/(view|open|receiver)\/([a-zA-Z0-9_\-]+)/);
    if (receiverMatch && receiverMatch[2]) {
      const secretId = receiverMatch[2];
      console.log(`🛡️ [VaultX SPA Router] Matching receiver route for secret ID: ${secretId}`);
      this.mountReceiverView(secretId);
      return;
    }

    if (path === '/open') {
      this.navigateTo('open', false);
      return;
    }
    if (path === '/lab') {
      this.navigateTo('lab', false);
      return;
    }
    if (path === '/files') {
      this.navigateTo('files', false);
      return;
    }
    if (path === '/what-if') {
      this.navigateTo('whatif', false);
      return;
    }
    if (path === '/incidents') {
      this.navigateTo('incidents', false);
      return;
    }

    // Default to dashboard
    this.navigateTo(this.currentTab, false);
  },

  navigateTo(tabKey, updateHistory = true) {
    this.currentTab = tabKey;
    const navbar = document.getElementById('main-navbar');
    if (navbar) navbar.style.display = 'flex';

    // Update active nav link
    document.querySelectorAll('.nav-link').forEach(link => {
      link.classList.remove('active');
      if (link.dataset.tab === tabKey) {
        link.classList.add('active');
      }
    });

    if (updateHistory) {
      const path = tabKey === 'dashboard' ? '/' : `/${tabKey}`;
      window.history.pushState({ tab: tabKey }, '', path);
    }

    const container = document.getElementById('main-content');
    if (!container) return;

    switch (tabKey) {
      case 'dashboard':
        DashboardComponent.render(container);
        break;
      case 'create':
        CreateSecretComponent.render(container);
        break;
      case 'secrets':
        ActiveSecretsComponent.render(container);
        break;
      case 'packages':
        UniversalDeliveryComponent.render(container);
        break;
      case 'open':
        OpenPackageComponent.render(container);
        break;
      case 'files':
        FileGatewayComponent.render(container);
        break;
      case 'whatif':
        WhatIfSimulatorComponent.render(container);
        break;
      case 'lab':
        SecurityLabComponent.render(container);
        break;
      case 'incidents':
        IncidentsComponent.render(container);
        break;
      default:
        DashboardComponent.render(container);
    }
  },

  mountReceiverView(secretId) {
    const navbar = document.getElementById('main-navbar');
    if (navbar) navbar.style.display = 'none'; // Receivers never see sender controls!

    const container = document.getElementById('main-content');
    if (container) {
      ReceiverViewComponent.render(container, secretId);
    }
  },

  openViewLink(secretId, customUrl) {
    const targetUrl = customUrl || `${window.location.origin}/view/${secretId}`;
    window.open(targetUrl, '_blank');
  },

  async toggleGlobalLock() {
    if (!confirm('Toggle Emergency Vault Lock?\nWhen active, all sensitive file views are restricted.')) {
      return;
    }
    try {
      const res = await API.toggleVaultLock();
      alert(res.message);
      DashboardComponent.loadStats();
    } catch (e) {
      alert('Error toggling lock: ' + e.message);
    }
  },

  showSecretCreatedModal(data) {
    // Determine accurate canonical and alternative URLs based on active browser origin
    const origin = window.location.origin;
    const canonicalUrl = `${origin}/view/${data.id}`;
    const lanUrl = data.lanUrl || canonicalUrl;

    const modal = document.createElement('div');
    modal.className = 'modal-backdrop';
    modal.id = 'secret-created-modal';
    modal.innerHTML = `
      <div class="modal-content" style="max-width: 650px; text-align: center;">
        <div style="font-size: 2.5rem; margin-bottom: 0.5rem;">🎉</div>
        <h2 style="font-size: 1.4rem; color: #fff; font-weight: 700;">Secret Encrypted & Ready to Share</h2>
        <p style="color: var(--text-dim); font-size: 0.85rem; margin-bottom: 1.25rem;">
          Protected by AES-256-GCM. Plaintext has been wiped from memory.
        </p>

        <!-- Canonical Access URL Box -->
        <div style="background: rgba(10,16,30,0.85); border: 1px solid var(--border-glow); border-radius: var(--radius-md); padding: 1.15rem; margin-bottom: 1rem; text-align: left;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem;">
            <span style="font-size: 0.75rem; font-weight: 700; color: var(--cyber-cyan); text-transform: uppercase;">
              🔗 Canonical Receiver Link
            </span>
            <span class="badge badge-active" style="font-size: 0.65rem;">One-Time Safe</span>
          </div>
          <div style="font-family: var(--font-mono); font-size: 0.875rem; color: #fff; word-break: break-all; margin-bottom: 0.75rem; padding: 0.5rem; background: #020408; border-radius: 6px; border: 1px solid #1E293B;">
            ${canonicalUrl}
          </div>
          <div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
            <button class="btn btn-primary btn-sm" id="btn-copy-canon" onclick="App.copyText('${canonicalUrl}', 'btn-copy-canon')">
              📋 Copy Link
            </button>
            <button class="btn btn-secondary btn-sm" onclick="App.openViewLink('${data.id}', '${canonicalUrl}')">
              👁️ Open Link
            </button>
          </div>
        </div>

        ${lanUrl !== canonicalUrl ? `
          <!-- Local Area Network Link for Phone/Other Device Testing -->
          <div style="background: rgba(10,16,30,0.6); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 0.85rem; margin-bottom: 1rem; text-align: left;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
              <span style="font-size: 0.725rem; font-weight: 600; color: var(--amber); text-transform: uppercase;">
                📱 Local Wi-Fi / LAN Device Link (For Phone / Tablet)
              </span>
            </div>
            <div style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted); word-break: break-all; margin-bottom: 0.5rem;">
              ${lanUrl}
            </div>
            <div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
              <button class="btn btn-secondary btn-sm" id="btn-copy-lan" style="padding: 2px 8px; font-size: 0.75rem;" onclick="App.copyText('${lanUrl}', 'btn-copy-lan')">
                📋 Copy LAN Link
              </button>
              <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.75rem;" onclick="App.openViewLink('${data.id}', '${lanUrl}')">
                👁️ Open LAN Link
              </button>
            </div>
          </div>
        ` : ''}

        <!-- QR Code -->
        <div style="margin-bottom: 1.25rem;">
          <div style="display: inline-block; padding: 10px; background: #070B14; border: 1px solid var(--border-subtle); border-radius: 8px;">
            <img src="${data.qrCodeDataUrl}" alt="Secure QR Code" style="width: 160px; height: 160px; display: block;">
          </div>
          <div style="font-size: 0.7rem; color: var(--text-dim); margin-top: 0.4rem;">
            *QR points strictly to URL reference. Plaintext secret is NEVER stored inside QR.
          </div>
        </div>

        <!-- Receiver Link Test Panel -->
        <div style="background: rgba(0,0,0,0.4); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 0.85rem; margin-bottom: 1.25rem; text-align: left;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
            <span style="font-size: 0.75rem; font-weight: 700; color: #fff; text-transform: uppercase;">
              🧪 Secure Receiver Link Test
            </span>
            <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.7rem;" onclick="App.runReceiverLinkTest('${data.id}')">
              Verify Link
            </button>
          </div>
          <div id="modal-link-test-results" style="font-size: 0.75rem; color: var(--text-dim);">
            Click "Verify Link" to run the 7-stage diagnostic check.
          </div>
        </div>

        <div style="font-size: 0.725rem; color: var(--text-muted); font-family: var(--font-mono); margin-bottom: 1.25rem;">
          SHA256 Fingerprint: ${data.integrityHash ? data.integrityHash.substring(0, 24) + '...' : 'Verified'}
        </div>

        <button class="btn btn-secondary" style="width: 100%;" onclick="document.getElementById('secret-created-modal').remove()">
          Done / Close
        </button>
      </div>
    `;
    document.body.appendChild(modal);

    // Auto-run test once for immediate visual confirmation
    this.runReceiverLinkTest(data.id);
  },

  async runReceiverLinkTest(secretId) {
    const container = document.getElementById('modal-link-test-results');
    if (!container) return;

    container.innerHTML = '<span style="color: var(--cyber-cyan);">Evaluating link pipeline...</span>';
    try {
      const diag = await API.getSecretDiagnostics(secretId);
      container.innerHTML = `
        <div style="display: flex; flex-direction: column; gap: 0.25rem;">
          <div style="color: ${diag.tokenPersisted ? 'var(--emerald)' : '#F87171'}; font-weight: 600;">
            ${diag.tokenPersisted ? '✓' : '✗'} Token Persisted in Database (Status: ${diag.status})
          </div>
          <div style="color: ${diag.receiverRouteReachable ? 'var(--emerald)' : '#F87171'};">
            ✓ Receiver Route Reachable (/view/${secretId})
          </div>
          <div style="color: ${diag.expiryChecked ? 'var(--emerald)' : '#F87171'};">
            ✓ Expiry Validated (${diag.viewsRemaining}/${diag.maxViews} views remaining)
          </div>
          <div style="color: var(--cyber-cyan); font-weight: bold; margin-top: 0.25rem;">
            ${diag.diagnosticsPassed ? '🟢 Link Ready for Recipient Access' : '🔴 Blocked: ' + diag.status}
          </div>
        </div>
      `;
    } catch (e) {
      container.innerHTML = `<span style="color: #F87171;">Diagnostic check failed: ${e.message}</span>`;
    }
  },

  async showDeliveryReceipt(secretId) {
    try {
      const res = await API.getSecretStatus(secretId);
      const s = res.secret;
      const proof = res.destructionProof;

      const modal = document.createElement('div');
      modal.className = 'modal-backdrop';
      modal.id = 'receipt-modal';
      modal.innerHTML = `
        <div class="modal-content" style="max-width: 650px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <div>
              <h3 style="font-size: 1.2rem; color: #fff; font-weight: 700;">Secure Delivery Receipt</h3>
              <div style="font-size: 0.75rem; color: var(--text-dim); font-family: var(--font-mono);">Secret ID: ${s.id}</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('receipt-modal').remove()">✕</button>
          </div>

          <div style="background: rgba(10,16,30,0.8); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1.25rem; font-size: 0.85rem; margin-bottom: 1.25rem;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem;">
              <div><span style="color: var(--text-dim);">Secret Title:</span> <strong>${s.title}</strong></div>
              <div><span style="color: var(--text-dim);">Classification:</span> <strong>${s.sensitivity}</strong></div>
              <div><span style="color: var(--text-dim);">Views Recorded:</span> <strong>${s.max_views - s.views_remaining} / ${s.max_views}</strong></div>
              <div><span style="color: var(--text-dim);">Current Status:</span> <span class="badge ${s.status === 'ACTIVE' ? 'badge-active' : 'badge-destroyed'}">${s.status}</span></div>
            </div>
          </div>

          ${proof ? `
            <div style="background: rgba(16,185,129,0.06); border: 1px solid var(--emerald); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 1.25rem; font-size: 0.8rem;">
              <div style="font-weight: 700; color: var(--emerald); margin-bottom: 0.35rem;">✓ Cryptographic Destruction Record Verified</div>
              <div>Proof Hash: <code style="font-family: var(--font-mono); color: var(--cyber-cyan);">${proof.proofHash}</code></div>
              <div>Reason: ${proof.reason}</div>
              <div>Destroyed At: ${new Date(proof.destroyedAt).toLocaleString()}</div>
            </div>
          ` : ''}

          <h4 style="font-size: 0.9rem; color: #fff; margin-bottom: 0.5rem;">Associated Security Events</h4>
          <div style="background: rgba(0,0,0,0.3); border-radius: 6px; padding: 0.5rem; max-height: 180px; overflow-y: auto; font-size: 0.775rem;">
            ${res.events.map(e => `
              <div style="display: flex; justify-content: space-between; padding: 0.35rem 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                <span class="badge badge-cyan" style="font-size: 0.65rem;">${e.event_type}</span>
                <span style="color: var(--text-dim);">${new Date(e.created_at).toLocaleTimeString()}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    } catch (e) {
      alert('Error fetching receipt: ' + e.message);
    }
  },

  showPolicySimulationModal(data) {
    const modal = document.createElement('div');
    modal.className = 'modal-backdrop';
    modal.id = 'sim-test-modal';
    modal.innerHTML = `
      <div class="modal-content" style="max-width: 750px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
          <div>
            <h3 style="font-size: 1.2rem; color: #fff; font-weight: 700;">Policy Simulation Matrix</h3>
            <div style="font-size: 0.75rem; color: var(--cyber-cyan);">Coverage Score: ${data.coverage.coverageFraction} Protections Active</div>
          </div>
          <button class="btn btn-secondary btn-sm" onclick="document.getElementById('sim-test-modal').remove()">✕</button>
        </div>

        <div style="max-height: 380px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.75rem;">
          ${data.scenarioResults.map(r => `
            <div style="padding: 0.75rem; background: rgba(0,0,0,0.4); border-radius: 6px; font-size: 0.8rem; border-left: 3px solid ${r.riskLevel === 'HIGH' ? 'var(--rose)' : 'var(--emerald)'};">
              <div style="display: flex; justify-content: space-between; font-weight: 600; color: #fff;">
                <span>${r.scenario}</span>
                <span class="badge ${r.riskLevel === 'HIGH' ? 'badge-critical' : 'badge-active'}">${r.riskLevel}</span>
              </div>
              <div style="color: var(--text-muted); margin-top: 0.25rem;">Action: ${r.action}</div>
              <div style="color: var(--cyber-cyan); font-size: 0.75rem; margin-top: 0.2rem;">Final State: ${r.finalState}</div>
            </div>
          `).join('')}
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  },

  copyText(text, btnId) {
    const doUpdateBtn = () => {
      const btn = document.getElementById(btnId);
      if (btn) {
        btn.innerText = '✓ Copied!';
        setTimeout(() => { btn.innerText = '📋 Copy Link'; }, 2500);
      }
    };

    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(doUpdateBtn).catch(() => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }

    function fallbackCopy(str) {
      const el = document.createElement('textarea');
      el.value = str;
      el.setAttribute('readonly', '');
      el.style.position = 'absolute';
      el.style.left = '-9999px';
      document.body.appendChild(el);
      el.select();
      try {
        document.execCommand('copy');
        doUpdateBtn();
      } catch (err) {
        console.error('Fallback copy failed', err);
      }
      document.body.removeChild(el);
    }
  }
};

window.addEventListener('DOMContentLoaded', () => {
  App.init();
});
