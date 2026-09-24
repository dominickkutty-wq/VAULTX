const UniversalDeliveryComponent = {
  async render(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div>
          <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            📦 Universal Secure Package (.vx) & Multi-Channel Delivery
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            "STORE ANYWHERE. TRANSFER ANYWHERE. OPEN ONLY WITH AUTHORIZATION."
          </p>
        </div>
        <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="App.navigateTo('open')">📂 Open / Inspect .vx</button>
          <button class="btn btn-primary btn-sm" onclick="App.navigateTo('create')">+ New Package</button>
        </div>
      </div>

      <!-- Core Principle Banner -->
      <div class="card" style="margin-bottom: 1.5rem; background: linear-gradient(135deg, rgba(13,21,38,0.9), rgba(0,240,255,0.06)); border-color: var(--border-glow);">
        <div style="display: flex; gap: 1.5rem; align-items: center;">
          <div style="font-size: 3rem;">🌐</div>
          <div>
            <div style="font-weight: 700; font-size: 1.1rem; color: #fff;">VaultX Universal Secure Transfer Architecture</div>
            <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.25rem;">
              The physical transfer medium (USB, SD card, CD, Email, WhatsApp, Telegram) is NEVER the security boundary. 
              The encrypted <code>.vx</code> container remains locked by VaultX identity authorization, atomic view counters, and sender policies.
            </p>
          </div>
        </div>
      </div>

      <!-- Channels Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; margin-bottom: 1.5rem;">
        <!-- Digital Channels -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">📱 Digital Channels</div>
            <span class="badge badge-cyan">Zero Secret Leakage</span>
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.75rem; font-size: 0.85rem;">
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>🔗 One-Time Secure Link</span>
              <span class="badge badge-active">Available</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>📷 Scannable Dynamic QR</span>
              <span class="badge badge-active">Available</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>✉️ Encrypted Email Dispatch</span>
              <span class="badge badge-active">Configured</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>💬 WhatsApp / Telegram / SMS</span>
              <span class="badge badge-active">URL-Safe Ref</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>🏢 Microsoft Teams / Slack</span>
              <span class="badge badge-active">Scraper Shield</span>
            </div>
          </div>
        </div>

        <!-- Physical Storage & Media -->
        <div class="card">
          <div class="card-header">
            <div class="card-title">💾 Physical Storage Media</div>
            <span class="badge badge-cyan">Encrypted .vx Container</span>
          </div>
          <div style="display: flex; flex-direction: column; gap: 0.75rem; font-size: 0.85rem;">
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>⚡ USB Pen Drive / Flash Disk</span>
              <button class="btn btn-secondary btn-sm" style="padding: 2px 8px; font-size: 0.75rem;" onclick="UniversalDeliveryComponent.exportDemoPackage()">Export .vx</button>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>💽 External HDD / SSD Storage</span>
              <span class="badge badge-active">Supported</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>💳 SD & microSD Cards</span>
              <span class="badge badge-active">Supported</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>💿 CD / DVD / Blu-ray Disc</span>
              <span class="badge badge-active">Air-Gapped</span>
            </div>
            <div style="display: flex; justify-content: space-between; padding: 0.5rem; background: rgba(0,0,0,0.3); border-radius: 6px;">
              <span>🏷️ NFC Card / RFID Reference</span>
              <span class="badge badge-active">NDEF Ref</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Active Universal Packages Table -->
      <div class="card">
        <div class="card-header">
          <div class="card-title">📋 Configured Universal Packages</div>
          <button class="btn btn-secondary btn-sm" onclick="UniversalDeliveryComponent.loadPackages()">🔄 Refresh</button>
        </div>
        <div class="table-responsive">
          <table class="data-table" id="packages-table">
            <thead>
              <tr>
                <th>Package ID</th>
                <th>Package Name</th>
                <th>Linked Secret Type</th>
                <th>Sensitivity</th>
                <th>Configured Delivery Channels</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading packages...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    await this.loadPackages();
  },

  async loadPackages() {
    try {
      const res = await API.getPackages();
      const tbody = document.querySelector('#packages-table tbody');
      if (!tbody) return;

      if (!res.packages || res.packages.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">No packages exported yet.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.packages.map(p => {
        const channels = p.delivery_methods.join(', ');
        return `
          <tr>
            <td style="font-family: var(--font-mono); font-weight: 600; color: var(--cyber-cyan);">${p.package_id}</td>
            <td style="font-weight: 600; color: #fff;">${p.package_name}</td>
            <td><span class="badge badge-cyan">${p.secret_type}</span></td>
            <td><span class="badge ${p.sensitivity === 'Critical' ? 'badge-critical' : 'badge-pending'}">${p.sensitivity}</span></td>
            <td style="font-size: 0.8rem; color: var(--text-muted);">${channels}</td>
            <td><span class="badge ${p.status === 'ACTIVE' ? 'badge-active' : 'badge-destroyed'}">${p.status}</span></td>
            <td>
              <div style="display: flex; gap: 0.4rem;">
                <a href="/api/packages/${p.package_id}/download" class="btn btn-secondary btn-sm" download>⬇️ Download .vx</a>
                <button class="btn btn-secondary btn-sm" onclick="App.openViewLink('${p.secret_id}')">Open</button>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load packages:', err);
    }
  },

  exportDemoPackage() {
    window.location.href = '/api/packages/VX-DEMO-PACKAGE/download';
  }
};
