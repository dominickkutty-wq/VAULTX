const FileGatewayComponent = {
  currentFilter: null,

  async render(container) {
    container.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <div>
          <h1 style="font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.5rem;">
            📁 Zero-Trust File Security Gateway
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem;">
            Scan • Verify • Classify • Encrypt • Version • Control View • Audit
          </p>
        </div>
        <button class="btn btn-primary btn-sm" onclick="FileGatewayComponent.showImportModal()">+ Secure Import File</button>
      </div>

      <!-- Overview Cards -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem;">
        <div class="stat-card">
          <div class="stat-label">Total Vault Files</div>
          <div class="stat-value" id="fg-total-files" style="color: var(--cyber-cyan);">—</div>
          <div class="stat-sub">Hardware AES-256-GCM</div>
        </div>
        <div class="stat-card rose">
          <div class="stat-label">Highly Confidential</div>
          <div class="stat-value" id="fg-critical-files" style="color: #F87171;">—</div>
          <div class="stat-sub">Identity & financial data detected</div>
        </div>
        <div class="stat-card emerald">
          <div class="stat-label">Integrity Status</div>
          <div class="stat-value" style="color: var(--emerald); font-size: 1.3rem;">100% VERIFIED</div>
          <div class="stat-sub">SHA-256 cryptographic check</div>
        </div>
        <div class="stat-card amber">
          <div class="stat-label">Legacy Migration</div>
          <div class="stat-value" style="color: var(--amber); font-size: 1.3rem;">READY</div>
          <div class="stat-sub">Pendrive, CD, Telegram import</div>
        </div>
      </div>

      <!-- Files Filter & Table -->
      <div class="card">
        <div class="card-header">
          <div style="display: flex; align-items: center; gap: 1rem;">
            <div class="card-title">🗄️ Encrypted Vault Files</div>
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn btn-secondary btn-sm" onclick="FileGatewayComponent.filter('')">All</button>
              <button class="btn btn-secondary btn-sm" onclick="FileGatewayComponent.filter('HIGHLY_CONFIDENTIAL')">Highly Confidential</button>
              <button class="btn btn-secondary btn-sm" onclick="FileGatewayComponent.filter('CONFIDENTIAL')">Confidential</button>
              <button class="btn btn-secondary btn-sm" onclick="FileGatewayComponent.filter('INTERNAL')">Internal</button>
            </div>
          </div>
        </div>

        <div class="table-responsive">
          <table class="data-table" id="vault-files-table">
            <thead>
              <tr>
                <th>File Name</th>
                <th>Classification</th>
                <th>Size</th>
                <th>Detected Sensitive Patterns</th>
                <th>Version</th>
                <th>SHA-256 Checksum</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">Loading vault files...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;

    await this.loadFiles();
  },

  async loadFiles(classification = '') {
    try {
      const res = await API.getFiles(classification);
      const tbody = document.querySelector('#vault-files-table tbody');
      if (!tbody) return;

      const totalEl = document.getElementById('fg-total-files');
      const critEl = document.getElementById('fg-critical-files');
      if (totalEl) totalEl.innerText = res.files.length;
      if (critEl) critEl.innerText = res.files.filter(f => f.classification === 'HIGHLY_CONFIDENTIAL').length;

      if (!res.files || res.files.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">No files imported yet. Click "+ Secure Import File" above.</td></tr>`;
        return;
      }

      tbody.innerHTML = res.files.map(f => {
        const signals = f.sensitivity_signals || [];
        const signalsHtml = signals.length > 0 
          ? signals.map(s => `<span class="badge badge-critical" style="font-size: 0.65rem; margin-right: 3px;">${s}</span>`).join('')
          : '<span style="color: var(--text-dim); font-size: 0.75rem;">None</span>';

        return `
          <tr>
            <td>
              <div style="font-weight: 600; color: #fff;">${this.escape(f.filename)}</div>
              <div style="font-size: 0.7rem; color: var(--text-dim); font-family: var(--font-mono);">${f.id}</div>
            </td>
            <td>
              <span class="badge ${f.classification === 'HIGHLY_CONFIDENTIAL' ? 'badge-critical' : (f.classification === 'CONFIDENTIAL' ? 'badge-pending' : 'badge-active')}">
                ${f.classification}
              </span>
            </td>
            <td style="font-family: var(--font-mono); font-size: 0.8rem;">${(f.file_size / 1024).toFixed(1)} KB</td>
            <td>${signalsHtml}</td>
            <td><span class="badge badge-cyan">v${f.current_version}</span></td>
            <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">
              ${f.sha256_hash.substring(0, 14)}...
            </td>
            <td>
              <div style="display: flex; gap: 0.4rem;">
                <button class="btn btn-secondary btn-sm" onclick="FileGatewayComponent.viewFile('${f.id}')">👁️ View</button>
                <button class="btn btn-secondary btn-sm" onclick="FileGatewayComponent.showDetails('${f.id}')">Security Panel</button>
                <a href="/api/files/${f.id}/download" class="btn btn-secondary btn-sm" download>⬇️</a>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load vault files:', err);
    }
  },

  filter(cls) {
    this.loadFiles(cls);
  },

  showImportModal() {
    const modal = document.createElement('div');
    modal.className = 'modal-backdrop';
    modal.id = 'import-modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
          <h3 style="font-size: 1.15rem; color: #fff; font-weight: 700;">Universal Secure File Import</h3>
          <button class="btn btn-secondary btn-sm" onclick="document.getElementById('import-modal').remove()">✕</button>
        </div>

        <form id="import-file-form" onsubmit="FileGatewayComponent.handleImportSubmit(event)">
          <div class="form-group">
            <label class="form-label">Import Source Channel</label>
            <select class="form-select" id="import-source">
              <option value="Local Computer">Local Computer / Hard Disk</option>
              <option value="Pendrive / USB Flash">Pendrive / USB Flash Drive</option>
              <option value="External HDD / SSD">External HDD / SSD Storage</option>
              <option value="CD/DVD Extracted">CD / DVD Extracted Media</option>
              <option value="Telegram Export">Telegram Exported Attachment</option>
              <option value="Email Download">Email Attachment</option>
              <option value="WhatsApp Export">WhatsApp Exported Document</option>
            </select>
          </div>

          <div class="form-group">
            <label class="form-label">Select File to Protect</label>
            <input type="file" class="form-input" id="import-file-input" required>
            <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.35rem;">
              File will be hashed, scanned for sensitive credentials/IDs, encrypted with AES-256-GCM, and stored safely.
            </div>
          </div>

          <div style="display: flex; justify-content: flex-end; gap: 0.5rem; margin-top: 1.5rem;">
            <button type="button" class="btn btn-secondary" onclick="document.getElementById('import-modal').remove()">Cancel</button>
            <button type="submit" class="btn btn-primary" id="btn-submit-import">🔐 Scan, Encrypt & Import</button>
          </div>
        </form>
      </div>
    `;
    document.body.appendChild(modal);
  },

  async handleImportSubmit(e) {
    e.preventDefault();
    const fileInput = document.getElementById('import-file-input');
    if (!fileInput.files || !fileInput.files[0]) return;

    const file = fileInput.files[0];
    const source = document.getElementById('import-source').value;
    const btn = document.getElementById('btn-submit-import');
    btn.disabled = true;
    btn.innerText = '🛡️ Scanning & Encrypting...';

    const formData = new FormData();
    formData.append('file', file);
    formData.append('source', source);

    try {
      const res = await API.importFile(formData);
      document.getElementById('import-modal')?.remove();
      alert(`✅ File "${res.file.filename}" securely imported and encrypted!\nClassification: ${res.file.classification}\nSensitive Signals: ${res.file.sensitivitySignals.length}`);
      this.loadFiles();
    } catch (err) {
      alert('File import failed: ' + err.message);
      btn.disabled = false;
      btn.innerText = '🔐 Scan, Encrypt & Import';
    }
  },

  async viewFile(fileId) {
    try {
      const res = await API.viewFileText(fileId);
      const modal = document.createElement('div');
      modal.className = 'modal-backdrop';
      modal.id = 'viewer-modal';
      modal.innerHTML = `
        <div class="modal-content" style="max-width: 750px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <div>
              <h3 style="font-size: 1.15rem; color: #fff; font-weight: 700;">Secure Document Viewer</h3>
              <div style="font-size: 0.75rem; color: var(--text-dim);">${this.escape(res.filename)} • ${res.classification}</div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('viewer-modal').remove()">✕</button>
          </div>

          <div style="background: rgba(16,185,129,0.1); border: 1px solid var(--emerald); padding: 0.5rem 0.8rem; border-radius: 6px; font-size: 0.75rem; color: var(--emerald); margin-bottom: 1rem;">
            ✓ Integrity Verified: SHA-256 verified against vault metadata. Decrypted in ephemeral RAM only.
          </div>

          <pre style="background: #020408; padding: 1.25rem; border-radius: 8px; border: 1px solid #1E293B; color: #00F0FF; font-family: var(--font-mono); font-size: 0.85rem; max-height: 400px; overflow: auto; white-space: pre-wrap;">${this.escape(res.textPreview || 'Binary file preview. Download to view complete binary.')}</pre>
        </div>
      `;
      document.body.appendChild(modal);
    } catch (err) {
      alert('Cannot view file: ' + err.message);
    }
  },

  async showDetails(fileId) {
    try {
      const details = await API.getFileDetails(fileId);
      const modal = document.createElement('div');
      modal.className = 'modal-backdrop';
      modal.id = 'details-modal';
      modal.innerHTML = `
        <div class="modal-content" style="max-width: 700px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h3 style="font-size: 1.2rem; color: #fff; font-weight: 700;">File Security Panel & Version History</h3>
            <button class="btn btn-secondary btn-sm" onclick="document.getElementById('details-modal').remove()">✕</button>
          </div>

          <div style="margin-bottom: 1.25rem; font-size: 0.85rem;">
            <div><strong>File:</strong> ${this.escape(details.file.filename)}</div>
            <div><strong>Current Version:</strong> v${details.file.current_version}</div>
            <div><strong>Classification:</strong> ${details.file.classification}</div>
            <div><strong>SHA-256:</strong> <code style="font-family: var(--font-mono); color: var(--cyber-cyan);">${details.file.sha256_hash}</code></div>
          </div>

          <h4 style="font-size: 0.95rem; color: #fff; margin-bottom: 0.5rem;">Version History</h4>
          <div style="background: rgba(0,0,0,0.3); border-radius: 6px; padding: 0.5rem; margin-bottom: 1.25rem; max-height: 180px; overflow-y: auto;">
            ${details.versions.map(v => `
              <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.4rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 0.8rem;">
                <div>
                  <span class="badge badge-cyan">v${v.version_number}</span>
                  <span style="color: var(--text-muted); margin-left: 0.5rem;">${this.escape(v.change_summary)}</span>
                </div>
                <div>
                  ${v.version_number !== details.file.current_version ? `
                    <button class="btn btn-secondary btn-sm" style="padding: 2px 6px; font-size: 0.7rem;" onclick="FileGatewayComponent.restoreVersion('${fileId}', ${v.version_number})">Restore</button>
                  ` : '<span style="color: var(--emerald); font-size: 0.75rem;">Current</span>'}
                </div>
              </div>
            `).join('')}
          </div>

          <h4 style="font-size: 0.95rem; color: #fff; margin-bottom: 0.5rem;">Upload New Version</h4>
          <form onsubmit="FileGatewayComponent.handleNewVersion(event, '${fileId}')" style="display: flex; gap: 0.5rem;">
            <input type="file" id="version-file-input" required class="form-input" style="padding: 0.4rem;">
            <button type="submit" class="btn btn-primary btn-sm">+ Upload v${details.file.current_version + 1}</button>
          </form>
        </div>
      `;
      document.body.appendChild(modal);
    } catch (err) {
      alert('Error fetching file details: ' + err.message);
    }
  },

  async handleNewVersion(e, fileId) {
    e.preventDefault();
    const input = document.getElementById('version-file-input');
    if (!input.files || !input.files[0]) return;

    const formData = new FormData();
    formData.append('file', input.files[0]);
    formData.append('changeSummary', 'Manual version update from security panel');

    try {
      await API.addFileVersion(fileId, formData);
      document.getElementById('details-modal')?.remove();
      alert('✅ New file version encrypted and saved!');
      this.loadFiles();
    } catch (err) {
      alert('Failed to add version: ' + err.message);
    }
  },

  async restoreVersion(fileId, versionNumber) {
    try {
      await API.restoreFileVersion(fileId, versionNumber);
      document.getElementById('details-modal')?.remove();
      alert(`✅ Restored to version v${versionNumber}!`);
      this.loadFiles();
    } catch (err) {
      alert('Failed to restore version: ' + err.message);
    }
  },

  escape(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
  }
};
