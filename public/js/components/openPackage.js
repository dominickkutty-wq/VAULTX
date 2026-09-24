const OpenPackageComponent = {
  render(container) {
    container.innerHTML = `
      <div style="max-width: 750px; margin: 2rem auto;">
        <div style="text-align: center; margin-bottom: 2rem;">
          <div style="font-size: 2.8rem; margin-bottom: 0.5rem;">📂</div>
          <h1 style="font-size: 1.6rem; font-weight: 700; color: #fff;">
            Open Universal Secure Package (.vx)
          </h1>
          <p style="color: var(--text-dim); font-size: 0.85rem; max-width: 500px; margin: 0 auto;">
            Import an encrypted VaultX package from USB, SD card, external drive, or cloud download.
          </p>
        </div>

        <div class="card" style="margin-bottom: 1.5rem; text-align: center; padding: 2.5rem; border: 2px dashed var(--border-subtle); cursor: pointer;" id="vx-drop-zone" onclick="document.getElementById('vx-file-input').click()">
          <input type="file" id="vx-file-input" accept=".vx,.json" style="display: none;" onchange="OpenPackageComponent.handleFileSelected(event)">
          <div style="font-size: 2.5rem; margin-bottom: 0.75rem;">⚡</div>
          <div style="font-weight: 600; color: #fff; font-size: 1.1rem; margin-bottom: 0.25rem;">
            Click to upload or Drag & Drop .vx Package here
          </div>
          <div style="color: var(--text-dim); font-size: 0.8rem;">
            Supports <code>vaultx-secret.vx</code> encrypted container files
          </div>
        </div>

        <!-- Demonstration Sample Loader -->
        <div style="text-align: center; margin-bottom: 1.5rem;">
          <button class="btn btn-secondary btn-sm" onclick="OpenPackageComponent.loadDemoPackage()">
            ⚡ Load Demo USB Package (prod-secrets-package.vx)
          </button>
        </div>

        <!-- Result Box -->
        <div id="package-inspect-result" style="display: none;"></div>
      </div>
    `;

    const dropZone = document.getElementById('vx-drop-zone');
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'var(--cyber-cyan)';
    });
    dropZone.addEventListener('dragleave', () => {
      dropZone.style.borderColor = 'var(--border-subtle)';
    });
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.style.borderColor = 'var(--border-subtle)';
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        OpenPackageComponent.processFile(e.dataTransfer.files[0]);
      }
    });
  },

  handleFileSelected(event) {
    if (event.target.files && event.target.files[0]) {
      this.processFile(event.target.files[0]);
    }
  },

  async processFile(file) {
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const content = JSON.parse(e.target.result);
        await this.inspectAndOpen(content);
      } catch (err) {
        alert('Failed to parse .vx file: ' + err.message);
      }
    };
    reader.readAsText(file);
  },

  async loadDemoPackage() {
    try {
      const res = await API.getPackages();
      if (res.packages && res.packages.length > 0) {
        const demoPkg = res.packages[0];
        // Fetch raw json
        const fileRes = await fetch(`/api/packages/${demoPkg.package_id}/download`);
        const json = await fileRes.json();
        await this.inspectAndOpen(json);
      } else {
        alert('No demo package available. Create one first.');
      }
    } catch (e) {
      alert('Error loading demo package: ' + e.message);
    }
  },

  async inspectAndOpen(packageContent) {
    const resultBox = document.getElementById('package-inspect-result');
    resultBox.style.display = 'block';
    resultBox.innerHTML = `
      <div class="card" style="text-align: center; padding: 2rem;">
        <div style="font-size: 2rem; margin-bottom: 0.5rem;">🔍</div>
        <div style="font-weight: 600; color: #fff;">Verifying Package Integrity & Authorization...</div>
      </div>
    `;

    try {
      const res = await API.openPackage(packageContent);

      resultBox.innerHTML = `
        <div class="card" style="border-color: var(--border-glow); box-shadow: var(--shadow-cyan);">
          <div class="card-header">
            <div class="card-title">✅ VaultX Secure Package Verified</div>
            <span class="badge badge-active">Integrity Confirmed</span>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.85rem; margin-bottom: 1.25rem;">
            <div>
              <span style="color: var(--text-dim);">Package ID:</span>
              <div style="font-family: var(--font-mono); color: var(--cyber-cyan); font-weight: 600;">${res.packageId}</div>
            </div>
            <div>
              <span style="color: var(--text-dim);">Authoritative Status:</span>
              <div><span class="badge badge-active">${res.status}</span></div>
            </div>
            <div>
              <span style="color: var(--text-dim);">Views Remaining:</span>
              <div style="font-weight: 600; color: #fff;">${res.viewsRemaining} View</div>
            </div>
            <div>
              <span style="color: var(--text-dim);">Cryptographic Integrity:</span>
              <div style="color: var(--emerald); font-weight: 600;">✓ SHA-256 Matched</div>
            </div>
          </div>

          <div style="background: rgba(10, 16, 30, 0.8); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 1rem; margin-bottom: 1.5rem; font-size: 0.8rem; color: var(--text-muted);">
            💡 Notice: The package contains only AES-256-GCM encrypted ciphertext. Decryption requires satisfying sender identity and policy verification through the VaultX gateway.
          </div>

          <div style="text-align: center;">
            <button class="btn btn-primary btn-lg" style="width: 100%;" onclick="App.openViewLink('${res.secretId}')">
              🛡️ Continue to Identity Verification & Reveal
            </button>
          </div>
        </div>
      `;
    } catch (err) {
      resultBox.innerHTML = `
        <div class="card" style="border-color: var(--rose); box-shadow: var(--shadow-rose);">
          <div class="card-header">
            <div class="card-title" style="color: #F87171;">⚠️ Package Verification Failed</div>
            <span class="badge badge-destroyed">Access Denied</span>
          </div>
          <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 1rem;">
            ${err.message || 'Package integrity failure or secret already burned/revoked.'}
          </p>
          <div style="font-size: 0.775rem; color: var(--text-dim);">
            VaultX fails closed. Physical possession of the encrypted .vx file does not grant authorization.
          </div>
        </div>
      `;
    }
  }
};
