// VaultX Frontend API Client with Robust Network & Diagnostic Handling
const API = {
  getBaseUrl() {
    return window.location.origin;
  },

  async get(url) {
    const res = await fetch(url, {
      headers: {
        'Cache-Control': 'no-cache',
        'Accept': 'application/json'
      }
    });

    let data;
    const text = await res.text();
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = { error: 'RESPONSE_PARSE_ERROR', message: text.substring(0, 150) || `HTTP ${res.status}` };
    }

    if (!res.ok) {
      const err = new Error(data.message || data.error || `HTTP ${res.status}`);
      err.data = data;
      err.status = res.status;
      throw err;
    }
    return data;
  },

  async post(url, body) {
    const isFormData = body instanceof FormData;
    const res = await fetch(url, {
      method: 'POST',
      headers: isFormData ? { 'Accept': 'application/json' } : { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: isFormData ? body : JSON.stringify(body)
    });

    let data;
    const text = await res.text();
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = { error: 'RESPONSE_PARSE_ERROR', message: text.substring(0, 150) || `HTTP ${res.status}` };
    }

    if (!res.ok) {
      const err = new Error(data.message || data.error || `HTTP ${res.status}`);
      err.data = data;
      err.status = res.status;
      throw err;
    }
    return data;
  },

  // System Stats
  getStats: () => API.get('/api/system/stats'),
  toggleVaultLock: () => API.post('/api/system/toggle-lock', {}),
  getAuditLedger: () => API.get('/api/system/audit-ledger'),
  getIncidents: () => API.get('/api/system/incidents'),
  getCanaries: () => API.get('/api/system/canaries'),
  triggerCanary: (canaryId) => API.post('/api/system/trigger-canary', { canaryId }),
  getRotations: () => API.get('/api/system/rotations'),

  // Secrets
  createSecret: (payload) => API.post('/api/secrets', payload),
  getSecrets: () => API.get('/api/secrets'),
  getSecretStatus: (id) => API.get(`/api/secrets/${id}/status`),
  revokeSecret: (id) => API.post(`/api/secrets/${id}/revoke`, {}),
  approveDualConsent: (id, decision) => API.post(`/api/secrets/${id}/dual-consent`, { decision }),
  confirmDeadMan: (id) => API.post(`/api/secrets/${id}/dead-man-confirm`, {}),

  // Receiver API
  getSecretMetadata: (id) => API.get(`/api/view/${id}/metadata`),
  getSecretDiagnostics: (id) => API.get(`/api/view/${id}/diagnostics`),
  requestOtp: (id, email) => API.post(`/api/view/${id}/request-otp`, { email }),
  verifyReceiver: (id, payload) => API.post(`/api/view/${id}/verify`, payload),
  burnSecret: (id, sessionId, sessionToken) => API.post(`/api/view/${id}/burn`, { sessionId, sessionToken }),
  heartbeat: (id, sessionId, token) => API.get(`/api/view/${id}/session/${sessionId}/heartbeat?token=${token}`),

  // Universal Packages
  createPackage: (payload) => API.post('/api/packages/create', payload),
  getPackages: () => API.get('/api/packages'),
  openPackage: (packageContent) => API.post('/api/packages/open', { packageContent }),

  // File Gateway
  importFile: (formData) => API.post('/api/files/import', formData),
  getFiles: (filter) => API.get('/api/files' + (filter ? `?classification=${filter}` : '')),
  getFileDetails: (id) => API.get(`/api/files/${id}`),
  viewFileText: (id) => API.get(`/api/files/${id}/view`),
  addFileVersion: (id, formData) => API.post(`/api/files/${id}/version`, formData),
  restoreFileVersion: (id, versionNumber) => API.post(`/api/files/${id}/restore-version`, { versionNumber }),

  // What-If Simulator
  simulateWhatIf: (policy, scenario) => API.post('/api/what-if/simulate', { policy, scenario }),
  testPolicy: (policy) => API.post('/api/what-if/test-policy', { policy }),

  // Security Lab Tests
  runBotTest: () => API.post('/api/lab/test-bot', {}),
  runConcurrencyTest: () => API.post('/api/lab/test-concurrency', {}),
  runWrongReceiverTest: () => API.post('/api/lab/test-wrong-receiver', {}),
  runTamperTest: () => API.post('/api/lab/test-tamper', {}),
  runExpiryTest: () => API.post('/api/lab/test-expiry', {}),
  runKillSwitchTest: () => API.post('/api/lab/test-kill-switch', {}),
  inspectDatabase: () => API.get('/api/lab/inspect-db')
};
