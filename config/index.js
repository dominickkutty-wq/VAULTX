const crypto = require('crypto');
const path = require('path');
const os = require('os');

// Master Encryption Key - loaded from environment variable, NEVER stored in the database
let masterKey = process.env.VAULTX_MASTER_KEY;

if (!masterKey) {
  // Generate an ephemeral 32-byte key for development/hackathon session
  masterKey = crypto.randomBytes(32).toString('hex');
  console.log('🛡️ [VaultX Config] Notice: VAULTX_MASTER_KEY not set in environment.');
  console.log('🛡️ [VaultX Config] Generated ephemeral 256-bit Master Key in memory (never written to DB).');
} else if (masterKey.length === 64) {
  // Hex-encoded 32-byte key
} else {
  // Hash to ensure exact 32 bytes (256 bits)
  masterKey = crypto.createHash('sha256').update(masterKey).digest('hex');
}

// Helper to determine the local LAN IPv4 address (for multi-device / mobile testing on same Wi-Fi)
function getLanIpAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal (127.0.0.1) and non-ipv4 addresses
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

const lanIp = getLanIpAddress();
const port = parseInt(process.env.PORT || '3000', 10);
const configuredAppUrl = process.env.APP_URL || process.env.PUBLIC_APP_URL || process.env.VAULTX_APP_URL || null;

const config = {
  port,
  host: process.env.HOST || '0.0.0.0', // Listen on all network interfaces for LAN access
  lanIp,
  configuredAppUrl,
  masterKeyHex: masterKey,
  masterKeyBuffer: Buffer.from(masterKey, 'hex'),
  dbPath: process.env.VAULTX_DB_PATH || path.join(__dirname, '..', 'data', 'vaultx.db'),
  sweeperIntervalMs: 10000, // 10 seconds for rapid cleanup
  defaultExpirySeconds: 600, // 10 minutes default
  maxViewsDefault: 1,
  appLevelZeroTrace: true,
  uploadsDir: path.join(__dirname, '..', 'data', 'encrypted_vault_files'),
  packagesDir: path.join(__dirname, '..', 'data', 'packages'),

  /**
   * Dynamically resolves the base URL for receiver links:
   * 1. Uses explicit APP_URL / PUBLIC_APP_URL if provided in environment
   * 2. Uses incoming request host/proto if available
   * 3. Falls back to localhost / LAN IP
   */
  resolveBaseUrl(req) {
    if (configuredAppUrl) {
      return configuredAppUrl.replace(/\/+$/, '');
    }
    if (req) {
      const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
      const host = req.headers['x-forwarded-host'] || req.get('host');
      if (host) {
        return `${proto}://${host}`;
      }
    }
    return `http://localhost:${port}`;
  },

  getLanBaseUrl() {
    return `http://${lanIp}:${port}`;
  },

  getLocalBaseUrl() {
    return `http://localhost:${port}`;
  }
};

module.exports = config;
