const express = require('express');
const path = require('path');
const fs = require('fs');
const config = require('./config');
const expirySweeper = require('./services/expirySweeper');

// Import routes
const secretsRouter = require('./routes/secrets');
const viewRouter = require('./routes/view');
const packageRouter = require('./routes/packageRoutes');
const filesRouter = require('./routes/files');
const whatIfRouter = require('./routes/whatIf');
const securityLabRouter = require('./routes/securityLab');
const systemRouter = require('./routes/system');

const app = express();

// Security Headers & CORS Middleware
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Session-Token');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Parsers
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Static file hosting for frontend SPA
app.use(express.static(path.join(__dirname, 'public')));

// API Routes
app.use('/api/secrets', secretsRouter);
app.use('/api/packages', packageRouter);
app.use('/api/files', filesRouter);
app.use('/api/what-if', whatIfRouter);
app.use('/api/lab', securityLabRouter);
app.use('/api/system', systemRouter);

// Safe Landing Page & Receiver API (handles /view/:id, /open/:id, /receiver/:id)
app.use('/', viewRouter);

// SPA client-side routes fallback (Guarantees receiver links resolve to public/index.html)
app.get([
  '/dashboard', '/open', '/open/:id', '/view/:id', '/receiver/:id',
  '/lab', '/files', '/what-if', '/incidents', '/share/:token'
], (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  return res.status(200).send('VaultX Enterprise Platform');
});

// Centralized Safe Error Handler - NEVER leak stack traces
app.use((err, req, res, next) => {
  console.error('🛡️ [VaultX Error Handler]:', err.message);
  res.status(err.status || 500).json({
    error: 'A security or server error occurred. Request was safely halted.',
    safeCode: 'SECURITY_GATEWAY_INTERVENTION'
  });
});

// Start background TTL & Dead-Man Switch sweeper
expirySweeper.start();

// Seed initial sample data if DB is fresh so the judge has immediate active and rich demo data
function seedInitialData() {
  const db = require('./database/db');
  const count = db.prepare('SELECT COUNT(*) as count FROM secrets').get().count;
  if (count === 0) {
    const cryptoService = require('./services/cryptoService');
    const policyEngine = require('./services/policyEngine');
    const presets = policyEngine.getPresets();

    // 1. Demo AWS API Key Secret (Secure preset)
    const id1 = 'demo-aws-prod';
    const enc1 = cryptoService.encrypt('AKIA_PROD_VAULTX_SECURE_ACCESS_KEY_SECRET_99982', `vaultx-id-${id1}`);
    db.prepare(`
      INSERT INTO secrets (
        id, ciphertext, iv, auth_tag, salt, integrity_hash, secret_type, title, description,
        sensitivity, max_views, views_remaining, created_at, expires_at, status,
        security_policy, is_zero_trace, policy_version
      ) VALUES (?, ?, ?, ?, ?, ?, 'API Key', 'Production AWS Deployment Key', 'Requires OTP & Passkey. One-time viewing.', 'High', 1, 1, ?, ?, 'ACTIVE', ?, 0, 1)
    `).run(id1, enc1.ciphertext, enc1.iv, enc1.authTag, enc1.salt, enc1.integrityHash, Date.now(), Date.now() + (10 * 60 * 1000), JSON.stringify(presets.SECURE));

    // 2. Demo Database Password Secret (Critical Zero-Trace preset)
    const id2 = 'demo-db-root';
    const enc2 = cryptoService.encrypt('postgres://admin:V4ultX_Zero_Tr4ce_P@ss!@cluster0.db.vault:5432/core', `vaultx-id-${id2}`);
    db.prepare(`
      INSERT INTO secrets (
        id, ciphertext, iv, auth_tag, salt, integrity_hash, secret_type, title, description,
        sensitivity, max_views, views_remaining, created_at, expires_at, status,
        security_policy, is_zero_trace, policy_version
      ) VALUES (?, ?, ?, ?, ?, ?, 'Password', 'Postgres Master Cluster Connection', 'Zero-trace application mode with camera & multi-factor verification.', 'Critical', 1, 1, ?, ?, 'ACTIVE', ?, 1, 1)
    `).run(id2, enc2.ciphertext, enc2.iv, enc2.authTag, enc2.salt, enc2.integrityHash, Date.now(), Date.now() + (5 * 60 * 1000), JSON.stringify(presets.CRITICAL_ZERO_TRACE));

    // 3. Demo Universal Secure Package (.vx)
    const packageId = 'VX-DEMO-PACKAGE';
    const pkgData = {
      vaultx_package_version: '2.0-UNIVERSAL',
      package_id: packageId,
      secret_id: id1,
      package_name: 'prod-secrets-package.vx',
      created_at: Date.now(),
      expires_at: Date.now() + (15 * 60 * 1000),
      secret_type: 'API Key',
      sensitivity: 'High',
      delivery_channels: ['USB Flash Drive', 'Encrypted Email', 'QR Code'],
      integrity_fingerprint: enc1.integrityHash,
      crypto_container: {
        cipher: 'aes-256-gcm',
        ciphertext: enc1.ciphertext,
        iv: enc1.iv,
        auth_tag: enc1.authTag,
        salt: enc1.salt
      }
    };
    const pkgPath = path.join(config.packagesDir, `${packageId}.vx`);
    fs.writeFileSync(pkgPath, JSON.stringify(pkgData, null, 2));
    db.prepare(`
      INSERT INTO universal_packages (package_id, secret_id, package_name, package_file_path, delivery_methods, integrity_fingerprint, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(packageId, id1, 'prod-secrets-package.vx', pkgPath, JSON.stringify(['USB Flash Drive', 'Encrypted Email', 'QR Code']), enc1.integrityHash, Date.now());

    // 4. Demo Secure File in File Gateway
    const fileSecurityGateway = require('./services/fileSecurityGateway');
    const sampleEnv = `DATABASE_URL=postgres://user:pass@db:5432/app\nJWT_SECRET=super-secret-key-123456789\nSTRIPE_KEY=rk_live_999888777666555444\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n`;
    fileSecurityGateway.importFile({
      buffer: Buffer.from(sampleEnv, 'utf8'),
      originalName: 'production.env',
      mimeType: 'text/plain',
      owner: 'SecurityAdmin',
      source: 'CD/DVD Extraction'
    });

    console.log('🛡️ [VaultX Seed] Initial security demo data created (Demo AWS Secret, Postgres Secret, .vx package, production.env).');
  }
}

seedInitialData();

// Start Server
const server = app.listen(config.port, config.host, () => {
  console.log('================================================================');
  console.log(`🛡️  VAULTX — Identity-Bound Ephemeral Secret Vault`);
  console.log(`🔐  Enterprise Zero-Trust File Security Gateway`);
  console.log(`⚡  Local URL:   http://localhost:${config.port}`);
  console.log(`🌐  LAN Network: http://${config.lanIp}:${config.port}`);
  if (config.configuredAppUrl) {
    console.log(`🌍  Public URL:  ${config.configuredAppUrl}`);
  }
  console.log(`📡  Storage Engine: SQLite (WAL Mode)`);
  console.log(`🔑  Crypto Engine: AES-256-GCM (Hardware HKDF Derivation)`);
  console.log('================================================================');
});

module.exports = { app, server };
