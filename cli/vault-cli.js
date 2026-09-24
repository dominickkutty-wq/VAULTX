#!/usr/bin/env node
const http = require('http');
const readline = require('readline');

const API_HOST = process.env.VAULTX_HOST || 'localhost';
const API_PORT = process.env.VAULTX_PORT || 3000;

function printHelp() {
  console.log(`
=============================================================
  VAULTX — Identity-Bound Ephemeral Secret Vault CLI
=============================================================
Usage:
  node cli/vault-cli.js [command] [options]

Commands:
  create [secret]     Create an ephemeral encrypted secret
  pipe                Read secret from STDIN and create secret
  health              Check VaultX server health status
  stats               Display operational metrics
  --help, -h          Show this help manual

Examples:
  node cli/vault-cli.js create "SuperSecretApiKey123"
  echo "MyDbPassword" | node cli/vault-cli.js pipe
  node cli/vault-cli.js create "API_KEY_999" --ttl 5 --views 1 --type "API Key"
=============================================================
`);
}

function makeRequest(method, path, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = http.request({
      hostname: API_HOST,
      port: API_PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
      }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ status: res.statusCode, data: json });
        } catch (e) {
          resolve({ status: res.statusCode, data });
        }
      });
    });

    req.on('error', err => reject(err));
    if (payload) req.write(payload);
    req.end();
  });
}

async function handleCreate(secretText, opts = {}) {
  if (!secretText || secretText.trim().length === 0) {
    console.error('❌ Error: Secret content cannot be empty.');
    process.exit(1);
  }

  console.log('🛡️  Encrypting secret with AES-256-GCM...');
  try {
    const res = await makeRequest('POST', '/api/secrets', {
      secret: secretText.trim(),
      secretType: opts.type || 'Custom Secret',
      title: opts.title || 'CLI Ephemeral Secret',
      sensitivity: opts.sensitivity || 'High',
      policy: {
        viewing: {
          maxViews: Number(opts.views || 1),
          expiryMinutes: Number(opts.ttl || 10),
          viewingDurationSeconds: 60
        },
        protection: {
          disableCopy: true,
          scraperShield: true
        }
      }
    });

    if (res.status === 201) {
      console.log('\n=============================================================');
      console.log('✅ SECURE SECRET CREATED SUCCESSFULLY');
      console.log('=============================================================');
      console.log(`Secret ID:        ${res.data.id}`);
      console.log(`Access URL:       ${res.data.viewUrl}`);
      console.log(`Integrity SHA256: ${res.data.integrityHash}`);
      console.log(`Max Views:        ${res.data.maxViews}`);
      console.log(`Expires At:       ${new Date(res.data.expiresAt).toLocaleTimeString()}`);
      console.log(`Coverage Score:   ${res.data.coverageScore}`);
      console.log('=============================================================\n');
      console.log('Notice: Secret plaintext was NOT stored or logged in database.');
    } else {
      console.error(`❌ Server Error (${res.status}):`, res.data.error || res.data);
    }
  } catch (err) {
    console.error('❌ Connection failed. Ensure VaultX server is running on port 3000:', err.message);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || '--help';

  if (command === '--help' || command === '-h') {
    printHelp();
    return;
  }

  if (command === 'health') {
    try {
      const res = await makeRequest('GET', '/api/system/health');
      console.log('VaultX Server Health:', res.data);
    } catch (e) {
      console.error('Cannot reach server:', e.message);
    }
    return;
  }

  if (command === 'stats') {
    try {
      const res = await makeRequest('GET', '/api/system/stats');
      console.log('VaultX Operational Statistics:', res.data);
    } catch (e) {
      console.error('Cannot reach server:', e.message);
    }
    return;
  }

  if (command === 'pipe') {
    let input = '';
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    rl.on('line', line => input += line + '\n');
    rl.on('close', async () => {
      await handleCreate(input.trim());
    });
    return;
  }

  if (command === 'create') {
    const secret = args[1];
    await handleCreate(secret);
    return;
  }

  // Fallback: if user ran `echo "secret" | node cli/vault-cli.js`
  if (!process.stdin.isTTY) {
    let input = '';
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    rl.on('line', line => input += line + '\n');
    rl.on('close', async () => {
      await handleCreate(input.trim());
    });
    return;
  }

  printHelp();
}

main();
