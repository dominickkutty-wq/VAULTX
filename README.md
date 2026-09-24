# VaultX — Identity-Bound Ephemeral Secret Vault & Zero-Trust File Security Gateway

> **"Store Anywhere. Transfer Anywhere. Open Only With Authorization."**

VaultX is an enterprise-grade cybersecurity platform built to eliminate permanent plaintext secret exposure across modern chat apps (Slack, Teams, Discord), emails, file transfers, and physical storage media (USB flash drives, SD cards, external HDDs, CD/DVDs).

---

## 🛡️ Core Security Architecture & Non-Negotiable Guarantees

1. **Hardware-Accelerated AES-256-GCM Encryption**:
   - Every secret is encrypted using **AES-256-GCM** with a **unique cryptographically random 12-byte IV** and a **16-byte authentication tag**.
   - Derived subkeys are calculated per secret via **HKDF-SHA256** using unique random salts.
   - Master Key is loaded **strictly from environment variables** (`VAULTX_MASTER_KEY`) and **NEVER stored in the database or written to disk**.
   - **Zero Plaintext at Rest**: SQLite database contains only ciphertext, IVs, authentication tags, and salts.

2. **Atomic One-Time Destruction & Concurrency Protection**:
   - `POST /api/view/:id/burn` executes inside a **synchronous atomic SQLite transaction** in WAL mode.
   - When 20 simultaneous requests target a single-use secret (`max_views = 1`), **exactly 1 request succeeds with HTTP 200 + decrypted payload**, while **19 requests are blocked with HTTP 404**.
   - Double-read race conditions are mathematically prevented at the storage engine level.

3. **Scraper & Bot Shield**:
   - Automatic detection of link-expanding crawlers (Slackbot, Discordbot, Twitterbot, facebookexternalhit, spiders).
   - `GET /view/:id` returns safe landing metadata only. Automated crawlers **never decrypt or burn secrets**.
   - Decryption requires explicit, consent-based human interaction.

4. **Sender Security Policy Builder & Receiver Identity Binding**:
   - Senders can bind secrets to specific receiver emails, requiring multi-factor verification:
     - 6-digit Email OTP
     - Hardware FIDO2 Passkey / WebAuthn biometrics
     - Live Camera & Liveness Verification (with visible recording indicator and immediate evidence purge)
     - Custom verification passphrases
   - Viewing session countdown timer (30s, 45s, 60s, custom) with auto-blur on browser focus loss and auto-burn upon expiration.

5. **Universal Secure Package (`.vx`) & Multi-Channel Delivery**:
   - Export secrets as encrypted standalone `.vx` containers for physical transfer (USB pen drives, external SSDs, SD cards, CD/DVDs, NFC).
   - "Store anywhere, open securely": The transfer medium is NOT the security boundary. Opening `.vx` requires connecting to the VaultX policy engine for identity authorization.

6. **Zero-Trust File Security Gateway**:
   - Universal secure import from local folders, USB flash drives, CD/DVD extraction, Telegram/Email exports.
   - Deep regex scanning for sensitive patterns (Payment Cards, SSNs / National IDs, API Keys, Private Certificates, Bank Account numbers).
   - Automatic classification: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `HIGHLY_CONFIDENTIAL`.
   - File versioning (v1, v2, restore version) with SHA-256 tamper verification.
   - Emergency Vault Lock (`🔒 LOCK VAULT`) restricting all sensitive operations.

7. **Next-Gen Innovation Layer**:
   - **Secret Fragmentation Engine**: Splits sensitive payloads into independently encrypted fragments in memory.
   - **Dual-Consent Mode**: Secret reveal remains locked until sender explicitly approves pending access.
   - **Dead-Man Switch**: Automatically destroys secrets if the sender fails to check in within configured interval.
   - **What-If Security Simulator**: Interactive simulator testing scenarios against the real policy engine.
   - **Security Lab for Judges**: Live executable test suite (Bot attack, 20 concurrent requests, tampering, DB inspection).
   - **Canary / Decoy Secrets**: Synthetic credentials that trigger critical alerts when accessed.
   - **Application-Level Zero-Trace Mode**: Guarantees zero plaintext in DB, logs, and telemetry.

---

## 🚀 Quick Start Guide

### 1. Requirements
- Node.js v18+ (tested on Node.js v26.3.0)
- npm / npm.cmd

### 2. Installation
```bash
# Dependencies already installed: express, better-sqlite3, multer, qrcode
npm install
```

### 3. Start VaultX Server
```bash
npm start
# or: node server.js
```
The server starts at `http://localhost:3000`.

### 4. Run Automated Security Test Suite
```bash
npm test
# or: node tests/security-tests.js
```
Expected output:
```
=============================================================
  VAULTX COMPREHENSIVE SECURITY VERIFICATION SUITE
=============================================================
  ✅ [PASS] AES-256-GCM Encryption with unique IV, salt & Auth Tag
  ✅ [PASS] Tampered Ciphertext or Auth Tag Fails Decryption Safely
  ✅ [PASS] 20 Concurrent Requests on 1-View Secret: Exactly 1x 200, 19x 404
  ✅ [PASS] Scraper Bot Request Does NOT Decrypt or Burn Secret
  ✅ [PASS] Background Sweeper Purges Expired Secrets
  ✅ [PASS] Identity Binding: Wrong Receiver Blocked (403), Correct Receiver Allowed
  ✅ [PASS] Secret Fragmentation: Independent Encrypted Fragments Reconstructed in Memory
  ✅ [PASS] File Security Gateway: Import, Sensitive Data Pattern Scan, Encryption & Versioning
  ✅ [PASS] Application-Level Zero-Trace: Zero Plaintext in Database or Logs
=============================================================
  TEST RESULTS: 9 / 9 PASSED (100% SUCCESS)
=============================================================
```

---

## 💻 VaultX CLI Tool

VaultX includes a secure command-line tool supporting piped stdin and automated workflows:

```bash
# Show CLI Help
node cli/vault-cli.js --help

# Create a secure secret
node cli/vault-cli.js create "MyConfidentialApiKey123"

# Pipe secret via STDIN (e.g. from bash/powershell)
echo "DatabaseRootPassword99!" | node cli/vault-cli.js pipe

# Check server health and sweeper status
node cli/vault-cli.js health

# View operational stats
node cli/vault-cli.js stats
```

---

## 🔬 Judge Demonstration & Verification (Security Lab)

Open `http://localhost:3000` in any browser and navigate to **Security Lab**:

1. **Test 01 — Scraper / Bot Defense**:
   - Click `Run Bot Attack Simulation`.
   - Result: Simulates `User-Agent: Slackbot-LinkExpanding 1.0`. Proves bot gets safe preview while views remaining stays 1/1 without burning.

2. **Test 02 — 20 Concurrent Requests (Double-Read Prevention)**:
   - Click `Run 20 Concurrent Requests Test`.
   - Result: Fires 20 simultaneous threads. Exactly **1 request succeeds with 200**, and **19 requests are safely blocked with 404**.

3. **Test 03 — Identity Binding / Wrong Receiver**:
   - Proves unauthorized email receives `403 Forbidden` while secret remains intact.

4. **Test 04 — Cryptographic Tamper Protection**:
   - Modifies 1 byte in stored ciphertext. Proves AES-256-GCM authentication tag fails cleanly with zero plaintext leakage.

5. **Test 05 — Automatic Expiry Sweeper**:
   - Verifies the 10-second background worker purges expired records from disk.

6. **Inspect Database (Proof of Zero Plaintext)**:
   - Click `Inspect Database` to examine raw SQLite table rows. Shows only AES-256-GCM `ciphertext`, `iv`, `auth_tag`, and `salt`.

---

## 📂 Project Structure

```
d:\#9 RAALE\
├── server.js                        # Express server entrypoint & background worker init
├── package.json
├── .env.example
├── config/
│   └── index.js                     # 256-bit Master Key & runtime configuration
├── database/
│   └── db.js                        # SQLite connection, WAL mode, schema & indexes
├── services/
│   ├── cryptoService.js             # AES-256-GCM, HKDF subkeys, SHA-256 fingerprints
│   ├── fragmentationService.js      # Encrypted secret payload fragmentation (A, B, C)
│   ├── policyEngine.js              # Centralized policy validator & simulator
│   ├── riskEngine.js                # Anomaly detection & risk scoring (Low, Med, High)
│   ├── sessionManager.js            # Short-lived viewing sessions & heartbeats
│   ├── expirySweeper.js             # Background worker running every 10s
│   ├── fileSecurityGateway.js       # File import, regex scanner, versioning & encryption
│   ├── incidentCorrelator.js        # Consolidates security signals into incidents
│   ├── auditLogger.js               # Privacy-safe audit ledger & destruction proofs
│   └── canaryService.js             # Synthetic canary credentials & intrusion traps
├── routes/
│   ├── secrets.js                   # /api/secrets (create, list, receipts, kill-switch)
│   ├── view.js                      # /view/:id (safe landing, verification, atomic burn)
│   ├── packageRoutes.js             # /api/packages (.vx export, open, and download)
│   ├── files.js                     # /api/files (import, secure viewer, versions)
│   ├── whatIf.js                    # /api/what-if (simulator & policy testing)
│   ├── securityLab.js               # /api/lab (live executable judge test suite)
│   └── system.js                    # /api/system (stats, lock vault, incidents, canaries)
├── cli/
│   └── vault-cli.js                 # Terminal CLI for automated workflows & stdin
├── tests/
│   └── security-tests.js            # Automated security test suite (9 / 9 passing)
└── public/
    ├── index.html                   # Master SPA interface
    ├── css/
    │   └── styles.css               # Obsidian & Cyber Cyan enterprise design system
    └── js/
        ├── app.js                   # SPA router and modal controller
        ├── utils/
        │   └── api.js               # Frontend API client
        └── components/
            ├── dashboard.js         # Security Operations Center & pipeline visualizer
            ├── createSecret.js      # Policy builder, presets, coverage score, QR modal
            ├── activeSecrets.js     # Active secrets ledger, receipts, kill switch
            ├── receiverView.js      # Safe landing, camera verification, atomic burn
            ├── universalDelivery.js # Multi-channel hub (digital & physical storage)
            ├── openPackage.js       # Drag-and-drop .vx package inspector
            ├── fileGateway.js       # Zero-trust file import, viewer, and versioning
            ├── whatIfSimulator.js   # What-if threat modeling simulator
            ├── securityLab.js       # Live judge test execution cards
            └── incidents.js         # Audit ledger, incidents, and canaries
```

---

## 🏆 Hackathon Compliance Checklist

| Requirement | Status | Verification |
| :--- | :---: | :--- |
| **AES-256-GCM Encryption** | ✅ Complete | Verified in `cryptoService.js` and `npm test` |
| **Unique IV & Auth Tag** | ✅ Complete | Unique 12-byte IV per secret, 16-byte auth tag |
| **Master Key Not in DB** | ✅ Complete | Loaded strictly from env/RAM, never stored |
| **Zero Plaintext at Rest** | ✅ Complete | Verified via DB Inspector & `npm test` |
| **Safe Landing Page** | ✅ Complete | `GET /view/:id` serves safe HTML without burning |
| **Scraper / Bot Defense** | ✅ Complete | Verified with Slackbot User-Agent simulation |
| **Atomic Concurrency Protection** | ✅ Complete | 20 parallel requests: exactly 1x 200, 19x 404 |
| **Automatic Expiry Sweeper** | ✅ Complete | Background worker sweeps every 10 seconds |
| **Sender Policy Builder** | ✅ Complete | Presets, OTP, Passkeys, Camera, Auto-blur, Timers |
| **Receiver Verification** | ✅ Complete | Email OTP, Passkey, Camera Liveness with consent |
| **Universal `.vx` Packages** | ✅ Complete | "Store Anywhere, Open Securely" format |
| **Zero-Trust File Gateway** | ✅ Complete | Import, regex pattern scanner, versioning, AES-256 |
| **What-If Simulator** | ✅ Complete | 9 real interactive policy simulation scenarios |
| **Dual-Consent Authorization** | ✅ Complete | Reveal locked until sender approves pending request |
| **Dead-Man Switch** | ✅ Complete | Auto-destructs if sender fails to confirm check-in |
| **Secret Fragmentation** | ✅ Complete | Splits into encrypted fragments A, B, C in memory |
| **Security Lab Demo** | ✅ Complete | 6 live executable judge test cards in the UI |
| **CLI Utility** | ✅ Complete | `node cli/vault-cli.js create "secret"` works |
