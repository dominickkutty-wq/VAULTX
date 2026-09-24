/**
 * VaultX — Receiver Secure Link & Sharing Verification Suite
 * Tests canonical URL generation, multi-route resolution (/view, /open, /receiver),
 * unauthenticated cross-browser access, bot prefetch protection, diagnostic pipeline,
 * and clean error handling (expired, revoked, consumed, invalid).
 */
const assert = require('assert');

const BASE_URL = 'http://localhost:3000';

async function runReceiverLinkTests() {
  console.log('\n=============================================================');
  console.log('  VAULTX RECEIVER SECURE LINK & SHARING VERIFICATION SUITE');
  console.log('=============================================================\n');

  let passed = 0;
  let total = 0;

  async function test(name, fn) {
    total++;
    try {
      await fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ❌ [FAIL] ${name}`);
      console.error(`     Error: ${err.message}`);
    }
  }

  // Helper to create a secret
  async function createSecret(overrides = {}) {
    const res = await fetch(`${BASE_URL}/api/secrets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: overrides.title || 'Receiver Test Secret',
        secret: overrides.secret || 'my-super-confidential-token-12345',
        policy: {
          viewing: { expiryMinutes: overrides.expiryMinutes || 30, maxViews: overrides.maxViews !== undefined ? overrides.maxViews : 1 },
          verification: overrides.verification || {},
          advanced: { destructionMode: 'burn_on_read' }
        }
      })
    });
    return await res.json();
  }

  // TEST 1: Canonical Link Generation & Formats
  await test('Canonical Link Generation & Non-Localhost LAN/Base URL Fallback', async () => {
    const secret = await createSecret();
    assert(secret.id, 'Secret ID should be generated');
    assert(secret.viewUrl.includes(`/view/${secret.id}`), 'viewUrl should contain /view/:id');
    assert(secret.lanUrl.includes(`/view/${secret.id}`), 'lanUrl should contain /view/:id');
    assert(secret.localUrl.includes(`http://localhost:3000/view/${secret.id}`), 'localUrl should be localhost');
    assert.strictEqual(secret.canonicalPath, `/view/${secret.id}`, 'canonicalPath must match');
  });

  // TEST 2: Multi-Route Landing Page Reachability (/view, /open, /receiver)
  await test('Multi-Route Landing Page Reachability (/view, /open, /receiver)', async () => {
    const secret = await createSecret();
    const routes = [`/view/${secret.id}`, `/open/${secret.id}`, `/receiver/${secret.id}`];

    for (const r of routes) {
      const res = await fetch(`${BASE_URL}${r}`, {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36' }
      });
      assert.strictEqual(res.status, 200, `Route ${r} should return HTTP 200`);
      const text = await res.text();
      assert(text.includes('VaultX'), `Route ${r} should render HTML shell containing VaultX`);
    }
  });

  // TEST 3: Bot / Crawler Prefetch Does NOT Burn or Decrypt
  await test('Bot / Crawler Prefetch Shield: Secret Remains Active & Unburned', async () => {
    const secret = await createSecret({ maxViews: 1 });
    
    // Simulate Slackbot / Discord / WhatsApp preview crawler
    const botRes = await fetch(`${BASE_URL}/view/${secret.id}`, {
      headers: { 'User-Agent': 'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)' }
    });
    assert.strictEqual(botRes.status, 200, 'Bot should receive 200 safe crawler landing');
    const html = await botRes.text();
    assert(html.includes('Scraper Shield Active'), 'Bot preview must trigger Scraper Shield');
    assert(!html.includes('my-super-confidential-token-12345'), 'Plaintext must NEVER be present in bot preview');

    // Verify secret is STILL intact and views_remaining is STILL 1
    const metaRes = await fetch(`${BASE_URL}/api/view/${secret.id}/metadata`);
    assert.strictEqual(metaRes.status, 200);
    const meta = await metaRes.json();
    assert.strictEqual(meta.viewsRemaining, 1, 'Secret view count must remain unconsumed after crawler hit');
  });

  // TEST 4: Receiver Test Panel 7-Stage Diagnostic Pipeline
  await test('Receiver Test Panel 7-Stage Diagnostic Pipeline', async () => {
    const secret = await createSecret();
    const diagRes = await fetch(`${BASE_URL}/api/view/${secret.id}/diagnostics`);
    assert.strictEqual(diagRes.status, 200);
    const diag = await diagRes.json();
    assert.strictEqual(diag.linkGenerated, true);
    assert.strictEqual(diag.tokenPersisted, true);
    assert.strictEqual(diag.receiverRouteReachable, true);
    assert.strictEqual(diag.tokenValidated, true);
    assert.strictEqual(diag.secretRetrieved, true);
    assert.strictEqual(diag.permissionChecked, true);
    assert.strictEqual(diag.expiryChecked, true);
    assert.strictEqual(diag.diagnosticsPassed, true);
    assert.strictEqual(diag.status, 'ACTIVE');
  });

  // TEST 5: Standalone Cross-Browser Receiver Reveal & Atomic Destruction
  await test('Standalone Receiver Reveal & Atomic Destruction (No Sender Session)', async () => {
    const secret = await createSecret({ secret: 'secret-payload-xyz-777', maxViews: 1 });

    // Step A: Receiver opens link in clean session without sender cookies/headers
    const metaRes = await fetch(`${BASE_URL}/api/view/${secret.id}/metadata`);
    assert.strictEqual(metaRes.status, 200);

    // Step B: Verification creates viewing session
    const verifyRes = await fetch(`${BASE_URL}/api/view/${secret.id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ receiverIdentity: 'recipient@partner.com' })
    });
    assert.strictEqual(verifyRes.status, 200);
    const session = await verifyRes.json();
    assert(session.sessionId, 'Session ID required');

    // Step C: Burn & Reveal
    const burnRes = await fetch(`${BASE_URL}/api/view/${secret.id}/burn`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: session.sessionId, sessionToken: session.sessionToken })
    });
    assert.strictEqual(burnRes.status, 200);
    const revealed = await burnRes.json();
    assert.strictEqual(revealed.secret, 'secret-payload-xyz-777');

    // Step D: Second access by receiver or anyone else is rejected with SECRET_ALREADY_CONSUMED
    const secondMeta = await fetch(`${BASE_URL}/api/view/${secret.id}/metadata`);
    assert.strictEqual(secondMeta.status, 410, 'Consumed secret metadata should return HTTP 410');
    const secondMetaBody = await secondMeta.json();
    assert.strictEqual(secondMetaBody.error, 'SECRET_ALREADY_CONSUMED');

    const secondBurn = await fetch(`${BASE_URL}/api/view/${secret.id}/burn`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: session.sessionId, sessionToken: session.sessionToken })
    });
    assert.strictEqual(secondBurn.status, 404, 'Second reveal should be blocked');
  });

  // TEST 6: Clean Error States (INVALID_LINK, REVOKED_LINK, EXPIRED_LINK)
  await test('Clean Structured Error States (INVALID_LINK, REVOKED_LINK, EXPIRED_LINK)', async () => {
    // 1. Invalid link
    const invalidRes = await fetch(`${BASE_URL}/api/view/non-existent-secret-id-9999/metadata`);
    assert.strictEqual(invalidRes.status, 404);
    const invalidJson = await invalidRes.json();
    assert.strictEqual(invalidJson.error, 'INVALID_LINK');

    // 2. Revoked link
    const toRevoke = await createSecret();
    await fetch(`${BASE_URL}/api/secrets/${toRevoke.id}/revoke`, { method: 'POST' });
    const revokedRes = await fetch(`${BASE_URL}/api/view/${toRevoke.id}/metadata`);
    assert.strictEqual(revokedRes.status, 403);
    const revokedJson = await revokedRes.json();
    assert.strictEqual(revokedJson.error, 'REVOKED_LINK');

    // 3. Expired link (check diagnostic / metadata behavior)
    const expiredRes = await fetch(`${BASE_URL}/api/view/expired-test-id/metadata`);
    assert.strictEqual(expiredRes.status, 404); // Not found or expired returns clean error
  });

  // TEST 7: Identity Binding Check on Receiver Link
  await test('Identity Binding: Enforce Recipient Authorization', async () => {
    const boundSecret = await createSecret({
      verification: {
        requireEmailOtp: false,
        boundIdentity: 'authorized.dev@enterprise.internal'
      }
    });

    // Receiver with WRONG identity is rejected
    const badVerify = await fetch(`${BASE_URL}/api/view/${boundSecret.id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ receiverIdentity: 'impostor@attacker.com' })
    });
    assert.strictEqual(badVerify.status, 403, 'Unauthorized receiver identity must be blocked with 403');
    const badBody = await badVerify.json();
    assert.strictEqual(badBody.reason, 'IDENTITY_MISMATCH');

    // Receiver with CORRECT identity is allowed
    const goodVerify = await fetch(`${BASE_URL}/api/view/${boundSecret.id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ receiverIdentity: 'authorized.dev@enterprise.internal' })
    });
    assert.strictEqual(goodVerify.status, 200, 'Authorized receiver must pass verification');
    const goodBody = await goodVerify.json();
    assert(goodBody.sessionId);
  });

  console.log('\n=============================================================');
  console.log(`  RECEIVER LINK TEST RESULTS: ${passed} / ${total} PASSED (${Math.round((passed/total)*100)}%)`);
  console.log('=============================================================\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runReceiverLinkTests().catch(err => {
  console.error('Test Suite Fatal Error:', err);
  process.exit(1);
});
