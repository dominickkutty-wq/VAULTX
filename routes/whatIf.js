const express = require('express');
const router = express.Router();
const policyEngine = require('../services/policyEngine');

/**
 * POST /api/what-if/simulate
 * Simulates a security scenario against a given policy
 */
router.post('/simulate', (req, res) => {
  try {
    const { policy, scenario } = req.body;
    if (!scenario) {
      return res.status(400).json({ error: 'Scenario identifier required' });
    }

    const result = policyEngine.simulateScenario(policy, scenario);
    return res.json({
      success: true,
      simulation: result
    });
  } catch (err) {
    console.error('What-If simulation error:', err);
    return res.status(500).json({ error: 'Failed to simulate scenario' });
  }
});

/**
 * POST /api/what-if/test-policy
 * Runs a full test battery against a draft policy before creation
 */
router.post('/test-policy', (req, res) => {
  try {
    const { policy } = req.body;
    if (!policy) {
      return res.status(400).json({ error: 'Policy object required' });
    }

    const coverage = policyEngine.calculateConfigurationCoverage(policy);
    const scenarios = [
      'LINK_LEAKED',
      'BOT_PREVIEW',
      'NEW_DEVICE',
      'FAILED_OTP',
      'CONCURRENT_RACE',
      'TAMPERED_CIPHERTEXT',
      'EXPIRED_LINK',
      'SENDER_REVOCATION',
      'TAB_BLUR'
    ];

    const results = scenarios.map(sc => policyEngine.simulateScenario(policy, sc));

    return res.json({
      success: true,
      coverage,
      scenarioResults: results
    });
  } catch (err) {
    console.error('Test policy error:', err);
    return res.status(500).json({ error: 'Failed to run policy test battery' });
  }
});

module.exports = router;
