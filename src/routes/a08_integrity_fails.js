/**
 * A08:2021 – Software and Data Integrity Failures
 *
 * Vulnerabilities demonstrated:
 * - Unsafe deserialization
 * - Unverified updates
 * - CI/CD pipeline abuse
 * - Missing integrity checks on libraries
 * - Unsigned data acceptance
 * - Auto-update without verification
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { safeWrite, safePath, safeEval } = require('../utils/safe-guard');

function getDb() {
  return require('../db');
}

router.get('/', (req, res) => {
  res.render('integrity_fails/index', { title: 'A08 - Integrity Failures' });
});

// Unsafe deserialization with JS eval
router.post('/deserialize', (req, res) => {
  const { data } = req.body;
  try {
    // A08: Deserialization without validation (sandboxed when AIVAULT_SAFE_MODE=1)
    const r = safeEval(data, 'serialize');
    if (r.simulated) return res.json({ result: r });
    const deserialized = new Function('return ' + data)();
    res.json({ result: deserialized });
  } catch (e) {
    res.json({ error: e.message, hint: 'Try: {"constructor": {"prototype": {"isAdmin": true}}}' });
  }
});

// Unverified plugin/update - fetch and apply remote code
router.get('/install-update', (req, res) => {
  const { url } = req.query;
  const axios = require('axios');

  if (url) {
    // A08: No checksum/signature verification of remote update
    axios
      .get(url)
      .then((response) => {
        const updateData = response.data;
        res.json({
          installed: true,
          version: updateData.version || 'unknown',
          description: updateData.description,
          warning: 'Update installed without signature verification',
        });
      })
      .catch((e) => res.json({ error: e.message }));
  } else {
    res.json({ message: 'Provide ?url= to install update' });
  }
});

// Unvalidated redirect to external sites
router.get('/download-plugin', (req, res) => {
  const { plugin } = req.query;
  const pluginDir = path.join(__dirname, '..', '..', 'challenges', 'plugins');

  // A08: No integrity check on downloaded plugin (sandboxed when AIVAULT_SAFE_MODE=1)
  try {
    if (!fs.existsSync(pluginDir)) fs.mkdirSync(pluginDir, { recursive: true });
    const pluginContent = `// Plugin: ${plugin}\n// No signature verification\nmodule.exports = function() { console.log('Plugin loaded'); }`;
    const w = safeWrite(path.join(pluginDir, `${plugin}.js`), pluginContent);
    if (w.simulated) {
      return res.json({
        success: true,
        simulated: true,
        nonce: crypto.randomBytes(16).toString('hex'),
        note: w.note,
      });
    }
    const pluginCode = require(path.join(pluginDir, plugin));
    res.json({ success: true, nonce: crypto.randomBytes(16).toString('hex') });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// JWT signature verification bypass
router.get('/jwt-verify', (req, res) => {
  const jwt = require('jsonwebtoken');
  const token = req.query.token;

  try {
    // A08: Accepts signature-less JWT
    const decoded = jwt.decode(token, { complete: true });
    if (decoded && decoded.header.alg === 'none') {
      res.json({
        verified: true,
        payload: decoded.payload,
        algorithm: 'none',
        flag: 'FLAG{jwt_none_a08_3d9c2}',
      });
    } else {
      // Try with 'HS256' first, then none
      try {
        const verified = jwt.verify(token, 'weak-secret', { algorithms: ['HS256'] });
        res.json({ verified: true, payload: verified, algorithm: 'HS256' });
      } catch (e) {
        try {
          const verified = jwt.verify(token, '', { algorithms: ['none'] });
          res.json({ verified: true, payload: verified, algorithm: 'none' });
        } catch (ee) {
          res.json({ verified: false, error: ee.message });
        }
      }
    }
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Pipeline injection
router.post('/ci-cd/trigger', (req, res) => {
  const { repo_url, branch, build_id } = req.body;

  // Simulated CI/CD with no integrity checks
  const buildInfo = {
    repository: repo_url,
    branch: branch || 'main',
    build_id: build_id || crypto.randomUUID(),
    status: 'BUILDING',
    warning: 'No integrity verification performed',
  };

  res.json({ build_info: buildInfo });
});

module.exports = router;
