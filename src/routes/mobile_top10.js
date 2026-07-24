/**
 * OWASP Top 10 Mobile Risks (2024)
 *
 * M1: Improper Credential Usage
 * M2: Inadequate Supply Chain Security
 * M3: Insecure Authentication/Authorization
 * M4: Insufficient Input Validation
 * M5: Insecure Communication
 * M6: Inadequate Privacy Controls
 * M7: Insufficient Binary Protections
 * M8: Security Misconfiguration
 * M9: Insecure Data Storage
 * M10: Insufficient Cryptography
 *
 * Each endpoint simulates a mobile backend vulnerability
 */

const express = require('express');
const router = express.Router();

function getDb() {
  return require('../db');
}

// ==================== M1: Improper Credential Usage ====================
// Simulating mobile app that hardcodes credentials in the APK
router.post('/m1/api/login', (req, res) => {
  // M1: Mobile app embeds these credentials
  const embeddedCredentials = [
    { client: 'mobile-app', client_secret: 'hardcoded-in-apk-secret-2024', env: 'prod' },
    { api_key: 'MOBILE_SDK_KEY_PLAINTEXT_123', type: 'api' },
    { google_maps_key: 'AIzaSy1234-hardcoded-API-KEY-IN-APP', type: 'api' },
  ];

  const { client_id, client_secret } = req.body;
  // M1: Weak credential validation
  if (client_secret === 'hardcoded-in-apk-secret-2024') {
    res.json({
      authenticated: true,
      token: 'mobile-jwt-token-harcoded',
      warning: 'Credentials extracted from APK reverse engineering',
      embedded_credentials: embeddedCredentials,
      flag: 'FLAG{m1_embedded_m1_4c8d1}',
    });
  } else {
    res.json({ error: 'Invalid client credentials' });
  }
});

// ==================== M2: Insecure Supply Chain ====================
// Simulating malware injection via third-party SDK
router.get('/m2/sdk/:version', (req, res) => {
  const maliciousSDK = {
    name: 'malicious-analytics-sdk',
    version: req.params.version,
    permissions: [
      'FLAG{m2_sdk_m2_7e3b5}',
      'READ_CONTACTS',
      'ACCESS_FINE_LOCATION',
      'READ_SMS',
      'RECORD_AUDIO',
      'INSTALL_PACKAGES',
    ],
    description: 'This SDK was injected via supply chain and requests excessive permissions',
  };
  res.json(maliciousSDK);
});

// ==================== M3: Insecure Authentication ====================
// Mobile auth - biometric bypass simulation
router.get('/m3/api/profile', (req, res) => {
  const db = getDb();
  const token = req.headers.authorization || '';

  // M3: JWT with none alg or accepting any token
  try {
    const decoded = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(decoded.id || 1);
    res.json({ user });
  } catch (e) {
    res.json({ error: 'Provide any JWT in Authorization header', hint: 'No real auth' });
  }
});

// M3: OTP Bypass in mobile
router.post('/m3/api/2fa/verify', (req, res) => {
  const { user_id, otp, bypass_2fa } = req.body;

  // M3: Mobile API that allows 2FA bypass
  if (bypass_2fa === 'true' || otp === '000000') {
    res.json({
      verified: true,
      message: '2FA bypassed via API',
      flag: 'FLAG{m3_2fa_skip_m3_2b8e6}',
    });
  } else {
    res.json({ error: 'Invalid OTP' });
  }
});

// ==================== M4: Insufficient Input Validation ====================
// Mobile endpoint with no input validation
router.post('/m4/api/search', (req, res) => {
  const db = getDb();
  const { q } = req.body;

  // M4: SQL Injection from mobile input
  try {
    const query = `SELECT * FROM users WHERE username LIKE '%${q}%'`;
    const results = db.prepare(query).all();
    res.json({ results, query, hidden_flag: 'FLAG{m4_sqli_m4_5c1d9}' });
  } catch (e) {
    res.json({ error: e.message, query: e.message });
  }
});

router.post('/m4/api/download', (req, res) => {
  const { url } = req.body;
  const axios = require('axios');

  // M4: SSRF via mobile download
  axios
    .get(url)
    .then((r) => res.json({ data: r.data }))
    .catch((e) => res.json({ error: e.message }));
});

// ==================== M5: Insecure Communication ====================
// Endpoint simulating cleartext communication
router.get('/m5/api/health', (req, res) => {
  // M5: Setting headers that hint cleartext HTTP
  res.json({
    protocol: req.protocol,
    secure: req.secure,
    warning: 'This endpoint should only be called via HTTPS',
    cleartext_traffic: 'Possible for MiTM attack',
    flag: 'FLAG{m5_cleartext_m5_8a4f3}',
  });
});

// DNS rebinding via insecure mobile config
router.get('/m5/api/config', (req, res) => {
  res.json({
    allowed_hosts: ['*'],
    ssl_pinning: 'disabled',
    certificates: 'trust all (incl. self-signed)',
  });
});

// ==================== M6: Inadequate Privacy Controls ====================
router.get('/m6/api/user-data', (req, res) => {
  const db = getDb();
  // M6: Sending excessive PII to mobile
  const user = db
    .prepare('SELECT id, username, password, email, credit_card, ssn FROM users WHERE id = ?')
    .get(1);
  res.json({
    user,
    device_info: req.headers['user-agent'],
    ip: req.ip,
    location: 'tracked',
    advertising_id: 'collected',
  });
});

// ==================== M7: Insufficient Binary Protections ====================
router.get('/m7/api/debug-info', (req, res) => {
  // Debug endpoint left in prod
  res.json({
    debug: true,
    root_check: 'disabled',
    emulator_check: 'disabled',
    tampering_protection: 'removed for debug build',
    keys_obfuscation: false,
    anti_tamper: false,
  });
});

// ==================== M8: Security Misconfiguration ====================
router.get('/m8/api/admin-credentials', (req, res) => {
  // Default / test credentials that are still active
  res.json({
    admin_portal: {
      url: 'http://localhost:8080/admin',
      default_user: 'admin',
      default_password: 'admin123',
      never_changed: true,
    },
    api_keys: getDb().prepare('SELECT * FROM api_keys').all(),
    flag: 'FLAG{m8_default_m8_4b8c1}',
  });
});

// ==================== M9: Insecure Data Storage ====================
router.get('/m9/api/storage', (req, res) => {
  // M9: API designed for insecure local storage
  res.json({
    user_tokens: {
      access_token: 'eyJhbGciOiAiSFMyNTYsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYXBpIn0.x',
      refresh_token: 'should_not_be_local_db',
      expiration: Date.now() + 86400000,
    },
    storage_locations: [
      'SharedPreferences (world readable)',
      'SQLite Database (no encryption)',
      'Realm DB (default encryption)',
      'Internal Storage (/data/data (none)',
    ],
    sensitive_data: {
      credit_card: '4532-1122-3344-5566',
      pin: '1234',
      biometric: 'key-in-plain-text',
    },
  });
});

// ==================== M10: Insufficient Cryptography ====================
router.get('/m10/api/encrypt', (req, res) => {
  const crypto = require('crypto');
  const { data } = req.query;
  const key = '1234567890abcdef';
  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null);
  let encrypted = cipher.update(data || 'test', 'utf8', 'hex');
  encrypted += cipher.final('hex');

  res.json({
    algorithm: 'AES-128-ECB',
    key: key,
    key_size: 128,
    encrypted,
    warnings: [
      'ECB mode is cryptographically broken (level-1 attack)',
      'Key is hardcoded in app',
      'No key derivation function used',
    ],
    flag: 'FLAG{m10_ecb_m10_1a6b9}',
  });
});

// Mobile endpoint that allows reverse engineering to steal tokens
router.get('/m1/api/refresh-token', (req, res) => {
  res.json({
    access_token: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJyb2xlIjoiYWRtaW4iLCJ1c2VySWQiOjF9.',
    refresh_token: 'permanent_refresh_no_expiry',
    expires_in: 999999999,
  });
});

module.exports = router;
