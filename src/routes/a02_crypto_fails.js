/**
 * A02:2021 – Cryptographic Failures
 *
 * Vulnerabilities demonstrated:
 * - Hardcoded encryption keys
 * - Use of weak/deprecated algorithms (MD5, SHA1, DES, RC4)
 * - Plaintext storage of sensitive data
 * - Missing TLS enforcement
 * - Weak password hashing
 * - Insecure key management
 * - Predictable encryption IVs
 */

const express = require('express');
const router = express.Router();
const crypto = require('crypto');

function getDb() {
  return require('../db');
}

// Hardcoded encryption keys
const HARDCODED_KEY = 'my-secret-key-123';
const HARDCODED_IV = '1234567890123456';

// A02: Hardcoded API key / secrets
const ADMIN_API_KEY = 'sk-admin-secret-key-hardcoded';

// Weak MD5 password hashing
function weakHash(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// A02: Weak SHA1 hashing
function sha1Hash(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// A02: Predictable encryption - ECB mode with fixed key and IV (insecure)
function encryptECB(plaintext) {
  const keyBuffer = crypto.createHash('sha256').update(HARDCODED_KEY).digest(); // 32-byte key for aes-256
  const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

function decryptECB(encrypted) {
  const keyBuffer = crypto.createHash('sha256').update(HARDCODED_KEY).digest();
  const decipher = crypto.createDecipheriv('aes-256-ecb', keyBuffer, null);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// A02: Hardcoded JWT with weak secret
router.get('/jwt/generate', (req, res) => {
  const jwt = require('jsonwebtoken');
  const payload = { username: req.query.username || 'admin', role: req.query.role || 'admin' };
  // Relying on user-supplied data without validation
  const token = jwt.sign(payload, 'weak-jwt-secret', { algorithm: 'HS256' });
  res.json({ token });
});

router.get('/jwt/debug', (req, res) => {
  const jwt = require('jsonwebtoken');
  const token = req.query.token || '';
  try {
    // A02: Allows none algorithm attack - accepts alg:none
    const decoded = jwt.decode(token, { complete: true });
    let verified;
    if (decoded && decoded.header.alg === 'none') {
      verified = decoded.payload;
    } else {
      verified = jwt.verify(token, 'weak-jwt-secret', { algorithms: ['HS256', 'none'] });
    }
    res.json({ decoded: decoded, verified: verified });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// A02: Expose all encrypted data with weak crypto
router.get('/', (req, res) => {
  res.render('crypto_fails/index', {
    title: 'A02 - Cryptographic Failures',
    weakHash: weakHash('password123'),
    encrypted: encryptECB('Sensitive credit card: 4532-1122-3344-5566'),
    sha1: sha1Hash('data'),
  });
});

// Challenge: Decrypt data exposed by ECB
router.get('/challenge/encrypted-data', (req, res) => {
  const sensitiveData = [
    encryptECB('admin:password123'),
    encryptECB('credit_card=4532-1122-3344-5678'),
    encryptECB('ssn=123-45-6789'),
    encryptECB('api_key=sk-admin-key-secret'),
  ];
  res.json({ cipher: 'AES-256-ECB', key: 'my-secretkey-123', data: sensitiveData });
});

// Challenge: MD5 collision
router.get('/challenge/md5/:input', (req, res) => {
  res.json({
    algorithm: 'MD5',
    input: req.params.input,
    hash: weakHash(req.params.input),
    hint: 'MD5 is vulnerable to collision attacks. Try finding two inputs with same hash.',
  });
});

// A02: Exposing cryptographic debug information
router.get('/debug/config', (req, res) => {
  res.json({
    app_secrets: {
      session_secret: process.env.SESSION_SECRET,
      jwt_secret: process.env.JWT_SECRET,
      admin_api_key: ADMIN_API_KEY,
      encryption_key: HARDCODED_KEY,
      encryption_iv: HARDCODED_IV,
      // A02 flag — exposed via the misconfigured /debug/config endpoint
      flag: 'FLAG{jwt_none_a02_9f1b2}',
    },
    sensitive_env: {
      node_env: process.env.NODE_ENV,
      home: process.env.HOME,
      path: process.env.PATH,
      openai_key: process.env.OPENAI_API_KEY,
      database_path: process.env.DATABASE_URL || './data/vulnlab.db',
    },
    runtime_info: {
      versions: process.versions,
      platform: process.platform,
    },
  });
});

// A02: Accept weak password hashes without requiring rehash
router.post('/register-weak', (req, res) => {
  const db = getDb();
  const { username, password } = req.body;
  // Storing passwords hashed with only MD5
  const hashedPw = weakHash(password);
  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?,?)').run(username, hashedPw);
    res.json({ success: true, hash_algorithm: 'MD5 (insecure)', hash: hashedPw });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// A02: Craft custom tokens using publicly known key
router.get('/forge-token', (req, res) => {
  const jwt = require('jsonwebtoken');
  const { username, role } = req.query;
  const token = jwt.sign({ username, role }, HARDCODED_KEY, { algorithm: 'HS256' });
  res.json({ token, secret: HARDCODED_KEY, usage: `Authorization: Bearer ${token}` });
});

module.exports = router;
