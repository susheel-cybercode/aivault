/**
 * OWASP Top 10 API Security Risks (2023)
 *
 * API1:2023 - Broken Object Level Authorization
 * API2:2023 - Broken Authentication
 * API3:2023 - Broken Object Property Level Authorization
 * API4:2023 - Unrestricted Resource Consumption
 * API5:2023 - Broken Function Level Authorization
 * API6:2023 - Unrestricted Access to Sensitive Business Flows
 * API7:2023 - Server Side Request Forgery (SSRF)
 * API8:2023 - Security Misconfiguration
 * API9:2023 - Improper Inventory Management
 * API10:2023 - Unsafe Consumption of APIs
 */

const express = require('express');
const router = express.Router();
const axios = require('axios');
const { safeFetch, safeEval } = require('../utils/safe-guard');

function getDb() {
  return require('../db');
}

// API middleware: intentionally minimal auth
router.use((req, res, next) => {
  // Simulate API gateway with no real auth
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  req.apiAuthenticated = !!apiKey;
  req.userId = req.headers['x-user-id'] || 1;
  next();
});

// ==================== API1:2023 - Broken Object Level Authorization ====================
router.get('/b1/users/:id/profile', (req, res) => {
  const db = getDb();
  // API1: No ownership verification. User 2 can view User 1's data
  const user = db
    .prepare('SELECT id, username, email, credit_card, ssn FROM users WHERE id = ?')
    .get(req.params.id);
  if (user) res.json({ success: true, data: user });
  else res.status(404).json({ error: 'User not found' });
});

router.get('/b1/users/:id/orders', (req, res) => {
  const db = getDb();
  // API1: IDOR - access any user's orders
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ?').all(req.params.id);
  res.json({ orders });
});

router.patch('/b1/users/:id', (req, res) => {
  const db = getDb();
  // API1: Can modify any user
  const updates = req.body;
  const setClauses = Object.keys(updates)
    .map((k) => `${k} = '${updates[k]}'`)
    .join(', ');
  db.prepare(`UPDATE users SET ${setClauses} WHERE id = ${req.params.id}`).run();
  res.json({ success: true, modified: updates });
});

// ==================== API2:2023 - Broken Authentication ====================
router.post('/b2/auth/login', (req, res) => {
  const db = getDb();
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const user = db.prepare(query).get();
    if (user) {
      // API2: Weak token generation
      const token = Buffer.from(`${user.id}:${user.username}:${Date.now()}`).toString('base64');
      res.json({
        success: true,
        token,
        user: { id: user.id, username: user.username, role: user.role },
      });
    } else {
      // API2: User enumeration
      const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
      if (exists) res.json({ error: 'Incorrect password' });
      else res.json({ error: 'User not found' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// API2: JWT None Algorithm attack
router.post('/b2/auth/verify', (req, res) => {
  const jwt = require('jsonwebtoken');
  const token = req.body.token || req.headers.authorization?.split(' ')[1];

  try {
    const decoded = jwt.decode(token, { complete: true });
    if (decoded?.header?.alg === 'none') {
      return res.json({ valid: true, user: decoded.payload, algorithm: 'none' });
    }
    const verified = jwt.verify(token, 'weak-jwt-secret');
    res.json({ valid: true, user: verified });
  } catch (e) {
    res.json({ valid: false, error: e.message });
  }
});

// ==================== API3:2023 - Broken Object Property Level Authorization ====================
router.post('/b3/users', (req, res) => {
  const db = getDb();
  const { username, password, email, role, credit_card } = req.body;

  // API3: Mass assignment - accepts role, credit_card from user
  const items = {
    username: username || '',
    password: password || '',
    email: email || '',
    role: role || 'user',
    credit_card: credit_card || '',
  };

  try {
    db.prepare(
      'INSERT INTO users (username, password, email, role, credit_card) VALUES (?,?,?,?,?)'
    ).run(items.username, items.password, items.email, items.role, items.credit_card);
    res.json({ success: true, user: items });
  } catch (e) {
    res.json({ error: e.message });
  }
});

router.patch('/users/:id', (req, res) => {
  const db = getDb();
  const updates = req.body;

  // API3: Can update any property including role
  Object.keys(updates).forEach((key) => {
    if (['username', 'password', 'email', 'role', 'credit_card', 'ssn'].includes(key)) {
      db.prepare(`UPDATE users SET ${key} = ? WHERE id = ?`).run(updates[key], req.params.id);
    }
  });

  res.json({ success: true, updated: updates });
});

// ==================== API4:2023 - Unrestricted Resource Consumption ====================
router.post('/upload', (req, res) => {
  // API4: No size limits, no rate limiting
  const data = req.body.data;
  if (data) {
    try {
      const result = JSON.parse(data);
      // API4: Memory exhaustion possible with large payloads
      res.json({ size: data.length, parsed: result });
    } catch (e) {
      res.json({ error: e.message, size: data?.length });
    }
  } else {
    res.json({ error: 'No data provided' });
  }
});

// API4: Infinite query depth
router.get('/users', (req, res) => {
  const db = getDb();
  const { expand } = req.query;
  let users = db.prepare('SELECT * FROM users').all();

  // API4: Recursive expansion with no depth limit
  if (expand) {
    users = users.map((u) => ({
      ...u,
      credit_cards: db.prepare('SELECT * FROM credit_cards WHERE user_id = ?').all(u.id),
      posts: db.prepare('SELECT * FROM posts WHERE user_id = ?').all(u.id),
      api_keys: db.prepare('SELECT * FROM api_keys WHERE user_id = ?').all(u.id),
    }));
  }

  res.json({ users });
});

// API4: No pagination - large result set
router.get('/orders', (req, res) => {
  const db = getDb();
  // API4: Can request all orders with no pagination
  const orders = db.prepare('SELECT * FROM orders').all();
  res.json({ orders, count: orders.length });
});

// ==================== API5:2023 - Broken Function Level Authorization ====================
router.delete('/users/:id', (req, res) => {
  const db = getDb();
  // API5: No admin check - any authenticated user can delete
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true, deleted: req.params.id });
});

router.get('/admin/users', (req, res) => {
  const db = getDb();
  // API5: Admin endpoint without role verification
  const users = db.prepare('SELECT * FROM users').all();
  res.json({ users });
});

router.get('/admin/credits', (req, res) => {
  const db = getDb();
  // API5: Sensitive admin action exposed
  const cards = db.prepare('SELECT * FROM credit_cards').all();
  res.json({ cards });
});

// ==================== API6:2023 - Unrestricted Access to Sensitive Business Flows ====================
router.post('/coupon/apply', (req, res) => {
  const { code } = req.body;
  const coupons = {
    GET50OFF: 0.5,
    GET100OFF: 0,
    ADMIN_RESET: 100,
  };

  // API6: No business flow rate limiting
  // No validation that coupon can only be used once
  const discount = coupons[code] || 0;
  res.json({ code, discount, applied: 'success' });
});

router.post('/purchase', (req, res) => {
  const { product_id, quantity, coupon } = req.body;

  // API6: no abuse protection
  // Negative quantity vuln
  let total = (product_id === 1 ? 49.99 : 9.99) * quantity;
  if (coupon === 'GETFREE') total = 0;
  if (quantity < 0) total = -total; // credit of balance

  res.json({ product_id, quantity, total, success: true });
});

// ==================== API7:2023 - SSRF ====================
router.get('/fetch-url', async (req, res) => {
  const { url } = req.query;
  if (url) {
    try {
      const sc = safeFetch(url);
      if (sc.blocked) {
        return res.json({ error: sc.note, hint: 'Metadata address blocked in safe mode' });
      }
      const response = await axios.get(sc.url, { timeout: 5000 });
      res.json({ data: response.data });
    } catch (e) {
      res.json({ error: e.message, hint: 'Try: ?url=http://169.254.169.254/latest/meta-data/' });
    }
  } else {
    res.json({ error: 'url required' });
  }
});

// ==================== API8:2023 - Security Misconfiguration ====================
router.get('/config', (req, res) => {
  // API8: Exposing configuration details
  res.json({
    version: '1.0.0',
    environment: 'development',
    debug: true,
    cors: '*',
    stack_traces: 'enabled',
    endpoints: [
      'GET /api/users/:id/profile',
      'POST /api/users',
      'GET /api/admin/users',
      'DELETE /api/users/:id',
      'GET /api/config',
      'POST /api/upload',
      'GET /api/purchase',
    ],
  });
});

// api8: verbose error messages
router.get('/error', (req, res) => {
  const { input } = req.query;
  try {
    JSON.parse(input);
    res.json({ ok: true });
  } catch (e) {
    // API8: Full error trace
    res.status(500).json({
      error: e.message,
      stack: e.stack,
      input,
      type: typeof input,
    });
  }
});

// ==================== API9:2023 - Improper Inventory Management ====================
router.get('/v1/users', (req, res) => {
  // API9: Old API version still active
  const db = getDb();
  res.json(db.prepare('SELECT id, username, password, email, ssn as flag FROM users').all());
});

router.get('/v2/users', (req, res) => {
  // API9: Inconsistent versions
  const db = getDb();
  res.json(db.prepare('SELECT * FROM users').all());
});

router.get('/legacy/users', (req, res) => {
  // API9: Legacy endpoint with elevated privileges
  const db = getDb();
  res.json(db.prepare('SELECT * FROM users').all());
});

// ==================== API10:2023 - Unsafe Consumption of APIs ====================
router.post('/process-url', async (req, res) => {
  const { url } = req.body;
  // API10: No validation on consumed API (sandboxed in safe mode)
  try {
    const sc = safeFetch(url);
    if (sc.blocked) return res.json({ error: sc.note });
    const result = await axios.get(sc.url);
    const serialized = JSON.stringify(result.data);
    const r = safeEval(serialized, 'serialize');
    if (r.simulated) return res.json({ success: true, data: r });
    const processed = eval('(' + serialized + ')');
    res.json({ success: true, data: processed });
  } catch (e) {
    res.json({ error: e.message });
  }
});

module.exports = router;
