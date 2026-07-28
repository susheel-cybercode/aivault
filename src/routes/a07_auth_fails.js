/**
 * A07:2021 – Identification and Authentication Failures
 *
 * Vulnerabilities demonstrated:
 * - Weak password policy
 * - Credential stuffing
 * - Session fixation
 * - No MFA
 * - Predictable session tokens
 * - Brute force login
 * - Weak password recovery
 * - Session not invalidated on logout
 */

const express = require('express');
const router = express.Router();

function getDb() {
  return require('../db');
}

router.get('/', (req, res) => {
  res.render('auth_fails/index', { title: 'A07 - Auth Failures' });
});

// Brute force login - no rate limit
router.post('/brute-force-login', (req, res) => {
  const db = getDb();
  const { username, password } = req.body;

  // A07: User enumeration via different error messages
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    return res.json({ error: 'Username not found' }); // User enumeration!
  }

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  const result = db.prepare(query).get();

  if (result) {
    res.json({ success: true, message: 'Login successful', user });
  } else {
    res.json({ error: 'Password incorrect' }); // Confirms user exists!
  }
});

// Weak password policy check
router.post('/register', (req, res) => {
  const db = getDb();
  const { username, password } = req.body;

  // A07: No password complexity enforcement
  // Only check: password exists
  if (!password) return res.json({ error: 'Password required' });

  try {
    db.prepare('INSERT INTO users (username, password) VALUES (?,?)').run(username, password);
    res.json({ success: true, message: 'Registered with weak password policy' });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Credential Stuffing
router.get('/exposed-credentials', (req, res) => {
  const db = getDb();
  // A07: Credential leakage - showing all stored passwords
  const users = db.prepare('SELECT username, password, email FROM users').all();
  res.json({ leaked_credentials: users, count: users.length, flag: 'FLAG{cred_stuff_a07_4c1b6}' });
});

// Session Fixation Vulnerability
router.get('/create-session', (req, res) => {
  const { sid } = req.query;
  // A07: Accepts user-supplied session ID — we ACTUALLY ISSUES a cookie with that ID
  if (sid) {
    // Real session fixation: forge a connect.sid cookie the browser will send back
    res.cookie('connect.sid', sid, { httpOnly: false, sameSite: 'lax' });
    // The lab also remembers the attack so a successful "login" later confirms fixation
    req.session.attacker_fixed_session = sid;
    req.session.user = { id: 1, username: 'admin', role: 'admin' };
    return res.json({
      message: 'Session created with FIXED ID',
      session_id: sid,
      hint:
        'Your browser now has connect.sid=' +
        sid +
        '. On next request, that cookie is sent instead of your real session.',
      flag_hint:
        'Send a request with Cookie: connect.sid=' +
        sid +
        ' and check /auth-failures/api/user-info?id=1',
    });
  } else {
    res.json({ message: 'Provide ?sid= to fix session' });
  }
});

// Session Not Invalidated After Password Change
router.post('/change-password', (req, res) => {
  const db = getDb();
  const { user_id, new_password } = req.body;

  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(new_password, user_id);

  // A07: No session invalidation after password change
  res.json({ success: true, message: 'Password changed but old sessions still valid!' });
});

// Weak authentication - knowable response
router.get('/api/user-info', (req, res) => {
  const db = getDb();
  const user_id = req.query.id || 1;
  const user = db
    .prepare('SELECT id, username, email, role, reset_token, credit_card FROM users WHERE id = ?')
    .get(user_id);
  res.json(user);
});

// Demo of user enumeration via registration
router.post('/check-username', (req, res) => {
  const db = getDb();
  const { username } = req.body;
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(username);

  if (exists) {
    res.json({ available: false, message: 'Username already taken' });
  } else {
    res.json({ available: true, message: 'Username available' });
  }
});

module.exports = router;
