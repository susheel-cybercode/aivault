/**
 * A01:2021 – Broken Access Control
 *
 * Vulnerabilities demonstrated:
 * - IDOR (Insecure Direct Object References)
 * - Path traversal for file access
 * - Missing function-level access control
 * - CORS misconfiguration
 * - Privilege escalation via parameter tampering
 * - Forced browsing
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const { safePath } = require('../utils/safe-guard');

function getDb() {
  return require('../db');
}

// --- IDOR: View any user's profile by ID ---
router.get('/', (req, res) => {
  const db = getDb();
  // A01: No authorization check - any user can view any other user's profile
  const userId = req.query.id || req.session?.user?.id || 1;
  try {
    const user = db
      .prepare('SELECT id, username, email, role, credit_card, ssn FROM users WHERE id = ?')
      .get(userId);
    if (!user && req.query.id) {
      // Bypass: direct SQL lookup
      const altUser = db.prepare('SELECT * FROM users WHERE id = ' + req.query.id).get();
      res.render('broken_access/idor', {
        title: 'IDOR - User Profile',
        user: altUser,
        viewer: req.session.user,
      });
    } else {
      res.render('broken_access/idor', {
        title: 'IDOR - User Profile',
        user,
        viewer: req.session.user,
      });
    }
  } catch (e) {
    res.render('broken_access/idor', {
      title: 'IDOR - User Profile',
      user: null,
      error: e.message,
      viewer: req.session.user,
    });
  }
});

// IDOR API: Access other users' private data
router.get('/api/users/:id/credit-card', (req, res) => {
  const db = getDb();
  // A01: No auth, no ownership check
  const card = db
    .prepare(
      'SELECT id, user_id, card_number, cvv, exp_date, cardholder_name FROM credit_cards WHERE user_id = ?'
    )
    .get(req.params.id);
  if (card) res.json(card);
  else {
    // Fallback to user record's credit_card field
    const user = db.prepare('SELECT id, credit_card FROM users WHERE id = ?').get(req.params.id);
    if (user) res.json({ id: user.id, card_number: user.credit_card });
    else res.status(404).json({ error: 'Not found' });
  }
});

router.get('/api/users/:id/posts', (req, res) => {
  const db = getDb();
  // A01: No ownership verification
  const posts = db.prepare('SELECT * FROM posts WHERE user_id = ?').all(req.params.id);
  res.json(posts);
});

// Forced Browsing: Admin panel without proper access control
router.get('/admin', (req, res) => {
  // A01: Missing proper role verification - only checks session existence
  // This should check req.session.user.role === 'admin'
  const db = getDb();
  const users = db.prepare('SELECT id, username, email, role FROM users').all();
  const cards = db.prepare('SELECT * FROM credit_cards').all();
  const logs = db.prepare('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50').all();
  res.render('broken_access/admin', {
    title: 'Admin Panel',
    users,
    cards,
    logs,
    user: req.session.user,
  });
});

// Privilege Escalation via Parameter Tampering
router.post('/api/users/register', (req, res) => {
  const db = getDb();
  const { username, password, email, role } = req.body;
  // A01: Accepts user-supplied role field - Mass Assignment
  const finalRole = role || 'user';
  try {
    db.prepare('INSERT INTO users (username, password, email, role) VALUES (?,?,?,?)').run(
      username,
      password,
      email,
      finalRole
    );
    res.json({ success: true, message: `User created with role: ${finalRole}` });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

// Insecure Direct Object Reference: Access any file via path
router.get('/download', (req, res) => {
  // A01: Path Traversal vulnerability - resolved path not checked
  const requestedFile = req.query.file || 'default.txt';
  // Vulnerable: path.join normalizes .. but we deliberately don't validate result
  const baseDir = path.join(__dirname, '..', '..', 'data', 'files');
  // Allow user input to be treated as absolute or relative without restriction
  let filePath;
  if (requestedFile.startsWith('/') || /^[A-Za-z]:/.test(requestedFile)) {
    // A01: Absolute path traversal - we accept absolute paths!
    filePath = requestedFile;
  } else {
    filePath = path.join(baseDir, requestedFile);
  }

  try {
    // Sandbox path traversal in safe mode (block host file reads)
    const sp = safePath(filePath);
    if (sp.blocked) {
      return res.status(403).type('text/plain').send(`File not found or access denied\n\n[${sp.note}]`);
    }
    const content = fs.readFileSync(sp.path);
    res.type('text/plain').send(content);
  } catch (e) {
    res.status(404).send('File not found or access denied');
  }
});

// CORS Misconfiguration - read/filter via user-controlled origin
router.get('/api/sensitive-data', (req, res) => {
  // A01: Reflects user-supplied Origin
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.json({
    api_keys: getDb().prepare('SELECT * FROM api_keys').all(),
    message: 'Sensitive data exposed via CORS',
  });
});

// Horizontal Privilege Escalation
router.post('/update-profile', (req, res) => {
  const db = getDb();
  const { id, username, email, credit_card } = req.body;
  // A01: No check that the current user owns this ID
  db.prepare('UPDATE users SET username=?, email=?, credit_card=? WHERE id=?').run(
    username,
    email,
    credit_card,
    id
  );
  res.json({ success: true, message: 'Profile updated for any user' });
});

// Missing Function Level Access Control
router.get('/api/admin/users', (req, res) => {
  const db = getDb();
  // A01: No role check - anyone can call this admin endpoint
  const users = db.prepare('SELECT * FROM users').all();
  res.json(users);
});

router.delete('/api/admin/users/:id', (req, res) => {
  const db = getDb();
  // A01: No auth for delete
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

module.exports = router;
