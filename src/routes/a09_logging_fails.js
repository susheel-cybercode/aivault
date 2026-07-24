/**
 * A09:2021 – Security Logging and Monitoring Failures
 *
 * Vulnerabilities demonstrated:
 * - Logging of sensitive data (passwords, tokens, credit cards)
 * - No detection of attacks
 * - No alerting mechanism
 * - Insufficient logging
 * - Log injection
 * - Storing logs without protection
 * - No log rotation/retention
 * - Hardcoded logging credentials
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

function getDb() {
  return require('../db');
}

router.get('/', (req, res) => {
  const db = getDb();
  // A09: Logs publicly accessible
  const logs = db.prepare('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').all();
  res.render('logging_fails/index', { title: 'A09 - Logging Failures', logs });
});

// Log sensitive data
router.get('/api/logs', (req, res) => {
  const db = getDb();
  // File-based log output
  const logFile = path.join(__dirname, '..', '..', 'data', 'app.log');
  if (fs.existsSync(logFile)) {
    const content = fs.readFileSync(logFile, 'utf8');
    res.type('text').send(content);
  } else {
    // Return DB logs with sensitive data
    const allLogs = db.prepare('SELECT * FROM logs').all();
    res.json(allLogs);
  }
});

// Making logging requests visible
router.get('/api/logs/recent', (req, res) => {
  const db = getDb();
  const logs = db.prepare('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 20').all();
  res.json(logs);
});

// Log-sensitive data insert
router.post('/api/logs/add', (req, res) => {
  const db = getDb();
  const { level, message, user_id, ip } = req.body;

  // A09: No log sanitization - accepting any data
  db.prepare('INSERT INTO logs (level, message, user_id, ip) VALUES(?,?,?,?)').run(
    level,
    message,
    user_id,
    ip
  );
  res.json({ success: true });
});

// Stored logs with sensitive info exposed
router.post('/login-with-logs', (req, res) => {
  const db = getDb();
  const { username, password } = req.body;

  // A09: Logging passwords in cleartext!
  db.prepare('INSERT INTO logs (level, message, ip) VALUES (?,?,?)').run(
    'INFO',
    `Login attempt - username: ${username}, password: ${password} | FLAG{log_inject_a09_6a4f3}`,
    req.ip
  );

  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  try {
    const user = db.prepare(query).get();
    if (user) {
      // A09: Logging session tokens
      db.prepare('INSERT INTO logs (level, message, ip) VALUES (?,?,?)').run(
        'INFO',
        `User ${username} logged in. Session: ${JSON.stringify(req.session)}`,
        req.ip
      );
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.json({ success: true });
    }
    db.prepare('INSERT INTO logs (level, message, ip) VALUES (?,?,?)').run(
      'WARN',
      `Failed login for ${username}`,
      req.ip
    );
    res.json({ success: false });
  } catch (e) {
    db.prepare('INSERT INTO logs (level, message, ip) VALUES (?,?,?)').run(
      'ERROR',
      e.message,
      req.ip
    );
    res.status(500).json({ error: e.message });
  }
});

// Log injection demo
router.get('/search-logs', (req, res) => {
  const db = getDb();
  const { q } = req.query;

  if (q) {
    // A09: Log query with injection vulnerability
    try {
      const results = db.prepare(`SELECT * FROM logs WHERE message LIKE '%${q}%'`).all();
      res.json({ query, results });
    } catch (e) {
      res.json({ error: e.message });
    }
  } else {
    res.json({ results: [] });
  }
});

// A09: No monitoring alerts configured
router.get('/health', (req, res) => {
  res.json({
    status: 'UP',
    monitoring: {
      active: false,
      alerts: [],
      last_scan: null,
      warnings: 'No monitoring configured, high-risk breach undetected',
    },
  });
});

module.exports = router;
