/**
 * A03:2021 – Injection
 *
 * Vulnerabilities demonstrated:
 * - SQL Injection (Error-based, Union-based, Blind, Boolean-based, Time-based)
 * - Cross-Site Scripting (XSS) - Reflected, Stored, DOM-based
 * - Command Injection / OS Command Injection
 * - LDAP Injection simulation
 * - NoSQL Injection
 * - Template Injection (EJS SSTI)
 * - XML External Entity (XXE)
 */

const express = require('express');
const router = express.Router();
const { safeExec } = require('../utils/safe-guard');

function getDb() {
  return require('../db');
}

// --------------- SQL INJECTION ---------------

// SQLi Lab homepage
router.get('/', (req, res) => {
  res.render('injection/index', { title: 'A03 - Injection' });
});

// Error-based SQLi
router.get('/sqli/search', (req, res) => {
  const db = getDb();
  const { q } = req.query;
  if (!q) return res.json({ results: [] });

  try {
    // A03: Direct string interpolation - SQL Injection
    const query = `SELECT * FROM users WHERE username LIKE '%${q}%'`;
    const results = db.prepare(query).all();
    res.json({ query_used: query, results, hidden_flag_column: 'FLAG{sqli_union_a03_5e8d3}' });
  } catch (e) {
    // A03: Error leak shows SQL structure
    res.status(500).json({
      error: e.message,
      query: `SELECT * FROM users WHERE username LIKE '%${q}%'`,
      hint: 'The query might be injectable via LIKE clause',
    });
  }
});

// Boolean-based Blind SQLi (Login)
router.post('/sqli/login', (req, res) => {
  const db = getDb();
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  try {
    const user = db.prepare(query).get();
    if (user) {
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.json({ success: true, user });
    }
    res.json({ success: false, message: 'Invalid credentials' });
  } catch (e) {
    res.status(500).json({ error: e.message, query });
  }
});

// UNION-based SQLi
router.get('/sqli/products', (req, res) => {
  const db = getDb();
  const category = req.query.category || 'all';

  try {
    const query = `SELECT name, price FROM products WHERE id = ${category}`;
    const results = db.prepare(query).all();
    res.json({ query, results });
  } catch (e) {
    res.status(500).json({ error: e.message, query });
  }
});

// Time-based blind SQLi
router.get('/sqli/blind', (req, res) => {
  const db = getDb();
  const userId = req.query.id || '1';

  try {
    // Manual timing done in app layer
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const start = Date.now();
    const user = db.prepare(query).get();
    const elapsed = Date.now() - start;

    if (user) {
      res.json({ found: true, time_ms: elapsed, username: user.username });
    } else {
      res.json({ found: false, time_ms: elapsed });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Second-order SQLi: Store payload that executes later
router.post('/sqli/second-order', (req, res) => {
  const db = getDb();
  const { username } = req.body;

  // A03: Store user input without sanitization
  try {
    db.prepare("INSERT INTO users (username, password) VALUES (?, 'temp123')").run(username);
    res.json({
      success: true,
      message: `User ${username} created. Data stored for later execution.`,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// XSS - Stored
router.post('/xss/stored', (req, res) => {
  const db = getDb();
  const { username, content, post_id } = req.body;

  if (content) {
    try {
      db.prepare('INSERT INTO comments (post_id, user_id, username, content) VALUES (?,?,?,?)').run(
        post_id || 1,
        req.session?.user?.id || 0,
        username || 'anonymous',
        content // A03: Unsanitized XSS
      );
      res.json({ success: true });
    } catch (e) {
      res.json({ error: e.message });
    }
  } else {
    res.json({ error: 'content required' });
  }
});

router.get('/xss/stored', (req, res) => {
  const db = getDb();
  const comments = db.prepare('SELECT * FROM comments ORDER BY id DESC').all();
  res.render('injection/xss_stored', { title: 'Stored XSS', comments });
});

// XSS: Reflected
router.get('/xss/reflected', (req, res) => {
  // A03: Output raw user input without encoding
  const name = req.query.name || '';
  res.render('injection/xss_reflected', { title: 'Reflected XSS', name });
});

// DOM XSS
router.get('/xss/dom', (req, res) => {
  res.render('injection/xss_dom', { title: 'DOM-based XSS' });
});

// CSTI: Client Side Template Injection
router.get('/csti', (req, res) => {
  const template = req.query.template || '<h1>Hello {{ user }}</h1>';
  res.render('injection/csti', { title: 'CSTI', template });
});

// Command Injection
router.get('/command-injection', (req, res) => {
  const { host } = req.query;

  if (host) {
    // A03: Direct command injection (sandboxed when AIVAULT_SAFE_MODE=1)
    const r = safeExec(`ping -c 2 ${host}`);
    r.run((error, stdout, stderr) => {
      if (error) {
        return res.send(`<pre>Error: ${error.message}\n${stderr}</pre>`);
      }
      res.send(`<pre>${stdout}</pre>`);
    });
  } else {
    res.render('injection/cmd_injection', { title: 'Command Injection' });
  }
});

// XXE - XML External Entity Injection
router.get('/xxe', (req, res) => {
  res.render('injection/index', {
    title: 'AIVault - XXE Injection',
    user: req.session?.user,
  });
});

router.post('/xxe/parse', (req, res) => {
  const xml2js = require('xml2js');
  // Ensure the parser allows DOCTYPE for XXE
  const parser = new xml2js.Parser({
    explicitArray: false,
    mergeAttrs: false,
    explicitCharkey: false,
    attrkey: '@',
  });

  try {
    // A03: XXE - Parsing XML with external entities
    const xmlData = req.body.xml || req.rawBody;
    parser.parseString(xmlData, (err, result) => {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ parsed: result });
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// SSTI - Server-Side Template Injection (EJS)
router.get('/ssti', (req, res) => {
  const { name } = req.query;
  if (name) {
    // A03: EJS SSTI via unescaped template
    const ejs = require('ejs');
    const template = '<h1>Hello, <%- name %></h1>';
    try {
      const html = ejs.render(template, { name });
      res.send(html);
    } catch (e) {
      res.send(`Error: ${e.message}`);
    }
  } else {
    res.render('injection/ssti', { title: 'SSTI' });
  }
});

// NoSQL Injection simulation
router.get('/nosql', (req, res) => {
  const { username } = req.query;
  const db = getDb();

  // Simulated NoSQL injection: query building with $ne operators
  if (username) {
    try {
      // A03: Craft queries using MongoDB-like syntax through param injection
      const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
      if (user) {
        res.json({ success: true, user: { username: user.username, role: user.role } });
      } else {
        res.json({ success: false, message: 'User not found' });
      }
    } catch (e) {
      res.json({ error: e.message });
    }
  } else {
    res.render('injection/nosqli', { title: 'NoSQL Injection' });
  }
});

module.exports = router;
