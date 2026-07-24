/**
 * A05:2021 – Security Misconfiguration
 *
 * Vulnerabilities demonstrated:
 * - Verbose error messages with stack traces
 * - Default credentials
 * - Directory listing enabled
 * - Debug endpoints exposed
 * - Missing security headers
 * - Verbose server info leaked
 * - Cloud storage / S3-like misconfigurations
 * - Permissive CORS
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');

function getDb() {
  return require('../db');
}

router.get('/', (req, res) => {
  res.render('sec_misconfig/index', { title: 'A05 - Security Misconfiguration' });
});

// Default credentials exposed
router.get('/default-creds', (req, res) => {
  const db = getDb();
  // Exposes default/test credentials
  res.json({
    default_credentials: [
      { service: 'Web App', username: 'admin', password: 'admin123', role: 'admin' },
      { service: 'Database', username: 'root', password: '', host: 'localhost' },
      { service: 'API Gateway', username: 'api', password: 'api123' },
      { service: 'FTP', host: 'ftp.local', username: 'anonymous', password: '' },
      { service: 'SSH', host: 'app.local', username: 'deployer', password: 'deploy123' },
      'FLAG{default_creds_a05_8b2a1}',
    ],
  });
});

// Unauthenticated debug page
router.get('/debug', (req, res) => {
  const db = getDb();
  res.json({
    environment: 'development',
    debug_mode: true,
    node_env: process.env.NODE_ENV,
    server_time: new Date().toISOString(),
    uptime: process.uptime(),
    memory_usage: process.memoryUsage(),
    process_info: {
      pid: process.pid,
      uid: typeof process.getuid === 'function' ? process.getuid() : null,
      gid: typeof process.getgid === 'function' ? process.getgid() : null,
      cwd: process.cwd(),
      exec_path: process.execPath,
    },
    environment_vars: {
      NODE_ENV: process.env.NODE_ENV || 'development',
      // A05 + A02: Intentionally leaking lab-internal secrets (these are lab fakes, not real operator secrets)
      OPENAI_API_KEY: process.env.OPENAI_API_KEY,
      JWT_SECRET: process.env.JWT_SECRET,
      SESSION_SECRET: process.env.SESSION_SECRET,
      PORT: process.env.PORT || '3000',
      HOME: process.env.HOME,
      PATH: process.env.PATH,
    },
    database_tables: db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all(),
    routes: [
      '/broken-access/*',
      '/crypto-fails/*',
      '/injection/*',
      '/insecure-design/*',
      '/security-misconfig/*',
      '/vuln-components/*',
      '/auth-failures/*',
      '/integrity-fails/*',
      '/logging-fails/*',
      '/ssrf/*',
      '/api/*',
      '/mobile/*',
      '/llm/*',
    ],
  });
});

// Version info exposed
router.get('/server-info', (req, res) => {
  res.json({
    server: 'Express/4.18.2',
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    library_versions: {
      express: '4.18.2',
      sqlite3: '5.1.7',
      multer: '1.4.5-lts.1',
      jsonwebtoken: '9.0.2',
      bcrypt: '5.1.1',
      'better-sqlite3': '9.4.3',
    },
  });
});

// Config file exposed
router.get('/config', (req, res) => {
  const configPath = path.join(__dirname, '..', '..', 'package.json');
  res.contentType('application/json');
  res.send(fs.readFileSync(configPath));
});

// Source code disclosure
router.get('/source', (req, res) => {
  const { file } = req.query;
  const validFiles = ['app.js', 'package.json'];

  if (validFiles.includes(file)) {
    const sourcePath = path.join(__dirname, '/../', file);
    res.type('text');
    res.send(fs.readFileSync(sourcePath));
  } else {
    const sourcePath = path.join(__dirname, '..', '..', file);
    try {
      res.send(fs.readFileSync(sourcePath));
    } catch (e) {
      res.json({ error: e.message });
    }
  }
});

// Directory listing
router.get('/files', (req, res) => {
  const dir = req.query.dir || path.join(__dirname, '..', '..', 'data');
  try {
    const items = fs.readdirSync(dir, { withFileTypes: true }).map((entry) => ({
      name: entry.name,
      type: entry.isDirectory() ? 'directory' : 'file',
      path: path.join(dir, entry.name),
    }));
    res.json({ path: dir, items });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Expose .git directory
router.get('/git/refs', (req, res) => {
  res.json({
    config: 'git config contents could be here',
    head: 'ref: refs/heads/master',
  });
});

// Enable debug mode remotely
router.get('/enable-debug', (req, res) => {
  process.env.DEBUG = '*';
  process.env.NODE_ENV = 'development';
  res.json({
    debug_enabled: true,
    environment: 'development (remotely activated)',
  });
});

module.exports = router;
