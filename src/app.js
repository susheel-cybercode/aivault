/**
 * OWASP Vulnerable Lab - Main Application
 *
 * ⚠️  WARNING: This application is INTENTIONALLY VULNERABLE.
 * DO NOT deploy on a public network without proper isolation.
 * This is for educational purposes only.
 *
 * Contains: OWASP Top 10 Web, API, Mobile, and LLM vulnerabilities
 */

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./docs/openapi');

// ⚠️ CRITICAL: Using fake/in-memory-only AI tokens and SQLite
// No real API keys should ever be committed
process.env.OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || 'sk-vulnlab-demo-placeholder-do-not-use-real-key';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'insecure-jwt-secret-for-lab';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'weak-session-secret-123';

const app = express();
const PORT = process.env.PORT || 3000;

// --- INTENTIONALLY VULNERABLE MIDDLEWARE SETUP ---

// CORS: A05 - Security Misconfiguration
// All origins allowed with credentials
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: '*',
  })
);

// A05: Security Misconfiguration - no helmet, verbose errors, no rate limiting
app.use(bodyParser.json({ limit: '100mb' })); // A05: No payload limits
app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
app.use(cookieParser());

// A02: Broken Authentication - Weak session config
// C4 fix: SameSite must be 'lax' for cross-site support, secure auto-set by env in prod
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'weak-session-secret-123',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: false, // Accessible via JavaScript (intentional XSS vuln)
      sameSite: 'lax',
      maxAge: 86400000,
    },
  })
);

// --- MASTER SAFETY GATE (public hosting shield) ---
// Set VULNLAB_GATE_USER + VULNLAB_GATE_PASS to lock the entire lab behind
// Basic Auth. Disabled by default for local dev; recommended for any public
// deployment. Also see VULNLAB_SAFE_MODE (default 1) which sandboxes RCE/SSRF.
const gateUser = process.env.VULNLAB_GATE_USER;
const gatePass = process.env.VULNLAB_GATE_PASS;
if (gateUser && gatePass) {
  app.use((req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) {
      res.set('WWW-Authenticate', 'Basic realm="VulnLab"');
      return res.status(401).send('Authentication required to access VulnLab.');
    }
    const [scheme, b64] = auth.split(' ');
    if (scheme !== 'Basic') return res.status(401).send('Unsupported auth scheme.');
    const [u, p] = Buffer.from(b64, 'base64').toString().split(':');
    if (u === gateUser && p === gatePass) return next();
    res.set('WWW-Authenticate', 'Basic realm="VulnLab"');
    return res.status(401).send('Invalid credentials.');
  });
}

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// API documentation (Swagger UI)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// EJS templating
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- DATABASE SETUP ---
// Uses Node.js built-in `node:sqlite` (Node >= 22)
const db = require('./db');

// ========== ROUTES ==========

// Homepage
app.get('/', (req, res) => {
  res.render('index', {
    title: 'OWASP Vulnerable Lab',
    user: req.session.user,
    categories: getCategoryList(),
  });
});

// --- A01: Broken Access Control ---
const brokenAccessRoutes = require('./routes/a01_broken_access');
app.use('/broken-access', brokenAccessRoutes);

// --- A02: Cryptographic Failures ---
const cryptoFailRoutes = require('./routes/a02_crypto_fails');
app.use('/crypto-fails', cryptoFailRoutes);

// --- A03: Injection ---
const injectionRoutes = require('./routes/a03_injection');
app.use('/injection', injectionRoutes);

// --- A04: Insecure Design ---
const insecureDesignRoutes = require('./routes/a04_insecure_design');
app.use('/insecure-design', insecureDesignRoutes);

// --- A05: Security Misconfiguration ---
const secMisconfigRoutes = require('./routes/a05_sec_misconfig');
app.use('/security-misconfig', secMisconfigRoutes);

// --- A06: Vulnerable Components ---
const vulnComponentsRoutes = require('./routes/a06_vuln_components');
app.use('/vuln-components', vulnComponentsRoutes);

// --- A07: Auth Failures ---
const authFailRoutes = require('./routes/a07_auth_fails');
app.use('/auth-failures', authFailRoutes);

// --- A08: Software & Data Integrity ---
const integrityFailRoutes = require('./routes/a08_integrity_fails');
app.use('/integrity-fails', integrityFailRoutes);

// --- A09: Logging & Monitoring ---
const loggingFailRoutes = require('./routes/a09_logging_fails');
app.use('/logging-fails', loggingFailRoutes);

// --- A10: SSRF ---
const ssrfRoutes = require('./routes/a10_ssrf');
app.use('/ssrf', ssrfRoutes);

// ========== OWASP TOP 10 API ==========
const apiRoutes = require('./routes/api_top10');
app.use('/api', apiRoutes);

// ========== OWASP TOP 10 MOBILE ==========
const mobileRoutes = require('./routes/mobile_top10');
app.use('/mobile', mobileRoutes);

// ========== OWASP TOP 10 FOR LLM ==========
const llmRoutes = require('./routes/llm_top10');
app.use('/llm', llmRoutes);

// ========== STORY / FACTION ROUTES ==========
const storyRoutes = require('./routes/story');
app.use('/story', storyRoutes);

// Generic auth pages
app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // A03: SQL Injection vulnerable login
  try {
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    const user = db.prepare(query).get();
    if (user) {
      req.session.user = { id: user.id, username: user.username, role: user.role };
      return res.redirect('/dashboard');
    }
  } catch (e) {}
  res.render('login', { title: 'Login', error: 'Invalid credentials' });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const posts = db.prepare('SELECT * FROM posts WHERE user_id = ?').all(req.session.user.id);
  res.render('dashboard', { title: 'Dashboard', user: req.session.user, posts });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Global error handler with stack trace leak (A05)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({
    error: err.message,
    stack: err.stack, // Leaking stack trace
    file: err.fileName,
    line: err.lineNumber,
  });
});

// Helper
function getCategoryList() {
  return [
    {
      id: 'web',
      name: 'OWASP Top 10 Web (2021)',
      routes: [
        'broken-access',
        'crypto-fails',
        'injection',
        'insecure-design',
        'security-misconfig',
        'vuln-components',
        'auth-failures',
        'integrity-fails',
        'logging-fails',
        'ssrf',
      ],
    },
    {
      id: 'api',
      name: 'OWASP Top 10 API Security (2023)',
      routes: [
        'api:broken-object-level',
        'api:broken-auth',
        'api:broken-prop-auth',
        'api:unrestricted-resources',
        'api:broken-function',
        'api:unrestricted-access',
        'api:security-misconfig',
        'api:injection',
        'api:improper-assets',
        'api:insufficient-logging',
      ],
    },
    {
      id: 'mobile',
      name: 'OWASP Top 10 Mobile (2024)',
      routes: [
        'mobile:credentials',
        'mobile:supply-chain',
        'mobile:insecure-auth',
        'mobile:insufficient-crypto',
        'mobile:insecure-comm',
        'mobile:insecure-auth',
        'mobile:client-injection',
        'mobile:security-update',
        'mobile:data-leakage',
        'mobile:security-config',
      ],
    },
    {
      id: 'llm',
      name: 'OWASP Top 10 for LLM Applications (2025)',
      routes: [
        'llm:prompt',
        'llm:insecure-output',
        'llm:training-poison',
        'llm:dos',
        'llm:supply-chain',
        'llm:sensitive-data',
        'llm:insecure-plugin',
        'llm:excessive-agency',
        'llm:overreliance',
        'llm:model-theft',
      ],
    },
  ];
}

// Start server only when run directly (not when required in tests)
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(
      `\x1b[31m⚠️   VULNERABLE LAB running on port ${PORT} - FOR EDUCATIONAL USE ONLY\x1b[0m`
    );
    console.log(`\x1b[33m   Warning: This app contains active vulnerabilities\x1b[0m`);
  });
}

module.exports = { app, db };
