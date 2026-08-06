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
const categories = require('./data/categories');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./docs/openapi');
const rateLimit = require('express-rate-limit');

// ⚠️ CRITICAL: Using fake/in-memory-only AI tokens and SQLite
// No real API keys should ever be committed
process.env.OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || 'sk-aivault-demo-placeholder-do-not-use-real-key';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'insecure-jwt-secret-for-lab';
process.env.SESSION_SECRET = process.env.SESSION_SECRET || 'weak-session-secret-123';

const app = express();
const PORT = process.env.PORT || 3000;

// --- RATE LIMITING (protects public deployments from abuse) ---
// Skip in test mode so the test suite isn't affected
if (process.env.NODE_ENV !== 'test') {
  const apiLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 100, // 100 requests per minute per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests from this IP, please slow down.' },
  });
  // Apply to all routes except health check
  app.use((req, res, next) => {
    if (req.path === '/health') return next();
    return apiLimiter(req, res, next);
  });
}

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

// Story alignment: expose faction / user to every template
app.use((req, res, next) => {
  res.locals.faction = req.session.faction || null;
  res.locals.factionName = req.session.faction
    ? require('./story').STORY.factions[req.session.faction].name
    : null;
  res.locals.handle = req.session.handle || null;
  res.locals.user = req.session.user || null;
  next();
});

// --- MASTER SAFETY GATE (public hosting shield) ---
// Set AIVAULT_GATE_USER + AIVAULT_GATE_PASS to lock the entire lab behind
// Basic Auth. Disabled by default for local dev; recommended for any public
// deployment. Also see AIVAULT_SAFE_MODE (default 1) which sandboxes RCE/SSRF.
const gateUser = process.env.AIVAULT_GATE_USER;
const gatePass = process.env.AIVAULT_GATE_PASS;
if (gateUser && gatePass) {
  app.use((req, res, next) => {
    const auth = req.headers.authorization;
    if (!auth) {
      res.set('WWW-Authenticate', 'Basic realm="AIVault"');
      return res.status(401).send('Authentication required to access AIVault.');
    }
    const [scheme, b64] = auth.split(' ');
    if (scheme !== 'Basic') return res.status(401).send('Unsupported auth scheme.');
    const [u, p] = Buffer.from(b64, 'base64').toString().split(':');
    if (u === gateUser && p === gatePass) return next();
    res.set('WWW-Authenticate', 'Basic realm="AIVault"');
    return res.status(401).send('Invalid credentials.');
  });
}

// EJS templating
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- DATABASE SETUP ---
// Uses Node.js built-in `node:sqlite` (Node >= 22)
const db = require('./db');

// ========== ROUTES ==========

// Health check endpoint (for Render / fly.io / Docker healthcheck)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', service: 'AIVault', uptime: process.uptime() });
});

// Homepage (must come before express.static so public/index.html doesn't override)
app.get('/', (req, res) => {
  res.render('index', {
    title: 'AIVault',
    user: req.session.user,
    categories: getCategoryList(),
  });
});

// Static files (CSS, JS, images) — mounted after the homepage route
app.use(express.static(path.join(__dirname, 'public')));

// API documentation (Swagger UI)
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

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
// ========== OWASP CLOUD‑NATIVE TOP 10 ==========
const cloudRoutes = require('./routes/cloud_top10');
app.use('/cloud', cloudRoutes);

// ========== STORY / FACTION ROUTES ==========
const storyRoutes = require('./routes/story');
app.use('/story', storyRoutes);
const campaignRoutes = require('./routes/campaign');
app.use('/campaign', campaignRoutes);

// ========== FULL CYBERSECURITY CURRICULUM ==========

// --- Network Security ---
const networkRoutes = require('./routes/network');
app.use('/network', networkRoutes);

// --- Cryptography ---
const cryptoRoutes = require('./routes/crypto');
app.use('/crypto-lab', cryptoRoutes);

// --- Reverse Engineering ---
const reverseRoutes = require('./routes/reverse');
app.use('/reverse', reverseRoutes);

// --- Digital Forensics ---
const forensicsRoutes = require('./routes/forensics');
app.use('/forensics', forensicsRoutes);

// --- Social Engineering ---
const socialRoutes = require('./routes/social');
app.use('/social', socialRoutes);

// --- IoT / OT Security ---
const iotRoutes = require('./routes/iot');
app.use('/iot', iotRoutes);

// --- Blockchain / Web3 ---
const blockchainRoutes = require('./routes/blockchain');
app.use('/blockchain', blockchainRoutes);

// --- Malware Analysis ---
const malwareRoutes = require('./routes/malware');
app.use('/malware', malwareRoutes);

// --- Wireless Security ---
const wirelessRoutes = require('./routes/wireless');
app.use('/wireless', wirelessRoutes);

// --- DevSecOps ---
const devsecopsRoutes = require('./routes/devsecops');
app.use('/devsecops', devsecopsRoutes);

// --- Threat Hunting & Blue Team ---
const threatHuntingRoutes = require('./routes/threat_hunting');
app.use('/threat-hunting', threatHuntingRoutes);

// --- OSINT ---
const osintRoutes = require('./routes/osint');
app.use('/osint', osintRoutes);

// --- Red Team Operations ---
const redTeamRoutes = require('./routes/red_team');
app.use('/red-team', redTeamRoutes);

// --- Cloud Security (Deep Dive) ---
const cloudSecRoutes = require('./routes/cloud_sec');
app.use('/cloud-sec', cloudSecRoutes);

// --- Privacy & Data Protection ---
const privacyRoutes = require('./routes/privacy');
app.use('/privacy', privacyRoutes);

// ========== HACKPATH-ALIGNED NEW MODULES ==========

// --- Technical Foundations (Pillar 1) ---
const foundationsRoutes = require('./routes/foundations');
app.use('/foundations', foundationsRoutes);

// --- SOC & Detection Engineering (Pillar 4) ---
const socRoutes = require('./routes/soc');
app.use('/soc', socRoutes);

// --- Incident Response (Pillar 4) ---
const incidentResponseRoutes = require('./routes/incident_response');
app.use('/incident-response', incidentResponseRoutes);

// --- GRC — Governance, Risk & Compliance (Pillar 6) ---
const grcRoutes = require('./routes/grc');
app.use('/grc', grcRoutes);

// --- FLAG SUBMISSION & SCORING ---
// In-memory store of all known flags for verification
const knownFlags = new Set();
function loadFlags() {
  const routeDir = require('path').join(__dirname, 'routes');
  const fs2 = require('fs');
  fs2.readdirSync(routeDir).forEach((f) => {
    if (!f.endsWith('.js')) return;
    try {
      const content = fs2.readFileSync(require('path').join(routeDir, f), 'utf-8');
      const matches = content.match(/FLAG\{[^}]+\}/g);
      if (matches) matches.forEach((m) => knownFlags.add(m));
    } catch (e) {}
  });
}
loadFlags();

// GET /flags — view to submit flags
app.get('/flags', (req, res) => {
  if (!req.session.solves) req.session.solves = [];
  res.render('flags/submit', {
    title: 'Submit Flag',
    solved: req.session.solves,
    error: null,
    success: null,
  });
});

// POST /flags/submit — verify a flag and record it
app.post('/flags/submit', (req, res) => {
  const { flag } = req.body;
  if (!req.session.solves) req.session.solves = [];
  let result;
  if (!flag || !flag.startsWith('FLAG{') || !flag.endsWith('}')) {
    result = { error: 'Invalid flag format. Use FLAG{...}', success: false };
  } else if (req.session.solves.includes(flag)) {
    result = { error: 'You already captured this flag!', success: false };
  } else if (knownFlags.has(flag)) {
    // Record flag in session
    req.session.solves.push(flag);
    // Compute points based on flag length
    const points = flag.length;
    // Persist points to DB for leaderboard
    try {
      const sid = req.sessionID;
      const player = db.prepare('SELECT id FROM players WHERE session_id = ?').get(sid);
      if (!player) {
        // Insert new player entry
        db.prepare(
          'INSERT INTO players (session_id, faction, total_points, first_solve, last_solve) VALUES (?,?,?,?,?)'
        ).run(sid, '', points, new Date().toISOString(), new Date().toISOString());
      } else {
        // Update existing player points
        db.prepare(
          'UPDATE players SET total_points = total_points + ?, last_solve = ? WHERE session_id = ?'
        ).run(points, new Date().toISOString(), sid);
      }
    } catch (e) {
      console.error('Flag DB update error:', e);
    }
    result = {
      success: true,
      message: 'Flag captured! +' + points + ' points',
      count: req.session.solves.length,
    };
  } else {
    result = { error: 'Flag not recognized. Keep hunting!', success: false };
  }
  res.render('flags/submit', {
    title: 'Submit Flag',
    solved: req.session.solves,
    error: result.error || null,
    success: result.success ? result : null,
  });
});

// GET /leaderboard — public leaderboard
app.get('/leaderboard', (req, res) => {
  try {
    const players = db
      .prepare(
        'SELECT handle, total_points, faction FROM players WHERE total_points > 0 ORDER BY total_points DESC LIMIT 20'
      )
      .all();
    res.render('leaderboard', {
      title: 'Leaderboard',
      players: players.filter((p) => p.total_points > 0),
      sessionSolves: req.session.solves?.length || 0,
    });
  } catch (e) {
    res.render('leaderboard', {
      title: 'Leaderboard',
      players: [],
      sessionSolves: req.session.solves?.length || 0,
    });
  }
});

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
app.use((err, _req, res, _next) => {
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
    // New curriculum categories
    {
      id: 'network',
      name: 'Network Security',
      routes: [
        'network:port-scan',
        'network:dns-poisoning',
        'network:arp-spoof',
        'network:firewall-evasion',
        'network:pcap-analyze',
      ],
    },
    {
      id: 'crypto-lab',
      name: 'Cryptography Lab',
      routes: [
        'crypto:hash-identify',
        'crypto:caesar',
        'crypto:vigenere',
        'crypto:rsa-weak',
        'crypto:key-exchange',
      ],
    },
    {
      id: 'reverse',
      name: 'Reverse Engineering',
      routes: [
        'reverse:strings',
        'reverse:crackme',
        'reverse:buffer-overflow',
        'reverse:anti-debug',
        'reverse:format-string',
      ],
    },
    {
      id: 'forensics',
      name: 'Digital Forensics',
      routes: [
        'forensics:log-analysis',
        'forensics:file-carving',
        'forensics:memory-analysis',
        'forensics:timeline',
        'forensics:stego',
      ],
    },
    {
      id: 'social',
      name: 'Social Engineering',
      routes: [
        'social:phishing',
        'social:pretexting',
        'social:osint',
        'social:deepfake',
        'social:spear-phish',
      ],
    },
    {
      id: 'iot',
      name: 'IoT / OT Security',
      routes: [
        'iot:default-creds',
        'iot:firmware-extract',
        'iot:mqtt-hijack',
        'iot:modbus-exploit',
        'iot:ble-attack',
      ],
    },
    {
      id: 'blockchain',
      name: 'Blockchain / Web3',
      routes: [
        'blockchain:reentrancy',
        'blockchain:overflow',
        'blockchain:flash-loan',
        'blockchain:access-control',
        'blockchain:mev-front-run',
      ],
    },
    {
      id: 'malware',
      name: 'Malware Analysis',
      routes: [
        'malware:static',
        'malware:sandbox',
        'malware:unpack',
        'malware:yara',
        'malware:rootkit',
      ],
    },
    {
      id: 'wireless',
      name: 'Wireless Security',
      routes: [
        'wireless:wep',
        'wireless:wpa2-handshake',
        'wireless:evil-twin',
        'wireless:wps',
        'wireless:ble-sniff',
      ],
    },
    {
      id: 'devsecops',
      name: 'DevSecOps',
      routes: [
        'devsecops:git-secrets',
        'devsecops:dependency-confusion',
        'devsecops:terraform-misconfig',
        'devsecops:container-escape',
        'devsecops:supply-chain-action',
      ],
    },
    {
      id: 'threat-hunting',
      name: 'Threat Hunting & Blue Team',
      routes: [
        'threat-hunting:siem-query',
        'threat-hunting:mitre-identify',
        'threat-hunting:anomaly',
        'threat-hunting:memory-hunt',
        'threat-hunting:hunt',
      ],
    },
    {
      id: 'osint',
      name: 'OSINT',
      routes: [
        'osint:username-check',
        'osint:metadata',
        'osint:subdomains',
        'osint:social-recon',
        'osint:breach-check',
      ],
    },
    {
      id: 'red-team',
      name: 'Red Team Operations',
      routes: [
        'red-team:c2-beacon',
        'red-team:lateral-movement',
        'red-team:persistence',
        'red-team:lotl',
        'red-team:evasion',
      ],
    },
    {
      id: 'cloud-sec',
      name: 'Cloud Security',
      routes: [
        'cloud-sec:s3-public',
        'cloud-sec:iam-escalation',
        'cloud-sec:metadata-ssrf',
        'cloud-sec:container-breakout',
        'cloud-sec:lambda-injection',
      ],
    },
    {
      id: 'privacy',
      name: 'Privacy & Data Protection',
      routes: [
        'privacy:pii-overcollection',
        'privacy:consent',
        'privacy:dsar',
        'privacy:data-transfer',
        'privacy:breach-notification',
      ],
    },
    // HackPath-aligned new modules
    {
      id: 'foundations',
      name: 'Technical Foundations (Pillar 1)',
      routes: [
        'foundations:binary',
        'foundations:linux-fundamentals',
        'foundations:networking',
        'foundations:crypto-basics',
        'foundations:cia-triad',
      ],
    },
    {
      id: 'soc',
      name: 'SOC & Detection Engineering (Pillar 4)',
      routes: [
        'soc:siem-query',
        'soc:alert-triage',
        'soc:detection-rule',
        'soc:mitre-map',
        'soc:anomaly',
      ],
    },
    {
      id: 'incident-response',
      name: 'Incident Response (Pillar 4)',
      routes: [
        'incident-response:nist-lifecycle',
        'incident-response:chain-of-custody',
        'incident-response:containment',
        'incident-response:malware-triage',
        'incident-response:lessons-learned',
      ],
    },
    {
      id: 'grc',
      name: 'GRC — Governance, Risk & Compliance (Pillar 6)',
      routes: ['grc:risk-assessment', 'grc:compliance', 'grc:controls', 'grc:audit', 'grc:bcp-dr'],
    },
  ];
}

// Start server only when run directly (not when required in tests)
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    const c = {
      red: '\x1b[31m',
      yellow: '\x1b[33m',
      cyan: '\x1b[36m',
      green: '\x1b[32m',
      reset: '\x1b[0m',
      bold: '\x1b[1m',
    };
    console.log(
      `${c.red}${c.bold}⚠️  AIVAULT running on port ${PORT} — FOR EDUCATIONAL USE ONLY${c.reset}`
    );
    console.log(`${c.yellow}   Warning: This app contains active vulnerabilities${c.reset}`);
    const isProd = process.env.NODE_ENV === 'production';
    const safeMode = (process.env.AIVAULT_SAFE_MODE ?? '1') !== '0';
    console.log(
      `   Safe Mode: ${safeMode ? c.green + 'ON' : c.red + 'OFF'}${c.reset}  ·  NODE_ENV: ${process.env.NODE_ENV || 'development'}`
    );
    if (isProd && (!gateUser || !gatePass)) {
      console.log(
        `${c.red}   ⚠ WARNING: No AIVAULT_GATE_USER / AIVAULT_GATE_PASS set in production.${c.reset}`
      );
      console.log(
        `${c.yellow}     Anyone on the internet can access all vulnerabilities.${c.reset}`
      );
      console.log(`${c.yellow}     Set Basic Auth credentials to lock the lab.${c.reset}`);
    }
    console.log(
      `${c.cyan}   Docs: http://localhost:${PORT}/api-docs  ·  Health: http://localhost:${PORT}/health${c.reset}`
    );
  });
}

module.exports = { app, db };
