/**
 * A04:2021 – Insecure Design
 *
 * Vulnerabilities demonstrated:
 * - Missing rate limiting / No brute force protection
 * - Flawed password reset flow
 * - Weak question-based MFA bypass
 * - Unrestricted file upload
 * - Insecure workflow bypass
 * - Business logic flaws
 * - Missing validation
 */

const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

function getDb() {
  return require('../db');
}

// A04: Unrestricted file upload with no type/name validation
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '..', '..', 'data', 'uploads');
    if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // A04: Using original filename - allows path traversal + malicious extensions
    cb(null, file.originalname);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: Infinity }, // A04: No file size restriction
  fileFilter: (req, file, cb) => {
    cb(null, true); // A04: No file type filtering
  },
});

router.get('/', (req, res) => {
  res.render('insecure_design/index', { title: 'A04 - Insecure Design' });
});

// Flawed Password Reset Flow
router.get('/forgot-password', (req, res) => {
  res.render('insecure_design/forgot_password', {
    title: 'Forgot Password',
    step: 'email',
    token: null,
  });
});

router.post('/forgot-password', (req, res) => {
  const db = getDb();
  const { email } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  if (user) {
    // A04: Predictable reset token
    const token = `${user.username}-reset-${Date.now()}`;
    db.prepare('UPDATE users SET reset_token = ? WHERE id = ?').run(token, user.id);

    res.render('insecure_design/reset_flow', {
      title: 'Password Reset',
      step: 'token',
      token,
      user_id: user.id,
      email,
    });
  } else {
    res.json({ error: 'Email not found' });
  }
});

router.get('/reset-password', (req, res) => {
  const db = getDb();
  const { token } = req.query;

  if (!token) {
    // A04: Allow reset without token in GET params
    const { user_id } = req.query;
    if (user_id) {
      const user = db
        .prepare('SELECT id, username, email, reset_token FROM users WHERE id = ?')
        .get(user_id);
      return res.json({ user, hint: 'Token not required' });
    }
  }

  // A04: Token is predictable, can be brute forced
  const user = db.prepare('SELECT * FROM users WHERE reset_token = ?').get(token);
  res.render('insecure_design/reset_password', {
    title: 'Reset Password',
    user_id: user?.id,
    token,
  });
});

router.post('/password-reset/confirm', (req, res) => {
  const db = getDb();
  const { user_id, new_password } = req.body;

  // A04: No token required at all for password change!
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(new_password, user_id);
  res.json({ success: true, message: 'Password updated' });
});

// Two-factor Bypass
router.get('/2fa-bypass', (req, res) => {
  res.render('insecure_design/2fa_bypass', { title: '2FA Bypass' });
});

router.post('/2fa/verify', (req, res) => {
  const { code } = req.body;

  // A04: 2FA code is static '123456' and stored in database
  // Also, direct user_id-based access allows bypass
  if (code === '123456') {
    res.json({ success: true, token: 'verified-session-token' });
  } else {
    res.json({ success: false });
  }
});

// Direct API calls to skip 2FA step
router.post('/2fa/skip', (req, res) => {
  const { user_id } = req.body;
  // A04: API skips 2FA entirely if you just pass logged_in param
  res.json({
    success: true,
    message: `User ${user_id} logged in without 2FA`,
    session: {
      user_id,
      authenticated: true,
      two_factor_required: false,
      flag: 'FLAG{2fa_skip_a04_2c6f8}',
    },
  });
});

// Unvalidated Redirect
router.get('/redirect', (req, res) => {
  // A04: Open redirect
  const { url } = req.query;
  if (url) res.redirect(url);
  else res.render('insecure_design/redirect', { title: 'Open Redirect' });
});

// Business Logic: Coupon abuse
router.get('/coupon', (req, res) => {
  res.render('insecure_design/coupon', { title: 'Coupon Abuse' });
});

router.post('/apply-coupon', (req, res) => {
  const { code, price } = req.body;
  let finalPrice = parseFloat(price) || 100;

  // 逻辑漏洞: Can apply same coupon multiple times
  if (code === 'SUMMER50') {
    finalPrice *= 0.5;
  } else if (code === 'FLAT10') {
    finalPrice -= 10;
  } else if (code === 'FREE') {
    finalPrice = 0;
  }

  res.json({ original: price, discounted: finalPrice, code });
});

// Batch Order Processing vulnerability
router.post('/bulk-order', (req, res) => {
  const { quantities } = req.body;
  // A04: Input array allows quantity bypass
  let maxQty = 0;
  if (Array.isArray(quantities)) {
    maxQty = Math.max(...quantities);
  } else {
    maxQty = parseInt(quantities);
  }

  // A04: Bypass for max order check - only checks first element
  if (typeof quantities === 'object' && quantities[0]) {
    if (quantities[0] < 10) {
      res.json({
        success: true,
        ordered: quantities.length ? quantities[quantities.length - 1] : maxQty,
        message: 'Order accepted: Only validator checks qty[0]',
      });
    } else {
      res.json({ error: 'Max 10 items per order' });
    }
  } else {
    if (maxQty < 10) res.json({ success: true, ordered: maxQty });
    else res.json({ error: 'Max 10 items per order' });
  }
});

// A04: Unrestricted file upload endpoint (no type/size validation)
router.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.json({ error: 'No file uploaded' });
  res.json({
    success: true,
    filename: req.file.originalname,
    path: req.file.path,
    size: req.file.size,
    mimetype: req.file.mimetype,
  });
});

module.exports = router;
