/**
 * Cloud Native Top 10 – OWASP Cloud Security Risks (2024)
 *
 * This module provides a simple menu of the Cloud-Native Top 10 vulnerabilities.
 * Each entry is intentionally vulnerable (e.g., insecure metadata access, container escape).
 * The endpoints are mostly placeholders that demonstrate the attack surface –
 * the actual vulnerable implementation lives in the corresponding view templates.
 */

const express = require('express');
const router = express.Router();

// Render the Cloud-Native Top 10 overview page
router.get('/', (req, res) => {
  res.render('cloud_top10/index', {
    title: 'OWASP Cloud-Native Top 10',
    user: req.session?.user,
  });
});

// Example: Insecure Metadata Access (C1)
router.get('/metadata', (req, res) => {
  // In a real cloud environment this would fetch http://169.254.169.254/...
  // Here we simulate the response while safe‑mode blocks actual network calls.
  res.json({
    vuln: 'C1: Insecure Cloud Metadata Access',
    description: 'Exposes instance metadata to the attacker via SSRF.',
    demo: 'Attempt to fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    flag: 'FLAG{cloud_meta_c1_3b8d5}',
  });
});

// Example: Container Escape via Privileged Mount (C2)
router.get('/container-escape', (req, res) => {
  // Demonstration placeholder – no real escape performed.
  res.json({
    vuln: 'C2: Container Escape via Privileged Mount',
    description: 'Allows breaking out of the container by mounting host filesystem.',
    flag: 'FLAG{cloud_escape_c2_1f6a4}',
  });
});

// Example: Weak IAM Role Permissions (C3)
router.get('/iam', (req, res) => {
  res.json({
    vuln: 'C3: Over-Privileged IAM Role',
    description: 'IAM role grants broad permissions, enabling privilege escalation.',
    flag: 'FLAG{cloud_iam_c3_9c2e7}',
  });
});

// Additional placeholder endpoints could be added for the rest of the Cloud Top 10.

module.exports = router;
