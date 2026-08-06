/**
 * Privacy & Data Protection Module
 * Covers: GDPR, PII handling, data minimization, DPA, consent, data breaches
 * Difficulty: Beginner -> Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('privacy/index', {
    title: 'Privacy & Data Protection',
    user: req.session?.user,
  });
});

// P1: Over-Collection of PII (Beginner)
router.get('/pii-overcollection', (req, res) => {
  res.json({
    vuln: 'P1: Excessive PII Collection (GDPR Article 5(1)(c))',
    level: 'Beginner',
    description:
      'A signup form collects data far beyond what is needed for the service. Identify the lawfully collected vs excessive fields.',
    form_fields: [
      { field: 'full_name', needed: true, gdpr_basis: 'contract' },
      { field: 'email', needed: true, gdpr_basis: 'contract' },
      { field: 'national_id', needed: false, gdpr_basis: 'none' },
      { field: 'medical_history', needed: false, gdpr_basis: 'none' },
      { field: 'biometric_face_scan', needed: false, gdpr_basis: 'none' },
      { field: 'sexual_orientation', needed: false, gdpr_basis: 'none' },
    ],
    hint: 'GDPR requires data minimization — collect only what is necessary for the stated purpose.',
    flag: 'FLAG{priv01_pii_minimization_f2g3}',
  });
});

// P2: Inadequate Consent Mechanism (Beginner)
router.get('/consent', (req, res) => {
  res.json({
    vuln: 'P2: Invalid Consent — Pre-ticked Boxes & Dark Patterns',
    level: 'Beginner',
    description:
      'A cookie banner uses pre-ticked boxes and vague language. This violates GDPR consent requirements.',
    cookie_banner_issues: [
      'Pre-ticked marketing consent boxes (invalid under GDPR)',
      'No option to reject all cookies (dark pattern)',
      'Accept button is large/green, reject is tiny/grey',
      'Consent bundled (marketing + analytics in one toggle)',
      'No way to withdraw consent later',
    ],
    regulation: 'GDPR Article 4(11) + Article 7',
    hint: 'Consent must be freely given, specific, informed, and an unambiguous affirmative action.',
    flag: 'FLAG{priv02_invalid_consent_h4i5}',
  });
});

// P3: Data Subject Rights Failure (Intermediate)
router.get('/dsar', (req, res) => {
  res.json({
    vuln: 'P3: Non-Functional Data Subject Access Request (DSAR)',
    level: 'Intermediate',
    description:
      'A company advertises GDPR rights but their DSAR process blocks users with excessive identity verification and delays.',
    bottlenecks: [
      'Requires notarized ID for a simple request (disproportionate)',
      '30-day deadline ignored — delayed 90 days',
      'Data export provided in machine-generated XML (not portable)',
      'No process for erasure (Right to be Forgotten)',
    ],
    gdpr_rights: [
      'Art 15: Access right',
      'Art 16: Right to rectification',
      'Art 17: Right to erasure',
      'Art 20: Right to data portability',
      'Art 21: Right to object',
    ],
    hint: 'Each failed right is a separate violation. Document each with evidence + timestamp.',
    flag: 'FLAG{priv03_dsar_blocked_j6k7}',
  });
});

// P4: Cross-Border Data Transfer Violation (Advanced)
router.get('/data-transfer', (req, res) => {
  res.json({
    vuln: 'P4: Illegal Cross-Border Data Transfer',
    level: 'Advanced',
    description:
      'EU user data is transferred to a server in a country without adequacy decision or SCCs.',
    transfer_chain: [
      { from: 'EU (Ireland)', to: 'US (AWS Virginia)', safeguard: 'none', issue: 'No SCC' },
      { from: 'US', to: 'India (outsourced support)', safeguard: 'none', issue: 'No DPA' },
      { from: 'India', to: 'Russia (analytics)', safeguard: 'none', issue: 'No adequacy' },
    ],
    regulation: 'GDPR Chapter V (Articles 44-50)',
    hint: 'Post-Schrems II, US transfers need SCCs + Transfer Impact Assessment.',
    flag: 'FLAG{priv04_cross_border_l8m9}',
  });
});

// P5: Data Breach Notification Failure (Pro)
router.get('/breach-notification', (req, res) => {
  res.json({
    vuln: 'P5: Failure to Notify Data Breach within 72 Hours',
    level: 'Pro',
    description:
      'A breach occurred 10 days ago. Authorities + affected users were never notified. Calculate the violations and required notifications.',
    incident: {
      breach_date: '2024-01-10',
      detected_date: '2024-01-12',
      today: '2024-01-20',
      records_compromised: 250000,
      data_types: ['names', 'emails', 'passwords (plaintext)', 'partial SSNs', 'IP addresses'],
      notifications_sent: 0,
    },
    gdpr_violations: [
      'Art 33: Authority not notified within 72h of becoming aware',
      'Art 34: Data subjects not notified (high risk breach)',
      'Art 33(5): Breach register not maintained',
      'Art 32: No encryption applied (plaintext passwords)',
    ],
    max_fine: '4% of annual global turnover or €20M (whichever is higher)',
    hint: 'Start the clock from awareness, not breach date. Document everything in the breach register.',
    flag: 'FLAG{priv05_breach_notification_n0p1}',
  });
});

module.exports = router;
