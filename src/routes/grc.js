/**
 * GRC — Governance, Risk & Compliance Module (HackPath Pillar 6)
 * Covers: Security governance, risk frameworks, control frameworks, compliance, audit
 * Difficulty: Beginner → Intermediate
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('grc/index', {
    title: 'GRC — Governance, Risk & Compliance',
    user: req.session?.user,
  });
});

// G1: CIA Triad & Risk Assessment (Beginner)
router.get('/risk-assessment', (req, res) => {
  res.json({
    vuln: 'G1: Risk Assessment — Likelihood × Impact',
    level: 'Beginner',
    description:
      'Risk = Threat × Vulnerability × Impact. You rate each on a 1-5 scale. A risk score above 15 needs treatment.',
    scenario: {
      threat: 'Ransomware (likelihood: 4/5)',
      vulnerability: 'Unpatched RDP exposed to internet (severity: 5/5)',
      impact: 'Complete operational shutdown (impact: 5/5)',
    },
    challenge: 'Calculate the risk score. Is this acceptable or does it need treatment?',
    hint: 'Risk = 4 × 5 × 5 = 100 (on a 125 scale). Anything above 15 needs immediate treatment. This is critical.',
    flag: 'FLAG{grc_risk_100_critical_g1a0}',
  });
});

// G2: Compliance Frameworks (Beginner)
router.get('/compliance', (req, res) => {
  res.json({
    vuln: 'G2: Compliance — Which Framework Applies?',
    level: 'Beginner',
    description:
      'You must know which regulation your organization is subject to: GDPR (EU), HIPAA (US healthcare), PCI-DSS (payment cards), SOX (US public companies).',
    scenarios: [
      'Your company processes credit card payments online → PCI-DSS',
      'Your company stores EU citizens personal data → GDPR',
      'Your company is a US hospital storing patient records → HIPAA',
      'Your company is publicly traded on the US stock market → SOX',
    ],
    challenge:
      'A breach exposes EU customer records AND credit card numbers. What compliance applies?',
    hint: 'GDPR (EU personal data) + PCI-DSS (cardholder data) — both. Report to the supervisory authority within 72 hours under GDPR.',
    flag: 'FLAG{grc_gdpr_pci_both_72h_g2b1}',
  });
});

// G3: Control Frameworks (Intermediate)
router.get('/controls', (req, res) => {
  res.json({
    vuln: 'G3: Control Frameworks — NIST 800-53 & ISO 27001',
    level: 'Intermediate',
    description:
      'Security controls are grouped: Technical, Operational, Management (NIST). ISO 27001 uses Annex A controls (14 domains, 114 controls). Know the difference.',
    sample_controls: {
      'Technical (automated)': ['Firewall rules', 'Disk encryption', 'MFA'],
      'Operational (process)': [
        'Security awareness training',
        'Incident response plan',
        'Patch management process',
      ],
      'Management (governance)': [
        'Risk assessment policy',
        'Access control policy',
        'Security governance board',
      ],
    },
    challenge:
      'Is "encrypting all laptops at rest" a Technical, Operational, or Management control?',
    hint: 'Encryption is automated (software does it) → Technical control. The policy requiring it would be Management.',
    flag: 'FLAG{grc_technical_encryption_g3c2}',
  });
});

// G4: Audit & Assurance (Intermediate)
router.get('/audit', (req, res) => {
  res.json({
    vuln: 'G4: Audit — Evidence Gathering & Testing',
    level: 'Intermediate',
    description:
      'An auditor asks: "Prove your access reviews happen." You need evidence: logs, tickets, review records. Auditors test by sampling.',
    audit_evidence: [
      'Quarterly access review reports signed by managers',
      'Ticketing system export showing access removal after terminations',
      'Active Directory logs showing last login times',
      'Policy document showing review frequency is defined',
    ],
    challenge:
      'An auditor samples 20 terminated employees. 3 still had active accounts 72 hours after termination. Is this a finding?',
    hint: 'Yes — this is a finding. Most policies require immediate (same-day) removal. 72 hours = failed control. Report as an exception.',
    flag: 'FLAG{grc_audit_72h_exception_g4d3}',
  });
});

// G5: Business Continuity & DR (Pro)
router.get('/bcp-dr', (req, res) => {
  res.json({
    vuln: 'G5: Business Continuity — RTO & RPO',
    level: 'Pro',
    description:
      'RTO (Recovery Time Objective) = how long can we be down? RPO (Recovery Point Objective) = how much data can we lose? These drive your backups and failover.',
    terms: {
      RTO: 'Maximum tolerable downtime (e.g., critical system RTO = 4 hours)',
      RPO: 'Maximum tolerable data loss (e.g., financial system RPO = 15 minutes)',
      Failover: 'Automatic switch to backup system',
      'DR Drill': 'Regular practice run to validate the BC/DR plan actually works',
    },
    challenge:
      'A financial trading system has RTO=15min, RPO=0. What backup strategy satisfies this?',
    hint: 'RPO=0 means zero data loss = synchronous replication to a hot DR site. RTO=15min = automated failover. Tape backups (hours) will NOT satisfy this.',
    flag: 'FLAG{grc_rto15_rpo0_sync_dr_g5e4}',
  });
});

module.exports = router;
