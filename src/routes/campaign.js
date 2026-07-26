// Campaign mode – walks the player through a story line by line
// Each step points to an existing vulnerable endpoint. When the player
// finishes a step they POST /campaign/complete/:id which stores the step
// number in the session (req.session.campaignCompleted).

const express = require('express');
const router = express.Router();

// Define the ordered steps of the campaign
const steps = [
  {
    id: 1,
    title: 'Choose Your Faction',
    description: 'Select either the Aegis Wardens or the Null Collective to set your stance.',
    url: '/story',
  },
  {
    id: 2,
    title: 'Broken Access Control (A01)',
    description: 'Explore IDOR, path traversal and forced browsing.',
    url: '/broken-access',
  },
  {
    id: 3,
    title: 'Cryptographic Failures (A02)',
    description: 'Inspect weak hashing, hard‑coded keys and broken ECB cipher.',
    url: '/crypto-fails',
  },
  {
    id: 4,
    title: 'Injection (A03)',
    description: 'Practice SQLi, XSS and command injection.',
    url: '/injection',
  },
  {
    id: 5,
    title: 'Insecure Design (A04)',
    description: 'Bypass weak password reset and 2FA mechanisms.',
    url: '/insecure-design',
  },
  {
    id: 6,
    title: 'Server‑Side Request Forgery (A10)',
    description: 'Play with the SSRF explorer and metadata fetch.',
    url: '/ssrf',
  },
  {
    id: 7,
    title: 'Cloud‑Native Top 10 (2024)',
    description: 'Discover insecure cloud metadata, container escape and over‑privileged IAM.',
    url: '/cloud',
  },
  {
    id: 8,
    title: 'Finale – Seal or Release ECHO‑7',
    description: 'Make the final decision and finish the story.',
    url: '/story/vault',
  },
];

// Show the campaign dashboard – which step is next, which are done
router.get('/', (req, res) => {
  const completed = req.session.campaignCompleted || [];
  // Find the first step that is not completed (or the last one if all done)
  const nextStep = steps.find((s) => !completed.includes(s.id)) || steps[steps.length - 1];
  res.render('campaign', {
    title: 'VulnLab Campaign Mode',
    steps,
    completed,
    nextStep,
    user: req.session?.user,
  });
});

// Mark a step as completed – called from a simple form on the dashboard
router.post('/complete/:id', (req, res) => {
  const stepId = parseInt(req.params.id, 10);
  if (!req.session.campaignCompleted) req.session.campaignCompleted = [];
  if (!req.session.campaignCompleted.includes(stepId)) {
    req.session.campaignCompleted.push(stepId);
  }
  res.redirect('/campaign');
});

module.exports = router;
