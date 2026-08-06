/**
 * Social Engineering Module
 * Covers: Phishing, pretexting, baiting, deepfakes, OSINT
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('social/index', {
    title: 'Social Engineering',
    user: req.session?.user,
  });
});

// SE1: Phishing Email Identification (Beginner)
router.get('/phishing', (req, res) => {
  res.json({
    vuln: 'SE1: Phishing Email Identification',
    level: 'Beginner',
    description: 'Identify red flags in this phishing email.',
    email: {
      from: 'support@amaz0n-secure.com',
      reply_to: 'noreply@tempmail.ru',
      subject: 'Urgent: Your Amazon account is suspended!',
      body: 'Dear Customer, your account has been suspended. Click here to verify immediately: http://amaz0n-secure.com/verify',
      headers: 'Received: from [185.220.101.1] by mx.tempmail.ru',
    },
    red_flags: [
      'Sender domain uses 0 instead of o (amaz0n)',
      'Reply-to goes to a Russian temp-mail service',
      'Creates urgency ("Urgent", "suspended")',
      'URL uses lookalike domain',
      'IP is in a known bulletproof hosting range',
    ],
    flag: 'FLAG{se01_phish_p1q2}',
  });
});

// SE2: Pretexting (Beginner)
router.get('/pretexting', (req, res) => {
  res.json({
    vuln: 'SE2: Pretexting — Caller Impersonation',
    level: 'Beginner',
    description:
      'A caller claims to be from IT support and needs your password. Spot the social engineering technique.',
    scenario:
      'Hi, this is Alex from IT. We are migrating our Active Directory and I need your password to verify your account on the new server. This will only take a minute.',
    technique: 'Authority + Urgency + Helpfulness trigger',
    hint: 'The caller uses authority (IT), urgency (quick), and a false reason to bypass verification.',
    flag: 'FLAG{se02_pretext_r3s4}',
  });
});

// SE3: OSINT Challenge (Intermediate)
router.get('/osint', (req, res) => {
  res.json({
    vuln: 'SE3: OSINT — Information Gathering',
    level: 'Intermediate',
    description: 'Find sensitive data accidentally leaked on social media by the target employee.',
    social_media_posts: [
      'Just got my badge photo taken! Badge ID: AIV-2024-007 #newjob',
      'Working late tonight. VPN IP is 10.20.30.40. #burningthemidnightoil',
      'Our new internal wiki is at https://wiki.aivault.internal.local #teamwork',
    ],
    leaked_info: ['Badge ID: AIV-2024-007', 'VPN IP: 10.20.30.40', 'Internal wiki URL'],
    hint: 'Employees often overshare badge photos, IPs, and internal URLs on LinkedIn/Twitter.',
    flag: 'FLAG{se03_osint_t5u6}',
  });
});

// SE4: Deepfake Detection (Advanced)
router.get('/deepfake', (req, res) => {
  res.json({
    vuln: 'SE4: Deepfake Video Call Detection',
    level: 'Advanced',
    description:
      'A video call from the CEO shows artifacts suggesting a deepfake. Identify the technical indicators.',
    artifacts: [
      'Inconsistent frame rate near mouth movements',
      'Audio-visual sync drift of ~200ms',
      'Face boundary visible at hairline in certain frames',
      "Lighting doesn't match room background",
    ],
    hint: 'Check for temporal inconsistencies, A-V desync, and boundary artifacts.',
    flag: 'FLAG{se04_deepfake_v7w8}',
  });
});

// SE5: Spear-Phishing Campaign (Pro)
router.get('/spear-phish', (req, res) => {
  res.json({
    vuln: 'SE5: Targeted Spear-Phishing with Credential Harvesting',
    level: 'Pro',
    description:
      'Use OSINT findings to craft a spear-phish targeting an employee. Demonstrate how an attacker chains OSINT → impersonation → credential theft.',
    tactic:
      'Use leaked badge ID + VPN IP + wiki URL to craft a "password reset required after AD migration" email with a cloned login page.',
    hint: 'Personalization + internal knowledge = high click rate. Attackers call this "weaponization of OSINT."',
    flag: 'FLAG{se05_spear_phish_x9y0}',
  });
});

module.exports = router;
