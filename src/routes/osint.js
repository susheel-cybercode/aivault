/**
 * OSINT (Open Source Intelligence) Module
 * Covers: Recon, username enumeration, metadata, leaks, social media scraping
 * Difficulty: Beginner -> Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('osint/index', {
    title: 'OSINT',
    user: req.session?.user,
  });
});

// O1: Username Enumeration Across Platforms (Beginner)
router.get('/username-check', (req, res) => {
  res.json({
    vuln: 'O1: Username Enumeration Across Platforms',
    level: 'Beginner',
    description:
      'Use tools like Sherlock or namechk to find where a username is registered across 300+ platforms.',
    target_username: 'targetuser_aivault',
    platforms_found: [
      { site: 'github.com', url: 'https://github.com/targetuser_aivault', exists: true },
      { site: 'twitter.com', url: 'https://twitter.com/targetuser_aivault', exists: true },
      { site: 'reddit.com', url: 'https://reddit.com/user/targetuser_aivault', exists: true },
      { site: 'instagram.com', url: 'https://instagram.com/targetuser_aivault', exists: false },
      { site: 'linkedin.com', url: 'https://linkedin.com/in/targetuser_aivault', exists: true },
    ],
    hint: 'sherlock targetuser_aivault --print-found',
    flag: 'FLAG{osint01_username_enum_b2c3}',
  });
});

// O2: Metadata Extraction from Documents (Beginner)
router.get('/metadata', (req, res) => {
  res.json({
    vuln: 'O2: Metadata Extraction (EXIF/Document Properties)',
    level: 'Beginner',
    description:
      'Documents and images often contain hidden metadata (author, GPS, device info). Use exiftool to extract.',
    file_metadata: {
      filename: 'quarterly_report.pdf',
      author: 'internal-dev@company.com',
      created: '2024-03-15 14:32:11',
      modified: '2024-03-18 08:15:00',
      software: 'Microsoft Word 365',
      gps: '40.7128, -74.0060 (New York office)',
      device: 'iPhone 15 Pro',
    },
    hint: 'exiftool quarterly_report.pdf | grep -i author',
    flag: 'FLAG{osint02_metadata_leak_d4e5}',
  });
});

// O3: DNS & Subdomain Enumeration (Intermediate)
router.get('/subdomains', (req, res) => {
  res.json({
    vuln: 'O3: Subdomain Enumeration via Passive DNS',
    level: 'Intermediate',
    description:
      'Discover hidden subdomains using certificate transparency logs, DNS brute force, and passive DNS.',
    domain: 'aivault-target.com',
    subdomains: [
      { subdomain: 'api.aivault-target.com', ip: '10.0.1.50', source: 'crt.sh' },
      { subdomain: 'dev.aivault-target.com', ip: '10.0.1.51', source: 'amass' },
      { subdomain: 'staging.aivault-target.com', ip: '10.0.1.52', source: 'subfinder' },
      { subdomain: 'vpn.aivault-target.com', ip: '10.0.1.53', source: 'crt.sh' },
      { subdomain: 'old-stage.aivault-target.com', ip: '10.0.1.54', source: 'wayback' },
    ],
    hint: 'curl -s "https://crt.sh/?q=aivault-target.com&output=json" | jq',
    flag: 'FLAG{osint03_subdomain_enum_f6g7}',
  });
});

// O4: Social Media Intelligence (Advanced)
router.get('/social-recon', (req, res) => {
  res.json({
    vuln: 'O4: Social Media Intelligence Gathering',
    level: 'Advanced',
    description:
      'Build a target profile by correlating posts, geolocation, connections, and timestamps across social platforms.',
    target: {
      name: 'Jane Developer',
      employer: 'AIVault Corp',
      role: 'Senior Engineer',
      location: 'San Francisco, CA',
      interests: ['machine learning', 'rock climbing', 'home networking'],
      recent_posts: [
        {
          platform: 'Twitter',
          date: '2024-03-20',
          text: 'Just deployed our new microservice to staging! #devops',
        },
        {
          platform: 'GitHub',
          date: '2024-03-18',
          text: 'Pushed commit to internal-repo/aivault-api at 18:42',
        },
        {
          platform: 'Reddit',
          date: '2024-03-15',
          text: 'Best home lab switch for VLAN segmentation?',
        },
      ],
      inferred_info: 'Works on microservices, uses staging environment, has a home lab with VLANs',
    },
    hint: 'Cross-reference timestamps + locations + technical posts to infer infrastructure details.',
    flag: 'FLAG{osint04_social_recon_h8i9}',
  });
});

// O5: Dark Web & Breach Data Monitoring (Pro)
router.get('/breach-check', (req, res) => {
  res.json({
    vuln: 'O5: Credential Leak & Breach Database Monitoring',
    level: 'Pro',
    description:
      'Check if target credentials appear in known breaches using HaveIBeenPwned, DeHashed, or breach databases.',
    target_email: 'cto@aivault-target.com',
    breaches: [
      { breach: 'LinkedIn 2021', data_types: ['email', 'name', 'job_title'], count: '700M' },
      { breach: 'Adobe 2013', data_types: ['email', 'password_hint'], count: '153M' },
      { breach: 'Collection #1', data_types: ['email', 'password'], count: '773M' },
    ],
    exposed_passwords: ['summer2021!', 'Aivault$$$2023', 'P@ssw0rd!'],
    hint: 'Use haveibeenpwned API or dehashed.com to correlate breaches with corporate credentials.',
    flag: 'FLAG{osint05_breach_correlation_j0k1}',
  });
});

module.exports = router;
