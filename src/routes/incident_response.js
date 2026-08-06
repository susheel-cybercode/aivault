/**
 * Incident Response & Forensics Module (HackPath Pillar 4)
 * Covers: IR lifecycle (NIST), evidence handling, containment, eradication, lessons learned, malware triage
 * Difficulty: Beginner → Intermediate
 * Note: Complements the existing forensics.js (which covers technical artifacts)
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('incident_response/index', {
    title: 'Incident Response',
    user: req.session?.user,
  });
});

// IR1: NIST IR Lifecycle (Beginner)
router.get('/nist-lifecycle', (req, res) => {
  res.json({
    vuln: 'IR1: NIST Incident Response Lifecycle',
    level: 'Beginner',
    description:
      'The NIST SP 800-61 IR lifecycle has 4 phases. Know them cold — every IR plan follows this structure.',
    phases: [
      '1. Preparation — build the IR team, tools, runbooks, contact lists BEFORE an incident',
      '2. Detection & Analysis — identify the incident scope, gather logs, determine severity',
      '3. Containment, Eradication & Recovery — isolate, remove threat, restore systems',
      '4. Post-Incident Activity — lessons learned, update runbooks, improve detection',
    ],
    challenge: 'An attacker is actively exfiltrating data. Which NIST phase are you in?',
    hint: 'Active breach = Containment. You must stop the exfiltration first, then eradicate and recover.',
    flag: 'FLAG{ir_nist_containment_phase_ir1a0}',
  });
});

// IR2: Evidence Handling — Chain of Custody (Beginner)
router.get('/chain-of-custody', (req, res) => {
  res.json({
    vuln: 'IR2: Chain of Custody',
    level: 'Beginner',
    description:
      'Forensic evidence must be handled so it is admissible in court. Every transfer must be documented and the evidence must never be altered.',
    challenge: 'You seized a laptop at 14:00. List the chain-of-custody steps that must happen.',
    correct_steps: [
      'Photograph the device and document the scene',
      'Use a write-blocker before imaging the disk',
      'Create a forensic image (dd, FTK Imager)',
      'Compute SHA-256 hash of the original AND image',
      'Label, seal, and tag the evidence with case number',
      'Log every person who handles the evidence with timestamp',
    ],
    hint: 'Write-blocker + forensic image + hash + log every transfer = admissible chain of custody.',
    flag: 'FLAG{ir_chain_of_custody_writeblocker_ir2b1}',
  });
});

// IR3: Containment Strategy (Intermediate)
router.get('/containment', (req, res) => {
  res.json({
    vuln: 'IR3: Containment — Isolate Without Tipping Off the Attacker',
    level: 'Intermediate',
    description:
      'You detected a foothold in the network. If you disconnect the host immediately, the attacker may know they are detected and switch tactics. Choose your containment carefully.',
    scenario: {
      compromised_host: 'SRV-FIN-01 (10.0.5.20)',
      attacker_c2: '185.220.101.45',
      persistence: 'a Scheduled Task named "WindowsDefenderUpdate"',
      data_at_risk: 'financial records, customer PII',
    },
    options: [
      'A. Pull the network cable immediately (fastest containment)',
      'B. Blackhole the C2 IP at the firewall, leave the host online (silent containment — observe attacker)',
      'C. Remove the scheduled task and reboot (clean house fast)',
      'D. Do nothing until leadership approves',
    ],
    challenge: 'Which containment strategy preserves forensic evidence while cutting C2?',
    hint: 'B is correct — blackhole the C2 at the network edge. Host stays online for forensics; attacker loses control but cannot tell.',
    flag: 'FLAG{ir_blackhole_c2_silent_contain_ir3c2}',
  });
});

// IR4: Malware Triage (Intermediate)
router.get('/malware-triage', (req, res) => {
  res.json({
    vuln: 'IR4: Malware Triage — Static & Dynamic Anlaysis',
    level: 'Intermediate',
    description:
      'You found a suspicious executable on a compromised host. Triage it in order: static analysis first, then dynamic in a sandbox.',
    file: {
      name: 'update.exe',
      size: '245,760 bytes',
      first_seen: 'Unknown (no VT hits)',
      imports: ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'LoadLibraryA'],
      strings: ['cmd.exe', '/c', 'powershell -enc', 'http://185.220.101.45/beacon'],
    },
    challenge: 'What do the imports and strings tell you about this malware?',
    hint: 'CreateRemoteThread + VirtualAllocEx + WriteProcessMemory = process injection. /c powershell -enc = encoded PS payload. The URL is a C2 beacon. This is a loader/implant.',
    flag: 'FLAG{ir_malware_injection_beacon_ir4d3}',
  });
});

// IR5: Lessons Learned Report (Pro)
router.get('/lessons-learned', (req, res) => {
  res.json({
    vuln: 'IR5: Post-Incident — Lessons Learned Report',
    level: 'Pro',
    description:
      'After every incident, you write a lessons-learned report. The team found the initial breach came via a phishing email that bypassed the email filter. What should the report recommend?',
    incident_summary: {
      root_cause: 'Phishing email with macro-enabled attachment bypassed the email filter',
      dwell_time: '14 days',
      impact: '2,000 customer records exfiltrated',
      detection_gap: 'No alert on outbound data transfer over port 443 to new domain',
    },
    challenge: 'List 5 concrete recommendations to prevent a similar incident.',
    good_recommendations: [
      'Block all macro-enabled attachments from external senders',
      'Add egress filtering to detect large outbound transfers to new domains',
      'Disable macros by default via GPO',
      'Deploy EDR with behavioral detection (not just signatures)',
      'Run quarterly phishing simulations and retrain staff',
    ],
    hint: 'Fix the prevention gap (macros), the detection gap (egress monitoring), and the human gap (training).',
    flag: 'FLAG{ir_lessons_learned_macro_egress_ir5e4}',
  });
});

module.exports = router;
