/**
 * Digital Forensics Module
 * Covers: Disk imaging, memory analysis, log forensics, timeline creation
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('forensics/index', {
    title: 'Digital Forensics',
    user: req.session?.user,
  });
});

// F1: Log Analysis (Beginner)
router.get('/log-analysis', (req, res) => {
  res.json({
    vuln: 'F1: Apache Access Log Analysis',
    level: 'Beginner',
    description: 'Identify the SQL injection attempt in these access log entries.',
    logs: [
      '10.0.0.5 - - "GET /search?q=laptop HTTP/1.1" 200 4092',
      '10.0.0.5 - - "GET /search?q=test HTTP/1.1" 200 4092',
      '10.0.0.99 - - "GET /search?q=\' OR 1=1-- HTTP/1.1" 200 8192',
      '10.0.0.5 - - "GET /about HTTP/1.1" 200 2048',
    ],
    hint: 'Look for the single quote and OR 1=1 pattern from the unusual IP.',
    flag: 'FLAG{for01_sqli_log_e1f2}',
  });
});

// F2: File Carving (Beginner)
router.get('/file-carving', (req, res) => {
  res.json({
    vuln: 'F2: File Carving — Recover Deleted Files',
    level: 'Beginner',
    description: 'A disk image has deleted files. Match file signatures to recover them.',
    signatures: [
      { hex: 'FF D8 FF E0', type: 'JPEG' },
      { hex: '25 50 44 46', type: 'PDF' },
      { hex: '50 4B 03 04', type: 'ZIP/PK' },
      { hex: '89 50 4E 47', type: 'PNG' },
    ],
    hint: 'Use foremost or photorec to carve files by magic bytes.',
    flag: 'FLAG{for02_carve_g3h4}',
  });
});

// F3: Memory Dump Analysis (Intermediate)
router.get('/memory-analysis', (req, res) => {
  res.json({
    vuln: 'F3: Volatility Memory Analysis',
    level: 'Intermediate',
    description: 'A RAM dump has suspicious processes. Find the injected shellcode.',
    volatility_output: [
      'Offset(P)  Name                 PID   PPID',
      '---------- ----                 ---   ----',
      '0x108      explorer.exe         1784  1700',
      '0x232      svchost.exe          892   660',
      '0x456      svchost.exe          994   892    ← suspicious: non-standard parent',
      '0x578      cmd.exe              2980  994    ← spawned by suspicious svchost',
    ],
    hint: 'The second svchost has PID 994 and parent 892 (another svchost), then spawns cmd.exe.',
    flag: 'FLAG{for03_memory_i5j6}',
  });
});

// F4: Timeline Creation (Advanced)
router.get('/timeline', (req, res) => {
  res.json({
    vuln: 'F4: Timeline Reconstruction',
    level: 'Advanced',
    description: 'Reconstruct the attack timeline from filesystem metadata (mactime output).',
    timeline: [
      '2024-01-15 09:00:00  /tmp/.cache/scan  (created)',
      '2024-01-15 09:02:14  /etc/passwd       (accessed)',
      '2024-01-15 09:02:15  /etc/shadow       (accessed)',
      '2024-01-15 09:03:00  /tmp/.cache/payload.bin (created)',
      '2024-01-15 09:03:05  /bin/login        (modified)',
    ],
    hint: 'Attacker scanned, read password files, dropped payload, replaced login binary.',
    flag: 'FLAG{for04_timeline_k7l8}',
  });
});

// F5: Steganography (Pro)
router.post('/stego', (req, res) => {
  const { image } = req.body;
  res.json({
    vuln: 'F5: Steganography Detection',
    level: 'Pro',
    description:
      'A PNG image contains embedded data in the LSB of pixel values. Extract the hidden message.',
    method: 'LSB steganography in alpha channel',
    image_provided: image || '(none)',
    hint: 'Use zsteg or stegsolve to inspect the least significant bits.',
    flag: 'FLAG{for05_stego_m9n0}',
  });
});

module.exports = router;
