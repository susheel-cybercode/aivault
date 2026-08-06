/**
 * Technical Foundations Module (HackPath Pillar 1)
 * Covers: Computer Architecture, Data Representation, OS Fundamentals,
 *         Networking Basics, Cybersecurity Principles
 * Difficulty: Beginner
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('foundations/index', {
    title: 'Technical Foundations',
    user: req.session?.user,
  });
});

// F1: Binary & Hexadecimal (Beginner)
router.get('/binary', (req, res) => {
  res.json({
    vuln: 'F1: Data Representation — Binary & Hex',
    level: 'Beginner',
    description:
      'Computers store everything as binary. Learn to convert between decimal, binary, and hex — the language of memory addresses and payloads.',
    challenge: 'Convert the decimal number 255 to hexadecimal. Then convert 0xDEAD to binary.',
    walkthrough:
      '255 in hex = 0xFF (since 255 = 15*16 + 15). 0xDEAD = 1101 1110 1010 1101 in binary.',
    hint: 'Each hex digit = 4 bits. D=1101, E=1110, A=1010, D=1101.',
    flag: 'FLAG{foundations_binary_ff_dead_f1a0}',
  });
});

// F2: OS Fundamentals — Linux Commands (Beginner)
router.get('/linux-fundamentals', (req, res) => {
  res.json({
    vuln: 'F2: Operating Systems — Linux Fundamentals',
    level: 'Beginner',
    description:
      'Every hacker needs Linux. Practice the core commands: ls, cd, cat, grep, find, chmod, ps, netstat.',
    challenge: 'What command finds all files owned by root with SUID set in /usr/bin?',
    walkthrough: 'find /usr/bin -user root -perm -u=s -type f 2>/dev/null',
    hint: 'find /usr/bin -user root -perm /4000',
    flag: 'FLAG{foundations_linux_suid_find_f2b1}',
  });
});

// F3: Networking — OSI Model & Ports (Beginner)
router.get('/networking', (req, res) => {
  res.json({
    vuln: 'F3: Networking — OSI Model & Common Ports',
    level: 'Beginner',
    description:
      'The OSI model has 7 layers. Security work requires knowing which layer an attack targets and what protocols run on which ports.',
    challenge:
      'Which OSI layer does a SYN flood target? What port does DNS use by default (TCP+UDP)?',
    walkthrough:
      'SYN flood = Layer 4 (Transport). DNS = port 53 (both TCP and UDP). A SYN flood is a Transport-layer DoS because it exhausts TCP connection state.',
    hint: 'Layer 4 = Transport. DNS = 53. SYN = TCP handshake.',
    flag: 'FLAG{foundations_osi_layer4_dns53_f3c2}',
  });
});

// F4: Cryptography Fundamentals (Beginner)
router.get('/crypto-basics', (req, res) => {
  res.json({
    vuln: 'F4: Cryptography — Hashing vs Encryption',
    level: 'Beginner',
    description:
      'Hashing = one-way (integrity). Encryption = reversible (confidentiality). Signatures combine both for authenticity.',
    challenge:
      'What is the SHA-256 hash of the string "AIVault"? Why can you not "decrypt" a hash?',
    walkthrough:
      'Hashes are deterministic one-way functions. You cannot reverse them — you can only brute-force inputs until the hash matches. SHA-256 of "AIVault" = 3a7b... (compute with: echo -n "AIVault" | sha256sum).',
    hint: 'echo -n "AIVault" | sha256sum — Hashes are irreversible by design.',
    flag: 'FLAG{foundations_hash_oneway_f4d3}',
  });
});

// F5: Security Principles — CIA Triad (Beginner)
router.get('/cia-triad', (req, res) => {
  res.json({
    vuln: 'F5: Security Principles — CIA Triad & AAA',
    level: 'Beginner',
    description:
      'Confidentiality, Integrity, Availability — the triad. Plus Authentication, Authorization, Accounting (AAA). Every vulnerability breaks one of these.',
    challenge:
      'A ransomware attack encrypts files and demands payment. Which CIA pillars does it violate?',
    walkthrough:
      'Ransomware violates Availability (files are inaccessible) and potentially Integrity (files are modified). Confidentiality may be breached if data is exfiltrated first (double extortion).',
    hint: 'Availability = you cannot use the data. Integrity = the data was modified.',
    flag: 'FLAG{foundations_cia_ransomware_f5e4}',
  });
});

module.exports = router;
