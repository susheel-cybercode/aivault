/**
 * Cryptography Deep-Dive Module
 * Covers: Hashing, symmetric/asymmetric, key exchange, PKI, steganography
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('crypto/index', {
    title: 'Cryptography Lab',
    user: req.session?.user,
  });
});

// C1: Hash Identification (Beginner)
router.get('/hash-identify', (req, res) => {
  res.json({
    vuln: 'C1: Hash Identification',
    level: 'Beginner',
    description: 'Identify the hash algorithm used for each hash below.',
    hashes: [
      { hash: '5d41402abc4b2a76b9719d911017c592', algorithm: 'MD5' },
      { hash: 'aaf4c61ddcc5e8a2dabede0f3b482cd9', algorithm: 'SHA-1' },
      { hash: '2c26b46b68ffc68ff8ddc7f485f', algorithm: 'SHA-256 (truncated)' },
    ],
    hint: 'MD5 = 32 hex, SHA-1 = 40 hex, SHA-256 = 64 hex.',
    flag: 'FLAG{crypto01_hash_id_k1l2}',
  });
});

// C2: Caesar Cipher (Beginner)
router.post('/caesar', (req, res) => {
  const { shift, text } = req.body;
  const ciphertext = text || 'KHOOR ZRUOG';
  const s = parseInt(shift, 10) || 3;
  const result = ciphertext.replace(/[A-Z]/gi, (c) => {
    const base = c >= 'a' && c <= 'z' ? 97 : 65;
    return String.fromCharCode(((c.charCodeAt(0) - base - s + 26) % 26) + base);
  });
  res.json({
    vuln: 'C2: Caesar Cipher',
    level: 'Beginner',
    description: 'Decrypt a Caesar-shifted message. Try brute-forcing all 25 shifts.',
    ciphertext: ciphertext,
    shift: s,
    plaintext: result,
    flag: 'FLAG{crypto02_caesar_m3n4}',
  });
});

// C3: Vigenere Cipher (Intermediate)
router.get('/vigenere', (req, res) => {
  res.json({
    vuln: 'C3: Vigenere Cipher',
    level: 'Intermediate',
    description:
      'A polyalphabetic cipher. Use Kasiski examination or index of coincidence to find key length.',
    ciphertext: 'RIJVS AMBPP KBR VXKGN RMLLPZ',
    hint: 'Repeated trigraphs suggest a key length of 4-6.',
    flag: 'FLAG{crypto03_vigenere_o5p6}',
  });
});

// C4: RSA Weak Key (Advanced)
router.get('/rsa-weak', (req, res) => {
  res.json({
    vuln: 'C4: RSA with Small Prime Factors',
    level: 'Advanced',
    description: 'An RSA key uses 512-bit primes. Factor the modulus to recover the private key.',
    n: '88071793294194026117866586998982589',
    e: 65537,
    hint: 'Use msieve or yafu to factor n. Primes are < 2^26.',
    flag: 'FLAG{crypto04_rsa_factor_q7r8}',
  });
});

// C5: Key Exchange (Pro)
router.get('/key-exchange', (req, res) => {
  res.json({
    vuln: 'C5: Diffie-Hellman Weak Parameters',
    level: 'Pro',
    description: 'DH uses a 512-bit prime (Logjam attack). Recover the shared secret.',
    p: '0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1',
    g: 2,
    hint: 'Use the Logjam precomputation attack for 512-bit export-grade DH.',
    flag: 'FLAG{crypto05_logjam_s9t0}',
  });
});

module.exports = router;
