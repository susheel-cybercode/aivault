/**
 * Reverse Engineering Module
 * Covers: Binary analysis, disassembly, decompilation, exploit dev
 * Difficulty: Beginner → Pro
 */

const express = require('express');
const router = express.Router();

router.get('/', (req, res) => {
  res.render('reverse/index', {
    title: 'Reverse Engineering',
    user: req.session?.user,
  });
});

// R1: String Extraction (Beginner)
router.get('/strings', (req, res) => {
  res.json({
    vuln: 'R1: String Extraction',
    level: 'Beginner',
    description:
      'Run `strings` on a binary to find hidden messages. Which string looks like a flag?',
    strings_extracted: [
      '/lib64/ld-linux-x86-64.so.2',
      'libc.so.6',
      'printf',
      'Hello, hacker!',
      'FLAG{?????}',
      '__gmon_start__',
    ],
    hint: 'Look for a string matching the FLAG{...} pattern.',
    flag: 'FLAG{rev01_strings_u1v2}',
  });
});

// R2: Crackme — Simple Password Check (Beginner)
router.post('/crackme', (req, res) => {
  const { password } = req.body;
  // Simulated disassembly:
  // mov eax, [password]
  // cmp eax, 0x64726177  ; "draw" reversed = "ward"
  const correct = 'ward';
  const isCorrect = password === correct;
  res.json({
    vuln: 'R2: Crackme — Simple Comparison',
    level: 'Beginner',
    description: 'Disassembly shows `cmp eax, 0x64726177`. Decode the hex and find the password.',
    disassembly: 'cmp DWORD PTR [rbp-0x10], 0x64726177',
    hint: '0x64726177 in little-endian ASCII spells "ward".',
    your_input: password || '(none)',
    correct: isCorrect,
    flag: isCorrect ? 'FLAG{rev02_crackme_w3x4}' : null,
  });
});

// R3: Buffer Overflow (Intermediate)
router.get('/buffer-overflow', (req, res) => {
  res.json({
    vuln: 'R3: Stack Buffer Overflow',
    level: 'Intermediate',
    description:
      'A 64-byte buffer is followed by the return address on the stack. Overwrite RIP to redirect execution.',
    disassembly:
      'lea rax, [rbp-0x40] ; buffer at rbp-0x40 (64 bytes)\n' +
      'mov rdi, rax\n' +
      'call gets          ; vulnerable — no bounds check',
    hint: 'Padding = 64 bytes + 8 bytes saved RBP = 72 bytes before return address.',
    flag: 'FLAG{rev03_bof_y5z6}',
  });
});

// R4: Anti-Debugging (Advanced)
router.get('/anti-debug', (req, res) => {
  res.json({
    vuln: 'R4: Anti-Debugging Evasion',
    level: 'Advanced',
    description: 'Binary uses ptrace(PTRACE_TRACEME) self-check. Bypass it to reveal the flag.',
    anti_debug_code:
      'if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {\n' +
      '  printf("Debugger detected!\n");\n' +
      '  exit(1);\n' +
      '}',
    hint: 'Patch the ptrace call to always return 0, or use LD_PRELOAD to hook ptrace.',
    flag: 'FLAG{rev04_anti_debug_a7b8}',
  });
});

// R5: Format String Vulnerability (Pro)
router.get('/format-string', (req, res) => {
  res.json({
    vuln: 'R5: Format String Exploitation',
    level: 'Pro',
    description: 'printf(user_input) allows reading/writing arbitrary memory via %n, %x, %p.',
    vulnerable_code: 'printf(argv[1]);  // no format specifier!',
    hint: 'Use %p to leak stack, then %n to write to the GOT entry of exit().',
    flag: 'FLAG{rev05_fmt_string_c9d0}',
  });
});

module.exports = router;
