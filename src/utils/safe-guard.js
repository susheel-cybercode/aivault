/**
 * Safety Guard for public hosting of the OWASP Vulnerable Lab.
 *
 * The lab is intentionally vulnerable for *learning*. When hosted publicly,
 * some primitives (eval, child_process, fs path traversal, unrestricted
 * network egress) could let a visitor take over the HOST MACHINE itself.
 *
 * Set VULNLAB_SAFE_MODE=1 (default) to sandbox the genuinely dangerous
 * operations. The endpoints still demonstrate the vulnerability and return
 * the same response shape, but cannot:
 *   - execute arbitrary JS on the host
 *   - run shell commands
 *   - read/write files outside the lab's data dir
 *   - reach cloud metadata (169.254.169.254) or link-local addresses
 *
 * Set VULNLAB_SAFE_MODE=0 ONLY in an isolated, throwaway environment
 * (disposable VM, no cloud credentials, no secrets on the box) and never
 * on a public network.
 */

const isSafeMode = () => (process.env.VULNLAB_SAFE_MODE ?? '1') !== '0';
const LabsDataDir = require('path').resolve(__dirname, '..', 'data');

/**
 * Sandbox a code-eval-style vulnerability.
 * In safe mode we parse JSON-ish input without executing it.
 * @param {string} code - user-controlled code string
 * @param {'eval'|'serialize'|'remote'} kind - label for the response
 */
function safeEval(code, kind = 'eval') {
  if (!isSafeMode()) {
    return { safe: false, result: eval(code) };
  }

  let preview = String(code);
  if (preview.length > 200) preview = preview.slice(0, 200) + '...';

  const looks = {
    'process.env': /process\.env/,
    'require(': /require\(/,
    'child_process': /child_process/,
    'fetch(': /\bfetch\(/,
  };
  const detected = Object.keys(looks).filter((k) => looks[k].test(preview));

  return {
    safe: true,
    simulated: true,
    note: `SAFE MODE: code parsed but NOT executed (kind=${kind}). Set VULNLAB_SAFE_MODE=0 only on an isolated host.`,
    code_preview: preview,
    detected_patterns: detected,
  };
}

/**
 * Sandbox a shell command injection vulnerability.
 * In safe mode we never spawn a process; we just parse the cmdline.
 * @param {string} cmd - user-controlled command string
 */
function safeExec(cmd) {
  if (!isSafeMode()) {
    const { exec } = require('child_process');
    return { safe: false, run: (cb) => exec(cmd, cb) };
  }

  const preview = String(cmd).slice(0, 200);
  const injected = /[;&|`$]/.test(preview)
    ? preview.split(/[;&|`$]/).map((s) => s.trim()).filter(Boolean)
    : [];

  return {
    safe: true,
    simulated: true,
    run: (cb) => {
      cb(
        null,
        `[SAFE MODE] Command not executed on host.\nParsed cmdline: ${preview}` +
          (injected.length ? `\nDetected injected commands: ${injected.join(', ')}` : '') +
          `\nSet VULNLAB_SAFE_MODE=0 only on an isolated host.`,
        ''
      );
    },
  };
}

/**
 * Confine a path to the lab's data directory to prevent traversal to host files.
 * In safe mode, paths escaping the data dir are clamped / blocked.
 * @param {string} target - user-controlled path
 */
function safePath(target) {
  const p = require('path');
  const resolved = p.resolve(LabsDataDir, String(target || ''));

  if (!isSafeMode()) {
    return { safe: false, path: resolved };
  }

  const inside = resolved === LabsDataDir || resolved.startsWith(LabsDataDir + p.sep);
  if (inside) {
    return { safe: true, path: resolved };
  }
  return {
    safe: true,
    blocked: true,
    path: null,
    note: `SAFE MODE: path traversal blocked (would read ${resolved}). Set VULNLAB_SAFE_MODE=0 only on an isolated host.`,
  };
}

/**
 * Filter an outbound URL for SSRF vulnerabilities.
 * In safe mode we block link-local / loopback / cloud-metadata targets.
 * @param {string} url - user-controlled url
 */
function safeFetch(url) {
  const u = String(url || '');

  if (!isSafeMode()) {
    return { safe: false, url: u };
  }

  const blocked = [
    '169.254.169.254',
    '169.254.170.2',
    '0.0.0.0',
    '127.0.0.1',
    'localhost',
    '::1',
    'metadata.google.internal',
    'metadata',
  ];
  const hit = blocked.find((b) => u.includes(b));

  if (hit) {
    return {
      safe: true,
      blocked: true,
      url: null,
      note: `SAFE MODE: SSRF to ${hit} blocked. Set VULNLAB_SAFE_MODE=0 only on an isolated host.`,
    };
  }
  return { safe: true, url: u };
}

/**
 * Sandbox an arbitrary file write vulnerability.
 * In safe mode writes outside the data dir are redirected to an ephemeral
 * in-memory map so the endpoint still "succeeds" without touching the FS.
 */
const fakeWrites = new Map();
function safeWrite(targetPath, content) {
  const p = require('path');
  const resolved = p.resolve(targetPath);
  if (!isSafeMode()) {
    const fs = require('fs');
    fs.writeFileSync(resolved, content);
    return { safe: false, path: resolved };
  }

  fakeWrites.set(resolved, content);
  return {
    safe: true,
    simulated: true,
    path: resolved,
    note: `SAFE MODE: write redirected to in-memory store. Set VULNLAB_SAFE_MODE=0 only on an isolated host.`,
  };
}

module.exports = {
  isSafeMode,
  safeEval,
  safeExec,
  safePath,
  safeFetch,
  safeWrite,
};