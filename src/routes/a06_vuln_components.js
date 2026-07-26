/**
 * A06:2021 – Vulnerable and Outdated Components
 *
 * Vulnerabilities demonstrated:
 * - Known vulnerable versions of libraries (simulated)
 * - Missing dependency checks
 * - Outdated software with known CVEs
 * - Unpatched known issues
 * - Using end-of-life components
 */

const express = require('express');
const router = express.Router();
const { exec } = require('child_process');
const { safeEval } = require('../utils/safe-guard');

function getDb() {
  return require('../db');
}

router.get('/', (req, res) => {
  const vulnComponents = [
    {
      name: 'lodash',
      version: '4.17.20',
      known_issues: ['CVE-2021-23337 - Command Injection via template', 'Prototype Pollution'],
      status: 'VULNERABLE',
    },
    {
      name: 'express',
      version: '4.18.2',
      known_issues: ['Multiple CVEs in dependencies'],
      status: 'VULNERABLE',
    },
    {
      name: 'jsonwebtoken',
      version: '8.5.1',
      known_issues: ['JWT algorithm confusion (CVE-2022-23529)', 'None algorithm attack'],
      status: 'VULNERABLE',
    },
    {
      name: 'sqlite3',
      version: '5.1.7',
      known_issues: ['CVE-2023-7104', 'Potential memory corruption'],
      status: 'VULNERABLE',
    },
    {
      name: 'multer',
      version: '1.4.5-lts.1',
      known_issues: ['CVE-2022-24434 - Directory traversal'],
      status: 'VULNERABLE',
    },
    {
      name: 'axios',
      version: '1.6.0',
      known_issues: ['CVE-2023-45857 - XSRF token leakage'],
      status: 'VULNERABLE',
    },
  ];

  res.render('vuln_components/index', { title: 'A06 - Vulnerable Components', vulnComponents });
});

// Try to download & evaluate arbitrary code from remote
router.get('/eval-remote', (req, res) => {
  const axios = require('axios');
  const { url } = req.query;

  if (url) {
    axios
      .get(url)
      .then((response) => {
        try {
          // A06: Eval'ing remote code (sandboxed when AIVAULT_SAFE_MODE=1)
          const r = safeEval(response.data, 'remote');
          if (r.simulated) return res.json({ success: true, result: r });
          return res.json({ success: true, result: r.result });
        } catch (e) {
          res.json({ error: 'eval failed: ' + e.message });
        }
      })
      .catch((e) => res.json({ error: e.message }));
  } else {
    res.send(
      '<form><input name="url" placeholder="URL to download & eval"><button>Execute</button></form>'
    );
  }
});

// Deserialization vulnerability
router.post('/deserialize', (req, res) => {
  const data = req.body.data;
  try {
    // A06: Unsafe deserialization (sandboxed when AIVAULT_SAFE_MODE=1)
    const r = safeEval(data, 'serialize');
    if (r.simulated) return res.json({ deserialized: r });
    return res.json({ deserialized: r.result });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// Use package with known prototype pollution
router.get('/merge-objects', (req, res) => {
  const obj1 = JSON.parse(req.query.obj1 || '{"a":1}');
  const obj2 = JSON.parse(req.query.obj2 || '{"b":2}');

  // Vulnerable merge (simulated lodash merge)
  function merge(target, source) {
    for (const key in source) {
      if (typeof source[key] === 'object') {
        if (!target[key]) target[key] = {};
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }

  const merged = merge(obj1, obj2);
  res.json({ merged, hidden_flag: 'FLAG{proto_pollute_a06_7d3e9}' });
});

module.exports = router;
