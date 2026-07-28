/**
 * A10:2021 – Server-Side Request Forgery (SSRF)
 *
 * Vulnerabilities demonstrated:
 * - SSRF via URL fetcher
 * - SSRF via file downloader
 * - SSRF via image proxy
 * - SSRF via webhook validator
 * - SSRF via PDF/image generator
 * - Blind SSRF
 * - Internal port scanning
 * - Cloud metadata endpoint access
 */

const express = require('express');
const router = express.Router();
const axios = require('axios');
const net = require('net');
const { safeFetch } = require('../utils/safe-guard');

router.get('/', (req, res) => {
  res.render('ssrf/index', { title: 'A10 - SSRF' });
});

// Basic SSRF: URL Fetcher
router.get('/fetch', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.render('ssrf/fetch', { title: 'SSRF - URL Fetcher', result: null });
  }

  try {
    // A10: No URL validation, allows internal addresses (sandboxed in safe mode)
    const sc = safeFetch(url);
    if (sc.blocked) {
      return res.json({ error: sc.note, hint: 'Metadata address blocked in safe mode' });
    }
    const response = await axios.get(sc.url, {
      timeout: 5000,
      validateStatus: () => true,
      maxRedirects: 10,
      withCredentials: true,
    });

    const db = require('../db');
    db.prepare('INSERT INTO logs (level, message, ip) VALUES (?,?,?)').run(
      'INFO',
      `SSRF fetch to: ${url}, status: ${response.status}`,
      req.ip
    );

    res.json({
      status: response.status,
      headers: response.headers,
      data: typeof response.data === 'string' ? response.data.substring(0, 5000) : response.data,
      size:
        typeof response.data === 'string'
          ? response.data.length
          : JSON.stringify(response.data).length,
    });
  } catch (e) {
    res.json({ error: e.message, hint: 'Try http://169.254.169.254/latest/meta-data/' });
  }
});

// Port Scanning via SSRF
router.get('/port-scan', async (req, res) => {
  const { host, port } = req.query;

  if (host && port) {
    try {
      await new Promise((resolve, reject) => {
        const socket = net.createConnection(parseInt(port), host, () => {
          socket.end();
          resolve();
        });
        socket.setTimeout(3000);
        socket.on('error', reject);
        socket.on('timeout', () => {
          socket.destroy();
          reject(new Error('timeout'));
        });
      });
      res.json({ host, port, open: true });
    } catch (e) {
      res.json({ host, port, open: false, error: e.message });
    }
  } else {
    res.render('ssrf/scan', { title: 'SSRF - Port Scanner' });
  }
});

// Image Proxy - SSRF via image URL
router.get('/image-proxy', (req, res) => {
  const { url } = req.query;

  if (url) {
    axios
      .get(url, { responseType: 'arraybuffer', timeout: 5000 })
      .then((response) => {
        const contentType = response.headers['content-type'] || 'image/png';
        res.contentType(contentType);
        res.send(response.data);
      })
      .catch((e) => res.json({ error: e.message }));
  } else {
    res.render('ssrf/image_proxy', { title: 'Image Proxy SSRF' });
  }
});

// Webhook Validation - SSRF
router.post('/webhook-test', async (req, res) => {
  const { url } = req.body;

  if (url) {
    try {
      // A10: SSRF via webhook testing - allows internal IP
      const response = await axios.post(
        url,
        {
          event: 'webhook.test',
          timestamp: new Date().toISOString(),
          data: { message: 'Webhook verification ping' },
        },
        { timeout: 5000 }
      );

      res.json({
        url,
        status: response.status,
        valid: response.status === 200,
        response:
          typeof response.data === 'object' ? response.data : response.data?.substring(0, 1000),
      });
    } catch (e) {
      res.json({ error: e.message });
    }
  } else {
    res.json({ error: 'URL required' });
  }
});

module.exports = router;
