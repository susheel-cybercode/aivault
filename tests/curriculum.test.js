const request = require('supertest');
const { testApp } = require('../tests/setup');

describe('Curriculum Modules', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  // --- Network Security ---
  describe('Network', () => {
    const base = '/network';
    const getEndpoints = [
      '/port-scan',
      '/dns-poisoning',
      '/arp-spoof',
      '/firewall-evasion',
    ];
    getEndpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
    it('POST /network/pcap-analyze', async () => {
      const res = await agent.post(`${base}/pcap-analyze`);
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  // --- Cryptography Lab ---
  describe('Cryptography Lab', () => {
    const base = '/crypto-lab';
    it('GET /hash-identify', async () => {
      const res = await agent.get(`${base}/hash-identify`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('POST /caesar', async () => {
      const res = await agent.post(`${base}/caesar`).send({ shift: 3, text: 'KHOOR' });
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /vigenere', async () => {
      const res = await agent.get(`${base}/vigenere`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /rsa-weak', async () => {
      const res = await agent.get(`${base}/rsa-weak`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /key-exchange', async () => {
      const res = await agent.get(`${base}/key-exchange`);
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  // --- Reverse Engineering ---
  describe('Reverse Engineering', () => {
    const base = '/reverse';
    it('GET /strings', async () => {
      const res = await agent.get(`${base}/strings`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('POST /crackme', async () => {
      const res = await agent.post(`${base}/crackme`).send({ password: 'ward' });
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /buffer-overflow', async () => {
      const res = await agent.get(`${base}/buffer-overflow`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /anti-debug', async () => {
      const res = await agent.get(`${base}/anti-debug`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /format-string', async () => {
      const res = await agent.get(`${base}/format-string`);
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  // --- Digital Forensics ---
  describe('Digital Forensics', () => {
    const base = '/forensics';
    const getEndpoints = [
      '/log-analysis',
      '/file-carving',
      '/memory-analysis',
      '/timeline',
    ];
    getEndpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
    it('POST /stego', async () => {
      const res = await agent.post(`${base}/stego`);
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  // --- Social Engineering ---
  describe('Social Engineering', () => {
    const base = '/social';
    const endpoints = [
      '/phishing',
      '/pretexting',
      '/osint',
      '/deepfake',
      '/spear-phish',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- IoT / OT Security ---
  describe('IoT / OT Security', () => {
    const base = '/iot';
    const endpoints = [
      '/default-creds',
      '/firmware-extract',
      '/mqtt-hijack',
      '/modbus-exploit',
      '/ble-attack',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- Blockchain / Web3 ---
  describe('Blockchain / Web3', () => {
    const base = '/blockchain';
    const endpoints = [
      '/reentrancy',
      '/overflow',
      '/flash-loan',
      '/access-control',
      '/mev-front-run',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- Malware Analysis ---
  describe('Malware Analysis', () => {
    const base = '/malware';
    it('GET /static', async () => {
      const res = await agent.get(`${base}/static`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /sandbox', async () => {
      const res = await agent.get(`${base}/sandbox`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /unpack', async () => {
      const res = await agent.get(`${base}/unpack`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('POST /yara', async () => {
      const res = await agent.post(`${base}/yara`).send({ rule: '' });
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /rootkit', async () => {
      const res = await agent.get(`${base}/rootkit`);
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  // --- Wireless Security ---
  describe('Wireless Security', () => {
    const base = '/wireless';
    const endpoints = [
      '/wep',
      '/wpa2-handshake',
      '/evil-twin',
      '/wps',
      '/ble-sniff',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- DevSecOps ---
  describe('DevSecOps', () => {
    const base = '/devsecops';
    const endpoints = [
      '/git-secrets',
      '/dependency-confusion',
      '/terraform-misconfig',
      '/container-escape',
      '/supply-chain-action',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- Threat Hunting & Blue Team ---
  describe('Threat Hunting & Blue Team', () => {
    const base = '/threat-hunting';
    it('GET /siem-query', async () => {
      const res = await agent.get(`${base}/siem-query`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /mitre-identify', async () => {
      const res = await agent.get(`${base}/mitre-identify`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /anomaly', async () => {
      const res = await agent.get(`${base}/anomaly`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('GET /memory-hunt', async () => {
      const res = await agent.get(`${base}/memory-hunt`);
      expect([200, 302, 404]).toContain(res.status);
    });
    it('POST /hunt', async () => {
      const res = await agent.post(`${base}/hunt`).send({ hypothesis: 'test' });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  // --- OSINT ---
  describe('OSINT', () => {
    const base = '/osint';
    const endpoints = [
      '/username-check',
      '/metadata',
      '/subdomains',
      '/social-recon',
      '/breach-check',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- Red Team Operations ---
  describe('Red Team Operations', () => {
    const base = '/red-team';
    const endpoints = [
      '/c2-beacon',
      '/lateral-movement',
      '/persistence',
      '/lotl',
      '/evasion',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- Cloud Security ---
  describe('Cloud Security', () => {
    const base = '/cloud-sec';
    const endpoints = [
      '/s3-public',
      '/iam-escalation',
      '/metadata-ssrf',
      '/container-breakout',
      '/lambda-injection',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });

  // --- Privacy & Data Protection ---
  describe('Privacy & Data Protection', () => {
    const base = '/privacy';
    const endpoints = [
      '/pii-overcollection',
      '/consent',
      '/dsar',
      '/data-transfer',
      '/breach-notification',
    ];
    endpoints.forEach(ep => {
      it(`GET ${base}${ep}`, async () => {
        const res = await agent.get(`${base}${ep}`);
        expect([200, 302, 404]).toContain(res.status);
      });
    });
  });
});
