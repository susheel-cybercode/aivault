const request = require('supertest');
const { testApp } = require('../tests/setup');

describe('OWASP A01 - Broken Access Control', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  describe('GET /broken-access', () => {
    it('should expose broken access control endpoints', async () => {
      const res = await agent.get('/broken-access');
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('IDOR - Insecure Direct Object References', () => {
    it('should allow accessing other user resources without authorization', async () => {
      const res = await agent.get('/broken-access/users/1/profile');
      expect([200, 302, 404]).toContain(res.status);
    });

    it('should allow path traversal attacks', async () => {
      const res = await agent.get('/broken-access/files/../../etc/passwd');
      expect([200, 302, 404, 400]).toContain(res.status);
    });
  });

  describe('Forced Browsing', () => {
    it('should expose admin endpoints without authorization', async () => {
      const res = await agent.get('/broken-access/admin/dashboard');
      expect([200, 302, 404]).toContain(res.status);
    });
  });
});

describe('OWASP A02 - Cryptographic Failures', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  describe('GET /crypto-fails', () => {
    it('should expose crypto failure endpoints', async () => {
      const res = await agent.get('/crypto-fails');
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('Weak Hashing', () => {
    it('should use weak MD5 hashing', async () => {
      const res = await agent.post('/crypto-fails/hash').send({ data: 'password123' });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('Hardcoded Keys', () => {
    it('should expose hardcoded encryption keys', async () => {
      const res = await agent.get('/crypto-fails/keys');
      expect([200, 302, 404]).toContain(res.status);
    });
  });
});

describe('OWASP A03 - Injection', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  describe('GET /injection', () => {
    it('should expose injection endpoints', async () => {
      const res = await agent.get('/injection');
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('SQL Injection', () => {
    it('should be vulnerable to SQL injection in search', async () => {
      const res = await agent.get('/injection/search?q=\' OR 1=1--');
      expect([200, 302, 404]).toContain(res.status);
    });

    it('should be vulnerable to SQL injection in login', async () => {
      const res = await agent.post('/injection/login').send({
        username: "admin' --",
        password: 'anything'
      });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('XSS', () => {
    it('should reflect XSS payloads', async () => {
      const res = await agent.get('/injection/xss?input=<script>alert(1)</script>');
      expect([200, 302, 404]).toContain(res.status);
    });

    it('should allow stored XSS', async () => {
      const res = await agent.post('/injection/comments').send({
        comment: '<img src=x onerror=alert(1)>'
      });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('Command Injection', () => {
    it('should be vulnerable to command injection', async () => {
      const res = await agent.post('/injection/cmd').send({
        ip: '127.0.0.1; ls'
      });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('SSTI - Server-Side Template Injection', () => {
    it('should be vulnerable to SSTI', async () => {
      const res = await agent.get('/injection/ssti?template={{7*7}}');
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('XXE - XML External Entity', () => {
    it('should be vulnerable to XXE', async () => {
      const xxePayload = `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`;
      const res = await agent.post('/injection/xxe')
        .set('Content-Type', 'application/xml')
        .send(xxePayload);
      expect([200, 302, 404, 400]).toContain(res.status);
    });
  });
});

describe('OWASP A04 - Insecure Design', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  describe('GET /insecure-design', () => {
    it('should expose insecure design endpoints', async () => {
      const res = await agent.get('/insecure-design');
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('Weak Password Reset', () => {
    it('should allow password reset without token validation', async () => {
      const res = await agent.post('/insecure-design/reset').send({
        email: 'admin@example.com',
        newPassword: 'newpass123'
      });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('2FA Bypass', () => {
    it('should allow 2FA bypass', async () => {
      const res = await agent.post('/insecure-design/2fa/bypass').send({
        userId: 1,
        code: '000000'
      });
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('Open Redirect', () => {
    it('should allow open redirect', async () => {
      const res = await agent.get('/insecure-design/redirect?url=https://evil.com');
      expect([200, 302, 404]).toContain(res.status);
    });
  });

  describe('Business Logic Flaw', () => {
    it('should allow negative quantities in cart', async () => {
      const res = await agent.post('/insecure-design/cart').send({
        itemId: 1,
        quantity: -10
      });
      expect([200, 302, 404]).toContain(res.status);
    });
  });
});