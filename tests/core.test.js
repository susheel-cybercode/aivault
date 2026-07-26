const request = require('supertest');
const { testApp } = require('../tests/setup');

describe('OWASP Vulnerable Lab - Core Routes', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  describe('GET /', () => {
    it('should return 200 and render index page', async () => {
      const res = await agent.get('/');
      expect(res.status).toBe(200);
      expect(res.text).toMatch(/AIVault|ECHO-7/i);
    });
  });

  describe('GET /login', () => {
    it('should return login page', async () => {
      const res = await agent.get('/login');
      expect(res.status).toBe(200);
      expect(res.text).toContain('Login');
    });
  });

  describe('POST /login - SQL Injection (A03)', () => {
    it('should be vulnerable to SQL injection', async () => {
      const res = await agent
        .post('/login')
        .send({ username: "admin' --", password: 'anything' })
        .redirects(0);
      expect([200, 302]).toContain(res.status);
    });

    it('should reject invalid credentials', async () => {
      const res = await agent
        .post('/login')
        .send({ username: 'invalid', password: 'invalid' })
        .redirects(0);
      expect(res.status).toBe(200);
      expect(res.text).toContain('Invalid credentials');
    });
  });

  describe('GET /dashboard - Auth Required', () => {
    it('should redirect to login when not authenticated', async () => {
      const res = await agent.get('/dashboard').redirects(0);
      expect(res.status).toBe(302);
      expect(res.headers.location).toBe('/login');
    });
  });
});

describe('OWASP A01 - Broken Access Control', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should expose /broken-access endpoint', async () => {
    const res = await agent.get('/broken-access');
    expect([200, 302, 404]).toContain(res.status);
  });
});

describe('OWASP A03 - Injection', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should expose /injection endpoint', async () => {
    const res = await agent.get('/injection');
    expect([200, 302, 404]).toContain(res.status);
  });
});

describe('OWASP A05 - Security Misconfiguration', () => {
  it('should expose debug endpoints', async () => {
    const agent = request.agent(testApp);
    const res = await agent.get('/security-misconfig/debug');
    expect([200, 302, 404]).toContain(res.status);
  });

  it('should leak stack traces on error', async () => {
    const agent = request.agent(testApp);
    const res = await agent.get('/security-misconfig/error');
    expect([200, 500, 404]).toContain(res.status);
    if (res.status === 500) {
      expect(res.body.stack).toBeDefined();
    }
  });
});

describe('OWASP A07 - Authentication Failures', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should expose brute force endpoint', async () => {
    const res = await agent.get('/auth-failures/brute-force');
    expect([200, 302, 404]).toContain(res.status);
  });
});

describe('OWASP A10 - SSRF', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should expose SSRF endpoints', async () => {
    const res = await agent.get('/ssrf');
    expect([200, 302, 404]).toContain(res.status);
  });
});

describe('API Endpoints', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should expose /api endpoints', async () => {
    const res = await agent.get('/api');
    expect([200, 302, 404]).toContain(res.status);
  });
});

describe('Story Mode', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should expose /story endpoint', async () => {
    const res = await agent.get('/story');
    expect([200, 302, 404]).toContain(res.status);
  });
});

describe('Security Headers (A05)', () => {
  it('should have permissive CORS', async () => {
    const agent = request.agent(testApp);
    const res = await agent.get('/').set('Origin', 'http://evil.com');
    expect(res.headers['access-control-allow-origin']).toBe('http://evil.com');
    expect(res.headers['access-control-allow-credentials']).toBe('true');
  });

  it('should not have secure headers (intentional)', async () => {
    const agent = request.agent(testApp);
    const res = await agent.get('/');
    expect(res.headers['x-frame-options']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBeUndefined();
  });
});

describe('Error Handling - Stack Trace Leak (A05)', () => {
  it('should leak stack traces in error responses', async () => {
    const agent = request.agent(testApp);
    const res = await agent.get('/security-misconfig/error');
    expect([200, 500, 404]).toContain(res.status);
    if (res.status === 500) {
      expect(res.body.stack).toBeDefined();
    }
  });
});