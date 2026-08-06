const { testApp, request } = require('./setup');

describe('OWASP Web Top 10 routes (A02–A10)', () => {
  const routes = [
    '/crypto-fails',
    '/injection',
    '/insecure-design',
    '/security-misconfig',
    '/vuln-components',
    '/auth-failures',
    '/integrity-fails',
    '/logging-fails',
    '/ssrf',
  ];

  let agent;
  beforeAll(() => {
    agent = request.agent(testApp);
  });

  routes.forEach((path) => {
    test(`GET ${path} responds successfully`, async () => {
      const res = await agent.get(path);
      expect(res.statusCode).toBeGreaterThanOrEqual(200);
      expect(res.statusCode).toBeLessThan(400);
    });
  });
});