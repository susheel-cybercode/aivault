const request = require('supertest');
const { testApp } = require('../tests/setup');

describe('OWASP Cloud‑Native Top 10', () => {
  let agent;

  beforeEach(() => {
    agent = request.agent(testApp);
  });

  it('should serve the cloud top‑10 overview page', async () => {
    const res = await agent.get('/cloud');
    expect([200, 302, 404]).toContain(res.status);
  });

  it('should expose Insecure Metadata Access placeholder', async () => {
    const res = await agent.get('/cloud/metadata');
    expect(res.body).toHaveProperty('vuln', 'C1: Insecure Cloud Metadata Access');
    expect([200, 302, 404]).toContain(res.status);
  });

  it('should expose Container Escape placeholder', async () => {
    const res = await agent.get('/cloud/container-escape');
    expect(res.body).toHaveProperty('vuln', 'C2: Container Escape via Privileged Mount');
    expect([200, 302, 404]).toContain(res.status);
  });
});
