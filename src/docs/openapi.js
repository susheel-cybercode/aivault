/**
 * OpenAPI 3.0 specification for the OWASP Vulnerable Lab API
 * This document describes all intentionally vulnerable endpoints
 */
const swaggerSpec = {
  openapi: '3.0.3',
  info: {
    title: 'AIVault ECHO-7 API',
    description:
      'INTENTIONALLY VULNERABLE - For educational/CTF use only. ' +
      'Covers OWASP Top 10 across Web, API, Mobile, and LLM applications. ' +
      'Each endpoint is a "vault seal" in the ECHO-7 story. ' +
      'Exploit (Null Collective) or audit (Aegis Wardens) them.',
    version: '1.0.0',
    license: {
      name: 'MIT',
      url: 'https://opensource.org/licenses/MIT',
    },
    contact: {
      name: 'OWASP Vulnerable Lab',
      url: 'https://github.com/susheel-cybercode/aivault',
    },
  },
  servers: [
    { url: '/', description: 'Local server' },
    { url: 'https://owasp-vulnerable-lab.onrender.com', description: 'Render deployment' },
  ],
  tags: [
    { name: 'A01-Access', description: 'Broken Access Control' },
    { name: 'A02-Crypto', description: 'Cryptographic Failures' },
    { name: 'A03-Injection', description: 'Injection flaws' },
    { name: 'A04-Design', description: 'Insecure Design' },
    { name: 'A05-Misconfig', description: 'Security Misconfiguration' },
    { name: 'A06-Components', description: 'Vulnerable Components' },
    { name: 'A07-Auth', description: 'Authentication Failures' },
    { name: 'A08-Integrity', description: 'Integrity Failures' },
    { name: 'A09-Logging', description: 'Logging and Monitoring Failures' },
    { name: 'A10-SSRF', description: 'Server-Side Request Forgery' },
    { name: 'API', description: 'OWASP API Top 10 (2023)' },
    { name: 'Mobile', description: 'OWASP Mobile Top 10 (2024)' },
    { name: 'LLM', description: 'OWASP LLM Top 10 (2025)' },
    { name: 'Story', description: 'ECHO-7 Story mode' },
  ],
  components: {
    securitySchemes: {
      sessionAuth: {
        type: 'apiKey',
        in: 'cookie',
        name: 'connect.sid',
      },
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
    },
  },
  paths: {
    '/': {
      get: {
        tags: ['Core'],
        summary: 'Homepage - Lab index',
        responses: { 200: { description: 'HTML page' } },
      },
    },
    '/login': {
      get: {
        tags: ['Core'],
        summary: 'Login form (SQLi vulnerable)',
        responses: { 200: { description: 'HTML page' } },
      },
      post: {
        tags: ['A03-Injection'],
        summary: 'Login (VULNERABLE to SQL injection)',
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: { type: 'string' },
                  password: { type: 'string' },
                },
              },
            },
          },
        },
        responses: {
          200: { description: 'Login failed' },
          302: { description: 'Login success - redirect to dashboard' },
        },
      },
    },
    '/api/b1/users/{id}/profile': {
      get: {
        tags: ['API'],
        summary: 'API1 - BOLA: Read user profile without auth',
        parameters: [{ in: 'path', name: 'id', required: true, schema: { type: 'integer' } }],
        responses: {
          200: { description: 'User profile (IDOR vulnerable)' },
          404: { description: 'Not found' },
        },
      },
    },
    '/api/b3/users': {
      post: {
        tags: ['API'],
        summary: 'API3 - Mass Assignment: create user (pass role:admin)',
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  username: { type: 'string' },
                  password: { type: 'string' },
                  role: { type: 'string' },
                },
              },
            },
          },
        },
        responses: {
          200: { description: 'Created' },
          201: { description: 'Created' },
        },
      },
    },
    '/llm/llm01/chat': {
      post: {
        tags: ['LLM'],
        summary: 'LLM01 - Prompt Injection',
        requestBody: {
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: { message: { type: 'string' } },
              },
            },
          },
        },
        responses: { 200: { description: 'LLM response (vulnerable)' } },
      },
    },
    '/mobile/m1/api/login': {
      get: {
        tags: ['Mobile'],
        summary: 'M1 - Hardcoded credentials',
        responses: { 200: { description: 'Credentials exposed' } },
      },
    },
    '/story': {
      get: {
        tags: ['Story'],
        summary: 'Choose faction (Aegis vs Null)',
        responses: { 200: { description: 'HTML page' } },
      },
    },
  },
};

module.exports = swaggerSpec;
