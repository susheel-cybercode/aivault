const request = require('supertest');

jest.setTimeout(10000);

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.OPENAI_API_KEY = 'sk-test-key';
process.env.PORT = '0';

const { app } = require('../src/app');

global.testApp = app;
global.request = request;

module.exports = { testApp: app, request };