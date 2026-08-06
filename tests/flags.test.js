// Flag submission and leaderboard integration tests
const request = require('supertest');
const { testApp } = require('../tests/setup');
const db = require('../src/db');

// Ensure using test environment (setup already sets env)


/** Helper to get current player rows with points */
function getPlayersWithPoints() {
  return db.prepare('SELECT * FROM players WHERE total_points > 0').all();
}

describe('Flag submission and leaderboard integration', () => {
  let agent;

  beforeEach(() => {
    // Fresh agent for each test to isolate session
    agent = request.agent(testApp);
  });

  test('Submitting a valid flag records points and appears on leaderboard', async () => {
    const flag = 'FLAG{osint01_username_enum_b2c3}';
    // Establish session
    await agent.get('/flags').expect(200);
    const before = getPlayersWithPoints().length;
    const res = await agent
      .post('/flags/submit')
      .send({ flag })
      .expect(200);
    // Response should contain success message and points info
    expect(res.text).toMatch(/Flag captured! \+\d+ points/);
    const afterRows = getPlayersWithPoints();
    // A new player row should have been created (or updated) with the flag length as points
    expect(afterRows.length).toBeGreaterThanOrEqual(before + 1);
    const matching = afterRows.find(p => p.total_points === flag.length);
    expect(matching).toBeDefined();
  });

  test('Submitting the same flag again yields an error and does not increase points', async () => {
    const flag = 'FLAG{osint01_username_enum_b2c3}';
    await agent.get('/flags').expect(200);
    // First submission (should succeed)
    await agent.post('/flags/submit').send({ flag }).expect(200);
    const playerBefore = getPlayersWithPoints().find(p => p.total_points === flag.length);
    const pointsBefore = playerBefore ? playerBefore.total_points : 0;
    // Second submission (duplicate)
    const dupRes = await agent.post('/flags/submit').send({ flag }).expect(200);
    expect(dupRes.text).toMatch(/already captured/);
    const playerAfter = getPlayersWithPoints().find(p => p.session_id === playerBefore.session_id);
    // Points should remain unchanged
    expect(playerAfter.total_points).toBe(pointsBefore);
  });

  test('Submitting an invalid flag format returns an error', async () => {
    await agent.get('/flags').expect(200);
    const res = await agent
      .post('/flags/submit')
      .send({ flag: 'BADFLAG' })
      .expect(200);
    expect(res.text).toMatch(/Invalid flag format/);
  });
});
