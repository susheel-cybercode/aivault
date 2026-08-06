const { request } = require('./setup');
const { STORY, ACHIEVEMENTS } = require('../src/story');

function agent() {
  return request.agent(global.testApp);
}

describe('Campaign Mode (guided ECHO-7 walkthrough)', () => {
  it('GET /campaign renders the story walkthrough', async () => {
    const a = agent();
    const res = await a.get('/campaign');
    expect(res.status).toBe(200);
    expect(res.text).toContain('ECHO-7 Operation');
    expect(res.text).toContain('Prologue');
    expect(res.text).toContain('Operation Timeline');
  });

  it('posts /campaign/complete/:id advances progress and is honor-system for prologue/finale', async () => {
    const a = agent();
    // First step is the Prologue (id 1) — walkthrough only, no flag
    let res = await a.get('/campaign');
    const before = (res.text.match(/done-tag/g) || []).length;
    res = await a.post('/campaign/complete/1');
    expect(res.status).toBe(302);
    res = await a.get('/campaign');
    expect(res.text.match(/done-tag/g).length).toBeGreaterThan(before);
  });

  it('solving a real story chapter flag auto-advances the matching campaign step', async () => {
    const a = agent();
    // enlist a faction so story flag submission is allowed
    let res = await a
      .post('/story/faction')
      .set('Content-Type', 'application/json')
      .send({ faction: 'aegis' });
    expect([200, 302]).toContain(res.status);
    // before solving, campaign step 2 (web:a01) should not be done
    res = await a.get('/campaign');
    const before = (res.text.match(/done-tag/g) || []).length;
    // solve web:a01 via the real flag-verified path
    const a01 = STORY.chapters.find((c) => c.pillar === 'web' && c.id === 'a01');
    res = await a
      .post('/story/chapter/web/a01/submit-flag')
      .set('Content-Type', 'application/json')
      .send({ flag: a01.flag });
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // campaign should now reflect the completed step 2
    res = await a.get('/campaign');
    expect((res.text.match(/done-tag/g) || []).length).toBeGreaterThan(before);
  });

  it('walks the full campaign completion flow to the finale', async () => {
    const a = agent();
    await a
      .post('/story/faction')
      .set('Content-Type', 'application/json')
      .send({ faction: 'null' });
    for (let i = 1; i <= 8; i++) {
      await a.post('/campaign/complete/' + i);
    }
    const res = await a.get('/campaign');
    expect(res.text).toContain('8 / 8 seals broken');
    expect(res.text).toContain('Story complete');
  });
});

describe('Cloud-Native pillar (added to story)', () => {
  it('exposes 3 cloud chapters in STORY.chapters', () => {
    const cloud = STORY.chapters.filter((c) => c.pillar === 'cloud');
    expect(cloud.length).toBe(3);
    expect(cloud.map((c) => c.id).sort()).toEqual(['c1', 'c2', 'c3']);
  });

  it('includes a cloud_master achievement', () => {
    expect(ACHIEVEMENTS).toEqual(
      expect.arrayContaining([expect.objectContaining({ id: 'cloud_master' })])
    );
  });

  it('renders each cloud chapter briefing', async () => {
    const a = agent();
    await a
      .post('/story/faction')
      .set('Content-Type', 'application/json')
      .send({ faction: 'aegis' });
    for (const id of ['c1', 'c2', 'c3']) {
      const res = await a.get('/story/chapter/cloud/' + id);
      expect(res.status).toBe(200);
    }
  });
});
