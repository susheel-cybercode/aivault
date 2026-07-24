/**
 * Story / Faction Controller
 * Handles faction selection, vault progress display, chapter bookend views,
 * **flag submission (real exploit verification)**, leaderboard, scoreboard.
 */

const express = require('express');
const router = express.Router();
const {
  STORY,
  getChapter,
  getFactionProgress,
  getChapterPoints,
  getRank,
  getEarnedAchievements,
  ACHIEVEMENTS,
} = require('../story');

function getDb() {
  return require('../db');
}

// ---- helpers
function ensureFaction(req, res, next) {
  if (!req.session.faction)
    return res.status(403).json({ error: 'Select a faction first at /story' });
  next();
}

function recordSolve(db, session_id, key, points) {
  // upsert player
  const p = db.prepare('SELECT id FROM players WHERE session_id = ?').get(session_id);
  if (!p) {
    db.prepare(
      'INSERT INTO players (session_id, faction, total_points, first_solve, last_solve) VALUES (?,?,?,?,?)'
    ).run(session_id, '', points, new Date().toISOString(), new Date().toISOString());
  } else {
    db.prepare(
      'UPDATE players SET total_points = total_points + ?, last_solve = ? WHERE session_id = ?'
    ).run(points, new Date().toISOString(), session_id);
  }
  // insert progress row if not present
  const prog = db
    .prepare('SELECT id FROM challenge_progress WHERE user_id = 0 AND challenge_id = ?')
    .get(key);
  if (!prog) {
    db.prepare(
      'INSERT INTO challenge_progress (user_id, challenge_id, completed) VALUES (0,?,1)'
    ).run(key);
  }
}

// Story landing
router.get('/', (req, res) => {
  res.render('story/intro', {
    title: STORY.title,
    story: STORY,
    user: req.session.user,
    faction: req.session.faction,
  });
});

// Faction selection
router.post('/faction', (req, res) => {
  const { faction, handle } = req.body;
  if (faction !== 'aegis' && faction !== 'null') {
    return res.status(400).json({ error: 'Invalid faction. Choose aegis or null.' });
  }
  req.session.faction = faction;
  req.session.completed = req.session.completed || [];
  req.session.handle = handle || `agent-${Math.random().toString(36).slice(2, 8)}`;
  req.session.save?.(() => {
    res.json({
      success: true,
      faction,
      handle: req.session.handle,
      message: `Joined ${STORY.factions[faction].name} as ${req.session.handle}`,
    });
  });
});

// Vault overview
router.get('/vault', (req, res) => {
  if (!req.session.faction) return res.redirect('/story');
  const completed = req.session.completed || [];
  const byPillar = { web: [], api: [], mobile: [], llm: [] };
  STORY.chapters.forEach((c) => {
    c._completed = completed.includes(`${c.pillar}:${c.id}`);
    c._points = getChapterPoints(c);
    byPillar[c.pillar].push(c);
  });
  const progress = getFactionProgress(req.session.faction, completed);
  const rank = getRank(req.session.faction, progress.points);
  const achievements = getEarnedAchievements(completed);
  res.render('story/vault', {
    title: 'The ECHO Vault',
    story: STORY,
    faction: req.session.faction,
    factionData: STORY.factions[req.session.faction],
    progress,
    rank,
    achievements,
    chapters: byPillar,
    handle: req.session.handle,
    user: req.session.user,
  });
});

// Single chapter briefing
router.get('/chapter/:pillar/:id', (req, res) => {
  const { pillar, id } = req.params;
  const chapter = getChapter(pillar, id);
  if (!chapter) return res.status(404).send('Chapter not found');

  const completed = (req.session.completed || []).includes(`${pillar}:${id}`);
  const faction = req.session.faction || 'null';
  const factionData = STORY.factions[faction];
  const progress = getFactionProgress(faction, req.session.completed || []);

  res.render('story/chapter', {
    title: `${chapter.code}: ${chapter.name}`,
    chapter,
    pillar,
    completed,
    faction: factionData,
    factionKey: faction,
    progress,
    user: req.session.user,
  });
});

// Show source (DVWA-style)
router.get('/chapter/:pillar/:id/source', (req, res) => {
  const chapter = getChapter(req.params.pillar, req.params.id);
  if (!chapter) return res.status(404).json({ error: 'Chapter not found' });
  const fs = require('fs');
  const path = require('path');
  const routeFileMap = {
    web: {
      a01: 'a01_broken_access.js',
      a02: 'a02_crypto_fails.js',
      a03: 'a03_injection.js',
      a04: 'a04_insecure_design.js',
      a05: 'a05_sec_misconfig.js',
      a06: 'a06_vuln_components.js',
      a07: 'a07_auth_fails.js',
      a08: 'a08_integrity_fails.js',
      a09: 'a09_logging_fails.js',
      a10: 'a10_ssrf.js',
    },
    api: 'api_top10.js',
    mobile: 'mobile_top10.js',
    llm: 'llm_top10.js',
  };
  let file;
  if (req.params.pillar === 'web') file = routeFileMap.web[req.params.id];
  else file = routeFileMap[req.params.pillar];
  if (!file) return res.json({ error: 'Source mapping missing' });
  try {
    const src = fs.readFileSync(path.join(__dirname, file), 'utf8');
    res.type('text/plain').send(src);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Show a hint (3 escalating)
router.get('/chapter/:pillar/:id/hint/:n', (req, res) => {
  const chapter = getChapter(req.params.pillar, req.params.id);
  if (!chapter) return res.status(404).json({ error: 'Not found' });
  const n = parseInt(req.params.n);
  if (n < 1 || n > chapter.hints.length)
    return res.status(400).json({ error: 'Invalid hint number' });
  res.json({ hint: chapter.hints[n - 1], level: n, total: chapter.hints.length });
});

// FLAG SUBMISSION  (the real completion path)
router.post('/chapter/:pillar/:id/submit-flag', ensureFaction, (req, res) => {
  const { pillar, id } = req.params;
  const { flag } = req.body;
  const chapter = getChapter(pillar, id);
  if (!chapter) return res.status(404).json({ error: 'Chapter not found' });
  const key = `${pillar}:${id}`;
  const already = (req.session.completed || []).includes(key);
  if (!flag) return res.status(400).json({ error: 'Provide a flag' });

  if (String(flag).trim() === chapter.flag) {
    if (!already) {
      req.session.completed = req.session.completed || [];
      req.session.completed.push(key);
      const pts = getChapterPoints(chapter);
      try {
        const db = getDb();
        const sid = req.sessionID;
        recordSolve(db, sid, key, pts);
      } catch (e) {
        /* ignore */
      }
    }
    const progress = getFactionProgress(req.session.faction, req.session.completed);
    const rank = getRank(req.session.faction, progress.points);
    const achievements = getEarnedAchievements(req.session.completed);
    // find next unsolved chapter suggestion
    const idx = STORY.chapters.findIndex((c) => c.pillar === pillar && c.id === id);
    let next = null;
    for (let i = idx + 1; i < STORY.chapters.length; i++) {
      if (!req.session.completed.includes(`${STORY.chapters[i].pillar}:${STORY.chapters[i].id}`)) {
        next = STORY.chapters[i];
        break;
      }
    }
    return res.json({
      success: true,
      message:
        req.session.faction === 'aegis'
          ? `Seal reinforced. ${chapter.code} secured.`
          : `Seal cracked. ${chapter.code} breached.`,
      progress,
      rank,
      newAchievements: achievements,
      nextChapter: next ? { pillar: next.pillar, id: next.id, name: next.name } : null,
      points_awarded: already ? 0 : getChapterPoints(chapter),
    });
  } else {
    return res.status(403).json({
      success: false,
      error: 'Incorrect flag. Exploit the vulnerability to obtain the real flag.',
    });
  }
});

// Backwards compatibility: keep the old /complete endpoint but require a flag now
router.post('/chapter/:pillar/:id/complete', ensureFaction, (req, res) => {
  // Redirect users to submit-flag with the body's flag
  const { flag } = req.body;
  if (!flag) {
    return res.status(400).json({
      error:
        'Flag required. Use POST /story/chapter/:pillar/:id/submit-flag with {flag:"FLAG{...}"}',
    });
  }
  // Re-dispatch by falling through
  const chapter = getChapter(req.params.pillar, req.params.id);
  if (!chapter) return res.status(404).json({ error: 'Chapter not found' });
  const key = `${req.params.pillar}:${req.params.id}`;
  const already = (req.session.completed || []).includes(key);
  if (String(flag).trim() === chapter.flag) {
    if (!already) {
      req.session.completed = req.session.completed || [];
      req.session.completed.push(key);
      try {
        const db = getDb();
        recordSolve(db, req.sessionID, key, getChapterPoints(chapter));
      } catch (e) {}
    }
    return res.json({
      success: true,
      progress: getFactionProgress(req.session.faction, req.session.completed),
    });
  }
  return res.status(403).json({ success: false, error: 'Incorrect flag' });
});

// Scoreboard
router.get('/scoreboard', (req, res) => {
  const db = getDb();
  const completed = req.session.completed || [];
  let board = [];
  try {
    board = db
      .prepare(
        `
      SELECT challenge_id, COUNT(*) as solves
      FROM challenge_progress WHERE completed = 1
      GROUP BY challenge_id ORDER BY solves DESC
    `
      )
      .all();
  } catch (e) {}
  const myProgress = getFactionProgress(req.session.faction || 'null', completed);
  const myRank = getRank(req.session.faction || 'null', myProgress.points);
  const achievements = getEarnedAchievements(completed);
  res.render('story/scoreboard', {
    title: 'Scoreboard — VulnLab',
    board,
    story: STORY,
    myProgress,
    myRank,
    achievements,
    completed,
    faction: req.session.faction,
    handle: req.session.handle,
    user: req.session.user,
  });
});

// Backwards compatibility for old /leaderboard URL
router.get('/leaderboard', (req, res) => res.redirect('/story/scoreboard'));

module.exports = router;
