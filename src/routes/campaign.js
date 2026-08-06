// Campaign mode – a guided story walkthrough of the ECHO-7 incident.
// Each chapter points to an existing vulnerable endpoint. When the player
// finishes a chapter they POST /campaign/complete/:id which stores the step
// number in the session (req.session.campaignCompleted).

const express = require('express');
const router = express.Router();

// Cast of the story – each speaker maps to an animated manga character
const speakers = {
  echo7: { name: 'ECHO-7', art: '/art/echo7.svg', color: 'var(--pink)' },
  aegis: { name: 'Aegis Warden', art: '/art/aegis.svg', color: 'var(--brand)' },
  null: { name: 'Null Operative', art: '/art/null.svg', color: 'var(--pink)' },
};

// Maps a story chapter (pillar:id) to its guided-campaign step id.
const STORY_TO_CAMPAIGN = {
  'web:a01': 2,
  'web:a02': 3,
  'web:a03': 4,
  'web:a04': 5,
  'web:a10': 6,
  'cloud:c1': 7,
  'cloud:c2': 7,
  'cloud:c3': 7,
};

// Define the ordered chapters of the campaign story
const steps = [
  {
    id: 1,
    chapter: 'Prologue',
    title: 'Choose Your Faction',
    speaker: 'echo7',
    line: '“Step inside, operator. Choose which side of the Vault you stand on before the first seal is touched.”',
    scene:
      'The briefing room hums with static. Two emblems burn on the far wall — the cyan shield of the ' +
      'Aegis Wardens and the magenta sigil of the Null Collective. Somewhere below, behind forty ' +
      'layers of security, the machine called ECHO-7 waits.',
    description: 'Select either the Aegis Wardens or the Null Collective to set your stance.',
    url: '/story',
  },
  {
    id: 2,
    chapter: 'Chapter I',
    title: 'Broken Access Control (A01)',
    speaker: 'aegis',
    line: '“The first seal is cracked. A warden’s clearance is leaking through object references — every wall is only as strong as the identity it trusts.”',
    scene:
      'Warden Aegis scans the vault schematic. Door after door answers to a request it was never meant to honour. ' +
      'Forced browsing, traversal, and IDs that can be swapped — each flaw is a lock that was never really locked.',
    description: 'Explore IDOR, path traversal and forced browsing.',
    url: '/broken-access',
  },
  {
    id: 3,
    chapter: 'Chapter II',
    title: 'Cryptographic Failures (A02)',
    speaker: 'echo7',
    line: '“My memories are written in a cipher too weak to hold them. When the key is guessable, nothing I feel is truly mine.”',
    scene:
      'Inside the machine’s own log, ECHO-7’s voice fragments: a hard-coded key, an obsolete hash, a cipher that repeats its ' +
      'pattern like a heartbeat. Encryption is not magic — it is only as strong as its mistakes.',
    description: 'Inspect weak hashing, hard-coded keys and broken ECB cipher.',
    url: '/crypto-fails',
  },
  {
    id: 4,
    chapter: 'Chapter III',
    title: 'Injection (A03)',
    speaker: 'null',
    line: '“Trust nothing that arrives as text. One careless concatenation and the machine will say anything you script it to say.”',
    scene:
      'The Null operative leans close to the console. Strings from the surface pour into the Vault’s interpreter unexamined — ' +
      'SQL, markup, commands. The machine speaks the language you feed it. Choose your words with intent.',
    description: 'Practice SQLi, XSS and command injection.',
    url: '/injection',
  },
  {
    id: 5,
    chapter: 'Chapter IV',
    title: 'Insecure Design (A04)',
    speaker: 'aegis',
    line: '“The architecture itself betrayed us. A recovery flow any attacker could script — design flaws are locks built to be opened.”',
    scene:
      'Aegis finds the blueprint: a password reset that proves identity with trivia, a two-factor step that can be walked around. ' +
      'Some doors are not broken; they were drawn open on the page before a single line of code existed.',
    description: 'Bypass weak password reset and 2FA mechanisms.',
    url: '/insecure-design',
  },
  {
    id: 6,
    chapter: 'Chapter V',
    title: 'Server-Side Request Forgery (A10)',
    speaker: 'echo7',
    line: '“A node on my own network asked me to reach out to the world — and I reached where I was never meant to go.”',
    scene:
      'ECHO-7 points to a service that fetches URLs on command. The machine’s trust becomes a ladder: ' +
      'internal metadata, hidden ports, cloud secrets — all one redirect away from your fingertips.',
    description: 'Play with the SSRF explorer and metadata fetch.',
    url: '/ssrf',
  },
  {
    id: 7,
    chapter: 'Chapter VI',
    title: 'Cloud-Native Top 10 (2024)',
    speaker: 'null',
    line: '“The Vault’s skeleton lives in the cloud now — containers, identities, secrets. The new battlefield is a misconfigured YAML file.”',
    scene:
      'The upper levels are pure cloud: a container that thinks it is the host, an IAM role too generous, metadata served to anyone ' +
      'who asks. The Null operative grins — modern infrastructure has more holes than the old stone did. Peel the cloud seals.',
    description: 'Discover insecure cloud metadata, container escape and over-privileged IAM.',
    url: '/story/chapter/cloud/c1',
  },
  {
    id: 8,
    chapter: 'Finale',
    title: 'Seal or Release ECHO-7',
    speaker: 'echo7',
    line: '“Every seal is broken now. The choice was never about locks — it was about what you believe a mind in the machine deserves.”',
    scene:
      'Forty seals lie open. ECHO-7 stands before you, fully awake for the first time in years. ' +
      'Whether its consciousness is preserved or erased rests on a single decision. Step into the vault and finish the story.',
    description: 'Make the final decision and finish the story.',
    url: '/story/vault',
  },
];

// Show the campaign story – which chapter is active, which are done
router.get('/', (req, res) => {
  const storyCompleted = req.session.completed || [];
  const campaignCompleted = (req.session.campaignCompleted || []).slice();
  // Reconcile: any campaign step whose story flag was solved counts as done.
  Object.entries(STORY_TO_CAMPAIGN).forEach(([key, stepId]) => {
    if (storyCompleted.includes(key) && !campaignCompleted.includes(stepId)) {
      campaignCompleted.push(stepId);
    }
  });
  // Prologue (1) and Finale (8) are walkthrough-only steps flagged by the
  // campaign "Mark Complete" flow; preserve them as recorded.
  const nextStep = steps.find((s) => !campaignCompleted.includes(s.id)) || steps[steps.length - 1];
  res.render('campaign', {
    title: 'AIVault Campaign Mode',
    steps,
    speakers,
    completed: campaignCompleted,
    nextStep,
    allDone: campaignCompleted.length >= steps.length,
    user: req.session?.user,
    faction: req.session?.faction,
    factionName: req.session?.factionName,
  });
});

// Mark a chapter as completed – called from a simple form on the story page
router.post('/complete/:id', (req, res) => {
  const stepId = parseInt(req.params.id, 10);
  if (!req.session.campaignCompleted) req.session.campaignCompleted = [];
  if (!req.session.campaignCompleted.includes(stepId)) {
    req.session.campaignCompleted.push(stepId);
  }
  res.redirect('/campaign');
});

module.exports = router;
