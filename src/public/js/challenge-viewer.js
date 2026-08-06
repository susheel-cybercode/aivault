/* AIVault — Challenge Viewer
   Intercepts links to challenge API endpoints and renders JSON nicely in-page
   so players see hints, descriptions, and flags without raw JSON. */
(function () {
  'use strict';

  const levelColors = {
    Beginner: '#00ff41',
    Intermediate: '#ffae00',
    Advanced: '#ff3b3b',
    Pro: '#ff3b3b',
  };

  function isChallengeLink(href) {
    return (
      href &&
      href.startsWith('http') === false &&
      href.startsWith('/') &&
      !href.endsWith('/') &&
      !href.startsWith('/login') &&
      !href.startsWith('/dashboard') &&
      !href.startsWith('/flags') &&
      !href.startsWith('/leaderboard') &&
      !href.startsWith('/story') &&
      !href.startsWith('/campaign') &&
      !href.startsWith('/api-docs') &&
      !href.startsWith('/health') &&
      !href.startsWith('/#') &&
      !href.startsWith('/cloud')
    );
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      if (c === '&') return '&';
      if (c === '<') return '<';
      if (c === '>') return '>';
      if (c === '"') return '"';
      return '&#039;';
    });
  }

  function syntaxHighlight(str) {
    return esc(str)
      .replace(/(\/\/[^\n]*|#[^\n]*)/g, '<span style="color:#4a5568;">$1</span>')
      .replace(/('[^']*'|"[[^"]*")/g, '<span style="color:#00ff41;">$1</span>')
      .replace(
        /(\bfunction\b|\bvar\b|\bconst\b|\blet\b|\breturn\b|\bif\b|\belse\b|\bfor\b|\bwhile\b|\btrue\b|\bfalse\b|\bnull\b|\bundefined\b)/g,
        '<span style="color:#ffae00;">$1</span>'
      )
      .replace(/(\b\d+\b)/g, '<span style="color:#ffae00;">$1</span>')
      .replace(
        /(\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|UNION|DROP|CREATE|TABLE|INTO|VALUES)\b)/gi,
        '<span style="color:#ffae00;font-weight:700;">$1</span>'
      );
  }

  function renderValue(key, val) {
    if (val === null) return '<span style="color:#4a5568;">null</span>';
    if (typeof val === 'boolean') return '<span style="color:#00ff41;">' + val + '</span>';
    if (typeof val === 'number') return '<span style="color:#ffae00;">' + val + '</span>';
    if (typeof val === 'string') {
      if (key === 'flag')
        return (
          '<span style="color:#00ff41; font-weight:700; font-family:var(--font-mono);">' +
          esc(val) +
          '</span>'
        );
      if (key === 'hint')
        return (
          '<span style="color:#ffae00; font-style:italic; line-height:1.6;">' + esc(val) + '</span>'
        );
      if (key === 'level')
        return (
          '<span style="color:' +
          (levelColors[val] || '#00ff41') +
          '; font-weight:700; text-transform:uppercase; letter-spacing:1px; font-size:0.78rem;">' +
          esc(val) +
          '</span>'
        );
      return '<span style="color:var(--text); line-height:1.65;">' + esc(val) + '</span>';
    }
    return (
      '<span style="color:var(--phosphor); font-family:var(--font-mono);">' +
      syntaxHighlight(JSON.stringify(val, null, 2)) +
      '</span>'
    );
  }

  function renderJson(data) {
    let html = '';

    // Header card
    if (data.vuln) {
      html +=
        '<div class="data-card" style="margin-bottom:1rem; border-left:3px solid var(--brand);">' +
        '<h3 style="margin-top:0; color:var(--brand); font-size:1.1rem;">' +
        esc(data.vuln) +
        '</h3>';
    }
    if (data.level) {
      html +=
        '<div style="margin-bottom:0.6rem; display:flex; align-items:center; gap:0.6rem;">' +
        '<span style="font-size:0.65rem; text-transform:uppercase; letter-spacing:1.5px; color:var(--text-3); font-family:var(--font-mono);">DIFFICULTY</span> ' +
        renderValue('level', data.level) +
        '</div>';
    }
    if (data.description) {
      html +=
        '<p style="color:var(--text); margin-bottom:0.5rem; font-size:0.92rem; line-height:1.7;">' +
        esc(data.description) +
        '</p>';
    }
    html += '</div>';

    // Hint
    if (data.hint) {
      html +=
        '<div class="hint" style="margin-bottom:1rem;"><strong style="color:var(--amber); margin-right:0.3rem; text-transform:uppercase; font-size:0.72rem; letter-spacing:1px;">[HINT]</strong> ' +
        renderValue('hint', data.hint) +
        '</div>';
    }

    // Flag card
    if (data.flag) {
      html +=
        '<div class="data-card" style="margin-bottom:1rem; text-align:center; padding:1.5rem; border-color:var(--phosphor); box-shadow:none;">' +
        '<div style="font-size:0.65rem; text-transform:uppercase; letter-spacing:2px; color:var(--text-3); font-family:var(--font-mono); margin-bottom:0.4rem;">[ FLAG_CAPTURED ]</div>' +
        renderValue('flag', data.flag) +
        '<div style="margin-top:1rem;"><a href="/flags" class="button" style="font-size:0.78rem; padding:0.5rem 1.1rem;">[ SUBMIT_FLAG ]</a></div>' +
        '</div>';
    }

    // Extra fields
    const skip = ['vuln', 'level', 'description', 'hint', 'flag'];
    const extra = Object.keys(data).filter(function (k) {
      return skip.indexOf(k) === -1;
    });
    if (extra.length > 0) {
      html +=
        '<div class="data-card" style="border-left:3px solid var(--phosphor);"><h3 style="margin-top:0; color:var(--phosphor); font-size:0.82rem; text-transform:uppercase; letter-spacing:0.5px; font-family:var(--font-mono); border-bottom:1px dotted var(--border-2); padding-bottom:0.35rem;">// CHALLENGE_DATA</h3>';
      extra.forEach(function (key) {
        const val = renderValue(key, data[key]);
        html +=
          '<div style="margin-bottom:1rem;">' +
          '<div style="font-size:0.68rem; text-transform:uppercase; letter-spacing:1.5px; color:var(--text-3); margin-bottom:0.35rem; font-family:var(--font-mono);">' +
          esc(key) +
          '</div>' +
          '<pre style="margin:0; font-size:0.8rem; white-space:pre-wrap; color:var(--phosphor); background:#050505; padding:0.9rem 1.1rem; border:1px solid var(--border-2); border-left:3px solid var(--phosphor); border-radius:0; box-shadow:none; line-height:1.6; text-shadow:none;">' +
          val +
          '</pre>' +
          '</div>';
      });
      html += '</div>';
    }
    return html;
  }

  function fetchChallenge(url, pushState) {
    const body =
      document.querySelector('.terminal-body') ||
      document.querySelector('.terminal-container') ||
      document.body;
    const oldContent = body.innerHTML;
    body.innerHTML =
      '<div style="text-align:center; padding:4rem; color:var(--text-2); font-family:var(--font-mono); font-size:0.82rem;">' +
      '<span style="color:var(--brand);">▸</span> LOADING CHALLENGE ' +
      esc(url) +
      '...' +
      '</div>';

    fetch(url)
      .then(function (r) {
        return r.json();
      })
      .then(function (data) {
        body.innerHTML =
          '<a href="javascript:history.back()" style="font-size:0.74rem; margin-bottom:1.5rem; display:inline-block; color:var(--phosphor); font-family:var(--font-mono); padding:0.3rem 0.6rem; border:1px solid var(--phosphor);">[ ← BACK ]</a>' +
          renderJson(data) +
          '<hr style="border-color:var(--border-2); margin:2rem 0;"><div class="footer"><p><a href="/">← BACK_TO_ROOT</a></p></div>';
        if (pushState) history.pushState({ challenge: url }, '', url);
        window.scrollTo(0, 0);
      })
      .catch(function (err) {
        body.innerHTML = oldContent;
        console.error('Challenge view failed:', err);
      });
  }

  document.addEventListener('click', function (e) {
    const link = e.target.closest('a');
    if (!link) return;
    const href = link.getAttribute('href');
    if (!isChallengeLink(href)) return;
    const parts = href.split('/').filter(Boolean);
    if (parts.length < 2) return;
    e.preventDefault();
    fetchChallenge(href, true);
  });

  window.addEventListener('popstate', function (e) {
    if (e.state && e.state.challenge) {
      fetchChallenge(e.state.challenge, false);
    } else {
      location.reload();
    }
  });
})();
